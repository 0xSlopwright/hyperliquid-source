#!/usr/bin/env python3
"""Map node #94 VoteGlobal admission and quorum: gate class table, listed sets, vote tally, row pop and apply.

The hosts 0x2704d90, 0x4e03dd0, 0x4e04300, the tally 0x2329990, 0x48c5de0, the row pop, the quorum test and the gate 0x282ec60
with copies run as real bytes in an interpreter inside this tool. The apply function, the validator lookup, the member test and the
stake quorum are stubs with checked arguments. A separately written rule list predicts every result, call and tracker row. No objdump
or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_vote_quorum.py --out <dir>
"""

import argparse
import bisect
import collections
import copy
import datetime
import fractions
import hashlib
import json
import math
import multiprocessing
import random
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Section, relocation and FDE views of one ELF byte string, through the shared parsers."""

    def __init__(self, blob):
        self.blob = blob
        self.relative_map = None
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        for row in fdes:
            ends[row["start"]] = max(ends.get(row["start"], 0), row["end"])
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va):
        for section in self.mapped:
            if section["address"] <= va < section["address"] + section["size"]:
                return va - section["address"] + section["offset"]
        raise EvidenceError("address outside file-backed sections: %#x" % va)

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
            if marker in path:
                path = path[path.rindex(marker) + 1:]
                break
        return path, line, column


OVERLAY_LOW = 0x577AE70


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


def fdiv(left, right):
    return left / right


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep, repne = 0, 0, False, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
        elif byte == 0xF2:
            repne = True
        elif byte == 0xF0:
            pass
        elif byte != 0x2E:
            break
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        rex = window[pos]
        pos += 1
    wide = bool(rex & 8)
    width = 8 if wide else (2 if opsize else 4)
    byte = window[pos]
    pos += 1
    imm = None
    rip_at = None

    def modrm(vector=False):
        nonlocal pos, rip_at
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("x" if vector else "r", rm | ((rex & 1) << 3))
        base, index, scale, rip = None, None, 1, False
        if rm == 4:
            sib = window[pos]
            pos += 1
            scale = 1 << (sib >> 6)
            index = ((sib >> 3) & 7) | ((rex & 2) << 2)
            if index == 4:
                index = None
            base = (sib & 7) | ((rex & 1) << 3)
            if sib & 7 == 5 and mod == 0:
                base = None
                disp = struct.unpack_from("<i", window, pos)[0]
                pos += 4
                return reg, ("m", base, index, scale, disp, False)
        elif rm == 5 and mod == 0:
            rip = True
        else:
            base = rm | ((rex & 1) << 3)
        disp = 0
        if mod == 1:
            disp = struct.unpack_from("<b", window, pos)[0]
            pos += 1
        elif mod == 2 or rip:
            if rip:
                rip_at = pos
            disp = struct.unpack_from("<i", window, pos)[0]
            pos += 4
        return reg, ("m", base, index, scale, disp, rip)

    def immediate(size):
        nonlocal pos, imm
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
        imm = (pos, size)
        pos += size
        return value

    def finish(op, a=None, b=None, w=None, cc=None, target=None):
        size = pos
        if (width if w is None else w) == 1 and not rex:
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
            if a and a[0] == "r" and 4 <= a[1] <= 7:
                a = ("h", a[1] - 4)
            if b and b[0] == "r" and 4 <= b[1] <= 7:
                b = ("h", b[1] - 4)

        def fix(operand):
            if operand and operand[0] == "m" and operand[5]:
                return ("m", None, None, 1, va + size + operand[4], False)
            return operand
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm, rip_at)

    if 0x50 <= byte <= 0x57:
        return finish("push", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if 0x58 <= byte <= 0x5F:
        return finish("pop", ("r", (byte & 7) | ((rex & 1) << 3)), w=8)
    if byte < 0x40 and byte & 7 < 4:
        name = GROUP1[byte >> 3]
        w = 1 if not byte & 1 else width
        reg, rm = modrm()
        if byte & 2:
            return finish(name, ("r", reg), rm, w)
        return finish(name, rm, ("r", reg), w)
    if byte < 0x40 and byte & 7 in (4, 5):
        w = 1 if byte & 7 == 4 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish(GROUP1[byte >> 3], ("r", RAX), ("i", value), w)
    if byte == 0x63 and wide:
        reg, rm = modrm()
        return finish("movsxd", ("r", reg), rm, 8)
    if 0x70 <= byte <= 0x7F:
        rel = immediate(1)
        return finish("jcc", cc=byte & 15, target=va + pos + rel)
    if byte in (0x80, 0x81, 0x83):
        reg, rm = modrm()
        w = 1 if byte == 0x80 else width
        value = immediate(4 if byte == 0x81 and w != 2 else 2 if byte == 0x81 else 1)
        return finish(GROUP1[reg & 7], rm, ("i", value), w)
    if byte in (0x84, 0x85):
        reg, rm = modrm()
        return finish("test", rm, ("r", reg), 1 if byte == 0x84 else width)
    if byte in (0x88, 0x89, 0x8A, 0x8B):
        reg, rm = modrm()
        w = 1 if not byte & 1 else width
        if byte & 2:
            return finish("mov", ("r", reg), rm, w)
        return finish("mov", rm, ("r", reg), w)
    if byte == 0x8D:
        reg, rm = modrm()
        return finish("lea", ("r", reg), rm, width)
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 2 if opsize else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0x6B:
        reg, rm = modrm()
        value = immediate(1)
        return finish("imul3", ("r", reg), rm, width, target=value)
    if byte == 0xD3:
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("r", RCX), width)
    if byte in (0xD1, 0xD0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        return finish(SHIFTS[reg & 7], rm, ("i", 1), 1 if byte == 0xD0 else width)
    if byte in (0xC1, 0xC0):
        reg, rm = modrm()
        if reg & 7 not in SHIFTS:
            raise EvidenceError("unsupported shift at %#x" % va)
        value = immediate(1) & 0xFF
        return finish(SHIFTS[reg & 7], rm, ("i", value), 1 if byte == 0xC0 else width)
    if byte == 0xC3:
        return finish("ret")
    if byte == 0xCC:
        return finish("int3")
    if byte in (0xC6, 0xC7):
        reg, rm = modrm()
        w = 1 if byte == 0xC6 else width
        value = immediate(1 if w == 1 else 2 if w == 2 else 4)
        return finish("mov", rm, ("i", value & MASK[w]), w)
    if byte == 0xE8:
        rel = immediate(4)
        return finish("call", target=va + pos + rel)
    if byte == 0xE9:
        rel = immediate(4)
        return finish("jmp", target=va + pos + rel)
    if byte == 0xEB:
        rel = immediate(1)
        return finish("jmp", target=va + pos + rel)
    if byte in (0xF6, 0xF7):
        reg, rm = modrm()
        w = 1 if byte == 0xF6 else width
        kind = reg & 7
        if kind == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
        if kind in (2, 3, 4, 5, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 5: "imul1", 6: "div"}[kind], rm, w=w)
        raise EvidenceError("unsupported group 3 opcode at %#x" % va)
    if byte in (0xFE, 0xFF):
        reg, rm = modrm()
        kind = reg & 7
        w = 1 if byte == 0xFE else width
        if kind in (0, 1):
            return finish("inc" if kind == 0 else "dec", rm, w=w)
        if byte == 0xFF and kind == 2:
            return finish("calli", rm, w=8)
        if byte == 0xFF and kind == 4:
            return finish("jmpi", rm, w=8)
        if byte == 0xFF and kind == 6:
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xBC and rep:
            reg, rm = modrm()
            return finish("tzcnt", ("r", reg), rm, width)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x6E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x7E and opsize and wide:
            reg, rm = modrm()
            return finish("movq", rm, ("x", reg), 8)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB6, 0xB7):
            reg, rm = modrm()
            return finish("movzx", ("r", reg), rm, width, cc=1 if two == 0xB6 else 2)
    raise EvidenceError("undecodable opcode %#x at %#x" % (byte, va))


def decode_range(image, start, end):
    """Decode [start, end) linearly; the last instruction must end exactly at end."""
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]

    def read(va, count):
        return code[va - start:va - start + count]

    rows = []
    va = start
    while va < end:
        row = decode(read, va)
        row.data = bytes(read(va, row.size))
        rows.append(row)
        va = row.next
    if va != end:
        raise EvidenceError("decoder overran FDE end at %#x" % end)
    return rows


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.fresh = (bytes([STACK_MARK]) * STACK_SIZE, bytes([STACK_MARK]) * HEAP_SIZE)
        self.statics = {}
        self.overlay = None

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
        if self.overlay is not None and OVERLAY_LOW <= addr and addr + count <= OVERLAY_LOW + 0x60:
            return self.overlay, addr - OVERLAY_LOW
        return None, 0

    def read(self, addr, count):
        return int.from_bytes(self.bytes_at(addr, count), "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = (value & MASK.get(count, (1 << (8 * count)) - 1)).to_bytes(count, "little")

    def put_bytes(self, addr, data):
        buffer, at = self.locate(addr, len(data))
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + len(data)] = data

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return self.statics[addr].to_bytes(count, "little")
        try:
            offset = self.image.offset(addr)
        except EvidenceError:
            raise Halt("read outside every mapping: %#x" % addr)
        return bytes(self.image.blob[offset:offset + count])

    def copy(self, dst, src, count):
        self.put_bytes(dst, self.bytes_at(src, count))

class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va)
        data = bytearray(self.image.blob[offset:offset + count])
        for index in range(count):
            if va + index in self.patches:
                data[index] = self.patches[va + index]
        return data

    def address(self, operand):
        _, base, index, scale, disp, _ = operand
        value = disp
        if base is not None:
            value += self.regs[base]
        if index is not None:
            value += self.regs[index] * scale
        return value & MASK[8]

    def get(self, operand, width):
        kind = operand[0]
        if kind == "r":
            return self.regs[operand[1]] & MASK[width]
        if kind == "h":
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
        if operand[0] == "r":
            reg = operand[1]
            if width >= 4:
                self.regs[reg] = value
            else:
                self.regs[reg] = (self.regs[reg] & ~MASK[width]) | value
        else:
            self.memory.write(self.address(operand), width, value)

    def condition(self, code):
        result = {
            0: self.of, 1: self.cf, 2: self.zf, 3: self.cf or self.zf, 4: self.sf,
            5: self.pf, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        return bool(result) != bool(code & 1)

    def set_logic(self, result, width):
        self.cf = self.of = False
        self.zf = result & MASK[width] == 0
        self.sf = bool(result & SIGN[width])

    def add_sub(self, left, right, carry, width, subtract):
        mask = MASK[width]
        if subtract:
            result = (left - right - carry) & mask
            self.cf = left < right + carry
            self.of = bool((left ^ right) & (left ^ result) & SIGN[width])
        else:
            total = left + right + carry
            result = total & mask
            self.cf = total > mask
            self.of = bool(~(left ^ right) & (left ^ result) & SIGN[width])
        self.zf = result == 0
        self.sf = bool(result & SIGN[width])
        return result

    def push(self, value):
        self.regs[RSP] -= 8
        self.memory.write(self.regs[RSP], 8, value)

    def pop(self):
        value = self.memory.read(self.regs[RSP], 8)
        self.regs[RSP] += 8
        return value

    def stub(self, hook):
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def step(self, row):
        op = row.op
        width = row.width
        if op == "mov":
            self.put(row.a, width, self.get(row.b, width))
        elif op == "jcc":
            return row.target if self.condition(row.cc) else row.next
        elif op == "lea":
            self.put(row.a, width, self.address(row.b))
        elif op == "push":
            self.push(self.regs[row.a[1]])
        elif op == "pop":
            self.regs[row.a[1]] = self.pop()
        elif op in ("add", "adc", "sub", "sbb", "cmp"):
            carry = int(self.cf) if op in ("adc", "sbb") else 0
            result = self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in ("add", "adc"))
            if op != "cmp":
                self.put(row.a, width, result)
        elif op in ("and", "or", "xor", "test"):
            left, right = self.get(row.a, width), self.get(row.b, width)
            result = left & right if op in ("and", "test") else left | right if op == "or" else left ^ right
            self.set_logic(result, width)
            if op != "test":
                self.put(row.a, width, result)
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
        elif op == "call":
            self.push(row.next)
            if row.target in self.real:
                return row.target
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
        elif op == "ret":
            return self.pop()
        elif op == "movzx":
            self.put(row.a, width, self.get(row.b, row.cc))
        elif op == "set":
            self.put(row.a, 1, int(self.condition(row.cc)))
        elif op == "cmov":
            value = self.get(row.b, width)
            self.put(row.a, width, value if self.condition(row.cc) else self.get(row.a, width))
        elif op in ("inc", "dec"):
            carry = self.cf
            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == "dec")
            self.cf = carry
            self.put(row.a, width, value)
        elif op == "neg":
            value = self.add_sub(0, self.get(row.a, width), 0, width, True)
            self.put(row.a, width, value)
        elif op == "not":
            self.put(row.a, width, ~self.get(row.a, width))
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
                result = value << count
            elif op == "shr":
                result = value >> count
            else:
                result = (value - (1 << (8 * width)) if value & SIGN[width] else value) >> count
            if count:
                self.set_logic(result, width)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.vector(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
        elif op == "div":
            divisor = self.get(row.a, width)
            if divisor == 0:
                raise Halt("division by zero at %#x" % row.va)
            dividend = (self.regs[RDX] & MASK[width]) << (8 * width) | (self.regs[RAX] & MASK[width])
            quotient, remainder = divmod(dividend, divisor)
            if quotient > MASK[width]:
                raise Halt("division overflow at %#x" % row.va)
            self.regs[RAX], self.regs[RDX] = quotient, remainder
        elif op == "movsxd":
            value = self.get(row.b, 4)
            self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)
        else:
            self.step_vector(row, op)
        return row.next

    def low(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]] & MASK[8]
        return self.memory.read(self.address(operand), 8)

    def set_low(self, register, bits):
        self.xmm[register] = (self.xmm[register] & ~MASK[8]) | bits

    def step_vector(self, row, op):
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
        if op == "movsd":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.set_low(row.a[1], self.low(row.b))
                else:
                    self.xmm[row.a[1]] = self.low(row.b)
            else:
                self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "movq":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "minsd":
                result = left if left < right else right
            else:
                result = left if left > right else right
            self.set_low(row.a[1], to_bits(result))
        elif op == "ucomisd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            unordered = left != left or right != right
            self.of = self.sf = False
            self.pf = unordered
            self.zf = unordered or left == right
            self.cf = unordered or left < right
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


SERIALIZE_RMP = 0x39908E0
SERIALIZE_JSON = 0x3990470
DECODE_RMP = 0x175F130
RMP_COPIES = (0x2BC6810, 0x3EDA980)
DECODE_JSON = 0x1D0CB80
JSON_COPIES = (0x318D7D0,)
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
MARK_BASE = 0x7700000000

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x400000
ARENA_END = HEAP_BASE + 0x2F0000
OUT = HEAP_BASE + 0x100
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
INDENT_AT = SERIALIZER + 0x80
DECODER = HEAP_BASE + 0x6000
DECODED = HEAP_BASE + 0x8000
INPUT = HEAP_BASE + 0x2F0000
STATUS_OK = 0x8000000000000004
ERROR_WORD = 2
STATE_SIZE = 0x298
LONG_STEP_LIMIT = 6000000
MUTANT_STEP_LIMIT = 900000


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = image.real_set()
        machine.step_limit = LONG_STEP_LIMIT
        machine.memory.statics = image.static_view()
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.live = {}

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END:
            raise Halt("fixture arena full")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed block size")
        del self.live[at]

    def on_realloc(self, machine):
        old, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(old in self.live, "realloc of a live block")
        at = self.alloc(size)
        self.put(at, self.data(old, min(size, self.live[old])))
        del self.live[old]
        machine.regs[RAX] = at

    def on_copy(self, machine):
        if machine.regs[RDX]:
            self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_compare(self, machine):
        left, right = self.data(machine.regs[RDI], machine.regs[RDX]), self.data(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, machine):
        raise Panicked("panic path reached")

    def fresh(self):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}

    def decode_rmp(self, data, entry=DECODE_RMP):
        self.fresh()
        self.put(INPUT, data)
        self.write(DECODER + 0x10, INPUT)
        self.write(DECODER + 0x18, len(data))
        self.write(DECODER + 0x20, 1, 1)
        self.write(DECODER + 0x22, 1024, 2)
        self.machine.run(entry, {RDI: DECODED, RSI: DECODER, RDX: 0})
        if self.read(DECODED) != ERROR_WORD:
            return ("ok",)
        tag = self.read(DECODED + 8, 1)
        if tag == 6:
            return ("error", self.data(self.read(DECODED + 0x18), self.read(DECODED + 0x20)).decode())
        return ("kind", tag)

    def decode_json(self, text, entry=DECODE_JSON):
        self.fresh()
        data = text.encode()
        self.put(INPUT, data)
        for offset in range(0, 0x60, 8):
            self.write(DECODER + offset, 0)
        self.write(DECODER + 0x18, INPUT)
        self.write(DECODER + 0x20, len(data))
        self.write(DECODER + 0x48, 128, 1)
        self.machine.run(entry, {RDI: DECODED, RSI: DECODER})
        if self.read(DECODED) != ERROR_WORD:
            return ("ok",)
        box = self.read(DECODED + 8)
        self.expect(self.read(box) == 0, "serde_json error with a text")
        return ("error", self.data(self.read(box + 8), self.read(box + 0x10)).decode())

    def writer(self):
        pointer = self.alloc(0x20000)
        self.write(WRITER, 0x20000)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)

    def pack(self, named, human):
        self.writer()
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, 0)
        self.write(SERIALIZER + 0xA, human, 1)
        self.write(SERIALIZER + 0xB, named, 1)
        self.machine.run(SERIALIZE_RMP, {RDI: OUT, RSI: DECODED, RDX: SERIALIZER})
        self.expect(self.read(OUT) == STATUS_OK, "serializer status %#x" % self.read(OUT))
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).hex()

    def text(self, indent):
        self.writer()
        self.put(INDENT_AT, indent.encode())
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, INDENT_AT)
        self.write(SERIALIZER + 0x10, len(indent))
        self.write(SERIALIZER + 0x18, 0)
        self.write(SERIALIZER + 0x20, 0xEE, 1)
        self.machine.run(SERIALIZE_JSON, {RDI: DECODED, RSI: SERIALIZER})
        self.expect(self.machine.regs[RAX] == 0, "json status")
        self.expect(self.read(SERIALIZER + 0x18) == 0, "indent level back at its start")
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).decode()


class TextRange:
    """Every code address runs for real."""

    def __contains__(self, va):
        return va < 0x6000000


def real_set(self):
    return TextRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


EXCHANGE = DECODED - 0x8F8
HOST = (0x2704D90, 0x4E03DD0, 0x4E04300)
APPLY = (0x2355F40, 0x4CAA870, 0x4CB3200)
GATE = (0x282EC60, 0x48F5570, 0x48F52E0)
RESOLVE = (0x275EA20, 0x4D8B030, 0x4D8B3B0)
TALLY = (0x2329990, 0x48C5DE0)
VALIDATOR_LOOKUP = 0x33690C0
MEMBER = 0x3367530
STAKE_QUORUM = 0x3366B60
ONCE = 0x4EE3B20
INIT = {3: 0x1451FB0, 0: 0x14520E0}
LISTED = {3: 0x577AE70, 0: 0x577AEA0}
INIT_SLOT = {3: 0x577AE70, 0: 0x577AEA0}
CLASS_TABLE = 0x58C1D8
CLASS_ARMS = 0x3F2C68
TEXT_TABLE = 0x59A8D0
OUT_AT = HEAP_BASE + 0x3000
SIGNER_AT = HEAP_BASE + 0x3200
ACTION_AT = HEAP_BASE + 0x3300
BUILD_AT = HEAP_BASE + 0x3500
OK = 0x186
NONE_TAG = 0x74
EPOCH_ROOT, EPOCH_HEIGHT, EPOCH_ACTIVE, EPOCH_NOW = 0x111, 2, 0x4444, 0x4444
STUB_ERROR = 0x94
USER_ERROR = 0x58


class Log:
    def __init__(self):
        self.rows = []

    def add(self, *row):
        self.rows.append(row)


def field(offset, copy_index):
    return offset + 0xA80 if copy_index == 2 and offset >= 0x740 else offset


def key20(seed):
    return bytes([0x70 + (seed & 15)] * 19) + bytes([seed & 255])


def key32(seed):
    return bytes([0x30 + (seed & 15)] * 31) + bytes([seed & 255])


def low_address(value):
    return bytes(16) + struct.pack(">I", value)


OTHER_LISTED = (bytes.fromhex("347e6c7376d33a5c6c1d0dfe606a4902eb87cc86"), bytes.fromhex("b9310ff6caa98cba9442b3663876cbabab0b5ac6"), bytes.fromhex("bdcae99dbc8ff081dd36f395b05687ae710bed49"))


def walk(reader, root, height, key_size, offset=8):
    count_at = 8 + 11 * key_size + 2
    child_at = (count_at + 2 + 7) & ~7
    rows = []

    def visit(node, level):
        count = reader(node + count_at, 2)
        for index in range(count):
            if level:
                visit(reader(node + child_at + 8 * index), level - 1)
            rows.append(node + offset + index * key_size)
        if level:
            visit(reader(node + child_at + 8 * count), level - 1)
    if root:
        visit(root, height)
    return rows


class Votes(Harness):
    def __init__(self, image, patches=None, cache=None):
        Harness.__init__(self, image, patches, cache)
        machine = self.machine
        self.skip = set()
        machine.real = Stubbed(self.skip)
        machine.memory.overlay = bytearray(0x60)
        for va, hook in ((VALIDATOR_LOOKUP, self.on_validator), (MEMBER, self.on_member), (STAKE_QUORUM, self.on_quorum)):
            self.hook(va, hook)
        self.hook(ONCE, self.on_once)
        for va in APPLY:
            self.hook(va, self.on_apply)
        for va in RESOLVE:
            self.hook(va, self.on_resolve)
        self.log = Log()
        self.world = None
        self.index = 0

    def hook(self, va, action):
        self.skip.add(va)
        self.machine.calls[va] = action
        self.machine.slots[va] = action

    def on_once(self, machine):
        raise Halt("once reached after the fixture filled the static")

    def on_validator(self, machine):
        out, state, signer, epoch = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(state == EXCHANGE + field(0x3840, self.index), "staking pointer")
        self.expect(epoch == EPOCH_NOW, "epoch word")
        key = self.data(signer, 20)
        found = self.world["validators"].get(key)
        self.log.add("validator", key.hex()[-4:])
        if found is None:
            self.write(out, STUB_ERROR, 2)
            return
        self.write(out, OK, 2)
        self.put(out + 2, found)

    def on_member(self, machine):
        self.expect(machine.regs[RDI] == EXCHANGE + field(0x3840, self.index), "member staking pointer")
        key = self.data(machine.regs[RSI], 32)
        self.log.add("member", key.hex()[-4:])
        machine.regs[RAX] = 1 if key in self.world["members"] else 0

    def on_quorum(self, machine):
        self.expect((machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]) == (EPOCH_ROOT, EPOCH_HEIGHT, EPOCH_ACTIVE), "quorum epoch words")
        at = machine.regs[RCX]
        ids = [self.data(row, 32) for row in walk(self.read, self.read(at), self.read(at + 8), 32, 0)]
        self.expect(len(ids) == self.read(at + 0x10), "set length")
        self.log.add("quorum", ",".join(item.hex()[-4:] for item in ids))
        machine.regs[RAX] = 1 if stake_passes(self.world, ids) else 0

    def on_apply(self, machine):
        out, action, state = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(state == EXCHANGE, "apply state")
        self.log.add("apply", self.read(action), self.read(action + 8))
        status = self.world["apply_status"]
        self.write(out, status, 2)
        self.put(out + 2, bytes(0x5E))

    def on_resolve(self, machine):
        out, signer = machine.regs[RDI], machine.regs[RDX]
        self.expect(machine.regs[RSI] == EXCHANGE, "resolve state")
        key = self.data(signer, 20)
        self.log.add("resolve", key.hex()[-4:])
        found = self.world["users"].get(key)
        self.write(out, OK if found else USER_ERROR, 2)
        self.put(out + 2, found or key)

    def statics(self, world):
        memory = self.machine.memory
        for chain in (3, 0):
            self.machine.run(INIT[chain], {RDI: BUILD_AT})
            base = OVERLAY_LOW + (0 if chain == 3 else 0x30)
            row = bytearray(self.data(BUILD_AT, 0x28))
            if chain == world["chain"]:
                row[0x18:0x20] = struct.pack("<Q", world["threshold"])
            memory.overlay[base - OVERLAY_LOW:base - OVERLAY_LOW + 0x30] = bytes(row) + bytes(8)

    def prepare(self, world, index):
        self.fresh()
        self.world, self.index = world, index
        self.log = Log()
        self.statics(world)
        self.put(EXCHANGE, bytes(0x4600))
        self.write(EXCHANGE + field(0x8F2, index), world["chain"], 1)
        self.write(EXCHANGE + field(0x3888, index), EPOCH_NOW)
        staking = EXCHANGE + field(0x3840, index)
        self.write(staking + 0x30, EPOCH_ROOT)
        self.write(staking + 0x38, EPOCH_HEIGHT)
        self.write(staking + 0x48, EPOCH_ACTIVE)

    def vote(self, signer, action):
        tag, payload = action
        self.put(SIGNER_AT, signer)
        self.put(ACTION_AT, bytes(0xF0))
        self.write(ACTION_AT, tag)
        self.write(ACTION_AT + 8, payload)
        if tag == 0x1D:
            self.write(ACTION_AT + 0x10, 8)
        index = self.index
        self.put(OUT_AT, bytes(0x60))
        if index == 0:
            self.machine.run(HOST[0], {RDI: OUT_AT, RSI: EXCHANGE, RDX: SIGNER_AT, RCX: ACTION_AT})
            status = self.read(OUT_AT, 2)
            return (OK, self.read(OUT_AT + 2, 1)) if status == OK else (status,)
        self.machine.run(HOST[index], {RDI: OUT_AT, RSI: ACTION_AT, RDX: SIGNER_AT, RCX: EXCHANGE})
        first = self.read(OUT_AT, 1)
        if first == 9:
            return (OK, self.read(OUT_AT + 1, 1))
        self.expect(first == 0xE, "copy result byte")
        return (self.read(OUT_AT + 8, 2),)

    def gate(self, signer, tag):
        self.put(SIGNER_AT, signer)
        self.put(ACTION_AT, bytes(0xF0))
        self.write(ACTION_AT, tag)
        self.put(OUT_AT, bytes(0x60))
        self.machine.run(GATE[self.index], {RDI: OUT_AT, RSI: ACTION_AT, RDX: SIGNER_AT, RCX: EXCHANGE})
        status = self.read(OUT_AT, 2)
        return (status, self.data(OUT_AT + 2, 20).hex()[-4:]) if status == OK else (status,)

    def tracker(self):
        at = EXCHANGE + field(0x3510, self.index)
        root, height, size = self.read(at + 0x18), self.read(at + 0x20), self.read(at + 0x28)
        if not size:
            return None
        self.expect(size == 1 and height == 0 and root != 0, "one tracker row")
        row = root
        done = self.read(row + 0x108, 1)
        tag = self.read(row)
        kept = None if tag == NONE_TAG else (tag, self.read(row + 8))
        rows = []
        count = self.read(row + 0x100)
        node_keys = []

        def visit(node, level):
            used = self.read(node + 0xC6A, 2)
            for index in range(used):
                if level:
                    visit(self.read(node + 0xC70 + 8 * index), level - 1)
                node_keys.append((node + 0xF0 * index, node + 0xA50 + 0x30 * index))
            if level:
                visit(self.read(node + 0xC70 + 8 * used), level - 1)
        if self.read(row + 0xF0):
            visit(self.read(row + 0xF0), self.read(row + 0xF8))
        self.expect(len(node_keys) == count, "vote map length")
        for key, value in node_keys:
            ids = [self.data(item, 32).hex()[-4:] for item in walk(self.read, self.read(value), self.read(value + 8), 32, 0)]
            signers = [self.data(item, 20).hex()[-4:] for item in walk(self.read, self.read(value + 0x18), self.read(value + 0x20), 20)]
            rows.append(((self.read(key), self.read(key + 8)), tuple(ids), tuple(signers)))
        return (done, kept, tuple(rows))


class Stubbed:
    """Every code address runs for real, but for the named outer steps."""

    def __init__(self, skip):
        self.skip = skip

    def __contains__(self, va):
        return va < 0x6000000 and va not in self.skip


def stake_passes(world, ids):
    total = sum(world["stakes"].values())
    return sum(world["stakes"].get(item, 0) for item in ids) * 3 > total * 2


def listed_count(world, signers):
    return sum(1 for item in signers if item in world["listed"])


def fast_action(action):
    tag, payload = action
    index = tag - 0x12 if tag >= 0x12 else 0x4E
    return index in (0xB, 0x20, 0x55) or (index == 0x4A and payload & 0xFF == 1)


def spec_quorum(world, votes, log, action):
    ids, signers = votes
    ordered = sorted(ids)
    log.append(("quorum", ",".join(item.hex()[-4:] for item in ordered)))
    need = 0 if fast_action(action) else world["threshold"]
    return stake_passes(world, ordered) and listed_count(world, signers) >= need


def spec_vote(world, row, signer, action, log):
    log.append(("validator", signer.hex()[-4:]))
    chosen = world["validators"].get(signer)
    listed = signer in world["listed"]
    if chosen is None and not listed:
        return (0x91,), row
    items = []
    if chosen is not None:
        items.append(("id", chosen))
    if listed:
        items.append(("signer", signer))
    passed = False
    for kind, key in items:
        if kind == "id":
            log.append(("member", key.hex()[-4:]))
            if key not in world["members"]:
                continue
        if row is None:
            row = dict(done=False, action=None, votes={})
        votes = row["votes"].setdefault(action, (set(), set()))
        before = row["done"] or spec_quorum(world, votes, log, action)
        votes[0 if kind == "id" else 1].add(key)
        if before:
            continue
        if spec_quorum(world, votes, log, action):
            row["done"] = True
            row["action"] = action
            passed = True
    if not passed:
        return (OK, 0), row
    log.append(("apply",) + action)
    status = world["apply_status"]
    return ((OK, 1) if status == OK else (status,)), None


def spec_gate(world, signer, tag, table, log):
    index = tag - 0x74 if tag >= 0x74 else 0x14
    kind = table[index]
    if kind in (0, 1):
        log.append(("validator", signer.hex()[-4:]))
        if signer in world["validators"]:
            return (OK, signer.hex()[-4:])
        if kind == 1 and signer in world["listed"]:
            return (OK, signer.hex()[-4:])
        return (0x7B,)
    if kind == 2:
        return (OK, signer.hex()[-4:])
    if kind == 3:
        log.append(("resolve", signer.hex()[-4:]))
        found = world["users"].get(signer)
        return (OK, found.hex()[-4:]) if found else (USER_ERROR,)
    return (0x7D,)


def plain_row(row):
    if row is None:
        return None
    rows = []
    for action in sorted(row["votes"]):
        ids, signers = row["votes"][action]
        rows.append((action, tuple(item.hex()[-4:] for item in sorted(ids)), tuple(item.hex()[-4:] for item in sorted(signers))))
    return (1 if row["done"] else 0, row["action"], tuple(rows))


class Case:
    def __init__(self, name, kind, world, index, ops):
        self.name, self.kind, self.world, self.index, self.ops = name, kind, world, index, ops


def world_of(**change):
    validators = {key20(seed): key32(seed) for seed in range(1, 8)}
    row = dict(chain=3, threshold=0, apply_status=OK, validators=validators, members=set(validators.values()), stakes={key32(seed): 10 for seed in range(1, 8)}, users={})
    row.update(change)
    row["listed"] = {low_address(1), low_address(2), low_address(3)} if row["chain"] == 3 else set(OTHER_LISTED)
    return row


def extended(chosen):
    rows = dict(world_of()["validators"])
    rows[low_address(2)] = chosen
    return rows


def run_case(harness, case):
    harness.prepare(case.world, case.index)
    got = []
    states = []
    for op in case.ops:
        if op[0] == "vote":
            got.append(harness.vote(op[1], op[2]))
            states.append(harness.tracker())
        else:
            got.append(harness.gate(op[1], op[2]))
    return tuple(got), tuple(tuple(row) for row in harness.log.rows), tuple(states)


def spec_run(case):
    world = case.world
    log, got, states = [], [], []
    row = None
    table = class_table()
    for op in case.ops:
        if op[0] == "vote":
            result, row = spec_vote(world, row, op[1], op[2], log)
            got.append(result)
            states.append(plain_row(row))
        else:
            got.append(spec_gate(world, op[1], op[2], table, log))
    return tuple(got), tuple(tuple(item) for item in log), tuple(states)


CLASS_ROWS = {}


def class_table():
    if not CLASS_ROWS:
        image = getattr(load_image, "cached", None) or load_image()
        load_image.cached = image
        offset = image.offset(CLASS_TABLE)
        CLASS_ROWS.update(enumerate(image.blob[offset:offset + 0x58]))
    return CLASS_ROWS


U64_TAGS = (0x16, 0x32, 0x40, 0x45, 0x46)
FAST_TAGS = ((0x1D, 0), (0x5C, 1), (0x5C, 0))


def voters(*seeds):
    return [key20(seed) for seed in seeds]


def votes(rows, action=(0x16, 5)):
    return [("vote", signer, action) for signer in rows]


def vote_cases():
    cases = []
    for index in range(3):
        mark = "h%d_" % index
        action = (0x16, 5)
        cases.append(Case(mark + "unknown_refused", "admit", world_of(), index, votes(voters(30))))
        cases.append(Case(mark + "one_vote_keeps", "tally", world_of(), index, votes(voters(1))))
        cases.append(Case(mark + "twice_same", "tally", world_of(), index, votes(voters(1, 1))))
        cases.append(Case(mark + "four_of_seven_below", "tally", world_of(), index, votes(voters(1, 2, 3, 4))))
        cases.append(Case(mark + "five_of_seven_pass", "pass", world_of(), index, votes(voters(1, 2, 3, 4, 5))))
        cases.append(Case(mark + "six_after_pass", "pass", world_of(), index, votes(voters(1, 2, 3, 4, 5, 6))))
        cases.append(Case(mark + "exact_two_thirds_fails", "pass", world_of(stakes={key32(seed): 10 for seed in range(1, 4)}, validators={key20(seed): key32(seed) for seed in range(1, 4)}, members={key32(seed) for seed in range(1, 4)}), index, votes(voters(1, 2, 3))))
        cases.append(Case(mark + "two_actions_apart", "tally", world_of(), index, votes(voters(1, 2, 3, 4)) + [("vote", key20(5), (0x16, 6)), ("vote", key20(6), (0x40, 5))]))
        cases.append(Case(mark + "pass_clears_other_votes", "pass", world_of(), index, votes(voters(1, 2), (0x16, 6)) + votes(voters(1, 2, 3, 4, 5)) + votes(voters(7), (0x16, 6))))
        cases.append(Case(mark + "non_member_counts_nothing", "tally", world_of(members={key32(seed) for seed in range(2, 8)}), index, votes(voters(1, 2))))
        cases.append(Case(mark + "non_member_only", "tally", world_of(members=set()), index, votes(voters(1))))
        cases.append(Case(mark + "listed_alone", "listed", world_of(), index, votes([low_address(1)])))
        cases.append(Case(mark + "listed_three", "listed", world_of(), index, votes([low_address(1), low_address(2), low_address(3)])))
        cases.append(Case(mark + "listed_also_validator", "listed", world_of(validators=extended(key32(2))), index, votes([low_address(2)] + voters(1, 3, 4, 5))))
        cases.append(Case(mark + "listed_validator_last_vote", "listed", world_of(validators=extended(key32(5))), index, votes(voters(1, 2, 3, 4) + [low_address(2)])))
        cases.append(Case(mark + "threshold_two_waits", "threshold", world_of(threshold=2), index, votes(voters(1, 2, 3, 4, 5)) + votes([low_address(1)])))
        cases.append(Case(mark + "threshold_two_met", "threshold", world_of(threshold=2), index, votes(voters(1, 2, 3, 4, 5)) + votes([low_address(1), low_address(2)])))
        cases.append(Case(mark + "threshold_listed_first", "threshold", world_of(threshold=1), index, votes([low_address(3)] + voters(1, 2, 3, 4, 5))))
        cases.append(Case(mark + "apply_refused", "apply", world_of(apply_status=0x143), index, votes(voters(1, 2, 3, 4, 5))))
        cases.append(Case(mark + "apply_refused_then_new", "apply", world_of(apply_status=0x143), index, votes(voters(1, 2, 3, 4, 5, 6))))
        cases.append(Case(mark + "chain_other", "chain", world_of(chain=0), index, votes([OTHER_LISTED[0]] + voters(1, 2, 3, 4, 5))))
        cases.append(Case(mark + "chain_other_low_refused", "chain", world_of(chain=0), index, votes([low_address(1)])))
        cases.append(Case(mark + "chain_main_other_refused", "chain", world_of(), index, votes([OTHER_LISTED[1]])))
        cases.append(Case(mark + "chain_other_threshold", "chain", world_of(chain=0, threshold=3), index, votes(voters(1, 2, 3, 4, 5) + list(OTHER_LISTED))))
        cases.append(Case(mark + "no_stake_all", "pass", world_of(stakes={}), index, votes(voters(1))))
        cases.append(Case(mark + "uneven_stake", "pass", world_of(stakes={key32(1): 70, key32(2): 20, key32(3): 10}), index, votes(voters(2, 3, 1))))
        for tag in U64_TAGS:
            cases.append(Case(mark + "tag_%x_pass" % tag, "tag", world_of(), index, votes(voters(1, 2, 3, 4, 5), (tag, 9))))
        for tag, value in FAST_TAGS:
            cases.append(Case(mark + "fast_%x_%d_pass" % (tag, value), "fast", world_of(), index, votes(voters(1, 2, 3, 4, 5), (tag, value))))
            cases.append(Case(mark + "fast_%x_%d_row_pop" % (tag, value), "fast", world_of(), index, votes(voters(6, 7), (0x16, 8)) + votes(voters(1, 2, 3, 4, 5, 6), (tag, value))))
        for tag, value in FAST_TAGS + ((0x32, 4),):
            cases.append(Case(mark + "fast_%x_%d_threshold" % (tag, value), "fast", world_of(threshold=2), index, votes(voters(1, 2, 3, 4, 5), (tag, value))))
        cases.append(Case(mark + "plain_threshold_same_votes", "fast", world_of(threshold=2), index, votes(voters(1, 2, 3, 4, 5), (0x16, 4))))
        cases.append(Case(mark + "tags_sorted", "tag", world_of(), index, [("vote", key20(1 + i), (tag, 9 - i)) for i, tag in enumerate(U64_TAGS)]))
        cases.append(Case(mark + "same_tag_values_sorted", "tag", world_of(), index, [("vote", key20(1 + i), (0x16, value)) for i, value in enumerate((9, 3, 7, 5))]))
        cases.append(Case(mark + "many_actions", "tag", world_of(), index, [("vote", key20(1), (0x16, value)) for value in range(14)]))
    return cases


GATE_TAGS = ((0x74 + 24, "class 0"), (0x10, "class 1"), (0x75, "class 2"), (0x74, "class 3"), (0x74 + 0x38, "class 4"))


def gate_cases():
    cases = []
    user = key20(40)
    for index in range(3):
        world = world_of(users={user: key20(41)})
        for tag, label in GATE_TAGS:
            mark = "g%d_%s_" % (index, label.replace(" ", ""))
            cases.append(Case(mark + "validator", "gate", world, index, [("gate", key20(1), tag)]))
            cases.append(Case(mark + "listed", "gate", world, index, [("gate", low_address(2), tag)]))
            cases.append(Case(mark + "user", "gate", world, index, [("gate", user, tag)]))
            cases.append(Case(mark + "stranger", "gate", world, index, [("gate", key20(50), tag)]))
        other = world_of(chain=0)
        cases.append(Case("g%d_chain_other_listed" % index, "gate", other, index, [("gate", OTHER_LISTED[2], 0x10)]))
        cases.append(Case("g%d_chain_other_low" % index, "gate", other, index, [("gate", low_address(1), 0x10)]))
        cases.append(Case("g%d_chain_other_stranger" % index, "gate", other, index, [("gate", key20(50), 0x10)]))
    return cases


def all_cases():
    return vote_cases() + gate_cases()


def vector_cases(count):
    rng = random.Random(0x94E0)
    cases = []
    for number in range(count):
        size = rng.randint(1, 8)
        stakes = {key32(seed): rng.randint(1, 50) for seed in range(1, size + 1)}
        validators = {key20(seed): key32(seed) for seed in range(1, size + 1)}
        members = {key32(seed) for seed in range(1, size + 1) if rng.random() > 0.15}
        if rng.random() < 0.3:
            validators[rng.choice((low_address(rng.randint(1, 3)), OTHER_LISTED[rng.randint(0, 2)]))] = key32(rng.randint(1, size))
        world = world_of(chain=rng.choice((3, 3, 0)), threshold=rng.choice((0, 0, 0, 1, 2)), apply_status=rng.choice((OK, OK, OK, 0x143)), validators=validators, members=members, stakes=stakes)
        ops = []
        for _ in range(rng.randint(1, 12)):
            signer = rng.choice([key20(rng.randint(1, size + 1)), key20(rng.randint(1, size)), low_address(rng.randint(1, 4)), OTHER_LISTED[rng.randint(0, 2)]])
            ops.append(("vote", signer, (rng.choice(U64_TAGS), rng.randint(1, 3))))
        cases.append(Case("v%04d" % number, "vector", world, number % 3, ops))
    return cases


PINS = (
    ("host_epoch", 0x2704db4, "4c8bb688380000", "mov r14,[rsi+0x3888]: active epoch word, Staking +0x48"),
    ("host_chain", 0x2704dc3, "0fb696f2080000", "movzx edx,byte [rsi+0x8f2]: chain byte"),
    ("host_chain_three", 0x2704de1, "80fa03", "cmp dl,3: picks static 0x577ae70, else 0x577aea0"),
    ("host_listed_lookup", 0x2704e3a, "e8214ecafe", "call 0x13a9c60: signer in the listed set"),
    ("host_validator_lookup", 0x2704e86, "ff15bce20603", "call through slot 0x5773148: 0x33690c0"),
    ("host_validator_ok", 0x2704e8c, "6681bc24080200008601", "cmp word status,0x186"),
    ("host_refuse", 0x2705189, "6641c7079100", "mov word [r15],0x91: neither listed nor validator"),
    ("host_tag_shift", 0x2704ee7, "488d48ee", "lea rcx,[rax-0x12]: raw tag to index"),
    ("host_tag_inline", 0x2704eef, "b84e000000", "mov eax,0x4e: raw tag below 0x12"),
    ("host_fast_b", 0x2704f02, "4883f80b", "cmp rax,0xb"),
    ("host_fast_20", 0x2704f0c, "4883f820", "cmp rax,0x20"),
    ("host_fast_4a", 0x2705009, "4883f84a", "cmp rax,0x4a"),
    ("host_fast_55", 0x2705013, "4883f855", "cmp rax,0x55"),
    ("host_fast_byte", 0x2705210, "80780801", "cmp byte [rax+8],1: index 0x4a only with this byte"),
    ("host_tracker", 0x2704f1e, "480510350000", "add rax,0x3510: vote tracker in the Exchange"),
    ("host_vote_plain", 0x2704fb2, "e8a9717aff", "call 0x1eac160: vote with the static set"),
    ("host_vote_cloned", 0x27050b4, "e8576e7aff", "call 0x1eabf10: vote with a clone of the static set"),
    ("host_pop_plain", 0x2704ff7, "e87447c2ff", "call 0x2329770: row pop after a pass"),
    ("host_pop_cloned", 0x27050f2, "e8196d7aff", "call 0x1eabe10: row pop with a clone"),
    ("host_none", 0x2704fb7, "83bc246804000074", "cmp dword result,0x74: 0x74 means no pass"),
    ("host_apply", 0x2705155, "e8e60dc5ff", "call 0x2355f40: apply after the pop"),
    ("host_applied_byte", 0x2705175, "41884702", "mov [r15+2],al: 1 applied, 0 only recorded"),
    ("tally_id_flag", 0x23299bb, "f60101", "test byte [rcx],1: voter has a validator key"),
    ("tally_listed_flag", 0x23299be, "0fb65121", "movzx edx,byte [rcx+0x21]: voter is listed"),
    ("tally_member", 0x2329c8d, "ff15a5a04403", "call through slot 0x5773d38: 0x3367530"),
    ("tally_row_size", 0x2329de5, "4c69a4246001000010010000", "imul r12,[rsp+0x160],0x110: tracker row size"),
    ("tally_key_size", 0x2329e3b, "4c69f0f0000000", "imul r14,rax,0xf0: action key size"),
    ("tally_vote_value", 0x2329fe4, "4881c3500a0000", "add rbx,0xa50: votes value area of the node"),
    ("tally_done", 0x2329fee, "4180bc240801000000", "cmp byte [r12+0x108],0: row already passed"),
    ("tally_before", 0x232a13e, "e8cdf4ffff", "call 0x2329610: quorum before the new vote"),
    ("tally_add_signer", 0x232a02c, "e82faa5300", "call 0x2864a60: listed signer into votes +0x18"),
    ("tally_add_id", 0x232a17c, "e89f935300", "call 0x2863520: validator key into votes +0"),
    ("tally_after", 0x232a1a5, "e866f4ffff", "call 0x2329610: quorum after the new vote"),
    ("tally_mark", 0x232a1b7, "41c684240801000001", "mov byte [r12+0x108],1"),
    ("tally_prune_limit", 0x232a42d, "4883f865", "cmp rax,0x65: tracker +0x28 at 101 rows"),
    ("quorum_stake", 0x232969b, "e8c0d40301", "call 0x3366b60: stake quorum on the validator keys"),
    ("quorum_listed", 0x2329719, "ff1539604403", "call through slot 0x576f758: 0x145a660"),
    ("quorum_and", 0x232972b, "4020dd", "and bpl,bl: both must hold"),
    ("listed_compare", 0x145a96e, "4c3b5618", "cmp r10,[rsi+0x18]: counted members against the static word"),
    ("listed_result", 0x145a972, "0f93c0", "setae al"),
    ("init_threshold_main", 0x145203b, "48c7431800000000", "mov qword [rbx+0x18],0"),
    ("init_word_main", 0x1452043, "48c7432001000000", "mov qword [rbx+0x20],1"),
    ("init_threshold_other", 0x145216b, "48c7431800000000", "mov qword [rbx+0x18],0"),
    ("init_word_other", 0x1452173, "48c7432001000000", "mov qword [rbx+0x20],1"),
    ("class_shift", 0x335ecb3, "488d488c", "lea rcx,[rax-0x74]"),
    ("class_inline", 0x335ecbb, "b814000000", "mov eax,0x14: word below 0x74 is VoteGlobal, index 20"),
    ("class_table", 0x335ecc4, "488d0d0dd522fd", "lea rcx,[rip]: class table 0x58c1d8"),
    ("gate_class_shift", 0x282ec91, "488d51ff", "lea rdx,[rcx-1]"),
    ("gate_class_two", 0x282ec97, "80f902", "cmp cl,2: classes 0 and 1 share an arm"),
    ("gate_validator", 0x282ecc6, "ff157c44f402", "call through slot 0x5773148: 0x33690c0"),
    ("gate_listed_bit", 0x282ecdf, "40f6c501", "test bpl,1: class 1 falls to the listed set"),
    ("gate_user", 0x282ed12, "e809fdf2ff", "call 0x275ea20"),
    ("gate_not_allowed", 0x282ed5f, "66c7037d00", "mov word [rbx],0x7d"),
    ("gate_not_validator", 0x282ee06, "66c7037b00", "mov word [rbx],0x7b"),
    ("gate_ok", 0x282ed55, "66c7038601", "mov word [rbx],0x186"),
)
NAMES = {
    0x2704D90: "host", 0x4E03DD0: "host_copy", 0x4E04300: "host_third",
    0x1EAC160: "vote_plain", 0x1EABF10: "vote_cloned", 0x1EABE10: "pop_cloned",
    0x45B0690: "vote_plain_copy", 0x45B0440: "vote_cloned_copy", 0x45B0340: "pop_cloned_copy",
    0x2329990: "tally", 0x48C5DE0: "tally_copy", 0x2329610: "quorum", 0x48C3E20: "quorum_copy",
    0x2329770: "row_pop", 0x48C45E0: "row_pop_copy", 0x145A660: "listed_count",
    0x282EC60: "gate", 0x48F5570: "gate_copy", 0x48F52E0: "gate_third",
    0x1451FB0: "listed_init_chain_3", 0x14520E0: "listed_init_other",
}
HELPERS = {0x13A9C60: "listed_lookup", 0x335ECB0: "action_class", 0x1B27F70: "action_compare", 0x23CAF20: "action_clone", 0x239E440: "action_drop", 0x2863520: "id_set_insert", 0x2864A60: "signer_set_insert", 0x2879910: "row_insert", 0x287A8E0: "vote_insert", 0x27E7970: "id_set_clone", 0x27E6C10: "signer_set_clone", 0x28673F0: "row_remove", 0x14CA7B0: "listed_build_insert"}
STUBS = {0x2355F40: "apply", 0x4CAA870: "apply_copy", 0x4CB3200: "apply_third", 0x33690C0: "validator_lookup", 0x3367530: "member_test", 0x3366B60: "stake_quorum", 0x275EA20: "user_resolve", 0x4D8B030: "user_resolve_copy", 0x4D8B3B0: "user_resolve_third"}
ACTION_NAMES = ("noop", "approveAgent", "batchModify", "cancel", "cancelByCloid", "claimRewards", "createSubAccount", "createVault", "evmRawTx", "ForceIncreaseEpochAction", "liquidate", "linkStakingUser", "modify", "NetChildVaultPositionsAction", "order", "registerReferrer", "RegisterValidatorAction", "CValidatorAction", "scheduleCancel", "setDisplayName", "VoteGlobalAction", "validatorL1Vote", "validatorL1Stream", "validatorL1UpdateReferenceOracle", "SetGlobalAction", "setReferrer", "spotDeploy", "spotUser", "spotSend", "SignValidatorSetUpdateAction", "subAccountModify", "subAccountTransfer", "subAccountSpotTransfer", "tokenDelegate", "twapCancel", "twapOrder", "updateIsolatedMargin", "topUpIsolatedOnlyMargin", "updateLeverage", "usdSend", "ValidatorSignWithdrawalAction", "vaultDistribute", "vaultModify", "vaultTransfer", "VoteEthDepositAction", "VoteEthFinalizedValidatorSetUpdateAction", "VoteEthFinalizedWithdrawalAction", "withdraw3", "VoteAppHash", "govPropose", "govVote", "usdClassTransfer", "multiSig", "convertToMultiSigUser", "approveBuilderFee", "startFeeTrial", "SystemBoleAction", "SystemSpotSendAction", "deployerSendToEvmForFrozenUser", "SystemUsdClassTransferAction", "CSignerAction", "cWithdraw", "cDeposit", "cUserModify", "reassessFees", "evmUserModify", "reserveRequestWeight", "finalizeEvmContract", "perpDeploy", "sendAsset", "SystemApproveBuilderFeeAction", "SystemSendAssetAction", "SystemAlignedQuoteSupplyDelta", "agentEnableDexAbstraction", "userDexAbstraction", "borrowLend", "sendToEvmWithData", "userPortfolioMargin", "userSetAbstraction", "agentSetAbstraction", "userOutcome", "gossipPriorityBid", "agentSendAsset", "hip3LiquidatorTransfer", "l1ValidatorVoteBridgeDeposit", "authorizeAqav2Role", "stakingLinkDisableTradingUser", "voteL1Hash")
RULES = {0: "validator signer only, else 0x7b", 1: "validator signer or listed address, else 0x7b", 2: "any signer", 3: "known user, resolved by 0x275ea20, else its status", 4: "refused, 0x7d"}
TAGS = (0x7B, 0x7D, 0x91)
SAMPLE = 1
VECTORS = 300
WORKERS = 4
MUTANT_CASES = 6
SURVIVED = "equal outcome on every picked case that reaches the row"
MUTANT_STATE = {}
MUTANT_STEP_LIMIT = 300000
SITES = {va: name for va, name in NAMES.items()}
SLOT_SITES = {0x5773200: "action_class", 0x576F758: "listed_count", 0x576F760: "listed_static_chain_3", 0x576F768: "listed_static_other"}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def text_of(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def status_rows(image):
    rows = []
    for tag in TAGS:
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        code = text_of(image, arm, 64)
        at = code.find(b"\x48\x8d\x35")
        text = ""
        if at >= 0:
            start = arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
            size = struct.unpack_from("<I", code, at + 8)[0] if code[at + 7] == 0xBA else 0
            text = text_of(image, start, min(size, 90)).decode("ascii", "replace")
        rows.append(("%#x" % tag, "%#x" % arm, text))
    return rows


def pin_rows(image):
    rows = []
    for name, va, data, meaning in PINS:
        got = text_of(image, va, len(data) // 2).hex()
        if got != data:
            raise EvidenceError("pin %s: %s" % (name, got))
        rows.append((name, "%#x" % va, data, meaning))
    return rows


def class_rows(image):
    rows = []
    table = text_of(image, CLASS_TABLE, len(ACTION_NAMES))
    arms = [CLASS_ARMS + struct.unpack_from("<i", image.blob, image.offset(CLASS_ARMS) + 4 * index)[0] for index in range(4)]
    for index, name in enumerate(ACTION_NAMES):
        kind = table[index]
        rows.append((index, "%#x" % (index + 0x74), kind, "%#x" % arms[0 if kind < 2 else kind - 1], RULES[kind], name))
    return rows


def listed_rows(harness):
    rows = []
    for chain in (3, 0):
        world = world_of(chain=chain)
        harness.prepare(world, 0)
        base = LISTED[chain]
        root, height, size, first, second = (harness.read(base + at) for at in (0, 8, 0x10, 0x18, 0x20))
        keys = [harness.data(item, 20).hex() for item in walk(harness.read, root, height, 20)]
        if len(keys) != size or set(keys) != {item.hex() for item in world["listed"]}:
            raise EvidenceError("listed set of chain %d" % chain)
        for key in keys:
            rows.append(("3" if chain == 3 else "not 3", "%#x" % base, "%#x" % INIT[chain], key, first, second))
    return rows


def caller_rows(image):
    base, text = image.text_bytes()
    rows = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if target in SLOT_SITES:
            rows.append((SLOT_SITES[target], "slot %#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
    for match in re.finditer(b"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        at = match.start()
        target = base + at + 7 + struct.unpack_from("<i", text, at + 3)[0]
        if target in SLOT_SITES:
            rows.append((SLOT_SITES[target], "load %#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 > len(text):
            break
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in SITES:
            rows.append((SITES[target], "direct", "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
    return sorted(rows)


def edits_for(image, rows):
    edits = []
    for row in rows:
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
    return edits


def first_failure(harness, cases, wants):
    for case, want in zip(cases, wants):
        try:
            if run_case(harness, case) != want:
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, TypeError, struct.error):
            return case
    return None


def spread(items, count):
    if len(items) <= count:
        return items
    head = items[:count // 2]
    rest = items[count // 2:]
    step = len(rest) / (count - count // 2)
    return head + [rest[int(index * step)] for index in range(count - count // 2)]


def mutant_job(job):
    va, kind, patch = job
    state = MUTANT_STATE
    picked = spread([case for case in state["order"] if va in state["reach"][case.name]], MUTANT_CASES)
    harness = Votes(state["image"], patch, state["cache"])
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases, reach, cost, harness, sample):
    wants = {case.name: spec_run(case) for case in cases}
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=harness.machine.cache)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return len(jobs), pool.map(mutant_job, jobs[::sample], 4)


def check_case(harness, case):
    harness.machine.seen = set()
    before = harness.machine.steps
    got = run_case(harness, case)
    want = spec_run(case)
    if got != want:
        raise EvidenceError("case %s: %s against %s" % (case.name, got, want))
    return got, harness.machine.seen, harness.machine.steps - before


def check_job(index):
    state = MUTANT_STATE
    harness = state.get("worker")
    if harness is None:
        harness = state["worker"] = Votes(state["image"])
    return check_case(harness, state["all"][index])


def analyse(image, mutate=True, vectors=VECTORS, cases=None, sample=SAMPLE):
    load_image.cached = image
    harness = Votes(image)
    named = cases if cases is not None else all_cases()
    generated = vector_cases(vectors)
    every = named + generated
    MUTANT_STATE.update(image=image, all=every)
    MUTANT_STATE.pop("worker", None)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        done = pool.map(check_job, range(len(every)), 8)
    rows, reach, cost = [], {}, {}
    for case, (got, items, steps) in zip(named, done):
        reach[case.name], cost[case.name] = items, steps
        rows.append((case, got))
    seen = set()
    for _, items, _ in done:
        seen |= items
    table = {}
    for target in sorted(NAMES):
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    result = dict(table=table, named=rows, vector_count=len(generated), pins=pin_rows(image), statuses=status_rows(image), classes=class_rows(image), listed=listed_rows(harness), sizes={target: image.exact_fde(target)[1] - target for target in NAMES}, helpers=[(HELPERS[va], "%#x" % va, image.exact_fde(va)[1] - va, sum(1 for at in seen if va <= at < image.exact_fde(va)[1])) for va in sorted(HELPERS)], stubs=[(STUBS[va], "%#x" % va, image.exact_fde(va)[1] - va) for va in sorted(STUBS)])
    if mutate:
        result["callers"] = caller_rows(image)
        result["edit_count"], result["mutations"] = run_mutants(image, table, named, reach, cost, harness, sample)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table, sizes = result["table"], result["sizes"]
    order = sorted(NAMES)
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in order for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in order])
    tsv("helpers.tsv", ("name", "address", "body_bytes", "reached_rows"), result["helpers"])
    tsv("stubs.tsv", ("name", "address", "body_bytes"), result["stubs"])
    tsv("constants.tsv", ("name", "address", "bytes", "meaning"), result["pins"])
    tsv("status-text.tsv", ("tag", "display_arm", "text"), result["statuses"])
    tsv("action-classes.tsv", ("index", "raw_tag", "class", "gate_arm", "rule", "name_from_dispatch_packets"), result["classes"])
    tsv("listed-sets.tsv", ("chain_byte", "static", "initializer", "address", "word_0x18", "word_0x20"), result["listed"])
    tsv("scenarios.tsv", ("case", "group", "copy", "results", "calls", "last_tracker"), [(case.name, case.kind, case.index, ";".join(",".join(str(part) for part in item) for item in got[0]), len(got[1]), repr(got[2][-1]) if got[2] else "") for case, got in result["named"]])
    groups = collections.Counter(case.kind for case, _ in result["named"])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "helpers": len(result["helpers"]), "stubs": len(result["stubs"]), "named_scenarios": len(result["named"]), "groups": dict(sorted(groups.items())), "vector_scenarios": result["vector_count"], "instructions": sum(len(items) for items in table.values()), "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "pins": len(result["pins"]), "action_classes": len(result["classes"])}
    if "mutations" in result:
        tsv("callers.tsv", ("function", "form", "site", "host"), result["callers"])
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
        items = result["mutations"]
        summary["mutations"] = {"edits_possible": result["edit_count"], "sample_step": SAMPLE, "total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
