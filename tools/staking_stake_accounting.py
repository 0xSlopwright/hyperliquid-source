#!/usr/bin/env python3
"""Map node #94 stake accounting and the active validator set from the delegate core to signer power.

0x398dc90 with 0x3c0e8b0 and 0x3c0f6e0 moves wei between user balance, delegation rows, per validator member rows and the
stake pair. 0x3990130 compounds rewards through it. 0x3c10fa0 with 0x3c11bd0 turns stake rows into the top N set and into
per mille signer power. The real bytes run in an interpreter inside this tool with every callee real: a state goes in through
the real CStaking msgpack reader 0x175f130, the functions run on that memory, the real writer 0x39908e0 gives the state back,
and a separately written rule list predicts every result, every recorder call and the written state byte for byte. Every reached
conditional row and immediate is mutated. No objdump or readelf output is parsed and the binary is never executed.

    python3 tools/staking_stake_accounting.py --out <dir>
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
STACK_SIZE = 0x8000
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

    def reset(self, used=HEAP_SIZE):
        """Refill the stack and the first `used` heap bytes; the rest must still be untouched."""
        self.stack[:] = self.fresh[0]
        self.heap[:used] = memoryview(self.fresh[1])[:used]

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
            return self.heap, addr - HEAP_BASE
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


REQUIRED = object()
ADDRESS_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 20 bytes"
HASH_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 32 bytes"
TIME_TEXT = "a formatted date and time string"
MAP_TEXT = "a map or a sequence of tuples"
ADDRESS = ("addr",)
HASH = ("hash",)
TIME = ("time",)
WEI = ("wei",)
U64 = ("u64",)
USIZE = ("usize",)
NONZERO = ("nonzero",)
BOOL = ("bool",)
TEXT = ("text",)
U16 = ("u16",)
IP = ("ip",)
UNIT = ("unit",)


def struct_of(name):
    return ("struct", name)


def map_of(key, value):
    return ("map", key, value)


def set_of(item):
    return ("set", item)


def seq_of(item):
    return ("seq", item)


def opt_of(item):
    return ("opt", item)


def tracker_of(name):
    return ("struct", name)


STAKES = struct_of("CValidatorStakes")
SIGNERS = set_of(ADDRESS)
STRUCTS = {
    "CStaking": (("stakes", struct_of("EpochTracker_stakes"), REQUIRED), ("allowed_validators", set_of(ADDRESS), REQUIRED), ("allow_all_validators", BOOL, REQUIRED), ("broadcasters", set_of(ADDRESS), REQUIRED), ("validator_to_profile", map_of(ADDRESS, struct_of("CValidatorProfile")), REQUIRED), ("delegations", struct_of("Delegations"), REQUIRED), ("proposals", map_of(HASH, struct_of("Proposal")), REQUIRED), ("stakes_decay_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("jailed_signers", struct_of("EpochTracker_signers"), REQUIRED), ("jvt", struct_of("RawSignatureTracker"), "jail vote tracker"), ("jail_until", map_of(ADDRESS, TIME), REQUIRED), ("signer_to_last_manual_unjail_time", map_of(ADDRESS, TIME), REQUIRED), ("native_token_reserve", opt_of(WEI), None), ("stage_reward_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("validator_to_staged_rewards", map_of(ADDRESS, WEI), REQUIRED), ("distribute_reward_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("user_states", map_of(ADDRESS, struct_of("UserState")), REQUIRED), ("pending_withdrawals", struct_of("PendingWithdrawals"), REQUIRED), ("self_delegation_requirement", WEI, REQUIRED), ("disabled_validators", set_of(ADDRESS), ()), ("disabled_node_ips", set_of(IP), ()), ("validator_to_state", map_of(ADDRESS, struct_of("CValidatorState")), ())),
    "EpochTracker_stakes": (("epoch_values", struct_of("EpochValues_stakes"), REQUIRED), ("current", STAKES, REQUIRED), ("period", NONZERO, REQUIRED), ("n_keep", USIZE, REQUIRED), ("current_round", U64, REQUIRED)),
    "EpochValues_stakes": (("initial_round", U64, REQUIRED), ("round_to_val", map_of(U64, STAKES), REQUIRED)),
    "EpochTracker_signers": (("epoch_values", struct_of("EpochValues_signers"), REQUIRED), ("current", SIGNERS, REQUIRED), ("period", NONZERO, REQUIRED), ("n_keep", USIZE, REQUIRED), ("current_round", U64, REQUIRED)),
    "EpochValues_signers": (("initial_round", U64, REQUIRED), ("round_to_val", map_of(U64, SIGNERS), REQUIRED)),
    "CValidatorStakes": (("max_n_validators", opt_of(USIZE), None), ("validator_to_stake", map_of(ADDRESS, struct_of("CValidatorStake")), REQUIRED)),
    "CValidatorStake": (("effective", WEI, 0), ("target", WEI, 0)),
    "CValidatorProfile": (("node_ip", IP, REQUIRED), ("name", TEXT, REQUIRED), ("description", TEXT, REQUIRED), ("delegations_disabled", BOOL, False), ("commission_bps", U64, 10000), ("signer", ADDRESS, REQUIRED)),
    "Delegations": (("user_to_delegations", map_of(ADDRESS, map_of(ADDRESS, struct_of("Delegation"))), REQUIRED), ("validator_to_state", map_of(ADDRESS, struct_of("ValidatorState")), REQUIRED)),
    "Delegation": (("t", TIME, REQUIRED), ("w", WEI, REQUIRED)),
    "ValidatorState": (("total_delegated", WEI, REQUIRED), ("delegator_to_epoch_delegation", map_of(ADDRESS, struct_of("EpochDelegation")), REQUIRED)),
    "EpochDelegation": (("c", WEI, REQUIRED), ("m", WEI, REQUIRED), ("e", U64, REQUIRED)),
    "Proposal": (("title", TEXT, REQUIRED), ("description", TEXT, REQUIRED), ("end", TIME, REQUIRED), ("votes", map_of(ADDRESS, struct_of("Vote")), REQUIRED), ("proposer", ADDRESS, REQUIRED), ("quorum", U64, REQUIRED), ("category", ("names", ("accelerated", "constitutional", "ecosystem", "electoral")), REQUIRED)),
    "Vote": (("choice", ("names", ("yes", "no", "abstain")), REQUIRED), ("weight", U64, REQUIRED)),
    "BucketGuard": (("last_bucket", U64, REQUIRED), ("bucket_millis", NONZERO, REQUIRED)),
    "RawSignatureTracker": (("name", TEXT, REQUIRED), ("hsc", UNIT, None), ("i", map_of(ADDRESS, struct_of("UniqueKeyState")), REQUIRED)),
    "UserState": (("b", WEI, 0), ("l", opt_of(TIME), None)),
    "PendingWithdrawals": (("queue", map_of(TIME, seq_of(struct_of("CWithdrawal"))), REQUIRED), ("user_to_total_withdrawal", map_of(ADDRESS, struct_of("TotalWithdrawal")), REQUIRED)),
    "CWithdrawal": (("user", ADDRESS, REQUIRED), ("wei", WEI, REQUIRED)),
    "TotalWithdrawal": (("wei", WEI, REQUIRED), ("n", USIZE, REQUIRED)),
    "CValidatorState": (("register_time", TIME, REQUIRED), ("last_signer_change_time", TIME, REQUIRED), ("delegations_blocked", BOOL, REQUIRED)),
    "UniqueKeyState": (("arq", BOOL, REQUIRED), ("qst", ("names", ("Q", "N")), "N"), ("vts", map_of(("nil_key",), ("opaque",)), REQUIRED)),
}
NAME_OF = {"EpochTracker_stakes": "EpochTracker", "EpochTracker_signers": "EpochTracker", "EpochValues_stakes": "EpochValues", "EpochValues_signers": "EpochValues"}
SKIP_WHEN_DEFAULT = {"UserState"}
ARRAY_REQUIRED = {"native_token_reserve", "max_n_validators"}


def wire_name(name):
    return NAME_OF.get(name, name)


def stamp(text):
    """A time text in the shortest of the 0, 3, 6, 9 fraction forms."""
    if "." not in text:
        return text
    head, tail = text.split(".")
    nanos = int(tail.ljust(9, "0"))
    if nanos == 0:
        return head
    if nanos % 1000000 == 0:
        return "%s.%03d" % (head, nanos // 1000000)
    if nanos % 1000 == 0:
        return "%s.%06d" % (head, nanos // 1000)
    return "%s.%09d" % (head, nanos)


def order_of(kind, value):
    if kind == IP:
        return (0, value[1]) if value[0] == "Ip" else (1, value[1])
    return value


def default_for(kind, rule):
    if rule == "jail vote tracker":
        return dict(name=rule, hsc=None, i=[])
    if kind == opt_of(WEI) or kind[0] == "opt":
        return None
    if isinstance(rule, tuple):
        return []
    return rule


def canon(kind, value):
    """Fill defaults and put maps and sets in their sorted order."""
    tag = kind[0]
    if tag == "struct":
        out = {}
        for field, inner, rule in STRUCTS[kind[1]]:
            if field in value:
                out[field] = canon(inner, value[field])
            else:
                out[field] = default_for(inner, rule)
        return out
    if tag == "map":
        rows = [(canon(kind[1], key), canon(kind[2], item)) for key, item in value]
        return sorted(rows, key=lambda row: order_of(kind[1], row[0]))
    if tag == "set":
        return sorted({tuple(item) if kind[1] == IP else item for item in value}, key=lambda item: order_of(kind[1], item))
    if tag == "seq":
        return [canon(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else canon(kind[1], value)
    if kind == TIME:
        return stamp(value)
    if kind == IP:
        return tuple(value)
    if kind == ADDRESS or kind == HASH:
        return value.lower()
    return value


def mp_head(size, small, wide16, wide32):
    if size < 16:
        return bytes([small | size])
    if size < 0x10000:
        return bytes([wide16]) + size.to_bytes(2, "big")
    return bytes([wide32]) + size.to_bytes(4, "big")


def mp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_text(text):
    data = text.encode()
    if len(data) < 32:
        return bytes([0xA0 | len(data)]) + data
    if len(data) < 256:
        return bytes([0xD9, len(data)]) + data
    return b"\xda" + len(data).to_bytes(2, "big") + data


def emit(kind, value, named, human):
    """Canonical value to msgpack, by the rule list of this packet."""
    tag = kind[0]
    if tag == "struct":
        rows = STRUCTS[kind[1]]
        kept = [row for row in rows if not (kind[1] in SKIP_WHEN_DEFAULT and value[row[0]] == row[2])]
        size = len(kept)
        out = mp_head(size, 0x80, 0xDE, 0xDF) if named else mp_head(size, 0x90, 0xDC, 0xDD)
        for field, inner, _ in kept:
            if named:
                out += mp_text(field)
            out += emit(inner, value[field], named, human)
        return out
    if tag == "map":
        out = mp_head(len(value), 0x90, 0xDC, 0xDD)
        for key, item in value:
            out += b"\x92" + emit(kind[1], key, named, human) + emit(kind[2], item, named, human)
        return out
    if tag in ("set", "seq"):
        return mp_head(len(value), 0x90, 0xDC, 0xDD) + b"".join(emit(kind[1], item, named, human) for item in value)
    if tag == "opt":
        return b"\xc0" if value is None else emit(kind[1], value, named, human)
    if kind == UNIT:
        return b"\x90" if value is None else mp_text(value)
    if tag == "bool":
        return b"\xc3" if value else b"\xc2"
    if tag in ("u64", "usize", "nonzero", "wei", "u16"):
        return mp_uint(value)
    if kind == QST and value == "Q":
        return b"\x81" + mp_text("Q") + b"\xc0"
    if tag in ("addr", "hash", "time", "text", "names"):
        return mp_text(value)
    if kind == IP:
        if value[0] == "LocalNode":
            return b"\x81" + mp_text("LocalNode") + mp_uint(value[1])
        if human:
            return b"\x81" + mp_text("Ip") + mp_text(value[1])
        return b"\x81" + mp_text("Ip") + b"\x94" + b"".join(mp_uint(int(part)) for part in value[1].split("."))
    raise EvidenceError("no rule for %s" % (kind,))


def plain(kind, value):
    """Canonical value to the object tree of the JSON form."""
    tag = kind[0]
    if tag == "struct":
        return {field: plain(inner, value[field]) for field, inner, _ in STRUCTS[kind[1]] if not (kind[1] in SKIP_WHEN_DEFAULT and value[field] == _)}
    if tag == "map":
        return [[plain(kind[1], key), plain(kind[2], item)] for key, item in value]
    if tag in ("set", "seq"):
        return [plain(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else plain(kind[1], value)
    if kind == IP:
        return {value[0]: value[1]}
    if kind == QST and value == "Q":
        return {"Q": None}
    return value


ROOT = struct_of("CStaking")
QST = ("names", ("Q", "N"))


def wire_input(kind, value, named=True):
    """Input bytes for the msgpack decoder: friendly values, strings for Ip, no skipped fields."""
    tag = kind[0]
    if tag == "struct":
        rows = [row for row in STRUCTS[kind[1]] if row[0] in value]
        out = mp_head(len(rows), 0x80, 0xDE, 0xDF) if named else mp_head(len(rows), 0x90, 0xDC, 0xDD)
        for field, inner, _ in rows:
            if named:
                out += mp_text(field)
            out += wire_input(inner, value[field], named)
        return out
    if tag == "map":
        out = mp_head(len(value), 0x90, 0xDC, 0xDD)
        for key, item in value:
            out += b"\x92" + wire_input(kind[1], key, named) + wire_input(kind[2], item, named)
        return out
    if tag in ("set", "seq"):
        return mp_head(len(value), 0x90, 0xDC, 0xDD) + b"".join(wire_input(kind[1], item, named) for item in value)
    if tag == "opt":
        return b"\xc0" if value is None else wire_input(kind[1], value, named)
    if kind == IP:
        return b"\x81" + mp_text(value[0]) + (mp_text(value[1]) if value[0] == "Ip" else mp_uint(value[1]))
    if kind == UNIT:
        return b"\x90" if value is None else mp_text(value)
    return emit(kind, value, True, True)


def json_input(kind, value):
    tag = kind[0]
    if tag == "struct":
        return {field: json_input(inner, value[field]) for field, inner, _ in STRUCTS[kind[1]] if field in value}
    if tag == "map":
        return [[json_input(kind[1], key), json_input(kind[2], item)] for key, item in value]
    if tag in ("set", "seq"):
        return [json_input(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else json_input(kind[1], value)
    if kind == IP:
        return {value[0]: value[1]}
    if kind == QST and value == "Q":
        return {"Q": None}
    return value


def address(seed):
    return "0x" + bytes((seed * 7 + index * 13 + 1) & 0xFF for index in range(20)).hex()


def digest(seed):
    return "0x" + bytes((seed * 11 + index * 5 + 3) & 0xFF for index in range(32)).hex()


TIME_A = "2024-01-02T03:04:05.123456789"
TIME_B = "2025-11-30T23:59:59.5"
TIME_C = "2023-06-07T08:09:10"
GUARD_1 = dict(last_bucket=1700000000000, bucket_millis=60000)
GUARD_2 = dict(last_bucket=1700000001000, bucket_millis=70000)
GUARD_3 = dict(last_bucket=1700000002000, bucket_millis=80000)


def stakes_row(seed):
    return dict(max_n_validators=seed + 21, validator_to_stake=[[address(seed), dict(effective=seed * 1000 + 1, target=seed * 1000 + 2)], [address(seed + 1), dict(effective=seed * 1000 + 3, target=seed * 1000 + 4)]])


def full_state():
    return dict(
        stakes=dict(epoch_values=dict(initial_round=4001, round_to_val=[[4002, stakes_row(3)], [4003, dict(validator_to_stake=[[address(9), dict(effective=9, target=0)]])]]), current=stakes_row(5), period=86401, n_keep=7, current_round=4004),
        allowed_validators=[address(1), address(2)], allow_all_validators=True, broadcasters=[address(3)],
        validator_to_profile=[[address(4), dict(node_ip=("Ip", "10.20.30.40"), name="alpha", description="first", delegations_disabled=True, commission_bps=512, signer=address(5))], [address(6), dict(node_ip=("LocalNode", 9), name="b", description="", signer=address(7))]],
        delegations=dict(user_to_delegations=[[address(8), [[address(4), dict(t=TIME_A, w=900)], [address(6), dict(t=TIME_B, w=901)]]]], validator_to_state=[[address(4), dict(total_delegated=902, delegator_to_epoch_delegation=[[address(8), dict(c=903, m=904, e=905)]])]]),
        proposals=[[digest(1), dict(title="raise", description="more", end=TIME_B, votes=[[address(1), dict(choice="yes", weight=906)], [address(2), dict(choice="abstain", weight=907)]], proposer=address(1), quorum=908, category="ecosystem")]],
        stakes_decay_bucket_guard=dict(GUARD_1),
        jailed_signers=dict(epoch_values=dict(initial_round=5001, round_to_val=[[5002, [address(10), address(11)]]]), current=[address(12)], period=5003, n_keep=5004, current_round=5005),
        jvt=dict(name="votes", hsc=None, i=[[address(13), dict(arq=True, qst="N", vts=[])]]),
        jail_until=[[address(14), TIME_A], [address(15), TIME_C]], signer_to_last_manual_unjail_time=[[address(16), TIME_B]], native_token_reserve=909,
        stage_reward_bucket_guard=dict(GUARD_2), validator_to_staged_rewards=[[address(17), 910], [address(18), 911], [address(19), 912]], distribute_reward_bucket_guard=dict(GUARD_3),
        user_states=[[address(20), dict(b=913, l=TIME_A)], [address(21), dict(b=914)], [address(22), dict(l=TIME_B)], [address(23), dict()]],
        pending_withdrawals=dict(queue=[[TIME_B, [dict(user=address(24), wei=915), dict(user=address(25), wei=916)]], [TIME_A, [dict(user=address(26), wei=917)]]], user_to_total_withdrawal=[[address(24), dict(wei=1831, n=2)]]),
        self_delegation_requirement=10000000000000,
        disabled_validators=[address(27)], disabled_node_ips=[("Ip", "1.2.3.4"), ("LocalNode", 200), ("Ip", "1.2.3.3")],
        validator_to_state=[[address(28), dict(register_time=TIME_A, last_signer_change_time=TIME_B, delegations_blocked=True)]])


def least_state():
    return dict(
        stakes=dict(epoch_values=dict(initial_round=0, round_to_val=[]), current=dict(validator_to_stake=[]), period=1, n_keep=0, current_round=0),
        allowed_validators=[], allow_all_validators=False, broadcasters=[], validator_to_profile=[], delegations=dict(user_to_delegations=[], validator_to_state=[]), proposals=[],
        stakes_decay_bucket_guard=dict(last_bucket=0, bucket_millis=1), jailed_signers=dict(epoch_values=dict(initial_round=0, round_to_val=[]), current=[], period=1, n_keep=0, current_round=0),
        jail_until=[], signer_to_last_manual_unjail_time=[], stage_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1), validator_to_staged_rewards=[], distribute_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1),
        user_states=[], pending_withdrawals=dict(queue=[], user_to_total_withdrawal=[]), self_delegation_requirement=0)


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

CORE = 0x398DC90
UNDELEGATE = 0x3C0E8B0
DELEGATE = 0x3C0F6E0
SINK = 0x3990130
POWER = 0x3C10FA0
ACTIVE = 0x3C11BD0
SLOT_RECORDER = 0x5773190
SLOT_POWER = 0x5775128
SLOT_CORE = 0x5774D20
SLOT_LIMIT = 0x576E118
SEC_SEVERE = 0x3C1ADA0
SINK_FAIL = 0x3999770
RECORDER_SUB = 0x56DFD90
RECORDER_ADD = 0x56DFD78
OVERLAY_LOW = 0x5786000
OVERLAY_HIGH = 0x5788000
ROW_AT = HEAP_BASE + 0x3000
CORE_OUT = HEAP_BASE + 0x3200
SINK_OUT = HEAP_BASE + 0x3300
BLOCK_AT = HEAP_BASE + 0x3400
POWER_OUT = HEAP_BASE + 0x3500
U64_MAX = (1 << 64) - 1
LOCK_TABLE = 0x20BE20
OK = 0x186
FOUNDATION = {
    1: ("0x7db9972a235370a311d0ae3dfc545a954c786599", "0xa40cf273de4f77278b911dd4c6a023d60647d979", "0xa89a7f8ab7bcf9c57542e22dc0e4b768b0101762", "0xf027b2abfa8de836d8cdcce22af88bb8aacef849"),
    2: ("0x172054cfc01b32effe0bf6af7a15b36e1ad730b3", "0x3c83a5cae32a05e88ca6a0350edb540194851a76", "0x4dbf394da4b348b88e8090d22051af83e4cbaef4", "0x946bf3135c7d15e4462b510f74b6e304aabb5b21"),
    3: ("0x5ac99df645f3414876c816caa18b2d234024b487", "0x66be52ec79f829cc88e5778a255e2cb9492798fd", "0x80f0cd23da5bf3a0101110cfd0f89c8a69a1384d", "0xa82fe73bbd768bc15d1ef2f6142a21ff8bd762ad", "0xdf35aee8ef5658686142acd1e5ab5dbcdf8c51e8"),
}
LOCK_SECONDS = {0: 604800, 1: 120, 2: 120, 3: 86400}
NOW = "2025-03-04T05:06:07.5"
BEFORE = "2025-03-04T05:06:07.499999999"
AFTER = "2025-03-04T05:06:07.500000001"
LATER = "2025-03-05T00:00:00"
EARLIER = "2024-12-31T23:59:59"


def parse_time(text):
    head, _, tail = text.partition(".")
    return datetime.datetime.strptime(head, "%Y-%m-%dT%H:%M:%S"), int(tail.ljust(9, "0")) if tail else 0


def add_seconds(text, seconds):
    when, nanos = parse_time(text)
    head = (when + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S")
    return stamp("%s.%09d" % (head, nanos))


class Book:
    """Spec state: dicts over a canonical CStaking value, back to canonical form for emit."""

    def __init__(self, value):
        self.value = copy.deepcopy(value)

    def rows(self, *path):
        node = self.value
        for key in path:
            node = node[key]
        return node


def find(rows, key):
    for row in rows:
        if row[0] == key:
            return row[1]
    return None


def place(rows, key, item):
    rows.append([key, item])
    rows.sort(key=lambda row: row[0])
    return item


def remove(rows, key):
    rows[:] = [row for row in rows if row[0] != key]


class Log:
    def __init__(self):
        self.rows = []

    def add(self, *row):
        self.rows.append(row)


def latest_key(tracker):
    low, cur = tracker["epoch_values"]["initial_round"], tracker["current_round"]
    end = min(low + 2000, U64_MAX)
    start = low if cur < end else max(cur - 200, low)
    keys = [row[0] for row in tracker["epoch_values"]["round_to_val"] if row[0] <= start]
    return keys[-1] if keys else None


def sat_sub(left, right, log):
    if left < right:
        log.add("under")
        return 0
    return left - right


def sat_add(left, right, log):
    if left + right > U64_MAX:
        log.add("over")
        return U64_MAX
    return left + right


def spec_delegate(value, available, wei, key, now, user, validator, chain, keep, log):
    if available < wei:
        return 0xFC
    states = value["user_states"]
    row = find(states, user)
    if row is None:
        row = place(states, user, dict(b=0, l=None))
    row["b"] = sat_sub(row["b"], wei, log)
    lock = LOCK_SECONDS[chain]
    delegations = value["delegations"]
    inner = find(delegations["user_to_delegations"], user)
    if inner is None:
        inner = place(delegations["user_to_delegations"], user, [])
    item = find(inner, validator)
    if item is None:
        place(inner, validator, dict(t=now if keep else add_seconds(now, lock), w=wei))
    else:
        item["w"] = sat_add(item["w"], wei, log)
        if not keep:
            item["t"] = add_seconds(now, lock)
    state = find(delegations["validator_to_state"], validator)
    if state is None:
        state = place(delegations["validator_to_state"], validator, dict(total_delegated=0, delegator_to_epoch_delegation=[]))
    state["total_delegated"] = sat_add(state["total_delegated"], wei, log)
    member = find(state["delegator_to_epoch_delegation"], user)
    if member is None:
        place(state["delegator_to_epoch_delegation"], user, dict(c=wei, m=0, e=key))
    else:
        if member["e"] != key:
            member["e"], member["m"] = key, member["c"]
        member["c"] = sat_add(member["c"], wei, log)
    return OK


def spec_undelegate(value, tag, floor, wei, key, now, user, validator, log):
    delegations = value["delegations"]
    inner = find(delegations["user_to_delegations"], user)
    if inner is None:
        return 0xFE
    item = find(inner, validator)
    if item is None or item["w"] < wei:
        return 0xFE
    if tag == 0:
        if parse_time(item["t"]) > parse_time(now):
            return 0xFF
        if item["w"] - wei < floor:
            return 0x130
    row = find(value["user_states"], user)
    if row is None:
        row = place(value["user_states"], user, dict(b=0, l=None))
    left = item["w"] - wei
    item["w"] = left
    row["b"] = sat_add(row["b"], wei, log)
    if left == 0:
        remove(inner, validator)
        if not inner:
            remove(delegations["user_to_delegations"], user)
    state = find(delegations["validator_to_state"], validator)
    if state is None:
        state = place(delegations["validator_to_state"], validator, dict(total_delegated=0, delegator_to_epoch_delegation=[]))
    state["total_delegated"] = sat_sub(state["total_delegated"], wei, log)
    members = state["delegator_to_epoch_delegation"]
    member = find(members, user)
    if member is None:
        member = place(members, user, dict(c=0, m=0, e=key))
    left = sat_sub(member["c"], wei, log)
    member["c"] = left
    if member["e"] == key:
        member["m"] = min(member["m"], left)
    else:
        member["e"], member["m"] = key, left
    if left == 0:
        remove(members, user)
        if not members:
            remove(delegations["validator_to_state"], validator)
    return OK


def stake_row(value, validator):
    return find(value["stakes"]["current"]["validator_to_stake"], validator)


def spec_core(value, tag, word, wei, now, user, validator, chain, log):
    stake = stake_row(value, validator)
    if stake is None:
        return 0x91
    key = latest_key(value["stakes"])
    if key is None:
        return 0x97
    if tag != 2:
        status = spec_undelegate(value, tag, word, wei, key, now, user, validator, log)
        if status != OK:
            return status
        stake["target"] = sat_sub(stake["target"], wei, log)
        stake["effective"] = min(stake["effective"], stake["target"])
        if user == validator:
            state = find(value["validator_to_state"], validator)
            if state is not None:
                inner = find(value["delegations"]["user_to_delegations"], user)
                item = find(inner, validator) if inner is not None else None
                if item is None or item["w"] < value["self_delegation_requirement"]:
                    state["delegations_blocked"] = True
        return OK
    if not word & 1:
        profile = find(value["validator_to_profile"], validator)
        if profile is not None and profile["delegations_disabled"]:
            return 0xFD
    state = find(value["validator_to_state"], validator)
    if state is None:
        return 0x91
    if state["delegations_blocked"]:
        return 0xFD
    row = find(value["user_states"], user)
    balance = row["b"] if row is not None else 0
    pending = find(value["pending_withdrawals"]["user_to_total_withdrawal"], user)
    held = pending["wei"] if pending is not None else 0
    status = spec_delegate(value, max(balance - held, 0), wei, key, now, user, validator, chain, bool(word & 1), log)
    if status != OK:
        return status
    if stake["target"] + wei > U64_MAX:
        log.add("severe", 0xBE)
    else:
        stake["target"] += wei
    return OK


def spec_sink(value, rows, now, chain, log):
    merged = {}
    for amount, user, validator, kind in rows:
        if kind == 2:
            break
        key = (user, kind)
        merged[key] = sat_add(merged.get(key, 0), amount, log)
        status = spec_core(value, 2, 1, amount, now, user, validator, chain, log)
        if status != OK:
            log.add("sink_failed", status)
    return sorted(merged.items())


def spec_active(value, stakes, chain):
    members = FOUNDATION[chain]
    rows = [(row[1]["effective"], row[0]) for row in stakes["validator_to_stake"]]
    rows.sort(key=lambda row: (row[1] not in members, -row[0], row[1]))
    left = stakes["max_n_validators"] if stakes["max_n_validators"] is not None else U64_MAX
    picked, live = {}, False
    floor = value["self_delegation_requirement"]
    users = value["delegations"]["user_to_delegations"]
    for amount, validator in rows:
        if left == 0:
            break
        if find(value["validator_to_profile"], validator) is None:
            continue
        if validator not in members and floor != 0:
            inner = find(users, validator)
            item = find(inner, validator) if inner is not None else None
            if item is None or item["w"] < floor:
                continue
        live = live or amount != 0
        picked[validator] = amount
        left -= 1
    if not live:
        for validator in members:
            picked[validator] = picked.get(validator, 0) + 1
    return picked


def spec_power(value, stakes, chain):
    members = FOUNDATION[chain]
    picked = spec_active(value, stakes, chain)
    order = sorted(picked)
    total = sum(picked.values())
    done, every, inside, top = True, 0, 0, 0
    for validator in order:
        amount = picked[validator]
        if total == 0 or amount * 1000 > U64_MAX:
            done = False
            break
        share = amount * 1000 // total
        picked[validator] = share
        if validator in members:
            inside += share
            top = max(top, share)
        every += share
    if done:
        need = 2 * every + 3 * top - 3 * inside
        if need >= 0:
            extra = -(-(need + 1) // (len(members) - 3))
            for validator in members:
                picked[validator] = picked.get(validator, 0) + extra
    out = {}
    for validator in sorted(picked):
        profile = find(value["validator_to_profile"], validator)
        signer = profile["signer"] if profile is not None else validator
        out[signer] = picked[validator]
    return sorted(out.items())


def walk_tree(harness, root, height, keys, stride, length, edges, read_row):
    rows = []

    def go(node, level):
        count = harness.read(node + length, 2)
        for index in range(count):
            if level:
                go(harness.read(node + edges + index * 8), level - 1)
            rows.append(read_row(node, index, harness.data(node + keys + index * stride, stride)))
        if level:
            go(harness.read(node + edges + count * 8), level - 1)

    if root:
        go(root, height)
    return rows


class Case:
    def __init__(self, name, kind, state, ops, chain=3, stakes=None):
        self.name, self.kind, self.state, self.ops, self.chain, self.stakes = name, kind, state, ops, chain, stakes


def overlay_init(self):
    low, high = OVERLAY_LOW, OVERLAY_HIGH
    over = bytearray(high - low)
    statics = self.statics
    for at in range(low, high, 8):
        if at in statics:
            over[at - low:at - low + 8] = statics[at].to_bytes(8, "little")
        else:
            try:
                offset = self.image.offset(at)
            except EvidenceError:
                continue
            over[at - low:at - low + 8] = self.image.blob[offset:offset + 8]
    self.overlay, self.overlay_fresh = over, bytes(over)


def locate(self, addr, count):
    if self.stack_base <= addr and addr + count <= STACK_TOP:
        return self.stack, addr - self.stack_base
    if HEAP_BASE <= addr and addr + count <= HEAP_BASE + HEAP_SIZE:
        return self.heap, addr - HEAP_BASE
    if OVERLAY_LOW <= addr and addr + count <= OVERLAY_HIGH:
        return self.overlay, addr - OVERLAY_LOW
    return None, 0


Memory.locate = locate
Memory.overlay_init = overlay_init
Memory.overlay = None


class Book2(Harness):
    def __init__(self, image, patches=None, cache=None):
        Harness.__init__(self, image, patches, cache)
        machine = self.machine
        machine.real = Stubbed()
        image.static_view()[SLOT_RECORDER] = MARK_BASE + SLOT_RECORDER
        machine.memory.overlay_init()
        machine.slots[MARK_BASE + SLOT_RECORDER] = self.on_recorder
        machine.calls[SEC_SEVERE] = self.on_severe
        machine.calls[SINK_FAIL] = self.on_sink_fail
        self.log = Log()
        self.snapshots = {}
        self.times = {}

    def fresh(self):
        Harness.fresh(self)
        memory = self.machine.memory
        memory.overlay[:] = memory.overlay_fresh

    def on_recorder(self, machine):
        at = machine.regs[RSI]
        self.log.add({RECORDER_SUB: "under", RECORDER_ADD: "over"}[at])

    def on_severe(self, machine):
        self.log.add("severe", self.read(machine.regs[RDI], 2))

    def on_sink_fail(self, machine):
        self.log.add("sink_failed", self.read(machine.regs[RDI], 2))

    def time_bytes(self, text):
        text = stamp(text)
        if text not in self.times:
            state = least_state()
            state["validator_to_state"] = [[address(1), dict(register_time=text, last_signer_change_time=text, delegations_blocked=False)]]
            if self.decode_rmp(wire_input(ROOT, state)) != ("ok",):
                raise EvidenceError("time fixture refused")
            self.times[text] = self.data(self.read(DECODED + 0x278) + 0xE4, 12)
        return self.times[text]

    def load(self, data):
        got = self.snapshots.get(data)
        memory = self.machine.memory
        if got is None:
            result = self.decode_rmp(data)
            if result != ("ok",):
                raise EvidenceError("fixture refused: %s" % (result,))
            self.snapshots[data] = (bytes(memory.heap[:HEAP_USED]), bytes(memory.overlay), self.top, dict(self.live))
            return
        heap, over, self.top, live = got
        memory.stack[:] = memory.fresh[0]
        memory.heap[:HEAP_USED] = heap
        memory.overlay[:] = over
        self.live = dict(live)

    def put_row(self, tag, word, wei, now, user, validator, chain):
        self.write(ROW_AT, tag)
        self.write(ROW_AT + 8, word)
        self.write(ROW_AT + 0x10, wei)
        self.put(ROW_AT + 0x18, now)
        self.put(ROW_AT + 0x24, bytes.fromhex(user[2:]))
        self.put(ROW_AT + 0x38, bytes.fromhex(validator[2:]))
        self.write(ROW_AT + 0x4C, chain, 1)

    def core(self, tag, word, wei, now, user, validator, chain):
        self.put_row(tag, word, wei, now, user, validator, chain)
        self.machine.run(CORE, {RDI: CORE_OUT, RSI: DECODED, RDX: ROW_AT})
        return self.read(CORE_OUT, 2)

    def sink(self, rows, now, chain):
        size = len(rows)
        pointer = self.alloc(max(size, 1) * 0x38)
        for index, (amount, user, validator, kind) in enumerate(rows):
            row = pointer + index * 0x38
            self.write(row, amount)
            self.put(row + 8, bytes.fromhex(user[2:]))
            self.put(row + 0x1C, bytes.fromhex(validator[2:]))
            self.write(row + 0x30, kind, 1)
        vector = ROW_AT + 0x80
        self.write(vector, max(size, 1))
        self.write(vector + 8, pointer)
        self.write(vector + 0x10, size)
        self.put(BLOCK_AT + 0x60, now)
        self.machine.run(SINK, {RDI: SINK_OUT, RSI: DECODED, RDX: chain, RCX: BLOCK_AT, R8: vector})

        def row_of(node, index, key):
            return (("0x" + key[:20].hex(), key[20]), self.read(node + 8 + index * 8))

        return walk_tree(self, self.read(SINK_OUT), self.read(SINK_OUT + 8), 0x64, 0x15, 0x62, 0x150, row_of)

    def power_map(self, entry, chain):
        self.machine.run(entry, {RDI: POWER_OUT, RSI: DECODED, RDX: chain, RCX: DECODED})

        def row_of(node, index, key):
            return ("0x" + key.hex(), self.read(node + 8 + index * 8))

        return walk_tree(self, self.read(POWER_OUT), self.read(POWER_OUT + 8), 0x60, 0x14, 0x13E, 0x140, row_of)

    def final(self):
        return self.pack(1, 1)


class Stubbed:
    """Every code address runs for real, but for the two sinks of failure text."""

    def __contains__(self, va):
        return va < 0x6000000 and va != SEC_SEVERE and va != SINK_FAIL


def run_case(harness, case):
    harness.log = Log()
    data = wire_input(ROOT, case.state)
    times = {}
    for op in case.ops:
        if op[0] in ("core", "sink"):
            times[op[-1]] = harness.time_bytes(op[-1])
    harness.load(data)
    out = []
    for op in case.ops:
        name = op[0]
        if name == "core":
            _, tag, word, wei, user, validator, chain, when = op
            out.append(harness.core(tag, word, wei, times[when], user, validator, chain))
        elif name == "sink":
            _, rows, chain, when = op
            out.append(harness.sink(rows, times[when], chain))
        elif name == "power":
            out.append(harness.power_map(POWER, op[1]))
        elif name == "active":
            out.append(sorted(harness.power_map(ACTIVE, op[1])))
    return (tuple(map(repr, out)), tuple(map(repr, harness.log.rows)), hashlib.sha256(bytes.fromhex(harness.final())).hexdigest())


def spec_run(case):
    value = canon(ROOT, case.state)
    book = copy.deepcopy(value)
    log = Log()
    out = []
    for op in case.ops:
        name = op[0]
        if name == "core":
            _, tag, word, wei, user, validator, chain, now = op
            out.append(spec_core(book, tag, word, wei, stamp(now), user, validator, chain, log))
        elif name == "sink":
            _, rows, chain, now = op
            out.append([(key, amount) for key, amount in spec_sink(book, rows, stamp(now), chain, log)])
        elif name == "power":
            out.append(spec_power(book, book["stakes"]["current"], op[1]))
        elif name == "active":
            out.append(sorted(spec_active(book, book["stakes"]["current"], op[1]).items()))
    return (tuple(map(repr, out)), tuple(map(repr, log.rows)), hashlib.sha256(emit(ROOT, book, True, True)).hexdigest())


def v(index):
    return address(index + 30)


def u(index):
    return address(index + 60)


def profile(signer=None, disabled=False, commission=1000):
    return dict(node_ip=("Ip", "10.0.0.1"), name="n", description="d", delegations_disabled=disabled, commission_bps=commission, signer=signer or address(90))


def cstate(blocked=False):
    return dict(register_time=TIME_C, last_signer_change_time=TIME_C, delegations_blocked=blocked)


def base(count=3):
    """Validators v(0..), users u(0..); round 500 is the latest history key, user u(0) holds 10000."""
    state = least_state()
    stakes = [[v(index), dict(effective=(index + 1) * 1000, target=(index + 1) * 1100)] for index in range(count)]
    state["stakes"] = dict(epoch_values=dict(initial_round=500, round_to_val=[[400, dict(validator_to_stake=stakes)], [500, dict(validator_to_stake=stakes)]]), current=dict(validator_to_stake=copy.deepcopy(stakes)), period=86400, n_keep=9, current_round=510)
    state["validator_to_profile"] = [[v(index), profile(signer=address(index + 120))] for index in range(count)]
    state["validator_to_state"] = [[v(index), cstate()] for index in range(count)]
    state["user_states"] = [[u(0), dict(b=10000, l=TIME_A)], [u(1), dict(b=7)]]
    state["delegations"] = dict(
        user_to_delegations=[[u(2), [[v(0), dict(t=EARLIER, w=900)], [v(1), dict(t=EARLIER, w=800)]]], [u(3), [[v(0), dict(t=LATER, w=500)]]]],
        validator_to_state=[[v(0), dict(total_delegated=1400, delegator_to_epoch_delegation=[[u(2), dict(c=900, m=850, e=500)], [u(3), dict(c=500, m=400, e=400)]])], [v(1), dict(total_delegated=800, delegator_to_epoch_delegation=[[u(2), dict(c=800, m=800, e=400)]])]])
    return state


def tweak(change, count=3):
    state = base(count)
    change(state)
    return state


def core_op(tag, word, wei, user, validator, chain=3, now=NOW):
    return ("core", tag, word, wei, user, validator, chain, now)


DELEGATE_ROW = (2, 0)
REWARD_ROW = (2, 1)
UNDELEGATE_ROW = (2 + 1, 0)
EXIT_ROW = (0, 0)
OTHER_ROW = (1, 2)


def set_at(path, value):
    def change(state):
        node = state
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return change


def with_rows(*changes):
    def change(state):
        for item in changes:
            item(state)
    return change


def set_user(user, balance, lock=None):
    def change(state):
        remove(state["user_states"], user)
        place(state["user_states"], user, dict(b=balance, l=lock) if lock else dict(b=balance))
    return change


def set_pending(user, wei):
    def change(state):
        state["pending_withdrawals"]["user_to_total_withdrawal"] = [[user, dict(wei=wei, n=1)]]
    return change


def set_stake(validator, effective, target):
    def change(state):
        find(state["stakes"]["current"]["validator_to_stake"], validator).update(effective=effective, target=target)
    return change


def set_row(user, validator, wei=None, time=None):
    def change(state):
        item = find(find(state["delegations"]["user_to_delegations"], user), validator)
        if wei is not None:
            item["w"] = wei
        if time is not None:
            item["t"] = time
    return change


def set_member(validator, user, **fields):
    def change(state):
        row = find(state["delegations"]["validator_to_state"], validator)
        find(row["delegator_to_epoch_delegation"], user).update(fields)
    return change


def set_total(validator, wei):
    def change(state):
        find(state["delegations"]["validator_to_state"], validator)["total_delegated"] = wei
    return change


def drop_state(validator):
    def change(state):
        remove(state["delegations"]["validator_to_state"], validator)
    return change


def drop_member(validator, user):
    def change(state):
        remove(find(state["delegations"]["validator_to_state"], validator)["delegator_to_epoch_delegation"], user)
    return change


def add_row(user, validator, wei, time):
    def change(state):
        rows = state["delegations"]["user_to_delegations"]
        inner = find(rows, user)
        if inner is None:
            inner = place(rows, user, [])
        place(inner, validator, dict(t=time, w=wei))
    return change


def bad_cases():
    """Refusals of the core and what each leaves untouched."""
    cases = []

    def case(name, state, *ops):
        cases.append(Case(name, "refuse", state, list(ops)))

    case("unknown_validator_with_rows", base(), core_op(*DELEGATE_ROW, 10, u(0), v(7)))
    case("empty_stakes", tweak(set_at(("stakes", "current", "validator_to_stake"), [])), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("unknown_validator_undelegate", base(), core_op(*UNDELEGATE_ROW, 10, u(2), v(7)))
    case("no_history_row", tweak(set_at(("stakes", "epoch_values", "round_to_val"), [])), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    low = lambda value: set_at(("stakes", "epoch_values", "initial_round"), value)
    cur = lambda value: set_at(("stakes", "current_round"), value)
    rows = lambda *keys: lambda state: state["stakes"]["epoch_values"].update(round_to_val=[[key, dict(validator_to_stake=[])] for key in keys])
    case("stale_history_row", tweak(low(300)), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("stale_history_undelegate", tweak(low(300)), core_op(*UNDELEGATE_ROW, 10, u(2), v(0)))
    case("window_start_below_every_key", tweak(with_rows(rows(450, 500), low(400))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    for name, first, now, keys in (("early_uses_low", 500, 2499, (400, 500, 2300, 2301)), ("edge_2000_uses_cur_minus_200", 500, 2500, (400, 500, 2300, 2301)), ("one_past_edge", 500, 2501, (400, 500, 2300, 2301)), ("later_keeps_older_row", 500, 2600, (400, 500, 2300, 2301)), ("key_equal_low", 500, 510, (500, 501)), ("key_between", 500, 510, (499, 501)), ("low_above_cur_minus_200", 2400, 4399, (2300, 2400, 2500)), ("cur_minus_200_below_low", 2400, 4400, (2300, 2400, 4199, 4200, 4201)), ("low_wins_max", 4300, 6000, (4000, 4300, 5800)), ("cur_below_low", 500, 300, (400, 500)), ("three_level_many_rows", 500, 3000, tuple(range(2780, 2820)))):
        case("window_" + name, tweak(with_rows(rows(*keys), low(first), cur(now))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("window_low_near_top", tweak(with_rows(rows(5, 1 << 63), low(U64_MAX - 100), cur(U64_MAX - 50))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("window_low_near_top_edge", tweak(with_rows(rows(5, U64_MAX - 300), low(U64_MAX - 2100), cur(U64_MAX))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    disabled = lambda state: find(state["validator_to_profile"], v(0)).update(delegations_disabled=True)
    case("profile_disabled_delegate", tweak(disabled), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("profile_disabled_reward_row_passes", tweak(disabled), core_op(*REWARD_ROW, 10, u(0), v(0)))
    case("profile_disabled_undelegate_passes", tweak(disabled), core_op(*UNDELEGATE_ROW, 10, u(2), v(0)))
    case("no_profile_row_passes", tweak(lambda state: remove(state["validator_to_profile"], v(0))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("no_profile_rows_at_all", tweak(set_at(("validator_to_profile",), [])), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("no_validator_state_row", tweak(lambda state: remove(state["validator_to_state"], v(0))), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("no_validator_state_rows", tweak(set_at(("validator_to_state",), [])), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("no_validator_state_reward_row", tweak(set_at(("validator_to_state",), [])), core_op(*REWARD_ROW, 10, u(0), v(0)))
    blocked = lambda state: find(state["validator_to_state"], v(0)).update(delegations_blocked=True)
    case("blocked_delegate", tweak(blocked), core_op(*DELEGATE_ROW, 10, u(0), v(0)))
    case("blocked_reward_row", tweak(blocked), core_op(*REWARD_ROW, 10, u(0), v(0)))
    case("blocked_undelegate_passes", tweak(blocked), core_op(*UNDELEGATE_ROW, 10, u(2), v(0)))
    case("no_user_row", base(), core_op(*DELEGATE_ROW, 1, u(9), v(0)))
    case("wei_above_balance", base(), core_op(*DELEGATE_ROW, 10001, u(0), v(0)))
    case("pending_cuts_available", tweak(set_pending(u(0), 9000)), core_op(*DELEGATE_ROW, 1001, u(0), v(0)))
    case("pending_above_balance", tweak(set_pending(u(0), 20000)), core_op(*DELEGATE_ROW, 1, u(0), v(0)))
    case("pending_of_other_user", tweak(set_pending(u(5), 20000)), core_op(*DELEGATE_ROW, 1, u(0), v(0)))
    case("undelegate_no_rows", tweak(set_at(("delegations",), dict(user_to_delegations=[], validator_to_state=[]))), core_op(*UNDELEGATE_ROW, 1, u(2), v(0)))
    case("undelegate_no_user", base(), core_op(*UNDELEGATE_ROW, 1, u(0), v(0)))
    case("undelegate_no_validator_row", base(), core_op(*UNDELEGATE_ROW, 1, u(3), v(1)))
    case("undelegate_above_row", base(), core_op(*UNDELEGATE_ROW, 901, u(2), v(0)))
    case("exit_lock_later_date", base(), core_op(*EXIT_ROW, 1, u(3), v(0)))
    case("exit_lock_same_date_later_second", tweak(set_row(u(3), v(0), time="2025-03-04T05:06:08")), core_op(*EXIT_ROW, 1, u(3), v(0)))
    case("exit_lock_one_nano_after", tweak(set_row(u(3), v(0), time=AFTER)), core_op(*EXIT_ROW, 1, u(3), v(0)))
    case("exit_floor_refused", base(), core_op(0, 200, 800, u(2), v(0)))
    case("exit_floor_refused_after_lock_check", tweak(set_row(u(2), v(0), time=LATER)), core_op(0, 200, 800, u(2), v(0)))
    return cases


def good_cases():
    cases = []

    def case(name, state, *ops):
        cases.append(Case(name, "apply", state, list(ops)))

    for chain in (0, 1, 2, 3):
        case("delegate_first_row_chain_%d" % chain, base(), core_op(*DELEGATE_ROW, 2500, u(0), v(0), chain))
    moved = with_rows(set_user(u(2), 300, TIME_B))
    case("delegate_existing_row_resets_time", tweak(moved), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_existing_row_new_key", tweak(with_rows(moved, set_member(v(0), u(2), e=400))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_existing_row_same_key", tweak(with_rows(moved, set_member(v(0), u(2), e=500, m=5))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_second_validator", tweak(moved), core_op(*DELEGATE_ROW, 100, u(2), v(2)))
    case("delegate_all_available", tweak(set_pending(u(0), 4000)), core_op(*DELEGATE_ROW, 6000, u(0), v(0)))
    case("delegate_zero_with_no_user_row", base(), core_op(*DELEGATE_ROW, 0, u(9), v(0)))
    case("delegate_keeps_lock_word", base(), core_op(*DELEGATE_ROW, 10000, u(0), v(1)))
    case("delegate_no_validator_group", tweak(lambda state: set_user(u(0), 50)(state)), core_op(*DELEGATE_ROW, 50, u(0), v(2)))
    case("delegate_group_missing_row_present", tweak(with_rows(moved, drop_state(v(0)))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_member_missing_row_present", tweak(with_rows(moved, drop_member(v(0), u(2)))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("reward_row_new_keeps_now", base(), core_op(*REWARD_ROW, 500, u(0), v(0)))
    case("reward_row_existing_keeps_time", tweak(moved), core_op(*REWARD_ROW, 100, u(2), v(0)))
    case("reward_row_word_bit_1_only_checks", tweak(lambda state: find(state["validator_to_profile"], v(0)).update(delegations_disabled=True)), core_op(2, 2, 10, u(0), v(0)))
    case("delegate_row_wei_overflow", tweak(with_rows(moved, set_row(u(2), v(0), wei=U64_MAX - 5), set_total(v(0), 1), set_member(v(0), u(2), c=1))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_total_overflow", tweak(with_rows(moved, set_total(v(0), U64_MAX - 5))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_member_overflow", tweak(with_rows(moved, set_member(v(0), u(2), c=U64_MAX - 5))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_target_overflow", tweak(with_rows(moved, set_stake(v(0), 1, U64_MAX - 5))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    case("delegate_target_at_edge", tweak(with_rows(moved, set_stake(v(0), 1, U64_MAX - 100))), core_op(*DELEGATE_ROW, 100, u(2), v(0)))
    for row, name in ((UNDELEGATE_ROW, "open"), (EXIT_ROW, "exit"), (OTHER_ROW, "other")):
        case("undelegate_part_%s" % name, base(), core_op(*row, 100, u(2), v(0)))
        case("undelegate_whole_row_%s" % name, base(), core_op(*row, 800, u(2), v(1)))
        case("undelegate_only_row_of_user_%s" % name, tweak(set_row(u(3), v(0), time=EARLIER)), core_op(*row, 500, u(3), v(0)))
        case("undelegate_zero_%s" % name, tweak(set_row(u(3), v(0), time=EARLIER)), core_op(*row, 0, u(3), v(0)))
    case("undelegate_open_ignores_lock", base(), core_op(*UNDELEGATE_ROW, 100, u(3), v(0)))
    case("undelegate_other_ignores_lock", base(), core_op(*OTHER_ROW, 100, u(3), v(0)))
    case("exit_at_equal_time", tweak(set_row(u(3), v(0), time=NOW)), core_op(*EXIT_ROW, 100, u(3), v(0)))
    case("exit_one_nano_before", tweak(set_row(u(3), v(0), time=BEFORE)), core_op(*EXIT_ROW, 100, u(3), v(0)))
    case("exit_earlier_date_later_clock", tweak(set_row(u(3), v(0), time="2025-03-03T23:59:59.9")), core_op(*EXIT_ROW, 100, u(3), v(0)))
    case("exit_floor_equal", base(), core_op(0, 200, 700, u(2), v(0)))
    case("exit_floor_above_row_uses_saturating", base(), core_op(0, 0, 900, u(2), v(0)))
    case("undelegate_new_user_row", tweak(with_rows(set_row(u(2), v(0), time=EARLIER))), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_balance_overflow", tweak(set_user(u(2), U64_MAX - 3)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_no_group", tweak(drop_state(v(0))), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_no_member", tweak(drop_member(v(0), u(2))), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_no_member_last_in_group", tweak(with_rows(drop_member(v(0), u(2)), drop_member(v(0), u(3)))), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_no_group_rows", tweak(lambda state: state["delegations"].update(validator_to_state=[])), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_total_under", tweak(set_total(v(0), 10)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_member_under", tweak(set_member(v(0), u(2), c=10)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_member_same_key_min_keeps", tweak(set_member(v(0), u(2), m=100)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_member_same_key_min_drops", base(), core_op(*UNDELEGATE_ROW, 500, u(2), v(0)))
    case("undelegate_member_old_key", tweak(set_member(v(0), u(2), e=400)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_last_member_drops_group", base(), core_op(*UNDELEGATE_ROW, 800, u(2), v(1)))
    case("undelegate_member_zero_row_left", tweak(set_row(u(2), v(0), wei=2000)), core_op(*UNDELEGATE_ROW, 900, u(2), v(0)))
    case("undelegate_target_under", tweak(set_stake(v(0), 0, 10)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_effective_min", tweak(set_stake(v(0), 1000, 1040)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    case("undelegate_effective_kept", tweak(set_stake(v(0), 900, 1040)), core_op(*UNDELEGATE_ROW, 50, u(2), v(0)))
    self_row = with_rows(add_row(v(0), v(0), 1000, EARLIER), lambda state: find(state["delegations"]["validator_to_state"], v(0))["delegator_to_epoch_delegation"].append([v(0), dict(c=1000, m=1000, e=500)]), set_at(("self_delegation_requirement",), 800))
    case("self_exit_above_floor", tweak(self_row), core_op(*UNDELEGATE_ROW, 100, v(0), v(0)))
    case("self_exit_equal_floor", tweak(self_row), core_op(*UNDELEGATE_ROW, 200, v(0), v(0)))
    case("self_exit_below_floor_blocks", tweak(self_row), core_op(*UNDELEGATE_ROW, 201, v(0), v(0)))
    case("self_exit_whole_row_blocks", tweak(self_row), core_op(*UNDELEGATE_ROW, 1000, v(0), v(0)))
    case("self_exit_whole_row_only_row_blocks", tweak(with_rows(self_row, lambda state: remove(state["delegations"]["user_to_delegations"], v(0)), add_row(v(0), v(0), 1000, EARLIER))), core_op(*UNDELEGATE_ROW, 1000, v(0), v(0)))
    case("self_exit_no_state_row", tweak(with_rows(self_row, lambda state: remove(state["validator_to_state"], v(0)))), core_op(*UNDELEGATE_ROW, 1000, v(0), v(0)))
    case("self_exit_no_state_rows", tweak(with_rows(self_row, set_at(("validator_to_state",), []))), core_op(*UNDELEGATE_ROW, 1000, v(0), v(0)))
    case("self_exit_zero_floor", tweak(with_rows(self_row, set_at(("self_delegation_requirement",), 0))), core_op(*UNDELEGATE_ROW, 999, v(0), v(0)))
    case("other_user_never_blocks", tweak(with_rows(self_row)), core_op(*UNDELEGATE_ROW, 900, u(2), v(0)))
    case("self_exit_other_validator_state", tweak(with_rows(add_row(u(2), v(2), 5, EARLIER), set_at(("self_delegation_requirement",), 800), lambda state: find(state["delegations"]["validator_to_state"], v(1))["delegator_to_epoch_delegation"].sort())), core_op(*UNDELEGATE_ROW, 1, u(2), v(1)))
    return [item for item in cases if item is not None]


def wide_state(count=40, users=40):
    """Tall trees, so that real inserts split and real removals merge."""
    state = base(count)
    state["user_states"] = [[u(index), dict(b=100000 + index)] for index in range(users)]
    state["delegations"] = dict(user_to_delegations=[[u(index), [[v(item), dict(t=EARLIER, w=100 + item)] for item in range(count)]] for index in range(users)],
                                validator_to_state=[[v(item), dict(total_delegated=users * (100 + item), delegator_to_epoch_delegation=[[u(index), dict(c=100 + item, m=100 + item, e=500)] for index in range(users)])] for item in range(count)])
    return state


def tree_cases():
    cases = []

    def case(name, state, *ops):
        cases.append(Case(name, "tree", state, list(ops)))

    wide = wide_state(14, 14)
    case("tree_undelegate_all_rows_of_user", wide, *[core_op(*UNDELEGATE_ROW, 100 + item, u(7), v(item)) for item in range(14)])
    case("tree_undelegate_all_members_of_validator", wide, *[core_op(*UNDELEGATE_ROW, 105, u(item), v(5)) for item in range(14)])
    case("tree_delegate_grows", tweak(lambda state: state["user_states"].append([u(5), dict(b=1000000)]), 30), *[core_op(*DELEGATE_ROW, 10 + item, u(5), v(item)) for item in range(30)])
    case("tree_delegate_many_users", tweak(lambda state: state.update(user_states=[[u(index), dict(b=1000)] for index in range(30)]), 3), *[core_op(*DELEGATE_ROW, 10 + item, u(item), v(1)) for item in range(30)])
    return cases


def sink_cases():
    cases = []

    def case(name, state, rows, chain=3):
        cases.append(Case(name, "sink", state, [("sink", rows, chain, NOW)]))

    case("sink_empty", base(), [])
    case("sink_one_commission", base(), [(100, v(0), v(0), 0)])
    case("sink_one_delegator", base(), [(100, u(0), v(0), 1)])
    case("sink_same_user_two_validators", base(), [(100, u(0), v(0), 1), (50, u(0), v(1), 1)])
    case("sink_same_user_two_kinds", base(), [(100, u(0), v(0), 0), (50, u(0), v(1), 1)])
    case("sink_kind_order", base(), [(100, u(0), v(0), 1), (50, u(0), v(1), 0), (3, u(0), v(2), 1)])
    case("sink_two_users_sorted", base(), [(100, u(0), v(0), 1), (5, u(1), v(0), 1)])
    case("sink_stops_at_kind_2", base(), [(100, u(0), v(0), 1), (5, u(0), v(1), 2), (7, u(0), v(1), 1)])
    case("sink_short_balance_fails_row", base(), [(20000, u(0), v(0), 1), (5, u(0), v(1), 1)])
    case("sink_blocked_validator_fails_row", tweak(lambda state: find(state["validator_to_state"], v(0)).update(delegations_blocked=True)), [(10, u(0), v(0), 1), (5, u(0), v(1), 1)])
    case("sink_unknown_validator_fails_row", base(), [(10, u(0), v(7), 1)])
    case("sink_disabled_profile_passes", tweak(lambda state: find(state["validator_to_profile"], v(0)).update(delegations_disabled=True)), [(10, u(0), v(0), 1)])
    case("sink_sum_overflow", tweak(set_user(u(0), U64_MAX)), [(U64_MAX, u(0), v(0), 1), (U64_MAX, u(0), v(0), 1)])
    case("sink_chain_0", base(), [(100, u(0), v(0), 1)], 0)
    rows = [(10 + index, u(index % 2), v(index % 3), index % 2) for index in range(14)]
    case("sink_many_rows", tweak(lambda state: state.update(user_states=[[u(0), dict(b=1000)], [u(1), dict(b=1000)]])), rows)
    rows = [(1, u(index), v(0), 1) for index in range(25)]
    case("sink_splits_result_tree", tweak(lambda state: state.update(user_states=[[u(index), dict(b=10)] for index in range(25)])), rows)
    return cases


def power_state(rows, floor=0, max_n=None, signers=None, self_rows=()):
    """rows: (validator, effective), every one with a profile."""
    state = least_state()
    stakes = [[item, dict(effective=amount, target=amount)] for item, amount in rows]
    state["stakes"] = dict(epoch_values=dict(initial_round=500, round_to_val=[[500, dict(validator_to_stake=stakes)]]), current=dict(max_n_validators=max_n, validator_to_stake=copy.deepcopy(stakes)) if max_n is not None else dict(validator_to_stake=copy.deepcopy(stakes)), period=86400, n_keep=9, current_round=510)
    state["validator_to_profile"] = [[item, profile(signer=(signers or {}).get(item, address(index + 120)))] for index, (item, _) in enumerate(rows)]
    state["self_delegation_requirement"] = floor
    state["delegations"] = dict(user_to_delegations=[[item, [[item, dict(t=EARLIER, w=wei)]]] for item, wei in self_rows], validator_to_state=[])
    return state


def power_cases():
    cases = []

    def case(name, state, chain=3):
        cases.append(Case(name, "power", state, [("active", chain), ("power", chain)], chain))

    for chain in (1, 2, 3):
        f = FOUNDATION[chain]
        case("no_rows_chain_%d" % chain, power_state([]), chain)
        case("only_foundation_equal_chain_%d" % chain, power_state([(item, 1000) for item in f]), chain)
        case("foundation_and_one_large_chain_%d" % chain, power_state([(item, 1000) for item in f] + [(v(0), 1000000)]), chain)
        case("foundation_and_many_small_chain_%d" % chain, power_state([(item, 1000) for item in f] + [(v(index), 500 + index) for index in range(6)]), chain)
        case("one_foundation_row_chain_%d" % chain, power_state([(f[0], 5000), (v(0), 100)]), chain)
        case("all_zero_stakes_chain_%d" % chain, power_state([(item, 0) for item in f] + [(v(0), 0)]), chain)
    f = FOUNDATION[3]
    case("no_foundation_rows", power_state([(v(0), 100), (v(1), 300)]))
    case("foundation_needs_no_boost", power_state([(f[0], 900), (f[1], 900), (f[2], 900), (f[3], 900), (f[4], 900)]))
    case("foundation_uneven", power_state([(f[0], 9000), (f[1], 100), (f[2], 100), (f[3], 100), (f[4], 100), (v(0), 100)]))
    case("foundation_share_above_need", power_state([(f[0], 100000), (f[1], 100000), (f[2], 100000), (f[3], 100000), (f[4], 100000), (v(0), 1)]))
    case("rounding_of_extra_exact", power_state([(f[0], 250), (f[1], 250), (f[2], 250), (f[3], 250), (v(0), 0)]))
    case("rounding_of_shares_down", power_state([(v(0), 1), (v(1), 1), (v(2), 1)]))
    case("share_rounds_to_zero", power_state([(v(0), 1), (v(1), 100000)]))
    case("limit_zero", power_state([(v(0), 100), (v(1), 300)], max_n=0))
    case("limit_one_large_wins", power_state([(v(0), 100), (v(1), 300)], max_n=1))
    case("limit_foundation_first", power_state([(v(0), 900), (f[0], 1)], max_n=1))
    case("limit_two_stake_order", power_state([(v(0), 100), (v(1), 300), (v(2), 200)], max_n=2))
    case("limit_tie_key_order", power_state([(v(0), 100), (v(1), 100), (v(2), 100)], max_n=2))
    case("limit_filter_runs_first", power_state([(v(0), 900), (v(1), 800), (v(2), 700)], floor=10, max_n=2, self_rows=[(v(1), 10), (v(2), 11)]))
    case("floor_rejects_short_self", power_state([(v(0), 900), (v(1), 800)], floor=10, self_rows=[(v(0), 9), (v(1), 10)]))
    case("floor_rejects_no_row", power_state([(v(0), 900), (v(1), 800)], floor=10, self_rows=[(v(1), 10)]))
    case("floor_rejects_no_rows", power_state([(v(0), 900)], floor=10))
    case("floor_skips_foundation", power_state([(f[0], 900), (v(1), 800)], floor=10))
    state = power_state([(v(0), 900), (v(1), 800)], floor=10, self_rows=[(v(1), 10)])
    state["delegations"]["user_to_delegations"].append([v(0), [[v(1), dict(t=EARLIER, w=99)]]])
    state["delegations"]["user_to_delegations"].sort()
    case("floor_self_row_of_other_validator", state)
    state = power_state([(v(0), 100), (v(1), 300)])
    remove(state["validator_to_profile"], v(0))
    case("no_profile_skipped", state)
    state["validator_to_profile"] = []
    case("no_profiles", copy.deepcopy(state))
    case("stake_zero_active_kept", power_state([(v(0), 0), (v(1), 300)]))
    case("all_zero_no_foundation", power_state([(v(0), 0), (v(1), 0)]))
    case("all_zero_some_foundation", power_state([(v(0), 0), (f[1], 0)]))
    case("all_zero_limit", power_state([(v(0), 0), (f[1], 0)], max_n=1))
    case("all_rows_filtered_foundation_gets_one", power_state([(v(0), 900)], floor=10))
    case("same_signer_last_key_wins", power_state([(v(0), 100), (v(1), 300)], signers={v(0): address(99), v(1): address(99)}))
    case("signer_sorts_apart", power_state([(v(0), 100), (v(1), 300), (v(2), 500)], signers={v(0): address(201), v(1): address(7), v(2): address(99)}))
    case("foundation_signer_row", power_state([(f[0], 100), (v(1), 300)], signers={f[0]: address(5)}))
    case("foundation_missing_keeps_own_key", power_state([(v(1), 300)]))
    case("large_values_bail_raw", power_state([(v(0), 1 << 61), (v(1), 1 << 61)]))
    case("large_second_row_bails", power_state([(v(0), 1000), (v(1), (1 << 54) + 1)]))
    case("eight_more_rows", power_state([(v(index), 100 + index * 3) for index in range(8)]))
    case("twenty_one_rows_full_sort", power_state([(v(index), 1000 - index * 7 % 13) for index in range(21)]))
    case("thirty_rows_with_foundation", power_state([(v(index), 1000 + index * 7 % 13) for index in range(26)] + [(item, 50) for item in f[:4]], max_n=27))
    case("thirty_rows_with_ties", power_state([(v(index), 100 + index % 2) for index in range(30)], max_n=25))
    case("no_bail_small_total", power_state([(f[0], 1), (f[1], 2)]))
    return cases


def link_cases():
    """Reward into stake, undelegate into set, whole sequences: state of one op feeds the next."""
    cases = []
    f = FOUNDATION[3]
    state = power_state([(f[index], 1000) for index in range(5)] + [(v(0), 4000)])
    state["validator_to_state"] = [[v(0), cstate()]]
    state["user_states"] = [[u(0), dict(b=5000)]]
    cases.append(Case("delegate_then_power_uses_effective", "link", state, [("power", 3), core_op(*DELEGATE_ROW, 5000, u(0), v(0)), ("power", 3)]))
    state = power_state([(v(0), 4000), (v(1), 1000)], floor=100, self_rows=[(v(0), 100), (v(1), 100)])
    state["validator_to_state"] = [[v(0), cstate()], [v(1), cstate()]]
    state["delegations"]["validator_to_state"] = [[v(0), dict(total_delegated=100, delegator_to_epoch_delegation=[[v(0), dict(c=100, m=100, e=500)]])], [v(1), dict(total_delegated=100, delegator_to_epoch_delegation=[[v(1), dict(c=100, m=100, e=500)]])]]
    cases.append(Case("self_exit_blocks_and_leaves_set", "link", state, [("active", 3), core_op(*UNDELEGATE_ROW, 1, v(0), v(0)), ("active", 3), core_op(*DELEGATE_ROW, 1, v(0), v(0))]))
    cases.append(Case("reward_row_after_block", "link", tweak(set_user(u(2), 100)), [("sink", [(50, u(2), v(0), 1)], 3, NOW), core_op(*UNDELEGATE_ROW, 950, u(2), v(0)), ("sink", [(50, u(2), v(0), 1)], 3, NOW)]))
    return cases


class Draw:
    def __init__(self, seed):
        self.seed = seed

    def next(self):
        self.seed = (self.seed * 6364136223846793005 + 1442695040888963407) & U64_MAX
        return self.seed >> 33

    def pick(self, items):
        return items[self.next() % len(items)]


def vector_cases(count):
    cases = []
    for seed in range(count):
        draw = Draw(seed * 2 + 1)
        state = wide_state(4 + draw.next() % 5, 3 + draw.next() % 5)
        state["self_delegation_requirement"] = draw.pick((0, 50, 110, 1000))
        for row in state["validator_to_state"]:
            row[1]["delegations_blocked"] = draw.next() % 5 == 0
        users = [u(index) for index in range(9)] + [v(index) for index in range(4)]
        validators = [v(index) for index in range(10)]
        ops = []
        for _ in range(12):
            user, validator, chain = draw.pick(users), draw.pick(validators), draw.pick((0, 1, 2, 3))
            kind = draw.next() % 6
            wei = draw.pick((0, 1, 50, 100, 101, 5000, 100000))
            if kind < 2:
                ops.append(core_op(2, 0, wei, user, validator, chain))
            elif kind == 2:
                ops.append(core_op(2, 1, wei, user, validator, chain))
            elif kind == 3:
                ops.append(core_op(draw.pick((0, 3, 1)), draw.pick((0, 10)), wei, user, validator, chain))
            elif kind == 4:
                ops.append(("sink", [(draw.pick((1, 7, 100)), draw.pick(users), draw.pick(validators), draw.next() % 2) for _ in range(3)], chain, NOW))
            else:
                ops.append(("power", draw.pick((1, 2, 3))))
        cases.append(Case("seed_%d" % seed, "vector", state, ops))
    return cases


def all_cases():
    return bad_cases() + good_cases() + tree_cases() + sink_cases() + power_cases() + link_cases()


NAMES = {
    CORE: "stake_core", UNDELEGATE: "undelegate_books", DELEGATE: "delegate_books", SINK: "reward_compound_sink", 0x33946B0: "address_map_get", POWER: "signer_power_map", ACTIVE: "active_validators",
    0x3316460: "take_collect", 0x3307DF0: "active_filter", 0x33C2FB0: "active_order", 0x3316640: "signer_collect", 0x3BD4D80: "signer_vector", 0x3BE48F0: "signer_of_row", 0x3BB0300: "stake_vector", 0x3BE5F30: "stake_walk",
    0x3387F80: "insertion_sort_active", 0x3386250: "insertion_sort_key", 0x2FDD2D0: "merged_row_search", 0x37D5E10: "history_latest_row", 0x2FE1490: "history_range", 0x33BC0A0: "user_row_entry", 0x33BC840: "merged_row_entry", 0x33BC970: "power_row_entry",
    0x33BD9B0: "member_row_entry", 0x33C2310: "group_row_insert", 0x33BF8C0: "user_books_insert", 0x33C2B30: "delegation_row_insert", 0x33BF770: "member_row_insert", 0x33ABD60: "delegation_row_remove", 0x33ACB30: "user_books_remove", 0x33ABB40: "member_row_remove", 0x33ACD70: "group_row_remove",
}
PINS = (
    ("round_word", 0x398ddd2, "498b7658", "mov rsi,[r14+0x58]: current_round goes to the history window"),
    ("history_call", 0x398ddd6, "e83580e4ff", "call 0x37d5e10"),
    ("tag_two", 0x398dde7, "48837c241802", "cmp qword [rsp+0x18],2: tag 2 is a delegate row"),
    ("value_bit", 0x398ddf8, "f644244001", "test byte [rsp+0x40],1: value bit 0 skips the profile test"),
    ("profile_root", 0x398de08, "488ba850010000", "mov rbp,[rax+0x150]: validator_to_profile"),
    ("status_unknown", 0x398decd, "66c7009100", "mov word [rax],0x91"),
    ("status_history", 0x398dedc, "66c7009700", "mov word [rax],0x97"),
    ("profile_flag", 0x398e1e7, "803b01", "cmp byte [rbx],1: delegations_disabled"),
    ("status_disabled", 0x398e1f1, "66c700fd00", "mov word [rax],0xfd"),
    ("state_root", 0x398e200, "488b9878020000", "mov rbx,[rax+0x278]: validator_to_state"),
    ("state_stride", 0x398e284, "4883c51c", "add rbp,0x1c: 28 byte CValidatorState"),
    ("blocked_read", 0x398e2c9, "807d0000", "cmp byte [rbp+0],0: delegations_blocked"),
    ("pending_root", 0x398e568, "498b9628020000", "mov rdx,[r14+0x228]: user_to_total_withdrawal"),
    ("available", 0x398e6e7, "4829f8480f43d0", "sub rax,rdi / cmovae rdx,rax: available is balance minus pending, floor 0"),
    ("floor_read", 0x398e551, "483b8140020000", "cmp rax,[rcx+0x240]: self_delegation_requirement"),
    ("blocked_write", 0x398e55e, "c60301", "mov byte [rbx],1: delegations_blocked set"),
    ("undelegate_call", 0x398e0ba, "e8f1072800", "call 0x3c0e8b0"),
    ("delegate_call", 0x398e8aa, "e8310e2800", "call 0x3c0f6e0"),
    ("target_sub", 0x398e2e4, "482b5c2450", "sub rbx,[rsp+0x50]: target minus wei"),
    ("effective_min", 0x398e308, "480f42c3", "cmovb rax,rbx: effective becomes min(effective, target)"),
    ("target_add", 0x398e9d4, "49030424", "add rax,[r12]: target plus wei"),
    ("status_overflow", 0x398ea46, "66c7442460be00", "mov word [rsp+0x60],0xbe"),
    ("books_arg", 0x398e032, "4d8da668010000", "lea r12,[r14+0x168]: delegations"),
    ("status_low", 0x3c0e90b, "66c70424fe00", "mov word [rsp],0xfe"),
    ("tag_zero", 0x3c0eaf1, "4883bc24f800000000", "cmp qword [rsp+0xf8],0: tag 0 alone runs the lock and floor tests"),
    ("status_lock", 0x3c0ec8b, "66c70424ff00", "mov word [rsp],0xff"),
    ("status_floor", 0x3c0ecba, "66c704243001", "mov word [rsp],0x130"),
    ("floor_compare", 0x3c0ecc0, "483b8c24e0000000", "cmp rcx,[rsp+0xe0]: remainder against the value word"),
    ("group_stride", 0x3c0ec2b, "4983c5e0", "add r13,-0x20: 0x20 byte group row"),
    ("member_key_test", 0x3c0ef3b, "4d3b7e10", "cmp r15,[r14+0x10]: e against the history key"),
    ("member_min", 0x3c0ef48, "480f42c3", "cmovb rax,rbx: m becomes min(m, c)"),
    ("status_balance", 0x3c0f72a, "66b8fc00", "mov ax,0xfc"),
    ("balance_test", 0x3c0f72e, "48394a10", "cmp [rdx+0x10],rcx: available against wei"),
    ("lock_table", 0x3c0f7a8, "488d0571c65ffc", "lea rax,[rip-0x3a0398f]: table 0x20be20"),
    ("keep_flag", 0x3c0fa3b, "807c240700", "cmp byte [rsp+7],0: keep flag"),
    ("time_add", 0x3c0fc68, "ff154af3b501", "call 0x1459ca0 through the slot: time plus seconds"),
    ("member_snapshot", 0x3c0fe3f, "4c8973f8", "mov [rbx-8],r14: m takes c on the first change of an epoch"),
    ("sink_stop", 0x39901b5, "3c02", "cmp al,2: kind 2 ends the row walk"),
    ("sink_tag", 0x3990334, "48c744246002000000", "mov qword [rsp+0x60],2"),
    ("sink_value", 0x399033d, "c644246801", "mov byte [rsp+0x68],1"),
    ("window_add", 0x37d5e33, "4881c1d0070000", "add rcx,0x7d0: 2000 rounds"),
    ("window_back", 0x37d5e4e, "488d8838ffffff", "lea rcx,[rax-0xc8]: 200 rounds"),
    ("range_upper", 0x2fe14c5, "4a3b4cde08", "cmp rcx,[rsi+r11*8+8]: bound against keys, left edge means empty"),
    ("foundation_chain", 0x3c10fba, "80fa03", "cmp dl,3: chain 3 reads cell 0x5786238"),
    ("per_mille", 0x3c11467, "b8e8030000", "mov eax,0x3e8"),
    ("per_mille_mul", 0x3c1146c, "48f764f108", "mul qword [rcx+rsi*8+8]"),
    ("boost_three", 0x3c11641, "b903000000", "mov ecx,3"),
    ("set_size", 0x3c1167d, "4983fe04", "cmp r14,4: boost needs four members"),
    ("divide_by", 0x3c1173d, "498d76fd", "lea rsi,[r14-3]"),
    ("filter_floor", 0x3308045, "488b8040020000", "mov rax,[rax+0x240]: self_delegation_requirement"),
    ("filter_live", 0x3308236, "c60001", "mov byte [rax],1: a row with stake was taken"),
    ("limit_read", 0x3c11d13, "498b4f08", "mov rcx,[r15+8]: max_n_validators"),
    ("signer_field", 0x3be496f, "498d4538", "lea rax,[r13+0x38]: profile signer"),
)
SAMPLE = 9
WORKERS = 4
MUTANT_CASES = 6
SURVIVED = "equal outcome on every picked case that reaches the row"
MUTANT_STATE = {}
MUTANT_STEP_LIMIT = 400000
TEXT_TABLE = 0x59A8D0
STATUSES = (0x91, 0x97, 0xBE, 0xFC, 0xFD, 0xFE, 0xFF, 0x130)


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def text_of(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def status_rows(image):
    rows = []
    for tag in STATUSES:
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        code = text_of(image, arm, 96)
        at = code.find(b"\x48\x8d\x35")
        if at < 0 or code[at + 7] != 0xBA:
            rows.append(("%#x" % tag, "%#x" % arm, "text not at the plain form"))
            continue
        size = struct.unpack_from("<I", code, at + 8)[0]
        rows.append(("%#x" % tag, "%#x" % arm, text_of(image, arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0], size).decode("ascii")))
    return rows


def pin_rows(image):
    rows = []
    for name, va, data, meaning in PINS:
        got = text_of(image, va, len(data) // 2).hex()
        if got != data:
            raise EvidenceError("pin %s: %s" % (name, got))
        rows.append((name, "%#x" % va, data, meaning))
    return rows


def lock_rows(image):
    rows = []
    for chain, name in enumerate(("Local", "Sandbox", "Testnet", "Mainnet")):
        at = LOCK_TABLE + chain * 8
        value = struct.unpack("<d", text_of(image, at, 8))[0]
        if value != LOCK_SECONDS[chain]:
            raise EvidenceError("lock seconds %d" % chain)
        rows.append((chain, name, "%#x" % at, "%d" % value))
    return rows


def caller_rows(image):
    base, text = image.text_bytes()
    rows = []
    direct = {SINK: "reward_compound_sink", UNDELEGATE: "undelegate_books", DELEGATE: "delegate_books", ACTIVE: "active_validators", POWER: "signer_power_map", CORE: "stake_core"}
    slots = {SLOT_CORE: "stake_core", SLOT_POWER: "signer_power_map", 0x5773A30: "tick_host"}
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if target in slots:
            rows.append((slots[target], "slot %#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 > len(text):
            break
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in direct:
            rows.append((direct[target], "direct", "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
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
    harness = Book2(state["image"], patch, state["cache"])
    harness.snapshots, harness.times = state["snapshots"], state["times"]
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases, reach, cost, harness, sample):
    wants = {case.name: spec_run(case) for case in cases}
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=harness.machine.cache, snapshots=harness.snapshots, times=harness.times)
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
        harness = state["worker"] = Book2(state["image"])
        harness.snapshots, harness.times = state["snapshots"], state["times"]
    return check_case(harness, state["all"][index])


def analyse(image, mutate=True, vectors=30, cases=None, sample=SAMPLE):
    harness = Book2(image)
    named = cases if cases is not None else all_cases()
    generated = vector_cases(vectors)
    every = named + generated
    for case in every:
        for op in case.ops:
            if op[0] in ("core", "sink"):
                harness.time_bytes(op[-1])
    for case in every:
        harness.load(wire_input(ROOT, case.state))
    MUTANT_STATE.update(image=image, all=every, snapshots=harness.snapshots, times=harness.times)
    MUTANT_STATE.pop("worker", None)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        done = pool.map(check_job, range(len(every)), 4)
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
    result = dict(table=table, named=rows, vector_count=len(generated), pins=pin_rows(image), statuses=status_rows(image), locks=lock_rows(image), sizes={target: image.exact_fde(target)[1] - target for target in NAMES})
    if mutate:
        result["callers"] = caller_rows(image)
        pool = [case for case in named if cost[case.name] < 1500000]
        result["edit_count"], result["mutations"] = run_mutants(image, table, pool, reach, cost, harness, sample)
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
    tsv("constants.tsv", ("name", "address", "bytes", "meaning"), result["pins"])
    tsv("status-text.tsv", ("tag", "display_arm", "text"), result["statuses"])
    tsv("lock-seconds.tsv", ("chain_byte", "name", "table_row", "seconds"), result["locks"])
    tsv("scenarios.tsv", ("case", "group", "results", "recorder_rows", "state_sha256"), [(case.name, case.kind, ";".join(got[0]), ";".join(got[1]), got[2]) for case, got in result["named"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "named_scenarios": len(result["named"]), "vector_scenarios": result["vector_count"], "instructions": sum(len(items) for items in table.values()), "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "pins": len(result["pins"])}
    if "mutations" in result:
        tsv("callers.tsv", ("function", "form", "site", "host"), result["callers"])
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
        items = result["mutations"]
        summary["mutations"] = {"edits_possible": result["edit_count"], "total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
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
