#!/usr/bin/env python3
"""Map node #94 round clock, freeze height and hardfork reset of the staking EpochTrackers.

The vote gate 0x2703a90 sets scheduled_freeze_height, apply_block 0x2209d40 refuses blocks past it, begin_block 0x26f8b60 moves
height, round, time and both current_round words, the host 0x22689f0 resets the chain at the freeze height through 0x2207f30, the
frozen state path 0x32725d0 does the same on a loaded state, and 0x3996730 with 0x37d9a10, 0x37d9af0 and 0x37d9940 rolls the two
trackers. The real bytes run in an interpreter inside this tool: a CStaking state goes in through the real msgpack reader 0x175f130,
the functions run on that memory with their tree helpers real, the real writer 0x39908e0 gives the state back, and a separately
written rule list predicts every result, every logged call and the written state byte for byte. Every reached conditional row and
immediate is mutated, one in every SAMPLE rows. No objdump or readelf output is parsed and the binary is never executed.

    python3 tools/staking_round_clock.py --out <dir>
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

EXCHANGE = DECODED - 0x8F8
TICK = 0x3996730
STAGE = 0x3373420
PAYOUT = 0x33709F0
DECAY = 0x336F9F0
RECORD_STAKES = 0x37D9A10
RECORD_SIGNERS_GATED = 0x37D9AF0
RECORD_SIGNERS = 0x37D9940
HISTORY_ROW = 0x37D5E10
HISTORY_KEY = 0x37D9CF0
RESET = 0x2207F30
RELOAD = 0x32725D0
FREEZE = (0x2703A90, 0x4CF0750, 0x4CF0650)
BEGIN = (0x26F8B60, 0x4CDF180, 0x4CDF370)
BLOCK_STEP = (0x22297C0, 0x470E9A0, 0x47162D0)
APPLY = (0x2209D40, 0x42E5D40, 0x42E4600)
CLOCK = 0x4EE3800
DROP_MAP = 0x3402700
DROP_VEC = 0x33F0DA0
PATH_NAME = 0x332DE90
PARSE = 0x3273810
FORMAT = 0x1344760
ONCE = 0x4EE3B20
PANIC_TEXT = 0x576E108
PANIC_BOUND = 0x576E470
PANICS = {0x157AA10: "unwrap failed", 0x157B5AE: "height assert", 0x4B28343: "round assert", 0x4B283A9: "hardfork assert"}
OVERLAY_LOW = 0x5786000
OVERLAY_HIGH = 0x5788000
OUT_AT = HEAP_BASE + 0x3000
TIME_AT = HEAP_BASE + 0x3100
BLOCK_AT = HEAP_BASE + 0x3200
ARGS_AT = HEAP_BASE + 0x3300
NAME_AT = HEAP_BASE + 0x3400
OK = 0x186
U64_MAX = (1 << 64) - 1
WINDOW = 0xC350


class Reached(Exception):
    pass


class Log:
    def __init__(self):
        self.rows = []

    def add(self, *row):
        self.rows.append(row)


def sign32(value):
    return value - (1 << 32) if value & 0x80000000 else value


def moment(year, ordinal, seconds, nanos, flags=0):
    return ((year << 13 | ordinal << 4 | flags) & 0xFFFFFFFF, seconds, nanos)


def time_bytes(value):
    return struct.pack("<III", *value)


def later(new, old):
    return (sign32(new[0]), new[1], new[2]) > (sign32(old[0]), old[1], old[2])


def millis(value):
    date, seconds, nanos = value
    year = sign32(date) >> 13
    ordinal = date >> 4 & 0x1FF
    shifted, extra = year - 1, 0
    if year <= 0:
        cycles = (1 - year) // 400 + 1
        shifted += 400 * cycles
        extra = -146097 * cycles
    century = abs(shifted) // 100 * (1 if shifted >= 0 else -1)
    days = ordinal + extra + (shifted * 1461 >> 2) - century + (century >> 2) - 719163
    return max((days * 86400 + seconds) * 1000 + nanos // 1000000, 0)


def guard_step(value, last, width):
    bucket = value // width
    return max(bucket, last), bucket > last


def field(offset, copy_index):
    return offset + 0xA80 if copy_index == 2 and offset >= 0x740 else offset


CONTEXT = (("tx_tag", 0, 8), ("tx_value", 8, 8), ("initial_height", 0x10, 8), ("version", 0x18, 8), ("fork_round", 0x20, 8), ("height", 0x28, 8), ("round", 0x30, 8), ("stake_round", 0x950, 8), ("signer_round", 0x9F0, 8), ("freeze_tag", 0xB90, 8), ("freeze_height", 0xB98, 8))
BASE_TIME = moment(2025, 63, 18367, 500000000, 5)
OLD_TIME = moment(2025, 62, 3, 7, 5)


def context(**change):
    row = dict(tx_tag=1, tx_value=9, initial_height=100, version=3, fork_round=70, height=500, round=900, stake_round=899, signer_round=898, freeze_tag=0, freeze_height=0, time=BASE_TIME, prev=OLD_TIME, map_root=0, map_height=0, map_size=0, vec_a=0, vec_b=0, vec_c=0, word=0, mirror=None, width=3600000, last=0, parse_tag=0)
    row.update(change)
    return row


class Clock(Harness):
    def __init__(self, image, patches=None, cache=None):
        Harness.__init__(self, image, patches, cache)
        machine = self.machine
        self.skip = set()
        machine.real = Stubbed(self.skip)
        for va, hook in ((STAGE, self.on_stage), (PAYOUT, self.on_payout), (DECAY, self.on_decay), (CLOCK, self.on_clock), (DROP_MAP, self.on_drop_map), (DROP_VEC, self.on_drop_vec), (PATH_NAME, self.on_path), (PARSE, self.on_parse), (FORMAT, self.on_format)):
            self.hook(va, hook)
        self.hook(ONCE, self.on_once)
        for va, text in PANICS.items():
            self.hook(va, self.panic_with(text))
        for index in range(3):
            self.hook(BLOCK_STEP[index], self.on_step)
            self.hook(BEGIN[index], self.on_begin)
        machine.slots[MARK_BASE + PANIC_TEXT] = self.on_panic_text
        machine.slots[MARK_BASE + PANIC_BOUND] = self.panic_with("panic bound")
        self.log = Log()
        self.snapshots = {}
        self.time_arg = 0
        self.stop_begin = False
        self.parse_tag = 0
        self.path_error = False

    def hook(self, va, action):
        self.skip.add(va)
        self.machine.calls[va] = action
        self.machine.slots[va] = action

    def panic_with(self, text):
        def action(machine):
            self.log.add("panic", text)
            raise Reached()
        return action

    def on_panic_text(self, machine):
        self.log.add("panic", self.data(machine.regs[RDI], machine.regs[RSI]).decode())
        raise Reached()

    def label(self, at):
        return self.data(self.read(at), self.read(at + 8)).decode(), self.read(at + 0x20, 1)

    def on_once(self, machine):
        pass

    def on_stage(self, machine):
        self.log.add("stage", *self.label(machine.regs[RSI]))
        self.write(machine.regs[RDI], 2, 4)

    def on_payout(self, machine):
        self.log.add("payout", *self.label(machine.regs[RSI]))
        self.write(machine.regs[RDI], 2, 4)

    def on_decay(self, machine):
        self.log.add("decay", *self.label(machine.regs[RDI]))

    def on_clock(self, machine):
        machine.regs[RAX] = 0x11
        machine.regs[RDX] = 0x22
        machine.keep_rdx = True

    def on_drop_map(self, machine):
        at = machine.regs[RDI]
        if self.read(at):
            self.log.add("drop_map", 1, self.read(at + 0x10), self.read(at + 0x18), self.read(at + 0x40))
        else:
            self.log.add("drop_map", 0)

    def on_drop_vec(self, machine):
        at = machine.regs[RDI]
        self.log.add("drop_vec", self.read(at), self.read(at + 8), self.read(at + 0x10))

    def on_path(self, machine):
        at = machine.regs[RDI]
        self.log.add("path_name", self.read(machine.regs[RSI]), self.read(machine.regs[RSI] + 0x10), machine.regs[RDX])
        self.write(at, 1 << 63 if self.path_error else 0x40)
        self.write(at + 8, NAME_AT)
        self.write(at + 0x10, 0)
        self.write(at + 0x18, 0)

    def on_format(self, machine):
        at = machine.regs[RDI]
        self.write(at, 0)
        self.write(at + 8, NAME_AT)
        self.write(at + 0x10, 0)

    def on_parse(self, machine):
        at = machine.regs[RDI]
        if self.parse_tag == 2:
            self.write(at, 2, 4)
            self.write(at + 8, 0x77)
            return
        self.put(at, self.data(EXCHANGE, 0x3AE8))

    def on_step(self, machine):
        at, closure = machine.regs[RDI], machine.regs[RSI]
        text, changed = self.label(at)
        self.log.add("step", text, changed, self.read(closure) == EXCHANGE, self.read(closure + 8) == self.time_arg, self.data(self.read(closure + 0x10), 12).hex(), self.read(self.read(closure + 0x18), 1), self.read(EXCHANGE, 8), self.read(EXCHANGE + 0x28), self.read(EXCHANGE + 0x30))

    def on_begin(self, machine):
        if not self.stop_begin:
            raise Halt("begin outside an apply case")
        self.log.add("begin", machine.regs[RDI] == EXCHANGE, self.data(machine.regs[RSI], 12).hex(), machine.regs[RDX], machine.regs[RCX] & 0xFF)
        raise Reached()

    def put_context(self, row, index=0):
        at = EXCHANGE
        for name, offset, size in CONTEXT:
            self.write(at + field(offset, index), row[name], size)
        self.put(at + 0x60, time_bytes(row["time"]))
        self.put(at + 0x6C, time_bytes(row["prev"]))
        for offset, value in ((0x31E8, row["map_root"]), (0x31F0, row["map_height"]), (0x31F8, row["map_size"]), (0x3200, row["vec_a"]), (0x3208, row["vec_b"]), (0x3210, row["vec_c"]), (0x3218, row["word"]), (0x38F8, row["width"]), (0x3900, row["last"])):
            self.write(at + field(offset, index), value)
        self.write(at + field(0x3AE8, index), row["parse_tag"], 4)

    def get_context(self, index=0, mirror=False):
        at = EXCHANGE
        got = {name: self.read(at + field(offset, index), size) for name, offset, size in CONTEXT}
        got["time"] = self.data(at + 0x60, 12).hex()
        got["prev"] = self.data(at + 0x6C, 12).hex()
        got["last"] = self.read(at + field(0x3900, index))
        for name, offset in (("map_root", 0x31E8), ("map_size", 0x31F8), ("vec_a", 0x3200), ("vec_c", 0x3210), ("word", 0x3218)):
            got[name] = self.read(at + field(offset, index))
        if mirror and index == 2:
            got["mirror"] = (self.read(at + 0x1018), self.data(at + 0x1020, 12).hex())
        return got

    def load(self, data):
        got = self.snapshots.get(data)
        memory = self.machine.memory
        if got is None:
            result = self.decode_rmp(data)
            if result != ("ok",):
                raise EvidenceError("fixture refused: %s" % (result,))
            self.snapshots[data] = (bytes(memory.heap[:HEAP_USED]), self.top, dict(self.live))
            return
        heap, self.top, live = got
        memory.stack[:] = memory.fresh[0]
        memory.heap[:HEAP_USED] = heap
        self.live = dict(live)

    def freeze(self, index, row, value):
        self.put_context(row, index)
        self.machine.run(FREEZE[index], {RDI: OUT_AT, RSI: EXCHANGE, RDX: value})
        status = self.read(OUT_AT, 2)
        return (status, self.read(OUT_AT + 8)) if status != OK else (status,)

    def begin(self, index, row, new_time, round_number, flag):
        self.put_context(row, index)
        self.put(TIME_AT, time_bytes(new_time))
        self.time_arg = TIME_AT
        self.machine.run(BEGIN[index], {RDI: EXCHANGE, RSI: TIME_AT, RDX: round_number, RCX: flag})
        return "done"

    def apply(self, index, row, block, chain, frozen):
        self.put_context(row, index)
        self.write(EXCHANGE + field(0x8F2, index), chain, 1)
        self.write(EXCHANGE + field(0x3AE8, index), frozen, 4)
        self.put(BLOCK_AT + 0x38, time_bytes(block["time"]))
        for offset, name in ((0x18, "round"), (0x20, "parent"), (0x28, "version"), (0x30, "fork_round")):
            self.write(BLOCK_AT + offset, block[name])
        self.stop_begin = True
        try:
            self.machine.run(APPLY[index], {RDI: OUT_AT, RSI: EXCHANGE, RDX: BLOCK_AT})
        except Reached:
            return "stopped"
        finally:
            self.stop_begin = False
        raise Halt("apply ran past begin")

    def reset(self, row):
        self.put_context(row)
        self.machine.run(RESET, {RDI: EXCHANGE})
        return "done"

    def reload(self, row, height, parse_tag, path_error):
        self.put_context(row)
        self.parse_tag, self.path_error = parse_tag, path_error
        self.write(ARGS_AT, 0x51)
        self.write(ARGS_AT + 8, self.alloc(0x51))
        self.write(ARGS_AT + 0x10, 0x53)
        self.write(ARGS_AT + 0x18, height)
        try:
            self.machine.run(RELOAD, {RDI: EXCHANGE, RSI: ARGS_AT, RDX: 0x54})
        except Reached:
            return "stopped"
        return "done"

    def record(self, kind, round_number):
        entry, at = {"stakes": (RECORD_STAKES, DECODED), "gated": (RECORD_SIGNERS_GATED, DECODED + 0xB0), "plain": (RECORD_SIGNERS, DECODED + 0xB0)}[kind]
        self.machine.run(entry, {RDI: at, RSI: round_number})
        return "done"

    def tick(self, row, chain):
        self.put_context(row)
        self.machine.run(TICK, {RDI: OUT_AT, RSI: DECODED, RDX: chain, RCX: EXCHANGE, R8: 0x61, R9: 0x62})
        return "done"

    def history(self, kind):
        machine = self.machine
        if kind == "row":
            machine.run(HISTORY_ROW, {RDI: DECODED + 0x30, RSI: self.read(DECODED + 0x58)})
            at = machine.regs[RAX]
            return self.read(at) if at else None
        machine.run(HISTORY_KEY, {RDI: DECODED})
        return machine.regs[RDX] if machine.regs[RAX] else None

    def final(self):
        return self.pack(1, 1)


class Stubbed:
    """Every code address runs for real, but for the named outer steps."""

    def __init__(self, skip):
        self.skip = skip

    def __contains__(self, va):
        return va < 0x6000000 and va not in self.skip


def stake_rows(*seeds):
    return dict(validator_to_stake=[[address(seed + 30), dict(effective=seed * 7 + 1, target=seed * 9 + 2)] for seed in seeds])


def signer_rows(*seeds):
    return [address(seed + 60) for seed in seeds]


def tracked(rows=(), current=(1, 2), period=100, keep=9, low=500, round_number=1000, signer_list=(), signers=(3,), signer_period=50, signer_keep=9, signer_low=400, signer_round=1000):
    state = least_state()
    state["stakes"] = dict(epoch_values=dict(initial_round=low, round_to_val=[[key, stake_rows(key % 5)] for key in rows]), current=stake_rows(*current), period=period, n_keep=keep, current_round=round_number)
    state["jailed_signers"] = dict(epoch_values=dict(initial_round=signer_low, round_to_val=[[key, signer_rows(key % 4)] for key in signer_list]), current=signer_rows(*signers), period=signer_period, n_keep=signer_keep, current_round=signer_round)
    return state


class Case:
    def __init__(self, name, kind, state, ops):
        self.name, self.kind, self.state, self.ops = name, kind, state, ops


def spec_freeze(row, value):
    if row["freeze_tag"] & 0xFFFFFFFF == 1 and value >= row["freeze_height"]:
        return (0x73, row["freeze_height"])
    height = row["height"]
    if value < height or value > min(height + WINDOW, U64_MAX):
        return (0x72, value)
    row["freeze_tag"], row["freeze_height"] = 1, value
    return (OK,)


def spec_begin(row, index, new_time, round_number, flag, log):
    old = row["time"]
    if later(new_time, old):
        row["prev"], row["time"] = old, new_time
    row["height"] = min(row["height"] + 1, U64_MAX)
    row["tx_tag"] = 0
    row["round"] = row["stake_round"] = row["signer_round"] = round_number
    if index == 2:
        row["mirror"] = (row["height"], new_time)
    row["last"], changed = guard_step(millis(new_time), row["last"], row["width"])
    log.add("step", "begin_block", int(changed), True, True, time_bytes(old).hex(), flag & 0xFF, 0, row["height"], round_number)
    row["tx_tag"], row["tx_value"] = 1, 0
    return "done"


def spec_apply(row, block, chain, frozen, log):
    if row["freeze_tag"] == 1:
        if row["freeze_height"] < row["height"]:
            log.add("panic", "assertion failed: freeze_height >= self.locus.context.height()")
            return "stopped"
        if row["freeze_height"] == row["height"]:
            log.add("panic", "assertion failed: !self.state.is_frozen()")
            return "stopped"
    if block["round"] <= block["parent"]:
        log.add("panic", "assertion failed: round > parent_round")
    elif row["round"] != block["parent"]:
        log.add("panic", "round assert")
    elif (row["version"], row["fork_round"]) != (block["version"], block["fork_round"]):
        log.add("panic", "hardfork assert")
    elif chain != 3:
        log.add("panic", "assertion failed: features_ok")
    else:
        log.add("begin", True, time_bytes(block["time"]).hex(), block["round"], int(frozen == 2))
    return "stopped"


def spec_prune(rows, keep):
    del rows[:max(len(rows) - keep, 0)]


def spec_insert(rows, key, value):
    for index, row in enumerate(rows):
        if row[0] == key:
            rows[index] = [key, value]
            return
    rows.append([key, value])
    rows.sort(key=lambda row: row[0])


def spec_record(tracker, round_number):
    spec_insert(tracker["epoch_values"]["round_to_val"], round_number, copy.deepcopy(tracker["current"]))
    spec_prune(tracker["epoch_values"]["round_to_val"], tracker["n_keep"])


def spec_due(tracker, round_number):
    rows = tracker["epoch_values"]["round_to_val"]
    return not rows or round_number >= min(rows[-1][0] + tracker["period"], U64_MAX)


def spec_reset(row, value, log):
    row["initial_height"] = row["height"]
    row["version"] = min(row["version"] + 1, U64_MAX)
    row["fork_round"] = row["round"]
    row["freeze_tag"] = 0
    for name in ("stakes", "jailed_signers"):
        value[name]["epoch_values"]["initial_round"] = row["round"]
        spec_record(value[name], row["round"])
    if row["map_root"]:
        log.add("drop_map", 1, row["map_root"], row["map_height"], row["map_size"])
    else:
        log.add("drop_map", 0)
    log.add("drop_vec", row["vec_a"], row["vec_b"], row["vec_c"])
    row["map_root"] = row["map_size"] = row["vec_a"] = row["vec_c"] = row["word"] = 0


def spec_reload(row, value, height, parse_tag, path_error, log):
    log.add("path_name", 0x51, 0x53, height)
    if path_error:
        log.add("panic", "panic bound")
        return "stopped"
    if parse_tag == 2:
        log.add("panic", "unwrap failed")
        return "stopped"
    if row["height"] != height:
        log.add("panic", "height assert")
        return "stopped"
    spec_reset(row, value, log)
    return "done"


def spec_tick(row, value, log):
    now = millis(row["time"])
    round_number = row["round"]
    for name, label, tag in (("stage_reward_bucket_guard", "c_staking_stage_reward", "stage"), ("distribute_reward_bucket_guard", "c_staking_distribute_staged_rewards", "payout")):
        guard = value[name]
        guard["last_bucket"], changed = guard_step(now, guard["last_bucket"], guard["bucket_millis"])
        log.add(tag, label, int(changed))
    if spec_due(value["jailed_signers"], round_number):
        spec_record(value["jailed_signers"], round_number)
    if spec_due(value["stakes"], round_number):
        spec_record(value["stakes"], round_number)
    guard = value["stakes_decay_bucket_guard"]
    guard["last_bucket"], changed = guard_step(now, guard["last_bucket"], guard["bucket_millis"])
    log.add("decay", "decay_staking", int(changed))
    return "done"


def latest_key(tracker):
    low, cur = tracker["epoch_values"]["initial_round"], tracker["current_round"]
    end = min(low + 2000, U64_MAX)
    start = low if cur < end else max(cur - 200, low) if cur >= 200 else low
    keys = [row[0] for row in tracker["epoch_values"]["round_to_val"] if row[0] <= start]
    return keys[-1] if keys else None


def plain_context(row, index):
    got = {key: row[key] for key, _, _ in CONTEXT}
    got["time"] = time_bytes(row["time"]).hex()
    got["prev"] = time_bytes(row["prev"]).hex()
    got["last"] = row["last"]
    for name in ("map_root", "map_size", "vec_a", "vec_c", "word"):
        got[name] = row[name]
    mirror = row["mirror"]
    if mirror:
        got["mirror"] = (mirror[0], time_bytes(mirror[1]).hex())
    return got


def run_case(harness, case):
    harness.log = Log()
    if case.state is None:
        harness.fresh()
    else:
        harness.load(wire_input(ROOT, case.state))
    out = []
    for op in case.ops:
        name = op[0]
        if name == "freeze":
            row = context(**op[2])
            out.append((harness.freeze(op[1], row, op[3]), plain_digest(harness.get_context(op[1]))))
        elif name == "begin":
            row = context(**op[2])
            out.append((harness.begin(op[1], row, op[3], op[4], op[5]), plain_digest(harness.get_context(op[1], True))))
        elif name == "apply":
            row = context(**op[2])
            out.append(harness.apply(op[1], row, op[3], op[4], op[5]))
        elif name == "reset":
            row = context(**op[1])
            out.append((harness.reset(row), plain_digest(harness.get_context())))
        elif name == "reload":
            row = context(**op[1])
            result = harness.reload(row, op[2], op[3], op[4])
            out.append((result, plain_digest(harness.get_context()) if result == "done" else ""))
        elif name == "record":
            out.append(harness.record(op[1], op[2]))
        elif name == "tick":
            out.append(harness.tick(context(**op[1]), op[2]))
        elif name == "history":
            out.append(harness.history(op[1]))
    tail = hashlib.sha256(bytes.fromhex(harness.final())).hexdigest() if case.state is not None and not any(item[0] == "reload" and op_stopped(item, out) for item in case.ops) else ""
    return (tuple(map(repr, out)), tuple(map(repr, harness.log.rows)), tail)


def op_stopped(item, out):
    return any(row == ("stopped", "") for row in out)


def plain_digest(row):
    return hashlib.sha256(repr(sorted(row.items())).encode()).hexdigest()[:16]


def sync_rounds(book, row):
    """current_round of both trackers sits inside Exchange and the fixture writes it with the other context words."""
    book["stakes"]["current_round"] = row["stake_round"]
    book["jailed_signers"]["current_round"] = row["signer_round"]


def spec_run(case):
    value = canon(ROOT, case.state) if case.state is not None else None
    book = copy.deepcopy(value)
    log = Log()
    out = []
    stopped = False
    for op in case.ops:
        name = op[0]
        if name == "freeze":
            row = context(**op[2])
            result = spec_freeze(row, op[3])
            out.append((result, plain_digest(plain_context(row, op[1]))))
        elif name == "begin":
            row = context(**op[2])
            result = spec_begin(row, op[1], op[3], op[4], op[5], log)
            out.append((result, plain_digest(plain_context(row, op[1]))))
        elif name == "apply":
            row = context(**op[2])
            out.append(spec_apply(row, op[3], op[4], op[5], log))
        elif name == "reset":
            row = context(**op[1])
            sync_rounds(book, row)
            spec_reset(row, book, log)
            out.append(("done", plain_digest(plain_context(row, 0))))
        elif name == "reload":
            row = context(**op[1])
            sync_rounds(book, row)
            result = spec_reload(row, book, op[2], op[3], op[4], log)
            stopped = stopped or result == "stopped"
            out.append((result, plain_digest(plain_context(row, 0)) if result == "done" else ""))
        elif name == "record":
            if op[1] == "stakes":
                spec_record(book["stakes"], op[2])
            elif op[1] == "plain":
                spec_record(book["jailed_signers"], op[2])
            elif spec_due(book["jailed_signers"], op[2]):
                spec_record(book["jailed_signers"], op[2])
            out.append("done")
        elif name == "tick":
            row = context(**op[1])
            sync_rounds(book, row)
            out.append(spec_tick(row, book, log))
        elif name == "history":
            out.append(latest_key(book["stakes"]))
    tail = hashlib.sha256(emit(ROOT, book, True, True)).hexdigest() if book is not None and not stopped else ""
    return (tuple(map(repr, out)), tuple(map(repr, log.rows)), tail)


def freeze_cases():
    cases = []
    top = U64_MAX
    near = top - WINDOW
    rows = (
        ("empty_low", dict(height=500), 499), ("empty_same", dict(height=500), 500), ("empty_next", dict(height=500), 501), ("empty_top", dict(height=500), 50500), ("empty_past", dict(height=500), 50501),
        ("zero_height", dict(height=0), 0), ("zero_top", dict(height=0), 50000), ("zero_past", dict(height=0), 50001),
        ("near_edge", dict(height=near - 1), top - 1), ("near_edge_past", dict(height=near - 1), top), ("near_exact", dict(height=near), top), ("near_over", dict(height=near + 1), top), ("near_over_low", dict(height=near + 1), near), ("top_height", dict(height=top), top), ("top_low", dict(height=top), top - 1),
        ("set_same", dict(height=500, freeze_tag=1, freeze_height=800), 800), ("set_above", dict(height=500, freeze_tag=1, freeze_height=800), 801), ("set_below", dict(height=500, freeze_tag=1, freeze_height=800), 799), ("set_to_height", dict(height=500, freeze_tag=1, freeze_height=800), 500), ("set_below_height", dict(height=500, freeze_tag=1, freeze_height=800), 499),
        ("set_past_below_old", dict(height=500, freeze_tag=1, freeze_height=400), 300), ("set_past_equal", dict(height=500, freeze_tag=1, freeze_height=400), 400), ("set_far", dict(height=500, freeze_tag=1, freeze_height=90000), 60000), ("set_far_ok", dict(height=500, freeze_tag=1, freeze_height=90000), 50500), ("set_far_above", dict(height=500, freeze_tag=1, freeze_height=90000), 90001), ("stale_word_empty", dict(height=500, freeze_tag=0, freeze_height=800), 900),
    )
    for index in range(3):
        for name, change, value in rows:
            cases.append(Case("freeze_%d_%s" % (index, name), "freeze", None, [("freeze", index, change, value)]))
    return cases


def begin_cases():
    cases = []
    later_day = moment(2025, 64, 0, 0, 5)
    same_day = moment(2025, 63, 18367, 500000001, 5)
    next_second = moment(2025, 63, 18368, 0, 5)
    earlier_nano = moment(2025, 63, 18367, 499999999, 5)
    earlier_second = moment(2025, 63, 18366, 900000000, 5)
    earlier_day = moment(2025, 62, 86399, 999999999, 5)
    old_year = moment(-3, 40, 10, 5)
    far_year = moment(262000, 200, 86399, 999000000, 5)
    rows = (
        ("later_day", dict(), later_day, 901, 0), ("later_nano", dict(), same_day, 901, 0), ("later_second", dict(), next_second, 950, 1), ("equal", dict(), BASE_TIME, 901, 0), ("earlier_nano", dict(), earlier_nano, 901, 0), ("earlier_second", dict(), earlier_second, 901, 0), ("earlier_day", dict(), earlier_day, 901, 1),
        ("flags_differ", dict(), moment(2025, 63, 18367, 500000000, 6), 901, 0), ("flags_low", dict(), moment(2025, 63, 18367, 500000000, 4), 901, 0), ("negative_year", dict(time=moment(-5, 40, 10, 5)), old_year, 901, 0), ("negative_to_positive", dict(time=moment(-5, 40, 10, 5)), later_day, 901, 0), ("positive_to_negative", dict(), old_year, 901, 0),
        ("height_top", dict(height=U64_MAX), later_day, 901, 0), ("height_edge", dict(height=U64_MAX - 1), later_day, 901, 0), ("round_top", dict(), later_day, U64_MAX, 0), ("round_equal", dict(), later_day, 900, 0), ("round_below", dict(), later_day, 3, 0), ("tx_cleared", dict(tx_tag=0, tx_value=77), later_day, 901, 0),
        ("bucket_same", dict(last=485272), BASE_TIME, 901, 0), ("bucket_up", dict(last=485271), BASE_TIME, 901, 0), ("bucket_down", dict(last=485273), BASE_TIME, 901, 0), ("bucket_width_one", dict(width=1), later_day, 901, 0), ("bucket_width_wide", dict(width=1 << 33), later_day, 901, 0), ("bucket_width_wide_big", dict(width=(1 << 33) + 1, last=1), far_year, 901, 0), ("bucket_far", dict(), far_year, 901, 0), ("bucket_old_year", dict(), old_year, 901, 0),
        ("leap_day", dict(), moment(2024, 60, 0, 0, 5), 901, 0), ("year_end", dict(), moment(9999, 365, 86399, 999999999, 5), 901, 0), ("before_epoch", dict(), moment(1960, 1, 0, 0, 5), 901, 0), ("year_one", dict(), moment(1, 1, 0, 0, 5), 901, 0), ("year_zero", dict(), moment(0, 366, 0, 0, 5), 901, 0), ("year_400_back", dict(), moment(-400, 2, 1, 1, 5), 901, 0), ("millis_cut", dict(), moment(2025, 64, 1, 999999, 5), 901, 0), ("millis_up", dict(), moment(2025, 64, 1, 1000000, 5), 901, 0),
    )
    for index in range(3):
        for name, change, new_time, round_number, flag in rows:
            cases.append(Case("begin_%d_%s" % (index, name), "begin", None, [("begin", index, change, new_time, round_number, flag)]))
    return cases


def block(**change):
    row = dict(round=905, parent=900, version=3, fork_round=70, time=moment(2025, 64, 9, 8, 5))
    row.update(change)
    return row


def apply_cases():
    cases = []
    rows = (
        ("good", dict(), block(), 3, 0), ("good_frozen_word", dict(), block(), 3, 2), ("good_word_one", dict(), block(), 3, 1), ("good_word_three", dict(), block(), 3, 3), ("good_freeze_ahead", dict(freeze_tag=1, freeze_height=501), block(), 3, 0), ("good_stale_height", dict(freeze_tag=0, freeze_height=500), block(), 3, 0),
        ("freeze_equal", dict(freeze_tag=1, freeze_height=500), block(), 3, 0), ("freeze_past", dict(freeze_tag=1, freeze_height=499), block(), 3, 0), ("round_equal", dict(), block(round=900), 3, 0), ("round_below", dict(), block(round=899), 3, 0), ("round_next", dict(), block(round=901), 3, 0),
        ("parent_other", dict(), block(parent=901, round=905), 3, 0), ("parent_low", dict(), block(parent=899, round=905), 3, 0), ("version_other", dict(), block(version=4), 3, 0), ("fork_round_other", dict(), block(fork_round=71), 3, 0), ("chain_two", dict(), block(), 2, 0), ("chain_one", dict(), block(), 1, 0), ("chain_zero", dict(), block(), 0, 0),
        ("order_round_before_parent", dict(), block(round=800, parent=899), 3, 0), ("order_parent_before_fork", dict(), block(parent=899, version=9), 3, 0), ("order_fork_before_chain", dict(), block(version=9), 1, 0), ("order_freeze_first", dict(freeze_tag=1, freeze_height=500), block(round=1, version=9), 1, 0),
    )
    for index in range(3):
        for name, change, item, chain, frozen in rows:
            cases.append(Case("apply_%d_%s" % (index, name), "apply", None, [("apply", index, change, item, chain, frozen)]))
    return cases


def reset_cases():
    cases = []
    rows = (
        ("empty", tracked(), dict()), ("rows", tracked(rows=(400, 500, 600), signer_list=(450, 550)), dict()), ("key_present", tracked(rows=(500, 900), signer_list=(900,)), dict()), ("key_above", tracked(rows=(900, 1000), signer_list=(899, 901)), dict()),
        ("keep_zero", tracked(rows=(400, 500), keep=0, signer_list=(450,), signer_keep=0), dict()), ("keep_one", tracked(rows=(400, 500), keep=1, signer_list=(450, 460), signer_keep=1), dict()), ("keep_two", tracked(rows=(400, 500, 600), keep=2, signer_list=(450, 460, 470), signer_keep=2), dict()), ("keep_exact", tracked(rows=(400, 500), keep=3, signer_list=(450,), signer_keep=2), dict()),
        ("current_empty", tracked(rows=(400,), current=(), signers=()), dict()), ("many", tracked(rows=tuple(range(100, 2000, 100)), keep=12, signer_list=tuple(range(50, 1500, 50)), signer_keep=7, current=(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13), signers=tuple(range(1, 15))), dict()), ("key_replaced_many", tracked(rows=tuple(range(300, 1300, 100)), keep=5, signer_list=tuple(range(300, 1300, 100)), signer_keep=5, current=tuple(range(14))), dict()),
        ("map_set", tracked(rows=(400,)), dict(map_root=0x7001, map_height=2, map_size=5)), ("vec_set", tracked(rows=(400,)), dict(vec_a=0x31, vec_b=0x32, vec_c=0x33, word=8)), ("version_top", tracked(), dict(version=U64_MAX)), ("version_edge", tracked(), dict(version=U64_MAX - 1)), ("freeze_cleared", tracked(rows=(400,)), dict(freeze_tag=1, freeze_height=500)), ("zero_round", tracked(), dict(round=0, height=0)), ("top_round", tracked(rows=(U64_MAX,), signer_list=(U64_MAX,)), dict(round=U64_MAX)),
    )
    for name, state, change in rows:
        cases.append(Case("reset_" + name, "reset", state, [("reset", change)]))
        cases.append(Case("reload_" + name, "reload", state, [("reload", change, context(**change)["height"], 0, False)]))
    state = tracked(rows=(400, 500))
    cases.append(Case("reload_height_other", "reload", state, [("reload", dict(), 501, 0, False)]))
    cases.append(Case("reload_parse_error", "reload", state, [("reload", dict(), 500, 2, False)]))
    cases.append(Case("reload_path_error", "reload", state, [("reload", dict(), 500, 0, True)]))
    return cases


def record_cases():
    cases = []
    for name, state, ops in (
        ("stakes_empty", tracked(), [("record", "stakes", 700)]), ("stakes_add", tracked(rows=(400, 500)), [("record", "stakes", 700)]), ("stakes_replace", tracked(rows=(400, 500)), [("record", "stakes", 500)]), ("stakes_low_key", tracked(rows=(400, 500)), [("record", "stakes", 3)]), ("stakes_prune", tracked(rows=(400, 500), keep=2), [("record", "stakes", 700)]), ("stakes_prune_zero", tracked(rows=(400, 500), keep=0), [("record", "stakes", 700)]), ("stakes_prune_low_key", tracked(rows=(400, 500), keep=2), [("record", "stakes", 3)]), ("stakes_prune_many", tracked(rows=tuple(range(100, 2000, 50)), keep=4), [("record", "stakes", 5000)]), ("stakes_clone_many", tracked(rows=(400,), current=tuple(range(30))), [("record", "stakes", 700)]),
        ("gated_empty", tracked(), [("record", "gated", 700)]), ("gated_early", tracked(signer_list=(500,)), [("record", "gated", 549)]), ("gated_exact", tracked(signer_list=(500,)), [("record", "gated", 550)]), ("gated_late", tracked(signer_list=(500,)), [("record", "gated", 551)]), ("gated_same", tracked(signer_list=(500,)), [("record", "gated", 500)]), ("gated_low", tracked(signer_list=(500,)), [("record", "gated", 3)]), ("gated_top_key", tracked(signer_list=(U64_MAX - 10,), signer_period=50), [("record", "gated", U64_MAX)]), ("gated_top_key_low", tracked(signer_list=(U64_MAX - 10,), signer_period=50), [("record", "gated", U64_MAX - 1)]), ("gated_prune", tracked(signer_list=(400, 500), signer_keep=2), [("record", "gated", 700)]), ("gated_prune_many", tracked(signer_list=tuple(range(100, 2000, 50)), signer_keep=3), [("record", "gated", 5000)]), ("gated_last_of_many", tracked(signer_list=tuple(range(100, 2000, 50)), signer_keep=90), [("record", "gated", 1999)]),
        ("gated_last_of_many_exact", tracked(signer_list=tuple(range(100, 2000, 50)), signer_keep=90), [("record", "gated", 2000)]), ("plain_empty", tracked(), [("record", "plain", 700)]), ("plain_early", tracked(signer_list=(500,)), [("record", "plain", 501)]), ("plain_replace", tracked(signer_list=(500,)), [("record", "plain", 500)]), ("plain_keep", tracked(signer_list=(500, 600), signer_keep=1), [("record", "plain", 700)]), ("plain_keep_zero", tracked(signer_list=(500,), signer_keep=0), [("record", "plain", 700)]), ("plain_clone_many", tracked(signers=tuple(range(30))), [("record", "plain", 700)]),
    ):
        cases.append(Case("record_" + name, "record", state, ops))
    return cases


def guards(state, **change):
    for name, value in change.items():
        state[name] = value
    return state


def tick_cases():
    cases = []
    wide = dict(last_bucket=0, bucket_millis=1000)
    def fixed(*args, **more):
        state = tracked(*args, **more)
        state["stage_reward_bucket_guard"] = dict(last_bucket=7, bucket_millis=3600000)
        state["distribute_reward_bucket_guard"] = dict(last_bucket=485272, bucket_millis=3600000)
        state["stakes_decay_bucket_guard"] = dict(last_bucket=1 << 60, bucket_millis=86400000)
        return state
    for name, state, change in (
        ("no_rows", fixed(), dict(round=1000)), ("stake_early", fixed(rows=(901,)), dict(round=1000)), ("stake_exact", fixed(rows=(900,)), dict(round=1000)), ("stake_late", fixed(rows=(899,)), dict(round=1000)), ("stake_above", fixed(rows=(5000,)), dict(round=1000)), ("stake_top", fixed(rows=(U64_MAX - 10,)), dict(round=U64_MAX)), ("stake_top_low", fixed(rows=(U64_MAX - 10,)), dict(round=U64_MAX - 1)), ("stake_last_of_many", fixed(rows=tuple(range(100, 2000, 50)), keep=90), dict(round=2049)), ("stake_last_of_many_due", fixed(rows=tuple(range(100, 2000, 50)), keep=90), dict(round=2050)), ("stake_many_deep", fixed(rows=tuple(range(100, 9000, 50)), keep=2000, current=(1,)), dict(round=9000)),
        ("signer_early", fixed(rows=(990,), signer_list=(951,)), dict(round=1000)), ("signer_exact", fixed(rows=(990,), signer_list=(950,)), dict(round=1000)), ("both_due", fixed(rows=(900,), signer_list=(950,)), dict(round=1000)), ("both_prune", fixed(rows=(800, 900), keep=2, signer_list=(900, 950), signer_keep=2), dict(round=1000)), ("guards_all_up", guards(fixed(rows=(990,)), stage_reward_bucket_guard=wide, distribute_reward_bucket_guard=wide, stakes_decay_bucket_guard=wide), dict(round=1000)), ("guards_wide", guards(fixed(rows=(990,)), stage_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1 << 33), distribute_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1 << 33), stakes_decay_bucket_guard=dict(last_bucket=0, bucket_millis=1 << 33)), dict(round=1000)),
    ):
        cases.append(Case("tick_" + name, "tick", state, [("tick", change, 3)]))
    return cases


def history_cases():
    cases = []
    keys = (500, 600, 700, 1700, 2300, 2500, 2700)
    for cur in (500, 501, 2499, 2500, 2501, 2699, 2700, 2701, 2899, 2900, 2901, 5000):
        for kind in ("row", "key"):
            cases.append(Case("history_%s_%d" % (kind, cur), "history", tracked(rows=keys, low=500, round_number=cur), [("history", kind)]))
    for name, state in (("no_rows", tracked(low=500, round_number=3000)), ("before_low", tracked(rows=(600,), low=500, round_number=510)), ("low_zero", tracked(rows=(0, 150), low=0, round_number=100)), ("low_zero_past", tracked(rows=(0, 150, 2000), low=0, round_number=2199)), ("low_top", tracked(rows=(U64_MAX - 100,), low=U64_MAX - 100, round_number=U64_MAX)), ("low_edge", tracked(rows=(U64_MAX - 2000,), low=U64_MAX - 2000, round_number=U64_MAX)), ("low_edge_two", tracked(rows=(U64_MAX - 1999,), low=U64_MAX - 1999, round_number=U64_MAX)), ("first_key_above", tracked(rows=(3000,), low=500, round_number=3000)), ("deep", tracked(rows=tuple(range(0, 9000, 50)), low=0, round_number=5005))):
        for kind in ("row", "key"):
            cases.append(Case("history_%s_%s" % (kind, name), "history", state, [("history", kind)]))
    return cases


def life_cases():
    """A fork inside the window: the first 2000 rounds read the row the fork wrote."""
    cases = []
    start = tracked(rows=(8000, 8100, 8200), low=1000, round_number=8250, keep=5, period=100, signer_list=(8200,), signer_low=1000, signer_round=8250, signer_keep=5)
    fork = dict(round=8250, height=9000, stake_round=8250, signer_round=8250)
    for name, tail in (("fork_read", [("history", "row")]), ("fork_read_key", [("history", "key")]), ("fork_again", [("reset", dict(round=8260, height=9001, version=4, fork_round=8250, stake_round=8260, signer_round=8260)), ("history", "row")]), ("fork_record", [("record", "stakes", 8350), ("history", "key")]), ("fork_gated", [("record", "gated", 8299), ("record", "gated", 8300), ("history", "row")])):
        cases.append(Case("life_" + name, "life", start, [("reset", fork)] + tail))
    return cases


def all_cases():
    return freeze_cases() + begin_cases() + apply_cases() + reset_cases() + record_cases() + tick_cases() + history_cases() + life_cases()


def vector_cases(count):
    draw = random.Random(94)
    cases = []
    for number in range(count):
        kind = number % 5
        name = "v%d" % number
        if kind == 0:
            height = draw.choice((0, 7, 1000, U64_MAX - 50000, U64_MAX - 3, draw.getrandbits(64)))
            tag = draw.randrange(2)
            old = draw.choice((height, height + 3, draw.randrange(70000)))
            cases.append(Case(name, "freeze", None, [("freeze", number % 3, dict(height=height & U64_MAX, freeze_tag=tag, freeze_height=old & U64_MAX), min(height + draw.randrange(-5, 50010), U64_MAX) if height + 60000 < 1 << 64 and height > 5 else draw.getrandbits(64))]))
        elif kind == 1:
            new_time = moment(draw.randrange(-500, 9000), draw.randrange(1, 366), draw.randrange(86400), draw.randrange(1000000000), draw.randrange(16))
            cases.append(Case(name, "begin", None, [("begin", number % 3, dict(width=draw.choice((1, 1000, 3600000, 1 << 34)), last=draw.getrandbits(draw.choice((8, 30, 45)))), new_time, draw.getrandbits(64), draw.randrange(2))]))
        elif kind == 2:
            size = draw.randrange(0, 14)
            keys = sorted(draw.sample(range(100, 9000), size))
            cases.append(Case(name, "record", tracked(rows=keys, keep=draw.randrange(0, 16)), [("record", "stakes", draw.choice(keys or [55]) if draw.randrange(3) == 0 else draw.randrange(50, 9500))]))
        elif kind == 3:
            size = draw.randrange(0, 14)
            keys = sorted(draw.sample(range(100, 9000), size))
            step = draw.choice(("gated", "plain"))
            cases.append(Case(name, "record", tracked(signer_list=keys, signer_keep=draw.randrange(0, 16), signer_period=draw.choice((1, 50, 1000))), [("record", step, draw.choice(keys or [55]) if draw.randrange(3) == 0 else draw.randrange(50, 9500))]))
        else:
            keys = sorted(draw.sample(range(0, 9000), draw.randrange(1, 12)))
            low = keys[0]
            cases.append(Case(name, "history", tracked(rows=keys, low=low, round_number=draw.randrange(low, 12000)), [("history", draw.choice(("row", "key")))]))
    return cases


NAMES = {
    FREEZE[0]: "freeze_gate", FREEZE[1]: "freeze_gate_copy", FREEZE[2]: "freeze_gate_third", BEGIN[0]: "begin_block", BEGIN[1]: "begin_block_copy", BEGIN[2]: "begin_block_third",
    APPLY[0]: "apply_block", APPLY[1]: "apply_block_copy", APPLY[2]: "apply_block_third", RESET: "hardfork_reset", RELOAD: "frozen_state_reload", RECORD_STAKES: "stakes_record", RECORD_SIGNERS_GATED: "signers_record_gated",
    RECORD_SIGNERS: "signers_record_plain", HISTORY_KEY: "history_latest_key",
}
HELPERS = {
    TICK: "context_staking_tick", HISTORY_ROW: "context_history_latest_row", 0x2FE1490: "context_history_range",
    0x33EC760: "stakes_clone", 0x33A2C20: "stakes_insert", 0x33ADEC0: "stakes_pop_first", 0x33E31F0: "signers_clone", 0x33A5C70: "signers_insert", 0x33AE090: "signers_pop_first",
    0x2898770: "reset_stakes_clone", 0x2856EA0: "reset_stakes_insert", 0x2868E90: "reset_stakes_pop_first", 0x289F5F0: "reset_signers_clone", 0x284E860: "reset_signers_insert", 0x28691A0: "reset_signers_pop_first",
}
PINS = (
    ("apply_freeze_tag", 0x2209daf, "4d8b8e900b0000", "mov r9,[r14+0xb90]: scheduled_freeze_height tag"),
    ("apply_freeze_value", 0x2209dba, "4d8b96980b0000", "mov r10,[r14+0xb98]: scheduled_freeze_height value"),
    ("apply_freeze_height", 0x2209dcb, "4c3b5728", "cmp r10,[rdi+0x28]: against Context height"),
    ("apply_round_gate", 0x2209ddb, "4839f2", "cmp rdx,rsi: block round against parent round"),
    ("apply_parent_gate", 0x2209df1, "4839f7", "cmp rdi,rsi: Context round against parent round"),
    ("apply_chain_gate", 0x2209e2a, "80bbf208000003", "cmp byte [rbx+0x8f2],3: this build applies chain 3 only"),
    ("apply_frozen_word", 0x2209e41, "83bbe83a000002", "cmp dword [rbx+0x3ae8],2: flag handed to begin_block"),
    ("apply_begin_call", 0x2209e56, "e805ed4e00", "call 0x26f8b60"),
    ("apply_tick_site", 0x220a5ee, "ff153c945603", "call through slot 0x5773a30: staking tick"),
    ("begin_prev_time", 0x26f8ba6, "897b74", "mov [rbx+0x74],edi: old time goes to prev_time"),
    ("begin_height_inc", 0x26f8bc0, "48ffc1", "inc rcx: height"),
    ("begin_tx_none", 0x26f8bd2, "48c70300000000", "mov qword [rbx],0: tx_index None during the block step"),
    ("begin_round", 0x26f8bd9, "48895330", "mov [rbx+0x30],rdx: Context round"),
    ("begin_stake_round", 0x26f8bdd, "48899350090000", "mov [rbx+0x950],rdx: stakes current_round"),
    ("begin_signer_round", 0x26f8be4, "488993f0090000", "mov [rbx+0x9f0],rdx: jailed_signers current_round"),
    ("begin_guard_width", 0x26f8c95, "488b8bf8380000", "mov rcx,[rbx+0x38f8]: begin_block_logic_guard bucket_millis"),
    ("begin_step_call", 0x26f8d15, "e8a60ab3ff", "call 0x22297c0"),
    ("begin_tx_some", 0x26f8d1a, "48c70301000000", "mov qword [rbx],1: tx_index Some"),
    ("begin_tx_zero", 0x26f8d21, "48c7430800000000", "mov qword [rbx+8],0: tx_index value 0"),
    ("third_mirror_height", 0x4cdf3fb, "4889bb18100000", "mov [rbx+0x1018],rdi: third copy keeps height in a second place"),
    ("third_mirror_time", 0x4cdf40e, "48898b20100000", "mov [rbx+0x1020],rcx: third copy keeps the block time there"),
    ("freeze_tag_test", 0x2703a9d, "83be900b000001", "cmp dword [rsi+0xb90],1"),
    ("freeze_lower_only", 0x2703aad, "4839ca", "cmp rdx,rcx: a set height can only move down"),
    ("freeze_status_lower", 0x2703af3, "66c7007300", "mov word [rax],0x73"),
    ("freeze_low", 0x2703ab6, "4839ca", "cmp rdx,rcx: value against height"),
    ("freeze_span_guard", 0x2703abb, "4881f9b03cff", "cmp rcx,-50000: overflow branch of the window"),
    ("freeze_span", 0x2703ac4, "4881c150c30000", "add rcx,0xc350: 50000 heights"),
    ("freeze_status_window", 0x2703b09, "66c7007200", "mov word [rax],0x72"),
    ("freeze_store_tag", 0x2703adb, "48c786900b000001000000", "mov qword [rsi+0xb90],1"),
    ("freeze_store_value", 0x2703ae6, "488996980b0000", "mov [rsi+0xb98],rdx"),
    ("vote_limit", 0x23589b4, "48b8cccccccccccccc0c", "mov rax,0x0ccccccccccccccc: limit on the vote value before the gate"),
    ("vote_gate_call", 0x23589cf, "e8bcb03a00", "call 0x2703a90"),
    ("host_apply_call", 0x2268f61, "ff1541ab5003", "call through slot 0x5773aa8: target 0x3751e80"),
    ("host_frozen_mark", 0x2268f67, "c683f049000001", "mov byte [rbx+0x49f0],1"),
    ("host_context_copy", 0x2268fd4, "0f114b10", "movups [rbx+0x10],xmm1: Context words copied out of the Exchange at rbx+0x88"),
    ("host_freeze_tag", 0x2269014, "83bb180c000001", "cmp dword [rbx+0xc18],1: Exchange+0xb90"),
    ("host_freeze_value", 0x2269021, "483983200c0000", "cmp [rbx+0xc20],rax: against height"),
    ("host_equal", 0x226902e, "0f8530010000", "jne: only freeze_height == height goes on"),
    ("host_reset_call", 0x2269157, "e8d4edf9ff", "call 0x2207f30"),
    ("reset_initial_height", 0x2207f4c, "48894f10", "mov [rdi+0x10],rcx: initial_height takes height"),
    ("reset_version", 0x2207f54, "48ffc0", "inc rax: hardfork version"),
    ("reset_fork_round", 0x2207f66, "4c896720", "mov [rdi+0x20],r12: hardfork round"),
    ("reset_freeze_clear", 0x2207f6a, "48c787900b000000000000", "mov qword [rdi+0xb90],0"),
    ("reset_stakes_low", 0x2207f75, "4c89a728090000", "mov [rdi+0x928],r12: stakes initial_round"),
    ("reset_stakes_keep", 0x2208010, "483b8348090000", "cmp rax,[rbx+0x948]: n_keep"),
    ("reset_signers_low", 0x2208060, "4c89a3b0090000", "mov [rbx+0x9b0],r12: jailed_signers initial_round"),
    ("reset_signers_keep", 0x220818a, "483b83e8090000", "cmp rax,[rbx+0x9e8]: n_keep"),
    ("reload_height", 0x32727d3, "4c39e0", "cmp rax,r12: file height against the wanted height"),
    ("reload_record_stakes", 0x3272830, "e8db715600", "call 0x37d9a10"),
    ("reload_record_signers", 0x327284d, "e8ee705600", "call 0x37d9940"),
    ("reload_host_call", 0x22b4c2c, "ff1596f04b03", "call through slot 0x5773cc8"),
    ("tick_signers", 0x3996a55, "e89630e4ff", "call 0x37d9af0: gate inside"),
    ("tick_period", 0x3996b52, "498b4e28", "mov rcx,[r14+0x28]: stakes period"),
    ("tick_due", 0x3996b68, "4939c4", "cmp r12,rax: round against last key plus period"),
    ("tick_stakes", 0x3996b73, "e8982ee4ff", "call 0x37d9a10: gate in the host"),
    ("tick_round", 0x399674e, "488b4130", "mov rax,[rcx+0x30]: Context round"),
    ("signers_period", 0x37d9bf2, "488b0b", "mov rcx,[rbx]: jailed_signers period"),
    ("signers_due", 0x37d9c07, "4939c6", "cmp r14,rax"),
    ("key_cur", 0x37d9d05, "488b5758", "mov rdx,[rdi+0x58]: current_round"),
    ("ctx_initial_height", 0x39872d1, "488d4b10", "lea rcx,[rbx+0x10]"),
    ("ctx_hardfork", 0x398731a, "488d7b18", "lea rdi,[rbx+0x18]"),
    ("ctx_height", 0x3987362, "488d4b28", "lea rcx,[rbx+0x28]"),
    ("ctx_round", 0x39873ad, "488b7330", "mov rsi,[rbx+0x30]"),
    ("ctx_time", 0x39873cc, "488d4b60", "lea rcx,[rbx+0x60]"),
    ("ctx_prev_time", 0x39873f7, "488d4b6c", "lea rcx,[rbx+0x6c]"),
    ("ser_freeze", 0x275b14c, "4d8b86900b0000", "mov r8,[r14+0xb90]"),
    ("ser_freeze_key", 0x275b15a, "488d15c641c9fd", "lea rdx,[rip]: key scheduled_freeze_height"),
    ("ser_guard", 0x275b44b, "4d8d86f8380000", "lea r8,[r14+0x38f8]"),
    ("ser_guard_key", 0x275b452, "488d15a340c9fd", "lea rdx,[rip]: key begin_block_logic_guard"),
)
TEXTS = (
    ("assert_freeze", 0x3d7418, "assertion failed: freeze_height >= self.locus.context.height()", "panic of apply_block and of the host"),
    ("assert_round", 0x3d746e, "assertion failed: round > parent_round", "panic of apply_block"),
    ("assert_frozen", 0x3d74b1, "assertion failed: !self.state.is_frozen()", "panic of apply_block"),
    ("assert_features", 0x3d7494, "assertion failed: features_ok", "panic of apply_block when the chain byte is not 3"),
    ("log_hardfork", 0x1ed148, "applying hardfork to frozen local abci_state ", "log text passed by the host just before the reset"),
    ("key_freeze", 0x3ef327, "scheduled_freeze_height", "Exchange key at +0xb90"),
    ("key_guard", 0x3ef4fc, "begin_block_logic_guard", "Exchange key at +0x38f8"),
    ("label_begin", 0x3efa04, "begin_block", "label given to the block step"),
    ("key_initial_height", 0x5a63f8, "initial_height", "Context +0x10"),
    ("key_hardfork", 0x20a618, "hardfork", "Context +0x18"),
    ("key_height", 0x5a6406, "height", "Context +0x28"),
    ("key_tx_index", 0x20b150, "tx_index", "Context +0"),
    ("key_time", 0x209d88, "time", "Context +0x60"),
    ("key_prev_time", 0x5a6411, "prev_time", "Context +0x6c"),
    ("text_abci_height", 0x1f58e5, "freeze_abci_height", "text near the frozen state reader"),
)
SAMPLE = 1
VECTORS = 300
WORKERS = 4
MUTANT_CASES = 6
SURVIVED = "equal outcome on every picked case that reaches the row"
MUTANT_STATE = {}
MUTANT_STEP_LIMIT = 800000
TEXT_TABLE = 0x59A8D0
STATUSES = (0x72, 0x73)
VOTE_TABLE = 0x3DD1B8
VOTE_ARM = 0x23589B0
SITES = {BEGIN[0]: "begin_block", BEGIN[1]: "begin_block_copy", BEGIN[2]: "begin_block_third", RESET: "hardfork_reset", FREEZE[0]: "freeze_gate", FREEZE[1]: "freeze_gate_copy", FREEZE[2]: "freeze_gate_third", RECORD_STAKES: "stakes_record", RECORD_SIGNERS_GATED: "signers_record_gated", RECORD_SIGNERS: "signers_record_plain"}
SLOT_SITES = {0x5773CC8: "frozen_state_reload", 0x5773A30: "staking_tick"}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def text_of(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def status_rows(image):
    rows = []
    for tag in STATUSES:
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        code = text_of(image, arm, 64)
        at = code.find(b"\x48\x8d\x15")
        template = arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
        data = text_of(image, template + 1, 48).split(b"\0")[0]
        rows.append(("%#x" % tag, "%#x" % arm, "%#x" % template, re.sub(rb"\xc0.?", b"{}", data, flags=re.S).decode("ascii")))
    return rows


def pin_rows(image):
    rows = []
    for name, va, data, meaning in PINS:
        got = text_of(image, va, len(data) // 2).hex()
        if got != data:
            raise EvidenceError("pin %s: %s" % (name, got))
        rows.append((name, "%#x" % va, data, meaning))
    return rows


def text_rows(image):
    rows = []
    for name, va, text, meaning in TEXTS:
        got = text_of(image, va, len(text)).decode("ascii")
        if got != text:
            raise EvidenceError("text %s: %s" % (name, got))
        rows.append((name, "%#x" % va, text, meaning))
    return rows


def vote_rows(image):
    rows = []
    for index in range(0x60):
        target = VOTE_TABLE + struct.unpack_from("<i", image.blob, image.offset(VOTE_TABLE) + 4 * index)[0]
        if target == VOTE_ARM:
            rows.append((index, "%#x" % (VOTE_TABLE + 4 * index), "%#x" % target))
    return rows


def caller_rows(image):
    base, text = image.text_bytes()
    rows = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if target in SLOT_SITES:
            rows.append((SLOT_SITES[target], "slot %#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
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
        except (Halt, EvidenceError, Panicked, Reached, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, TypeError, struct.error):
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
    harness = Clock(state["image"], patch, state["cache"])
    harness.snapshots = state["snapshots"]
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases, reach, cost, harness, sample):
    wants = {case.name: spec_run(case) for case in cases}
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=harness.machine.cache, snapshots=harness.snapshots)
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
        harness = state["worker"] = Clock(state["image"])
        harness.snapshots = state["snapshots"]
    return check_case(harness, state["all"][index])


def analyse(image, mutate=True, vectors=VECTORS, cases=None, sample=SAMPLE):
    harness = Clock(image)
    named = cases if cases is not None else all_cases()
    generated = vector_cases(vectors)
    every = named + generated
    for case in every:
        if case.state is not None:
            harness.load(wire_input(ROOT, case.state))
    MUTANT_STATE.update(image=image, all=every, snapshots=harness.snapshots)
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
    result = dict(table=table, named=rows, vector_count=len(generated), pins=pin_rows(image), texts=text_rows(image), statuses=status_rows(image), votes=vote_rows(image), sizes={target: image.exact_fde(target)[1] - target for target in NAMES}, helpers=[(HELPERS[va], "%#x" % va, image.exact_fde(va)[1] - va, sum(1 for at in seen if va <= at < image.exact_fde(va)[1])) for va in sorted(HELPERS)])
    if mutate:
        result["callers"] = caller_rows(image)
        pool = [case for case in named if cost[case.name] < MUTANT_STEP_LIMIT // 2]
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
    tsv("helpers.tsv", ("name", "address", "body_bytes", "reached_rows"), result["helpers"])
    tsv("constants.tsv", ("name", "address", "bytes", "meaning"), result["pins"])
    tsv("texts.tsv", ("name", "address", "text", "meaning"), result["texts"])
    tsv("status-text.tsv", ("tag", "display_arm", "template", "text"), result["statuses"])
    tsv("vote-arm.tsv", ("jump_index", "table_row", "target"), result["votes"])
    tsv("scenarios.tsv", ("case", "group", "results", "log_rows", "state_sha256"), [(case.name, case.kind, ";".join(got[0]), ";".join(got[1]), got[2]) for case, got in result["named"]])
    groups = collections.Counter(case.kind for case, _ in result["named"])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "helpers": len(result["helpers"]), "named_scenarios": len(result["named"]), "groups": dict(sorted(groups.items())), "vector_scenarios": result["vector_count"], "instructions": sum(len(items) for items in table.values()), "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "pins": len(result["pins"]), "texts": len(result["texts"])}
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
