#!/usr/bin/env python3
"""Map node #94 CoreWriter path: RawAction log gate, 16 action arms, ABI decoders, sender gates, row push and the row loop.

The host 0x333b2a0, the log decoder 0x37a31f0, the ABI decoders 0x37e6e90..0x37ea7e0, the sender gates and the row push run as real
bytes in an interpreter inside this tool. Only the action drop, the allocator and the byte copies are stubs. A separately written rule
list predicts every result. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_core_writer.py --out <dir>
"""
import argparse
import bisect
import collections
import copy
import datetime
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
BSS_LOW = 0x5788300
BSS_HIGH = 0x59B0E80


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
                return finish("movssr", ("x", reg), rm, 4)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        if two == 0xC6 and not opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufps", ("x", reg), rm, 16, target=value)
        if two == 0x71 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (2, 4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish({2: "psrlw", 4: "psraw", 6: "psllw"}[reg & 7], rm, ("i", value), 16)
        lanes = {0x61: "punpcklwd", 0x63: "packsswb", 0x67: "packuswb", 0x68: "punpckhbw", 0x69: "punpckhwd", 0x6A: "punpckhdq", 0x6B: "packssdw", 0x6D: "punpckhqdq", 0xDA: "pminub", 0xDE: "pmaxub", 0xD4: "paddq", 0xFC: "paddb", 0xFE: "paddd", 0xF8: "psubb"}
        if two in lanes and opsize:
            reg, rm = modrm(True)
            return finish(lanes[two], ("x", reg), rm, 16)
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
        if BSS_LOW <= addr < BSS_HIGH:
            return bytes(count)
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
        elif op == "shufps":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            picks = [(left >> (32 * ((row.target >> 0) & 3))) & MASK[4], (left >> (32 * ((row.target >> 2) & 3))) & MASK[4], (right >> (32 * ((row.target >> 4) & 3))) & MASK[4], (right >> (32 * ((row.target >> 6) & 3))) & MASK[4]]
            self.xmm[row.a[1]] = picks[0] | picks[1] << 32 | picks[2] << 64 | picks[3] << 96
        elif op in ("psllw", "psrlw", "psraw"):
            value, lanes = self.xmm[row.a[1]], 0
            count = row.b[1]
            for shift in range(0, 128, 16):
                lane = (value >> shift) & 0xFFFF
                if op == "psllw":
                    lane = (lane << count) & 0xFFFF if count < 16 else 0
                elif op == "psrlw":
                    lane = lane >> count if count < 16 else 0
                else:
                    lane = ((lane - 0x10000 if lane & 0x8000 else lane) >> min(count, 15)) & 0xFFFF
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op in ("punpcklwd", "punpckhwd", "punpckhbw", "punpckhdq", "punpckhqdq"):
            size = {"punpcklwd": 2, "punpckhwd": 2, "punpckhbw": 1, "punpckhdq": 4, "punpckhqdq": 8}[op]
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            start = 0 if op == "punpcklwd" else 8
            parts = []
            for at in range(start, start + 8, size):
                parts += [left[at:at + size], right[at:at + size]]
            self.xmm[row.a[1]] = int.from_bytes(b"".join(parts), "little")
        elif op in ("packsswb", "packuswb"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            out = bytearray()
            for value in (left, right):
                for shift in range(0, 128, 16):
                    lane = (value >> shift) & 0xFFFF
                    lane = lane - 0x10000 if lane & 0x8000 else lane
                    if op == "packsswb":
                        lane = max(-128, min(127, lane)) & 0xFF
                    else:
                        lane = max(0, min(255, lane))
                    out.append(lane)
            self.xmm[row.a[1]] = int.from_bytes(out, "little")
        elif op == "packssdw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            out = bytearray()
            for value in (left, right):
                for shift in range(0, 128, 32):
                    lane = (value >> shift) & MASK[4]
                    lane = lane - (1 << 32) if lane & SIGN[4] else lane
                    out += (max(-32768, min(32767, lane)) & 0xFFFF).to_bytes(2, "little")
            self.xmm[row.a[1]] = int.from_bytes(out, "little")
        elif op in ("pminub", "pmaxub", "paddb", "psubb"):
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            act = {"pminub": min, "pmaxub": max, "paddb": lambda a, b: (a + b) & 0xFF, "psubb": lambda a, b: (a - b) & 0xFF}[op]
            self.xmm[row.a[1]] = int.from_bytes(bytes(act(a, b) for a, b in zip(left, right)), "little")
        elif op == "paddq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left + right) & MASK[8]) | ((((left >> 64) + (right >> 64)) & MASK[8]) << 64)
        elif op == "paddd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> shift) + (right >> shift)) & MASK[4]) << shift for shift in range(0, 128, 32))
        elif op == "movssr":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] >> 32 << 32) | (self.xmm[row.b[1]] & MASK[4])
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



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
INPUT = HEAP_BASE + 0x2F0000
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


HOST = 0x333B2A0
LOG_DECODE = 0x37A31F0
TOPIC_AT = 0x20C6A0
CORE_ADDRESS = b"\x33" * 20
TOPIC0 = bytes.fromhex("8c7f585fb295f7eb1e6aeb8fba61b23a4fe60beda405f0045073b185c74412e3")
MARKER_HASH = 0x399C7A0
LOG_AT = HEAP_BASE + 0x1000
CTX_AT = HEAP_BASE + 0x1100
OUT_AT = HEAP_BASE + 0x1200
DISABLED_AT = HEAP_BASE + 0x1300
HASH_AT = HEAP_BASE + 0x1320
MAP_A_AT = HEAP_BASE + 0x1400
MAP_B_AT = HEAP_BASE + 0x1420
TABLE_AT = HEAP_BASE + 0x1440
TOPICS_AT = HEAP_BASE + 0x1500
DATA_VTABLE = HEAP_BASE + 0x1580
DATA_AT = HEAP_BASE + 0x2000
ROW_SIZE = 0x128
ACTION_SIZE = 0xF0
SLOT_MEMSET = 0x576E1F8
CPU_FEATURES = 0x4F15250
METRIC_CLOCK = 0x14385C0
ACTION_DROP = 0x3379F90
ACTION_MARK = 0x3379490


def keccak(data):
    rc = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
    rot = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    m = (1 << 64) - 1
    state = [[0] * 5 for _ in range(5)]
    data = bytearray(data) + b"\x01"
    data += bytes((-len(data)) % 136)
    data[-1] |= 0x80
    for block in range(0, len(data), 136):
        for i in range(17):
            state[i % 5][i // 5] ^= int.from_bytes(data[block + 8 * i:block + 8 * i + 8], "little")
        for value in rc:
            c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            d = [c[(x + 4) % 5] ^ (((c[(x + 1) % 5] << 1) | c[(x + 1) % 5] >> 63) & m) for x in range(5)]
            state = [[state[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = rot[x][y]
                    b[y][(2 * x + 3 * y) % 5] = (((state[x][y] << r) | state[x][y] >> (64 - r)) & m) if r else state[x][y]
            state = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y] & m) for y in range(5)] for x in range(5)]
            state[0][0] ^= value
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def word(value):
    return (value % (1 << 256)).to_bytes(32, "big")


def address_word(address):
    return bytes(12) + address


def abi_bytes(data):
    return word(0x20) + word(len(data)) + data + bytes((-len(data)) % 32)


def key20(seed):
    return hashlib.sha256(b"user%d" % seed).digest()[:20]


class Core(Harness):
    def __init__(self, image, patches=None, cache=None):
        Harness.__init__(self, image, patches, cache)
        self.skip = set()
        self.machine.real = Stubbed(self.skip)
        self.machine.memory.statics = dict(self.machine.memory.statics)
        self.machine.memory.statics[SLOT_MEMSET] = MARK_BASE + SLOT_MEMSET
        self.hook(CPU_FEATURES, self.on_features)
        self.hook(METRIC_CLOCK, self.on_clock)
        self.machine.slots[MARK_BASE + SLOT_MEMSET] = self.on_set

    def on_clock(self, machine):
        self.clock_calls += 1

    def on_features(self, machine):
        machine.regs[RAX] = 0

    def on_set(self, machine):
        if machine.regs[RDX]:
            self.put(machine.regs[RDI], bytes([machine.regs[RSI] & 0xFF]) * machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def hook(self, va, action):
        self.skip.add(va)
        self.machine.calls[va] = action
        self.machine.slots[va] = action

    def node(self, size, keys, key_at, key_size, count_at):
        at = self.alloc(size)
        self.put(at, bytes(size))
        for index, key in enumerate(keys):
            self.put(at + key_at + index * key_size, key)
        self.write(at + count_at, len(keys), 2)
        return at

    def hash_of(self, key):
        self.put(HEAP_BASE + 0x1600, key)
        self.machine.run(MARKER_HASH, {RDI: TABLE_AT + 0x20, RSI: HEAP_BASE + 0x1600})
        return self.machine.regs[RAX]

    def table(self, users):
        mask = 15
        base = self.alloc(16 * 0x58 + 32 + 16)
        base = (base + 16 * 0x58 + 15) & ~15
        self.put(base, b"\xff" * 32)
        for index in range(0, 0x20, 8):
            self.write(TABLE_AT + index, 0)
        self.write(TABLE_AT, base)
        self.write(TABLE_AT + 8, mask)
        self.write(TABLE_AT + 0x18, len(users))
        self.write(TABLE_AT + 0x20, 0x1122334455667788)
        self.write(TABLE_AT + 0x28, 0x99AABBCCDDEEFF00)
        self.write(TABLE_AT + 0x30, 0x0F1E2D3C4B5A6978)
        self.write(TABLE_AT + 0x38, 0x8796A5B4C3D2E1F0)
        for user in users:
            value = self.hash_of(user)
            top = value >> 57
            at = value & mask
            while self.read(base + at, 1) != 0xFF:
                at = (at + 1) & mask
            self.write(base + at, top, 1)
            if at < 16:
                self.write(base + mask + 1 + at, top, 1)
            self.put(base - (at + 1) * 0x58, user + bytes(0x58 - 20))

    def prepare(self, world):
        self.fresh()
        self.put(HEAP_BASE, bytes(0x3000))
        log = world["log"]
        self.put(TOPICS_AT, b"".join(log["topics"]))
        self.put(DATA_AT, log["data"])
        self.write(LOG_AT + 8, TOPICS_AT)
        self.write(LOG_AT + 0x10, len(log["topics"]))
        self.write(LOG_AT + 0x20, DATA_AT)
        self.write(LOG_AT + 0x28, len(log["data"]))
        self.put(LOG_AT + 0x38, log["address"])
        self.write(CTX_AT + 0x28, MAP_B_AT)
        self.write(CTX_AT + 0x38, TABLE_AT)
        self.write(CTX_AT + 0x40, MAP_A_AT)
        self.write(CTX_AT + 0x58, world["chain"], 1)
        self.write(OUT_AT + 0x18, 0)
        self.write(OUT_AT + 0x20, 8)
        self.write(OUT_AT + 0x28, 0)
        self.put(HASH_AT, world["hash"])
        keys = [bytes([version]) + bytes(7) + action.to_bytes(8, "little") for version, action in sorted(world["disabled"])]
        if keys:
            self.write(DISABLED_AT, self.node(0x120, keys, 0, 0x10, 0xBA))
        else:
            self.write(DISABLED_AT, 0)
        self.write(DISABLED_AT + 8, 0)
        if world["banned"]:
            self.write(MAP_A_AT, self.node(0x2B0, sorted(world["banned"]), 0x168, 20, 0x246))
        if world["blocked"]:
            self.write(MAP_B_AT, self.node(0x8D0, sorted(world["blocked"]), 0x798, 20, 0x876))
        self.table(world["known"])
        self.fixture = set(self.live)
        self.clock_calls = 0

    def execute(self, world):
        self.prepare(world)
        self.machine.run(HOST, {RDI: LOG_AT, RSI: CTX_AT, RDX: OUT_AT, RCX: DISABLED_AT, R8: HASH_AT})
        count = self.read(OUT_AT + 0x28)
        rows = []
        at = self.read(OUT_AT + 0x20)
        for index in range(count):
            rows.append(self.data(at + index * ROW_SIZE, ROW_SIZE))
        return rows


class Stubbed:
    """Every code address runs for real, except hooks."""

    def __init__(self, skip):
        self.skip = skip

    def __contains__(self, va):
        return va < 0x6000000 and va not in self.skip


def good_world(action, version=1, **change):
    user = key20(1)
    data = bytes([version]) + action[0].to_bytes(3, "big") + action[1]
    world = dict(log=dict(topics=[TOPIC0, address_word(user)], data=abi_bytes(data), address=CORE_ADDRESS), chain=3, hash=hashlib.sha256(b"tx").digest(), disabled=(), banned=(), blocked=(), known=(user,))
    world.update(change)
    return world

LIMIT = 0x0CCCCCCCCCCCCCCC
U64 = (1 << 64) - 1
U128 = (1 << 128) - 1
ARMS = {
    1: ("limit order", 0x82, ("u32", "bool", "u64", "u64", "bool", "u8", "u128"), 0x37E6E90, "OrderAction"),
    2: ("vault transfer", 0x9F, ("addr", "bool", "u64"), 0x37EA360, "VaultTransferAction"),
    3: ("token delegate", 0x95, ("addr", "u64", "bool"), 0x37E7940, "TokenDelegateAction"),
    4: ("staking deposit", 0xB2, ("u64",), 0x37E8670, "CDepositAction"),
    5: ("staking withdraw", 0xB1, ("u64",), 0x37E8670, "CWithdrawAction"),
    6: ("spot send", 0xAD, ("addr", "u64", "u64"), 0x37E8AB0, "SystemSpotSendAction"),
    7: ("usd class transfer", 0xAF, ("u64", "bool"), 0x37E9260, "SystemUsdClassTransferAction"),
    8: ("finalize evm contract", 0xB7, ("u64", "u8", "u64"), 0x37E87B0, "FinalizeEvmContractAction"),
    9: ("add api wallet", 0x75, ("addr", "string"), 0x37E8D60, "ApproveAgent3Action"),
    10: ("cancel by oid", 0x77, ("u32", "u64"), 0x37E98A0, "CancelAction"),
    11: ("cancel by cloid", 0x78, ("u32", "u128"), 0x37EA130, "CancelByCloidAction"),
    12: ("approve builder fee", 0xBA, ("u64", "addr"), 0x37EA7E0, "SystemApproveBuilderFeeAction"),
    13: ("send asset", 0xBB, ("addr", "addr", "u32", "u32", "u64", "u64"), 0x37E7E00, "SystemSendAssetAction"),
    14: ("not in the upstream table", 0xBC, ("u64", "u64", "bool"), 0x37E9D90, "SystemAlignedQuoteSupplyDeltaAction"),
    15: ("borrow lend", 0xAC, ("u8", "u64", "u64"), 0x37E95A0, "SystemBoleAction"),
    16: ("set abstraction", 0xC2, ("addr", "u8"), 0x37E9AF0, "dispatch variant 78"),
}
SAMPLE_VALUES = {
    1: (0x11223344, 1, 0x0112233445566778, 0x0102030405060708, 1, 2, 0x0A0B0C0D0E0F10111213141516171819),
    2: (key20(7), 1, 0x7172737475767778),
    3: (key20(7), 0x7172737475767778, 1),
    4: (0x7172737475767778,),
    5: (0x7172737475767779,),
    6: (key20(7), 0x4142434445464748, 0x7172737475767778),
    7: (0x7172737475767778, 1),
    8: (0x7172737475767778, 1, 0x4142434445464748),
    9: (key20(7), b"bot"),
    10: (0x11223344, 0x0172737475767778),
    11: (0x11223344, 0x0A0B0C0D0E0F10111213141516171819),
    12: (0x7172737475767778, key20(7)),
    13: (key20(7), key20(8), 5, 6, 0x4142434445464748, 0x7172737475767778),
    14: (0x7172737475767778, 0x4142434445464748, 1),
    15: (1, 0x7172737475767778, 0x4142434445464748),
    16: (key20(7), 3),
}


def encode_values(kinds, values):
    head, tail = [], []
    for kind, value in zip(kinds, values):
        if kind == "addr":
            head.append(address_word(value))
        elif kind == "string":
            head.append(None)
            tail.append(word(len(value)) + value + bytes((-len(value)) % 32))
        else:
            head.append(word(int(value)))
    offset = 32 * len(head)
    return b"".join(word(offset) if item is None else item for item in head) + b"".join(tail)


def tag_row(row, offset, value, size=8):
    return (offset, size, value.to_bytes(size, "little") if isinstance(value, int) else value)


def arm_fields(action, values, chain):
    """Named row fields and heap boxes one accepted action must hold, or None for a refused payload."""
    v = values
    if action == 1:
        if v[5] not in (1, 2, 3) or v[2] >= LIMIT or v[3] >= LIMIT:
            return None
        box = ((0, 1, {1: 0, 2: 2, 3: 1}[v[5]]), (9, 1, 2), (0x10, 8, v[2]), (0x18, 8, v[3]), (0x20, 4, v[0]), (0x24, 1, int(v[6] != 0)), (0x25, 16, v[6].to_bytes(16, "big")), (0x35, 1, int(v[1])), (0x36, 1, int(v[4])))
        return dict(fields=((0x30, 8, 1), (0x40, 8, 1)), box=(0x38, 0x38, box))
    if action == 2:
        return dict(fields=((8, 8, v[2]), (0x10, 20, v[0]), (0x24, 1, int(v[1]))))
    if action == 3:
        return dict(fields=((0x28, 8, v[1]), (0x38, 20, v[0]), (0x4C, 1, chain), (0x4D, 1, int(v[2]))))
    if action in (4, 5):
        return dict(fields=((0x28, 8, v[0]), (0x38, 1, chain)))
    if action == 6:
        return dict(fields=((8, 8, v[1]), (0x10, 8, v[2]), (0x18, 20, v[0])))
    if action == 7:
        return dict(fields=((8, 8, v[0]), (0x10, 1, int(v[1])), (0x18, 1, chain)))
    if action == 8:
        if v[1] not in (1, 2, 3):
            return None
        fields = ((8, 8, v[1] - 1), (0x18, 8, v[0]))
        return dict(fields=fields + (((0x10, 8, v[2]),) if v[1] == 1 else ()))
    if action == 9:
        if len(v[1]) >= 256:
            return None
        try:
            v[1].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not v[1]:
            return dict(fields=((8, 8, 1 << 63), (0x48, 20, v[0]), (0x5C, 1, chain)))
        return dict(fields=((8, 8, len(v[1])), (0x18, 8, len(v[1])), (0x48, 20, v[0]), (0x5C, 1, chain)), name=(0x10, v[1]))
    if action == 10:
        if v[1] >= LIMIT:
            return None
        return dict(fields=((8, 8, 1), (0x18, 8, 1)), box=(0x10, 0x10, ((0, 8, v[1]), (8, 4, v[0]))))
    if action == 11:
        return dict(fields=((8, 8, 1), (0x18, 8, 1)), box=(0x10, 0x14, ((0, 16, v[1].to_bytes(16, "big")), (0x10, 4, v[0]))))
    if action == 12:
        return dict(fields=((8, 8, v[0]), (0x10, 20, v[1])))
    if action == 13:
        fields = ((8, 8, int(v[2] != 0xFFFFFFFF)), (0x18, 8, int(v[3] != 0xFFFFFFFF)), (0x28, 8, v[4]), (0x30, 8, v[5]), (0x38, 20, v[0]), (0x4C, 1, int(v[1] != bytes(20))))
        if v[2] != 0xFFFFFFFF:
            fields += ((0x10, 4, v[2]),)
        if v[3] != 0xFFFFFFFF:
            fields += ((0x20, 4, v[3]),)
        if v[1] != bytes(20):
            fields += ((0x4D, 20, v[1]),)
        return dict(fields=fields)
    if action == 14:
        return dict(fields=((8, 8, v[0]), (0x10, 8, v[1]), (0x18, 1, int(v[2]))))
    if action == 15:
        if v[0] > 3:
            return None
        fields = ((8, 8, int(v[2] != 0)), (0x18, 8, v[1]), (0x20, 1, {0: 1, 1: 3, 2: 0, 3: 2}[v[0]]))
        return dict(fields=fields + (((0x10, 8, v[2]),) if v[2] else ()))
    if action == 16:
        if v[1] not in (1, 2, 3):
            return None
        return dict(fields=((0x30, 20, v[0]), (0x44, 1, {1: 1, 2: 3, 3: 4}[v[1]]), (0x45, 1, chain)))
    raise EvidenceError("arm")


def spec_row(world):
    log = world["log"]
    if log["address"] != CORE_ADDRESS or len(log["topics"]) < 2 or log["topics"][0] != TOPIC0:
        return None
    if log["data"] != abi_bytes(world["raw"]):
        return None
    raw = world["raw"]
    if len(raw) > 1000 or len(raw) < 4:
        return None
    version, action = raw[0], int.from_bytes(raw[1:4], "big")
    if (version, action) in world["disabled"] or version != 1 or not 1 <= action <= 16:
        return None
    parsed = strict_payload(action, raw[4:])
    if parsed is None:
        return None
    fields = arm_fields(action, parsed, world["chain"])
    user = log["topics"][1][12:]
    if fields is None or user in world["banned"] or user not in world["known"] or user in world["blocked"]:
        return None
    return dict(action=action, tag=ARMS[action][1], user=user, hash=world["hash"], **fields)


def strict_payload(action, payload):
    """Values if the payload is exactly the strict encoding of the arm's type tuple, else None."""
    kinds = ARMS[action][2]
    if len(payload) < 32 * len(kinds) or ("string" not in kinds and len(payload) != 32 * len(kinds)):
        return None
    values = []
    for index, kind in enumerate(kinds):
        raw = payload[32 * index:32 * index + 32]
        if kind == "addr":
            if raw[:12] != bytes(12):
                return None
            values.append(raw[12:])
        elif kind == "string":
            if raw != word(32 * len(kinds)):
                return None
            start = 32 * len(kinds)
            if len(payload) < start + 32:
                return None
            size = int.from_bytes(payload[start:start + 32], "big")
            if len(payload) != start + 32 + size + ((-size) % 32):
                return None
            data = payload[start + 32:start + 32 + size]
            if payload[start + 32 + size:start + 32 + size + ((-size) % 32)] != bytes((-size) % 32):
                return None
            values.append(data)
        else:
            number = int.from_bytes(raw, "big")
            if kind == "bool" and raw[:31] == bytes(31):
                values.append(int(raw[31] != 0))
                continue
            if number >= 1 << {"u8": 8, "u32": 32, "u64": 64, "u128": 128, "bool": 1}[kind]:
                return None
            values.append(number)
    return values


class Case:
    def __init__(self, name, kind, world):
        self.name, self.kind, self.world = name, kind, world


def world_of(raw, **change):
    user = key20(1)
    world = dict(log=dict(topics=[TOPIC0, address_word(user)], data=abi_bytes(raw), address=CORE_ADDRESS), raw=raw, chain=3, hash=hashlib.sha256(b"tx").digest(), disabled=(), banned=(), blocked=(), known=(user,))
    world.update(change)
    return world


def raw_of(action, values, version=1):
    return bytes([version]) + action.to_bytes(3, "big") + encode_values(ARMS[action][2], values)


def read_row(harness, row, spec_fields):
    got = []
    for offset, size, value in spec_fields:
        got.append((offset, size, row[offset:offset + size].hex()))
    return got


def want_of(world):
    if "system" in world:
        return ("loop",) + spec_loop(world)
    head = spec_writer(world) if "ops" in world else ()
    return head + row_want(world)


def row_want(world):
    spec = spec_row(world)
    if spec is None:
        return ("drop", 1)
    rows = [(0, 8, spec["tag"].to_bytes(8, "little").hex()), (0xF0, 20, spec["user"].hex()), (0x104, 32, spec["hash"].hex())]
    for offset, size, value in spec.get("fields", ()):
        rows.append((offset, size, (value.to_bytes(size, "little") if isinstance(value, int) else value).hex()))
    box = []
    if "box" in spec:
        for offset, size, value in spec["box"][2]:
            box.append((offset, size, (value.to_bytes(size, "little") if isinstance(value, int) else value).hex()))
    name = spec["name"][1].hex() if "name" in spec else None
    return ("row", spec["action"], tuple(rows), tuple(box), name)


def run_case(harness, case):
    if "system" in case.world:
        return ("loop",) + harness.run_loop(case.world)
    head = ()
    if "ops" in case.world:
        statuses, keys, rows = run_writer(harness, case.world)
        head = (statuses, keys)
    else:
        rows = harness.execute(case.world)
    want = row_want(case.world)
    harness.expect(len(rows) == (1 if want[0] == "row" else 0), "row count")
    live = sorted(size for at, size in harness.live.items() if at not in harness.fixture)
    if want[0] == "drop":
        harness.expect(not live, "no live block after a drop")
        return head + ("drop", 1)
    row = rows[0]
    spec = spec_row(case.world)
    fields = tuple((offset, size, row[offset:offset + size].hex()) for offset, size, _ in want[2])
    box = ()
    if want[3]:
        at = int.from_bytes(row[spec["box"][0]:spec["box"][0] + 8], "little")
        harness.expect(harness.live.get(at) == spec["box"][1], "box block size")
        data = harness.data(at, spec["box"][1])
        box = tuple((offset, size, data[offset:offset + size].hex()) for offset, size, _ in want[3])
    name = None
    if want[4] is not None:
        at = int.from_bytes(row[spec["name"][0]:spec["name"][0] + 8], "little")
        name = harness.data(at, len(spec["name"][1])).hex()
    expected_live = 1 + bool(want[3]) + (want[4] is not None)
    harness.expect(len(live) == expected_live, "live blocks %d" % len(live))
    return head + ("row", spec["action"], fields, box, name)


def spec_run(case):
    return want_of(case.world)

def replace(values, index, value):
    items = list(values)
    items[index] = value
    return items


def named_cases():
    cases = []

    def add(name, kind, raw, **change):
        cases.append(Case(name, kind, world_of(raw, **change)))

    # every arm: good, each word dirtied, truncated, extended
    for action, (label, tag, kinds, decoder, variant) in ARMS.items():
        values = SAMPLE_VALUES[action]
        good = raw_of(action, values)
        add("arm_%d_good" % action, "arm", good)
        add("arm_%d_chain_0" % action, "arm", good, chain=0)
        add("arm_%d_chain_9" % action, "arm", good, chain=9)
        for index in range(len(kinds)):
            at = 4 + 32 * index
            for byte in (0, 11, 23, 24, 31):
                dirty = bytearray(good)
                dirty[at + byte] ^= 0x40
                add("arm_%d_word_%d_byte_%d" % (action, index, byte), "dirty", bytes(dirty))
        for cut in (1, 31, 32, 33):
            add("arm_%d_cut_%d" % (action, cut), "length", good[:-cut])
        for extra in (1, 32, 64):
            add("arm_%d_extra_%d" % (action, extra), "length", good + bytes(extra))
        add("arm_%d_extra_dirty" % action, "length", good + b"\x01" * 32)
        add("arm_%d_only_header" % action, "length", good[:4])
        add("arm_%d_zero_words" % action, "arm", good[:4] + bytes(len(good) - 4))
        for index, kind in enumerate(kinds):
            if kind == "bool":
                add("arm_%d_bool_%d_zero" % (action, index), "bool", raw_of(action, replace(values, index, 0)))
                dirty = bytearray(good)
                dirty[4 + 32 * index + 31] = 2
                add("arm_%d_bool_%d_two" % (action, index), "bool", bytes(dirty))
                dirty[4 + 32 * index + 31] = 0xFF
                add("arm_%d_bool_%d_ff" % (action, index), "bool", bytes(dirty))
            if kind == "addr":
                add("arm_%d_addr_%d_zero" % (action, index), "bound", raw_of(action, replace(values, index, bytes(20))))
                add("arm_%d_addr_%d_ff" % (action, index), "bound", raw_of(action, replace(values, index, b"\xff" * 20)))
            if kind in ("u8", "u32", "u64", "u128") and action not in (1, 8, 10, 15, 16):
                add("arm_%d_num_%d_zero" % (action, index), "bound", raw_of(action, replace(values, index, 0)))
                top = {"u8": 0xFF, "u32": 0xFFFFFFFF, "u64": U64, "u128": U128}[kind]
                add("arm_%d_num_%d_max" % (action, index), "bound", raw_of(action, replace(values, index, top)))
                add("arm_%d_num_%d_over" % (action, index), "dirty", bytes(raw_of(action, replace(values, index, 0))[:4 + 32 * index]) + word(top + 1) + raw_of(action, values)[4 + 32 * index + 32:])
    v = SAMPLE_VALUES[1]
    for tif in range(0, 6):
        add("order_tif_%d" % tif, "order", raw_of(1, replace(v, 5, tif)))
    add("order_tif_255", "order", raw_of(1, replace(v, 5, 255)))
    add("order_tif_over", "order", raw_of(1, replace(v, 5, 256)))
    for index, label in ((2, "px"), (3, "sz")):
        for value in (0, 1, LIMIT - 1, LIMIT, LIMIT + 1, (1 << 63) - 2, (1 << 63) - 1, 1 << 63, U64 - 1, U64):
            add("order_%s_%#x" % (label, value), "order", raw_of(1, replace(v, index, value)))
    for flags in ((0, 0), (0, 1), (1, 0), (1, 1)):
        add("order_buy_%d_reduce_%d" % flags, "order", raw_of(1, replace(replace(v, 1, flags[0]), 4, flags[1])))
    for value in (0, 1, U128, 1 << 64, 1 << 127):
        add("order_cloid_%#x" % value, "order", raw_of(1, replace(v, 6, value)))
    for value in (0, 0xFFFFFFFF):
        add("order_asset_%#x" % value, "order", raw_of(1, replace(v, 0, value)))
    v = SAMPLE_VALUES[8]
    for value in range(0, 5):
        add("finalize_variant_%d" % value, "enum", raw_of(8, replace(v, 1, value)))
    add("finalize_variant_255", "enum", raw_of(8, replace(v, 1, 255)))
    add("finalize_nonce_zero", "enum", raw_of(8, replace(v, 2, 0)))
    add("finalize_nonce_zero_v2", "enum", raw_of(8, replace(replace(v, 1, 2), 2, 0)))
    v = SAMPLE_VALUES[10]
    for value in (0, 1, LIMIT - 1, LIMIT, U64):
        add("cancel_oid_%#x" % value, "enum", raw_of(10, replace(v, 1, value)))
    add("cancel_asset_max", "enum", raw_of(10, replace(v, 0, 0xFFFFFFFF)))
    v = SAMPLE_VALUES[13]
    for src, dst in ((0xFFFFFFFF, 6), (5, 0xFFFFFFFF), (0xFFFFFFFF, 0xFFFFFFFF), (0, 0), (0xFFFFFFFE, 0xFFFFFFFE)):
        add("send_dex_%#x_%#x" % (src, dst), "enum", raw_of(13, replace(replace(v, 2, src), 3, dst)))
    add("send_no_sub", "enum", raw_of(13, replace(v, 1, bytes(20))))
    v = SAMPLE_VALUES[15]
    for value in range(0, 6):
        add("bole_op_%d" % value, "enum", raw_of(15, replace(v, 0, value)))
        add("bole_op_%d_all" % value, "enum", raw_of(15, replace(replace(v, 0, value), 2, 0)))
    add("bole_op_255", "enum", raw_of(15, replace(v, 0, 255)))
    add("bole_token_zero", "enum", raw_of(15, replace(v, 1, 0)))
    v = SAMPLE_VALUES[16]
    for value in range(0, 6):
        add("abstraction_%d" % value, "enum", raw_of(16, replace(v, 1, value)))
    add("abstraction_255", "enum", raw_of(16, replace(v, 1, 255)))
    add("abstraction_zero_user", "enum", raw_of(16, replace(v, 0, bytes(20))))
    # add api wallet head check and names
    v = SAMPLE_VALUES[9]
    for name in (b"", b"a", b"x" * 31, b"x" * 32, b"x" * 33, b"x" * 64, b"x" * 200, b"x" * 255, b"x" * 256, b"x" * 300, b"\xff", b"\xc3\xa9", b"ab\x00"):
        add("wallet_name_%d_%s" % (len(name), name[:2].hex()), "wallet", raw_of(9, replace(v, 1, name)))
    good = raw_of(9, v)
    for at, label in ((4 + 11, "addr_top"), (4 + 12, "addr_low"), (4 + 32, "offset_top"), (4 + 62, "offset_30"), (4 + 64, "len_top"), (4 + 64 + 30, "len_30")):
        dirty = bytearray(good)
        dirty[at] ^= 1
        add("wallet_head_%s" % label, "wallet", bytes(dirty))
    dirty = bytearray(good)
    dirty[4 + 63] = 0x20
    add("wallet_offset_0x20", "wallet", bytes(dirty))
    dirty = bytearray(good)
    dirty[4 + 63] = 0x60
    add("wallet_offset_0x60", "wallet", bytes(dirty) + bytes(32))
    dirty = bytearray(good)
    dirty[4 + 96 + 3] = 0x41
    add("wallet_dirty_padding_%d" % 0, "wallet", bytes(dirty))
    add("wallet_short_0x5f", "wallet", good[:4 + 0x5F])
    add("wallet_exact_head", "wallet", good[:4 + 0x60])
    # header
    good = raw_of(4, (1000,))
    for size in (0, 1, 2, 3, 4):
        add("raw_len_%d" % size, "header", good[:size])
    add("raw_len_1000", "header", raw_of(9, (key20(7), b"x" * 200)) + bytes(1000 - len(raw_of(9, (key20(7), b"x" * 200)))))
    for size in (999, 1000, 1001, 1002, 4096):
        add("raw_pad_%d" % size, "header", (good + bytes(size))[:size])
    for version in (0, 2, 3, 0x7F, 0xFF):
        add("version_%d" % version, "header", bytes([version]) + good[1:])
    for action in (0, 17, 18, 0xFF, 0x100, 0x104, 0x10004, 0xFFFFFF):
        add("action_%#x" % action, "header", bytes([1]) + action.to_bytes(3, "big") + good[4:])
    # log gates
    base = world_of(good)
    user = key20(1)
    other = key20(2)

    def log_case(name, **log):
        world = world_of(good)
        world["log"] = dict(world["log"], **log)
        cases.append(Case(name, "log", world))

    log_case("log_address_last_byte", address=CORE_ADDRESS[:-1] + b"\x34")
    log_case("log_address_first_byte", address=b"\x34" + CORE_ADDRESS[1:])
    log_case("log_address_byte_15", address=CORE_ADDRESS[:15] + b"\x34" + CORE_ADDRESS[16:])
    log_case("log_address_byte_16", address=CORE_ADDRESS[:16] + b"\x34" + CORE_ADDRESS[17:])
    log_case("log_address_zero", address=bytes(20))
    log_case("log_no_topics", topics=[])
    log_case("log_one_topic", topics=[TOPIC0])
    log_case("log_three_topics", topics=[TOPIC0, address_word(user), bytes(32)])
    log_case("log_topic_byte_0", topics=[b"\x8d" + TOPIC0[1:], address_word(user)])
    log_case("log_topic_byte_16", topics=[TOPIC0[:16] + b"\x00" + TOPIC0[17:], address_word(user)])
    log_case("log_topic_byte_31", topics=[TOPIC0[:31] + b"\x00", address_word(user)])
    log_case("log_user_top_byte", topics=[TOPIC0, b"\x01" + address_word(user)[1:]])
    log_case("log_user_byte_11", topics=[TOPIC0, address_word(user)[:11] + b"\x01" + user])
    log_case("log_empty_data", data=b"")
    log_case("log_offset_0x40", data=word(0x40) + abi_bytes(good)[32:])
    log_case("log_offset_0", data=word(0) + abi_bytes(good)[32:])
    log_case("log_len_big", data=word(0x20) + word(len(good) + 1) + abi_bytes(good)[64:])
    log_case("log_len_small", data=word(0x20) + word(len(good) - 1) + abi_bytes(good)[64:])
    log_case("log_len_huge", data=word(0x20) + word(1 << 200) + abi_bytes(good)[64:])
    log_case("log_cut_tail", data=abi_bytes(good)[:-1])
    log_case("log_cut_head", data=abi_bytes(good)[:31])
    log_case("log_extra_word", data=abi_bytes(good) + bytes(32))
    log_case("log_extra_byte", data=abi_bytes(good) + bytes(1))
    log_case("log_dirty_padding", data=abi_bytes(good[:-1])[:-1] + b"\x01")
    # disabled pairs, sender sets
    add("disabled_hit", "gate", good, disabled=((1, 4),))
    add("disabled_other_id", "gate", good, disabled=((1, 5),))
    add("disabled_other_version", "gate", good, disabled=((2, 4),))
    add("disabled_two_rows_hit", "gate", good, disabled=((1, 3), (1, 4)))
    add("disabled_two_rows_miss", "gate", good, disabled=((1, 3), (1, 5)))
    add("disabled_many_hit_last", "gate", good, disabled=((0, 9), (1, 1), (1, 2), (1, 3), (1, 4)))
    add("disabled_version_0_row", "gate", bytes([0]) + good[1:], disabled=((0, 4),))
    add("disabled_action_99_row", "gate", bytes([1, 0, 0, 99]) + good[4:], disabled=((1, 99),))
    add("banned_sender", "gate", good, banned=(user,))
    add("banned_other", "gate", good, banned=(other,))
    add("banned_two", "gate", good, banned=tuple(sorted((other, user))))
    add("blocked_sender", "gate", good, blocked=(user,))
    add("blocked_other", "gate", good, blocked=(other,))
    add("blocked_two", "gate", good, blocked=tuple(sorted((other, user))))
    add("unknown_sender", "gate", good, known=(other,))
    add("unknown_empty", "gate", good, known=())
    add("known_two", "gate", good, known=(other, user))
    add("banned_and_unknown", "gate", good, banned=(user,), known=())
    add("banned_and_blocked", "gate", good, banned=(user,), blocked=(user,))
    add("unknown_and_blocked", "gate", good, known=(), blocked=(user,))
    return cases


def vector_cases(count):
    rng = random.Random(0x333B2A0)
    cases = []
    picks = sorted(ARMS)
    for index in range(count):
        action = rng.choice(picks)
        values = list(SAMPLE_VALUES[action])
        for at, kind in enumerate(ARMS[action][2]):
            mode = rng.random()
            if kind == "addr":
                values[at] = rng.randbytes(20) if mode < 0.8 else bytes(20)
            elif kind == "string":
                values[at] = rng.randbytes(rng.randrange(0, 12)) if mode < 0.3 else b"n" * rng.randrange(0, 40)
            elif kind == "bool":
                values[at] = rng.randrange(2)
            else:
                bits = {"u8": 3, "u32": 32, "u64": 64, "u128": 128}[kind]
                values[at] = rng.getrandbits(rng.randrange(1, bits + 1)) if kind != "u8" else rng.randrange(6)
        raw = raw_of(action, values)
        if rng.random() < 0.2:
            at = rng.randrange(len(raw))
            raw = raw[:at] + bytes([raw[at] ^ (1 << rng.randrange(8))]) + raw[at + 1:]
        change = {}
        user = key20(1)
        if rng.random() < 0.2:
            change["disabled"] = ((1, rng.randrange(1, 18)),)
        if rng.random() < 0.1:
            change["banned"] = (user,)
        if rng.random() < 0.1:
            change["known"] = ()
        if rng.random() < 0.1:
            change["blocked"] = (user,)
        change["chain"] = rng.randrange(8)
        cases.append(Case("vector_%d" % index, "vector", world_of(raw, **change)))
    return cases


def all_cases():
    return named_cases() + writer_cases() + loop_cases()

APPLY = {0: 0x2355F40, 1: 0x4CAA870, 2: 0x4CB3200}
SET_FIELD = {0: 0x3150, 1: 0x3150, 2: 0x3BD0}
WRITER_TAG = 0x5B
ACTION_AT = HEAP_BASE + 0x1700
STATUS_AT = HEAP_BASE + 0x1800
EXCHANGE_SIZE = 0x3C00


def walk_set(harness, root, height):
    keys = []

    def visit(node, level):
        count = harness.read(node + 0xBA, 2)
        for index in range(count + 1):
            if level:
                visit(harness.read(node + 0xC0 + 8 * index), level - 1)
            if index < count:
                keys.append((harness.read(node + index * 0x10, 1), harness.read(node + index * 0x10 + 8)))
    if root:
        visit(root, height)
    return keys


def run_writer(harness, world):
    harness.prepare(world)
    exchange = harness.alloc(EXCHANGE_SIZE)
    harness.put(exchange, bytes(EXCHANGE_SIZE))
    field = exchange + SET_FIELD[world["copy"]]
    statuses = []
    for action_id, version, enabled in world["ops"]:
        harness.put(ACTION_AT, bytes(0x100))
        harness.write(ACTION_AT, WRITER_TAG)
        harness.write(ACTION_AT + 8, action_id)
        harness.write(ACTION_AT + 0x10, version, 1)
        harness.write(ACTION_AT + 0x11, enabled, 1)
        harness.machine.run(APPLY[world["copy"]], {RDI: STATUS_AT, RSI: ACTION_AT, RDX: exchange})
        status = harness.read(STATUS_AT, 2)
        statuses.append((status, harness.read(STATUS_AT + 8) if status == 0x13F else 0))
    keys = tuple(walk_set(harness, harness.read(field), harness.read(field + 8)))
    count = harness.read(field + 0x10)
    harness.expect(count == len(keys), "set length word")
    harness.fixture = set(harness.live)
    harness.machine.run(HOST, {RDI: LOG_AT, RSI: CTX_AT, RDX: OUT_AT, RCX: field, R8: HASH_AT})
    rows = [harness.data(harness.read(OUT_AT + 0x20) + index * ROW_SIZE, ROW_SIZE) for index in range(harness.read(OUT_AT + 0x28))]
    return tuple(statuses), keys, rows


def spec_writer(world):
    keys = set()
    statuses = []
    for action_id, version, enabled in world["ops"]:
        if action_id >= LIMIT:
            statuses.append((0x13F, action_id))
            continue
        statuses.append((0x186, 0))
        if enabled:
            keys.discard((version, action_id))
        else:
            keys.add((version, action_id))
    return tuple(statuses), tuple(sorted(keys))


def writer_case(name, copy, ops, raw):
    world = world_of(raw, ops=tuple(ops), copy=copy)
    world["disabled"] = spec_writer(world)[1]
    return Case(name, "writer", world)


def writer_cases():
    cases = []
    raw = raw_of(4, (1000,))
    for copy in sorted(APPLY):
        p = "writer_%d_" % copy
        cases.append(writer_case(p + "disable_hits", copy, [(4, 1, 0)], raw))
        cases.append(writer_case(p + "disable_other_id", copy, [(5, 1, 0)], raw))
        cases.append(writer_case(p + "disable_other_version", copy, [(4, 2, 0)], raw))
        cases.append(writer_case(p + "enable_absent", copy, [(4, 1, 1)], raw))
        cases.append(writer_case(p + "disable_then_enable", copy, [(4, 1, 0), (4, 1, 1)], raw))
        cases.append(writer_case(p + "enable_then_disable", copy, [(4, 1, 1), (4, 1, 0)], raw))
        cases.append(writer_case(p + "disable_twice", copy, [(4, 1, 0), (4, 1, 0)], raw))
        cases.append(writer_case(p + "disable_twice_enable_once", copy, [(4, 1, 0), (4, 1, 0), (4, 1, 1)], raw))
        cases.append(writer_case(p + "id_limit_minus_one", copy, [(LIMIT - 1, 1, 0)], raw))
        cases.append(writer_case(p + "id_limit", copy, [(LIMIT, 1, 0)], raw))
        cases.append(writer_case(p + "id_max_enable", copy, [(U64, 1, 1)], raw))
        cases.append(writer_case(p + "version_zero_row", copy, [(4, 0, 0)], bytes([0]) + raw[1:]))
        cases.append(writer_case(p + "unknown_action_row", copy, [(99, 1, 0)], bytes([1, 0, 0, 99]) + raw[4:]))
        cases.append(writer_case(p + "enabled_byte_two", copy, [(4, 1, 0), (4, 1, 2)], raw))
        cases.append(writer_case(p + "many_rows", copy, [(index, 1 + index % 3, 0) for index in range(1, 40)], raw))
        cases.append(writer_case(p + "many_rows_removed", copy, [(index, 1, 0) for index in range(1, 30)] + [(index, 1, 1) for index in range(1, 30, 2)], raw))
    return cases

LOOP = 0x2760A70
ONCE = 0x4EE3B20
BLOCK = 0x2448500
LOOP_HOOKS = dict(metric=0x358DCD0, price=0x2760040, finish=0x2517D60, classify=0x335EC90, dispatch=0x2759240, result=0x2780900, encode=0x334CC40, context=0x3987CB0, delay=0x27584A0)
RESULT_AT = HEAP_BASE + 0x1900
CONTEXT_FIELDS = ((0, 0), (8, 0x3368), (0x10, 0x5B8), (0x18, 0x80), (0x20, 0x3380), (0x28, 0x8D0), (0x30, 0x8F8), (0x38, 0x740), (0x40, 0x39E8), (0x48, 0x3A30), (0x50, 0x498))
SYSTEM_ROW = 0x48
OUTPUT_ROW = 0x130


def sender_of(world, token):
    if world["native"] is not None and world["native"] == token:
        return b"\x22" * 20
    return b"\x20" + bytes(11) + token.to_bytes(8, "big")


def spec_loop(world):
    index, flag, calls = world["tx"], world["has_tx"], []
    n_system = 0
    for token, wei, dest in world["system"]:
        calls.append(("dispatch", 0xAD, token, wei, dest.hex(), sender_of(world, token).hex()))
        index = min(index + 1, U64) if flag else 1
        flag = 1
        n_system += 1
    n_core = 0
    for tag, user, tx_hash in world["core"]:
        if tag == 0xCC:
            break
        if flag:
            calls.append(("context", world["chain"], world["height"], index))
        calls.append(("delay", tag, user.hex(), tx_hash.hex()))
        index = min(index + 1, U64) if flag else 1
        flag = 1
        n_core += 1
    return tuple(calls), min(world["nonce"] + n_system, U64), flag, index, n_system + n_core


class Loop(Core):
    def __init__(self, image, patches=None, cache=None):
        Core.__init__(self, image, patches, cache)
        self.hook(BLOCK, self.on_block)
        self.hook(ONCE, self.on_metric)
        for name, va in LOOP_HOOKS.items():
            self.hook(va, getattr(self, "on_" + name))
        self.calls = []
        self.world = None
        self.exchange = 0

    def on_metric(self, machine):
        pass

    def on_finish(self, machine):
        raise Halt("finish call in the row loop fixture")

    def on_price(self, machine):
        self.write(machine.regs[RDI], 2)

    def on_classify(self, machine):
        machine.regs[RAX] = 5

    def on_result(self, machine):
        pass

    def on_encode(self, machine):
        pass

    def on_context(self, machine):
        self.write(machine.regs[RDI], 0)
        self.calls.append(("context", machine.regs[RSI] & 0xFF, machine.regs[RDX], machine.regs[RCX]))
        self.expect(machine.regs[R8] & 0xFF == 0, "context flag")

    def on_block(self, machine):
        out, state, context, base = machine.regs[RDI], machine.regs[RSI], machine.regs[RCX], self.exchange
        self.expect(state == base + 0xBC0, "block state pointer")
        self.expect(machine.regs[R8] == base + 0x8F3, "block fifth argument")
        for at, offset in CONTEXT_FIELDS:
            self.expect(self.read(context + at) == base + offset, "context word %#x" % at)
        self.expect(self.read(context + 0x58, 1) == self.world["chain"], "context chain byte")
        system = self.world["system"]
        block = self.alloc(max(len(system), 1) * SYSTEM_ROW)
        for index, (token, wei, dest) in enumerate(system):
            at = block + index * SYSTEM_ROW
            self.put(at, bytes(SYSTEM_ROW))
            self.write(at + 0x20, token)
            self.write(at + 0x28, wei)
            self.put(at + 0x30, dest)
        core = self.world["core"]
        rows = self.alloc(max(len(core), 1) * ROW_SIZE)
        for index, (tag, user, tx_hash) in enumerate(core):
            at = rows + index * ROW_SIZE
            self.put(at, bytes(ROW_SIZE))
            self.write(at, tag)
            self.put(at + 0xF0, user)
            self.put(at + 0x104, tx_hash)
        self.write(out, max(len(system), 1))
        self.write(out + 8, block)
        self.write(out + 0x10, len(system))
        self.write(out + 0x18, max(len(core), 1))
        self.write(out + 0x20, rows)
        self.write(out + 0x28, len(core))
        self.write(out + 0x30, 0)
        self.write(out + 0x38, 0)
        self.write(out + 0x40, 0)

    def on_dispatch(self, machine):
        action, signer, base = machine.regs[R8], machine.regs[R9], self.exchange
        self.expect(machine.regs[RSI] == base, "dispatch state")
        self.expect(machine.regs[RDX] & 0xFFFFFFFF == 0, "dispatch third word")
        self.expect(machine.regs[RCX] & 0xFF == 5, "dispatch class from the classifier")
        self.expect(self.read(base + 0x78, 1) == 1, "system flag during dispatch")
        self.calls.append(("dispatch", self.read(action), self.read(action + 8), self.read(action + 0x10), self.data(action + 0x18, 20).hex(), self.data(signer, 20).hex()))
        self.write(machine.regs[RDI], 0xD, 1)

    def on_delay(self, machine):
        out, state, user, action = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(state == self.exchange, "delay state")
        self.expect(machine.regs[R8] == 0 and machine.regs[R9] == 0, "delay flags")
        extra = self.read(machine.regs[RSP] + 0x10)
        self.expect(self.read(extra, 1) == 0, "delay hash tag")
        self.calls.append(("delay", self.read(action), self.data(user, 20).hex(), self.data(extra + 1, 32).hex()))
        self.write(out, 0xD, 1)

    def run_loop(self, world):
        self.fresh()
        self.put(HEAP_BASE, bytes(0x3000))
        self.world = world
        self.calls = []
        base = self.exchange = self.alloc(EXCHANGE_SIZE)
        self.put(base, bytes(EXCHANGE_SIZE))
        self.write(base + 0x8F2, world["chain"], 1)
        self.write(base, world["has_tx"])
        self.write(base + 8, world["tx"])
        self.write(base + 0x28, world["height"])
        self.write(base + 0x50, world["nonce"])
        if world["native"] is not None:
            self.write(base + 0x80, 1)
            self.write(base + 0x88, world["native"])
        self.machine.run(LOOP, {RDI: RESULT_AT, RSI: base})
        self.expect(self.read(base + 0x78, 1) == 0, "system flag after the loop")
        return tuple(self.calls), self.read(base + 0x50), self.read(base), self.read(base + 8), self.read(RESULT_AT + 0x10)


def loop_world(**change):
    world = dict(chain=3, has_tx=1, tx=5, height=77, nonce=9, native=None, system=(), core=())
    world.update(change)
    return world


def loop_cases():
    token = 0x4142434445464748
    system = (token, 1000, key20(21))
    core = (0xB2, key20(22), hashlib.sha256(b"a").digest())
    core2 = (0x95, key20(23), hashlib.sha256(b"b").digest())
    stop = (0xCC, key20(24), hashlib.sha256(b"c").digest())
    rows = dict(
        empty=dict(),
        one_core=dict(core=(core,)),
        two_core=dict(core=(core, core2)),
        one_system=dict(system=(system,)),
        system_then_core=dict(system=(system,), core=(core, core2)),
        no_tx_core=dict(has_tx=0, tx=0, core=(core,)),
        no_tx_two_core=dict(has_tx=0, tx=0, core=(core, core2)),
        no_tx_system=dict(has_tx=0, tx=0, system=(system,), core=(core,)),
        tx_saturates=dict(tx=U64 - 1, core=(core, core2)),
        nonce_saturates=dict(nonce=U64 - 1, system=(system, system)),
        native_token=dict(native=token, system=(system,)),
        native_other=dict(native=token + 1, system=(system,)),
        native_mixed=dict(native=token, system=(system, (token + 1, 5, key20(25)))),
        native_zero_token=dict(native=0, system=((0, 7, key20(26)),)),
        token_zero_no_native=dict(system=((0, 7, key20(26)),)),
        token_max=dict(system=((U64, 7, key20(26)),)),
        chain_zero=dict(chain=0, core=(core,)),
        sentinel_first=dict(core=(stop, core)),
        sentinel_second=dict(core=(core, stop, core2)),
        sentinel_last=dict(core=(core, core2, stop)),
    )
    return [Case("loop_" + name, "loop", loop_world(**change)) for name, change in sorted(rows.items())]


NAMES = {
    HOST: "raw_action_host", LOG_DECODE: "raw_action_log_decode", 0x3819C00: "abi_bytes_decode", 0x32FC560: "abi_bytes_encode", 0x333B000: "wallet_head_check",
    0x34263E0: "sender_map_lookup", 0x3597490: "sender_table_lookup", 0x35934D0: "sender_tree_lookup", 0x33C2F50: "row_push",
    0x285B7F0: "disabled_set_insert", 0x2866420: "disabled_set_remove", 0x2355F40: "vote_apply_writer_arm", 0x4CAA870: "vote_apply_writer_arm_copy", 0x4CB3200: "vote_apply_writer_arm_third",
    LOOP: "block_row_loop",
    0x37E6E90: "decode_order", 0x37E7940: "decode_token_delegate", 0x37E7E00: "decode_send_asset", 0x37E8670: "decode_one_u64", 0x37E87B0: "decode_finalize",
    0x37E8AB0: "decode_spot_send", 0x37E8D60: "decode_wallet", 0x37E9260: "decode_class_transfer", 0x37E95A0: "decode_bole", 0x37E98A0: "decode_cancel",
    0x37E9AF0: "decode_abstraction", 0x37E9D90: "decode_supply_delta", 0x37EA130: "decode_cancel_cloid", 0x37EA360: "decode_vault_transfer", 0x37EA7E0: "decode_builder_fee",
}
JUMP_TABLE = 0x5879FC
TAG_SITES = {1: 0x333B644, 2: 0x333BBDB, 3: 0x333BA2B, 4: 0x333BAD1, 5: 0x333B80E, 6: 0x333BC70, 7: 0x333BCE8, 8: 0x333C268, 9: 0x333C0DC, 10: 0x333B999, 11: 0x333BD72, 12: 0x333B7DB, 13: 0x333C17D, 14: 0x333BCC2, 15: 0x333B760, 16: 0x333C1DB}
DISPATCH = {0x82: "0x1eee7c0", 0x9F: "0x1e5fb20", 0x95: "0x1e5fa70", 0xB2: "0x1f65f80", 0xB1: "0x2758800", 0xAD: "0x1e5fcf0", 0xAF: "0x1e64530", 0xB7: "0x22ce0d0", 0x75: "0x1e5f770", 0x77: "0x22be610", 0x78: "0x21dff60", 0xBA: "0x1e64620", 0xBB: "0x2728e10", 0xBC: "0x1e64ac0", 0xAC: "0x1f69020", 0xC2: "0x1e60f90"}
PINS = (
    ("raw_action_topic", TOPIC_AT, TOPIC0.hex(), "first topic, equal to keccak256 of the text below (computed in this tool)"),
    ("raw_action_text", 0x59B77F, b"RawAction(address,bytes)".hex(), "event signature text"),
    ("events_label", 0x2087C0, b"CoreWriterEvents".hex(), "label in the decode error, length 0x10"),
    ("core_address_low", 0x206290, (b"\x33" * 16).hex(), "first 16 bytes of the log address compare"),
    ("core_address_high", 0x204CE0, (b"\x33" * 4).hex(), "last 4 bytes of the log address compare"),
    ("raw_length_cap", 0x333B37D, "4881fae8030000", "cmp $0x3e8,%rdx at the host: raw action above 1000 bytes is dropped"),
    ("short_raw_gate", 0x333B396, "4883c2fc4883fafd", "len - 4, then jae on -3: lengths 1, 2, 3 are dropped, length 0 is tested before"),
    ("version_gate", 0x333B4E3, "4180fa01", "cmp $0x1,%r10b: version 1 only, after the disabled set"),
    ("action_bound", 0x333B4ED, "49ffc94983f90f", "dec, cmp $0xf: actions 1 to 16"),
    ("disabled_key_stride", 0x333B3EA, "c1e504", "disabled set keys are 0x10 wide: u8 at +0, u64 at +8"),
    ("tif_map", 0x333B5AE, "41bc00020100", "0x10200 >> 8*(tif-1): Alo 0, Gtc 2, Ioc 1"),
    ("limit_word", 0x333B5D6, "48b8cccccccccccccc0c", "0x0ccccccccccccccc bound on price, size and oid"),
    ("bole_map", 0x333B730, "be01030002", "0x2000301 >> 8*op: 0 to 1, 1 to 3, 2 to 0, 3 to 2"),
    ("row_stride", 0x33C2F6D, "4969ff28010000", "imul $0x128: a pushed row is 0x128 bytes"),
    ("topic_count_gate", 0x37A339C, "4983fc01", "cmp $0x1,%r12: exactly one topic gives the length mismatch error, two or more pass"),
    ("host_call", 0x244A25C, "ff15e69d3203", "call through slot 0x5774048 inside the log loop of 0x2448500"),
    ("first_decoder_call", 0x244A1D6, "ff155c9e3203", "call through slot 0x5774038 (0x34273d0) before the raw action host, tag 1 takes the log"),
    ("loop_call", 0x2760B60, "e89b79ceff", "0x2760a70 calls the block function 0x2448500"),
    ("row_sentinel", 0x2761600, "4981fecc000000", "tag 0xcc ends the row loop in 0x2760a70"),
    ("loop_stride", 0x2761543, "4869ea28010000", "imul $0x128 in 0x2760a70"),
    ("enqueue_call", 0x27616F2, "e8a96dffff", "each row goes to the delay wrapper 0x27584a0"),
    ("system_send_tag", 0x27611EA, "48c78424c0050000ad000000", "first list rows become tag 0xad and run at once through 0x2759240"),
    ("native_system_user", 0x276116B, "48bb2222222222222222", "native token rows use sender bytes 0x22"),
)
SURVIVED = "equal outcome on every picked case that reaches the row"
SAMPLE = 1
VECTORS = 300
WORKERS = 4
MUTANT_CASES = 6
MUTANT_STATE = {}
MUTANT_STEP_LIMIT = 300000
SLOT_SITES = {0x5774048: "raw_action_host", 0x57759A8: "raw_action_log_decode", 0x57759B0: "sender_map_lookup"}
SITES = {va: name for va, name in NAMES.items()}
SITES.update({0x2448500: "block_function", 0x4464DC0: "block_function_copy", 0x44684D0: "block_function_third", 0x27584A0: "delay_wrapper", 0x4D81290: "delay_wrapper_copy", 0x4D81660: "delay_wrapper_third"})


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def text_of(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size])


def pin_rows(image):
    rows = []
    for name, va, data, meaning in PINS:
        got = text_of(image, va, len(data) // 2).hex()
        if got != data:
            raise EvidenceError("pin %s: %s" % (name, got))
        rows.append((name, "%#x" % va, data, meaning))
    return rows


def arm_rows(image):
    rows = []
    for index in range(16):
        action = index + 1
        arm = JUMP_TABLE + struct.unpack_from("<i", image.blob, image.offset(JUMP_TABLE) + 4 * index)[0]
        label, tag, kinds, decoder, variant = ARMS[action]
        site = TAG_SITES[action]
        code = text_of(image, site, 5)
        if not 0xB8 <= code[0] <= 0xBF or struct.unpack_from("<I", code, 1)[0] != tag:
            raise EvidenceError("tag site of action %d" % action)
        rows.append((action, label, "%#x" % arm, "%#x" % tag, "%#x" % site, "(" + ", ".join(kinds) + ")", "%#x" % decoder, variant, DISPATCH[tag]))
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
            try:
                host = image.fde(base + at)[0]
            except EvidenceError:
                continue
            rows.append((SITES[target], "direct", "%#x" % (base + at), "%#x" % host))
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
    harness = Loop(state["image"], patch, state["cache"])
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
        harness = state["worker"] = Loop(state["image"])
    return check_case(harness, state["all"][index])


def analyse(image, mutate=True, vectors=VECTORS, cases=None, sample=SAMPLE):
    harness = Loop(image)
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
        if got[0] == "loop":
            rows.append((case, ("loop", got[5], got[1:5]), ()))
        else:
            rows.append((case, got[2:], got[:2]) if "ops" in case.world else (case, got, ()))
    seen = set()
    for _, items, _ in done:
        seen |= items
    table = {}
    for target in sorted(NAMES):
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    helpers = collections.Counter()
    for va in seen:
        low = image.fde(va)[0]
        if low not in NAMES:
            helpers[low] += 1
    result = dict(table=table, named=rows, vector_count=len(generated), vector_rows=sum(1 for item in done[len(named):] if item[0][0] == "row"), pins=pin_rows(image), arms=arm_rows(image), sizes={target: image.exact_fde(target)[1] - target for target in NAMES}, helpers=[("%#x" % va, image.exact_fde(va)[1] - va, helpers[va]) for va in sorted(helpers)])
    if mutate:
        result["callers"] = caller_rows(image)
        result["edit_count"], result["mutations"] = run_mutants(image, table, named, reach, cost, harness, sample)
    return result


def row_text(got):
    if got[0] == "loop":
        return json.dumps(got[2], sort_keys=True).replace(" ", "")
    if got[0] != "row":
        return ""
    return ";".join("%#x=%s" % (item[0], item[2]) for item in got[2]) + (" box " + ",".join("%#x=%s" % (item[0], item[2]) for item in got[3]) if got[3] else "") + (" name " + got[4] if got[4] else "")


def writer_text(head):
    if not head:
        return ""
    return "s " + ",".join("%#x" % item[0] for item in head[0]) + " keys " + ",".join("%d:%d" % item for item in head[1][:12]) + (" +%d" % (len(head[1]) - 12) if len(head[1]) > 12 else "")


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table, sizes = result["table"], result["sizes"]
    order = sorted(NAMES)
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in order for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in order])
    tsv("helpers.tsv", ("address", "body_bytes", "reached_rows"), result["helpers"])
    tsv("arms.tsv", ("action", "upstream_name", "arm", "action_tag", "tag_site", "abi_types", "decoder", "tag_name_in_dispatch_packets", "handler_in_dispatch_packets"), result["arms"])
    tsv("constants.tsv", ("name", "address", "bytes", "meaning"), result["pins"])
    tsv("scenarios.tsv", ("case", "group", "outcome", "action", "row_fields", "writer_statuses_and_keys"), [(case.name, case.kind, got[0], got[1], row_text(got), writer_text(head)) for case, got, head in result["named"]])
    groups = collections.Counter(item[0].kind for item in result["named"])
    outcomes = collections.Counter(item[1][0] for item in result["named"])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "helpers": len(result["helpers"]), "named_scenarios": len(result["named"]), "groups": dict(sorted(groups.items())), "outcomes": dict(sorted(outcomes.items())), "vector_scenarios": result["vector_count"], "vector_rows": result["vector_rows"], "instructions": sum(len(items) for items in table.values()), "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "pins": len(result["pins"]), "arms": len(result["arms"])}
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
