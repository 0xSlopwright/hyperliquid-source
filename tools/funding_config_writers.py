#!/usr/bin/env python3
"""Pin the node #94 funding configuration writers: hip3 multiplier and interest rate setters, and the impact and clamp votes.

Real rows run from the setter entries and from the vote dispatchers, with the real decimal parser, float call, B-tree
iterators and hash table code. A separately written rule list predicts every result, table and field, and every reached
conditional row, immediate and field offset of the subject code is edited. No objdump or readelf output is parsed and the
binary is never executed. Standard library only.

    python3 tools/funding_config_writers.py --out <dir>
"""

import argparse
import bisect
import collections
import datetime
import fractions
import hashlib
import itertools
import json
import math
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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 200000


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
            for operand in (a, b):
                if operand and operand[0] == "r" and 4 <= operand[1] <= 7:
                    raise EvidenceError("high byte register at %#x" % va)

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
    if byte == 0x98 and wide:
        return finish("cdqe")
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
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
        if two == 0xC6 and not opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufps", ("x", reg), rm, 16, target=value)
        if two == 0x51 and repne:
            reg, rm = modrm(True)
            return finish("sqrtsd", ("x", reg), rm, 8)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("bts", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xFB, True): "psubq", (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd", (0x14, True): "punpcklqdq",
                  (0x55, True): "andnpd", (0x55, False): "andnpd", (0xDF, True): "andnpd", (0x59, True): "mulpd", (0x66, True): "pcmpgtd"}
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
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmpsd", ("x", reg), rm, 8, target=value)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdr", rm, ("x", reg), 4)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
        if two == 0xA5:
            reg, rm = modrm()
            return finish("shldc", rm, ("r", reg), width)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
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
        self.stop = None
        self.frame = 0

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
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
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

    def run(self, entry, args):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        self.push(RETURN_SENTINEL)
        self.regs[RSP] -= self.frame
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL and pc != self.stop:
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
        if pc == self.stop:
            return None
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
        elif op == "bt":
            count = self.regs[row.b[1]] if row.b[0] == "r" else row.b[1]
            self.cf = bool(self.get(row.a, width) >> (count & (8 * width - 1)) & 1)
        elif op == "bts":
            count = self.regs[row.b[1]] & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> count & 1)
            self.put(row.a, width, value | 1 << count)
        elif op == "movsx":
            size = row.cc
            value = self.get(row.b, size)
            self.put(row.a, width, value - (1 << (8 * size)) if value & SIGN[size] else value)
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
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            product = (left - (left >> 63 << 64)) * (right - (right >> 63 << 64))
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < (1 << 63)
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            self.zf = source == 0
            if source:
                self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi", "shldc"):
            bits = 8 * width
            count = (self.regs[RCX] if op in ("shrd", "shldc") else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op in ("shld", "shldc"):
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "rol":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) if count else value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
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
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
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
        elif op == "psubq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left & MASK[8]) - (right & MASK[8])) & MASK[8] | (((left >> 64) - (right >> 64)) & MASK[8]) << 64
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
        elif op == "cmpsd":
            if row.target not in (1, 2):
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if (left < right if row.target == 1 else left <= right) else 0)
        elif op == "andnpd":
            self.xmm[row.a[1]] = ~self.xmm[row.a[1]] & (MASK[8] | MASK[8] << 64) & self.vector(row.b)
        elif op == "mulpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = to_bits(to_float(left & MASK[8]) * to_float(right & MASK[8])) | to_bits(to_float(left >> 64) * to_float(right >> 64)) << 64
        elif op == "pcmpgtd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 32, 64, 96):
                one, two = (left >> shift) & MASK[4], (right >> shift) & MASK[4]
                if one - (one >> 31 << 32) > two - (two >> 31 << 32):
                    value |= MASK[4] << shift
            self.xmm[row.a[1]] = value
        elif op == "shufps":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            pick = row.target
            self.xmm[row.a[1]] = ((left >> (32 * (pick & 3))) & MASK[4]) | ((left >> (32 * (pick >> 2 & 3))) & MASK[4]) << 32 | ((right >> (32 * (pick >> 4 & 3))) & MASK[4]) << 64 | ((right >> (32 * (pick >> 6 & 3))) & MASK[4]) << 96
        elif op == "sqrtsd":
            value = self.low(row.b)
            result = to_float(value)
            if result == result and result > 0:
                value = to_bits(math.sqrt(result))
            elif result < 0:
                value = 0xFFF8000000000000
            self.set_low(row.a[1], value)
        elif op == "movdr":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return struct.unpack("<d", bytes.fromhex("000000000000f8ff"))[0]
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


OK = 0x186
TAG_TEXT = 0xE0
TAG_LENGTH = 0x143
TAG_NUMBER = 0x13F
TAG_IMPACT = 0x3C
TAG_CLAMP = 0x40
TAG_FLOAT = 0xAB
TAG_LOOKUP = 0x123
TAG_PARSE = 0xAC
TEXT_TABLE = 0x59A8D0
TAG_TEXTS = {TAG_IMPACT: "Impact usd too small", TAG_CLAMP: "Invalid clamp", TAG_FLOAT: "Error converting decimal to float", TAG_NUMBER: "Invalid input number", TAG_LENGTH: "Invalid input length"}
TAG_DROP = 0x3762510
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_SPLIT = 0x5773EC8
SLOT_ASSET = 0x5773318
SLOT_FLOAT = 0x5773968
SLOT_UNWRAP = 0x576E048
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048)
MARK_BASE = 0x7700000000
PARSE = 0x3799510
FLOAT = 0x4EAD680
CAP = 0x0CCCCCCCCCCCCCCC
TOP = MASK[8]
OVERRIDE_FLOOR = 600000000
DEFAULT_FLOOR = 6000000000
LIST_CAP = 10000
TEXT_CAP = 100
RATE_BOUND = 0.01
MULT_BOUND = 10.0
ROW_STRIDE = 0x138
OVERRIDE_AT = 0x48
MULT_AT = 0x78
RATE_AT = 0xA8
CLAMP_AT = 0xF0
DEFAULT_AT = 0xF8
MAPS = (OVERRIDE_AT, MULT_AT, RATE_AT)
FUNDING_STRUCT = b"struct FundingTracker with 8 elements"
MULT_TEXT = b"Invalid funding multiplier"
RATE_TEXT = b"Invalid funding interest rate"
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
EMPTY_GROUP = HEAP_BASE + 0x20
OUT = HEAP_BASE + 0x40
ACTION = HEAP_BASE + 0xA0
MAP_REF = HEAP_BASE + 0xE0
STATE_GAP = 0
DEX_ROWS = STATE + STATE_SIZE
DEX_ROOM = 4
META = DEX_ROWS + DEX_ROOM * ROW_STRIDE + 0x40
BUMP = META + 0x80
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
BUCKETS = 16
SEEDS = (0x1122334455667788, 0x99AABBCCDDEEFF01)
SHA_NOTE = "node 94"


AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


class Copy:
    def __init__(self, name, dispatch, table, base, dexes, setters, texts, hip3):
        self.name, self.dispatch, self.table, self.base, self.dexes, self.setters, self.texts, self.hip3 = name, dispatch, table, base, dexes, setters, texts, hip3


COPIES = (
    Copy("a", 0x2355F40, 0x3DD1B8, 0x5B8, 0x3368, dict(mult=0x273C960, rate=0x2743860), dict(mult=0x3EFBB4, rate=0x3EFBCE), 0x273E080),
    Copy("b", 0x4CAA870, 0x711064, 0x5B8, 0x3368, dict(mult=0x4D4D2B0, rate=0x4D5BD30), dict(mult=0x714FB5, rate=0x714FCF), 0x4D50130),
    Copy("c", 0x4CB3200, 0x711244, 0x1038, 0x3DE8, dict(mult=0x4D4DA70, rate=0x4D5B570), dict(mult=0x714FB5, rate=0x714FCF), 0x4D55B50),
)
MAP_F64 = 0x27C5980
MAP_U64 = 0x379C5C0
LIST_GATE = 0x1E7FEC0
FUNCTIONS = dict(multiplier=0x273C960, interest_rate=0x2743860, map_f64=MAP_F64, map_u64=MAP_U64, list_gate=LIST_GATE)
ARM_WINDOWS = (
    ("word_20", 0x2357779, 0x2357957), ("word_20_end", 0x235BE47, 0x235BE7C),
    ("word_21", 0x2357CB5, 0x2357D9B), ("word_21_end", 0x235B896, 0x235B8BD),
    ("word_22", 0x23572F8, 0x2357356), ("word_22_store", 0x235A804, 0x235A80B), ("word_22_refuse", 0x235C654, 0x235C663),
)
WORD_OVERRIDE, WORD_CLAMP, WORD_DEFAULT = 20, 21, 22
STRING_TREE = Layout(8, 24, 0x110, 24, 0, 0x218, 0x21A, 0x220)
VALUE_TREE = Layout(8, 24, 0x110, 8, 0, 0x168, 0x16A, 0x170)
ASSETS = {b"BTC": 0, b"ETH": 1, b"LAST": 9999, b"xyz:AAA": 10000, b"xyz:BBB": 10007, b"xyz:END": 19999, b"abc:CCC": 20003, b"far:OUT": 30000, b"far:TOP": 39999}
SPLIT_FAIL = b"nodex:AAA"
ASSETS.update({b"G%02d" % index: 100 + index for index in range(40)})
ASSETS.update({b"H%02d" % index: 10100 + index for index in range(40)})


class Case:
    DEFAULTS = dict(steps=(), copy=0, dexes=3, start=BUCKETS, inject=(), metas=2)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000 and target != TAG_DROP


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_SPLIT, self.on_split), (SLOT_ASSET, self.on_asset))
        if Harness.statics is None:
            table = dict(image.relative())
            for slot, _ in hooks:
                table[slot] = MARK_BASE + slot
            for slot in PANIC_SLOTS:
                table[slot] = MARK_BASE + slot
            Harness.statics = table
        machine.memory.statics = dict(Harness.statics)
        self.real_float = machine.memory.statics[SLOT_FLOAT]
        for slot, hook in hooks + ((SLOT_FLOAT, self.on_float),):
            machine.slots[MARK_BASE + slot] = hook
        for slot in PANIC_SLOTS:
            machine.slots[MARK_BASE + slot] = self.on_panic
        machine.slots[MARK_BASE + SLOT_UNWRAP] = self.on_unwrap
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic, TAG_DROP: self.on_drop}
        self.case = None
        self.live = {}
        self.inputs = set()
        self.cur = BUMP
        self.queue = []
        self.drops = []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

    def on_unwrap(self, machine):
        self.expect(machine.regs[RSI] == 0x2B and machine.memory.read(machine.regs[RDX], 2) == 0x141, "unwrap message and error")
        raise Panicked("panic path")

    def on_drop(self, machine):
        tag = machine.memory.read(machine.regs[RDI], 2)
        self.expect(tag == TAG_FLOAT or machine.regs[RDI] >> 32 == STACK_TOP >> 32 and tag == TAG_PARSE, "drop of an unused error")

    def bump(self, size):
        at = self.cur
        self.cur += (size + 15) & ~15
        self.expect(self.cur <= BUMP_END, "allocator room")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.bump(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.pop(at, None) == size, "free of a live block with its size")
        self.inputs.discard(at)

    def on_realloc(self, machine):
        old, new = machine.regs[RDI], machine.regs[RSI]
        size = self.live.pop(old, None)
        self.expect(size is not None, "realloc of a live block")
        at = self.bump(new)
        machine.memory.put_bytes(at, machine.memory.bytes_at(old, min(size, new)))
        machine.regs[RAX] = at

    def on_copy(self, machine):
        dst, src, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        if size:
            machine.memory.put_bytes(dst, machine.memory.bytes_at(src, size))
        machine.regs[RAX] = dst

    def on_cmp(self, machine):
        one, two = machine.memory.bytes_at(machine.regs[RDI], machine.regs[RDX]), machine.memory.bytes_at(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if one == two else 1 if one > two else MASK[8]

    def on_set(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], bytes([machine.regs[RSI] & 0xFF]) * machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def object_bytes(self, tag):
        return struct.pack("<H", tag) + bytes((0x41 + index) & 0xFF for index in range(2, 0x60))

    def on_split(self, machine):
        regs, memory = machine.regs, machine.memory
        copy = COPIES[self.case.copy]
        self.expect(regs[RSI] == STATE + copy.base, "split table argument")
        name = memory.bytes_at(regs[RDX], regs[RCX]) if regs[RCX] else b""
        if name == SPLIT_FAIL:
            memory.put_bytes(regs[RDI], self.object_bytes(TAG_LOOKUP))
            return
        memory.write(regs[RDI], 2, OK)
        memory.write(regs[RDI] + 8, 8, META + 0x10)

    def on_asset(self, machine):
        regs, memory = machine.regs, machine.memory
        name = memory.bytes_at(regs[RSI], regs[RDX]) if regs[RDX] else b""
        self.expect(regs[RCX] in (META, META + 0x10), "asset table argument")
        self.expect(regs[RCX] == self.asset_table, "asset table of this path")
        if name in ASSETS:
            memory.write(regs[RDI], 2, OK)
            memory.write(regs[RDI] + 8, 8, ASSETS[name])
        else:
            memory.put_bytes(regs[RDI], self.object_bytes(TAG_LOOKUP))

    def on_float(self, machine):
        self.expect(self.queue, "float value queue")
        bits, ok = self.queue.pop(0)
        machine.xmm_result = bits
        machine.regs[RAX] = ok

    def tree_bytes(self, layout, items, height):
        """Real shaped nodes; extra height is added as empty inner nodes over the top tree."""
        memory = self.machine.memory

        def node(rows, size):
            at = self.bump(size)
            memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for slot in range(11):
                memory.put_bytes(at + layout.key_at + layout.key_size * slot, b"\xfe" * layout.key_size)
            for slot, (key, value) in enumerate(rows):
                memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
                memory.write(at + layout.val_at + layout.val_size * slot, layout.val_size, value)
            return at

        if not items:
            return 0, 0xFEED
        if height >= 2 and len(items) <= 11:
            # One separator high up, with a chain of empty inner nodes down to each leaf.
            middle = len(items) // 2
            sides = [node(items[:middle], layout.leaf), node(items[middle + 1:], layout.leaf)]
            for _ in range(height - 1):
                for side, kid in enumerate(sides):
                    top = node([], layout.inner)
                    memory.write(top + layout.edge_at, 8, kid)
                    memory.write(kid + layout.parent_at, 8, top)
                    memory.write(kid + layout.index_at, 2, 0)
                    sides[side] = top
            root = node([items[middle]], layout.inner)
            for side, kid in enumerate(sides):
                memory.write(root + layout.edge_at + 8 * side, 8, kid)
                memory.write(kid + layout.parent_at, 8, root)
                memory.write(kid + layout.index_at, 2, side)
            return root, height
        if len(items) <= 11:
            root, level = node(items, layout.leaf), 0
        else:
            parts, seps, at = [], [], 0
            while len(items) - at > 11:
                parts.append(items[at:at + 5])
                seps.append(items[at + 5])
                at += 6
            parts.append(items[at:])
            kids = [node(part, layout.leaf) for part in parts]
            root = node(seps, layout.inner)
            for slot, kid in enumerate(kids):
                memory.write(root + layout.edge_at + 8 * slot, 8, kid)
                memory.write(kid + layout.parent_at, 8, root)
                memory.write(kid + layout.index_at, 2, slot)
            level = 1
        while level < height:
            top = node([], layout.inner)
            memory.write(top + layout.edge_at, 8, root)
            memory.write(root + layout.parent_at, 8, top)
            memory.write(root + layout.index_at, 2, 0)
            root, level = top, level + 1
        return root, level

    def block(self, data):
        at = self.bump(max(len(data), 1))
        self.machine.memory.put_bytes(at, data)
        self.inputs.add(at)
        return at

    def string(self, data):
        """A String triple; an empty one owns no block."""
        if not data:
            return struct.pack("<3Q", 0, 1, 0)
        return struct.pack("<3Q", len(data), self.block(data), len(data))

    def table(self, at):
        memory = self.machine.memory
        if self.case.start:
            size = self.case.start * 17 + 16
            block = self.bump(size)
            ctrl = block + self.case.start * 16
            memory.put_bytes(ctrl, b"\xff" * (self.case.start + 16))
            memory.put_bytes(at, struct.pack("<4Q", ctrl, self.case.start - 1, self.case.start * 7 // 8, 0))
        else:
            memory.put_bytes(at, struct.pack("<4Q", EMPTY_GROUP, 0, 0, 0))
        memory.put_bytes(at + 0x20, struct.pack("<2Q", *SEEDS))

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.live = {}
        self.inputs = set()
        self.cur = BUMP
        self.queue = list(case.inject)
        self.drops = []
        memory.statics[SLOT_FLOAT] = MARK_BASE + SLOT_FLOAT if case.inject else self.real_float
        copy = COPIES[case.copy]
        memory.put_bytes(EMPTY_GROUP, b"\xff" * 16)
        memory.write(STATE + copy.base + 8, 8, META)
        memory.write(STATE + copy.base + 0x10, 8, case.metas)
        memory.write(STATE + copy.dexes + 8, 8, DEX_ROWS)
        memory.write(STATE + copy.dexes + 0x10, 8, case.dexes)
        for dex in range(case.dexes):
            row = DEX_ROWS + dex * ROW_STRIDE
            for offset in MAPS:
                self.table(row + offset)

    def enter(self, entry, args):
        memory = self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x60)
        self.machine.run(entry, args)

    def error_view(self):
        memory = self.machine.memory
        tag = memory.read(OUT, 2)
        if tag == OK:
            return ("ok",)
        if tag == TAG_TEXT:
            cap, at, size = struct.unpack("<3Q", memory.bytes_at(OUT + 8, 24))
            self.expect(self.live.get(at) == cap, "text block")
            self.live.pop(at)
            return ("error", tag, memory.bytes_at(at, size))
        if tag == TAG_NUMBER:
            return ("error", tag, memory.read(OUT + 8, 8))
        if tag == TAG_LOOKUP:
            self.expect(memory.bytes_at(OUT, 0x60) == self.object_bytes(tag), "lookup error object")
        return ("error", tag)

    def step(self, step):
        memory = self.machine.memory
        copy = COPIES[self.case.copy]
        kind = step[0]
        if kind in ("mult", "rate"):
            _, rows, height = step
            self.asset_table = META + 0x10
            items = [(self.string(name), int.from_bytes(self.string(text), "little")) for name, text in sorted(rows)]
            root, level = self.tree_bytes(STRING_TREE, items, height)
            memory.put_bytes(MAP_REF, struct.pack("<3Q", root, level, len(items)))
            self.enter(copy.setters[kind], {RDI: OUT, RSI: STATE, RDX: MAP_REF})
            return self.error_view()
        self.asset_table = META
        memory.write(ACTION, 8, kind)
        if kind == WORD_OVERRIDE:
            _, rows, height, fake = step
            items = [(self.string(name), value) for name, value in sorted(rows)]
            root, level = self.tree_bytes(VALUE_TREE, items, height)
            memory.put_bytes(ACTION + 8, struct.pack("<3Q", root, level, len(items) if fake is None else fake))
        elif kind == WORD_CLAMP:
            memory.put_bytes(ACTION + 8, self.string(step[1]))
        else:
            memory.write(ACTION + 8, 8, step[1])
        self.enter(copy.dispatch, {RDI: OUT, RSI: ACTION, RDX: STATE})
        return self.error_view()

    def map_view(self, at):
        memory = self.machine.memory
        ctrl, mask, left, items = struct.unpack("<4Q", memory.bytes_at(at, 32))
        rows = {}
        for index in range(mask + 1):
            if memory.read(ctrl + index, 1) & 0x80 == 0:
                entry = ctrl - (index + 1) * 16
                rows[memory.read(entry, 8)] = memory.read(entry + 8, 8)
        self.expect(len(rows) == items, "table item count")
        return rows

    def view(self, before):
        memory = self.machine.memory
        state = {}
        now = bytearray(memory.heap[:FILL_END])
        now[OUT - HEAP_BASE:OUT - HEAP_BASE + 0x60] = before[OUT - HEAP_BASE:OUT - HEAP_BASE + 0x60]
        now[ACTION - HEAP_BASE:ACTION - HEAP_BASE + 0x40] = before[ACTION - HEAP_BASE:ACTION - HEAP_BASE + 0x40]
        now[MAP_REF - HEAP_BASE:MAP_REF - HEAP_BASE + 0x18] = before[MAP_REF - HEAP_BASE:MAP_REF - HEAP_BASE + 0x18]
        for dex in range(self.case.dexes):
            row = DEX_ROWS + dex * ROW_STRIDE
            for offset in MAPS:
                state[dex, offset] = self.map_view(row + offset)
                at = row + offset - HEAP_BASE
                now[at:at + 0x20] = before[at:at + 0x20]
            for offset in (CLAMP_AT, DEFAULT_AT):
                state[dex, offset] = memory.read(row + offset, 8)
                at = row + offset - HEAP_BASE
                now[at:at + 8] = before[at:at + 8]
        return state, bytes(now) == bytes(before)

    def run(self, case):
        self.fresh(case)
        before = bytes(self.machine.memory.heap[:FILL_END])
        results = []
        for step in case.steps:
            try:
                results.append(self.step(step))
            except Panicked:
                results.append(("panic",))
                break
        state, rest = self.view(before)
        return dict(results=results, state=state, rest=rest, kept=len(self.inputs) if results[-1] != ("panic",) else 0)


class Parsed:
    """Text to f64 through the real parser and the real float call on the unedited image."""
    cache = {}
    harness = None


def parsed(text):
    if text in Parsed.cache:
        return Parsed.cache[text]
    harness = Parsed.harness
    machine = harness.machine
    memory = machine.memory
    harness.case = Case("parse")
    memory.reset(HEAP_SIZE)
    harness.cur = BUMP
    memory.put_bytes(SCRATCH + 0x100, text)
    machine.run(PARSE, {RDI: SCRATCH, RSI: SCRATCH + 0x100, RDX: len(text)})
    tag = memory.read(SCRATCH, 2)
    if tag != OK:
        value = ("tag", tag)
    else:
        memory.put_bytes(SCRATCH + 0x70, memory.bytes_at(SCRATCH + 4, 16))
        machine.run(FLOAT, {RDI: SCRATCH + 0x70})
        value = ("value", machine.xmm[0] & MASK[8]) if machine.regs[RAX] & 1 else ("tag", TAG_FLOAT)
    Parsed.cache[text] = value
    return value


def spec_setter(case, kind, rows, want, inject):
    """Pass 1 reads rows in key order and stops at the first refusal; pass 2 writes all rows in the same order."""
    bound = TEXTS[kind]
    good = []
    for name, text in sorted(rows):
        if len(text) > TEXT_CAP:
            return ("error", TAG_LENGTH)
        if inject:
            bits, ok = inject.pop(0)
            read = ("value", bits) if ok & 1 else ("tag", TAG_FLOAT)
        else:
            read = parsed(text)
        if read[0] == "tag":
            return ("error", read[1])
        bits = read[1]
        value = to_float(bits)
        if (kind == "rate" and abs(value) > RATE_BOUND) or (kind == "mult" and (value < 0.0 or value > MULT_BOUND)):
            return ("error", TAG_TEXT, bound)
        if len(name) > TEXT_CAP:
            return ("error", TAG_LENGTH)
        if name == SPLIT_FAIL or name not in ASSETS:
            return ("error", TAG_LOOKUP)
        good.append((ASSETS[name], bits))
    field = MULT_AT if kind == "mult" else RATE_AT
    for asset, bits in good:
        dex = asset // 10000
        if dex >= case.dexes:
            return ("panic",)
        want[dex, field][asset] = bits
    return ("ok",)


TEXTS = dict(mult=MULT_TEXT, rate=RATE_TEXT)


def spec_override(case, rows, want, fake):
    count = len(rows) if fake is None else fake
    if count > LIST_CAP:
        return ("error", TAG_LENGTH)
    previous = None
    for name, value in sorted(rows):
        if case.dexes == 0 or case.metas == 0:
            return ("panic",)
        if len(name) > TEXT_CAP:
            return ("error", TAG_LENGTH)
        if name not in ASSETS:
            return ("error", TAG_LOOKUP)
        if value >= CAP:
            return ("error", TAG_NUMBER, previous)
        if value < OVERRIDE_FLOOR:
            return ("error", TAG_IMPACT)
        want[0, OVERRIDE_AT][ASSETS[name]] = value
        previous = value
    return ("ok",)


def clamp_refused(bits):
    return bits != 1 << 63 and (bits >> 63 == 1 or bits & (TOP >> 1) >= 0x7FF0000000000000)


def spec_clamp(case, text, want, inject):
    if len(text) > TEXT_CAP:
        return ("error", TAG_LENGTH)
    if inject:
        bits, ok = inject.pop(0)
        read = ("value", bits) if ok & 1 else ("tag", TAG_FLOAT)
    else:
        read = parsed(text)
    if read[0] == "tag":
        return ("error", read[1])
    if clamp_refused(read[1]):
        return ("error", TAG_CLAMP)
    want[0, CLAMP_AT] = read[1]
    return ("ok",)


def spec_default(value, want):
    if value >= CAP:
        return ("error", TAG_NUMBER, value)
    if value >> 10 <= 0x59682E:
        return ("error", TAG_IMPACT)
    want[0, DEFAULT_AT] = value
    return ("ok",)


def base_state(harness, case):
    state = {}
    fill = HEAP_FILL
    for dex in range(case.dexes):
        row = DEX_ROWS + dex * ROW_STRIDE - HEAP_BASE
        for offset in MAPS:
            state[dex, offset] = {}
        for offset in (CLAMP_AT, DEFAULT_AT):
            state[dex, offset] = int.from_bytes(fill[row + offset:row + offset + 8], "little")
    return state


def spec_for(harness, case):
    want = base_state(harness, case)
    results = []
    inject = list(case.inject)
    for step in case.steps:
        kind = step[0]
        if kind in ("mult", "rate"):
            result = spec_setter(case, kind, step[1], want, inject)
        elif kind == WORD_OVERRIDE:
            result = spec_override(case, step[1], want, step[3])
        elif kind == WORD_CLAMP:
            result = spec_clamp(case, step[1], want, inject)
        else:
            result = spec_default(step[1], want)
        results.append(result)
        if result == ("panic",):
            break
    return dict(results=results, state=want, rest=True, kept=0)


def same(case, got, want):
    if got["state"] != want["state"] or got["rest"] != want["rest"] or got["kept"] != want["kept"] or len(got["results"]) != len(want["results"]):
        return False
    for mine, theirs in zip(got["results"], want["results"]):
        if len(theirs) == 3 and theirs[2] is None:
            mine, theirs = mine[:2], theirs[:2]
        if mine != theirs:
            return False
    return True


def bits_of(value):
    return to_bits(value)


LONG = b"1" * 101
EDGE = b"1" * 100
NAME_100 = b"n" * 100
NAME_101 = b"n" * 101
GOOD_TEXTS = (b"0", b"0.0", b"-0", b"1", b"0.5", b"0.001", b"0.01", b"-0.01", b"0.0099999999", b"0.0100000001", b"-0.0100000001", b"0.01000000000000000001", b"0.010000000000000002", b"0.0100000000000001", b"-0.0100000000000000001",
              b"10", b"10.0", b"9.999999999", b"10.000000001", b"10.00000000000000001", b"10.0000000000001", b"-0.000000001", b"-1", b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", b"0.0000000000000000000000000001",
              b"79228162514264337593543950335", b"79228162514264337593543950336", b"-79228162514264337593543950335", b"", b" 1", b"1 ", b"+1", b"abc", b"1e1", b"1_0", b"0x10", b"1.2.3", b".", b"-", b".5", b"5.", b"NaN", b"inf")


def setter_cases():
    out = []
    for copy in range(3):
        for kind in ("mult", "rate"):
            for text in GOOD_TEXTS if copy == 0 else GOOD_TEXTS[:24:3]:
                out.append(Case("%s %s text %r" % (COPIES[copy].name, kind, text), copy=copy, steps=((kind, ((b"BTC", text),), 0),)))
            for name, rows in (("two rows", ((b"BTC", b"0.005"), (b"xyz:AAA", b"0.007"))), ("three dexes", ((b"BTC", b"0.001"), (b"abc:CCC", b"0.003"), (b"xyz:END", b"0.002"))),
                               ("later value refused", ((b"BTC", b"0.005"), (b"ETH", b"11"))), ("later value bad text", ((b"BTC", b"0.005"), (b"ETH", b"abc"))),
                               ("later name refused", ((b"BTC", b"0.005"), (b"nope", b"0.001"))), ("later split refused", ((b"BTC", b"0.005"), (SPLIT_FAIL, b"0.001"))),
                               ("name at the cap", ((NAME_100, b"0.001"),)), ("name past the cap", ((NAME_101, b"0.001"),)),
                               ("value at the cap", ((b"BTC", EDGE),)), ("value past the cap", ((b"BTC", LONG),)), ("value past the cap beats a bad name", ((NAME_101, LONG),)), ("bad value beats a bad name", ((NAME_101, b"99"),)),
                               ("no rows", ()), ("empty name", ((b"", b"0.001"),)), ("empty value", ((b"BTC", b""),)), ("far dex panics in pass 2", ((b"BTC", b"0.001"), (b"far:OUT", b"0.002"))), ("last local", ((b"LAST", b"0.001"), (b"xyz:AAA", b"0.002")))):
                out.append(Case("%s %s %s" % (COPIES[copy].name, kind, name), copy=copy, steps=((kind, rows, 0),)))
            many = tuple((b"xyz:AAA" if index == 7 else b"BTC" if index == 3 else b"ETH" if index == 5 else b"xyz:BBB" if index == 9 else b"xyz:END", b"0.00%d" % (index % 9 + 1)) for index in (3, 5, 7, 9, 11))
            out.append(Case("%s %s rows in key order" % (COPIES[copy].name, kind), copy=copy, steps=((kind, tuple(sorted(dict(many).items())), 0),)))
            out.append(Case("%s %s second action replaces" % (COPIES[copy].name, kind), copy=copy, steps=((kind, ((b"BTC", b"0.001"), (b"ETH", b"0.002")), 0), (kind, ((b"BTC", b"0.003"),), 0))))
            out.append(Case("%s %s empty table start" % (COPIES[copy].name, kind), copy=copy, start=0, steps=((kind, ((b"BTC", b"0.001"), (b"ETH", b"0.002")), 0),)))
            for height in (1, 2):
                rows = tuple(sorted((b"nm%02d" % index, b"0.00%d" % (index % 9 + 1)) for index in range(6)))
                out.append(Case("%s %s tree height %d refused" % (COPIES[copy].name, kind, height), copy=copy, steps=((kind, rows, height),)))
                rows = ((b"BTC", b"0.001"), (b"ETH", b"0.002"), (b"LAST", b"0.003"), (b"abc:CCC", b"0.004"), (b"xyz:AAA", b"0.005"), (b"xyz:BBB", b"0.006"))
                out.append(Case("%s %s tree height %d" % (COPIES[copy].name, kind, height), copy=copy, steps=((kind, rows, height),)))
    big = tuple(sorted((b"BTC" if index == 0 else b"xyz:AAA" if index == 1 else b"ETH" if index == 2 else b"far:TOP" if index == 3 else b"abc:CCC", b"0.00%d" % (index + 1)) for index in range(5)))
    out.append(Case("a rate dex at the count", dexes=4, steps=(("rate", big, 0),)))
    out.append(Case("a rate dex past the count", dexes=3, steps=(("rate", big, 0),)))
    out.append(Case("a rate one dex", dexes=1, steps=(("rate", ((b"BTC", b"0.001"), (b"xyz:AAA", b"0.002")), 0),)))
    out.append(Case("a mult one dex", dexes=1, steps=(("mult", ((b"BTC", b"1"), (b"xyz:AAA", b"2")), 0),)))
    for copy in range(3):
        for start in (0, BUCKETS):
            for kind in ("mult", "rate"):
                rows = tuple((b"%s%02d" % (b"GH"[index % 2:index % 2 + 1], index), b"0.00%d" % (index % 9 + 1)) for index in range(40))
                out.append(Case("%s %s forty rows from %d buckets" % (COPIES[copy].name, kind, start), copy=copy, start=start, steps=((kind, rows, 0),)))
                out.append(Case("%s %s forty rows twice from %d buckets" % (COPIES[copy].name, kind, start), copy=copy, start=start, steps=((kind, rows, 0), (kind, rows[:20], 1))))
    return out


FLOAT_POINTS = (0, 1, 1 << 52, (1 << 52) - 1, to_bits(0.01), to_bits(0.01) + 1, to_bits(0.01) - 1, to_bits(10.0), to_bits(10.0) + 1, to_bits(10.0) - 1, to_bits(1.0), 0x7FEFFFFFFFFFFFFF, 0x7FF0000000000000, 0x7FF0000000000001, 0x7FF8000000000000, 0x7FFFFFFFFFFFFFFF)
SIGNED_POINTS = tuple(sorted({point | 1 << 63 for point in FLOAT_POINTS} | set(FLOAT_POINTS)))


def inject_cases():
    out = []
    for copy in range(3):
        for bits in SIGNED_POINTS:
            for kind in ("mult", "rate"):
                out.append(Case("%s %s float %#x" % (COPIES[copy].name, kind, bits), copy=copy, inject=((bits, 1),), steps=((kind, ((b"BTC", b"1"),), 0),)))
            out.append(Case("%s clamp float %#x" % (COPIES[copy].name, bits), copy=copy, inject=((bits, 1),), steps=((WORD_CLAMP, b"1"),)))
        for kind in ("mult", "rate"):
            out.append(Case("%s %s float call refuses" % (COPIES[copy].name, kind), copy=copy, inject=((0, 0),), steps=((kind, ((b"BTC", b"1"),), 0),)))
        out.append(Case("%s clamp float call refuses" % COPIES[copy].name, copy=copy, inject=((0, 0),), steps=((WORD_CLAMP, b"1"),)))
    return out


def vote_cases():
    out = []
    for copy in range(3):
        name = COPIES[copy].name
        for value in (0, 1, 5999999999, 6000000000 - 1024, 6000000000 - 1, 6000000000, 6000000001, 6000001023, 6000001024, 7000000000, CAP - 1, CAP, CAP + 1, TOP):
            out.append(Case("%s default %d" % (name, value), copy=copy, steps=((WORD_DEFAULT, value),)))
        for text in GOOD_TEXTS if copy == 0 else GOOD_TEXTS[:12:2]:
            out.append(Case("%s clamp %r" % (name, text), copy=copy, steps=((WORD_CLAMP, text),)))
        out.append(Case("%s clamp at the cap" % name, copy=copy, steps=((WORD_CLAMP, EDGE),)))
        out.append(Case("%s clamp past the cap" % name, copy=copy, steps=((WORD_CLAMP, LONG),)))
        for value in (0, 1, OVERRIDE_FLOOR - 1, OVERRIDE_FLOOR, OVERRIDE_FLOOR + 1, CAP - 1, CAP, TOP):
            out.append(Case("%s override %d" % (name, value), copy=copy, steps=((WORD_OVERRIDE, ((b"BTC", value),), 0, None),)))
        for label, rows in (("two rows", ((b"BTC", 10 ** 9), (b"ETH", 2 * 10 ** 9))), ("later floor", ((b"BTC", 10 ** 9), (b"ETH", 5))), ("later cap", ((b"BTC", 10 ** 9), (b"ETH", CAP))), ("later name", ((b"BTC", 10 ** 9), (b"nope", 10 ** 9))),
                            ("name at the cap", ((NAME_100, 10 ** 9),)), ("name past the cap", ((NAME_101, 10 ** 9),)), ("later name past the cap", ((b"BTC", 10 ** 9), (NAME_101, 10 ** 9))), ("name beats value", ((NAME_101, 1),)), ("no rows", ()), ("empty name", ((b"", 10 ** 9),)),
                            ("dex prefix name", ((b"xyz:AAA", 10 ** 9),))):
            out.append(Case("%s override %s" % (name, label), copy=copy, steps=((WORD_OVERRIDE, rows, 0, None),)))
        out.append(Case("%s override replaces" % name, copy=copy, steps=((WORD_OVERRIDE, ((b"BTC", 10 ** 9),), 0, None), (WORD_OVERRIDE, ((b"BTC", 2 * 10 ** 9),), 0, None))))
        out.append(Case("%s override list at the cap" % name, copy=copy, steps=((WORD_OVERRIDE, (), 0, LIST_CAP),)))
        out.append(Case("%s override list past the cap" % name, copy=copy, steps=((WORD_OVERRIDE, (), 0, LIST_CAP + 1),)))
        out.append(Case("%s override empty table start" % name, copy=copy, start=0, steps=((WORD_OVERRIDE, ((b"BTC", 10 ** 9), (b"ETH", 2 * 10 ** 9)), 0, None),)))
        out.append(Case("%s override no dex row" % name, copy=copy, dexes=0, steps=((WORD_OVERRIDE, ((b"BTC", 10 ** 9),), 0, None),)))
        out.append(Case("%s override no meta row" % name, copy=copy, metas=0, steps=((WORD_OVERRIDE, ((b"BTC", 10 ** 9),), 0, None),)))
        rows = tuple((b"G%02d" % index, 10 ** 9 + index) for index in range(40))
        out.append(Case("%s override forty rows" % name, copy=copy, steps=((WORD_OVERRIDE, rows, 0, None),)))
        out.append(Case("%s override forty rows twice" % name, copy=copy, start=0, steps=((WORD_OVERRIDE, rows, 0, None), (WORD_OVERRIDE, rows[:20], 1, None))))
        for height in (1, 2):
            rows = ((b"BTC", 10 ** 9), (b"ETH", 2 * 10 ** 9), (b"LAST", 3 * 10 ** 9), (b"abc:CCC", 4 * 10 ** 9), (b"xyz:AAA", 5 * 10 ** 9), (b"xyz:BBB", 6 * 10 ** 9))
            out.append(Case("%s override tree height %d" % (name, height), copy=copy, steps=((WORD_OVERRIDE, rows, height, None),)))
            out.append(Case("%s override tree height %d refused" % (name, height), copy=copy, steps=((WORD_OVERRIDE, rows[:3] + ((b"nope", 10 ** 9),) + rows[3:], height, None),)))
    return out


def base_cases():
    return setter_cases() + inject_cases() + vote_cases()


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(harness, case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %r want %r" % (case.name, got["results"], want["results"]))
        outcomes.append(got)
    return outcomes


VECTORS = 120
MUTANT_VECTORS = 30
REACH_CAP = 12
SECOND_CAP = 40
THIRD_CAP = 200
MUTANT_STEP_LIMIT = 300000


def lcg(seed):
    state = [seed]

    def next_value(bound):
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state[0] >> 33) % bound
    return next_value


def vector_cases(count):
    out = []
    names = sorted(name for name in ASSETS if name != b"far:OUT" and name != b"far:TOP")
    for index in range(count):
        pick = lcg(index * 2 + 1)
        chosen = sorted(set(names[pick(len(names))] for _ in range(pick(6) + 1)))
        copy = pick(3)
        form = pick(4)
        if form < 2:
            kind = "rate" if form else "mult"
            scale = 12 if form else 3
            rows = tuple((name, b"%s%d.%012d" % (b"-" if pick(5) == 0 else b"", pick(2) * pick(scale), pick(10 ** 12)) if form == 0 else b"%s0.%03d%09d" % (b"-" if pick(2) else b"", pick(13), pick(10 ** 9))) for name in chosen)
            out.append(Case("vector %d" % index, copy=copy, steps=((kind, rows, 0),)))
        elif form == 2:
            rows = tuple((name, pick(10 ** 10) * pick(3)) for name in chosen)
            out.append(Case("vector %d" % index, copy=copy, steps=((WORD_OVERRIDE, rows, 0, None),)))
        else:
            out.append(Case("vector %d" % index, copy=copy, steps=((WORD_DEFAULT, pick(1 << 34)),)))
    return out


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            where = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + where: data[where] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            where = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + where: data[where] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        where = displacement_at(row, data)
        if where is not None:
            edits.append((row.va, "displacement", {row.va + where: data[where] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, cases):
    for case in cases:
        try:
            if not same(case, harness.run(case), spec_for(harness, case)):
                return case
        except AccessError:
            return case
    return None


def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


SURVIVOR_REASONS = {
    "stale": "same: the parser error carries no payload, these rows copy stale stack bytes behind the tag",
    "vec": "same: dangling pointer of an empty vector, never read",
    "handle": "same: height word of a tree iterator handle, read only when it climbs from an empty handle",
    "dropped": "same: tag of an unused error that the next call drops; neither value owns memory",
    "old": "same: the replaced value in xmm0 or rdx goes back to a caller that drops it",
    "found": "same: the found flag in eax is dropped by the caller",
    "hasher": "not killed: a shifted hasher field still gives a self consistent table, and no read back uses the first hasher",
    "shuffle": "same: the four dwords of the tag vector are equal",
    "second": "not killed: needs two equal tag bytes in one group where the first is another key",
    "fallible": "same: the fallible flag only matters when the allocator refuses",
    "niche": "same on reached values: only a None key word equals this constant and no real key has it",
    "dead": "same: the row pointer from this call is not read on this path",
}
SURVIVORS = {}
for address in (0x273CE3E, 0x273CE42, 0x273CE45, 0x273CE68, 0x273CE6C, 0x273CE70, 0x273CE74, 0x273CE80, 0x2743D45, 0x2743D49, 0x2743D4C, 0x2743D6F, 0x2743D73, 0x2743D77, 0x2743D7B, 0x2743D87):
    SURVIVORS[address] = "stale"
for address in (0x273C982, 0x2743882):
    SURVIVORS[address] = "vec"
for address in (0x273C9E0, 0x27438E0, 0x23577E5):
    SURVIVORS[address] = "handle"
for address in (0x273CCF7, 0x2743BF7, 0x2357895, 0x23578BB):
    SURVIVORS[address] = "dropped"
for address in (0x27C5A71, 0x379C6A1):
    SURVIVORS[address] = "old"
for address in (0x27C5A82, 0x379C6A9):
    SURVIVORS[address] = "found"
for address in (0x27C5999, 0x379C5D5):
    SURVIVORS[address] = "hasher"
for address in (0x27C59D0, 0x379C60A):
    SURVIVORS[address] = "shuffle"
for address in (0x27C5A14, 0x379C64E):
    SURVIVORS[address] = "second"
for address in (0x27C5AF5, 0x379C718):
    SURVIVORS[address] = "fallible"
SURVIVORS[0x2357841] = "niche"
SURVIVORS[0x235730E] = "dead"


def survivor_reason(va, kind):
    return SURVIVOR_REASONS[SURVIVORS[va]] if va in SURVIVORS else "unclassified"



def run_mutants(image, table, seen, cases, vectors):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    chosen = cases + vectors
    if first_failure(control, chosen) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    for name in table:
        for va, kind, patch in edits_for(image, table[name], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], THIRD_CAP))
            results.append((va, kind, "killed", hit.name) if hit is not None else (va, kind, "survived", survivor_reason(va, kind)))
    return results


REFERENCE = (
    ("map type", "BTreeMap<LocalAssetIndex, f64> keyed by local index", "hash map at dex row +0x78 and +0xa8, 16-byte slots, key is the whole asset id", "a rate rows in key order"),
    ("all or nothing", "one row inserted per call, an error stops at that row", "pass 1 reads every row and writes nothing; pass 2 writes all rows, so a refused row leaves every map unchanged", "a rate later value refused"),
    ("input form", "f64 and encoded id", "B-tree of String name to String value; value text is parsed as a decimal, then cut to f64", "a rate two rows"),
    ("refusal", "RegistryError enum values", "tag 0xe0 with an owned text; 0x143 for a name or value over 100 bytes; decimal and lookup errors pass through unchanged", "a mult later value refused"),
    ("rounding at the bound", "bound tested on the f64 argument", "the bound also reads the rounded f64, so a decimal just above it can pass", "a mult text b'10.00000000000000001'"),
    ("dex index", "asset_info_mut returns an error", "id/10000 past the dex count panics in pass 2 after earlier rows were written", "a rate far dex panics in pass 2"),
    ("override upper bound", "mainnet 5e12 and testnet 1e12 upper bound in validate_visible_bounds", "no such bound on this path: value below 0x0ccc... and at least 600000000", "a override 922337203685477579"),
    ("clamp action", "AssetValue with an asset below the index bound", "the action holds one text and no asset; the value goes to dex row 0", "a clamp b'0.5'"),
    ("default_impact_usd vote", "DefaultImpactUsd(u64), no bound", "x below 0x0ccc... else 0x13f; the compare x>>10 > 0x59682e means x >= 6000000000, else tag 0x3c", "a default 6000000000"),
)


def text_rows(image):
    rows = []
    for name, address, size in (("multiplier refused", 0x3EFBB4, 26), ("interest rate refused", 0x3EFBCE, 29)):
        rows.append(("%#x" % address, bytes(image.blob[address:address + size]).decode("ascii"), name))
    start = bytes(image.blob).find(b"asset_to_premiumsoverride_impact_usd")
    end = bytes(image.blob).find(FUNDING_STRUCT, start)
    if start < 0 or end - start > 200:
        raise EvidenceError("funding field names")
    rows.append(("%#x" % start, bytes(image.blob[start:end + len(FUNDING_STRUCT)]).decode("ascii"), "serde field names, then the struct text"))
    return rows


def text_at(image, arm):
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        return ""
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def tag_rows(image):
    rows = []
    for tag, want in sorted(TAG_TEXTS.items()):
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        text = text_at(image, arm)
        if text != want:
            raise EvidenceError("tag text %#x: %r" % (tag, text))
        rows.append(("%#x" % tag, text))
    return rows


def constant_rows(image):
    rows = []
    for address, meaning in ((0x20A8A8, "multiplier upper bound"), (0x20A2F8, "interest rate absolute bound"), (0x202ED0, "sign clear mask low word")):
        rows.append(("%#x" % address, bytes(image.blob[address:address + 8]).hex(), repr(struct.unpack_from("<d", image.blob, address)[0]), meaning))
    return rows


def copy_rows(image):
    rows = []
    for copy in COPIES:
        arms = [copy.table + struct.unpack_from("<i", image.blob, copy.table + 4 * (word - 0x12))[0] for word in (WORD_OVERRIDE, WORD_CLAMP, WORD_DEFAULT)]
        rows.append((copy.name, "%#x" % copy.dispatch, "%#x" % copy.hip3, "%#x" % copy.setters["mult"], "%#x" % copy.setters["rate"], "%#x" % copy.base, "%#x" % copy.dexes) + tuple("%#x" % arm for arm in arms))
    return rows


def caller_rows(image):
    base, text = image.text_bytes()
    wanted = {copy.setters[kind]: "%s %s" % (copy.name, kind) for copy in COPIES for kind in copy.setters}
    wanted[MAP_F64] = "map f64 a"
    wanted[MAP_U64] = "map u64 a"
    rows = []
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text):
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in wanted:
                try:
                    rows.append((wanted[target], "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
                except EvidenceError:
                    pass
        at = text.find(b"\xe8", at + 1)
    return rows


def subject_rows(image):
    table = {}
    for name, target in FUNCTIONS.items():
        table[name] = rows_of(image, target)
    for name, start, end in ARM_WINDOWS:
        table[name] = decode_range(image, start, end)
    return table


def analyse(image, mutate=True, vectors=VECTORS):
    Parsed.harness = Harness(image)
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = subject_rows(image)
    for name in table:
        for row in table[name]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {name: [row.va for row in table[name] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for name in table}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), texts=text_rows(image), tags=tag_rows(image), callers=caller_rows(image), copies=copy_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def outcome_row(case, got):
    digest = hashlib.sha256(repr(sorted(got["state"].items(), key=str)).encode()).hexdigest()[:16]
    return (case.name, COPIES[case.copy].name, " ; ".join(" ".join(("%#x" % part if isinstance(part, int) else part.decode("ascii") if isinstance(part, bytes) else str(part)) for part in result) for result in got["results"]), digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "bytes", "value", "meaning"), result["constants"])
    tsv("error-texts.tsv", ("address", "text", "when"), result["texts"])
    tsv("tag-texts.tsv", ("tag", "display text"), result["tags"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("callers.tsv", ("callee", "call", "function"), result["callers"])
    tsv("copies.tsv", ("copy", "vote dispatcher", "hip3 dispatcher", "multiplier", "interest rate", "meta base", "dex table", "word 20 arm", "word 21 arm", "word 22 arm"), result["copies"])
    tsv("outcomes.tsv", ("case", "copy", "result", "state digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "subjects": {name: {"address": "%#x" % result["table"][name][0].va, "bytes": sum(row.size for row in result["table"][name]), "instructions": len(result["table"][name]),
                            "unreached_rows": ["%#x" % va for va in result["unreached"][name]]} for name in result["table"]},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
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

