#!/usr/bin/env python3
"""Pin the node #94 UsdClassTransfer path: amount text, gates, the shared class move, its notional word and the event.

Real rows run from the signed handler, the system handler, the apply wrapper and the shared move in all three copies, with the
real text split, trim, address and decimal code. A separately written rule list predicts every result, callee argument and written
word, and every reached conditional row, immediate and field offset of the subject code is edited. No objdump or readelf output is
parsed and the binary is never executed. Standard library only.

    python3 tools/usd_class_transfer.py --out <dir>
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
        if two == 0x13 and not opsize and not repne:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
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
TEXT_TABLE = 0x59A8D0
TAG_VAULT, TAG_WITHDRAW, TAG_MARKET, TAG_DECIMALS, TAG_AMOUNT, TAG_ADDRESS, TAG_SUB, TAG_BALANCE, TAG_SPOT, TAG_FEATURE, TAG_LENGTH, TAG_NUMBER, TAG_PARSE = 0x15, 0x33, 0x141, 0xA8, 0x131, 0xB6, 0xDC, 0xF7, 0xF9, 0x16F, 0x143, 0x13F, 0xAC
TAG_TEXTS = {TAG_VAULT: "Vault may not perform this action.", TAG_WITHDRAW: "Insufficient balance for withdrawal.", TAG_MARKET: "Invalid perp DEX", TAG_DECIMALS: "Invalid number of decimals", TAG_AMOUNT: "Invalid UsdClassTransfer amount.",
             TAG_ADDRESS: "Failed to parse user address", TAG_BALANCE: "Insufficient balance for token transfer", TAG_SPOT: "Spot disabled", TAG_FEATURE: "Action disabled when unified account is active", TAG_LENGTH: "Invalid input length", TAG_NUMBER: "Invalid input number", TAG_PARSE: "Invalid decimal number"}
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_MARGIN = 0x5773178
SLOT_WITHDRAWABLE = 0x5774660
SLOT_BALANCES = 0x5773170
SLOT_HOLD = 0x5774730
SLOT_DEBIT = 0x57749D8
SLOT_PRICE = 0x5774548
SLOT_RECORD = 0x5773190
SLOT_SINK_A = 0x5774738
SLOT_SINK_C = 0x5776AD0
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048, 0x576EB38)
MARK_BASE = 0x7700000000
DROP_STATUS = 0x3379490
ROWS = 0x36F57F0
LEDGER = 0x371D120
CREDIT = 0x36FF4F0
STAMP = 0x3987CB0
TEXT_ERROR = 0x14B5530
HEX_ERROR = 0x14B5EA0
ERROR_DROP_MARK = MARK_BASE + 1
PARSER = 0x3980A60
COLLECT = 0x3BAFA30
TRIM = 0x337E6C0
GATE_C = 0x46E93E0
PARSE_DECIMAL = 0x3799510
RESCALE = 0x3750350
CAP = 0x0CCCCCCCCCCCCCCC
TOP = MASK[8]
HIGH = 1 << 63
GATE_LIMIT = 0x028F5C28F5C28F5C
CLAMP = 0x0147AE147AE147AE
WHOLE_CAP = (1 << 63) - 2
TEXT_CAP = 100
SEPARATOR = b"subaccount:"
EVENT_WORD = 0x800000000000000D
DEX_STRIDE = 0x2F0
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
OUT = HEAP_BASE + 0x40
ACTION = HEAP_BASE + 0xC0
USER = HEAP_BASE + 0x160
SPOT_ROW = HEAP_BASE + 0x180
MARGIN_ROW = HEAP_BASE + 0x1C0
TOTAL_ROW = HEAP_BASE + 0x200
USER_ROW = HEAP_BASE + 0x240
ERROR_OBJECT = HEAP_BASE + 0x2A0
ERROR_TABLE = HEAP_BASE + 0x2B0
DEXES = STATE + STATE_SIZE
DEX_ROOM = 3
BUMP = DEXES + DEX_ROOM * DEX_STRIDE + 0x40
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))


AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


VAULT_TREE = Layout(0x798, 20, 0, 0xB0, 0x790, 0x874, 0x876, 0x878)
BALANCE_TREE = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
PRICE_TREE = Layout(8, 8, 0x60, 8, 0, 0xB8, 0xBA, 0xC0)


class Copy:
    def __init__(self, name, handler, system, apply, core, auth, user_row, total_row, drop, sink, sink_at, shift):
        self.name, self.handler, self.system, self.apply, self.core, self.auth, self.user_row, self.total_row, self.drop, self.sink, self.sink_at, self.shift = name, handler, system, apply, core, auth, user_row, total_row, drop, sink, sink_at, shift


COPIES = (Copy("a", 0x1E60850, 0x1E64530, 0x2717CF0, 0x270F6F0, 0x2714F80, 0x2755400, 0x1F849B0, 0x277EBA0, SLOT_SINK_A, 0x8F3, 0),
          Copy("b", 0x46BB840, 0x4C03850, 0x4D0FAC0, 0x46E89A0, 0x4D0A330, 0x46F2FE0, 0x47D7CA0, 0x472F840, SLOT_SINK_A, 0x8F3, 0),
          Copy("c", 0x46BB610, 0x4C03760, 0x4D0FCA0, 0x46E8290, 0x4D0A180, 0x46F2E60, 0x47D7CA0, 0x472F840, SLOT_SINK_C, 0x5B8, 0xA80))
FUNCTIONS = dict(handler_a=COPIES[0].handler, system_a=COPIES[0].system, apply_a=COPIES[0].apply, core_a=COPIES[0].core, parser=PARSER, collect=COLLECT, core_b=COPIES[1].core, core_c=COPIES[2].core, gate_c=GATE_C)
COPY_ONLY = dict(handler_b=COPIES[1].handler, system_b=COPIES[1].system, apply_b=COPIES[1].apply, handler_c=COPIES[2].handler, system_c=COPIES[2].system, apply_c=COPIES[2].apply)
USER_A = bytes(range(1, 21))
USER_B = bytes(range(0x21, 0x35))
USER_C = bytes(range(0x41, 0x55))
HEX_B = USER_B.hex().encode()
SUB_TEXT = b"0x" + HEX_B
STAMP_BYTES = bytes(range(0xA0, 0xC0))
REFUSAL_BYTES = bytes(0x80 | (index * 3 + 5) & 0xFF for index in range(0x5E))
SHORT_ERRORS = (TAG_LENGTH, TAG_FEATURE, TAG_NUMBER)
TIME_WORDS = (0x1122334455667788, 0x99AABBCC)


def signed(value):
    return value - (1 << 64) if value >> 63 else value


class Case:
    DEFAULTS = dict(entry="core", copy=0, dexes=1, index=0, mode=0, amount=0, user=USER_A, token=0, vault=None, vault_rows=(), value=0, used=0, available=(0, 0), balances=(), scale=to_bits(1.0), prices=(), fallback=0x5151, hold_ok=1,
                    total=0, tally=0, disabled=0, kind=0, flags=(0, 0), text=b"", to_perp=0, stamped=0, refuse=0, height=0, stale=0)

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
        return 0x1300000 < target < 0x5660000 and target not in HOOKED


HOOKED = {DROP_STATUS, ROWS, LEDGER, CREDIT, STAMP, RESUME, TEXT_ERROR, HEX_ERROR} | {copy.auth for copy in COPIES} | {copy.user_row for copy in COPIES} | {copy.total_row for copy in COPIES} | {copy.drop for copy in COPIES}


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_MARGIN, self.on_margin), (SLOT_WITHDRAWABLE, self.on_withdrawable), (SLOT_BALANCES, self.on_balances), (SLOT_HOLD, self.on_hold), (SLOT_DEBIT, self.on_debit), (SLOT_PRICE, self.on_price), (SLOT_RECORD, self.on_record),
                 (SLOT_SINK_A, self.on_sink), (SLOT_SINK_C, self.on_sink))
        if Harness.statics is None:
            table = dict(image.relative())
            for slot, _ in hooks:
                table[slot] = MARK_BASE + slot
            for slot in PANIC_SLOTS:
                table[slot] = MARK_BASE + slot
            Harness.statics = table
        machine.memory.statics = dict(Harness.statics)
        for slot, hook in hooks:
            machine.slots[MARK_BASE + slot] = hook
        for slot in PANIC_SLOTS:
            machine.slots[MARK_BASE + slot] = self.on_panic
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic, DROP_STATUS: self.on_status_drop, ROWS: self.on_rows, LEDGER: self.on_ledger, CREDIT: self.on_credit, STAMP: self.on_stamp, TEXT_ERROR: self.on_text_error, HEX_ERROR: self.on_hex_error}
        machine.slots[ERROR_DROP_MARK] = self.on_error_drop
        for copy in COPIES:
            machine.calls[copy.auth] = self.on_auth
            machine.calls[copy.user_row] = self.on_user_row
            machine.calls[copy.total_row] = self.on_total_row
            machine.calls[copy.drop] = self.on_drop
        self.case = None
        self.copy = COPIES[0]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.reads = 0

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

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

    def dex(self):
        return DEXES + self.case.index * DEX_STRIDE

    def user_key(self, at):
        return self.machine.memory.bytes_at(at, 20)

    def on_status_drop(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == TAG_MARKET, "dropped status")

    def on_drop(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == TAG_WITHDRAW, "dropped withdraw status")
        self.events.append(("dropped",))

    def on_rows(self, machine):
        self.expect(machine.regs[RDI] == self.dex() + 0xF8, "margin rows of the dex")
        self.events.append(("margin row", self.user_key(machine.regs[RSI])))
        machine.regs[RAX] = MARGIN_ROW

    def on_margin(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == MARGIN_ROW and regs[RDX] == 0 and regs[RCX] & MASK[4] == 2 and regs[R9] == self.dex() + 0x60 and memory.read(regs[RSP], 8) == self.dex(), "margin arguments")
        memory.put_bytes(regs[RDI], struct.pack("<2Q", self.case.value, self.case.used))

    def on_withdrawable(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex(), "withdrawable dex")
        self.events.append(("withdrawable", self.user_key(regs[RSI])))
        regs[RAX] = self.case.available[self.reads]
        self.reads += 1

    def on_balances(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x80, "spot rows")
        self.events.append(("spot row", self.user_key(regs[RSI])))
        regs[RAX] = SPOT_ROW

    def on_hold(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x80, "hold state")
        self.events.append(("hold", self.user_key(regs[RSI]), regs[RDX], regs[RCX]))
        regs[RAX] = 0xABCDEF00 | self.case.hold_ok

    def on_ledger(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x80, "ledger state")
        self.events.append(("ledger", self.user_key(regs[RSI]), regs[RDX], regs[RCX] & MASK[4], regs[R8], regs[R9]))

    def on_credit(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex(), "credit dex")
        self.events.append(("credit", self.user_key(regs[RSI]), regs[RDX]))

    def on_debit(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex(), "debit dex")
        self.events.append(("debit", self.user_key(regs[RSI]), regs[RDX]))

    def on_price(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x90, "price map")
        self.events.append(("price", regs[RSI]))
        regs[RAX] = self.case.fallback

    def on_record(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] & MASK[4] == 0, "recorder first argument")
        self.events.append(("recorded", regs[RSI]))

    def on_total_row(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x740 + self.copy.shift, "total rows")
        self.events.append(("total row", self.user_key(regs[RSI])))
        regs[RAX] = TOTAL_ROW

    def on_user_row(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE, "user row state")
        self.events.append(("user row", self.user_key(regs[RSI])))
        regs[RAX] = USER_ROW

    def on_auth(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE and regs[RDX] == USER, "auth arguments")
        sub = self.user_key(regs[RCX])
        self.events.append(("auth", sub))
        if self.case.refuse:
            memory.put_bytes(regs[RDI], struct.pack("<H", TAG_SUB) + REFUSAL_BYTES)
        else:
            memory.put_bytes(regs[RDI], struct.pack("<H", OK) + sub + b"\x5a" * 0x10)
        regs[RAX] = regs[RDI]

    def on_stamp(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] & 0xFF == 3 and regs[RCX] == 0x4444 and regs[RDX] == 0x5555 and regs[R8] & 0xFF == 0, "stamp arguments")
        memory.put_bytes(regs[RDI], STAMP_BYTES)
        regs[RAX] = regs[RDI]
        self.events.append(("stamp",))

    def on_text_error(self, machine):
        cap, at, size = struct.unpack("<3Q", machine.memory.bytes_at(machine.regs[RDI], 24))
        self.expect(self.live.pop(at, None) == cap and size == cap, "error text block")
        self.events.append(("address text", machine.memory.bytes_at(at, size)))
        machine.regs[RAX] = ERROR_OBJECT

    def on_hex_error(self, machine):
        self.events.append(("address hex",))
        machine.regs[RAX] = ERROR_OBJECT

    def on_error_drop(self, machine):
        self.expect(machine.regs[RDI] == ERROR_OBJECT, "error object")
        self.events.append(("address error dropped",))

    def on_sink(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE + self.copy.sink_at, "event sink state")
        cap, at, size = struct.unpack("<3Q", memory.bytes_at(regs[RSI], 24))
        self.expect(cap == 1 and size == 1 and self.live.pop(at, None) == 20, "event user vector")
        word, bits, flag = memory.read(regs[R8], 8), memory.read(regs[R8] + 8, 8), memory.read(regs[R8] + 16, 1)
        self.events.append(("event", memory.bytes_at(at, 20), memory.bytes_at(regs[RDX], 12), memory.bytes_at(regs[RCX], 32), word, bits, flag))

    def tree_bytes(self, layout, items, height):
        """Real shaped nodes; extra height is added as empty inner nodes over the top tree."""
        memory = self.machine.memory

        def node(rows, size):
            at = self.bump(size)
            memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for slot in range(11):
                memory.put_bytes(at + layout.key_at + layout.key_size * slot, self.spare(layout))
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

    def spare(self, layout):
        """Bytes for unused key slots; with `stale` they repeat the searched key, as old rows do after a removal."""
        if not self.case.stale:
            return b"\xfe" * layout.key_size
        return self.case.user if layout is VAULT_TREE else struct.pack("<Q", self.case.token)

    def put_tree(self, at, layout, items, height=0):
        root, level = self.tree_bytes(layout, items, height) if items else (0, 0)
        self.machine.memory.put_bytes(at, struct.pack("<2Q", root, level))

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.copy = COPIES[case.copy]
        shift = self.copy.shift
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.reads = 0
        memory.put_bytes(STATE + 0x5C0 + shift, struct.pack("<3Q", DEXES, case.dexes, 0))
        dex = DEXES + case.index * DEX_STRIDE
        for index in range(DEX_ROOM):
            memory.write(DEXES + index * DEX_STRIDE + 0x50, 8, 0xD00D + index)
            memory.write(DEXES + index * DEX_STRIDE + 0x238, 8, 0xE00E + index)
            memory.write(DEXES + index * DEX_STRIDE + 0x2A0, 8, to_bits(7.0))
        memory.write(dex + 0x50, 8, case.token)
        memory.write(dex + 0x238, 8, case.total)
        memory.write(dex + 0x2A0, 8, case.scale)
        vault = sorted(set(case.vault_rows) | ({case.user} if case.vault is not None else set()))
        items = [(key, (case.vault if key == case.user else 0) << (0xAF * 8) | 0x5C << (0xAE * 8)) for key in vault]
        self.put_tree(STATE + 0x8D0 + shift, VAULT_TREE, items, case.height)
        items = [(struct.pack("<Q", key), low | high << 64 | 0x7777 << 128) for key, low, high in sorted(case.balances)]
        self.put_tree(SPOT_ROW + 0x10, BALANCE_TREE, items, case.height)
        items = [(struct.pack("<Q", key), value) for key, value in sorted(case.prices)]
        self.put_tree(STATE + 0x250, PRICE_TREE, items, case.height)
        memory.write(TOTAL_ROW + 0x18, 8, case.tally)
        memory.write(TOTAL_ROW + 0x10, 8, 0x1010101)
        memory.write(TOTAL_ROW + 0x20, 8, 0x2020202)
        memory.write(USER_ROW + 0x3C, 1, case.kind)
        memory.write(STATE + 0x5B0, 1, case.flags[0])
        memory.write(STATE + 0x5B1, 1, case.flags[1])
        memory.write(STATE + 0x3AC8 + shift, 1, case.disabled)
        memory.write(STATE, 4, 1 if case.stamped else 0)
        memory.write(STATE + 8, 8, 0x4444)
        memory.write(STATE + 0x28, 8, 0x5555)
        memory.put_bytes(STATE + 0x60, struct.pack("<QI", *TIME_WORDS))
        memory.write(STATE + 0x8F2 + shift, 1, 3)
        memory.put_bytes(USER, case.user)
        memory.write(ERROR_OBJECT, 8, ERROR_TABLE)
        memory.write(ERROR_TABLE, 8, ERROR_DROP_MARK)
        self.fixed = set(self.live)

    def enter(self):
        case, copy, machine, memory = self.case, self.copy, self.machine, self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x70)
        if case.entry == "core":
            machine.run(copy.core, {RDI: OUT, RSI: STATE, RDX: case.index, RCX: USER, R8: case.mode, R9: case.amount})
            return self.status(OUT)
        if case.entry == "apply":
            machine.run(copy.apply, {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.amount, R8: case.to_perp | 0x7700})
            return self.status(OUT)
        if case.entry == "system":
            memory.write(ACTION, 8, case.amount)
            memory.write(ACTION + 8, 1, case.to_perp)
            machine.run(copy.system, {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
            return self.outer()
        text = self.bump(max(len(case.text), 1))
        memory.put_bytes(text, case.text)
        self.text_block = text
        memory.put_bytes(ACTION, b"\xd1" * 0x48)
        memory.write(ACTION + 8, 8, text)
        memory.write(ACTION + 0x10, 8, len(case.text))
        memory.write(ACTION + 0x40, 1, case.to_perp)
        self.fixed.add(text)
        machine.run(copy.handler, {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
        return self.outer()

    def status(self, at):
        tag = self.machine.memory.read(at, 2)
        return ("ok",) if tag == OK else ("error", tag)

    def outer(self):
        memory = self.machine.memory
        code = memory.read(OUT, 1)
        if code == 0x0D:
            return ("ok",)
        self.expect(code == 0x0E, "outer code")
        tag = memory.read(OUT + 8, 2)
        if tag == TAG_NUMBER:
            return ("error", tag, memory.read(OUT + 0x10, 8))
        return ("error", tag)

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        before = bytes(memory.heap[:FILL_END])
        try:
            result = self.enter()
        except Panicked:
            result = ("panic",)
        now = bytearray(memory.heap[:FILL_END])
        dex = self.dex()
        state = dict(total=memory.read(dex + 0x238, 8), tally=memory.read(TOTAL_ROW + 0x18, 8), user=memory.bytes_at(USER, 20))
        for at, size in ((OUT, 0x70), (ACTION, 0x48), (USER, 20), (dex + 0x238, 8), (TOTAL_ROW + 0x18, 8)):
            now[at - HEAP_BASE:at - HEAP_BASE + size] = before[at - HEAP_BASE:at - HEAP_BASE + size]
        rest = bytes(now) == before
        tree = bytes(memory.heap[BUMP - HEAP_BASE:self.fixed_end()])
        return dict(result=result, events=list(self.events), state=state, rest=rest, leaked=sorted(set(self.live) - self.fixed) if result != ("panic",) else [], tree=hashlib.sha256(tree).hexdigest(), out=memory.bytes_at(OUT, 0x70))

    def fixed_end(self):
        return max([at + size for at, size in self.live.items() if at in self.fixed] + [BUMP]) - HEAP_BASE


def spec_scaled(amount, scale_bits):
    """Notional word of a positive amount: the clamped f64 product. The 100 times gate already keeps amount <= GATE_LIMIT."""
    product = float(amount) * to_float(scale_bits)
    if product != product or abs(product) == float("inf"):
        value = 0
    else:
        value = int(max(-9223372036854775808.0, min(9223372036854775808.0, product)))
        if value >= HIGH:
            value = HIGH - 1
    if value == -HIGH:
        raise Panicked("abs overflow")
    if abs(value) > CLAMP:
        value = max(-CLAMP, min(CLAMP, value))
    return max(value, 0)


def sat_add(left, right, events, location):
    full = left + right
    if -HIGH <= full < HIGH:
        return full
    events.append(("recorded", location))
    return HIGH - 1 if full > 0 else -HIGH


LOC_TOTAL_ADD = 0x56F1C50
LOC_TOTAL_SUB = 0x56F1CF8
LOC_TALLY = 0x5715EF8
LOC_MARGIN = 0x56F3A78


def spec_core(case, user, amount, mode, want):
    """Returns the result; fills the event list and the two written words of `want`."""
    events = want["events"]
    if case.index >= case.dexes:
        raise Panicked("dex index")
    if case.vault is not None and user == case.user and (case.token != 0 or case.vault == 0):
        return ("error", TAG_VAULT)
    if mode < 2:
        if amount >> 63:
            raise Panicked("negative amount")
        movable = amount
    else:
        events.append(("margin row", user))
        if case.used >> 63:
            raise Panicked("negative used margin")
        full = signed(case.value) - case.used
        if -HIGH <= full < HIGH:
            movable = full & TOP
        else:
            events.append(("recorded", LOC_MARGIN))
            movable = (HIGH - 1 if full > 0 else HIGH) & TOP
    move = signed(movable)
    base = max(move, 0)
    wei = base * 100
    if wei >> 64:
        return ("error", TAG_BALANCE)
    if mode == 1:
        events.append(("withdrawable", user))
        if amount >> 63:
            raise Panicked("negative amount")
        if case.available[0] < amount:
            return ("error", TAG_WITHDRAW)
    elif mode != 2:
        events.append(("spot row", user))
        rows = {key: (low, high) for key, low, high in case.balances}
        total, held = rows.get(case.token, (0, 0))
        if wei + held >> 64 or wei + held > total:
            return ("error", TAG_BALANCE)
    if move <= 0:
        return ("ok",)
    scaled = spec_scaled(base, case.scale)
    price = 0
    if case.token:
        prices = dict(case.prices)
        if case.token in prices:
            price = prices[case.token]
        else:
            events.append(("price", case.token))
            price = case.fallback
    total, tally = signed(case.total), signed(case.tally)
    if mode == 1 or mode == 2 or (case.copy == 2 and mode):
        if mode == 1:
            events.append(("withdrawable", user))
            if signed(move & TOP) > signed(case.available[1]):
                events.append(("dropped",))
                return ("ok",)
        events.append(("debit", user, base))
        want["total"] = sat_add(total, -base, events, LOC_TOTAL_SUB) & TOP
        events.append(("ledger", user, case.token, 0, wei, price))
        events.append(("total row", user))
        want["tally"] = sat_add(tally, -(scaled // 10000), events, LOC_TALLY) & TOP
        return ("ok",)
    events.append(("hold", user, case.token, wei))
    if not case.hold_ok:
        return ("ok",)
    events.append(("ledger", user, case.token, 1, wei, price))
    events.append(("credit", user, base))
    want["total"] = sat_add(total, base, events, LOC_TOTAL_ADD) & TOP
    events.append(("total row", user))
    want["tally"] = sat_add(tally, scaled // 10000, events, LOC_TALLY) & TOP
    return ("ok",)


def amount_bits(amount):
    """The u64 to f64 lanes of the wrapper, then the division by 1e6."""
    return to_bits((float(amount & 0xFFFFFFFF) + float(amount >> 32) * 4294967296.0) / 1e6)


def spec_apply(case, user, amount, want):
    if case.disabled:
        return ("error", TAG_SPOT)
    got = spec_core(case, user, amount, case.to_perp & 1 ^ 1, want)
    if got != ("ok",):
        return got
    if case.stamped:
        want["events"].append(("stamp",))
    stamp = STAMP_BYTES if case.stamped else bytes(32)
    want["events"].append(("event", user, struct.pack("<QI", *TIME_WORDS), stamp, EVENT_WORD, amount_bits(amount), case.to_perp))
    return ("ok",)


def spec_gate(case, user, want):
    want["events"].append(("user row", user))
    if case.kind > 3 and not case.flags[0] or case.kind == 3 and not case.flags[1]:
        return ("error", TAG_FEATURE)
    return None


def nearest_even(mantissa, scale):
    whole, rest = divmod(mantissa, 10 ** scale)
    twice = 2 * rest
    if twice > 10 ** scale or (twice == 10 ** scale and whole & 1):
        whole += 1
    return whole


def spec_decimal(text):
    """Amount text to raw 1e6 units for plain decimal text; rounded half even, never refused for digits past the sixth."""
    if text in LITERAL_TEXTS:
        return LITERAL_TEXTS[text]
    shape = re.fullmatch(rb"([+-]?)([0-9]*)(?:\.([0-9]*))?", text)
    if shape is None or not (shape[2] or shape[3]):
        raise EvidenceError("text outside the rule list: %r" % text)
    fraction = shape[3] or b""
    mantissa = int((shape[2] + fraction) or b"0")
    if mantissa >> 96 or len(fraction) > 28:
        raise EvidenceError("text outside the rule list: %r" % text)
    if mantissa == 0:
        return ("ok", 0)
    product, kept = mantissa * 10 ** 6, len(fraction)
    while product >> 96:
        if kept == 0:
            return ("error", TAG_DECIMALS)
        product //= 10
        kept -= 1
    whole = nearest_even(product, kept)
    if shape[1] == b"-" and whole != 0 or whole > WHOLE_CAP:
        return ("error", TAG_DECIMALS)
    return ("ok", whole)


BAD_TEXTS = (b"", b"x", b"abc", b"_1", b" 1", b"1 ", b"\t1", b"--1", b"+-1", b"+", b"-", b".", b"1.2.3", b"0x10", b"NaN", b"inf", b"\xd9\xa3", b"1" * 30, b"9" * 29, b"1e30", b"12e", b"e5", b".e2", b"1,5", b"$1", b"7\xc3\xa9", b"7\x1f", b"7\xe2\x80\x8b", b"7 ", b"7 subaccoun:" + SUB_TEXT, b"7 subaccoun")
LITERAL_TEXTS = {text: ("error", TAG_PARSE) for text in BAD_TEXTS}
LITERAL_TEXTS.update({b"1e3": ("ok", 10 ** 9), b"1E3": ("ok", 10 ** 9), b"1e-3": ("ok", 1000), b"1_000": ("ok", 10 ** 9), b"1_": ("ok", 10 ** 6), b"1.e2": ("ok", 10 ** 8), b"0." + b"1" * 29: ("ok", 111111), b"0." + b"5" * 40: ("ok", 555556), b"1." + b"1" * 30: ("ok", 1111111),
                      b"-1." + b"5" * 30: ("error", TAG_DECIMALS), b"1e-30": ("ok", 0), b"0.00000050000000000000000000001": ("ok", 0), b"0.00000049999999999999999999999": ("ok", 0), b"0.000000500000000000000000000000000001": ("ok", 0), b"79228162514264337593543950336": ("error", TAG_DECIMALS)})
WHITE = frozenset((0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000) + tuple(range(0x2000, 0x200B)))
TOO_SHORT = b"string too short to be Address"
BAD_PAD = b"trailing characters of Address string must be '0'"


def spec_address(text, events):
    """Optional lower case 0x; at least 40 bytes; extra leading bytes must be the character 0; the last 40 are hex."""
    body = text[2:] if text[:2] == b"0x" else text
    if len(body) < 40:
        events.extend((("address text", TOO_SHORT), ("address error dropped",)))
        return None
    pad = len(body) - 40
    if body[:pad] != b"0" * pad:
        events.extend((("address text", BAD_PAD), ("address error dropped",)))
        return None
    try:
        return bytes.fromhex(body[pad:].decode("ascii"))
    except ValueError:
        events.extend((("address hex",), ("address error dropped",)))
        return None


def rstrip_text(text):
    chars = text.decode("utf-8")
    end = len(chars)
    while end and ord(chars[end - 1]) in WHITE:
        end -= 1
    return chars[:end].encode("utf-8")


def spec_user(case, want):
    text = case.text
    if len(text) > TEXT_CAP:
        return ("error", TAG_LENGTH)
    if not text:
        return ("error", TAG_AMOUNT)
    left, found, right = text.partition(SEPARATOR)
    address = None
    if found:
        left = rstrip_text(left)
        address = spec_address(right, want["events"])
        if address is None:
            return ("error", TAG_ADDRESS)
    read = spec_decimal(left)
    if read[0] == "error":
        return read
    user = case.user
    if found:
        want["events"].append(("auth", address))
        if case.refuse:
            return ("error", TAG_SUB)
        user = address
        want["state_user"] = user
    refused = spec_gate(case, user, want)
    if refused:
        return refused
    return spec_apply(case, user, read[1], want)


def spec_for(case):
    want = dict(events=[], total=case.total, tally=case.tally, state_user=case.user)
    try:
        if case.entry == "core":
            result = spec_core(case, case.user, case.amount, case.mode, want)
        elif case.entry == "apply":
            result = spec_apply(case, case.user, case.amount, want)
        elif case.entry == "system":
            if case.amount >= CAP:
                result = ("error", TAG_NUMBER, case.amount)
            else:
                result = spec_gate(case, case.user, want) or spec_apply(case, case.user, case.amount, want)
        else:
            result = spec_user(case, want)
    except Panicked:
        result = ("panic",)
    want["result"] = result
    return want


def same(case, got, want):
    if got["result"] != want["result"] or got["events"] != want["events"]:
        return False
    if got["result"] == ("panic",):
        return got["rest"]
    if got["result"][0] == "error" and got["result"][1] not in SHORT_ERRORS and case.entry != "core" and not (case.entry == "apply" and case.disabled):
        block = got["out"][:0x60] if case.entry == "apply" else got["out"][8:0x68]
        if b"\x77" * 4 in block:
            return False
        if got["result"][1] == TAG_SUB and block != struct.pack("<H", TAG_SUB) + REFUSAL_BYTES:
            return False
    state = got["state"]
    return state["total"] == want["total"] and state["tally"] == want["tally"] and state["user"] == want["state_user"] and got["rest"] and not got["leaked"]


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %r %r %r %r %s want %r %r" % (case.name, got["result"], got["events"], got["state"], got["leaked"], got["rest"], want["result"], want))
        outcomes.append(got)
    return outcomes


FULL = 10 ** 12
GOOD_BALANCE = ((0, 10 ** 16, 0),)


def token_rows(token, total, held=0):
    return tuple(sorted({(token, total, held), (token ^ 1, 3, 2), (token + 2, 5, 4)}))


def named_core(copy):
    tag = "copy %s " % COPIES[copy].name
    fields = dict(copy=copy)
    out = []

    def add(name, **more):
        out.append(Case(tag + name, **dict(fields, **more)))

    # Market bound.
    add("dex index equal to the count panics", index=1, dexes=1, amount=5)
    add("dex index two of three", index=2, dexes=3, amount=5, balances=GOOD_BALANCE)
    add("dex index one of two", index=1, dexes=2, amount=5, balances=GOOD_BALANCE)
    # Vault gate.
    add("vault row flag zero on token 0", vault=0, amount=5, balances=GOOD_BALANCE)
    add("vault row flag one on token 0", vault=1, amount=5, balances=GOOD_BALANCE)
    add("vault row flag two on token 0", vault=2, amount=5, balances=GOOD_BALANCE)
    add("vault row flag one on token 7", vault=1, token=7, amount=5, balances=token_rows(7, FULL))
    add("no row among other vaults", vault_rows=(USER_B, USER_C), amount=5, balances=GOOD_BALANCE)
    add("row among other vaults", vault=1, vault_rows=(USER_B, USER_C), amount=5, balances=GOOD_BALANCE)
    add("row after smaller vaults", user=USER_C, vault=1, vault_rows=(USER_A, USER_B), amount=5, balances=GOOD_BALANCE)
    add("row after larger key only", user=USER_A, vault=0, vault_rows=(USER_B,), amount=5, balances=GOOD_BALANCE)
    add("deep vault tree", user=USER_C, vault=1, vault_rows=(USER_A, USER_B), height=2, amount=5, balances=GOOD_BALANCE)
    add("deep vault tree miss", user=USER_B, vault_rows=(USER_A, USER_C), height=2, amount=5, balances=GOOD_BALANCE)
    add("vault check before negative amount", vault=0, amount=TOP)
    # Mode 0, spot to perp.
    add("to perp plain", amount=1000000, balances=GOOD_BALANCE, scale=to_bits(1.0), total=50, tally=70)
    add("to perp zero", amount=0, balances=GOOD_BALANCE, total=50, tally=70)
    add("to perp zero without a row", amount=0, total=50, tally=70)
    add("to perp no row", amount=1)
    add("to perp exactly the balance", amount=7, balances=((0, 700, 0),))
    add("to perp one wei short", amount=7, balances=((0, 699, 0),))
    add("to perp with a hold exact", amount=7, balances=((0, 750, 50),))
    add("to perp with a hold short", amount=7, balances=((0, 749, 50),))
    add("to perp hold wraps", amount=1, balances=((0, TOP, TOP - 50),))
    add("to perp hold above total", amount=0, balances=((0, 10, 20),))
    add("to perp sum wraps", amount=2, balances=((0, TOP, TOP - 199),))
    add("to perp hold refused", amount=7, balances=((0, 700, 0),), hold_ok=0)
    add("to perp negative amount panics", amount=HIGH)
    add("to perp amount top of 100 times", amount=TOP // 100, balances=((0, TOP, 0),))
    add("to perp amount past 100 times", amount=TOP // 100 + 1, balances=((0, TOP, 0),))
    add("to perp largest i64", amount=HIGH - 1, balances=((0, TOP, 0),))
    add("to perp other token in tree", token=9, amount=7, balances=token_rows(9, 700), prices=((9, 1234),))
    add("to perp wide tree", token=9, amount=7, balances=tuple((key, 700 + key, 0) for key in range(2, 20)), prices=((9, 1234),))
    add("to perp deep tree", token=9, amount=7, balances=token_rows(9, 700), prices=((9, 1234), (11, 1), (3, 2)), height=2)
    add("to perp fallback price", token=9, amount=7, balances=token_rows(9, 700), prices=((8, 1), (10, 2)))
    add("to perp fallback empty map", token=9, amount=7, balances=token_rows(9, 700))
    add("to perp total saturates", amount=7, balances=((0, 700, 0),), total=HIGH - 3)
    add("to perp tally saturates", amount=10 ** 9, balances=GOOD_BALANCE, scale=to_bits(1.0), tally=HIGH - 3)
    add("to perp tally negative start", amount=10 ** 9, balances=GOOD_BALANCE, tally=(-5) & TOP)
    # Mode 1, perp to spot.
    add("from perp plain", mode=1, amount=1000000, available=(1000000, 1000000), total=50, tally=10 ** 6)
    add("from perp one above withdrawable", mode=1, amount=1000000, available=(999999, 999999))
    add("from perp zero", mode=1, amount=0, available=(0, 0))
    add("from perp zero with nothing", mode=1, amount=0)
    add("from perp large word passes the unsigned read", mode=1, amount=5, available=(HIGH, HIGH))
    add("from perp second read lower", mode=1, amount=5, available=(5, 4))
    add("from perp second read equal", mode=1, amount=5, available=(9, 5))
    add("from perp token", mode=1, token=9, amount=5, available=(5, 5), prices=((9, 77),))
    add("from perp token fallback", mode=1, token=9, amount=5, available=(5, 5))
    add("from perp total saturates", mode=1, amount=5, available=(5, 5), total=(-HIGH + 2) & TOP)
    add("from perp tally saturates", mode=1, amount=10 ** 9, available=(10 ** 9, 10 ** 9), tally=(-HIGH + 3) & TOP)
    add("from perp negative panics", mode=1, amount=HIGH, available=(TOP, TOP))
    add("from perp past 100 times", mode=1, amount=TOP // 100 + 1, available=(TOP, TOP))
    add("from perp total goes negative", mode=1, amount=9, available=(9, 9), total=3)
    # Mode 2, forced sweep of free margin.
    add("sweep plain", mode=2, value=500, used=100, total=1000, tally=10 ** 6)
    add("sweep ignores the amount word", mode=2, amount=7, value=500, used=100)
    add("sweep nothing free", mode=2, value=100, used=100)
    add("sweep below used", mode=2, value=100, used=500)
    add("sweep negative value", mode=2, value=(-5) & TOP, used=0)
    add("sweep used top bit panics", mode=2, value=5, used=HIGH)
    add("sweep underflow saturates", mode=2, value=HIGH, used=5)
    add("sweep token", mode=2, token=9, value=500, used=100, prices=((9, 55),))
    add("sweep past 100 times", mode=2, value=TOP // 100 + 1, used=0)
    add("sweep vault refused", mode=2, vault=0, value=500)
    add("sweep token fallback", mode=2, token=9, value=500, used=100)
    add("sweep with a passing vault row", mode=2, vault=1, value=500, used=100)
    add("from perp with a passing vault row", mode=1, vault=1, amount=5, available=(5, 5))
    add("sweep among other vault rows", mode=2, vault_rows=(USER_B, USER_C), value=500, used=100)
    add("from perp among other vault rows", mode=1, vault_rows=(USER_B, USER_C), amount=5, available=(5, 5))
    add("sweep large", mode=2, value=10 ** 9 + 123456, used=0, tally=99999, total=10 ** 10)
    add("largest scaled amount", amount=GATE_LIMIT, balances=((0, TOP, 0),), scale=to_bits(0.25))
    add("largest float scale", amount=1, balances=((0, TOP, 0),), scale=0x7FEFFFFFFFFFFFFF)
    add("largest float scale from perp", mode=1, amount=1, available=(1, 1), scale=0x7FEFFFFFFFFFFFFF)
    add("smallest float above range", amount=1, balances=((0, TOP, 0),), scale=to_bits(9223372036854775808.0))
    for height in (0, 1, 2):
        add("stale vault key height %d" % height, stale=1, vault_rows=(USER_B, USER_C, b"\xf0" * 20), height=height, amount=5, balances=GOOD_BALANCE)
        add("stale balance key height %d" % height, stale=1, token=10, amount=0, balances=((8, 700, 0), (9, 701, 0), (11, 702, 0), (12, 703, 0)), height=height)
        add("stale balance key short height %d" % height, stale=1, token=10, amount=1, balances=((8, 700, 0), (9, 701, 0), (11, 702, 0), (12, 703, 0)), height=height)
        add("stale price key height %d" % height, stale=1, token=10, amount=1, balances=((10, 700, 0),), prices=((8, 1), (9, 2), (11, 3), (12, 4)), height=height)
        add("stale miss above all height %d" % height, stale=1, token=20, amount=1, balances=((20, 700, 0),), prices=((8, 1), (9, 2), (11, 3), (12, 4)), height=height)
    add("third key of four vaults", user=USER_C, vault=0, vault_rows=(USER_A, USER_B, b"\xf0" * 20), amount=5, balances=GOOD_BALANCE)
    add("third key of six vaults", user=USER_C, vault=0, vault_rows=(USER_A, USER_B, b"\xe0" * 20, b"\xe8" * 20, b"\xf0" * 20), amount=5, balances=GOOD_BALANCE)
    add("sweep total saturates", mode=2, value=500, used=100, total=(-HIGH + 2) & TOP)
    add("sweep tally saturates", mode=2, value=10 ** 9, tally=(-HIGH + 3) & TOP)
    for key in (8, 9, 11, 12):
        add("deep balance tree key %d" % key, token=key, amount=7, balances=((8, 700, 0), (9, 701, 0), (11, 702, 0)), prices=((8, 1), (9, 2), (11, 3)), height=2)
        add("deep tree key %d from perp" % key, token=key, mode=1, amount=7, available=(7, 7), prices=((8, 1), (9, 2), (11, 3)), height=2)
        add("one level tree key %d" % key, token=key, amount=7, balances=((8, 700, 0), (9, 701, 0), (11, 702, 0)), prices=((8, 1), (9, 2), (11, 3)), height=1)
    add("wide price map", token=30, amount=7, balances=token_rows(30, 700), prices=tuple((key, key * 3) for key in range(10, 40)))
    add("wide price map last", token=39, amount=7, balances=token_rows(39, 700), prices=tuple((key, key * 3) for key in range(10, 40)))
    add("wide price map miss", token=50, amount=7, balances=token_rows(50, 700), prices=tuple((key, key * 3) for key in range(10, 40)))
    add("vault tree top right", user=USER_C, vault=1, vault_rows=(USER_A, USER_B), height=1, amount=5, balances=GOOD_BALANCE)
    add("vault tree top left", user=USER_A, vault=1, vault_rows=(USER_B, USER_C), height=1, amount=5, balances=GOOD_BALANCE)
    add("vault tree miss high", user=b"\xf0" * 20, vault_rows=(USER_A, USER_B, USER_C), height=2, amount=5, balances=GOOD_BALANCE)
    add("vault tree miss low", user=b"\x00" * 20, vault_rows=(USER_A, USER_B, USER_C), height=2, amount=5, balances=GOOD_BALANCE)
    # Mode 3 is not a mode 2: it falls through the two equal tests.
    add("mode 3 reads margin and takes the spot branch", mode=3, value=500, used=100, balances=GOOD_BALANCE)
    add("mode 3 short", mode=3, value=500, used=100, balances=((0, 39999, 0),))
    # Notional scale.
    for amount, bits in ((10 ** 6, to_bits(0.5)), (10 ** 6, to_bits(1e9)), (10 ** 6, 0x7FF8000000000000), (10 ** 6, 0x7FF0000000000000), (10 ** 6, to_bits(-1.0)), (10 ** 6, to_bits(1e300)), (10 ** 6, to_bits(-1e300)), (GATE_LIMIT, to_bits(0.5)), (GATE_LIMIT + 1, to_bits(0.5)), (GATE_LIMIT - 1, to_bits(1.0)),
                         (9999, to_bits(1.0)), (10000, to_bits(1.0)), (10001, to_bits(1.0)), (19999, to_bits(1.0)), (10 ** 6, to_bits(CLAMP / 1e6)), (10 ** 6, to_bits(CLAMP / 1e6 * 2)), (10 ** 6, 0xFFF8000000000000), (10 ** 6, to_bits(9.3e12)), (10 ** 6, to_bits(9.2233720368547e12))):
        add("scale %d %#x to perp" % (amount, bits), amount=amount, scale=bits, balances=((0, TOP, 0),), total=11, tally=22)
        add("scale %d %#x from perp" % (amount, bits), mode=1, amount=amount, scale=bits, available=(TOP >> 1, TOP >> 1), total=11, tally=22)
    return out


def named_apply(copy):
    tag = "copy %s apply " % COPIES[copy].name
    fields = dict(copy=copy, entry="apply")
    out = []

    def add(name, **more):
        out.append(Case(tag + name, **dict(fields, **more)))

    add("spot disabled", disabled=1, amount=5, to_perp=1)
    add("spot disabled from perp", disabled=7, amount=5)
    add("to perp event", to_perp=1, amount=2500000, balances=GOOD_BALANCE)
    add("from perp event", to_perp=0, amount=2500000, available=(2500000, 2500000))
    add("to perp event stamped", to_perp=1, amount=2500000, balances=GOOD_BALANCE, stamped=1)
    add("zero amount still sends an event", to_perp=1, amount=0, balances=GOOD_BALANCE)
    add("refused hold still sends an event", to_perp=1, amount=7, balances=((0, 700, 0),), hold_ok=0)
    add("failure passes the status", to_perp=1, amount=7)
    add("withdraw failure passes the status", to_perp=0, amount=7, available=(6, 6))
    add("large amount lanes", to_perp=1, amount=(1 << 53) + 3, balances=((0, TOP, 0),))
    add("other high byte of the bool", to_perp=1, amount=1, balances=GOOD_BALANCE)
    return out


def named_system(copy):
    tag = "copy %s system " % COPIES[copy].name
    fields = dict(copy=copy, entry="system")
    out = []

    def add(name, **more):
        out.append(Case(tag + name, **dict(fields, **more)))

    add("cap refused", amount=CAP, to_perp=1)
    add("largest refused", amount=TOP, to_perp=1)
    add("below cap", amount=CAP - 1, to_perp=1, balances=((0, TOP, 0),))
    add("to perp", amount=5, to_perp=1, balances=GOOD_BALANCE)
    add("from perp", amount=5, available=(5, 5))
    add("failure copied", amount=5, available=(4, 4))
    add("kind 2 passes", amount=5, kind=2, to_perp=1, balances=GOOD_BALANCE)
    add("kind 3 flag off", amount=5, kind=3, to_perp=1, balances=GOOD_BALANCE, flags=(1, 0))
    add("kind 3 flag on", amount=5, kind=3, to_perp=1, balances=GOOD_BALANCE, flags=(0, 1))
    add("kind 4 flag off", amount=5, kind=4, to_perp=1, balances=GOOD_BALANCE, flags=(0, 1))
    add("kind 4 flag on", amount=5, kind=4, to_perp=1, balances=GOOD_BALANCE, flags=(1, 0))
    add("kind 200 flag on", amount=5, kind=200, to_perp=1, balances=GOOD_BALANCE, flags=(1, 0))
    return out


PLAIN_TEXTS = (b"0", b"1", b"1.5", b"0.000001", b"0.0000005", b"0.0000015", b"0.00000051", b"0.0000025", b"12.3456785", b"12.3456775", b"+1", b"+1.25", b"-0", b"-0.0", b"-0.0000004", b"-0.0000005", b"-0.0000006", b"-1", b".5", b"5.", b"00012.50", b"9223372036854.775806", b"9223372036854.775807",
               b"9223372036854.7758065", b"9223372036854.7758055", b"9223372036855", b"184467440737.095516", b"184467440737.095517", b"922337203685.477580", b"79228162514264", b"79228162514264337593543", b"0.0000000000000000000000000001", b"1.0000000000000000000000000001")


def named_user(copy):
    tag = "copy %s user " % COPIES[copy].name
    fields = dict(copy=copy, entry="user", to_perp=1, balances=((0, TOP, 0),))
    out = []

    def add(name, **more):
        out.append(Case(tag + name, **dict(fields, **more)))

    for text in PLAIN_TEXTS:
        add("amount %s" % text.decode(), text=text)
    return out


def text_cases(copy):
    tag = "text " if copy == 0 else "copy %s text " % COPIES[copy].name
    fields = dict(entry="user", copy=copy, to_perp=1, balances=((0, TOP, 0),))
    out = []

    def add(name, **more):
        out.append(Case(tag + name, **dict(fields, **more)))

    add("empty", text=b"")
    add("length 100", text=b"0" * 100)
    add("length 101", text=b"0" * 101)
    add("sub plain", text=b"7 subaccount:" + SUB_TEXT)
    add("sub no space", text=b"7subaccount:" + SUB_TEXT)
    add("sub two spaces and a tab", text=b"7 \t subaccount:" + SUB_TEXT)
    add("sub without the 0x", text=b"7 subaccount:" + USER_B.hex().encode())
    add("sub upper case hex", text=b"7 subaccount:0x" + USER_B.hex().upper().encode())
    add("sub refused", text=b"7 subaccount:" + SUB_TEXT, refuse=1)
    add("sub short address", text=b"7 subaccount:0x1234")
    add("sub long address", text=b"7 subaccount:" + SUB_TEXT + b"00")
    add("sub bad hex", text=b"7 subaccount:0x" + b"g" * 40)
    add("sub empty address", text=b"7 subaccount:")
    add("second separator stays in the address", text=b"7 subaccount:" + SUB_TEXT + b"subaccount:1")
    add("sub only separator", text=b"subaccount:" + SUB_TEXT)
    add("sub bad amount", text=b"x subaccount:" + SUB_TEXT)
    add("sub bad address before bad amount", text=b"x subaccount:0x12")
    add("sub kind gate on the sub", text=b"7 subaccount:" + SUB_TEXT, kind=3)
    add("sub spot disabled", text=b"7 subaccount:" + SUB_TEXT, disabled=1)
    add("sub from perp", text=b"7 subaccount:" + SUB_TEXT, to_perp=0, available=(7000000, 7000000))
    add("sub zero", text=b"0 subaccount:" + SUB_TEXT)
    add("plain kind 3 off", text=b"7", kind=3, flags=(1, 0))
    add("plain kind 3 on", text=b"7", kind=3, flags=(0, 1))
    add("plain kind 4 off", text=b"7", kind=4, flags=(0, 1))
    add("plain kind 4 on", text=b"7", kind=4, flags=(1, 0))
    add("plain kind 0", text=b"7", kind=0)
    add("plain spot disabled", text=b"7", disabled=1)
    add("plain from perp", text=b"7", to_perp=0, available=(7000000, 7000000))
    add("plain from perp short", text=b"7", to_perp=0, available=(6999999, 6999999))
    add("rounded amount is the one moved", text=b"0.0000015", to_perp=1, balances=((0, 200, 0),))
    add("rounded amount short", text=b"0.0000015", to_perp=1, balances=((0, 199, 0),))
    for text in sorted(LITERAL_TEXTS):
        if len(text) <= TEXT_CAP:
            add("literal %r" % text, text=text)
    for name, text in (("zero padded", b"0x00" + HEX_B), ("one zero padded no prefix", b"0" + HEX_B), ("two zero padded", b"00" + HEX_B), ("padded with a one", b"10" + HEX_B), ("padded with a one and prefix", b"0x10" + HEX_B), ("tail zero", HEX_B + b"0"), ("39 hex with prefix", b"0x" + HEX_B[:-1]), ("39 hex", HEX_B[:-1]),
                       ("upper prefix", b"0X" + HEX_B), ("upper hex", b"0x" + HEX_B.upper()), ("all zero", b"0" * 40), ("two byte characters", "\u00e9".encode() * 20), ("two byte characters with prefix", b"0x" + "\u00e9".encode() * 20), ("long two byte", "\u00e9".encode() * 40), ("leading space", b" 0x" + HEX_B), ("trailing space", b"0x" + HEX_B + b" ")):
        add("address " + name, text=b"7 subaccount:" + text)
    for name, text in (("no break", "\u00a0"), ("next line", "\u0085"), ("ogham", "\u1680"), ("em", "\u2003"), ("hair", "\u200a"), ("after zero width", "\u200b"), ("line", "\u2028"), ("paragraph", "\u2029"), ("narrow", "\u202f"), ("math", "\u205f"), ("ideographic", "\u3000"), ("vertical tab", "\x0b"), ("unit", "\x1f"), ("mixed", " \t\u3000\n")):
        add("trim " + name, text=b"7" + text.encode() + b"subaccount:" + SUB_TEXT)
    add("trim on the plain path is absent", text=b"7 ")
    add("separator twice at the start", text=b"subaccount:subaccount:" + SUB_TEXT)
    add("separator cut", text=b"7 subaccoun:" + SUB_TEXT)
    add("near separator then real", text=b"7 subaccoun subaccount:" + SUB_TEXT)
    return out


def base_cases():
    out = []
    for copy in range(3):
        out += named_core(copy) + named_apply(copy) + named_system(copy) + named_user(copy) + text_cases(copy)
    return out


VECTORS = 400
MUTANT_VECTORS = 80
REACH_CAP = 12
SECOND_CAP = 40
THIRD_CAP = 300
MUTANT_STEP_LIMIT = 300000


def lcg(seed):
    state = [seed]

    def next_value(bound):
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state[0] >> 33) % bound
    return next_value


def wide(pick):
    return pick(10 ** (pick(9) * 2 + 1)) + (pick(3) == 0) * pick(1 << 31) * pick(1 << 31)


def amount_text(pick):
    whole = str(pick(10 ** (pick(13) + 1)))
    fraction = "".join(str(pick(10)) for _ in range(pick(10)))
    sign = ("", "", "", "+", "-")[pick(5)]
    return (sign + whole + ("." + fraction if fraction else "")).encode()


def vector_cases(count):
    out = []
    for index in range(count):
        pick = lcg(index * 2 + 1)
        copy = pick(3)
        token = (0, 0, 7, 9)[pick(4)]
        amount = wide(pick)
        total = wide(pick) * 100 + pick(1000)
        balances = token_rows(token, total, pick(1000)) if pick(5) else ()
        fields = dict(copy=copy, token=token, balances=balances, prices=((token, pick(10 ** 6)),) if token and pick(2) else (), scale=to_bits((pick(9) + 1) / 8.0), total=wide(pick), tally=wide(pick), vault=(None, None, None, 0, 1)[pick(5)], hold_ok=pick(9) != 0, available=(amount + pick(3) - 1 if amount else 0, amount + pick(3) - 1 if amount else 0))
        kind = pick(4)
        if kind == 0:
            out.append(Case("vector %d" % index, mode=pick(3), amount=amount, value=wide(pick), used=wide(pick), **fields))
        elif kind == 1:
            out.append(Case("vector %d" % index, entry="apply", to_perp=pick(2), amount=amount, disabled=pick(9) == 0, **fields))
        elif kind == 2:
            out.append(Case("vector %d" % index, entry="system", to_perp=pick(2), amount=amount, kind=pick(6), flags=(pick(2), pick(2)), **fields))
        else:
            text = amount_text(pick)
            if pick(3) == 0:
                text += (b" ", b"", b"\t  ")[pick(3)] + b"subaccount:" + SUB_TEXT
            fields["available"] = (10 ** 14, 10 ** 14)
            out.append(Case("vector %d" % index, entry="user", to_perp=pick(2), text=text, kind=pick(6), flags=(pick(2), pick(2)), refuse=pick(7) == 0, **fields))
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
            if not same(case, harness.run(case), spec_for(case)):
                return case
        except AccessError:
            return case
    return None


def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


SURVIVOR_REASONS = {
    "panic": "text length or status word set just before a panic call; the stub does not read them",
    "limit": "the 100 times gate refuses every amount past this bound, so a small change of the bound is not visible",
    "mask": "low bit of the sign mask or of the saturation word; the clamp below gives the same value",
    "clamp": "the f64 test only selects the clamp; the plain path and the clamp agree on these values",
    "low clamp": "low bit of the integer clamp; the row word is the value over 10000, so the quotient is the same, and a negative clamp ends at 0",
    "payload": "error payload bytes past the tag; no reader in the subject and the parser leaves stack bytes there",
    "mode": "rescale modes above 1 share one rule",
    "split": "a third part cannot exist, because the split stops at two parts",
    "vault length": "a longer key walk meets the fill or the stale key with a nonzero flag byte, same result",
    "second bound": "second read of the dex count on the same value; the first read refuses, and the edited read gives a pointer that passes",
    "reciprocal": "low bit of the reciprocal of 10000; the quotient is the same at the values this row ran, and the same constant is killed on the other tails",
}
SURVIVORS = {}
for group, rows in (
        ("panic", (0x270F8DF, 0x271002D, 0x271004E, 0x2710075, 0x46E8B81, 0x46E92F1, 0x46E9312, 0x46E9339, 0x46E95B6, 0x46E97A2, 0x46E97C9, 0x46E97F3)),
        ("limit", (0x270FACA, 0x46E8D81, 0x46E8344)),
        ("mask", (0x270FB04, 0x46E8DB5, 0x46E837B)),
        ("clamp", (0x270FB30, 0x270FB3A, 0x46E8DE1, 0x46E8DEB, 0x46E83AB, 0x46E83B5)),
        ("low clamp", (0x270FB8B, 0x270FB9A, 0x46E8E32, 0x46E8E41, 0x46E844F, 0x46E845E)),
        ("payload", (0x1E60876, 0x1E6095A, 0x1E6098E, 0x1E609BB, 0x3980C29, 0x3980C32, 0x3980C3B, 0x3980C44, 0x3980C4D, 0x3980C59, 0x3980C65, 0x3980C9D, 0x3980CA5, 0x3980CB2, 0x3980CBB, 0x3980CC4, 0x3980CCD, 0x3980CD6, 0x46E83C2, 0x46E83CA, 0x46E83D7, 0x46E83E0, 0x46E83EC, 0x46E83F5, 0x46E8407)),
        ("mode", (0x3980BB6,)),
        ("split", (0x3BAFAD1, 0x3BAFAEC)),
        ("vault length", (0x270F7C8, 0x270F81B, 0x46E8A75, 0x46E8ACB, 0x46E94A5, 0x46E94FB)),
        ("second bound", (0x270FA9B, 0x46E8D5C, 0x46E8309)),
        ("reciprocal", (0x46E8769,))):
    for address in rows:
        SURVIVORS[address] = group


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
        if name not in FUNCTIONS:
            continue
        for va, kind, patch in edits_for(image, table[name], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], THIRD_CAP))
            results.append((name, va, kind, "killed", hit.name) if hit is not None else (name, va, kind, "survived", survivor_reason(va, kind)))
    return results


REFERENCE = (
    ("amount digits", "more than six fraction digits return the malformed status 305", "the real decimal parser reads the text and 0x3750350 runs in mode 2: half even to six places, any further digits accepted; 0.0000015 moves 2 raw units", "text rounded amount is the one moved"),
    ("exponent and separators", "digits and one dot only", "the parser takes 1e3, 1E3, 1e-3, 1_000, 1_ and 1.e2; it refuses a leading underscore", "text literal b'1e3'"),
    ("negative text", "negative value carried into a signed amount", "a negative that rounds to a nonzero whole is tag 0xa8; one that rounds to zero is amount 0 and the action succeeds with no move", "copy a user amount -0.0000005"),
    ("user amount cap", "parsed.usd >= 0x0ccc... gives status 319 on the user path", "no such compare on the user path; the 100 times overflow refuses above floor(u64::MAX/100) with 0xf7, well below that cap, and 0x3750350 refuses above 2^63-2 with 0xa8. Only the system handler compares with 0x0ccc...", "copy a user amount 184467440737.095517"),
    ("three part text", "a third split part returns 305", "the split is a split-n of 2: a second separator stays inside the address text and gives 0xb6; the 0x131 branch for other part counts is not reached", "text second separator stays in the address"),
    ("0x131 status", "any malformed shape", "only the empty text reaches it; a bad amount is tag 0xac from the parser", "text empty"),
    ("amount before address", "the amount is parsed first", "the address is parsed first; 0xb6 hides a bad amount", "text sub bad address before bad amount"),
    ("space before the separator", "no trim", "the left part is trimmed at its end for all Unicode white space, only when a separator is present", "text trim ideographic"),
    ("address text", "strip 0x or 0X, exactly 40 hex digits", "lower case 0x only; extra leading bytes must be the character 0; errors text 'string too short to be Address' or the leading pad text", "text address zero padded"),
    ("status 249", "transfer class disabled, unknown class", "tag 0xf9 'Spot disabled', byte state +0x3ac8 nonzero", "copy a apply spot disabled"),
    ("status 21", "user or account ownership mismatch", "tag 0x15 'Vault may not perform this action.': user in the tree at state +0x8d0, refused unless token 0 and value byte +0xaf nonzero", "copy a vault row flag zero on token 0"),
    ("status 367", "feature gate", "tag 0x16f 'Action disabled when unified account is active'; kind 3 reads state +0x5b1, kinds above 3 read +0x5b0", "copy a system kind 3 flag off"),
    ("system gate order", "amount cap, then gate, then helper", "same order", "copy a system cap refused"),
    ("event on no move", "event only for a real transfer", "the event is sent for amount 0 and when the hold helper refuses: both return OK with no balance change", "copy a apply refused hold still sends an event"),
    ("dex", "no dex index", "the wrapper passes dex 0; other callers pass another index, the move reads dex +0x50 as token and works on any dex row", "copy a dex index two of three"),
)


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
    for address, meaning in ((0x20ACB8, "lower clamp of the product"), (0x20A7F0, "upper clamp of the product"), (0x20A2C8, "saturation compare after the cast"), (0x20AE60, "event amount divisor")):
        rows.append(("%#x" % address, bytes(image.blob[address:address + 8]).hex(), repr(struct.unpack_from("<d", image.blob, address)[0]), meaning))
    start = image.offset(0x5A8311)
    text = bytes(image.blob[start:start + len(SEPARATOR)])
    if text != SEPARATOR:
        raise EvidenceError("separator text")
    rows.append(("0x5a8311", text.hex(), text.decode(), "split text, length 11 at the call"))
    return rows


def location_rows(image):
    rows = []
    table = image.relative()
    for address, meaning in ((LOC_TOTAL_ADD, "total_net_deposit add"), (LOC_TOTAL_SUB, "total_net_deposit subtract"), (LOC_TALLY, "row +0x18 add and subtract"), (LOC_MARGIN, "free margin subtract")):
        path, line, column = image.location(address, table)
        rows.append(("%#x" % address, path, line, column, meaning))
    return rows


def caller_rows(image):
    """Every direct call of the three move entries, with the r8 write nearest before it, read from fixed byte shapes."""
    base, text = image.text_bytes()
    rows = []
    for copy in COPIES:
        at = text.find(b"\xe8")
        while at >= 0 and at + 5 <= len(text):
            va = base + at
            if va + 5 + struct.unpack_from("<i", text, at + 1)[0] == copy.core:
                rows.append((copy.name, "%#x" % copy.core, "%#x" % va, "%#x" % image.fde(va)[0], mode_before(text, at)))
            at = text.find(b"\xe8", at + 1)
    return rows


def mode_before(text, at):
    for back in range(3, 49):
        row = at - back
        if back >= 6 and text[row:row + 2] == b"\x41\xb8":
            return "%d" % struct.unpack_from("<I", text, row + 2)[0]
        if text[row:row + 3] == b"\x45\x31\xc0":
            return "0"
    return "register"


def subject_rows(image):
    table = {}
    for name, target in list(FUNCTIONS.items()) + list(COPY_ONLY.items()):
        table[name] = rows_of(image, target)
    return table


def copy_rows(image):
    rows = []
    for copy in COPIES:
        rows.append((copy.name, "%#x" % copy.handler, "%#x" % copy.system, "%#x" % copy.apply, "%#x" % copy.core, "%#x" % (STATE_OFFSET_DEX + copy.shift), "%#x" % (0x740 + copy.shift), "%#x" % (0x3AC8 + copy.shift), "%#x" % (0x8D0 + copy.shift), "%#x" % copy.sink, "%#x" % copy.sink_at))
    return rows


STATE_OFFSET_DEX = 0x5C0


def analyse(image, mutate=True, vectors=VECTORS):
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
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), tags=tag_rows(image), copies=copy_rows(image), locations=location_rows(image), callers=caller_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def event_text(event):
    return " ".join(part.hex() if isinstance(part, bytes) else "%#x" % part if isinstance(part, int) else str(part) for part in event)


def outcome_row(case, got):
    return (case.name, " ".join(("%#x" % part if isinstance(part, int) else str(part)) for part in got["result"]), "%#x" % got["state"]["total"], "%#x" % got["state"]["tally"], "; ".join(event_text(event) for event in got["events"]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "bytes", "value", "meaning"), result["constants"])
    tsv("tag-texts.tsv", ("tag", "display text"), result["tags"])
    tsv("locations.tsv", ("record", "path", "line", "column", "use"), result["locations"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "signed handler", "system handler", "apply", "move", "dex list offset", "row map offset", "spot off byte", "vault tree offset", "event slot", "event state offset"), result["copies"])
    tsv("callers.tsv", ("copy", "move entry", "call site", "function", "mode"), result["callers"])
    tsv("outcomes.tsv", ("case", "result", "total_net_deposit", "row word", "callee events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("subject", "address", "kind", "outcome", "detail"), [(name, "%#x" % va, k, o, d) for name, va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "subjects": {name: {"address": "%#x" % result["table"][name][0].va, "bytes": sum(row.size for row in result["table"][name]), "instructions": len(result["table"][name]),
                            "unreached_rows": ["%#x" % va for va in result["unreached"][name]]} for name in result["table"]},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived")}
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

