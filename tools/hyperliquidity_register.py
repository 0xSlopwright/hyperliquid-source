#!/usr/bin/env python3
"""Pin the node #94 RegisterHyperliquidity path: the deploy handler copies, the gate body, the price ladder and its two checks.

Real rows run from the handler in all three copies with real decimal parsing, tree, tick and rounding code. A separately
written rule list predicts every result, callee argument and written word, and every reached conditional row, immediate and
field offset of the subject code is edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/hyperliquidity_register.py --out <dir>
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
HEAP_SIZE = 0x100000
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
        self.stops = ()
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
        while pc != RETURN_SENTINEL and pc not in self.stops:
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
        if pc in self.stops:
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
            left, right = self.get(row.b, width), row.target & MASK[width]
            product = (left - (left >> (8 * width - 1) << (8 * width))) * (right - (right >> (8 * width - 1) << (8 * width)))
            self.put(row.a, width, product)
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
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
            left, right = self.get(row.a, width), self.get(row.b, width)
            product = (left - (left >> (8 * width - 1) << (8 * width))) * (right - (right >> (8 * width - 1) << (8 * width)))
            self.put(row.a, width, product)
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
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
TAG_TEXT, TAG_PX, TAG_SZ, TAG_DECIMAL = 0xDF, 0xA9, 0xAA, 0xA8
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_NOTE = 0x576F488
SLOT_BODY = 0x5774CD0
SLOT_RECORD = 0x5773170
SLOT_TICK_LOOKUP = 0x5773D30
SLOT_BALANCE = 0x5774660
SLOT_DEX = 0x5773D80
SLOT_SCALE = 0x5774CD8
SLOT_SEND = 0x57749E8
SLOT_SINK = 0x5774738
SLOT_ONCE = 0x576E8B8
SLOT_SINK_B = 0x5776AD0
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048, 0x576EB38, 0x576E1B0)
MARK_BASE = 0x7700000000
BODY = 0x3261C40
LADDER = 0x32639C0
SUM = 0x3262590
BAND = 0x3262600
ONCE = 0x577AB98
STATUS_DROP = 0x3379490
PROC = 0x3987CB0
TOP = MASK[8]
HIGH = 1 << 63
LIMIT = 0x1999999999999999
MAX_PX = 0x38D7EA4C68000
MAX_BALANCE = 0x68DB8BAC710CB
MAX_ORDERS, MIN_ORDERS = 4000, 10
RATIO = 1.003
END_LOW, END_HIGH, START_LOW, START_HIGH = 1000000000, 100000000000, 0, 10000000
BAND_LOW, BAND_HIGH = 700000, 1300000
SPOT_STRIDE = 0x20
TOKEN_STRIDE = 0xE8
ROW_STRIDE = 0xD8
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
OUT = HEAP_BASE + 0x40
PARAM = HEAP_BASE + 0xC0
USER = HEAP_BASE + 0x100
PX_STRING = HEAP_BASE + 0x120
SZ_STRING = HEAP_BASE + 0x140
TEXTS = HEAP_BASE + 0x200
RECORD = HEAP_BASE + 0x400
NAMES = HEAP_BASE + 0x500
DEX = HEAP_BASE + 0x600
SPOTS = STATE + STATE_SIZE
SPOT_ROOM = 6
TOKENS = SPOTS + SPOT_ROOM * SPOT_STRIDE
TOKEN_ROOM = 6
ROWS = TOKENS + TOKEN_ROOM * TOKEN_STRIDE
BUMP = ROWS + SPOT_ROOM * ROW_STRIDE
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
WHO = bytes(range(1, 21))
SYSTEM = b"\xff" * 20
REFUSAL = 0x123
PROC_BYTES = bytes(0xD0 + index for index in range(0x20))
STREAM_WORDS = bytes(range(0x50, 0x5C))

AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


BOOK_TREE = Layout(0x168, 8, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8)
BALANCE_TREE = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
SUPPLY_TREE = Layout(8, 8, 0x60, 8, 0, 0xB8, 0xBA, 0xC0)


class Copy:
    def __init__(self, name, handler, move, drops, location, shift, sink_at):
        self.name, self.handler, self.move, self.drops, self.location, self.shift, self.sink_at = name, handler, move, drops, location, shift, sink_at


COPIES = (Copy("a", 0x274FD60, 0x270F6F0, (0x277EBA0, 0x239CB60), 0x56BD9F0, 0, 0x8F3),
          Copy("b", 0x4D72A80, 0x46E8290, (0x4DAF4A0,), 0x57446A0, 0xA80, 0x5B8),
          Copy("c", 0x4D73550, 0x46E89A0, (0x4DAF4A0,), 0x57446A0, 0, 0x8F3))
FUNCTIONS = dict(body=BODY, ladder=LADDER, seed_sum=SUM, cap_band=BAND)
for copy_row in COPIES:
    FUNCTIONS["handler_" + copy_row.name] = copy_row.handler

MESSAGES = ((0x5848ED, 0x1E, "too many Hyperliquidity orders"), (0x5848CB, 0x22, "cannot seed more levels than exist"), (0x584696, 0x1D, "Hyperliquidity already exists"),
            (0x5848A6, 0x25, "Hyperliquidity already has token hold"), (0x58487B, 0x2B, "quote token must be USDC for Hyperliquidity"), (0x58485A, 0x21, "Hyperliquidity missing max supply"),
            (0x58483D, 0x1D, "too few Hyperliquidity orders"), (0x584819, 0x24, "Hyperliquidity configuration invalid"), (0x5846B3, 0x1E, "zero Hyperliquidity order size"),
            (0x5847F5, 0x24, "Hyperliquidity has incorrect balance"), (0x5846D1, 0x3B, "Hyperliquidity starting order value must be at least 1 USDC"), (0x5847CE, 0x27, "Hyperliquidity starting price too small"),
            (0x584738, 0x1F, "Hyperliquidity price is invalid"), (0x584757, 0x77, "market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price"),
            (0x58470C, 0x2C, "insufficient usdc for seeding hyperliquidity"), (0x3EFF7E, 0x23, "could not convert perp usdc to spot"))
TOO_MANY, CANNOT_SEED, EXISTS, HOLD, QUOTE, NO_SUPPLY, TOO_FEW, CONFIG, ZERO_SZ, BAD_BALANCE, SMALL_VALUE, SMALL_PX, BAD_PX, BAD_CAP, NO_USDC, NO_CONVERT = (row[2] for row in MESSAGES)


class Case:
    DEFAULTS = dict(entry="body", copy=0, spot=1, px=1000000, sz=100, n=10, seeded=0, avail=None, available=0, spots=((5, 0), (1, 0), (2, 3), (4, 0)), tokens=(("USDC", 8, 8, 0, 0), ("TEST", 2, 8, 0, 0), ("BASE", 3, 7, 0, 0), ("QUOT", 2, 6, 0, 0), ("HYPE", 2, 8, 0, 0), ("OTHR", 0, 2, 0, 0)),
                    held=None, hold=0, books=(), supplied=(0, 1, 2, 3, 4, 5), word=0, tick_hit=0, px_text=None, sz_text=None, dex_rows=1, send=OK, move=OK, proc=0, crowd=0, height=0, stale=0, lo=0, hi=0, v=0, rows=(), factor=0, row_word=0x3030, once=0, marks=None)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)
        self.base, self.quote = self.spots[self.spot] if self.spot < len(self.spots) else (0, 0)
        if self.avail is None:
            self.avail = TOP >> 1
        if self.held is None and self.base < len(self.tokens):
            token = self.tokens[self.base]
            amount = max(self.n - self.seeded, 0) * self.sz * 10 ** max(token[2] - token[1], 0)
            self.held = amount if amount <= TOP else 0


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000 and target not in HOOKED


HOOKED = {RESUME, STATUS_DROP, PROC}
for copy_row in COPIES:
    HOOKED |= {copy_row.move} | set(copy_row.drops)


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_NOTE, self.on_note), (SLOT_RECORD, self.on_record), (SLOT_TICK_LOOKUP, self.on_tick), (SLOT_BALANCE, self.on_balance), (SLOT_DEX, self.on_dex), (SLOT_SCALE, self.on_scale), (SLOT_SEND, self.on_send), (SLOT_SINK, self.on_sink), (SLOT_SINK_B, self.on_sink), (SLOT_ONCE, self.on_once))
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
        machine.calls = {RESUME: self.on_panic, STATUS_DROP: self.on_drop_status, PROC: self.on_proc}
        for copy in COPIES:
            machine.calls[copy.move] = self.on_move
            for target in copy.drops:
                machine.calls[target] = self.on_drop_wrapped
        self.case = None
        self.copy = COPIES[0]
        self.live = {}
        self.cur = BUMP
        self.events = []

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

    def on_note(self, machine):
        self.events.append(("note",))

    def on_record(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE + 0x80 and memory.bytes_at(regs[RSI], 20) == SYSTEM, "system user record")
        regs[RAX] = RECORD

    def on_tick(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x90 and regs[RSI] == self.case.spot and regs[RDX] == STATE + 0x90, "tick lookup")
        regs[RAX] = 0xAB00 | self.case.tick_hit

    def on_balance(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == DEX and memory.bytes_at(regs[RSI], 20) == WHO, "balance arguments")
        regs[RAX] = self.case.available

    def on_dex(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x5B8 + self.copy.shift and regs[RSI] == 0, "dex lookup")
        self.events.append(("dex",))
        regs[RAX] = DEX

    def on_scale(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == DEX and regs[RDX] == self.copy.location, "scale arguments")
        self.events.append(("scale", regs[RSI]))
        regs[RAX] = regs[RSI] + 7

    def on_send(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == DEX and memory.bytes_at(regs[RDX], 20) == WHO and memory.bytes_at(regs[RCX], 20) == SYSTEM and regs[R9] == 0, "send arguments")
        self.expect(memory.read(regs[RSP], 8) == STATE + 0x3840 + self.copy.shift and memory.read(regs[RSP] + 8, 8) == STATE + 0x5D0 + self.copy.shift, "send stack arguments")
        self.events.append(("send", regs[R8]))
        memory.write(regs[RDI], 2, self.case.send)

    def on_move(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE and regs[RDX] == 0 and memory.bytes_at(regs[RCX], 20) == SYSTEM and regs[R8] & 0xFF == 1, "move arguments")
        self.events.append(("move", regs[R9]))
        memory.write(regs[RDI], 2, self.case.move)

    def on_proc(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RCX] == 0x8888 and regs[RDX] == 0x2828 and regs[RSI] & 0xFF == 0x42 and regs[R8] == 0, "process word arguments")
        self.events.append(("proc",))
        memory.put_bytes(regs[RDI], PROC_BYTES)
        regs[RAX] = regs[RDI]

    def on_sink(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE + self.copy.sink_at, "sink target")
        cap, ptr, size = struct.unpack("<3Q", memory.bytes_at(regs[RSI], 24))
        self.expect((cap, size) == (1, 1) and memory.bytes_at(ptr, 20) == WHO, "sink user list")
        self.expect(self.live.pop(ptr, None) == 20, "sink takes the list")
        self.expect(memory.bytes_at(regs[RDX], 12) == STREAM_WORDS, "sink stream words")
        proc = memory.bytes_at(regs[RCX], 0x20)
        self.expect(proc == (PROC_BYTES if self.case.proc == 1 else bytes(0x20)), "sink process words")
        frame = memory.bytes_at(regs[R8], 0x28)
        head, cap, name, size = struct.unpack_from("<4Q", frame, 0)
        self.expect(head == 0x8000000000000010 and (cap, size) == (4, 4) and memory.bytes_at(name, 4) == b"USDC", "sink event words")
        self.expect(self.live.pop(name, None) == 4, "sink takes the name")
        self.events.append(("event", struct.unpack_from("<Q", frame, 0x20)[0]))

    def on_once(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == ONCE and regs[RSI] & 0xFF == 1, "lazy state")
        self.events.append(("once",))

    def on_drop_status(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == 0x141, "dropped lookup status")

    def on_drop_wrapped(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) in (TAG_PX, TAG_DECIMAL), "dropped wrapped status")

    def node(self, layout, rows, size):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(rows))
        spare = rows[0][0] if self.case.stale and rows else b"\xfe" * layout.key_size
        if self.case.stale == 2:
            spare = struct.pack("<Q", self.case.spot if layout is BOOK_TREE else self.case.base)
        for slot in range(11):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, spare)
        for slot, (key, value) in enumerate(rows):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
            if layout.val_size:
                memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        return at

    def tree(self, layout, items, height):
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED
        if len(items) <= 11:
            root, level = self.node(layout, items, layout.leaf), 0
        else:
            parts, seps, at = [], [], 0
            while len(items) - at > 11:
                parts.append(items[at:at + 5])
                seps.append(items[at + 5])
                at += 6
            parts.append(items[at:])
            kids = [self.node(layout, part, layout.leaf) for part in parts]
            root = self.node(layout, seps, layout.inner)
            for slot, kid in enumerate(kids):
                memory.write(root + layout.edge_at + 8 * slot, 8, kid)
                memory.write(kid + layout.parent_at, 8, root)
                memory.write(kid + layout.index_at, 2, slot)
            level = 1
        while level < height:
            top = self.node(layout, [], layout.inner)
            memory.write(top + layout.edge_at, 8, root)
            memory.write(root + layout.parent_at, 8, top)
            memory.write(root + layout.index_at, 2, 0)
            root, level = top, level + 1
        return root, level

    def put_tree(self, at, layout, items, height=0):
        root, level = self.tree(layout, items, height)
        self.machine.memory.put_bytes(at, struct.pack("<3Q", root, level, len(items)))

    def walk(self, layout, root, level):
        memory = self.machine.memory
        rows, nodes = [], []

        def down(node, depth):
            nodes.append(node)
            count = memory.read(node + layout.len_at, 2)
            for index in range(count + 1):
                if depth:
                    down(memory.read(node + layout.edge_at + 8 * index, 8), depth - 1)
                if index < count:
                    rows.append((memory.bytes_at(node + layout.key_at + layout.key_size * index, layout.key_size), memory.bytes_at(node + layout.val_at + layout.val_size * index, layout.val_size) if layout.val_size else b""))
        if root:
            down(root, level)
        return rows, nodes

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        memory.statics[ONCE] = case.once
        self.case = case
        self.copy = COPIES[case.copy]
        self.live = {}
        self.cur = BUMP
        self.events = []
        memory.put_bytes(USER, WHO)
        memory.put_bytes(STATE, b"\0" * 8)
        memory.write(STATE, 4, case.proc)
        memory.write(STATE + 8, 8, 0x8888)
        memory.write(STATE + 0x28, 8, 0x2828)
        shift = self.copy.shift
        memory.write(STATE + 0x8F2 + shift, 1, 0x42)
        memory.put_bytes(STATE + 0x60, STREAM_WORDS)
        memory.write(STATE + 0x1F8, 8, SPOTS)
        memory.write(STATE + 0x200, 8, len(case.spots))
        memory.write(STATE + 0x210, 8, TOKENS)
        memory.write(STATE + 0x218, 8, len(case.tokens))
        memory.write(STATE + 0x3388 + shift, 8, ROWS)
        memory.write(STATE + 0x3390 + shift, 8, len(case.spots))
        memory.write(STATE + 0x5C0 + shift, 8, DEX)
        memory.write(STATE + 0x5C8 + shift, 8, case.dex_rows)
        memory.write(STATE + 0x118, 8, 0)
        for index, (base, quote) in enumerate(case.spots):
            memory.put_bytes(SPOTS + index * SPOT_STRIDE, struct.pack("<2Q", base, quote))
        for index in range(len(case.spots)):
            memory.write(ROWS + index * ROW_STRIDE, 8, 0x5555)
            memory.write(ROWS + index * ROW_STRIDE + 0x78, 8, 0x4D4D)
        for index, (name, sz, wei, tag, value) in enumerate(case.tokens):
            at = TOKENS + index * TOKEN_STRIDE
            data = name.encode()
            memory.put_bytes(NAMES + 8 * index, data)
            memory.write(at, 8, tag)
            memory.write(at + 8, 8, value)
            memory.write(at + 0x38, 8, NAMES + 8 * index)
            memory.write(at + 0x40, 8, len(data))
            memory.write(at + 0x48, 1, sz)
            memory.write(at + 0x49, 1, wei)
        items = []
        extra = [(key, (7, 0, 9)) for key in range(100, 100 + case.crowd)]
        if case.held or case.hold:
            extra.append((case.base, (case.held, case.hold, 0x99)))
        for key, words in sorted(extra):
            items.append((struct.pack("<Q", key), struct.pack("<3Q", *words)))
        self.put_tree(RECORD + 0x10, BALANCE_TREE, items, case.height)
        self.put_tree(STATE + 0x408, SUPPLY_TREE, [(struct.pack("<Q", key), struct.pack("<Q", case.word if key == case.base else case.word ^ 0x5555)) for key in sorted(case.supplied)], case.height)
        self.put_tree(STATE + 0x38D0 + shift + 0x10, BOOK_TREE, [(struct.pack("<Q", key), struct.pack("<4Q", 0, 0, 0, 0)) for key in sorted(case.books)], case.height)
        px_text, sz_text = case.px_text, case.sz_text
        if px_text is not None:
            memory.put_bytes(TEXTS, px_text.encode())
            memory.put_bytes(PX_STRING, struct.pack("<3Q", len(px_text), TEXTS, len(px_text)))
            memory.put_bytes(TEXTS + 0x100, sz_text.encode())
            memory.put_bytes(SZ_STRING, struct.pack("<3Q", len(sz_text), TEXTS + 0x100, len(sz_text)))
        self.fixed = set(self.live)

    def enter(self):
        case, copy, machine, memory = self.case, self.copy, self.machine, self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x70)
        if case.entry == "band":
            value = machine.run(BAND, {RDI: case.lo, RSI: case.hi, RDX: case.v})
            return ("band", value & 0xFF)
        if case.entry == "sum":
            memory.put_bytes(SCRATCH, b"".join(struct.pack("<3Q", 0x1111, 0x2222, px) for px in case.rows))
            memory.put_bytes(PARAM, struct.pack("<3Q", 8, SCRATCH, len(case.rows)))
            memory.write(PARAM + 0x20, 8, case.seeded)
            memory.write(PARAM + 0x28, 8, case.sz)
            memory.put_bytes(PARAM + 0x30, struct.pack("<3Q", PARAM, PARAM + 0x20, PARAM + 0x28))
            machine.keep_rdx = True
            value = machine.run(SUM, {RDI: PARAM + 0x30})
            high = machine.regs[RDX]
            machine.keep_rdx = False
            return ("sum", value & 1, high if value & 1 else 0)
        if case.entry == "body":
            memory.put_bytes(PARAM, struct.pack("<6Q", case.px, case.spot, case.sz, case.n, case.seeded, case.avail))
            machine.run(BODY, {RDI: OUT, RSI: STATE + 0x38D0, RDX: PARAM, RCX: STATE + 0x80, R8: ROWS + case.spot * ROW_STRIDE})
            return self.status()
        memory.write(STACK_TOP - 0x100, 8, case.n)
        memory.write(STACK_TOP - 0xF8, 8, case.seeded)
        machine.run(copy.handler, {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.spot, R8: PX_STRING, R9: SZ_STRING})
        return self.status()

    def status(self):
        memory = self.machine.memory
        tag = memory.read(OUT, 2)
        if tag == OK:
            return ("ok", memory.read(OUT + 8, 8)) if self.case.entry == "body" else ("ok",)
        if tag == TAG_TEXT:
            at, size = struct.unpack("<2Q", memory.bytes_at(OUT + 8, 16))
            self.expect(self.image.offset(at) >= 0, "static text")
            data = bytes(self.image.blob[self.image.offset(at):self.image.offset(at) + size])
            return ("error", tag, data.decode())
        return ("error", tag)

    def view(self):
        case, memory = self.case, self.machine.memory
        nodes = []
        root, level, size = struct.unpack("<3Q", memory.bytes_at(STATE + 0x38D0 + self.copy.shift + 0x10, 24))
        rows, used = self.walk(BOOK_TREE, root, level)
        self.expect(len(rows) == size, "tree length word")
        nodes.extend(used)
        books = []
        blocks = []
        for key, value in rows:
            cap, ptr, count, order = struct.unpack("<4Q", value)
            if struct.unpack("<Q", key)[0] in case.books:
                continue
            if cap == HIGH:
                books.append((struct.unpack("<Q", key)[0], "none"))
                continue
            self.expect(self.live.get(ptr) == cap * 24 and count <= cap, "book vector block")
            blocks.append(ptr)
            levels = [struct.unpack("<3Q", memory.bytes_at(ptr + 24 * index, 24)) for index in range(count)]
            self.expect(all(row[0] == 0 for row in levels), "level head word")
            books.append((struct.unpack("<Q", key)[0], tuple(row[2] for row in levels), order))
        state = dict(books=tuple(books), mark=memory.read(ROWS + case.spot * ROW_STRIDE + 0x78, 8) if case.spot < len(case.spots) else 0)
        state["token"] = tuple((memory.read(TOKENS + index * TOKEN_STRIDE, 8), memory.read(TOKENS + index * TOKEN_STRIDE + 8, 8)) for index in range(len(case.tokens)))
        return state, nodes, blocks

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        end = BUMP - HEAP_BASE
        before = bytes(memory.heap[:end])
        try:
            result = self.enter()
        except Panicked:
            result = ("panic",)
        state, nodes, blocks = self.view()
        now = bytearray(memory.heap[:end])
        skips = [(OUT, 0x70), (STATE + 0x38D0 + self.copy.shift + 0x10, 24), (PARAM, 0x60), (SCRATCH, 0x400)]
        skips.append((ROWS + case.spot * ROW_STRIDE + 0x78, 8))
        for index in range(len(case.tokens)):
            skips.append((TOKENS + index * TOKEN_STRIDE, 16))
        for start, size in skips:
            now[start - HEAP_BASE:start - HEAP_BASE + size] = before[start - HEAP_BASE:start - HEAP_BASE + size]
        rest = bytes(now) == before
        used = set(nodes) | self.fixed | set(blocks)
        leaked = [] if result == ("panic",) else sorted(block for block in self.live if block not in used)
        return dict(result=result, events=list(self.events), state=state, rest=rest, leaked=leaked)


def round_half_away(value):
    whole = math.floor(value)
    return whole + 1 if value - whole >= 0.5 and value != whole else whole


def to_u64_saturating(number):
    return TOP if number >= 1 << 64 else max(0, int(number))


def next_level(px):
    return to_u64_saturating(float(round_half_away(float(px) * RATIO)))


def spot_digits(px):
    return max(0, len(str(px)) - 5)


class Model:
    """Separately written rules; state starts from the case fields and is edited as the rules say."""

    def __init__(self, case):
        self.case = case
        self.events = []
        self.books = []
        self.mark = 0
        self.token = [(row[3], row[4]) for row in case.tokens]

    def tick(self, px):
        case = self.case
        if case.tick_hit & 1:
            return 1000
        base, quote = case.tokens[case.base], case.tokens[case.quote]
        if quote[2] < base[1]:
            raise Panicked("quote wei below base size decimals")
        return min(10 ** spot_digits(px), 10 ** (quote[2] - base[1]))

    def floor_tick(self, px):
        step = self.tick(px)
        return min(px // step * step, TOP)

    def ladder(self, px, count):
        rows = []
        current = max(self.floor_tick(px), 1)
        for _ in range(count):
            rows.append(current)
            current = max(self.floor_tick(max(next_level(current), 1)), 1)
        return rows

    def scaled(self, px):
        case = self.case
        token = case.tokens[case.base]
        divisor = 1 if case.base == 0 else 10 ** (token[2] - token[1])
        product = case.word * px
        if product <= TOP:
            return True, product // divisor
        value = case.word // divisor * px
        return value <= TOP, value

    def lazy(self):
        if self.case.once:
            self.events.append(("once",))

    def cap_ok(self, px, low, high):
        ok, value = self.scaled(px)
        if not ok:
            return False
        self.lazy()
        return band(low, high, value)

    def band_call(self):
        low, high = self.case.lo, self.case.hi
        if min(low * BAND_LOW, TOP) * 100 <= TOP and min(high * BAND_HIGH, TOP) * 100 <= TOP:
            self.lazy()

    def body(self, px, spot, sz, n, seeded, avail):
        case = self.case
        if n > MAX_ORDERS:
            return TOO_MANY
        if seeded > n:
            return CANNOT_SEED
        if spot in case.books:
            self.lazy()
            return EXISTS
        if spot >= len(case.spots):
            raise Panicked("spot index")
        base, quote = case.base, case.quote
        held = case.held if case.held or case.hold else 0
        hold = case.hold
        if held == 0 and n == 0:
            self.lazy()
            self.mark = px
            self.books.append((spot, "none"))
            return ("ok", 0)
        if hold:
            return HOLD
        if quote != 0:
            self.events.append(("note",))
            return QUOTE
        if base not in case.supplied:
            self.events.append(("note",))
            return NO_SUPPLY
        if n < MIN_ORDERS:
            return TOO_FEW
        multiplier = 1.0
        for _ in range(n):
            multiplier *= RATIO
        whole = math.ceil(multiplier)
        if sz * n > LIMIT or whole > 1000000:
            return CONFIG
        step = px * whole
        if step > LIMIT or sz * step > LIMIT:
            return CONFIG
        if sz == 0:
            return ZERO_SZ
        token = case.tokens[base]
        if token[2] < token[1]:
            raise Panicked("wei decimals below size decimals")
        need = min((n - seeded) * sz, TOP)
        wei = need * 10 ** (token[2] - token[1])
        if wei > TOP or wei != held:
            self.events.append(("note",))
            return BAD_BALANCE
        rows = self.ladder(px, n)
        first, last = rows[0], rows[-1]
        if first * sz < 1000000:
            return SMALL_VALUE
        if first == last:
            return SMALL_PX
        for price, low, high in ((last, END_LOW, END_HIGH), (first, START_LOW, START_HIGH)):
            if price > MAX_PX or price % self.tick(price):
                return BAD_PX
            if not self.cap_ok(price, low, high) and token[0] != "HYPE":
                return BAD_CAP
        total = 0
        for price in rows[:seeded]:
            value = price * sz
            if value > TOP or value > HIGH - 2:
                self.events.append(("note",))
                return NO_USDC
            total += value
            if total > TOP:
                self.events.append(("note",))
                return NO_USDC
        if total > avail:
            self.events.append(("note",))
            return NO_USDC
        self.lazy()
        self.mark = px
        self.books.append((spot, tuple(rows), sz))
        return ("ok", total)

    def handler(self):
        case = self.case
        spot = case.spot
        if spot >= len(case.spots):
            raise Panicked("spot index")
        parsed = parse_text(case.px_text)
        if parsed is None:
            return ("error", PARSE_TAG)
        base, quote = case.tokens[case.base], case.tokens[case.quote]
        digits = quote[2] - base[1]
        if digits < 0:
            raise Panicked("quote wei below base size decimals")
        px = scale_half_even(parsed, digits)
        if not px:
            return ("error", TAG_PX)
        parsed = parse_text(case.sz_text)
        if parsed is None:
            return ("error", PARSE_TAG)
        sz = scale_snap(parsed, base[1])
        if sz is None:
            return ("error", TAG_SZ)
        if sz != parsed * 10 ** base[1]:
            self.events.append(("note",))
        if not case.dex_rows:
            raise Panicked("empty dex list")
        if case.available > MAX_BALANCE:
            return ("error", TAG_TEXT, NO_CONVERT)
        status = self.body(px, spot, sz, case.n, case.seeded, case.available * 100)
        if not isinstance(status, tuple):
            return ("error", TAG_TEXT, status)
        total = status[1]
        amount = total // 100 + (1 if total % 100 else 0)
        if self.token[case.base][0] & 0xFF == 0:
            self.token[case.base] = (1, amount)
        if amount == 0:
            return ("ok",)
        self.events += [("dex",), ("scale", amount), ("send", amount + 7)]
        if case.send != OK:
            raise Panicked("send refused")
        self.events.append(("move", amount))
        if case.move != OK:
            raise Panicked("move refused")
        if case.proc == 1:
            self.events.append(("proc",))
        self.events.append(("event", to_bits(float(-amount) / 1000000.0)))
        return ("ok",)

    def final(self):
        case = self.case
        return dict(books=tuple(self.books), mark=self.mark if self.books else (0x4D4D if case.spot < len(case.spots) else 0), token=tuple(self.token))


def band(low, high, value):
    first = min(low * BAND_LOW, TOP) * 100
    second = min(high * BAND_HIGH, TOP) * 100
    return first <= TOP and second <= TOP and first <= value <= second


def parse_text(text):
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", text) or len(text.replace(".", "").lstrip("0")) > 28:
        return None
    return fractions.Fraction(text)


def half_even(value):
    whole = value.numerator // value.denominator
    rest = value - whole
    half = fractions.Fraction(1, 2)
    return whole + 1 if rest > half or (rest == half and whole & 1) else whole


def scale_half_even(value, digits):
    number = half_even(value * 10 ** digits)
    return number if number <= HIGH - 2 else 0


def scale_snap(value, digits):
    scaled = value * 10 ** digits
    number = half_even(scaled)
    if abs(scaled - number) >= fractions.Fraction(1, 1000) or number > HIGH - 2:
        return None
    return number


def spec_for(case):
    model = Model(case)
    try:
        if case.entry == "band":
            result = ("band", int(band(case.lo, case.hi, case.v)))
            model.band_call()
        elif case.entry == "sum":
            total, ok = 0, 1
            for price in case.rows[:case.seeded]:
                value = price * case.sz
                total += value
                if value > HIGH - 2 or total > TOP:
                    ok = 0
                    break
            result = ("sum", ok, total if ok else 0)
        elif case.entry == "body":
            status = model.body(case.px, case.spot, case.sz, case.n, case.seeded, case.avail)
            result = status if isinstance(status, tuple) else ("error", TAG_TEXT, status)
        else:
            result = model.handler()
    except Panicked:
        result = ("panic",)
    return dict(result=result, events=model.events, state=model.final())


def same(case, got, want):
    return got["result"] == want["result"] and got["events"] == want["events"] and got["state"] == want["state"] and got["rest"] and not got["leaked"]


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s:\n got %.500r %.300r rest %s leaked %r\nwant %.500r %.300r" % (case.name, got["result"], (got["events"], {k: v if k != "books" else [(b[0], (len(b[1]), b[1][:3], b[1][-2:]) if isinstance(b[1], tuple) else b[1]) + b[2:] for b in v] for k, v in got["state"].items()}), got["rest"], got["leaked"], want["result"], (want["events"], {k: v if k != "books" else [(b[0], (len(b[1]), b[1][:3], b[1][-2:]) if isinstance(b[1], tuple) else b[1]) + b[2:] for b in v] for k, v in want["state"].items()})))
        outcomes.append(got)
    return outcomes


PARSE_TAG = 0xAC
TEST_TOKENS = (("USDC", 8, 8, 0, 0), ("TEST", 2, 8, 0, 0), ("BASE", 3, 7, 0, 0), ("QUOT", 2, 6, 0, 0), ("HYPE", 2, 8, 0, 0), ("OTHR", 0, 2, 0, 0))
HYPE_SPOTS = ((5, 0), (4, 0), (2, 3), (1, 0))
MAX_LAND = 973400584789000


def hype(name, **fields):
    fields.setdefault("spots", HYPE_SPOTS)
    return Case(name, **fields)


def base_cases():
    out = []
    add = out.append
    add(hype("body smallest good ladder"))
    add(hype("body seeded two levels", seeded=2))
    add(hype("body all levels seeded", seeded=10))
    add(hype("body orders above the bound", n=4001))
    add(hype("body orders at the bound", n=4000, px=1000000, sz=1))
    add(hype("body seeded above orders", seeded=11))
    add(hype("body book exists", books=(1,)))
    add(hype("body other book present", books=(0, 2)))
    add(hype("body spot past the list", spot=7, spots=HYPE_SPOTS))
    add(hype("body no orders and no balance", n=0, held=0))
    add(hype("body no orders no balance any quote", n=0, held=0, spot=2))
    add(hype("body no orders no balance seeded above", n=0, seeded=1, held=0))
    add(hype("body no orders but a balance", n=0, held=5))
    add(hype("body hold word set", hold=3))
    add(hype("body hold with no balance and no orders", n=0, held=0, hold=9))
    add(Case("body quote is not token zero", spot=2, held=1))
    add(hype("body base missing from supply map", supplied=(0, 2, 3)))
    add(hype("body nine orders", n=9))
    add(hype("body size times orders at limit", sz=LIMIT // 10, n=10, px=1, held=0))
    add(hype("body size times orders past limit", sz=LIMIT // 10 + 1, n=10, px=1, held=0))
    add(hype("body size times orders wraps", sz=1 << 62, n=10, held=0))
    add(hype("body px times multiple at limit", px=LIMIT // 2, sz=1, held=0))
    add(hype("body px times multiple past limit", px=LIMIT // 2 + 1, sz=1, held=0))
    add(hype("body px times multiple wraps", px=1 << 63, sz=1, held=0))
    add(hype("body third product past limit", px=1 << 40, sz=1 << 24, held=0))
    add(hype("body third product wraps", px=1 << 44, sz=1 << 19, n=10, held=0))
    add(hype("body zero size", sz=0, held=0))
    add(hype("body balance one short", held=999999999 * 1 + 0))
    add(hype("body balance one above", held=1000000001))
    add(hype("body balance product overflows", sz=1 << 40, px=1, n=100, held=7))
    add(hype("body exact balance with crowd", crowd=14, height=2, stale=2))
    add(hype("body balance tree stale keys", crowd=3, stale=1))
    add(hype("body value one under a dollar", px=999999, sz=1))
    add(hype("body value exactly a dollar", px=1000000, sz=1))
    add(hype("body price below the first rise", px=166000, sz=100, tick_hit=1))
    add(hype("body px 166 stuck", px=166, sz=10000))
    add(hype("body px 167 rises", px=167, sz=10000))
    add(hype("body px 1 stuck", px=1, sz=2000000))
    add(hype("body tick override floors to one", px=5, sz=1000000, tick_hit=1))
    add(hype("body tick override good", px=2000, sz=1000, tick_hit=1, n=20))
    add(hype("body tick override stuck", px=1000, sz=1000, tick_hit=1, n=10))
    add(hype("body five digit floor", px=1234567, sz=100))
    add(hype("body last level above max", px=MAX_PX - 1000000, sz=1, n=10))
    add(hype("body first level above max", px=MAX_PX + 1000000, sz=1, n=10))
    add(hype("body short tick ladder", px=999999, sz=2, n=10))
    add(hype("body seed fits exactly", seeded=2, avail=200301000 + 100000000 * 0))
    add(hype("body seed one short", seeded=2, avail=200299999))
    add(hype("body seed one over", seeded=2, avail=200300001))
    add(hype("body seed rows past signed limit", px=1 << 39, sz=1 << 24, seeded=1, n=10))
    add(Case("body cap not exempt fails at end", word=1))
    add(Case("body cap not exempt with zero word", word=0))
    good_word = 10 ** 15 // 2
    add(Case("body cap band passes", n=1450, px=2000000, sz=1, word=good_word))
    add(Case("body cap band end too low", n=1200, px=2000000, sz=1, word=good_word))
    add(Case("body cap band start too high", n=1450, px=2000000, sz=1, word=10 ** 15))
    add(Case("body cap band seeded", n=1450, px=2000000, sz=1, word=good_word, seeded=3))
    add(hype("body exempt name large word", word=TOP, px=1000000, sz=100))
    add(hype("body exempt name product overflow fallback", word=1 << 60, px=1000000, sz=100))
    for low, high, value in ((END_LOW, END_HIGH, 7 * 10 ** 16 - 1), (END_LOW, END_HIGH, 7 * 10 ** 16), (END_LOW, END_HIGH, 13 * 10 ** 18), (END_LOW, END_HIGH, 13 * 10 ** 18 + 1),
                             (START_LOW, START_HIGH, 0), (START_LOW, START_HIGH, 13 * 10 ** 14), (START_LOW, START_HIGH, 13 * 10 ** 14 + 1), (0, 0, 0), (0, 0, 1), (1 << 44, 1, 0), (1 << 44, 1 << 44, TOP),
                             (1 << 45, 1, 5), (1, 1 << 44, 5), (1, 1 << 45, 5), (TOP, 1, 1), (1, TOP, 1), (1 << 40, 1 << 40, 1 << 60)):
        add(Case("band %d %d %d" % (low, high, value), entry="band", lo=low, hi=high, v=value))
    for rows, seeded, sz in (((), 0, 5), ((3,), 0, 5), ((3, 4), 1, 5), ((3, 4), 2, 5), ((3, 4), 3, 5), ((HIGH - 2, 1), 1, 1), ((HIGH - 1, 1), 1, 1), ((HIGH, 1), 1, 1), ((1 << 32,), 1, 1 << 32), ((HIGH - 2, HIGH - 2, 1, 1, 5), 3, 1), ((HIGH - 2, HIGH - 2, 2), 3, 1), ((HIGH - 2, HIGH - 2, 3), 3, 1), ((HIGH - 2, HIGH - 2, HIGH - 2), 3, 1)):
        add(Case("sum %d rows %d seeded size %d first %d" % (len(rows), seeded, sz, rows[0] if rows else 0), entry="sum", rows=rows, seeded=seeded, sz=sz))
    add(hype("body size times orders exactly at limit", sz=LIMIT // 23, n=23, px=1, held=1))
    add(hype("body crowded book tree", books=(0, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), height=2))
    add(hype("body crowded book tree holds the spot", books=(0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), height=2, stale=1))
    for count, multiple in ((231, 3), (232, 3), (366, 4), (367, 4), (1000, 21), (1001, 21)):
        add(hype("body power edge %d" % count, n=count, px=LIMIT // multiple + 1, sz=1, held=1))
    add(hype("body last level at the price cap", px=MAX_LAND, sz=1, n=10, tick_hit=1))
    add(hype("body last level above the price cap", px=MAX_LAND + 1000, sz=1, n=10, tick_hit=1))
    edge = dict(spots=((1, 0), (1, 0)), tokens=(("USDC", 8, 8, 0, 0), ("EDGE", 8, 8, 0, 0)), supplied=(0, 1), px=2000, sz=1000, n=1430)
    add(Case("body end row low bound passes", word=70000000000000000 // 144239 + 1, **edge))
    add(Case("body end row low bound refuses", word=70000000000000000 // 144239, **edge))
    add(Case("body start row high bound passes", word=650000000000, **edge))
    add(Case("body start row high bound refuses", word=650000000001, **edge))
    far = dict(edge, n=3100)
    add(Case("body end row high bound passes", word=13000000000000000000 // 21460345, **far))
    add(Case("body end row high bound refuses", word=13000000000000000000 // 21460345 + 1, **far))
    add(hype("body lazy state set book exists", once=1, books=(1,)))
    add(hype("body lazy state set good", once=1))
    add(hype("body lazy state set no orders", once=1, n=0, held=0))
    add(Case("body lazy state set cap band", once=1, n=1450, px=2000000, sz=1, word=good_word))
    add(Case("band lazy state set", entry="band", lo=END_LOW, hi=END_HIGH, v=7 * 10 ** 16, once=1))
    for copy in range(3):
        name = "abc"[copy]
        common = dict(entry="handler", copy=copy, available=10 ** 8, px_text="1.0", sz_text="1", n=10)
        add(hype("handler %s no seed" % name, **common))
        add(hype("handler %s seeded" % name, seeded=2, **common))
        add(hype("handler %s seeded proc word" % name, seeded=2, proc=1, **dict(common, available=10 ** 9)))
        add(hype("handler %s preset token word" % name, seeded=1, tokens=(("USDC", 8, 8, 0, 0), ("TEST", 2, 8, 0, 0), ("BASE", 3, 7, 0, 0), ("QUOT", 2, 6, 0, 0), ("HYPE", 2, 8, 1, 55), ("OTHR", 0, 2, 0, 0)), **common))
        add(hype("handler %s balance at the cap" % name, seeded=0, **dict(common, available=MAX_BALANCE)))
        add(hype("handler %s balance past the cap" % name, seeded=0, **dict(common, available=MAX_BALANCE + 1)))
        add(hype("handler %s too poor to seed" % name, seeded=2, **dict(common, available=2)))
        add(hype("handler %s spot past the list" % name, spot=9, **common))
        add(hype("handler %s bad px text" % name, **dict(common, px_text="x1")))
        add(hype("handler %s bad sz text" % name, **dict(common, sz_text="1x")))
        add(hype("handler %s zero px" % name, **dict(common, px_text="0")))
        add(hype("handler %s px rounds to zero" % name, **dict(common, px_text="0.0000004")))
        add(hype("handler %s px half even down" % name, seeded=1, **dict(common, px_text="1.0000005")))
        add(hype("handler %s px half even up" % name, seeded=1, **dict(common, px_text="1.0000015")))
        add(hype("handler %s sz snap inside" % name, **dict(common, sz_text="1.0000099")))
        add(hype("handler %s sz snap outside" % name, **dict(common, sz_text="1.001")))
        add(hype("handler %s sz two places" % name, **dict(common, sz_text="1.25")))
        add(hype("handler %s no dex row" % name, dex_rows=0, **common))
        add(hype("handler %s px past the scale cap" % name, **dict(common, px_text="99999999999999")))
        add(hype("handler %s sz past the scale cap" % name, **dict(common, sz_text="999999999999999999")))
        add(hype("handler %s spot with a quote below base size" % name, spots=((5, 0), (4, 5), (2, 3), (1, 0)), tokens=(("USDC", 8, 8, 0, 0), ("TEST", 2, 8, 0, 0), ("BASE", 3, 7, 0, 0), ("QUOT", 2, 6, 0, 0), ("HYPE", 3, 8, 0, 0), ("OTHR", 0, 2, 0, 0)), **common))
        add(hype("handler %s send refused" % name, seeded=2, send=REFUSAL, **common))
        add(hype("handler %s move refused" % name, seeded=2, move=REFUSAL, **common))
        add(hype("handler %s no orders path" % name, held=0, **dict(common, n=0)))
        add(hype("handler %s body refusal keeps state" % name, books=(1,), **common))
        add(hype("handler %s seed fits exactly" % name, seeded=2, **dict(common, available=2003000)))
        add(hype("handler %s seed one short" % name, seeded=2, **dict(common, available=2002999)))
        add(hype("handler %s sum ends in 50" % name, seeded=1, sz=21, **dict(common, px_text="0.12345", sz_text="0.21")))
        add(hype("handler %s sum ends in 60" % name, seeded=1, sz=21, **dict(common, px_text="0.12346", sz_text="0.21")))
    return out


VECTORS = 300
MUTANT_VECTORS = 60
REACH_CAP = 12
SECOND_CAP = 20
THIRD_CAP = 30
MUTANT_STEP_LIMIT = 1500000


def lcg(seed):
    state = [seed]

    def next_value(bound):
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state[0] >> 33) % bound
    return next_value


def vector_cases(count):
    out = []
    for index in range(count):
        pick = lcg(index * 2 + 1)
        kind = index % 5
        if kind == 0:
            low, high = (END_LOW, START_LOW, pick(1 << 45))[pick(3)], (END_HIGH, START_HIGH, pick(1 << 45))[pick(3)]
            value = (min(low * BAND_LOW * 100, TOP), min(high * BAND_HIGH * 100, TOP), pick(1 << 62))[pick(3)] + pick(3) - 1
            out.append(Case("vector %d" % index, entry="band", lo=low, hi=high, v=value & TOP))
            continue
        if kind == 1:
            rows = tuple((pick(1 << 40) + 1) * (1 << pick(24)) for _ in range(pick(6)))
            out.append(Case("vector %d" % index, entry="sum", rows=rows, seeded=pick(7), sz=pick(1 << 20) + 1))
            continue
        tick_hit = 1 if pick(6) == 0 else 0
        px = (pick(10 ** (pick(9) + 1)) + 1) * (1000 if tick_hit else 1)
        sz = pick(10 ** (pick(5) + 1)) + 1
        n = 10 + pick(40) if pick(5) else pick(12)
        seeded = pick(n + 2) if pick(2) else 0
        fields = dict(px=px, sz=sz, n=n, seeded=seeded, tick_hit=tick_hit, spots=HYPE_SPOTS if pick(4) else Case.DEFAULTS["spots"], word=pick(1 << 40), crowd=pick(14), height=pick(3), stale=pick(3))
        fields["avail"] = pick(1 << 40) * pick(1 << 12) if pick(2) else None
        if pick(8) == 0:
            fields["held"] = pick(1 << 30)
        if pick(8) == 0:
            fields["hold"] = pick(9)
        if pick(8) == 0:
            fields["books"] = (0, 1)[:1 + pick(2)]
        if pick(8) == 0:
            fields["supplied"] = (0, 2, 3, 5)
        if kind in (2, 3):
            out.append(Case("vector %d" % index, entry="body", **fields))
            continue
        digits = pick(7)
        whole = pick(1000) + 1
        part = pick(10 ** digits)
        fields.pop("px")
        fields.pop("sz")
        fields.pop("avail")
        px_text = "%d.%0*d" % (whole, digits, part) if digits else str(whole)
        sz_text = str(pick(50) + 1) + (".%02d" % pick(100) if pick(2) else "")
        out.append(Case("vector %d" % index, entry="handler", copy=pick(3), available=(pick(1 << 40), MAX_BALANCE + pick(2) - 1 + pick(2))[pick(4) == 0], px_text=px_text, sz_text=sz_text, px=scale_half_even(fractions.Fraction(px_text), 6), sz=scale_snap(fractions.Fraction(sz_text), 2) or 0, proc=pick(2), once=0, **fields))
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


SURVIVOR_GROUPS = (
    ("same: a bound test of a list index or a panic argument; the fixture keeps these lists in range, or the path ends in a panic either way", (0x274FD7C, 0x274FE59, 0x274FE74, 0x274FF6C, 0x274FFFC, 0x2750560, 0x27505DE, 0x2750642, 0x275061B, 0x32622A4, 0x3261F80)),
    ("same: the power is finite, positive and below 2^63 for n up to 4000, so the float to integer guards and the 1e6 bound never decide", (0x326202F, 0x3262040, 0x326205B, 0x3262069, 0x3262094, 0x32620B0, 0x32620EA)),
    ("same: the 32 bit divide path gives the same quotient", (0x3262353, 0x32639F3)),
    ("same: the first push reallocates before the initial vector words are read", (0x3263A2C, 0x3263A35, 0x3263A3E)),
    ("same: a level is positive and well below 2^63 here, the guards after the round never decide", (0x3263ADB, 0x3263AFE, 0x3263B0F, 0x3263B1A)),
    ("same: a saturated word times 100 still overflows and refuses", (0x32626A1, 0x32626AD, 0x32626B4, 0x32626BC)),
    ("same: the low bound of the start row cannot bind, the end row needs a value at most 1.6e5 times larger", (0x3262280,)),
    ("left to the named body edge cases: ladders of 1430 and 3100 levels are outside this sweep, and these immediates are pinned in constants.tsv", (0x326225D, 0x3262266, 0x326228C)),
    ("not compared: status bytes past the tag on a refusal path", (0x3261D42,)),
)


def survivor_reason(va, kind):
    for text, rows in SURVIVOR_GROUPS:
        if va in rows:
            return text
    return "open: no case of the sweep set separates this edit"



def status_copy(name, row):
    """A store of status object bytes past the tag to [rbx+disp] in a handler: stale frame bytes, not compared."""
    data = row.data
    if not name.startswith("handler"):
        return False
    return data.startswith((b"\x0f\x11\x43", b"\x0f\x11\x4b", b"\x0f\x11\x53", b"\x0f\x11\x5b", b"\x66\x0f\x11\x43", b"\x66\x89\x4b", b"\x66\x89\x43", b"\x89\x4b", b"\x89\x43"))


def run_mutants(image, table, seen, cases, vectors):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    chosen = [case for case in cases if case.n <= 300] + vectors
    if first_failure(control, chosen) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    for name in table:
        if name in ("handler_b", "handler_c"):
            continue
        for va, kind, patch in edits_for(image, [row for row in table[name] if not status_copy(name, row)], seen):
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
    ("ladder step", "three reference files disagree: `l1/hyperliquidity.rs` build_order_ladder rounds and snaps, `impl_spot_deploy.rs:500` and `handlers/26_spot_deploy.rs:539` use ceil with no tick", "the first is right: round half away from zero through slot 0x576f6d8, floor to the tick of the rounded value, at least 1", "body px 166 stuck"),
    ("first level and mark", "`impl_spot_deploy.rs:487` starts from the raw price; no file writes a spot row word", "the first level is the start price floored to its tick; the raw start price is written to spot row +0x78", "body five digit floor"),
    ("end price", "`ceil_scaled_price` takes ceil(px*ratio^n), `impl_spot_deploy.rs:467` compares it with the raw price cap", "ceil(ratio^n) is taken alone and multiplied as an integer, no end price is built: sz*n, the multiple (at most 1e6), px*multiple and sz*px*multiple must each stay within 0x1999999999999999", "body px times multiple past limit"),
    ("configuration product", "`hyperliquidity.rs:210` tests n*sz, the two other files test max_supply*sz", "n*sz is right; max supply is in no product of this gate", "body size times orders past limit"),
    ("order of gates", "`impl_spot_deploy.rs:437` quote then book then hold; `hyperliquidity.rs:198` zero size before the product, first==last before the value test", "book, hold, quote, supply presence, too few, four products, zero size, balance, ladder, value test, first==last, cap rows, seed sum", "body zero size"),
    ("market cap bounds", "`market_cap_in_scaled_range` scales by 7e7 and 1.3e8, while `validate_ladder_shape` and `impl_spot_deploy.rs:478` compare the exact text bounds", "the scaled helper is the only compare; the exact bound form does not exist in the bytes", "band 1000000000 100000000000 70000000000000000"),
    ("market cap value", "`raw_market_cap_usdc`: (px*supply)/1e8 in u128", "0x32814c0(max supply, base token, level price): floor(supply*px/10^(wei-sz)) when the product fits 64 bits, else checked floor(supply/10^(wei-sz))*px", "body cap band passes"),
    ("cap row price tests", "`validate_market_cap_windows` tests price zero and the raw cap", "each row also needs price % tick == 0, a zero price would end the loop with success, and the map value read is the max supply", "body tick override floors to one"),
    ("balance", "no such test in any file", "(n - seeded) * sz scaled to wei must equal the hyperliquidity user balance of the base token exactly, else its own text", "body balance one short"),
    ("no book path", "n_orders below 10 is refused", "n = 0 with no balance row value skips the quote, supply and later gates, writes the mark and inserts an empty book word", "body no orders no balance any quote"),
    ("seed sum refusal", "`hyperliquidity.rs:241` gives ConfigurationInvalid, `impl_spot_deploy.rs:496` divides by 10000", "px*sz is added with no division, and a refused sum gives the same `insufficient usdc` text as a short balance", "sum 2 rows 1 seeded size 1 first 9223372036854775807"),
    ("debit", "`available -= amount`, protocol account credited", "ceil(sum/100) is written once to token row +0/+8, then one call to 0x370d980 and one to the move core toward the hyperliquidity user; a refused call panics; the event carries the name USDC and -amount/1e6", "handler a move refused"),
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


def message_rows(image):
    rows = []
    for va, size, want in MESSAGES:
        at = image.offset(va)
        data = bytes(image.blob[at:at + size])
        if data != want.encode():
            raise EvidenceError("message at %#x" % va)
        rows.append(("%#x" % va, size, want))
    return rows


FLOATS = ((0x20A838, "<d", "level ratio 1.003"), (0x20A730, "<d", "start of the power product 1.0"))
WORDS = ((0x3261C74 + 3, "<I", 4000, "`cmp $0xfa0,%r13`: largest order count"), (0x3261EEF + 3, "<B", 10, "`cmp $0xa,%r13`: smallest order count"), (0x32620EA + 3, "<I", 1000000, "`cmp $0xf4240,%rcx`: largest power multiple"),
         (0x32620D7 + 2, "<Q", LIMIT, "product limit of the four configuration tests"), (0x326230F + 2, "<Q", MAX_PX, "largest level price at the two cap rows"), (0x3262606 + 1, "<I", BAND_LOW, "low band factor before *100"), (0x326262A + 1, "<I", BAND_HIGH, "high band factor before *100"),
         (0x326225D + 5, "<I", END_LOW, "end row low bound"), (0x3262266 + 2, "<Q", END_HIGH, "end row high bound"), (0x326228C + 8, "<I", START_HIGH, "start row high bound"), (0x32621A7 + 2, "<I", 1000000, "smallest first level value"))


def constant_rows(image):
    rows = []
    for va, form, use in FLOATS:
        value = struct.unpack_from(form, image.blob, image.offset(va))[0]
        rows.append(("%#x" % va, repr(value), use))
    name = bytes(image.blob[image.offset(0x209E14):image.offset(0x209E14) + 4])
    if name != b"HYPE":
        raise EvidenceError("exempt name")
    rows.append(("0x209e14", name.decode(), "four byte name passed by the market cap fallback"))
    for va, form, want, use in WORDS:
        value = struct.unpack_from(form, image.blob, image.offset(va))[0]
        if value != want:
            raise EvidenceError("immediate at %#x: %#x" % (va, value))
        rows.append(("%#x" % va, "%#x" % value, use))
    return rows


def tag_rows(image):
    rows = []
    for tag in (TAG_TEXT, TAG_PX, TAG_SZ, PARSE_TAG):
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        rows.append(("%#x" % tag, "%#x" % arm, text_at(image, arm)))
    return rows


LOCATIONS = ((0x56F21F0, "bounds of a token or a spot row"), (0x56DF860, "ladder is empty, not reachable: n is at least 10 there"), (0x56F2270, "power of ten table end"), (0x56BD9F0, "scale helper call of copy a"), (0x57446A0, "scale helper call of copies b and c"))


def location_rows(image):
    relative = image.relative()
    rows = []
    for record, use in LOCATIONS:
        path, line, column = image.location(record, relative)
        rows.append(("%#x" % record, path, line, column, use))
    return rows


def caller_rows(image):
    """Every `ff 15 disp32` call of the body slot and every `e8 rel32` call of the three local helpers."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        va = base + at
        if va + 6 + struct.unpack_from("<i", text, at + 2)[0] == SLOT_BODY:
            rows.append(("body", "%#x" % SLOT_BODY, "%#x" % va, "%#x" % image.fde(va)[0]))
        at = text.find(b"\xff\x15", at + 1)
    for name, target in (("ladder", LADDER), ("seed_sum", SUM), ("cap_band", BAND)) + tuple(("handler_" + copy.name, copy.handler) for copy in COPIES):
        for at in range(len(text) - 5):
            if text[at] == 0xE8 and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                rows.append((name, "%#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, use in ((SLOT_BODY, "gate body"), (0x57747C8, "ceil of the power product"), (0x576F6D8, "round of each next level"), (0x5774768, "size to wei product"), (SLOT_TICK_LOOKUP, "tick override lookup, not read here"), (SLOT_RECORD, "balance record of a user"), (SLOT_BALANCE, "usdc balance read before the gate"), (SLOT_SCALE, "scale of the amount, merged in RE-004-usdc-ntl-scale-94"), (SLOT_SEND, "send of the amount"), (SLOT_SINK, "event sink")):
        rows.append(("%#x" % slot, "%#x" % relative[slot], use))
    return rows


def rise_rows():
    """Next level at tick 1, one row at each end of the stuck range."""
    rows = []
    last = None
    for px in range(1, 2001):
        moved = next_level(px) != px
        if moved != last:
            rows.append((px, next_level(px), "rises" if moved else "stuck"))
            last = moved
    return rows


def power_rows():
    rows = []
    product = 1.0
    for n in range(1, MAX_ORDERS + 1):
        product *= RATIO
        if n in (10, 100, 767, 768, 1000, 1419, 1420, 2000, 3000, 4000):
            rows.append((n, repr(product), math.ceil(product)))
    return rows


def subject_rows(image):
    return {name: rows_of(image, target) for name, target in FUNCTIONS.items()}


def copy_rows():
    return [(copy.name, "%#x" % copy.handler, "%#x" % copy.move, "%#x" % copy.location, "%#x" % (0x5C0 + copy.shift), "%#x" % (0x3388 + copy.shift), "%#x" % (0x38D0 + copy.shift)) for copy in COPIES]


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
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), messages=message_rows(image), tags=tag_rows(image), copies=copy_rows(), locations=location_rows(image), callers=caller_rows(image), slots=slot_rows(image), rises=rise_rows(), powers=power_rows())
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def cell(value):
    if isinstance(value, bytes):
        return value.hex() if len(value) <= 40 else "%d bytes %s" % (len(value), hashlib.sha256(value).hexdigest()[:16])
    if isinstance(value, int):
        return "%#x" % (value & TOP) if value < 0 else "%#x" % value
    if isinstance(value, (tuple, list)):
        if len(value) > 16:
            return "%d items %s" % (len(value), hashlib.sha256(repr(value).encode()).hexdigest()[:16])
        return "(" + " ".join(cell(part) for part in value) + ")"
    return str(value)


def outcome_row(case, got):
    state = got["state"]
    return (case.name, cell(got["result"]), cell(state["books"]), cell(state["mark"]), cell(state["token"][case.base] if case.base < len(state["token"]) else ()), "; ".join(cell(event) for event in got["events"]) if len(got["events"]) <= 24 else "%d events" % len(got["events"]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "value", "meaning"), result["constants"])
    tsv("messages.tsv", ("address", "length", "text"), result["messages"])
    tsv("tag-texts.tsv", ("tag", "display arm", "display text"), result["tags"])
    tsv("locations.tsv", ("record", "path", "line", "column", "use"), result["locations"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "handler", "move core", "scale location", "balance list field", "spot row field", "book map field"), result["copies"])
    tsv("callers.tsv", ("callee", "slot or address", "call site", "function"), result["callers"])
    tsv("slots.tsv", ("slot", "target", "use"), result["slots"])
    tsv("rise-table.tsv", ("price", "next level at tick 1", "state"), result["rises"])
    tsv("power-table.tsv", ("orders", "product of 1.003", "ceil"), result["powers"])
    tsv("outcomes.tsv", ("case", "result", "book", "spot row mark", "base token word", "callee events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
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
        summary["status_copy_rows_not_edited"] = sum(1 for name in result["table"] for row in result["table"][name] if status_copy(name, row))
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

