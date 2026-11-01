#!/usr/bin/env python3
"""Pin the node #94 SetGlobal oracle action path: three handler copies, the price row collect, the price map and the history ring.

Real rows run from the handler in all three copies with real decimal parsing, tree, time and vector code. A separately written
rule list predicts every result, callee argument, row and written word, and every reached conditional row, immediate and field
offset of the subject code is edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/set_global_oracle.py --out <dir>
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
        if two == 0xC5 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pextrw", ("r", reg), rm, 4, target=value)
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
TAG_BOUND, TAG_POSITIVE, TAG_SIGNER, TAG_UNKNOWN, TAG_FLOAT, PARSE_TAG = 0x143, 0x77, 0x94, 0x64, 0xAB, 0xAC
OK_BYTE, ERROR_BYTE = 0xB, 0xE
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_SIGNER = 0x5773148
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048, 0x576EB38, 0x576E1B0)
MARK_BASE = 0x7700000000
STATUS_DROP = 0x3379490
TOP = MASK[8]
NONE = 1 << 63
MAX_ITEMS, MAX_TEXT = 10000, 100
KEEP, KEEP_SECONDS = 100, 300
DAY = 86400
PACK = 10000
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
OUT = HEAP_BASE + 0x40
USER = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
DEX = HEAP_BASE + 0x400
BUMP = STATE + STATE_SIZE
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
WHO = bytes(range(1, 21))
SIGNER_WORD = 0x51525354
ROW_SIZE = 0x60
ENTRY_SIZE = 0x28
ITEM_SIZE = 0x30
OUT_ROW = 0x3C
RESULT_ROW = 0x18
UNIT_STRIDE = 0x30
DEX_STRIDE = 0x2F0
TABLE_STRIDE = 0x138
BOOK_STRIDE = 0xD8
REFRESH_SECONDS = 10
MAIN_MODE = 3
SZ_LIMIT = 7
SLOT_RECORDER = 0x5773190
LABEL = HEAP_BASE + 0x500
POINT = HEAP_BASE + 0x560
ROW_USED = (range(0, 0x1C), range(0x20, 0x3C), range(0x40, 0x5C))

AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


TEXT_TREE = Layout(8, 0x18, 0x110, 0x18, 0, 0x218, 0x21A, 0x220)


class Copy:
    def __init__(self, name, handler, step, shift, collect, fold, entry, insert, remove, push, refresh, builder, row, group, mark, stop):
        self.name, self.handler, self.step, self.shift, self.collect, self.fold, self.entry, self.insert, self.remove, self.push = name, handler, step, shift, collect, fold, entry, insert, remove, push
        self.refresh, self.builder, self.row, self.group, self.mark, self.stop = refresh, builder, row, group, mark, stop


COPIES = (Copy("a", 0x1F67B30, 0x27078A0, 0, 0x2512300, 0x26B7310, 0x1E82A80, 0x285F0E0, 0x28683E0, 0x25175C0, 0x2228A10, 0x2572180, 0x1E82600, 0x284DD30, 0x26E0660, 0x2228F78),
          Copy("b", 0x47B99B0, 0x4CF37F0, 0xA80, 0x486EDA0, 0x47BC2D0, 0x4ADEB40, 0x4939A20, 0x4942390, 0x454C7D0, 0x4711350, 0x4889CA0, 0x4ADE6C0, 0x493A300, 0x42FB970, 0x47118B8),
          Copy("c", 0x47B8DA0, 0x4CF94A0, 0, 0x486F7F0, 0x47BC9E0, 0x4ADEB40, 0x4939A20, 0x4942390, 0x454C7D0, 0x4710070, 0x4885C90, 0x4ADE6C0, 0x493A300, 0x42FB970, 0x47105D8))
FUNCTIONS = dict(clone_rows=0x3BC64B0)
for copy_row in COPIES[:2]:
    for field in ("handler", "collect", "fold", "entry", "insert", "remove", "push", "refresh", "builder", "row", "group"):
        FUNCTIONS[field + "_" + copy_row.name] = getattr(copy_row, field)
for field in ("handler", "collect", "fold", "refresh", "builder"):
    FUNCTIONS[field + "_c"] = getattr(COPIES[2], field)


class Dex:
    """One dex row of the refresh path: oracle raw words, book mark words and size decimals per asset."""

    def __init__(self, ident, szs, raws, marks=None, mode=0, last=None, changed=None, oracle_rows=None, book_rows=None):
        self.ident, self.szs, self.raws, self.mode, self.last = ident, szs, raws, mode, last
        self.marks = raws if marks is None else marks
        self.changed = len(szs) if changed is None else changed
        self.oracle_rows = len(raws) if oracle_rows is None else oracle_rows
        self.book_rows = len(self.marks) if book_rows is None else book_rows


class Case:
    DEFAULTS = dict(entry="handler", dexes=(), tables=None, tick=1, copy=0, pxs=(), ext=(), native=None, usdt=None, names=("BTC", "ETH", "SOL", "HYPE"), dex=0, dex_rows=1, auth=OK, step=OK, hist=(), room=None, head=0, now=((2025 << 13) | (100 << 4) | 6, 1000, 5), snapshot=2, pxs_word=None, ext_word=None, height=0, stale=0, result=1)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)
        if self.room is None:
            self.room = len(self.hist) + 1
        self.ext = tuple(sorted(self.ext, key=lambda item: item[0].encode()))


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000 and target not in HOOKED


HOOKED = {RESUME, STATUS_DROP}
for copy_row in COPIES:
    HOOKED |= {copy_row.step, copy_row.mark}
HOOKED.add(0x4EE3800)


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set), (SLOT_SIGNER, self.on_signer), (SLOT_RECORDER, self.on_recorder))
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
        machine.calls = {RESUME: self.on_panic, STATUS_DROP: self.on_drop_status}
        for copy in COPIES:
            machine.calls[copy.step] = self.on_step
            machine.calls[copy.mark] = self.on_mark
        machine.calls[0x4EE3800] = self.on_clock
        self.case = None
        self.copy = COPIES[0]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.kept = set()

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

    def on_signer(self, machine):
        regs, memory = machine.regs, machine.memory
        shift = self.copy.shift
        self.expect(regs[RSI] == STATE + 0x3840 + shift and memory.bytes_at(regs[RDX], 20) == WHO and regs[RCX] == SIGNER_WORD, "signer arguments")
        self.events.append(("signer",))
        memory.write(regs[RDI], 2, self.case.auth)

    def on_recorder(self, machine):
        self.events.append(("recorder", machine.regs[RDI] & 0xFF, machine.regs[RSI]))

    def on_clock(self, machine):
        self.expect(machine.regs[RDI] & 0xFF == 1, "clock id")
        self.events.append(("clock",))
        machine.regs[RAX] = 0x1234
        machine.regs[RDX] = 0x55

    def on_mark(self, machine):
        at = machine.regs[RDI]
        self.expect(at in self.book_marks, "mark row")
        self.events.append(("mark", self.book_marks[at]))
        machine.regs[RAX] = self.book_marks[at]

    def on_drop_status(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) in (0x141, self.case.auth), "dropped status")

    def on_step(self, machine):
        regs, memory = machine.regs, machine.memory
        refresh = self.case.entry == "refresh"
        self.expect(regs[RSI] == STATE and regs[R8] == (1 if refresh else 0) and regs[R9] == 0 and (refresh or regs[RDX] == 0), "timestep arguments")
        cap, ptr, count = struct.unpack("<3Q", memory.bytes_at(regs[RCX], 24))
        rows = []
        for index in range(count):
            data = memory.bytes_at(ptr + index * OUT_ROW, OUT_ROW)
            parts = []
            for at in (0, 0x14, 0x28):
                flag = struct.unpack_from("<I", data, at)[0]
                self.expect(flag in (0, 1), "row option flag")
                parts.append(decimal_value(data[at + 4:at + 20]) if flag else None)
            rows.append(tuple(parts))
        if cap:
            self.expect(self.live.pop(ptr, None) == cap * OUT_ROW, "row vector block")
        self.events.append(("timestep", regs[RDX], tuple(rows)) if refresh else ("timestep", tuple(rows)))
        out = regs[RDI]
        memory.write(out, 2, self.case.step)
        if self.case.step == OK:
            words = (0, 8, 0)
            if self.case.result:
                name = self.bump(3)
                memory.put_bytes(name, b"abc")
                block = self.bump(2 * RESULT_ROW)
                memory.put_bytes(block, struct.pack("<3Q", 3, name, 3) + struct.pack("<3Q", 0, 1, 0))
                words = (2, block, 2)
                self.kept = {name, block}
            memory.put_bytes(out + 8, struct.pack("<3Q", *words))
        regs[RAX] = out

    def node(self, layout, rows, size):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(rows))
        spare = rows[0][0] if self.case.stale and rows else b"\xfe" * layout.key_size
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

    def text(self, value):
        data = value.encode()
        at = self.bump(max(len(data), 1))
        self.machine.memory.put_bytes(at, data)
        return struct.pack("<3Q", max(len(data), 1), at, len(data))

    def option(self, value):
        return struct.pack("<3Q", NONE, 0x5050, 0x70) if value is None else self.text(value)

    def row_block(self, seed, count):
        if not count:
            return 8
        at = self.bump(count * ROW_SIZE)
        self.machine.memory.put_bytes(at, bytes((seed + index * 11) & 0xFF for index in range(count * ROW_SIZE)))
        return at

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.copy = COPIES[case.copy]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.kept = set()
        shift = self.copy.shift
        memory.put_bytes(USER, WHO)
        memory.put_bytes(STATE + 0x60, struct.pack("<3I", *case.now))
        memory.write(STATE + 0x580, 8, 0x4141414141414141)
        memory.write(STATE + 0x588, 8, 0x4242424242424242)
        memory.write(STATE + 0x5B8 + shift, 8, case.dex_rows)
        memory.write(STATE + 0x5C0 + shift, 8, DEX)
        memory.write(STATE + 0x5C8 + shift, 8, case.dex_rows)
        memory.write(STATE + 0x3888 + shift, 8, SIGNER_WORD)
        memory.write(DEX + 0x30, 8, case.dex)
        units = self.bump(max(len(case.names), 1) * UNIT_STRIDE)
        memory.write(DEX + 8, 8, units)
        memory.write(DEX + 0x10, 8, len(case.names))
        for index, name in enumerate(case.names):
            memory.put_bytes(units + index * UNIT_STRIDE, b"\x33" * 8 + self.text(name)[8:])
        snapshot = self.row_block(0x21, case.snapshot)
        memory.write(DEX + 0x60, 8, case.snapshot)
        memory.write(DEX + 0x68, 8, snapshot)
        memory.write(DEX + 0x70, 8, case.snapshot)
        self.snapshot = memory.bytes_at(snapshot, case.snapshot * ROW_SIZE) if case.snapshot else b""
        entries = self.bump(case.room * ENTRY_SIZE) if case.room else 8
        self.history = []
        for index, (date, secs, nanos, count) in enumerate(case.hist):
            at = entries + ((case.head + index) % case.room) * ENTRY_SIZE
            block = self.row_block(0x40 + index, count)
            memory.put_bytes(at, struct.pack("<3I", date, secs, nanos) + b"\x66" * 4 + struct.pack("<3Q", count, block, count))
            self.history.append(((date, secs, nanos), memory.bytes_at(block, count * ROW_SIZE) if count else b""))
        memory.put_bytes(STATE + 0x3590 + shift, struct.pack("<4Q", case.room, entries, case.head, len(case.hist)))
        memory.put_bytes(ACTION, struct.pack("<3Q", len(case.pxs), 0, len(case.pxs) if case.pxs_word is None else case.pxs_word))
        list_at = self.bump(max(len(case.pxs), 1) * ITEM_SIZE)
        memory.write(ACTION + 8, 8, list_at)
        for index, (oracle, mark) in enumerate(case.pxs):
            memory.put_bytes(list_at + index * ITEM_SIZE, self.option(oracle) + self.option(mark))
        memory.put_bytes(ACTION + 0x18, self.option(case.usdt))
        memory.put_bytes(ACTION + 0x30, self.option(case.native))
        items = [(self.text(name), self.text(value)) for name, value in case.ext]
        root, level = self.tree(TEXT_TREE, items, case.height)
        memory.put_bytes(ACTION + 0x48, struct.pack("<3Q", root, level, len(items) if case.ext_word is None else case.ext_word))
        self.book_marks = {}
        if case.entry == "refresh":
            self.refresh_fixture(case)
        self.fixed = set(self.live)

    def refresh_fixture(self, case):
        memory = self.machine.memory
        shift = self.copy.shift
        count = len(case.dexes)
        tables = count if case.tables is None else case.tables
        rows = self.bump(max(count, 1) * DEX_STRIDE)
        blocks = self.bump(max(tables, count, 1) * TABLE_STRIDE)
        memory.put_bytes(rows, b"\x44" * (max(count, 1) * DEX_STRIDE))
        memory.put_bytes(blocks, b"\x45" * (max(tables, count, 1) * TABLE_STRIDE))
        memory.write(STATE + 0x5C0 + shift, 8, rows)
        memory.write(STATE + 0x5C8 + shift, 8, count)
        memory.write(STATE + 0x3370 + shift, 8, blocks)
        memory.write(STATE + 0x3378 + shift, 8, tables)
        memory.put_bytes(LABEL, b"\x13" * 0x20 + bytes([case.tick]))
        memory.put_bytes(POINT, struct.pack("<3I", *case.now))
        for index, dex in enumerate(case.dexes):
            at = rows + index * DEX_STRIDE
            size = len(dex.szs)
            units = self.bump(max(size, 1) * UNIT_STRIDE)
            memory.put_bytes(units, b"\x46" * (max(size, 1) * UNIT_STRIDE))
            for slot, sz in enumerate(dex.szs):
                memory.write(units + slot * UNIT_STRIDE + 0x2A, 1, sz)
            memory.write(at + 8, 8, units)
            memory.write(at + 0x10, 8, size)
            memory.write(at + 0x30, 8, dex.ident)
            memory.write(at + 0x230, 1, dex.mode)
            memory.write(at + 0x280, 8, dex.changed)
            last = dex.last if dex.last is not None else (case.now[0] - 0x10, case.now[1], case.now[2])
            memory.put_bytes(at + 0x2E0, struct.pack("<3I", *last))
            prices = self.bump(max(dex.oracle_rows, 1) * ROW_SIZE)
            memory.put_bytes(prices, b"\x47" * (max(dex.oracle_rows, 1) * ROW_SIZE))
            for slot, raw in enumerate(dex.raws[:dex.oracle_rows]):
                memory.write(prices + slot * ROW_SIZE, 8, raw)
            memory.write(at + 0x68, 8, prices)
            memory.write(at + 0x70, 8, dex.oracle_rows)
            book = self.bump(max(dex.book_rows, 1) * BOOK_STRIDE)
            memory.put_bytes(book, b"\x48" * (max(dex.book_rows, 1) * BOOK_STRIDE))
            table = blocks + index * TABLE_STRIDE
            memory.write(table + 8, 8, book)
            memory.write(table + 0x10, 8, dex.book_rows)
            for slot, mark in enumerate(dex.marks[:dex.book_rows]):
                self.book_marks[book + slot * BOOK_STRIDE] = mark

    def enter(self):
        case, memory = self.case, self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x70)
        if case.entry == "refresh":
            self.machine.stops = (self.copy.stop,)
            value = self.machine.run(self.copy.refresh, {RDI: LABEL, RSI: STATE, RDX: POINT})
            self.machine.stops = ()
            return ("idle",) if value is not None else ("done",)
        self.machine.run(self.copy.handler, {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
        kind = memory.read(OUT, 1)
        if kind == OK_BYTE:
            cap, ptr, count = struct.unpack("<3Q", memory.bytes_at(OUT + 8, 24))
            return ("ok", cap, count, ptr in self.kept or (cap == 0 and ptr == 8))
        self.expect(kind == ERROR_BYTE, "out kind byte")
        tag = memory.read(OUT + 8, 2)
        if tag == TAG_BOUND:
            return ("error", tag, self.field_name(memory.read(OUT + 0x10, 8)))
        return ("error", tag)

    def field_name(self, at):
        memory, case = self.machine.memory, self.case
        for name, place in (("pxs", ACTION), ("usdtUsdcPx", ACTION + 0x18), ("nativePx", ACTION + 0x30), ("externalPerpPxs", ACTION + 0x48)):
            if at == place:
                return name
        return "other"

    def view(self):
        case, memory = self.case, self.machine.memory
        shift = self.copy.shift
        room, entries, head, count = struct.unpack("<4Q", memory.bytes_at(STATE + 0x3590 + shift, 32))
        rows, blocks = [], []
        for index in range(count):
            at = entries + ((head + index) % room) * ENTRY_SIZE
            date, secs, nanos = struct.unpack("<3I", memory.bytes_at(at, 12))
            cap, ptr, used = struct.unpack("<3Q", memory.bytes_at(at + 0x10, 24))
            self.expect(cap == used, "history vector words")
            data = memory.bytes_at(ptr, used * ROW_SIZE) if used else b""
            if used:
                self.expect(self.live.get(ptr) == cap * ROW_SIZE, "history vector block")
                blocks.append(ptr)
            rows.append(((date, secs, nanos), masked(data)))
        if room and entries != 8:
            self.expect(self.live.get(entries) == room * ENTRY_SIZE, "history ring block")
            blocks.append(entries)
        state = dict(native=memory.read(STATE + 0x588, 8), usdt=memory.read(STATE + 0x580, 8), history=tuple(rows))
        return state, blocks

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        end = BUMP - HEAP_BASE
        before = bytes(memory.heap[:end])
        try:
            result = self.enter()
        except Panicked:
            result = ("panic",)
        state, blocks = self.view()
        now = bytearray(memory.heap[:end])
        for start, size in ((OUT, 0x70), (STATE + 0x580, 16), (STATE + 0x3590 + self.copy.shift, 32)):
            now[start - HEAP_BASE:start - HEAP_BASE + size] = before[start - HEAP_BASE:start - HEAP_BASE + size]
        rest = bytes(now) == before
        used = self.fixed | set(blocks)
        if result[0] == "ok":
            used |= self.kept
        leaked = [] if result == ("panic",) else sorted(block for block in self.live if block not in used and block not in self.fixed)
        return dict(result=result, events=list(self.events), state=state, rest=rest, leaked=leaked)


def masked(data):
    out = bytearray()
    for start in range(0, len(data), ROW_SIZE):
        row = data[start:start + ROW_SIZE]
        for part in ROW_USED:
            out += row[part.start:part.stop]
    return bytes(out)


def decimal_value(data):
    flags, high, low, middle = struct.unpack("<4I", data)
    number = (high << 64) | (middle << 32) | low
    value = fractions.Fraction(number, 10 ** ((flags >> 16) & 0xFF))
    return -value if flags >> 31 else value


ODD_TEXTS = {"1e3": fractions.Fraction(1000), "1_000": fractions.Fraction(1000), "1_0.5": fractions.Fraction(21, 2), ".5": fractions.Fraction(1, 2), "5.": fractions.Fraction(5), "+7": fractions.Fraction(7), "-0": fractions.Fraction(0), "": None, "abc": None, " 1": None, "1 ": None, "0x10": None, "1.2.3": None, "-": None, ".": None, "--1": None}


def parse_text(text):
    if text in ODD_TEXTS:
        return ODD_TEXTS[text]
    if not re.fullmatch(r"[+-]?[0-9]+(\.[0-9]+)?", text):
        return None
    value = fractions.Fraction(text)
    if abs(value) >= 1 << 96:
        return None
    return value


RECORD = 0x56E9AC8


def next_time(point, seconds):
    date, secs, nanos = point
    secs += seconds
    while secs >= DAY:
        secs -= DAY
        date += 0x10
    return date, secs, nanos


def older(point, now):
    return (point[0] if point[0] < 1 << 31 else point[0] - (1 << 32), point[1], point[2]) < (now[0] if now[0] < 1 << 31 else now[0] - (1 << 32), now[1], now[2])


class Model:
    """Separately written rules; state starts from the case fields and is edited as the rules say."""

    def __init__(self, case, snapshot, history):
        self.case = case
        self.events = []
        self.table = None
        self.native = 0x4242424242424242
        self.usdt = 0x4141414141414141
        self.history = [(point, masked(data)) for point, data in history]
        self.snapshot = masked(snapshot)

    def price(self, text, field="other"):
        if len(text.encode()) > MAX_TEXT:
            return ("error", TAG_BOUND, field)
        value = parse_text(text)
        if value is None:
            return ("error", PARSE_TAG)
        if value <= 0:
            return ("error", TAG_POSITIVE)
        return value

    def handler(self):
        case = self.case
        if case.dex_rows == 0:
            raise Panicked("no dex row")
        size = len(case.ext) if case.ext_word is None else case.ext_word
        if size > MAX_ITEMS:
            return ("error", TAG_BOUND, "externalPerpPxs")
        external = {}
        if case.ext and case.names and case.dex * PACK > TOP and any(len(name.encode()) <= MAX_TEXT for name, _ in case.ext):
            raise Panicked("packed id")
        for place, (name, text) in enumerate(case.ext):
            if len(name.encode()) > MAX_TEXT:
                return ("error", TAG_BOUND, "other" if place else "pxs")
            if name not in case.names:
                continue
            asset = case.dex * PACK + case.names.index(name)
            if len(text.encode()) > MAX_TEXT:
                return ("error", TAG_BOUND, "other")
            value = self.price(text)
            if isinstance(value, tuple):
                return value
            external[asset] = value
        if case.ext_word is not None and case.ext_word > len(case.ext):
            raise Panicked("tree walk past its end")
        size = len(case.pxs) if case.pxs_word is None else case.pxs_word
        if size > MAX_ITEMS:
            return ("error", TAG_BOUND, "pxs")
        rows = []
        for index, (oracle, mark) in enumerate(case.pxs):
            row = []
            for text in (oracle, mark):
                if text is None:
                    row.append(None)
                    continue
                value = self.price(text)
                if isinstance(value, tuple):
                    return value
                row.append(value)
            if case.dex * PACK > TOP:
                raise Panicked("packed id")
            row.append(external.pop(case.dex * PACK + index, None))
            rows.append(tuple(row))
        self.events.append(("signer",))
        if case.auth != OK:
            return ("error", TAG_SIGNER)
        self.events.append(("timestep", tuple(rows)))
        if case.step != OK:
            return ("error", case.step)
        for field, text in (("nativePx", case.native), ("usdtUsdcPx", case.usdt)):
            if text is None:
                continue
            if len(text.encode()) > MAX_TEXT:
                return ("error", TAG_BOUND, field)
            value = parse_text(text)
            if value is None:
                return ("error", PARSE_TAG)
            bits = to_bits(decimal_float(value))
            if field == "nativePx":
                self.native = bits
            else:
                self.usdt = bits
        self.history.append((tuple(case.now), self.snapshot))
        while len(self.history) > KEEP and older(next_time(self.history[0][0], KEEP_SECONDS), case.now):
            self.history.pop(0)
        return ("ok", 2, 2, True) if case.result else ("ok", 0, 0, True)

    def refresh(self):
        case = self.case
        if case.tick != 1:
            return ("idle",)
        self.events.append(("clock",))
        tables = len(case.dexes) if case.tables is None else case.tables
        if tables != len(case.dexes):
            self.events.append(("recorder", 5, RECORD))
        groups = {}
        for index, dex in enumerate(case.dexes[:min(tables, len(case.dexes))]):
            if dex.mode == MAIN_MODE:
                continue
            last = dex.last if dex.last is not None else (case.now[0] - 0x10, case.now[1], case.now[2])
            if older(tuple(case.now), next_time(last, REFRESH_SECONDS)):
                continue
            rows = []
            for slot in range(len(dex.szs)):
                if dex.ident * PACK + slot > TOP:
                    raise Panicked("packed id")
                if slot >= dex.oracle_rows:
                    raise Panicked("oracle row")
                if dex.szs[slot] >= SZ_LIMIT:
                    raise Panicked("size decimals")
                oracle = float_decimal(float(dex.raws[slot]) / 10.0 ** (6 - dex.szs[slot]))
                if slot >= dex.book_rows:
                    raise Panicked("book row")
                self.events.append(("mark", dex.marks[slot]))
                mark = float_decimal(float(dex.marks[slot]) / 10.0 ** (6 - dex.szs[slot]))
                rows.append((oracle, mark, None))
            groups[dex.ident] = tuple(rows)
        for ident in sorted(groups):
            self.events.append(("timestep", ident, groups[ident]))
        return ("done",)

    def final(self):
        return dict(native=self.native, usdt=self.usdt, history=tuple(self.history))


def float_decimal(value):
    """The route of RE-004-decimal-px-map-94: binary float to a 96-bit mantissa and a power of ten, one digit at a time."""
    bits = to_bits(value)
    field = (bits >> 52) & 0x7FF
    fraction = bits & ((1 << 52) - 1)
    if field == 0 and fraction == 0:
        return fractions.Fraction(0)
    mantissa = fraction | (1 << 52) if field else fraction
    two = field - 1075 if field else -1074
    power = 0
    while two > 0:
        mantissa <<= 1
        two -= 1
    while two < 0:
        if mantissa & 1 == 0:
            mantissa >>= 1
        elif mantissa >> 64 <= 0x33333333:
            mantissa *= 5
            power -= 1
        else:
            mantissa >>= 1
        two += 1
    while power < -28:
        mantissa = half_up_tenth(mantissa)
        power += 1
    while power < 0 and mantissa >= 1 << 52:
        mantissa = half_up_tenth(mantissa)
        power += 1
    while power < 0 and mantissa % 10 == 0:
        mantissa //= 10
        power += 1
    return fractions.Fraction(mantissa, 10 ** -power)


def half_up_tenth(number):
    whole, rest = divmod(number, 10)
    return whole + 1 if rest >= 5 else whole


def decimal_float(value):
    """rust_decimal style: whole part and fraction part convert apart, then add."""
    sign = -1.0 if value < 0 else 1.0
    magnitude = abs(value)
    whole = magnitude.numerator // magnitude.denominator
    part = magnitude - whole
    if not part:
        return sign * float(whole) if whole else 0.0
    digits = 0
    while (part * 10 ** digits).denominator != 1:
        digits += 1
    return sign * (float(whole) + float(int(part * 10 ** digits)) / float(10 ** digits))


def spec_for(case, harness):
    model = Model(case, harness.snapshot, harness.history)
    try:
        result = model.refresh() if case.entry == "refresh" else model.handler()
    except Panicked:
        result = ("panic",)
    return dict(result=result, events=model.events, state=model.final())


def same(case, got, want):
    return got["result"] == want["result"] and got["events"] == want["events"] and got["state"] == want["state"] and got["rest"] and not got["leaked"]


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case, harness)
        if not same(case, got, want):
            raise EvidenceError("case %s:\n got %.400r %.300r %.300r rest %s leaked %r\nwant %.400r %.300r %.300r" % (case.name, got["result"], got["events"], (got["state"]["native"], got["state"]["usdt"], len(got["state"]["history"])), got["rest"], got["leaked"], want["result"], want["events"], (want["state"]["native"], want["state"]["usdt"], len(want["state"]["history"]))))
        outcomes.append(got)
    return outcomes


DAY0 = (2025 << 13) | (100 << 4) | 6
DAY1 = DAY0 + 0x10
BEFORE = DAY0 - 0x10
EARLY = DAY0 - 0x100


def old_rows(count, point=(EARLY, 10, 0)):
    return tuple(point + (1,) for _ in range(count))


def stale(*dexes, **fields):
    return Case(fields.pop("name"), entry="refresh", dexes=dexes, **fields)


def refresh_cases():
    out = []
    add = out.append
    now = (DAY0, 1000, 5)
    add(stale(name="refresh tick word not one", tick=0))
    add(stale(name="refresh tick word two", tick=2, dexes=()) if False else stale(Dex(1, (2,), (1000,)), name="refresh tick word two with a stale dex", tick=2))
    add(stale(name="refresh no dex"))
    add(stale(Dex(1, (2,), (1234567,), (1234000,)), name="refresh one asset"))
    add(stale(Dex(1, (0, 1, 2, 3, 4, 5, 6), tuple(1234567 + slot for slot in range(7))), name="refresh all size decimals"))
    add(stale(Dex(1, (2,), (0,), (0,)), name="refresh zero words give zero prices"))
    add(stale(Dex(1, (6,), (1,), (2,)), name="refresh smallest words"))
    add(stale(Dex(1, (0,), (TOP,), (TOP,)), name="refresh largest words"))
    add(stale(Dex(1, (3,), (4096029,), (4096030,)), name="refresh inexact float route"))
    add(stale(Dex(1, (0,), (419430423,), (419430423,)), name="refresh inexact float at k six"))
    add(stale(Dex(1, (), ()), name="refresh dex with no asset"))
    add(stale(Dex(0, (2,), (10,), mode=3), Dex(1, (2,), (20,)), name="refresh skips the main mode"))
    add(stale(Dex(1, (2,), (10,), mode=2), Dex(2, (2,), (20,), mode=1), name="refresh takes other modes"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 990, 5)), name="refresh exactly ten seconds old"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 990, 6)), name="refresh ten seconds less a nano"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 990, 4)), name="refresh ten seconds and a nano"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 991, 5)), name="refresh nine seconds old"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 989, 5)), name="refresh eleven seconds old"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 86399, 5)), now=(DAY1, 9, 5), name="refresh ten seconds over midnight"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 86399, 5)), now=(DAY1, 8, 5), name="refresh nine seconds over midnight"))
    add(stale(Dex(1, (2,), (10,), last=(DAY1, 0, 0)), now=(DAY0, 80000, 0), name="refresh later date is fresh"))
    add(stale(Dex(1, (2,), (10,), last=(BEFORE, 1100, 0)), name="refresh earlier date with late seconds"))
    add(stale(Dex(1, (2,), (10,), last=(DAY0, 980, 0)), Dex(2, (2,), (20,), last=(DAY0, 999, 0)), Dex(3, (2,), (30,), last=(DAY0, 500, 0)), name="refresh only stale dexes"))
    add(stale(Dex(3, (2,), (30,)), Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), name="refresh steps in id order"))
    add(stale(Dex(1, (2,), (10,)), Dex(1, (2,), (77,)), name="refresh same id keeps the later rows"))
    add(stale(Dex(1, (2,), (10,)), name="refresh timestep refused", step=0x77))
    add(stale(Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), name="refresh goes on past a refused step", step=0x77))
    add(stale(Dex(1, (2,), (10,)), name="refresh no result list", result=0))
    add(stale(Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), name="refresh more tables than dexes", tables=3))
    add(stale(Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), name="refresh fewer tables than dexes", tables=1))
    add(stale(Dex(1, (2,), (10,)), name="refresh no tables", tables=0))
    add(stale(Dex(1, (2, 2), (10, 11), oracle_rows=1), name="refresh short oracle rows panic"))
    add(stale(Dex(1, (2, 2), (10, 11), book_rows=1), name="refresh short book rows panic"))
    add(stale(Dex(1, (7,), (10,)), name="refresh size decimals seven panics"))
    add(stale(Dex(1, (2, 9), (10, 11)), name="refresh second asset size nine panics"))
    add(stale(Dex(1, (6, 6), (10, 11)), name="refresh size six twice"))
    add(stale(Dex(1 << 52, (2,), (10,)), name="refresh id overflow panics"))
    add(stale(Dex(1 << 52, (), ()), name="refresh id overflow with no asset"))
    add(stale(Dex(1, tuple(2 for _ in range(12)), tuple(1000 + slot for slot in range(12)), changed=5), name="refresh changed word differs"))
    add(stale(Dex(1, (2,), (10,), changed=0), Dex(2, (2,), (20,), changed=0), Dex(3, (2,), (30,), changed=0), Dex(4, (2,), (40,), changed=0), Dex(5, (2,), (50,), changed=0), name="refresh five changed dexes grow the id list"))
    add(stale(*[Dex(index, (2,), (index + 1,)) for index in range(1, 14)], name="refresh thirteen dexes split the group tree"))
    add(stale(*[Dex(index % 3 + 1, (2,), (index + 1,)) for index in range(7)], name="refresh repeated ids replace groups"))
    return out


def base_cases():
    out = []
    add = out.append
    good = (("1", "2"),)
    add(Case("empty action"))
    add(Case("empty action copy b", copy=1))
    add(Case("empty action copy c", copy=2))
    add(Case("no dex row panics", dex_rows=0))
    add(Case("one row both prices", pxs=good))
    add(Case("one row oracle only", pxs=(("1.5", None),)))
    add(Case("one row mark only", pxs=((None, "1.5"),)))
    add(Case("one row no price", pxs=((None, None),)))
    add(Case("four rows copy b", copy=1, pxs=(("1", "2"), (None, "3"), ("4", None), (None, None))))
    add(Case("four rows copy c", copy=2, pxs=(("1", "2"), (None, "3"), ("4", None), (None, None))))
    add(Case("nine rows grow the row vector", pxs=tuple((str(index + 1), None) for index in range(9))))
    add(Case("external moves into its row", pxs=(("1", None), ("2", None)), ext=(("ETH", "7.25"),)))
    add(Case("external first row", pxs=(("1", None), ("2", None)), ext=(("BTC", "7.25"),)))
    add(Case("two externals and a leftover row", pxs=(("1", None), ("2", None)), ext=(("BTC", "3"), ("ETH", "4"), ("SOL", "5"))))
    add(Case("external with no pxs row is dropped", ext=(("HYPE", "9"),)))
    add(Case("external past the pxs rows copy b", copy=1, pxs=(("1", None),), ext=(("SOL", "9"),)))
    add(Case("external on a row with no prices", pxs=((None, None), (None, None)), ext=(("ETH", "4"),)))
    add(Case("dex id packs the key", dex=2, pxs=(("1", None), ("2", None)), ext=(("ETH", "4"),)))
    add(Case("dex id packs the key copy c", copy=2, dex=7, pxs=(("1", None), ("2", None)), ext=(("BTC", "4"),)))
    add(Case("names unknown are skipped", pxs=good, ext=(("DOGE", "1"),)))
    add(Case("unknown name with a bad price is skipped", pxs=good, ext=(("DOGE", "x"),)))
    add(Case("unknown name with a negative price is skipped", pxs=good, ext=(("DOGE", "-1"),)))
    add(Case("unknown name with a long price is skipped", pxs=good, ext=(("DOGE", "1" * 101),)))
    add(Case("empty universe skips every name", names=(), pxs=good, ext=(("BTC", "1"),)))
    add(Case("name prefix is not a match", pxs=good, ext=(("BT", "1"), ("BTCX", "2"))))
    add(Case("same length other name", pxs=good, ext=(("BTD", "1"),)))
    add(Case("first of two equal names wins", names=("AAA", "BBB", "AAA"), pxs=(("1", None), ("2", None), ("3", None)), ext=(("AAA", "6"),)))
    add(Case("name of 100 bytes", names=("N" * 100,), pxs=good, ext=(("N" * 100, "1"),)))
    add(Case("name of 101 bytes refused", pxs=good, ext=(("N" * 101, "1"),)))
    add(Case("name of 101 bytes after a good one", pxs=good, ext=(("BTC", "1"), ("Z" * 101, "1"))))
    add(Case("external price of 100 bytes", pxs=good, ext=(("BTC", "1" * 100),)))
    add(Case("usdt 100 bytes refused by parser", usdt="1" * 100))
    add(Case("external price of 101 bytes refused", pxs=good, ext=(("BTC", "1" * 101),)))
    add(Case("external price zero", pxs=good, ext=(("BTC", "0"),)))
    add(Case("external price negative", pxs=good, ext=(("BTC", "-3"),)))
    add(Case("external price text refused", pxs=good, ext=(("BTC", "x"),)))
    add(Case("oracle zero", pxs=(("0", None),)))
    add(Case("oracle zero with a scale", pxs=(("0.000", None),)))
    add(Case("oracle negative", pxs=(("-0.5", None),)))
    add(Case("oracle smallest positive", pxs=(("0.0000000000000000000000000001", None),)))
    add(Case("oracle text refused", pxs=(("x", None),)))
    add(Case("oracle 101 bytes", pxs=(("1" * 101, None),)))
    add(Case("oracle 100 bytes refused by parser", pxs=(("1" * 100, None),)))
    add(Case("mark zero", pxs=(("1", "0"),)))
    add(Case("mark negative", pxs=(("1", "-1"),)))
    add(Case("mark text refused", pxs=(("1", "x"),)))
    add(Case("mark 101 bytes", pxs=(("1", "1" * 101),)))
    add(Case("second row refused after a good row", pxs=(("1", "2"), ("0", None))))
    add(Case("refused row after an external was moved", pxs=(("1", "2"), ("0", None)), ext=(("BTC", "5"),)))
    add(Case("oracle checked before mark", pxs=(("0", "x"),)))
    add(Case("mark none with a stale pointer word", pxs=((None, "2"), ("3", None))))
    for text in ODD_TEXTS:
        add(Case("oracle text %r" % text, pxs=((text, None),)))
    add(Case("external list at the bound walks past the tree", pxs=good, ext=(("BTC", "1"),), ext_word=MAX_ITEMS))
    add(Case("external list above the bound", pxs=good, ext=(("BTC", "1"),), ext_word=MAX_ITEMS + 1))
    add(Case("pxs at the bound stops on its first row", pxs=(("0", None),), pxs_word=MAX_ITEMS))
    add(Case("pxs above the bound", pxs=(("1", None),), pxs_word=MAX_ITEMS + 1))
    add(Case("external bound comes first", pxs=(("1", None),), pxs_word=MAX_ITEMS + 1, ext=(("BTC", "1"),), ext_word=MAX_ITEMS + 1))
    add(Case("external refused before pxs bound", pxs=good, pxs_word=MAX_ITEMS + 1, ext=(("BTC", "0"),)))
    add(Case("signer refused", pxs=good, auth=0x97))
    add(Case("signer refused copy b", copy=1, pxs=good, auth=0x97))
    add(Case("signer refused empty rows", auth=0x97))
    add(Case("signer refused other status", pxs=good, auth=0x91))
    add(Case("bad price wins over signer", pxs=(("0", None),), auth=0x97))
    add(Case("signer refused keeps both words", pxs=good, auth=0x97, native="3", usdt="4"))
    add(Case("timestep refused", pxs=good, step=0x77))
    add(Case("timestep refused copy b", copy=1, pxs=good, step=0x77))
    add(Case("timestep refused keeps both words", pxs=good, step=0x63, native="3", usdt="4"))
    add(Case("native only", native="2.5"))
    add(Case("usdt only", usdt="1.0002"))
    add(Case("both words", native="39.5", usdt="0.9995"))
    add(Case("both words copy b", copy=1, native="39.5", usdt="0.9995"))
    add(Case("both words copy c", copy=2, native="39.5", usdt="0.9995"))
    add(Case("native zero is stored", native="0"))
    add(Case("native negative is stored", native="-2.5"))
    add(Case("usdt zero is stored", usdt="0"))
    add(Case("usdt negative is stored", usdt="-0.5"))
    add(Case("native 100 bytes refused by parser", native="1" * 100))
    add(Case("native 101 bytes", native="1" * 101, pxs=good))
    add(Case("usdt 101 bytes", usdt="1" * 101, pxs=good))
    add(Case("usdt 101 bytes copy b", copy=1, usdt="1" * 101))
    add(Case("native text refused drops the result", native="x", usdt="1"))
    add(Case("native refused keeps timestep event", native="x", pxs=good))
    add(Case("usdt refused after native stored", native="2", usdt="x"))
    add(Case("usdt 101 bytes after native stored", native="2", usdt="1" * 101))
    add(Case("usdt refused no result list", result=0, usdt="x"))
    add(Case("no result list", result=0))
    add(Case("large decimal to float", native="79228162514264337593543950335"))
    add(Case("small decimal to float", usdt="0.0000000000000000000000000001"))
    add(Case("empty snapshot", snapshot=0))
    add(Case("one snapshot row", snapshot=1))
    add(Case("five snapshot rows", snapshot=5))
    add(Case("push into a full ring grows it", hist=old_rows(4), room=4))
    add(Case("push into a full ring grows it copy b", copy=1, hist=old_rows(4), room=4))
    add(Case("push wraps around the ring", hist=old_rows(3), room=5, head=3))
    add(Case("push into a wrapped full ring", hist=old_rows(5), room=5, head=2))
    add(Case("first push on an empty ring", hist=(), room=0))
    add(Case("99 kept plus one is 100", hist=old_rows(99), room=120))
    add(Case("100 kept plus one drops one", hist=old_rows(100), room=120))
    add(Case("100 kept plus one copy b", copy=1, hist=old_rows(100), room=120))
    add(Case("100 kept plus one copy c", copy=2, hist=old_rows(100), room=120))
    add(Case("110 kept drops down to 100", hist=old_rows(110), room=120))
    add(Case("drop stops at a fresh row", hist=old_rows(101) + ((DAY0, 999, 0, 1),) * 3, room=120))
    add(Case("drop with a wrapped head", hist=old_rows(103), room=110, head=100))
    add(Case("old rows under the cap stay", hist=old_rows(50), room=60))
    add(Case("fresh rows over the cap stay", hist=((DAY0, 900, 0, 1),) * 110, room=120))
    add(Case("zero capacity row dropped", hist=old_rows(101), room=110))
    empty = tuple((EARLY, 10, 0, 0) for _ in range(101))
    add(Case("rows with empty vectors dropped", hist=empty, room=110))
    edge = (DAY0, 700, 5)
    add(Case("front exactly 300 s old stays", hist=(edge + (1,),) * 101, room=110))
    add(Case("front 300 s old less a nano stays", hist=((DAY0, 700, 6, 1),) * 101, room=110))
    add(Case("front 300 s and a nano old goes", hist=((DAY0, 700, 4, 1),) + (edge + (1,),) * 101, room=110))
    add(Case("front 301 s old goes", hist=((DAY0, 699, 5, 1),) + (edge + (1,),) * 101, room=110))
    add(Case("front 299 s old stays", hist=((DAY0, 701, 5, 1),) * 101, room=110))
    add(Case("front in the day before stays", now=(DAY1, 299, 5), hist=((DAY0, 86399, 5, 1),) * 101, room=110))
    add(Case("front in the day before goes", now=(DAY1, 299, 6), hist=((DAY0, 86399, 5, 1),) + ((DAY1, 200, 5, 1),) * 101, room=110))
    add(Case("front a later date stays", now=(BEFORE, 1000, 5), hist=((DAY0, 1, 0, 1),) * 101, room=110))
    add(Case("late seconds and earlier date goes", now=(DAY1, 5, 0), hist=((DAY0, 80000, 0, 1),) + ((DAY1, 4, 0, 1),) * 101, room=110))
    add(Case("exact wrap of front to the next day", now=(DAY1, 0, 0), hist=((DAY0, 86100, 0, 1),) * 101, room=110))
    many = tuple(("N%02d" % index, str(index + 1)) for index in range(40))
    add(Case("forty externals over a two level tree", names=tuple(name for name, _ in many), pxs=tuple((str(index + 1), None) for index in range(40)), ext=many, room=2))
    add(Case("thirteen externals copy b", copy=1, names=tuple(name for name, _ in many[:13]), pxs=tuple((str(index + 1), None) for index in range(13)), ext=many[:13]))
    add(Case("three externals in a three level tree", height=3, pxs=good, ext=(("BTC", "1"), ("ETH", "2"), ("SOL", "3"))))
    add(Case("three externals in an eight level tree", height=8, pxs=good, ext=(("BTC", "1"), ("ETH", "2"), ("SOL", "3"))))
    add(Case("long name in an inner node", names=tuple(name for name, _ in many[:13]), pxs=good, ext=many[:5] + (("N05" + "x" * 98, "1"),) + many[6:13]))
    add(Case("name of 100 bytes in an inner node", names=tuple(name for name, _ in many[:13]), pxs=good, ext=many[:5] + (("N05" + "x" * 97, "1"),) + many[6:13]))
    add(Case("stale keys in unused slots", stale=1, pxs=(("1", None), ("2", None)), ext=(("BTC", "1"), ("ETH", "2"))))
    add(Case("full run copy a", pxs=(("1", "2"), (None, "3")), ext=(("ETH", "9"), ("DOGE", "1")), native="31.5", usdt="1.001", hist=old_rows(100), room=120, dex=3))
    add(Case("full run copy b", copy=1, pxs=(("1", "2"), (None, "3")), ext=(("ETH", "9"), ("DOGE", "1")), native="31.5", usdt="1.001", hist=old_rows(100), room=120, dex=3))
    add(Case("full run copy c", copy=2, pxs=(("1", "2"), (None, "3")), ext=(("ETH", "9"), ("DOGE", "1")), native="31.5", usdt="1.001", hist=old_rows(100), room=120, dex=3))
    add(Case("dex id overflow on a row panics", dex=1 << 52, pxs=(("1", None),)))
    add(Case("dex id overflow on a name panics", dex=1 << 52, ext=(("BTC", "1"),)))
    add(Case("dex id overflow unused with no lists", dex=1 << 52))
    add(Case("dex id overflow names empty rows empty", dex=1 << 52, names=(), ext=(("BTC", "1"),)))
    add(Case("dex id overflow after bad first price", dex=1 << 52, pxs=(("0", None),), names=()))
    out.extend(refresh_cases())
    for copy in (1, 2):
        for case in tuple(out):
            if case.copy == 0:
                fields = {key: getattr(case, key) for key in Case.DEFAULTS}
                fields.update(copy=copy, room=case.room)
                out.append(Case(case.name + " on copy " + "abc"[copy], **fields))
    return out


VECTORS = 200
MUTANT_VECTORS = 40
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


def vector_text(pick):
    kind = pick(9)
    if kind == 0:
        return "0"
    if kind == 1:
        return "-%d" % (pick(1000) + 1)
    if kind == 2:
        return "x%d" % pick(10)
    digits = pick(5)
    whole = pick(100000)
    return "%d.%0*d" % (whole, digits, pick(10 ** digits)) if digits else str(whole + 1)


def vector_cases(count):
    out = []
    for index in range(count):
        pick = lcg(index * 2 + 1)
        names = tuple("U%d" % slot for slot in range(pick(7)))
        known = [slot for slot in range(len(names))]
        ext = {}
        for _ in range(pick(5)):
            name = names[pick(len(names))] if names and pick(4) else "Z%d" % pick(5)
            ext[name] = vector_text(pick) if pick(3) else str(pick(1000) + 1)
        pxs = tuple(tuple((vector_text(pick) if pick(5) == 0 else str(pick(100000) + 1)) if pick(4) else None for _ in range(2)) for _ in range(pick(7)))
        hist = []
        size = (0, 3, 100, 101, 104)[pick(5)]
        for slot in range(size):
            seconds = 1000 - (301 if pick(2) else 200)
            hist.append((0x4000, seconds - (size - slot), pick(3), pick(3)))
        hist.sort(key=lambda row: row[1])
        room = size + pick(8) + (0 if size else 1)
        fields = dict(copy=pick(3), names=names, ext=tuple(ext.items()), pxs=pxs, hist=tuple(hist), room=room, head=pick(room) if room else 0, dex=pick(4), snapshot=pick(4), auth=OK if pick(6) else 0x97, step=OK if pick(6) else 0x77, height=pick(3), stale=pick(2), result=pick(2))
        if pick(2):
            fields["native"] = (str(pick(1000)), "%d.5" % pick(1000), "x", "-1")[pick(4)]
        if pick(2):
            fields["usdt"] = (str(pick(1000)), "%d.25" % pick(1000), "y", "0")[pick(4)]
        out.append(Case("vector %d" % index, **fields))
        if index % 3 == 0:
            dexes = []
            for slot in range(pick(5)):
                size = pick(5)
                szs = tuple(pick(7) for _ in range(size))
                raws = tuple(pick(1 << 44) for _ in range(size))
                dexes.append(Dex(pick(4), szs, raws, tuple(pick(1 << 44) for _ in range(size)), mode=pick(4), last=(DAY0, 985 + pick(30), pick(10)), changed=pick(9)))
            out.append(Case("refresh vector %d" % index, entry="refresh", dexes=tuple(dexes), copy=pick(3), step=OK if pick(4) else 0x77, result=pick(2)))
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
            if not same(case, harness.run(case), spec_for(case, harness)):
                return case
        except AccessError:
            return case
    return None


def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


STALE_BYTES = {0x25123C7, 0x25123D3, 0x25123F7, 0x25123FB, 0x25123FF, 0x2512629, 0x2512635, 0x2512659, 0x251265D, 0x2512661, 0x26B74CE, 0x26B74DB, 0x26B74E4, 0x26B74EB, 0x26B74EF, 0x26B74F3, 0x26B74F7, 0x26B74FE, 0x26B7502, 0x26B750B, 0x26B7517,
               0x1E82DBE, 0x1E82DC2, 0x1E82DC9, 0x1E82DD1, 0x1E82DD6, 0x1E82DDB, 0x1E82DE0, 0x1E82DE4, 0x1E82DE8, 0x1E82DEC, 0x1E82DF0, 0x1E82DF4, 0x1F68176, 0x1F6834F, 0x1F68567}
RANGE_ONLY = {0x1F681FB, 0x1F68208, 0x1F68232, 0x2228B7E, 0x2228B8B, 0x2228BBF}
NO_READ = {0x2228CA0, 0x2228CA4, 0x2228CAB, 0x2228A76, 0x2228D22}
UNREACHED_VALUE = {0x1E8268E, 0x1E826D3, 0x1E826E3, 0x1E82730, 0x1E82797, 0x1E8279B, 0x1E827B8, 0x1E82773, 0x1E828D8, 0x1E82929, 0x1E8296C, 0x1E82991, 0x1E82995, 0x1E829B2}
FIRST_ERROR = {0x26B74B2, 0x26B74B9}


def survivor_reason(va, kind):
    if va in STALE_BYTES:
        return "same: bytes of a status object behind the tag; tags are compared, these payload bytes are not"
    if va in RANGE_ONLY:
        return "same on any date the fixture can hold: range window and sign word of the time add"
    if va in NO_READ:
        return "same: the id list and its compare are never read"
    if va in UNREACHED_VALUE:
        return "same: non-finite and subnormal arms, and the unused error tag, cannot be reached from a u64 over a power of ten"
    if va in FIRST_ERROR:
        return "same: a collect stops at the first error, so the status slot still holds the ok tag"
    return "not killed by the sampled cases; not argued equivalent"



def status_copy(name, row):
    """A store of status object bytes past the tag to [rbx+disp] in a handler: frame bytes the status carries, not compared."""
    data = row.data
    if not name.startswith("handler"):
        return False
    return data.startswith((b"\x0f\x11\x43", b"\x0f\x11\x4b", b"\x0f\x11\x53", b"\x0f\x11\x5b", b"\x0f\x11\x42", b"\x0f\x11\x4a", b"\x0f\x11\x52", b"\x0f\x11\x5a", b"\x66\x89\x4b", b"\x66\x89\x4a", b"\x89\x4b", b"\x89\x4a"))


EDGE_WORDS = ("bound", "100 bytes", "101 bytes", "300 s", "kept", "ten seconds", "size decimals")


def run_mutants(image, table, seen, cases, vectors):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    chosen = cases + vectors
    edge = [case for case in cases if case.copy == 0 and any(word in case.name for word in EDGE_WORDS)]
    if first_failure(control, chosen) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    for name in table:
        if name.endswith(("_b", "_c")):
            continue
        for va, kind, patch in edits_for(image, [row for row in table[name] if not status_copy(name, row)], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, edge) if kind == "immediate" else None
            if hit is None:
                hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], THIRD_CAP))
            results.append((name, va, kind, "killed", hit.name) if hit is not None else (name, va, kind, "survived", survivor_reason(va, kind)))
    return results


REFERENCE = (
    ("wire shape", "`24_set_global.rs` has pxs and externalPerpPxs as two vectors of asset key plus price", "the serializer order is pxs, externalPerpPxs, usdtUsdcPx, nativePx; pxs is a list of (oracle, mark) optional decimal strings indexed by position, externalPerpPxs is a string to string tree walked in key order", "four rows copy b"),
    ("order of gates", "signer first, then parsing, then the timestep", "the two lists are parsed in full first: a refused price wins over a refused signer", "bad price wins over signer"),
    ("unknown asset", "unknown key gives status 100 with the name", "the lookup error is dropped and the entry is skipped before its price is read, so a bad price under an unknown name passes", "unknown name with a bad price is skipped"),
    ("external entries", "a map from asset to price handed to the timestep", "the map exists only during the handler: each row removes dex*10000+index, entries past the rows are dropped with no error", "external with no pxs row is dropped"),
    ("price type", "strings parse as f64, positive and finite", "list prices parse to 16-byte Decimal and compare with Decimal zero through 0x4eadb90; f64 appears only for the two optional words", "oracle smallest positive"),
    ("two optional words", "`parse_positive_f64` refuses zero and negative", "no sign test exists on 0x374fe60's path: zero and negative values are stored", "native negative is stored"),
    ("order of the two words", "usdtUsdcPx then nativePx, both before history", "nativePx first into S+0x588, usdtUsdcPx second into S+0x580, both after the timestep has run, with no undo when the second is refused", "usdt refused after native stored"),
    ("history row", "`RecentOracleResult` of time and heap length", "the ring S+0x3590 holds the time and a full clone of dex row +0x60 (0x60-byte rows)", "five snapshot rows"),
    ("history limit", "age above 300 s is removed, then the length is capped at 100", "a front row goes only while the length exceeds 100 AND front+300 s is strictly before now; old rows under the cap stay and fresh rows over the cap stay", "fresh rows over the cap stay"),
    ("stale refresh period", "`dex_registry.rs:12` HIP3_STATUS_REFRESH_SECS is ten days", "`mov $0xa,%edx` adds ten seconds to dex +0x2e0, compared as due at equality", "refresh exactly ten seconds old"),
    ("stale refresh trigger", "`dex_registry.rs:428` is also due when two order counts differ", "the words dex +0x10 and dex +0x280 only feed an id list that is pushed and freed with no read; a fresh dex is skipped before it", "refresh changed word differs"),
    ("stale refresh work", "`refresh_one_hip3_status` copies a count and stores the time", "the label text is refresh_hip3_stale_mark_pxs: every asset row goes to the shared timestep with r8 = 1, oracle = stored word, mark = 0x26e0660 of the book row, both over 10^(6-sz) through f64 into Decimal, no external price", "refresh one asset"),
    ("expected signer list", "`oracle_updater_signers` vector scan", "a call of 0x33690c0 with S+0x3840 and the word S+0x3888; every refusal becomes tag 0x94", "signer refused other status"),
)


def text_at(image, arm):
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0:
        return ""
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    if data[at + 7] == 0xBA:
        size = struct.unpack_from("<I", data, at + 8)[0]
    else:
        size = 48
    raw = bytes(image.blob[image.offset(target):image.offset(target) + size])
    return "".join(chr(item) if 32 <= item < 127 and item != 64 else "." for item in raw)


def tag_rows(image):
    rows = []
    for tag in (TAG_BOUND, TAG_POSITIVE, TAG_SIGNER, TAG_UNKNOWN, TAG_FLOAT, PARSE_TAG):
        arm = TEXT_TABLE + struct.unpack_from("<i", image.blob, image.offset(TEXT_TABLE) + 4 * tag)[0]
        rows.append(("%#x" % tag, "%#x" % arm, text_at(image, arm)))
    return rows


WIRE = ((0x1E8A0DE, 0x3BFDA8, 3, 0, "pxs"), (0x1E8A10B, 0x3BFDAB, 15, 0x48, "externalPerpPxs"), (0x1E8A135, 0x3BFDBA, 10, 0x18, "usdtUsdcPx"), (0x1E8A15F, 0x20AB70, 8, 0x30, "nativePx"))


def wire_rows(image):
    """Serializer rows: `lea key,%rsi` then `mov $len,%edx` a fixed distance on, with the field offset named for the record."""
    rows = []
    for va, key, size, field, want in WIRE:
        at = image.offset(va)
        data = bytes(image.blob[at:at + 20])
        if data[:3] != b"\x48\x8d\x35" or va + 7 + struct.unpack_from("<i", data, 3)[0] != key:
            raise EvidenceError("key load at %#x" % va)
        length = data.find(b"\xba")
        if struct.unpack_from("<I", data, length + 1)[0] != size:
            raise EvidenceError("key length at %#x" % va)
        name = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode()
        if name != want:
            raise EvidenceError("key text at %#x" % key)
        if field == 0:
            place = "the first field, rbx itself"
        else:
            prev = bytes(image.blob[at - 4:at])
            if field == 0x30:
                prev = bytes(image.blob[at - 4:at])
                if prev != b"\x48\x83\xc3\x30":
                    raise EvidenceError("field add at %#x" % va)
            elif prev != bytes((0x48, 0x8D, 0x4B, field)):
                raise EvidenceError("field load at %#x" % va)
            place = "action +%#x" % field
        rows.append(("%#x" % va, name, "%#x" % field, place))
    return rows


LABEL_TEXT = 0x3EFA6C
WORDS = ((0x2228B5F + 1, "<I", REFRESH_SECONDS, "`mov $0xa,%edx`: seconds added to dex +0x2e0"), (0x2228B27 + 6, "<B", MAIN_MODE, "`cmpb $0x3,0x230(%rbp)`: mode skipped by the refresh"), (0x2228B10 + 3, "<I", DEX_STRIDE, "dex row stride"), (0x2228B17 + 3, "<I", TABLE_STRIDE, "book table stride"), (0x1E8267C + 3, "<B", SZ_LIMIT, "`cmp $0x7,%rdx`: size decimals bound"),
         (0x1F67B9F + 3, "<I", MAX_ITEMS + 1, "`cmp $0x2711,%r12`: external entries"), (0x1F67F4E + 2, "<I", MAX_ITEMS + 1, "`cmp $0x2711,%rax`: pxs rows"), (0x1F67E0D + 3, "<B", MAX_TEXT + 1, "`cmp $0x65,%rdx`: external name bytes"), (0x1F67E7B + 3, "<B", MAX_TEXT + 1, "`cmp $0x65,%rdx`: external price bytes"),
         (0x1F68447 + 4, "<B", MAX_TEXT + 1, "`cmpq $0x65,0x40(%rbx)`: nativePx bytes"), (0x1F68490 + 4, "<B", MAX_TEXT + 1, "`cmpq $0x65,0x28(%rbx)`: usdtUsdcPx bytes"), (0x1E82B44 + 3, "<B", MAX_TEXT, "`cmp $0x64,%rdx`: oracle bytes"), (0x1E82BEF + 3, "<B", MAX_TEXT, "`cmp $0x64,%rdx`: mark bytes"),
         (0x1E82ACA + 1, "<I", PACK, "`mov $0x2710,%eax`: packed row key"), (0x1F6810E + 7, "<B", KEEP + 1, "`cmpq $0x65,0x35a8(%r15)`: ring length before the drop loop"), (0x1F68193 + 3, "<B", KEEP, "`cmp $0x64,%rax`: ring length inside the drop loop"), (0x1F681DC + 1, "<I", KEEP_SECONDS, "`mov $0x12c,%edx`: seconds added to the front row"), (0x1F6811C + 2, "<Q", 0x1845C8A0CE512957, "`movabs`: 86400 reciprocal for the day count"))


LOCATIONS = ((RECORD, "recorder call when the dex list and the book table list differ in length"), (0x56BDF70, "packed id overflow in the row builder"), (0x56F21C0, "unit row lookup of the row entry"), (0x56F3350, "size decimals above 6 in the row entry"), (0x56902A0, "oracle row bound"), (0x56BB460, "book row bound"), (0x56914F0, "packed id overflow of a pxs row"))


def location_rows(image):
    relative = image.relative()
    rows = []
    for record, use in LOCATIONS:
        path, line, column = image.location(record, relative)
        rows.append(("%#x" % record, path, line, column, use))
    return rows


def divisor_rows(image):
    rows = []
    for base in (0x3E0E90, 0x6F7470):
        for index in range(7):
            value = struct.unpack_from("<d", image.blob, image.offset(base + 8 * index))[0]
            if value != 10.0 ** index:
                raise EvidenceError("divisor table at %#x" % base)
            rows.append(("%#x" % base, index, repr(value)))
    return rows


def constant_rows(image):
    rows = []
    for va, form, want, use in WORDS:
        value = struct.unpack_from(form, image.blob, image.offset(va))[0]
        if value != want:
            raise EvidenceError("immediate at %#x: %#x" % (va, value))
        rows.append(("%#x" % va, "%#x" % value, use))
    label = bytes(image.blob[image.offset(LABEL_TEXT):image.offset(LABEL_TEXT) + 27])
    if label != b"refresh_hip3_stale_mark_pxs":
        raise EvidenceError("label text")
    rows.append(("%#x" % LABEL_TEXT, label.decode(), "27-byte label passed by the only caller 0x222a71e"))
    zero = bytes(image.blob[image.offset(0x207DA0):image.offset(0x207DA0) + 16])
    if zero != bytes(16):
        raise EvidenceError("decimal zero at 0x207da0")
    rows.append(("0x207da0", zero.hex(), "Decimal zero compared with each list price"))
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, use in ((0x5773318, "name to packed asset id, multiply and scan"), (0x57731D8, "text to Decimal"), (0x5773328, "text to f64 through Decimal, no sign test"), (SLOT_SIGNER, "signer test, stubbed here"), (0x5773320, "dex row by index"), (0x576E8A8, "time plus seconds"), (0x576E8B0, "date plus days"), (0x57710D0, "ring growth")):
        rows.append(("%#x" % slot, "%#x" % relative[slot], use))
    return rows


def caller_rows(image):
    """Every `e8 rel32` call of the subject functions."""
    base, text = image.text_bytes()
    wanted = {}
    for copy in COPIES:
        for field in ("handler", "collect", "fold", "entry", "insert", "remove", "push", "step"):
            wanted[getattr(copy, field)] = field
    wanted[0x3BC64B0] = "clone_rows"
    for copy in COPIES:
        for field in ("refresh", "builder", "row", "group", "mark"):
            wanted[getattr(copy, field)] = field
    rows = []
    at = text.find(b"\xe8")
    while at >= 0 and at + 5 <= len(text):
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in wanted:
            rows.append((wanted[target], "%#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
        at = text.find(b"\xe8", at + 1)
    return sorted(rows)


def subject_rows(image):
    """The refresh copies stop at the row after the id list drop: the rest of those functions is a timing metric."""
    stops = {copy.refresh: copy.stop for copy in COPIES}
    out = {}
    for name, target in FUNCTIONS.items():
        if target in stops:
            image.exact_fde(target)
            out[name] = decode_range(image, target, stops[target])
        else:
            out[name] = rows_of(image, target)
    return out


def copy_rows():
    return [(copy.name, "%#x" % copy.handler, "%#x" % copy.collect, "%#x" % copy.fold, "%#x" % copy.entry, "%#x" % copy.insert, "%#x" % copy.remove, "%#x" % copy.push, "%#x" % copy.step, "%#x" % (0x3590 + copy.shift), "%#x" % (0x3840 + copy.shift), "%#x" % (0x5C0 + copy.shift), "%#x" % copy.refresh, "%#x" % copy.builder, "%#x" % copy.row, "%#x" % copy.group, "%#x" % copy.mark, "%#x" % (0x3370 + copy.shift)) for copy in COPIES]


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
    result = dict(divisors=divisor_rows(image), locations=location_rows(image), table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), tags=tag_rows(image), wire=wire_rows(image), copies=copy_rows(), callers=caller_rows(image), slots=slot_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def cell(value):
    if isinstance(value, fractions.Fraction):
        return str(value)
    if isinstance(value, bytes):
        return value.hex() if len(value) <= 40 else "%d bytes %s" % (len(value), hashlib.sha256(value).hexdigest()[:16])
    if isinstance(value, int) and not isinstance(value, bool):
        return "%#x" % (value & TOP) if value < 0 else "%#x" % value
    if isinstance(value, (tuple, list)):
        if len(value) > 16:
            return "%d items %s" % (len(value), hashlib.sha256(repr(value).encode()).hexdigest()[:16])
        return "(" + " ".join(cell(part) for part in value) + ")"
    return str(value)


def outcome_row(case, got):
    state = got["state"]
    return (case.name.replace("\t", " "), case.entry, cell(got["result"]), "%#x" % state["native"], "%#x" % state["usdt"], len(state["history"]), "; ".join(cell(event) for event in got["events"]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("size-divisors.tsv", ("table", "6 - sz", "value"), result["divisors"])
    tsv("locations.tsv", ("record", "path", "line", "column", "use"), result["locations"])
    tsv("constants.tsv", ("address", "value", "meaning"), result["constants"])
    tsv("tag-texts.tsv", ("tag", "display arm", "display text"), result["tags"])
    tsv("wire-fields.tsv", ("key load", "key", "action offset", "field"), result["wire"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "handler", "collect", "fold", "entry", "insert", "remove", "push", "timestep", "history ring", "signer map", "dex list", "refresh", "row builder", "row entry", "group insert", "mark reader", "book table list"), result["copies"])
    tsv("callers.tsv", ("callee", "address", "call site", "function"), result["callers"])
    tsv("slots.tsv", ("slot", "target", "use"), result["slots"])
    tsv("outcomes.tsv", ("case", "entry", "result", "S+0x588", "S+0x580", "history rows", "callee events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
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

