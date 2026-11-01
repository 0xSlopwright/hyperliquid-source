#!/usr/bin/env python3
"""Pin the node #94 mark price sample path: decay rows, min and max volatility, and the delay fold that reads them.

Real rows run from the record, select and fold entries. A separately written rule list predicts every stored field, and
every reached conditional row, immediate and field offset of the subject code is edited. No objdump or readelf output is
parsed and the binary is never executed. Standard library only.

    python3 tools/vty_tracker.py --out <dir>
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
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd", (0x14, True): "punpcklqdq",
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
    # Masked SSE2 DIVSD: Intel SDM vol1 Table4-7 and Table11-1.
    # Preserve NaN sign/payload; quiet an SNaN. First NaN operand wins.
    one, two = to_bits(left), to_bits(right)
    for bits in (one, two):
        if bits & 0x7FFFFFFFFFFFFFFF > 0x7FF0000000000000:
            return to_float(bits | 0x0008000000000000)
    if (left == 0 and right == 0) or (math.isinf(left) and math.isinf(right)):
        return to_float(0xFFF8000000000000)
    if right == 0:
        return to_float(((one ^ two) & (1 << 63)) | 0x7FF0000000000000)
    return left / right


OK = 0x186
ROW_SIZE = 0x30
VALUE_SIZE = 0x80
SAMPLE_SIZE = 0x18
LEAF = 0x5B8
INNER = 0x618
TREE_AT = 0x70
DELAYER_MARK = 0xA7
WRITER = 0x392B930
SELECT = 0x3930C30
DEFAULT = 0x3930FF0
FOLD = 0x3BE4E20
INSERT = 0x33C0B70
LOGGER = 0x33750F0
ITERATOR = 0x33B6170
SECONDS = 0x1447130
MAKE_DATE = 0x151F6F0
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_ONCE = 0x576E8B8
SLOT_CURVE = 0x5776220
SLOT_WRITER = 0x57748D8
SLOT_OVERFLOW = 0x576E468
OVERFLOW_TEXT = b"`NaiveDateTime + TimeDelta` overflowed"
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150)
ONCE_STATE = 0x577AB98
RESUME = 0x5660110
MARK_BASE = 0x7700000000
DELAYER = HEAP_BASE + 0x100
STAMP = HEAP_BASE + 0x400
ROWS = HEAP_BASE + 0x500
ITER = HEAP_BASE + 0x900
TREE_REF = HEAP_BASE + 0xA00
MODE_REF = HEAP_BASE + 0xA40
BUMP = HEAP_BASE + 0x1000
BUMP_END = HEAP_BASE + 0x3F000
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000))
INDEFINITE = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000000))[0]
SIGN_BIT = 1 << 63
UNIX_DAY_BASE = 719163
BASE_DAY = 20000
BASE_SEC = BASE_DAY * 86400
DEFAULT_DAY = 0xAFAA8 - UNIX_DAY_BASE
LAST_YEAR = 262142
MAX_DAY = 365 * (LAST_YEAR - 1) + (LAST_YEAR - 1) // 4 - (LAST_YEAR - 1) // 100 + (LAST_YEAR - 1) // 400 + 365 - UNIX_DAY_BASE
INTERVALS = (30.0, 100.0, 300.0, 1000.0)
DEQUE_START = 8
ROW_START = 4
BUCKET_MILLIS = 600000
DEFAULT_MIN = 0.0001
DEFAULT_MAX = 0.0003
LOW_EDGE = 20.0
HIGH_EDGE = 100.0
SPACING = 1
EPSILON = 1e-20
MIN_DENOM = 1e-15
TINY = -1e-15
FLOOR = 10.0
ABSENT = 0.001
METRIC_NAME = b"deterministic_vty_alert_n_bucket_samples"
METRIC_LOW = 0.01
METRIC_HIGH = 0.05
SELECT_GATE = 20
SUBJECTS = (WRITER, SELECT, DEFAULT, FOLD)
NAMES = {WRITER: "record_sample", SELECT: "select_rate", DEFAULT: "new_tracker", FOLD: "delay_fold"}
SERDE = (b"vty_trackersstatus_guarddelayer_modedelay_scale", b"deterministic_vty_alert_n_bucket_samples", b"\nVty {min: ")
CONSTANTS = ((0x20B038, "elapsed must be above"), (0x20A960, "elapsed must be at most"), (0x20AA60, "denominator epsilon"), (0x20A278, "ratio minus one"), (0x20A730, "value and rate cap"), (0x20A4B0, "infinity kept by the cap"), (0x20A8A8, "decay floor"),
             (0x20B080, "smallest elapsed sum"), (0x20A448, "negative snap edge"), (0x20AFB8, "delay for an asset with no tracker"))
PAIRS = ((0x207C00, "default min, default max"), (0x205E70, "metric low, metric high"))
AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000 and target not in (LOGGER, ITERATOR)


class Layout:
    key_at, val_at, val_size, parent_at, index_at, len_at, edge_at, leaf, inner, key_size = 0x588, 0, VALUE_SIZE, 0x580, 0x5B4, 0x5B6, 0x5B8, LEAF, INNER, 4


def stamp(second, nanos=0):
    return (second, nanos)


class Row:
    """One entry of the decay vector, serde DeterministicEma."""

    def __init__(self, num=0.0, denom=0.0, decay=30.0, count=0, last=None, stale=(0x5151, 0x5252), pad=b"\x6d" * 4):
        self.num, self.denom, self.decay, self.count, self.last, self.stale, self.pad = num, denom, decay, count, last, stale, pad

    def copy(self):
        return Row(self.num, self.denom, self.decay, self.count, self.last, self.stale, self.pad)


class Track:
    def __init__(self, samples=(), rows=None, cap=DEQUE_START, head=0, millis=BUCKET_MILLIS, seen=0, low=DEFAULT_MIN, high=DEFAULT_MAX, sampled=0, logged=0, label=b"label"):
        self.samples, self.cap, self.head, self.millis, self.seen, self.low, self.high, self.sampled, self.logged, self.label = list(samples), cap, head, millis, seen, low, high, sampled, logged, label
        self.rows = [Row(decay=value) for value in INTERVALS] if rows is None else [row.copy() for row in rows]

    def copy(self):
        return Track(self.samples, self.rows, self.cap, self.head, self.millis, self.seen, self.low, self.high, self.sampled, self.logged, self.label)


class Case:
    DEFAULTS = dict(kind="record", key=7, steps=(), tracks=(), height=0, rows=(), mode=1, once=0, keys=(), start=0.0, curve=None, mode_byte=2, root=True)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


def key_bytes(key):
    return struct.pack("<I", key)


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_ONCE, self.on_once), (SLOT_CURVE, self.on_curve))
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
        machine.slots[MARK_BASE + SLOT_OVERFLOW] = self.on_overflow
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic, LOGGER: self.on_logger, ITERATOR: self.on_iterator}
        self.case = None
        self.live = {}
        self.events = []
        self.cur = BUMP
        self.dates = {}
        self.queue = []
        self.curves = []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_overflow(self, machine):
        self.expect(machine.memory.bytes_at(machine.regs[RDI], machine.regs[RSI]) == OVERFLOW_TEXT, "overflow text")
        raise Panicked("panic path")

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

    def on_once(self, machine):
        self.expect(machine.regs[RDI] == ONCE_STATE and machine.regs[RSI] & 0xFF == 1, "once state")
        self.events.append("once")

    def on_logger(self, machine):
        memory = machine.memory
        record, fields = machine.regs[RDI], machine.regs[RSI]
        pointer, size = memory.read(record, 8), memory.read(record + 8, 8)
        self.expect(memory.bytes_at(pointer, size) == METRIC_NAME, "metric name")
        self.expect((memory.read(record + 0x10, 8), memory.read(record + 0x18, 8)) == (to_bits(METRIC_LOW), to_bits(METRIC_HIGH)), "metric bounds")
        flag = memory.read(record + 0x20, 1)
        value = memory.read(fields, 8)
        self.expect(memory.read(fields + 8, 8) == value + 0x78 and memory.read(fields + 0x10, 8) == value + 0x50, "metric field pointers")
        self.events.append("log %d %d" % (flag, memory.read(value + 0x78, 8)))
        if flag == 1:
            memory.write(value + 0x78, 8, 0)

    def on_iterator(self, machine):
        memory = machine.memory
        out, state = machine.regs[RDI], machine.regs[RSI]
        self.expect(memory.bytes_at(state, 0x48) == self.iter_bytes, "iterator words")
        if self.queue:
            key = self.queue.pop(0)
            memory.write(out, 8, ITER + 0x80)
            memory.write(out + 8, 8, 0x4242)
            memory.write(out + 0x10, 8, 2)
            memory.write(ITER + 0x80 + 8 + 8, 4, key)
            memory.write(ITER + 0x80 + 8, 8, 0x3434343434343434)
        else:
            self.events.append("iterator end")
            memory.write(out, 8, 0)

    def on_curve(self, machine):
        mode, key, value = machine.regs[RDI] & 0xFF, machine.regs[RSI] & 0xFFFFFFFF, machine.xmm[0] & MASK[8]
        self.events.append("curve %d %d %#x" % (mode, key, value))
        reply = self.curves.pop(0)
        machine.curve_result = to_bits(reply)
        machine.xmm_result = to_bits(reply)

    def node(self, items, stale, size):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + Layout.parent_at, 8, 0)
        memory.write(at + Layout.len_at, 2, len(items))
        for slot in range(11):
            memory.put_bytes(at + Layout.key_at + 4 * slot, stale)
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + Layout.key_at + 4 * slot, key)
            memory.put_bytes(at + VALUE_SIZE * slot, value)
        return at

    def tree(self, items, stale):
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED
        if len(items) <= 11:
            return self.node(items, stale, LEAF), 0
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        kids = [self.node(part, stale, LEAF) for part in parts]
        root = self.node(seps, stale, INNER)
        for slot, kid in enumerate(kids):
            memory.write(root + Layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + Layout.parent_at, 8, root)
            memory.write(kid + Layout.index_at, 2, slot)
        return root, 1

    def walk(self):
        memory = self.machine.memory
        root, height = memory.read(DELAYER + TREE_AT, 8), memory.read(DELAYER + TREE_AT + 8, 8)
        rows = []

        def visit(at, level, parent, index):
            size = memory.read(at + Layout.len_at, 2)
            self.expect(memory.read(at + Layout.parent_at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + Layout.index_at, 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + Layout.edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.read(at + Layout.key_at + 4 * slot, 4), at + VALUE_SIZE * slot))
        if root:
            visit(root, height, 0, 0)
        return rows

    def make_date(self, day):
        """Date word of a Unix day, through the real chrono constructor."""
        if day not in self.dates:
            machine = self.machine
            memory = machine.memory
            saved = machine.frame
            result = machine.run(MAKE_DATE, {RDI: day + UNIX_DAY_BASE})
            machine.frame = saved
            word = result & 0xFFFFFFFF
            self.dates[day] = word
        return self.dates[day]

    def stamp_bytes(self, when):
        second, nanos = when
        day, rest = divmod(second, 86400)
        return struct.pack("<iII", to_i32(self.make_date(day)), rest, nanos)

    def put_row(self, at, row):
        memory = self.machine.memory
        memory.put_bytes(at, struct.pack("<3dQ", row.num, row.denom, row.decay, row.count))
        if row.last is None:
            memory.put_bytes(at + 0x20, struct.pack("<iII", 0, *row.stale))
        else:
            memory.put_bytes(at + 0x20, self.stamp_bytes(row.last))
        memory.write(at + 0x2C, 4, 0x6D6D6D6D)

    def value_bytes(self, track):
        memory = self.machine.memory
        label = self.bump(max(len(track.label), 1))
        memory.put_bytes(label, track.label)
        deque = self.bump(track.cap * SAMPLE_SIZE)
        for index, (when, price) in enumerate(track.samples):
            at = deque + ((track.head + index) % track.cap) * SAMPLE_SIZE
            memory.put_bytes(at, self.stamp_bytes(when) + b"\x6e" * 4 + struct.pack("<d", price))
        rows = self.bump(max(len(track.rows), 1) * ROW_SIZE)
        for index, row in enumerate(track.rows):
            self.put_row(rows + ROW_SIZE * index, row)
        words = (len(track.label), label, len(track.label), track.cap, deque, track.head, len(track.samples), max(len(track.rows), 1), rows, len(track.rows), track.millis, track.seen)
        return struct.pack("<12Q2d2Q", *(words + (track.low, track.high, track.sampled, track.logged)))

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:len(HEAP_FILL)] = HEAP_FILL
        memory.put_bytes(DELAYER, bytes([DELAYER_MARK]) * 0x100)
        self.case = case
        self.events = []
        self.live = {}
        self.cur = BUMP
        self.machine.memory.statics[ONCE_STATE] = case.once
        self.machine.frame = 0

    def track_view(self, at):
        memory = self.machine.memory
        words = struct.unpack("<12Q", memory.bytes_at(at, 96))
        cap_text, text, size, cap, deque, head, count, row_cap, rows, row_count, millis, seen = words
        low, high = memory.read(at + 0x60, 8), memory.read(at + 0x68, 8)
        samples = []
        for index in range(count):
            spot = deque + ((head + index) % cap) * SAMPLE_SIZE
            samples.append((memory.bytes_at(spot, 12), memory.read(spot + 0x10, 8)))
        row_view = [memory.bytes_at(rows + ROW_SIZE * index, ROW_SIZE) for index in range(row_count)]
        return dict(label=memory.bytes_at(text, size), label_cap=cap_text >= size, cap=cap, samples=samples, rows=row_view, row_cap=row_cap, row_block=self.live.get(rows), deque_block=self.live.get(deque, 0), millis=millis, seen=seen, low=low, high=high, sampled=memory.read(at + 0x70, 8), logged=memory.read(at + 0x78, 8))

    def view(self):
        memory = self.machine.memory
        return dict(trackers={key: self.track_view(at) for key, at in self.walk()}, length=memory.read(DELAYER + TREE_AT + 0x10, 8), before=memory.bytes_at(DELAYER, TREE_AT), events=list(self.events), panic=False)

    def run_record(self, case):
        memory = self.machine.memory
        items = [(key_bytes(key), self.value_bytes(track)) for key, track in sorted(case.tracks, key=lambda item: item[0])]
        root, height = self.tree(items, b"\xfe\xff\xff\xff")
        memory.write(DELAYER + TREE_AT, 8, root)
        memory.write(DELAYER + TREE_AT + 8, 8, height)
        memory.write(DELAYER + TREE_AT + 0x10, 8, len(items))
        panic = False
        for key, when, price in case.steps:
            memory.put_bytes(STAMP, self.stamp_bytes(when))
            self.machine.xmm[0] = to_bits(price)
            try:
                self.machine.run(WRITER, {RDI: DELAYER, RSI: key, RDX: STAMP})
            except Panicked:
                panic = True
                break
        got = dict(trackers={}, length=0, events=list(self.events), panic=True) if panic else self.view()
        return got

    def run_select(self, case):
        memory = self.machine.memory
        for index, row in enumerate(case.rows):
            self.put_row(ROWS + ROW_SIZE * index, row)
        for index in range(3):
            self.put_row(ROWS + ROW_SIZE * (len(case.rows) + index), Row(0.25 + index, 0.5, 1.0, 99, None))
        self.decoy = memory.bytes_at(ROWS + ROW_SIZE * len(case.rows), ROW_SIZE)
        for index in range(3):
            memory.put_bytes(ROWS + ROW_SIZE * (len(case.rows) + index), self.decoy)
        result = self.machine.run(SELECT, {RDI: ROWS, RSI: len(case.rows), RDX: case.mode})
        self.expect(all(memory.bytes_at(ROWS + ROW_SIZE * (len(case.rows) + index), ROW_SIZE) == self.decoy for index in range(3)), "rows past the end unchanged")
        got = dict(some=result & 1, rows=[memory.bytes_at(ROWS + ROW_SIZE * index, ROW_SIZE) for index in range(len(case.rows))])
        got["value"] = self.machine.xmm[0] & MASK[8] if result & 1 else None
        return got

    def run_fold(self, case):
        memory = self.machine.memory
        self.iter_bytes = bytes((0x21 + index) & 0xFF for index in range(0x48))
        memory.put_bytes(ITER, self.iter_bytes)
        memory.write(ITER + 0x48, 8, TREE_REF)
        memory.write(ITER + 0x50, 8, MODE_REF)
        memory.write(MODE_REF, 1, case.mode_byte)
        items = [(key_bytes(key), self.value_bytes(track)) for key, track in sorted(case.tracks, key=lambda item: item[0])]
        root, height = self.tree(items, b"\xfe\xff\xff\xff") if case.root else (0, 0xFEED)
        memory.write(TREE_REF, 8, root)
        memory.write(TREE_REF + 8, 8, height)
        self.queue = list(case.keys)
        self.curves = list(case.curve or ())
        self.machine.xmm[0] = to_bits(case.start)
        try:
            self.machine.run(FOLD, {RDI: ITER})
        except Panicked:
            return dict(panic=True, events=list(self.events), left=len(self.curves))
        return dict(panic=False, result=self.machine.xmm[0] & MASK[8], events=list(self.events), left=len(self.curves))

    def run(self, case):
        self.fresh(case)
        for piece in (case.tracks, case.steps):
            for item in piece:
                self.touch(item)
        if case.kind == "select":
            return self.run_select(case)
        if case.kind == "fold":
            return self.run_fold(case)
        return self.run_record(case)

    def touch(self, item):
        pass


def to_i32(word):
    return word - (1 << 32) if word >> 31 else word


def fdiv_spec(left, right):
    # Independent scalar rule: masked invalid division yields x86 indefinite,
    # while a NaN input retains its sign and payload with the quiet bit set.
    if math.isnan(left):
        return to_float(to_bits(left) | 0x0008000000000000)
    if math.isnan(right):
        return to_float(to_bits(right) | 0x0008000000000000)
    if math.isinf(left) and math.isinf(right):
        return INDEFINITE
    if right == 0:
        if left == 0:
            return INDEFINITE
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


def order_key(value):
    bits = to_bits(value)
    return ~bits & MASK[8] if bits & SIGN_BIT else bits | SIGN_BIT


def row_rate(row):
    if row.decay > float(row.count) or MIN_DENOM > row.denom:
        return None
    number = row.num
    if number < 0.0 and TINY < number:
        number = 0.0
    if 0.0 > number:
        return None
    return fdiv_spec(number, row.denom)


def spec_select(rows, mode):
    best = None
    for row in rows:
        rate = row_rate(row)
        if rate is None:
            continue
        if best is None:
            best = rate
        elif mode:
            if not order_key(best) > order_key(rate):
                best = rate
        elif order_key(best) > order_key(rate):
            best = rate
    if best is None:
        return None
    root = math.sqrt(best) if best == best and best >= 0 else best if best != best else math.nan
    if to_bits(root) & 0x7FFFFFFFFFFFFFFF > 0x7FEFFFFFFFFFFFFF:
        return root
    return 1.0 if not root < 1.0 else root


def seconds_since(now, then):
    if now < then:
        return 0.0
    gap = now[0] - then[0]
    nanos = now[1] - then[1]
    if nanos < 0:
        gap -= 1
        nanos += 10 ** 9
    micros = gap * 10 ** 6 + nanos // 1000
    # Native IMUL/JO and ADD/SETO reject an i64 microsecond overflow.
    if micros > (1 << 63) - 1:
        return 0.0
    return float(micros) / 1e6


def millis_of(when):
    return max(0, (when[0] // 86400 * 86400 + when[0] % 86400) * 1000 + when[1] // 10 ** 6)


def spec_new_track(key, default_seen):
    track = Track(label=b"AssetWire(%d)" % key, seen=default_seen, cap=0)
    track.rows = [Row(decay=value, stale=None, pad=FRESH[:4]) for value in INTERVALS]
    return track


def spec_step(track, now, price, events):
    if track.samples:
        earliest = (track.samples[-1][0][0] + SPACING, track.samples[-1][0][1])
        if now < earliest:
            return
        oldest = track.samples[0]
        elapsed = seconds_since(now, oldest[0])
        if now < oldest[0] and track.once:
            events.append("once")
        if elapsed > LOW_EDGE:
            if not elapsed > HIGH_EDGE:
                update_rows(track, now, price, oldest[1], elapsed, events)
            track.samples.pop(0)
    if len(track.samples) == track.cap:
        grow(track)
    track.samples.append((now, price))
    bucket = millis_of(now) // track.millis
    flag = 1 if bucket > track.seen else 0
    if flag:
        track.seen = bucket
    events.append("log %d %d" % (flag, track.logged))
    if flag:
        track.logged = 0


def grow(track):
    track.cap = max(track.cap * 2, ROW_START)


def update_rows(track, now, price, old, elapsed, events):
    move = fdiv_spec(price, old + EPSILON) + -1.0
    value = fdiv_spec(move * move, elapsed)
    capped = value > 1.0
    if capped and value != math.inf:
        value = 1.0
    for row in track.rows:
        if capped and events is not None and track.once:
            events.append("once")
        gap = 1.0 if row.last is None else seconds_since(now, row.last)
        if row.last is not None and now < row.last and track.once:
            events.append("once")
        if gap > row.decay:
            row.num = row.denom = 0.0
            row.decay = FLOOR if FLOOR > row.decay else row.decay
            row.count = 0
            if row.last is not None:
                row.stale = struct.unpack("<II", struct.pack("<II", *encode_clock(row.last)))
            row.last = None
            continue
        row.last = now
        keep = 1.0 - fdiv_spec(1.0, row.decay)
        row.num = value * gap + keep * row.num
        row.denom = gap + keep * row.denom
        row.count = min(row.count + 1, MASK[8])
    track.sampled = min(track.sampled + 1, MASK[8])
    track.logged = min(track.logged + 1, MASK[8])
    if track.sampled > SELECT_GATE:
        low = spec_select(track.rows, 0)
        high = spec_select(track.rows, 1)
        if low is not None:
            track.low = low
        if high is not None:
            track.high = high


def encode_clock(when):
    return (when[0] % 86400, when[1])


def expected_view(harness, case):
    events = []
    tracks = {key: track.copy() for key, track in case.tracks}
    for track in tracks.values():
        track.once = case.once
    panic = False
    for key, when, price in case.steps:
        if key not in tracks:
            tracks[key] = spec_new_track(key, default_bucket(harness))
            tracks[key].once = case.once
        if tracks[key].samples and overflow_of(harness, tracks[key].samples[-1][0]):
            panic = True
            break
        spec_step(tracks[key], when, price, events)
    if panic:
        return dict(trackers={}, length=0, events=events, panic=True)
    return dict(trackers={key: expected_track(harness, track) for key, track in tracks.items()}, length=len(tracks), before=bytes([DELAYER_MARK]) * TREE_AT, events=events, panic=False)


def overflow_of(harness, when):
    return when[0] // 86400 >= MAX_DAY


def default_bucket(harness):
    return (DEFAULT_DAY * 86400000) // BUCKET_MILLIS


def expected_track(harness, track):
    samples = [(harness.stamp_bytes(when), to_bits(price)) for when, price in track.samples]
    rows = []
    for row in track.rows:
        if row.last is None:
            clock = bytes(4) + (FRESH if row.stale is None else struct.pack("<II", *row.stale))
        else:
            clock = harness.stamp_bytes(row.last)
        rows.append(struct.pack("<3dQ", row.num, row.denom, row.decay, row.count) + clock + row.pad)
    row_cap = max(len(track.rows), ROW_START if track.label != b"label" else 1)
    return dict(label=track.label, label_cap=True, cap=track.cap, samples=samples, rows=rows, row_cap=row_cap, row_block=row_cap * ROW_SIZE, deque_block=track.cap * SAMPLE_SIZE, millis=track.millis, seen=track.seen, low=to_bits(track.low), high=to_bits(track.high), sampled=track.sampled, logged=track.logged)


def spec_fold(case):
    tracks = dict(case.tracks) if case.root else {}
    curve = list(case.curve or ())
    best = case.start
    events = []
    for key in case.keys:
        if key in tracks:
            value = curve.pop(0)
            events.append("curve %d %d %#x" % (case.mode_byte, key, to_bits(tracks[key].high)))
        else:
            value = ABSENT
        if value >= best:
            best = value
        elif not best >= value:
            return dict(panic=True, events=events, left=len(curve))
    events.extend(["iterator end"] * 2)
    return dict(panic=False, result=to_bits(best), events=events, left=len(curve))


def spec_for(harness, case):
    if case.kind == "select":
        value = spec_select(case.rows, case.mode)
        return dict(some=0 if value is None else 1, value=None if value is None else to_bits(value), rows=None)
    if case.kind == "fold":
        return spec_fold(case)
    return expected_view(harness, case)


def norm(value):
    """Two NaNs of a sum are the same value here; the select rows keep the sign that order needs."""
    if isinstance(value, dict):
        return {key: norm(item) for key, item in value.items()}
    if isinstance(value, list):
        return [norm(item) for item in value]
    if isinstance(value, tuple):
        return tuple(norm(item) for item in value)
    return value


def same(case, got, want):
    if case.kind == "select":
        return got["some"] == want["some"] and got["value"] == want["value"]
    return fix_nan(got) == fix_nan(want)


FRESH = bytes([STACK_MARK]) * 8
NAN_BYTES = struct.pack("<Q", 0x7FF8000000000000)


def fix_nan(value):
    if isinstance(value, dict):
        return {key: fix_nan(item) for key, item in value.items()}
    if isinstance(value, list):
        return [fix_nan(item) for item in value]
    if isinstance(value, tuple):
        return tuple(fix_nan(item) for item in value)
    if isinstance(value, bytes) and len(value) == ROW_SIZE:
        words = [value[at:at + 8] for at in range(0, 24, 8)]
        return b"".join(NAN_BYTES if struct.unpack("<Q", word)[0] & 0x7FFFFFFFFFFFFFFF > 0x7FF0000000000000 else word for word in words) + value[24:]
    if isinstance(value, int) and value >> 52 in (0x7FF, 0xFFF) and value & ((1 << 52) - 1):
        return 0x7FF8000000000000
    return value


START = BASE_SEC + 3600
VECTORS = 160
MUTANT_VECTORS = 30
REACH_CAP = 12
SECOND_CAP = 120
MUTANT_STEP_LIMIT = 300000
TOP = MASK[8]
UP = math.nextafter(TINY, 0.0)
DOWN = math.nextafter(TINY, -1.0)
BELOW = math.nextafter(MIN_DENOM, 0.0)


def at(second, nanos=0):
    return (START + second, nanos)


def older(*offsets):
    return [(at(offset), 100.0 + index) for index, offset in enumerate(offsets)]


def steady(count=0, num=1.0, denom=1.0, decay=30.0, last=None):
    return Row(num, denom, decay, count, last)


def ready_rows(last=None):
    return [steady(10 ** 6, 4e-6 * (index + 1), 2.0, value, last) for index, value in enumerate(INTERVALS)]


def one(name, track, when, price, key=7, **fields):
    return Case(name, key=key, tracks=((key, track),), steps=((key, when, price),), **fields)


def miss_cases():
    out = []
    for key in (0, 1, 5, 142, 10142, 99999, 110000, 100000123, 0xFFFFFFFD):
        out.append(Case("first sample of key %d" % key, tracks=(), steps=((key, at(0), 25.5),)))
    keys = [10 * index for index in range(1, 12)]
    for key in (5, 55, 115, 60, 0xFFFFFFFD):
        out.append(Case("new key beside %d full leaf" % key, tracks=tuple((value, Track()) for value in keys), steps=((key, at(0), 3.0),)))
    many = [10 * index for index in range(1, 18)]
    for key in (10, 60, 120, 170, 65, 175, 0xFFFFFFFD):
        out.append(Case("two level key %d" % key, tracks=tuple((value, Track()) for value in many), steps=((key, at(0), 3.0),)))
    return out


def spacing_cases():
    base = Track(samples=older(-5))
    out = [one("one second after newest", base, at(-4), 9.0), one("just under one second", base, at(-4 - 1, 999999999), 9.0), one("same instant", base, at(-5), 9.0), one("before newest", base, at(-9), 9.0)]
    out.append(one("one second across midnight", Track(samples=[((BASE_SEC + 86399, 5), 3.0)]), (BASE_SEC + 86400, 5), 4.0))
    out.append(one("under one second across midnight", Track(samples=[((BASE_SEC + 86399, 5), 3.0)]), (BASE_SEC + 86400, 4), 4.0))
    out.append(one("later day smaller clock", Track(samples=[((BASE_SEC + 86399, 5), 3.0)]), (BASE_SEC + 86500, 0), 4.0))
    out.append(one("earlier day larger clock", Track(samples=[((BASE_SEC + 200, 5), 3.0)]), (BASE_SEC - 100, 0), 4.0))
    out.append(one("same day smaller clock", Track(samples=[((BASE_SEC + 200, 5), 3.0)]), (BASE_SEC + 100, 0), 4.0))
    out.append(one("oldest ahead of now", Track(samples=[(at(30), 3.0), (at(-5), 3.0)]), at(0), 4.0))
    out.append(one("oldest ahead of now once", Track(samples=[(at(30), 3.0), (at(-5), 3.0)]), at(0), 4.0, once=1))
    out.append(one("newest at the last date", Track(samples=[((MAX_DAY * 86400 + 86399, 0), 3.0)]), (MAX_DAY * 86400 + 86399, 0), 4.0))
    return out


def edge_cases():
    out = []
    rows = ready_rows()
    for name, second, nanos in (("exactly twenty", 20, 0), ("twenty and a microsecond", 20, 1000), ("twenty and under a microsecond", 20, 999), ("exactly one hundred", 100, 0), ("one hundred and a microsecond", 100, 1000), ("one hundred and under a microsecond", 100, 999), ("far past", 5000, 0)):
        out.append(one("elapsed %s" % name, Track(samples=older(0), rows=rows), at(second, nanos), 101.0))
    for count in (1, 3, 7, 8):
        series = older(*range(0, count))
        out.append(one("full queue young %d" % count, Track(samples=series, rows=rows), at(count + 1), 101.0))
        out.append(one("old oldest %d" % count, Track(samples=[(at(-30), 77.0)] + series[1:], rows=rows), at(count + 1), 101.0))
        out.append(one("far oldest %d" % count, Track(samples=[(at(-3000), 77.0)] + series[1:], rows=rows), at(count + 1), 101.0))
    out.append(one("wrapped queue pop", Track(samples=[(at(-30), 77.0)] + older(1, 2, 3, 4, 5, 6, 7), head=5, rows=rows), at(9), 101.0))
    out.append(one("wrapped queue grow", Track(samples=older(1, 2, 3, 4, 5, 6, 7, 8), head=5, rows=rows), at(9), 101.0))
    out.append(one("queue of four grows", Track(samples=older(1, 2, 3, 4), cap=4, rows=rows), at(9), 101.0))
    out.append(one("queue of one", Track(samples=[(at(-30), 77.0)], cap=1, rows=rows), at(9), 101.0))
    out.append(one("queue empty with room", Track(samples=[], rows=rows, head=3), at(9), 101.0))
    return out


def value_cases():
    out = []
    rows = ready_rows()
    plain = Track(samples=[(at(-40), 100.0)], rows=rows)
    for name, price in (("small move", 100.5), ("flat", 100.0), ("down", 60.0), ("zero", 0.0), ("negative", -3.0), ("cap", 5000.0), ("huge", 1e300), ("max", sys.float_info.max), ("infinite", math.inf), ("minus infinite", -math.inf), ("nan", math.nan)):
        out.append(one("price %s" % name, plain, at(0), price))
        out.append(one("price %s once" % name, plain, at(0), price, once=1))
    for old in (0.0, -1e-20, 1e-300, -5.0, math.inf):
        out.append(one("old price %g" % old, Track(samples=[(at(-40), old)], rows=rows), at(0), 1e300))
        out.append(one("old price %g flat" % old, Track(samples=[(at(-40), old)], rows=rows), at(0), 0.0))
    out.append(one("value exactly one", Track(samples=[(at(-25), 1.0)], rows=rows), at(0), 6.0))
    return out


def row_cases():
    out = []
    base = [(at(-40), 100.0)]
    lasts = (("never", None), ("past", at(-1)), ("past fraction", at(-1, 123456789)), ("same", at(0)), ("future", at(30)), ("past decay edge", at(-30)), ("past decay over", at(-31, 999999000)), ("old", at(-1000)))
    for name, last in lasts:
        for decay in (30.0, 5.0, 10.0, 11.0, 0.5, 0.0, math.inf):
            row = Row(0.25, 0.5, decay, 9, last)
            out.append(one("row %s decay %g" % (name, decay), Track(samples=base, rows=[row, steady(3)]), at(0), 100.5))
            out.append(one("row %s decay %g capped" % (name, decay), Track(samples=base, rows=[row, steady(3)]), at(0), 5000.0))
    for price in (100.5, 5000.0):
        out.append(one("future row once at %g" % price, Track(samples=base, rows=[Row(0.25, 0.5, 30.0, 9, at(30))]), at(0), price, once=1))
    out.append(one("decay nan", Track(samples=base, rows=[Row(0.25, 0.5, math.nan, 9, at(-1))]), at(0), 100.5))
    out.append(one("count at top", Track(samples=base, rows=[Row(0.25, 0.5, 30.0, TOP, at(-1))]), at(0), 100.5))
    out.append(one("count at top capped", Track(samples=base, rows=[Row(0.25, 0.5, 30.0, TOP, at(-1))]), at(0), 5000.0))
    out.append(one("no rows", Track(samples=base, rows=[]), at(0), 100.5))
    out.append(one("no rows capped", Track(samples=base, rows=[]), at(0), 5000.0))
    return out


def gate_cases():
    out = []
    base = [(at(-40), 100.0)]
    for sampled in (0, 18, 19, 20, 21, TOP - 1, TOP):
        for logged in (0, 5, TOP - 1, TOP):
            out.append(one("counter %d log %d" % (sampled, logged), Track(samples=base, rows=ready_rows(), sampled=sampled, logged=logged, seen=2 * 10 ** 10), at(0), 100.5))
    invalid = [steady(1, 1.0, 1.0, 30.0)]
    out.append(one("gate open no valid row", Track(samples=base, rows=invalid, sampled=30), at(0), 100.5))
    out.append(one("only max stays", Track(samples=base, rows=[Row(-1.0, 1.0, 1.0, 50, None)], sampled=30), at(0), 100.5))
    out.append(one("rate one", Track(samples=base, rows=[Row(1e9, 1.0, 30.0, 50, at(-1))], sampled=30), at(0), 100.5))
    mixed = [Row(1e-6, 1.0, 30.0, 50, at(-1)), Row(4e-6, 1.0, 100.0, 50, at(-1)), Row(9e-6, 1.0, 300.0, 50, at(-1)), Row(16e-6, 1.0, 1000.0, 5, at(-1))]
    out.append(one("mixed rows", Track(samples=base, rows=mixed, sampled=30), at(0), 100.5))
    out.append(one("infinite rate stored", Track(samples=base, rows=[Row(math.inf, 1.0, 30.0, 50, at(-1))], sampled=30), at(0), 100.5))
    return out


def bucket_cases():
    out = []
    bucket = millis_of(at(0)) // BUCKET_MILLIS
    plain = dict(rows=[])
    for name, seen in (("below", bucket - 1), ("equal", bucket), ("above", bucket + 1), ("zero", 0), ("top", TOP)):
        out.append(one("bucket %s" % name, Track(seen=seen, logged=9, **plain), at(0), 1.0))
    for millis in (1, 7, 600000, 1 << 31, 1 << 32, (1 << 32) + 3, 1 << 45, TOP):
        for seen in (0, (millis_of(at(0)) // millis)):
            out.append(one("millis %d seen %d" % (millis, seen), Track(millis=millis, seen=seen, logged=3, **plain), at(0), 1.0))
    out.append(one("half second part", Track(seen=0, **plain), at(0, 999999999), 1.0))
    out.append(one("milli floor", Track(millis=1, seen=millis_of(at(0, 1999999)), **plain), at(0, 2000000), 1.0))
    out.append(one("milli floor under", Track(millis=1, seen=millis_of(at(0, 1999999)), **plain), at(0, 1999999), 1.0))
    out.append(one("before epoch", Track(seen=0, **plain), (-86400 * 3 + 5, 0), 1.0))
    out.append(Case("new key before the default bucket", steps=((3, (86400 * 100, 0), 1.0),)))
    out.append(Case("new key at the default bucket", steps=((3, (86400 * 365, 0), 1.0),)))
    out.append(Case("new key past the default bucket", steps=((3, (86400 * 365 + 600, 0), 1.0),)))
    out.append(one("epoch", Track(seen=0, **plain), (0, 0), 1.0))
    out.append(one("just over 32 bits", Track(seen=0, millis=3, **plain), (4294968, 0), 1.0))
    out.append(one("over 33 bits", Track(seen=0, millis=3, **plain), (8589935, 0), 1.0))
    out.append(one("far future", Track(seen=0, millis=1, **plain), (MAX_DAY * 86400 - 86400 * 200, 7000000), 1.0))
    out.append(one("year 100000", Track(seen=0, millis=1, **plain), (36500000 * 86400 + 12345, 0), 1.0))
    out.append(one("year zero", Track(seen=0, **plain), (-719000 * 86400, 0), 1.0))
    out.append(one("before year zero", Track(seen=0, **plain), (-800000 * 86400, 0), 1.0))
    out.append(one("millisecond one", Track(seen=0, millis=1, **plain), (0, 1000000), 1.0))
    return out


def select_cases():
    good = Row(4e-6, 1.0, 30.0, 40)
    out = [Case("select empty", kind="select", rows=(), mode=mode) for mode in (0, 1)]
    single = (("plain", good), ("count under", Row(4e-6, 1.0, 30.0, 29)), ("count equal", Row(4e-6, 1.0, 30.0, 30)), ("count high precision", Row(4e-6, 1.0, 9007199254740992.0, 9007199254740993)), ("count top", Row(4e-6, 1.0, 1e30, TOP)),
              ("decay nan", Row(4e-6, 1.0, math.nan, 40)), ("denominator edge", Row(4e-6, MIN_DENOM, 30.0, 40)), ("denominator under", Row(4e-6, BELOW, 30.0, 40)), ("denominator zero", Row(4e-6, 0.0, 30.0, 40)), ("denominator negative", Row(4e-6, -1.0, 30.0, 40)), ("denominator nan", Row(4e-6, math.nan, 30.0, 40)), ("denominator inf", Row(4e-6, math.inf, 30.0, 40)),
              ("number zero", Row(0.0, 1.0, 30.0, 40)), ("number minus zero", Row(-0.0, 1.0, 30.0, 40)), ("number snap", Row(-5e-16, 1.0, 30.0, 40)), ("number snap edge", Row(UP, 1.0, 30.0, 40)), ("number exact edge", Row(TINY, 1.0, 30.0, 40)), ("number under edge", Row(DOWN, 1.0, 30.0, 40)), ("number negative", Row(-1.0, 1.0, 30.0, 40)),
              ("number nan", Row(math.nan, 1.0, 30.0, 40)), ("number inf", Row(math.inf, 1.0, 30.0, 40)), ("both inf", Row(math.inf, math.inf, 30.0, 40)), ("rate one", Row(1.0, 1.0, 30.0, 40)), ("rate above", Row(4.0, 1.0, 30.0, 40)), ("rate just under", Row(0.9999999999999999, 1.0, 30.0, 40)), ("rate max", Row(sys.float_info.max, 1e-15, 30.0, 40)))
    for name, row in single:
        for mode in (0, 1):
            out.append(Case("select %s mode %d" % (name, mode), kind="select", rows=(row,), mode=mode))
            out.append(Case("select %s second mode %d" % (name, mode), kind="select", rows=(Row(9e-6, 1.0, 30.0, 40), row), mode=mode))
            out.append(Case("select %s first mode %d" % (name, mode), kind="select", rows=(row, Row(9e-6, 1.0, 30.0, 40)), mode=mode))
            out.append(Case("select %s third mode %d" % (name, mode), kind="select", rows=(Row(9e-6, 1.0, 30.0, 40), Row(1e-6, 1.0, 30.0, 40), row, Row(4e-6, 1.0, 30.0, 40)), mode=mode))
    near = [struct.unpack("<d", struct.pack("<Q", word))[0] for word in (0x3F00000080000001, 0x3F0000007FFFFFFF, 0x3F000000FFFFFFFF, 0x3F00000000000001)]
    for mode in (0, 1):
        for one_, two in ((0, 1), (1, 0), (2, 3), (3, 2), (0, 3), (3, 0)):
            out.append(Case("select close words %d %d mode %d" % (one_, two, mode), kind="select", rows=(Row(near[one_], 1.0, 30.0, 40), Row(near[two], 1.0, 30.0, 40)), mode=mode))
    negative_nan = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000123))[0]
    for mode in (0, 1):
        out.append(Case("select minus nan first mode %d" % mode, kind="select", rows=(Row(negative_nan, 1.0, 30.0, 40), good), mode=mode))
        out.append(Case("select minus nan second mode %d" % mode, kind="select", rows=(good, Row(negative_nan, 1.0, 30.0, 40)), mode=mode))
        out.append(Case("select nan against inf mode %d" % mode, kind="select", rows=(Row(math.nan, 1.0, 30.0, 40), Row(math.inf, 1.0, 30.0, 40)), mode=mode))
        out.append(Case("select zeros mode %d" % mode, kind="select", rows=(Row(-0.0, 1.0, 30.0, 40), Row(0.0, 1.0, 30.0, 40), Row(-0.0, 1.0, 30.0, 40)), mode=mode))
        out.append(Case("select equal mode %d" % mode, kind="select", rows=(good, good, good), mode=mode))
        out.append(Case("select skip then pick mode %d" % mode, kind="select", rows=(Row(4e-6, 1.0, 30.0, 2), good, Row(9e-6, 1.0, 30.0, 2), Row(1e-6, 1.0, 30.0, 40)), mode=mode))
    return out


def fold_cases():
    track = Track(high=0.002, low=0.001)
    other = Track(high=0.004, low=0.003)
    out = []
    tracks = ((3, track), (9, other))
    grid = (("no keys", (), (), 0.5), ("hit", (3,), (0.9,), 0.5), ("hit below", (3,), (0.2,), 0.5), ("hit equal", (3,), (0.5,), 0.5), ("miss", (4,), (), 0.0), ("miss below", (4,), (), 0.5), ("miss equal", (4,), (), 0.001), ("two hits", (3, 9), (0.9, 1.7), 0.5), ("falling", (3, 9), (1.7, 0.9), 0.5), ("mixed", (4, 3, 8, 9, 1), (0.9, 1.7), 0.0),
            ("hit nan", (3,), (math.nan,), 0.5), ("start nan hit", (3,), (0.9,), math.nan), ("start nan miss", (4,), (), math.nan), ("start nan empty", (), (), math.nan), ("after nan", (3, 9), (math.nan, 0.9), 0.0), ("hit infinite", (3,), (math.inf,), 0.5))
    for name, keys, curve, start in grid:
        for mode_byte in (0, 2, 3):
            out.append(Case("fold %s mode %d" % (name, mode_byte), kind="fold", tracks=tracks, keys=keys, curve=curve, start=start, mode_byte=mode_byte))
    for name, keys, start in (("no tree", (3, 4), 0.0), ("no tree above", (3,), 0.5), ("no tree no keys", (), 0.25)):
        out.append(Case("fold %s" % name, kind="fold", tracks=tracks, keys=keys, start=start, root=False))
    many = tuple((10 * index, Track(high=index * 1e-3)) for index in range(1, 18))
    for key in (10, 60, 65, 170, 175):
        out.append(Case("fold two level %d" % key, kind="fold", tracks=many, keys=(key,), curve=(0.9,) if key % 10 == 0 else (), start=0.0))
    return out


def base_cases():
    return miss_cases() + spacing_cases() + edge_cases() + value_cases() + row_cases() + gate_cases() + bucket_cases() + select_cases() + fold_cases()


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
        keys = [pick(5) * 3 for _ in range(pick(3) + 1)]
        now = pick(5000)
        steps = []
        price = 100.0 + pick(100)
        for _ in range(pick(50) + 8):
            now += (0, 1, 1, 2, 3, 5, 8, 13, 34, 120, 700)[pick(11)]
            price = max(0.001, price * (1 + (pick(2001) - 1000) / (20000.0 if pick(5) else 200.0)))
            steps.append((keys[pick(len(keys))], at(now, pick(10) * 100000000), price))
        out.append(Case("vector %d" % index, tracks=(), steps=tuple(steps), once=pick(9) == 0))
    return out


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(harness, case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %r want %r" % (case.name, got, want))
        outcomes.append(got)
    return outcomes


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


SURVIVORS = {
    (0x392BAE9, "immediate"): "range check of the seconds carry, a one second step cannot reach the bound",
    (0x392BAF6, "immediate"): "range check of the seconds carry, a one second step cannot reach the bound",
    (0x392BB29, "immediate"): "sign fix of a floor by 86400 on a value that is never negative",
    (0x392BBBE, "immediate"): "text length passed for a log line that is built and freed unread",
    (0x392BD54, "immediate"): "text length passed for a log line that is built and freed unread",
    (0x392BEDC, "immediate"): "text length passed for a log line that is built and freed unread",
    (0x392BBA3, "immediate"): "log flag and line word beside a path that only logs",
    (0x392BD39, "immediate"): "log flag and line word beside a path that only logs",
    (0x392BEC1, "immediate"): "log flag and line word beside a path that only logs",
    (0x392BB19, "immediate"): "low multiplier bit of a floor by 86400 on a seconds carry of 0 or 1",
    (0x392C0BD, "immediate"): "year at or below zero, the negative value ends at the clamp to zero",
    (0x392C0C5, "immediate"): "year at or below zero, the negative value ends at the clamp to zero",
    (0x392C0CC, "immediate"): "year at or below zero, the negative value ends at the clamp to zero",
    (0x392C0D2, "immediate"): "year at or below zero, the negative value ends at the clamp to zero",
    (0x392C0DC, "immediate"): "year at or below zero, the negative value ends at the clamp to zero",
    (0x392C104, "immediate"): "sign fix on a year whose negative side ends at the clamp to zero",
    (0x392C0FA, "immediate"): "low multiplier bit of a floor by 100, the floor is the same on every reached year",
    (0x3930FB9, "immediate"): "low bit of the finite mask, a root never reaches the top of the double range",
    (0x3930FCB, "immediate"): "low bit of the finite bound, a root never reaches the top of the double range",
    (0x3931002, "displacement"): "word read only by the unwind path of the new tracker",
    (0x393110B, "immediate"): "fixed date constant, the calendar arithmetic has one input",
    (0x3931115, "immediate"): "fixed date constant, the calendar arithmetic has one input",
    (0x393112F, "immediate"): "fixed date constant, the floor by 600000 hides the low bit",
    (0x3931168, "immediate"): "dangling pointer of an empty queue, never read",
    (0x3931168, "displacement"): "dangling pointer of an empty queue, the next store covers the moved word and the field is never read",
}


def survivor_reason(va, kind):
    return SURVIVORS.get((va, kind), "unclassified")



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
    for target in SUBJECTS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.dates = dict(control.dates)
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is None:
                hit = first_failure(harness, [case for case in reach[va] if not case.name.startswith("vector ")])
            results.append((va, kind, "killed", hit.name) if hit is not None else (va, kind, "survived", survivor_reason(va, kind)))
    return results


def logger_head(image):
    """Real rows at the head of the metric step: the flag byte decides whether the counter clears."""
    rows = []
    for flag in (0, 1, 2):
        harness = Harness(image)
        machine = harness.machine
        harness.fresh(Case("logger"))
        machine.real = frozenset()
        machine.calls[0x4EE3800] = lambda m: m.regs.__setitem__(RAX, 5)
        memory = machine.memory
        memory.write(ROWS + 0x20, 1, flag)
        memory.write(ROWS + 0x100, 8, ROWS + 0x180)
        memory.write(ROWS + 0x108, 8, ROWS + 0x1F8)
        memory.write(ROWS + 0x1F8, 8, 0x77)
        machine.stop = 0x3375133 if flag == 1 else 0x337552F
        machine.run(LOGGER, {RDI: ROWS, RSI: ROWS + 0x100})
        rows.append((flag, "%#x" % machine.stop, memory.read(ROWS + 0x1F8, 8)))
    return rows


REFERENCE = (
    ("rate", "valid_rate gives num/denom", "select gives min(1, sqrt(num/denom)); a non-finite root is returned as it is", "select rate above mode 1"),
    ("snap edge", "num >= -1e-15 snaps to 0", "only num > -1e-15 snaps; -1e-15 itself is dropped", "select number exact edge mode 1"),
    ("selection", "f64 min and max", "a total order on bits: positive NaN above infinity, negative values reversed bit order under zero", "select nan against inf mode 1"),
    ("queue", "pop only when len equals capacity", "oldest popped whenever it is over 20 s old, even past 100 s; never popped at 20 s or under, and the queue doubles when full", "full queue young 8"),
    ("return", "bool of bucket advance", "no value returned; the flag goes to a metric call that clears the second counter", "bucket below"),
    ("second counter", "log_counter only rises", "cleared on every bucket advance", "bucket below"),
    ("label", "no label field", "value starts with the text of the key, built before the default state", "first sample of key 7"),
    ("default bucket", "max_seen_bucket 0", "day 365 of the Unix epoch, 52560 buckets: date word from 0xafaa8 then floor of millis by 600000", "new key at the default bucket"),
    ("queue capacity", "VecDeque::with_capacity(8)", "starts with capacity 0 and a dangling pointer; the first push grows it to 4", "first sample of key 0"),
    ("consumer", "delay_for_action_kind uses one key", "fold over a key set, largest delay wins, absent tracker gives 0.001, unordered compare panics", "fold mixed mode 2"),
)


FIELD_PINS = (("samples", 0x18, 0x3931B08, 4), ("emas", 0x38, 0x3931B6B, 4), ("val.min", 0x60, 0x3931BC6, 6), ("val.max", 0x68, 0x3931BD2, 6), ("n_updates", 0x70, 0x3931CBA, 4), ("n_bucket_updates", 0x78, 0x3931CFF, 4))
KEY_READERS = (0x39314D0, 0x3931730, 0x3931A60)


def field_rows(image):
    rows = []
    for name, offset, address, size in FIELD_PINS:
        data = bytes(image.blob[image.offset(address):image.offset(address) + size])
        if data[-1] != offset:
            raise EvidenceError("field pin at %#x" % address)
        rows.append((name, "%#x" % offset, "%#x" % address, data.hex()))
    return rows


def key_rows(image):
    rows = []
    for target in KEY_READERS:
        low, high = image.exact_fde(target)
        code = bytes(image.blob[image.offset(low):image.offset(high)])
        at = code.find(b"\x48\x8d\x35")
        while at >= 0:
            window = code[at + 7:at + 18]
            mark = window.find(b"\xba")
            if mark >= 0:
                size = struct.unpack_from("<I", window, mark + 1)[0]
                where = low + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
                if 0 < size < 64 and where < 0x900000:
                    rows.append(("%#x" % target, "%#x" % (low + at), bytes(image.blob[where:where + size]).decode("ascii")))
            at = code.find(b"\x48\x8d\x35", at + 1)
    return rows


def constant_rows(image):
    rows = []
    for address, meaning in CONSTANTS:
        rows.append(("%#x" % address, bytes(image.blob[address:address + 8]).hex(), repr(struct.unpack_from("<d", image.blob, address)[0]), meaning))
    for address, meaning in PAIRS:
        rows.append(("%#x" % address, bytes(image.blob[address:address + 16]).hex(), repr(struct.unpack_from("<2d", image.blob, address)), meaning))
    return rows


def serde_rows(image):
    out = []
    for text in SERDE:
        where = bytes(image.blob).find(text)
        if where < 0:
            raise EvidenceError("text not in the image: %r" % text)
        out.append(("%#x" % where, text.decode().replace("\n", " ")))
    return out


def slot_rows(image):
    relative = image.relative()
    return [("%#x" % slot, "%#x" % relative.get(slot, 0), meaning) for slot, meaning in ((SLOT_WRITER, "record_sample, read by the three sampler copies"), (SLOT_CURVE, "delay curve, hook in the fold"), (0x576E8A8, "time plus delta, real"), (0x576E8B0, "date plus days, real"), (0x576E8C0, "seconds between two times, real"), (0x576E040, "format, real"), (0x576E890, "date from a day number, real"), (0x57718C8, "queue growth, real"), (SLOT_ONCE, "lazy cell, hook"))]


def edge_rows(cases, outcomes):
    rows = []
    for case, got in zip(cases, outcomes):
        if case.kind == "select":
            rows.append((case.name, case.mode, got["some"], "" if got["value"] is None else "%#018x" % got["value"]))
    return rows


def outcome_row(case, got):
    digest = hashlib.sha256(repr(sorted(fix_nan(got).items(), key=str)).encode()).hexdigest()[:16]
    if case.kind == "record":
        label = "panic" if got["panic"] else "keys %d" % got["length"]
    elif case.kind == "select":
        label = "none" if not got["some"] else "rate"
    else:
        label = "panic" if got["panic"] else "value"
    return (case.kind, case.name, label, digest)


def analyse(image, mutate=True, vectors=VECTORS):
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in SUBJECTS}
    for target in SUBJECTS:
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in SUBJECTS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, serde=serde_rows(image), slots=slot_rows(image), constants=constant_rows(image), logger=logger_head(image), edges=edge_rows(cases, outcomes), fields=field_rows(image), keys=key_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in SUBJECTS for row in result["table"][target]])
    tsv("constants.tsv", ("address", "bytes", "value", "meaning"), result["constants"])
    tsv("defaults.tsv", ("field", "offset", "value"), (("bucket vector capacity and length", "+0x38, +0x48", ROW_START), ("decay of the four rows", "+0x10 of each row", " ".join("%g" % value for value in INTERVALS)), ("queue capacity", "+0x18", DEQUE_START), ("bucket millis", "+0x50", BUCKET_MILLIS), ("min", "+0x60", DEFAULT_MIN), ("max", "+0x68", DEFAULT_MAX), ("seen bucket", "+0x58", (DEFAULT_DAY * 86400000) // BUCKET_MILLIS)))
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("select-edges.tsv", ("case", "mode", "some", "value_bits"), result["edges"])
    tsv("logger-head.tsv", ("flag", "stop", "word_after"), result["logger"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("field-offsets.tsv", ("field", "offset", "address", "bytes"), result["fields"])
    tsv("field-keys.tsv", ("function", "site", "key"), result["keys"])
    tsv("slots.tsv", ("slot", "target", "meaning"), result["slots"])
    tsv("outcomes.tsv", ("kind", "case", "result", "digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in SUBJECTS},
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

