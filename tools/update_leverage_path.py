#!/usr/bin/env python3
"""Pin the node #94 updateLeverage path: the leverage body, its handler and the routing wrapper.

Real rows run from the signed handler in all three copies, the routing wrapper and the leverage body, with real tree, clone and
set helpers. A separately written rule list predicts every result, callee argument and
written word, and every reached conditional row, immediate and field offset of the subject code is edited. No objdump or readelf
output is parsed and the binary is never executed. Standard library only.

    python3 tools/update_leverage_path.py --out <dir>
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
TAG_LEVERAGE, TAG_CROSS, TAG_SWITCH, TAG_CROSS_LOW, TAG_ISOLATED_LOW, TAG_TABLE, TAG_CAP = 0x43, 0x44, 0x45, 0x46, 0x47, 0x4F, 0x50
TAG_SPOT, TAG_OPERATIONS = 0x15E, 0x170
TAG_TEXTS = {TAG_LEVERAGE: "Invalid leverage value", TAG_CROSS: "Cross margin is not allowed for this asset.", TAG_SWITCH: "Cannot switch leverage type with open position.",
             TAG_CROSS_LOW: "Cross position does not have sufficient margin available to decrease leverage. To decrease leverage, deposit more collateral.",
             TAG_ISOLATED_LOW: "Isolated position does not have sufficient margin available to decrease leverage. To decrease leverage, add margin to the position.",
             TAG_SPOT: "Spot not supported", TAG_OPERATIONS: "Too many abstraction operations. Automated users should manually manage collateral."}
CAP_TEXT = 0x1FB430
CAP_WORDS = b"Max leverage at current position size is "
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_BODY = 0x5773DA8
SLOT_TIER_CAP = 0x5775998
SLOT_NAME = 0x576E0D0
SLOT_MARGIN_CHECK = 0x57746F0
SLOT_RECORD = 0x5773190
SLOT_WIRE = 0x5773950
SLOT_DEX = 0x5773D80
SLOT_DEX_ROW = 0x5774740
SLOT_CONTAINS = 0x5774748
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048, 0x576EB38, 0x576E1B0)
MARK_BASE = 0x7700000000
BODY = 0x37098A0
USER_HASH = 0x399C7A0
ROWS = 0x36F57F0
DEFAULT_ROW = 0x3BFFFD0
DROP_STATUS = 0x3379490
INDEX = 0x370E6A0
PEEK = 0x36F7350
LOC_OPEN_SUB = 0x56F1C98
LOC_OPEN_ADD = 0x56F1C68
TOP = MASK[8]
HIGH = 1 << 63
DEX_STRIDE = 0x2F0
PERP_STRIDE = 0x30
PRICE_STRIDE = 0x60
USER_STRIDE = 0x78
BUCKETS = 32
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
OUT = HEAP_BASE + 0x40
ACTION = HEAP_BASE + 0xC0
USER = HEAP_BASE + 0x160
USER_ROW = HEAP_BASE + 0x180
TRACK = HEAP_BASE + 0x1C0
EMPTY_VALUE = HEAP_BASE + 0x200
NAME = HEAP_BASE + 0x280
NAME_BYTES = b"TEST"
SMALL_TABLE = 50
EMPTY_MAX = 3
DEXES = STATE + STATE_SIZE
DEX_ROOM = 3
PERPS = DEXES + DEX_ROOM * DEX_STRIDE + 0x40
PERP_ROOM = 8
PRICES = PERPS + DEX_ROOM * PERP_ROOM * PERP_STRIDE
TABLES = PRICES + DEX_ROOM * PERP_ROOM * PRICE_STRIDE
BUMP = TABLES + DEX_ROOM * (BUCKETS * USER_STRIDE + BUCKETS + 0x20)
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
USER_A = bytes(range(1, 21))
USER_B = bytes(range(0x21, 0x35))
USER_C = bytes(range(0x41, 0x55))
ROW_TAIL = bytes(0xC0 + index for index in range(0x28))
REFUSAL = 0x123
WIRE_BYTES = bytes(0x80 | (index * 5 + 3) & 0xFF for index in range(0x5E))
STAT_WORDS = (0x4141414141414141, 0x4242424242424242, 0x4343434343434343, 0x44444444)

AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


ROW_TREE = Layout(0x2C8, 8, 0, 0x40, 0x2C0, 0x320, 0x322, 0x328)
SECOND_TREE = Layout(0xB8, 4, 0, 0x10, 0xB0, 0xE4, 0xE6, 0xE8)
SET_TREE = Layout(8, 20, 0xE4, 0, 0, 0xE4, 0xE6, 0xE8)
OPEN_TREE = Layout(8, 8, 0x60, 8, 0, 0xB8, 0xBA, 0xC0)
TABLE_TREE = Layout(0x270, 4, 8, 0x38, 0, 0x29C, 0x29E, 0x2A0)
TIER_TREE = Layout(0x168, 8, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8)


class Copy:
    def __init__(self, name, handler, apply, base, byte, tracker_at, count_at, user_row, tracker, pre, finish, post, drop_pre, drop_post):
        self.name, self.handler, self.apply, self.base, self.byte, self.tracker_at, self.count_at = name, handler, apply, base, byte, tracker_at, count_at
        self.user_row, self.tracker, self.pre, self.finish, self.post, self.drop_pre, self.drop_post = user_row, tracker, pre, finish, post, drop_pre, drop_post


COPIES = (Copy("a", 0x21E0B70, 0x2721860, 0x5B8, 0x3ACB, 0x770, 0x7D0, 0x2755400, 0x1F84640, 0x272FE00, 0x272F880, 0x272D000, 0x277EBA0, 0x277EBA0),
          Copy("b", 0x4897800, 0x4D26CC0, 0x5B8, 0x3ACB, 0x770, 0x7D0, 0x46F2FE0, 0x47D7550, 0x46EF9A0, 0x46EF720, 0x46EAA10, 0x4DAF4A0, 0x472F840),
          Copy("c", 0x48976C0, 0x4D27490, 0x1038, 0x454B, 0x11F0, 0x1250, 0x46F2E60, 0x47D7550, 0x46EFB70, 0x46EF4A0, 0x46EA0B0, 0x4DAF4A0, 0x472F840))
FUNCTIONS = dict(body=BODY)
for copy_row in COPIES:
    FUNCTIONS["handler_" + copy_row.name] = copy_row.handler
    FUNCTIONS["apply_" + copy_row.name] = copy_row.apply


def signed(value):
    return value - (1 << 64) if value >= HIGH else value


def user_hash(key):
    value = int.from_bytes(key[:8], "little") * 0x9E3779B97F4A7C15 & TOP
    return (value ^ (value >> 29)) & TOP


class Case:
    DEFAULTS = dict(entry="body", copy=0, users=(), crowd=0, who=USER_A, asset=0, cross=0, level=5, perps=((0, 20, 20),), prices=(100,), dex_id=0, dexes=1, tables=(), tier_height=0, cap=50, checks=(0, 0), flag=0x5A, opens=(), touched=(), active=(), height=0,
                    default=(1, 3), wire=None, klass=0, flag0=0, flag1=0, byte=0, word=0x77, counter=5, track=0, total=9, sets=(1, 0), pre=OK, post=OK, stale=0)

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


HOOKED = {RESUME, USER_HASH, ROWS, DEFAULT_ROW, DROP_STATUS, INDEX}
for copy_row in COPIES:
    HOOKED |= {copy_row.user_row, copy_row.tracker, copy_row.pre, copy_row.finish, copy_row.post, copy_row.drop_pre, copy_row.drop_post}


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_TIER_CAP, self.on_cap), (SLOT_NAME, self.on_name), (SLOT_MARGIN_CHECK, self.on_check), (SLOT_RECORD, self.on_record), (SLOT_WIRE, self.on_wire), (SLOT_DEX, self.on_dex), (SLOT_DEX_ROW, self.on_dex), (SLOT_CONTAINS, self.on_contains))
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
        machine.calls = {RESUME: self.on_panic, USER_HASH: self.on_hash, ROWS: self.on_rows, DEFAULT_ROW: self.on_default, DROP_STATUS: self.on_drop_status, INDEX: self.on_index}
        for copy in COPIES:
            machine.calls[copy.user_row] = self.on_user_row
            machine.calls[copy.tracker] = self.on_tracker
            machine.calls[copy.pre] = self.on_pre
            machine.calls[copy.finish] = self.on_finish
            machine.calls[copy.post] = self.on_post
            machine.calls[copy.drop_pre] = self.on_drop_result
            machine.calls[copy.drop_post] = self.on_drop_result
        self.case = None
        self.copy = COPIES[0]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.values = {}
        self.dex_at = DEXES
        self.calls_seen = 0
        self.searches = 0

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

    def user_key(self, at):
        return self.machine.memory.bytes_at(at, 20)

    def on_hash(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex_at + 0x118, "hash seed of the user table")
        regs[RAX] = user_hash(self.user_key(regs[RSI]))

    def on_rows(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex_at + 0xF8, "user table of the dex")
        user = self.user_key(regs[RSI])
        self.events.append(("rows", user))
        regs[RAX] = self.values.get(user, EMPTY_VALUE)

    def on_cap(self, machine):
        regs, memory = machine.regs, machine.memory
        node, level = memory.read(regs[RDI] + 0x18, 8), memory.read(regs[RDI] + 0x20, 8)
        for _ in range(level if node else 0):
            node = memory.read(node + TIER_TREE.edge_at, 8)
        self.events.append(("cap", regs[RSI], memory.read(node + 0x18, 1) if node else EMPTY_MAX))
        regs[RAX] = 0xAB00 | self.case.cap

    def on_name(self, machine):
        regs, memory = machine.regs, machine.memory
        size = memory.read(regs[RSI] + 0x10, 8)
        self.expect(memory.read(regs[RSI] + 8, 8) == NAME, "name of the perp row")
        at = self.bump(size)
        memory.put_bytes(at, NAME_BYTES)
        memory.put_bytes(regs[RDI], struct.pack("<3Q", size, at, size))
        regs[RAX] = regs[RDI]

    def on_index(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == self.dex_at + 0x128 and self.user_key(regs[RSI]) == self.case.who, "index arguments")
        self.events.append(("index", regs[RDX], regs[RCX] & MASK[4]))

    def on_check(self, machine):
        regs, memory = machine.regs, machine.memory
        mode = regs[RCX] & MASK[4]
        self.expect(mode in (1, 2) and regs[RSI] == (self.case.cross & 1) ^ 1 and regs[R9] == self.dex_at + 0x60 and memory.read(regs[RSP], 8) == self.dex_at, "margin check arguments")
        at = regs[RDI]
        rows = dict(self.walk(ROW_TREE, memory.read(at + 8, 8), memory.read(at + 0x10, 8))[0])
        row = rows[struct.pack("<Q", regs[RDX])]
        second = self.walk(SECOND_TREE, memory.read(at + 0x28, 8), memory.read(at + 0x30, 8))[0]
        words = struct.unpack("<3QI", memory.bytes_at(at + 0x40, 28))
        self.events.append(("check", mode, regs[RDX], signed(memory.read(at, 8)), struct.unpack_from("<I", row, 4)[0], struct.unpack_from("<I", row, 0x38)[0], memory.read(at + 0x20, 8), tuple(struct.unpack("<I", key)[0] for key, _ in second), words))
        regs[RAX] = self.case.checks[mode - 1]

    def on_record(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 0, "recorder first argument")
        self.events.append(("recorded", machine.regs[RSI]))

    def on_default(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDX] == self.dex_at, "default row dex")
        self.events.append(("default row", regs[RSI]))
        memory.put_bytes(regs[RDI], struct.pack("<IIQ", self.case.default[0], self.case.default[1], 0x5151))
        regs[RAX] = regs[RDI]

    def on_drop_status(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == 0x141, "dropped lookup status")

    def on_wire(self, machine):
        regs, memory = machine.regs, machine.memory
        case, copy = self.case, self.copy
        self.expect(regs[RSI] & MASK[4] == 0x5151 and regs[RDX] == STATE + copy.base and regs[RCX] == STATE + 0x90, "wire arguments")
        kind, value = case.wire
        at = regs[RDI]
        if kind == "error":
            memory.put_bytes(at, struct.pack("<H", value) + WIRE_BYTES)
            return
        memory.write(at, 2, OK)
        memory.write(at + 8, 4, 1 if kind == "spot" else 0)
        memory.write(at + 0x10, 8, value)

    def on_dex(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + self.copy.base and regs[RSI] < self.case.dexes, "dex lookup")
        regs[RAX] = DEXES + regs[RSI] * DEX_STRIDE

    def on_user_row(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE and self.user_key(regs[RSI]) == self.case.who, "user row")
        self.events.append(("user row",))
        regs[RAX] = USER_ROW

    def on_tracker(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + self.copy.tracker_at and self.user_key(regs[RSI]) == self.case.who, "tracker row")
        self.events.append(("tracker",))
        regs[RAX] = TRACK

    def on_contains(self, machine):
        regs, memory = machine.regs, machine.memory
        index = self.searches
        self.searches += 1
        self.expect(regs[RDI] == TRACK + 0x18 * index and memory.bytes_at(regs[RSI], 12) == bytes(range(0x50, 0x5C)), "set search")
        self.expect(regs[RDX] == 0x1000 * (2 * index + 1) and regs[RCX] == 0x1000 * (2 * index + 2), "window words")
        regs[RAX] = 0xAB00 | self.case.sets[index]

    def on_pre(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE and self.user_key(regs[RSI]) == self.case.who and regs[RDX] == self.case.word and regs[RCX] & 0xFF == 1, "routed pre")
        self.expect(memory.read(regs[R9], 8) == 2, "route marker")
        self.events.append(("pre", regs[R8], memory.read(regs[RSP] + 8, 4)))

    def on_finish(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE and self.user_key(regs[RSI]) == self.case.who and regs[RDX] == self.case.word and regs[RCX] & 0xFF == 1, "routed finish")
        self.events.append(("finish", regs[R8]))

    def on_post(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE and self.user_key(regs[RDX]) == self.case.who, "settlement arguments")
        stage = self.calls_seen
        self.calls_seen += 1
        first = stage == 0 and self.case.klass == 2
        self.events.append(("settle", regs[RCX], regs[R8] & 0xFF, regs[R9], memory.read(regs[RSP] + 8, 8), memory.read(regs[RSP] + 0x18, 8)) + ((memory.read(regs[RSP] + 0x10, 8),) if self.case.klass == 2 else ()))
        status = self.case.pre if first else self.case.post
        memory.write(regs[RDI], 2, status)
        regs[RAX] = regs[RDI]

    def on_drop_result(self, machine):
        tag = machine.memory.read(machine.regs[RDI], 2)
        self.events.append(("settle dropped", tag))

    def node(self, layout, rows, size):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(rows))
        spare = rows[0][0] if self.case.stale and rows else b"\xfe" * layout.key_size
        if self.case.stale == 2 and layout is ROW_TREE:
            spare = struct.pack("<Q", self.case.asset)
        for slot in range(11):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, spare)
        for slot, (key, value) in enumerate(rows):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
            if layout.val_size:
                memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        return at

    def tree(self, layout, items, height):
        """Real shaped nodes; returns root and level, with empty inner nodes up to `height`."""
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
        """In-order (key, value bytes) rows and the node list of one tree."""
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

    def put_table(self, table, seed_at, users):
        """Hashbrown control bytes and 0x78 byte elements at the real probe positions."""
        memory = self.machine.memory
        ctrl = table + BUCKETS * USER_STRIDE
        control = bytearray(b"\xff" * (BUCKETS + 16))
        places = {}
        for key in users:
            value = user_hash(key)
            top = value >> 57
            position, stride = value & (BUCKETS - 1), 0
            while True:
                free = [index for index in range(16) if control[(position + index) & (BUCKETS - 1)] == 0xFF]
                if free:
                    slot = (position + free[0]) & (BUCKETS - 1)
                    break
                stride += 16
                position = (position + stride) & (BUCKETS - 1)
            control[slot] = top
            if slot < 16:
                control[BUCKETS + slot] = top
            places[key] = ctrl - USER_STRIDE * (slot + 1)
        memory.put_bytes(ctrl, bytes(control))
        memory.put_bytes(seed_at, struct.pack("<4Q", ctrl, BUCKETS - 1, 0x4040, len(users)))
        return places

    def row_bytes(self, row):
        _, mode, leverage, margin, size, table = row
        return struct.pack("<IIqq", mode, leverage, margin, size) + ROW_TAIL[:0x20] + struct.pack("<I", table) + ROW_TAIL[0x24:]

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.copy = copy = COPIES[case.copy]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.values = {}
        self.calls_seen = 0
        self.searches = 0
        dex = case.asset // 10000 if case.entry in ("move", "topup") else case.asset // 10000
        self.dex_at = DEXES + dex * DEX_STRIDE if dex < DEX_ROOM else DEXES
        at = self.dex_at
        memory.write(STATE + copy.base + 8, 8, DEXES)
        memory.write(STATE + copy.base + 0x10, 8, case.dexes)
        memory.write(STATE + 0x58, 8, case.counter)
        memory.write(STATE + copy.count_at, 8, case.total)
        memory.write(STATE + 0x5B0, 1, case.flag0)
        memory.write(STATE + 0x5B1, 1, case.flag1)
        memory.write(STATE + copy.byte, 1, case.byte)
        memory.put_bytes(STATE + 0x60, bytes(range(0x50, 0x5C)))
        memory.put_bytes(STATE + 0x4E8, struct.pack("<4Q", 0x1000, 0x2000, 0x3000, 0x4000))
        memory.write(USER_ROW + 0x3C, 1, case.klass)
        memory.write(TRACK + 0x30, 8, case.track)
        memory.put_bytes(USER, case.who)
        for index in range(DEX_ROOM):
            row = DEXES + index * DEX_STRIDE
            memory.write(row + 0x50, 8, case.word)
        perps = PERPS + dex * PERP_ROOM * PERP_STRIDE if dex < DEX_ROOM else PERPS
        prices = PRICES + dex * PERP_ROOM * PRICE_STRIDE if dex < DEX_ROOM else PRICES
        memory.write(at + 8, 8, perps)
        memory.write(at + 0x10, 8, len(case.perps))
        memory.write(at + 0x30, 8, case.dex_id if case.dex_id is not None else dex)
        memory.write(at + 0x68, 8, prices)
        memory.write(at + 0x70, 8, len(case.prices))
        memory.write(at + 0x2ED, 1, case.flag)
        for index, (kind, leverage, table) in enumerate(case.perps[:PERP_ROOM]):
            memory.write(perps + index * PERP_STRIDE + 0x18, 4, table)
            memory.write(perps + index * PERP_STRIDE + 0x28, 1, kind)
            memory.put_bytes(perps + index * PERP_STRIDE, struct.pack("<3Q", len(NAME_BYTES), NAME, len(NAME_BYTES)))
        for index, price in enumerate(case.prices[:PERP_ROOM]):
            memory.write(prices + index * PRICE_STRIDE + 0x20, 8, price)
        memory.write(prices + len(case.prices) * PRICE_STRIDE + 0x20, 8, 5)
        keys = [row[0] for row in case.users] + [bytes([0xE0, index]) + bytes(18) for index in range(case.crowd)]
        ordered = [bytes([0xE0, index]) + bytes(18) for index in range(case.crowd)] + [row[0] for row in case.users]
        places = self.put_table(TABLES + dex * (BUCKETS * USER_STRIDE + BUCKETS + 0x20) if dex < DEX_ROOM else TABLES, at + 0xF8, ordered)
        memory.put_bytes(at + 0x118, b"\x11" * 32)
        rows_nodes = []
        for key in keys:
            memory.put_bytes(places[key], key + b"\x00" * 4)
        for user, account, rows, count, second in case.users:
            value = places[user] + 0x18
            self.values[user] = value
            memory.write(value, 8, account)
            self.put_tree(value + 8, ROW_TREE, [(struct.pack("<Q", row[0]), self.row_bytes(row)) for row in sorted(rows)], case.height)
            memory.write(value + 0x20, 8, count)
            self.put_tree(value + 0x28, SECOND_TREE, [(struct.pack("<I", key), bytes([key & 0xFF]) * 16) for key in sorted(second)])
            memory.put_bytes(value + 0x40, struct.pack("<3QI", *STAT_WORDS))
        items = []
        for table, tiers in sorted(case.tables):
            root, level = self.tree(TIER_TREE, [(struct.pack("<Q", index), bytes(0x18) + bytes([top]) + bytes(7)) for index, top in enumerate(tiers)], case.tier_height)
            items.append((struct.pack("<I", table), bytes(0x18) + struct.pack("<2Q", root, level) + bytes(0x10)))
        root, level = self.tree(TABLE_TREE, items, 0)
        memory.write(at + 0x38, 8, root)
        memory.write(at + 0x40, 8, level)
        memory.put_bytes(NAME, NAME_BYTES)
        self.put_tree(at + 0x170, OPEN_TREE, [(struct.pack("<Q", key), struct.pack("<q", value)) for key, value in sorted(case.opens)], case.height)
        self.put_tree(at + 0x188, SET_TREE, [(key, b"") for key in sorted(case.touched)], case.height)
        self.put_tree(at + 0x158, SET_TREE, [(key, b"") for key in sorted(case.active)], case.height)
        memory.write(EMPTY_VALUE + 8, 8, 0)
        memory.write(EMPTY_VALUE + 0x10, 8, 0xFEED)
        self.fixed = set(self.live)

    def enter(self):
        case, copy, machine, memory = self.case, self.copy, self.machine, self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x70)
        if case.entry == "body":
            machine.run(BODY, {RDI: OUT, RSI: self.dex_at, RDX: USER, RCX: case.asset, R8: case.cross, R9: case.level})
            return self.status(OUT)
        memory.put_bytes(ACTION, struct.pack("<IIB", case.level, 0x5151, case.cross))
        machine.run(copy.handler, {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
        return self.outer()

    def status(self, at):
        memory = self.machine.memory
        tag = memory.read(at, 2)
        if tag == OK:
            return ("ok",)
        if tag == TAG_CAP:
            return ("error", tag, memory.read(at + 4, 4))
        if tag == TAG_TABLE:
            cap, where, size = struct.unpack("<3Q", memory.bytes_at(at + 8, 24))
            self.expect(self.live.pop(where, None) == cap, "name block")
            return ("error", tag, memory.bytes_at(where, size))
        return ("error", tag)

    def outer(self):
        memory = self.machine.memory
        code = memory.read(OUT, 1)
        if code == 0x0D:
            return ("ok",)
        self.expect(code == 0x0E, "outer code")
        tag = memory.read(OUT + 8, 2)
        if self.case.wire[0] == "error":
            self.expect(memory.bytes_at(OUT + 10, 0x5E) == WIRE_BYTES, "wire error object")
        if tag == TAG_SPOT:
            return ("error", tag, memory.read(OUT + 0x10, 8))
        return self.status(OUT + 8)

    def view(self):
        """Every word the subject may write, read back from real layouts."""
        case, memory = self.case, self.machine.memory
        at = self.dex_at
        nodes = []

        def tree(layout, place):
            root, level, size = struct.unpack("<3Q", memory.bytes_at(place, 24))
            rows, used = self.walk(layout, root, level)
            self.expect(len(rows) == size, "tree length word")
            nodes.extend(used)
            return rows

        state = dict(touched=tuple(key for key, _ in tree(SET_TREE, at + 0x188)), active=tuple(key for key, _ in tree(SET_TREE, at + 0x158)),
                     opens=tuple((struct.unpack("<Q", key)[0], struct.unpack("<q", value)[0]) for key, value in tree(OPEN_TREE, at + 0x170)),
                     counter=memory.read(STATE + 0x58, 8), track=memory.read(TRACK + 0x30, 8), total=memory.read(STATE + self.copy.count_at, 8))
        value = self.values.get(case.who)
        if value is not None:
            rows = tree(ROW_TREE, value + 8)
            state["account"] = signed(memory.read(value, 8))
            state["count"] = memory.read(value + 0x20, 8)
            state["rows"] = tuple((struct.unpack("<Q", key)[0], data[:0x3C]) for key, data in rows)
        return state, nodes

    def run(self, case):
        self.fresh(case)
        memory = self.machine.memory
        end = self.cur - HEAP_BASE
        before = bytes(memory.heap[:end])
        try:
            result = self.enter()
        except Panicked:
            result = ("panic",)
        state, nodes = self.view()
        now = bytearray(memory.heap[:end])
        at = self.dex_at
        copy = self.copy
        skips = [(OUT, 0x70), (ACTION, 0x20), (STATE + 0x58, 8), (TRACK + 0x30, 8), (STATE + copy.count_at, 8), (at + 0x170, 24), (at + 0x188, 24), (at + 0x158, 24)]
        value = self.values.get(case.who)
        if value is not None:
            skips += [(value, 8), (value + 8, 24), (value + 0x20, 8)]
        for node in nodes:
            if node < self.cur:
                skips.append((node, self.live.get(node, 0)))
        for start, size in skips:
            now[start - HEAP_BASE:start - HEAP_BASE + size] = before[start - HEAP_BASE:start - HEAP_BASE + size]
        rest = bytes(now) == before
        used = set(nodes) | self.fixed
        leaked = [] if result == ("panic",) else sorted(block for block in self.live if block not in used)
        return dict(result=result, events=list(self.events), state=state, rest=rest, leaked=leaked)


class Model:
    """Separately written rules; state starts from the case fields and is edited as the rules say."""

    def __init__(self, case):
        self.case = case
        self.events = []
        self.users = {user: dict(account=account, rows={row[0]: list(row) for row in rows}, count=count, second=tuple(sorted(second))) for user, account, rows, count, second in case.users}
        self.fresh_rows = set()
        self.touched = set(case.touched)
        self.opens = dict(case.opens)
        self.counter = case.counter
        self.track = case.track
        self.total = case.total
        self.payload = None

    def add_recording(self, left, right, location):
        total = left + right
        if -HIGH <= total < HIGH:
            return total
        self.events.append(("recorded", location))
        return HIGH - 1 if total > 0 else -HIGH

    def open_interest(self, asset, size):
        if size == -HIGH:
            self.opens.setdefault(asset, 0)
            raise Panicked("abs of the smallest size")
        now = self.opens.setdefault(asset, 0)
        width = abs(size)
        low = self.add_recording(now, -width, LOC_OPEN_SUB)
        self.opens[asset] = self.add_recording(low, width, LOC_OPEN_ADD)

    def refuse(self, tag, payload=None):
        self.payload = payload
        return tag

    def body(self, asset, cross, level):
        """Tag of the leverage change; writes follow the rules below."""
        case = self.case
        dex, local = asset // 10000, asset % 10000
        if dex != case.dex_id or local >= len(case.perps):
            raise Panicked("asset outside this dex")
        kind, _, table = case.perps[local]
        if cross and kind != 0:
            return TAG_CROSS
        if table < SMALL_TABLE:
            top = table
        else:
            tiers = dict(case.tables).get(table)
            if tiers is None:
                raise Panicked("table id")
            top = tiers[0] if tiers else EMPTY_MAX
        if level > top:
            return TAG_LEVERAGE
        self.events.append(("rows", case.who))
        user = self.users.get(case.who)
        if user is None:
            raise EvidenceError("a new user row is not modelled")
        row = user["rows"].get(asset)
        if row is None:
            self.events.append(("default row", asset))
        elif row[4] != 0:
            if (row[1] == 0) != bool(cross):
                return TAG_SWITCH
            if local >= len(case.prices):
                raise Panicked("price row")
            self.events.append(("cap", case.prices[local], top))
            if level > case.cap:
                return self.refuse(TAG_CAP, case.cap)
            if table != row[5] or level < row[2]:
                shadow = (user["account"], level, table, user["count"], user["second"], STAT_WORDS)
                if table != row[5]:
                    self.events.append(("check", 2, asset) + shadow)
                    if signed(case.checks[1]) < 0:
                        return self.refuse(TAG_TABLE, NAME_BYTES)
                if level < row[2]:
                    self.events.append(("check", 1, asset) + shadow)
                    if signed(case.checks[0]) < 0:
                        return TAG_CROSS_LOW if cross else TAG_ISOLATED_LOW
        self.touched.add(case.who)
        if row is None:
            self.events.append(("default row", asset))
            mode, leverage = case.default
            row = [asset, mode, leverage, 0x5151, 0, 0]
            user["rows"][asset] = row
            self.fresh_rows.add(asset)
        old = row[2]
        row[5] = table
        if cross:
            row[1] = 0
        else:
            if row[1] != 1:
                row[3] = 0
            row[1] = 1
        row[2] = level
        self.open_interest(asset, row[4])
        if old != level:
            self.events.append(("index", asset, level))
        return OK

    def bump(self, value):
        return min(value + 1, TOP)

    def core_call(self, asset):
        self.counter = self.bump(self.counter)
        status = self.body(asset, self.case.cross, self.case.level)
        self.counter = max(self.counter - 1, 0)
        return status

    def apply(self, asset):
        case = self.case
        dex = asset // 10000
        self.events.append(("user row",))
        klass = case.klass
        if klass >= 4:
            direct = bool(case.flag0 & 1)
        else:
            direct = bool(case.flag1 & 1) or klass < 2
        if not direct and klass == 2 and case.byte == 0:
            direct = True
        if direct:
            self.counter = self.bump(self.counter)
            self.bound(dex)
            self.counter -= 1
            return self.core_call(asset)
        if klass == 2:
            if asset < 10000:
                return self.core_call(asset)
            self.events.append(("settle", case.word, 1 if case.word == 0 else 0, 0, 1, 0, dex))
            if case.pre != OK:
                self.events.append(("settle dropped", case.pre))
            status = self.core_call(asset)
            if case.byte == 1:
                self.events.append(("settle", case.word, 1, dex, 1 if case.word == 0 else 0, 0, 0))
                if case.post != OK:
                    self.events.append(("settle dropped", case.post))
            return status
        self.events.append(("tracker",))
        if not (case.sets[0] & 1 or case.sets[1] & 1):
            return TAG_OPERATIONS
        self.track = self.bump(self.track)
        self.total = self.bump(self.total)
        self.bound(dex)
        self.events.append(("pre", dex, 1 if klass == 4 else 0))
        status = self.core_call(asset)
        if klass == 4:
            self.events.append(("finish", dex))
        else:
            self.events.append(("settle", case.word, 1, dex, 0, 0))
            if case.post != OK:
                self.events.append(("settle dropped", case.post))
        return status

    def bound(self, dex):
        if dex >= self.case.dexes:
            raise Panicked("dex row")

    def update_entry(self):
        case = self.case
        kind, value = case.wire
        if kind == "error":
            return ("error", value)
        if kind == "spot":
            return ("error", TAG_SPOT, value)
        status = self.apply(value)
        return self.outcome(status)

    def outcome(self, status):
        if status == OK:
            return ("ok",)
        return ("error", status) if self.payload is None else ("error", status, self.payload)

    def final(self):
        case = self.case
        state = dict(touched=tuple(sorted(self.touched)), active=tuple(sorted(case.active)), opens=tuple(sorted(self.opens.items())), counter=self.counter, track=self.track, total=self.total)
        user = self.users.get(case.who)
        if user is not None:
            rows = []
            for key in sorted(user["rows"]):
                row = user["rows"][key]
                head = struct.pack("<IIqq", row[1], row[2], row[3], row[4])
                rows.append((key, head + (bytes(0x20) if key in self.fresh_rows else ROW_TAIL[:0x20]) + struct.pack("<I", row[5])))
            state["account"] = user["account"]
            state["count"] = user["count"]
            state["rows"] = tuple(rows)
        return state


def spec_for(case):
    model = Model(case)
    try:
        if case.entry == "body":
            result = model.outcome(model.body(case.asset, case.cross, case.level))
        else:
            result = model.update_entry()
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
            raise EvidenceError("case %s:\n got %r %r %r rest %s leaked %r\nwant %r %r %r" % (case.name, got["result"], got["events"], got["state"], got["rest"], got["leaked"], want["result"], want["events"], want["state"]))
        outcomes.append(got)
    return outcomes


NAME_TAG = NAME_BYTES
ISO = 1
SIZE = 1000
ROW = (0, ISO, 5, 7000, SIZE, 20)


def holder(account=50000, rows=(ROW,), count=1, second=(3, 9), user=USER_A):
    return (user, account, tuple(rows), count, tuple(second))


CROSS_ROW = (0, 0, 5, 7000, SIZE, 20)


def named_body():
    out = []

    def add(name, **more):
        fields = dict(entry="body", users=(holder(),), opens=((0, SIZE),), level=8)
        fields.update(more)
        out.append(Case("body " + name, **fields))

    add("raise leverage")
    add("same leverage has no index call", level=5)
    add("cross on an isolated only asset", cross=1, perps=((1, 20, 20),))
    add("cross on a strict asset", cross=1, perps=((2, 20, 20),))
    add("isolated on an isolated only asset", perps=((1, 20, 20),))
    add("cross kind test skipped for isolated", perps=((2, 20, 20),))
    add("asset of another dex panics", asset=10000)
    add("asset of another dex panics when cross", asset=10000, cross=1)
    add("local past the list panics", asset=1)
    add("local past the list panics when cross", asset=1, cross=1)
    add("small table id is the cap", level=20)
    add("one above a small table id", level=21)
    add("table id 49 is small", perps=((0, 20, 49),), level=49, users=(holder(rows=((0, ISO, 5, 7000, SIZE, 49),),),))
    add("table id zero caps at zero", perps=((0, 20, 0),), level=1)
    add("table id 50 reads the tree", perps=((0, 20, 50),), tables=((50, (25, 10)),), level=25, users=(holder(rows=((0, ISO, 5, 7000, SIZE, 50),),),))
    add("table first tier bounds", perps=((0, 20, 50),), tables=((50, (25, 10)),), level=26)
    add("table first leaf under inner nodes", perps=((0, 20, 50),), tables=((50, tuple(range(40, 15, -1))),), tier_height=3, level=40, users=(holder(rows=((0, ISO, 5, 7000, SIZE, 50),),),))
    add("table with no tiers caps at three", perps=((0, 20, 51),), tables=((51, ()),), level=3, users=(holder(rows=((0, ISO, 2, 7000, SIZE, 51),),),))
    add("table with no tiers refuses four", perps=((0, 20, 51),), tables=((51, ()),), level=4)
    add("table search among others", perps=((0, 20, 60),), tables=((50, (9,)), (55, (8,)), (60, (30,)), (70, (7,))), level=30, users=(holder(rows=((0, ISO, 5, 7000, SIZE, 60),),),))
    add("table id missing panics", perps=((0, 20, 55),), tables=((50, (9,)), (60, (8,))))
    add("no table tree panics", perps=((0, 20, 55),))
    add("table id above all panics", perps=((0, 20, 70),), tables=((50, (9,)), (60, (8,))))
    add("no row uses the default row", users=(holder(rows=(), count=0),), opens=())
    add("no row default isolated", users=(holder(rows=(), count=0),), opens=(), default=(1, 3), cross=0)
    add("no row default cross then isolated clears the margin word", users=(holder(rows=(), count=0),), opens=(), default=(0, 20), cross=0)
    add("no row cross", users=(holder(rows=(), count=0),), opens=(), cross=1)
    add("no row at default leverage has no index call", users=(holder(rows=(), count=0),), opens=(), level=3)
    deep = tuple((key, ISO, 5, key, 1 + key, 20) for key in range(0, 20) if key != 7)
    add("no row in a deep tree", users=(holder(rows=deep,),), perps=((0, 20, 20),) * 8, asset=7, prices=(7,) * 8, height=1, opens=())
    add("deep row found", users=(holder(rows=deep,),), perps=((0, 20, 20),) * 8, asset=3, prices=(7,) * 8, height=2, opens=(), stale=1)
    add("deep row lowered", users=(holder(rows=deep,),), perps=((0, 20, 20),) * 8, asset=3, prices=(7,) * 8, height=1, opens=(), level=2)
    add("deep row past the separators lowered", users=(holder(rows=tuple((key, ISO, 5, key, 1 + key, 20) for key in range(0, 8)) + tuple((key, ISO, 5, key, 1, 20) for key in range(20, 31)),),), perps=((0, 20, 20),) * 8, asset=6, prices=(7,) * 8, height=1, opens=(), level=2)
    add("empty row switches freely", users=(holder(rows=((0, ISO, 5, 7000, 0, 20),),),), cross=1)
    add("empty cross row to isolated clears the margin", users=(holder(rows=((0, 0, 5, 7000, 0, 20),),),))
    add("isolated to cross keeps the margin", users=(holder(rows=((0, ISO, 5, 7000, 0, 20),),),), cross=1, level=2)
    add("mode 2 empty row to isolated clears the margin", users=(holder(rows=((0, 2, 5, 7000, 0, 20),),),))
    add("mode 2 empty row to cross", users=(holder(rows=((0, 2, 5, 7000, 0, 20),),),), cross=1)
    add("switch with a position refused to isolated", users=(holder(rows=(CROSS_ROW,),),), cross=0)
    add("switch with a position refused to cross", cross=1)
    add("mode 2 with a position counts as isolated", users=(holder(rows=((0, 2, 5, 7000, SIZE, 20),),),), level=8)
    add("cross stays cross", users=(holder(rows=(CROSS_ROW,),),), cross=1)
    add("cross lowers leverage after the check", users=(holder(rows=(CROSS_ROW,),),), cross=1, level=2)
    add("cross lowering refused", users=(holder(rows=(CROSS_ROW,),),), cross=1, level=2, checks=(TOP, 0))
    add("isolated lowering refused", level=2, checks=(TOP, 0))
    add("isolated lowering check zero admits", level=2, checks=(0, 0))
    add("isolated lowering top positive admits", level=2, checks=((1 << 63) - 1, 0))
    add("lowering minus large word refuses", level=2, checks=(HIGH, 0))
    add("cap helper refuses", cap=7)
    add("cap helper edge", cap=8)
    add("cap helper zero", cap=0, level=1)
    add("cap helper byte top", cap=0xFF)
    add("price row past the list panics", asset=1, perps=((0, 20, 20),) * 2, users=(holder(rows=((1, ISO, 5, 1, 1, 20),),),), opens=())
    add("short position", users=(holder(rows=((0, ISO, 5, 7000, -SIZE, 20),),),), opens=((0, SIZE),))
    add("table change refused", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), checks=(0, TOP))
    add("table change admitted", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), checks=(0, 0))
    add("table change and lowering both run", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), level=3)
    add("table change passes lowering refused", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), level=3, checks=(TOP, 0))
    add("table change at same leverage", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), level=5)
    add("table change cross", users=(holder(rows=((0, 0, 5, 7000, SIZE, 30),),),), cross=1)
    add("table refusal beats the lowering check", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), level=3, checks=(TOP, TOP))
    add("second tree and stats reach the check", level=2, users=(holder(second=(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13),),))
    add("no second tree", level=2, users=(holder(second=()),))
    add("no rows but second tree", users=(holder(rows=(), second=(4, 5), count=0),), opens=())
    add("touched already", touched=(USER_A, USER_C))
    add("refusal leaves the touched set", level=21)
    add("active set untouched", active=(USER_A, USER_B))
    add("second dex", asset=10001, dex_id=1, perps=((0, 20, 20),) * 2, prices=(1, 2), users=(holder(rows=((10001, ISO, 5, 7000, SIZE, 20),),),), opens=())
    add("smallest size panics after the write", users=(holder(rows=((0, ISO, 5, 7000, -(1 << 63), 20),),),))
    add("open word saturates", opens=((0, -(1 << 63) + 5),))
    add("crowded table", crowd=9, users=(holder(user=USER_B), holder(), holder(user=USER_C)))
    add("stale key past the length", stale=1, users=(holder(rows=((0, ISO, 5, 7000, SIZE, 20), (2, ISO, 5, 7000, SIZE, 20)),),), perps=((0, 20, 20),) * 3, prices=(1, 2, 3), opens=())
    return out


def named_update(copy):
    out = []

    def add(name, **more):
        fields = dict(entry="update", copy=copy, wire=("perp", 0), users=(holder(),), opens=((0, SIZE),), level=8, dexes=2)
        fields.update(more)
        out.append(Case("update %s %s" % ("abc"[copy], name), **fields))

    second = dict(wire=("perp", 10001), asset=10001, dex_id=1, users=(holder(rows=((10001, ISO, 5, 7000, SIZE, 20),),),), perps=((0, 20, 20),) * 2, prices=(1, 2), opens=())
    add("class 0 direct")
    add("class 0 cross", users=(holder(rows=(CROSS_ROW,),),), cross=1)
    add("class 1 direct", klass=1)
    add("wire error passes", wire=("error", 0xEA))
    add("spot id refused", wire=("spot", 0xBEEF))
    add("body tag passes", level=21)
    add("cap payload passes", cap=7)
    add("name payload passes", users=(holder(rows=((0, ISO, 5, 7000, SIZE, 30),),),), checks=(0, TOP))
    add("dex out of the list panics", wire=("perp", 20000), asset=20000, dex_id=2, dexes=2)
    add("counter saturates", counter=TOP)
    add("counter zero", counter=0)
    add("class 2 flag zero byte direct", klass=2, byte=0, **second)
    add("class 2 flag1 direct", klass=2, byte=1, flag1=1, **second)
    add("class 2 main dex slot path", klass=2, byte=1)
    add("class 2 main dex byte 2", klass=2, byte=2)
    add("class 2 main dex counter top", klass=2, byte=1, counter=TOP)
    add("class 2 other dex byte 1", klass=2, byte=1, **second)
    add("class 2 other dex byte 1 zero word", klass=2, byte=1, word=0, **second)
    add("class 2 other dex byte 2 no post", klass=2, byte=2, **second)
    add("class 2 pre refusal dropped", klass=2, byte=1, pre=REFUSAL, **second)
    add("class 2 post refusal dropped", klass=2, byte=1, post=REFUSAL, **second)
    add("class 2 other dex counter top", klass=2, byte=1, counter=TOP, **second)
    add("class 2 first id of the second dex", klass=2, byte=1, wire=("perp", 10000), asset=10000, dex_id=1, users=(holder(rows=((10000, ISO, 5, 7000, SIZE, 20),),),), perps=((0, 20, 20),), prices=(1,), opens=())
    add("class 3 first set", klass=3)
    add("class 3 second set", klass=3, sets=(0, 1))
    add("class 3 no set", klass=3, sets=(0, 0))
    add("class 3 flag1 direct", klass=3, flag1=1)
    add("class 3 refusal dropped", klass=3, post=REFUSAL)
    add("class 3 counters saturate", klass=3, track=TOP, total=TOP)
    add("class 3 counter top", klass=3, counter=TOP)
    add("class 3 dex bound", klass=3, wire=("perp", 20000), asset=20000, dex_id=2)
    add("class 3 second dex", klass=3, **second)
    add("class 4 route", klass=4)
    add("class 4 second dex", klass=4, **second)
    add("class 4 flag0 direct", klass=4, flag0=1)
    add("class 4 flag1 alone routes", klass=4, flag1=1)
    add("class 4 no set", klass=4, sets=(0, 0))
    add("class 5 route has no finish", klass=5)
    add("direct on the second dex", **second)
    add("dex bound at the second dex", **dict(second, dexes=1))
    return out


def base_cases():
    out = named_body()
    for copy in range(3):
        out += named_update(copy)
    return out


VECTORS = 300
MUTANT_VECTORS = 60
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
    for index in range(count):
        pick = lcg(index * 2 + 1)

        def wide():
            value = (pick(10 ** (pick(9) + 1)) * (pick(1 << 20) + 1) ** pick(3)) & (HIGH - 1)
            return -value if pick(2) else value

        locals_ = pick(4) + 1
        ids = (5, 10, 20, 40, 50, 51, 60)
        perps = tuple((pick(3) * pick(2), 20, ids[pick(7)]) for _ in range(locals_))
        asset = pick(locals_ + (pick(6) == 0))
        rows = tuple((key, pick(3), 1 + pick(40), wide(), wide() if pick(3) else 0, ids[pick(7)]) for key in sorted({asset, pick(4), pick(4)}) if pick(5))
        users = (holder(account=wide(), rows=rows, count=pick(3), second=tuple(sorted({pick(30) for _ in range(pick(5))}))),)
        users += (holder(user=USER_B),) if pick(2) else ()
        prices = tuple(pick(10 ** (pick(6) + 1)) for _ in range(locals_ + (pick(6) != 0)))
        fields = dict(users=users, perps=perps, prices=prices, asset=asset, opens=tuple((key, wide()) for key in sorted({asset, pick(4)}) if pick(2)), level=1 + pick(45), cross=pick(2), cap=pick(60), checks=((TOP if pick(3) == 0 else pick(99)), (TOP if pick(3) == 0 else pick(99))),
                      tables=((50, (25, 10)), (51, ()), (60, (pick(50),))) if pick(5) else ((50, (25,)), (51, ())), default=(pick(2), 1 + pick(9)), touched=(USER_A,) if pick(3) == 0 else (), crowd=pick(5), height=pick(3), stale=pick(2), tier_height=pick(2))
        if index % 2 == 0:
            out.append(Case("vector %d" % index, entry="body", **fields))
        else:
            out.append(Case("vector %d" % index, entry="update", copy=pick(3), wire=("perp", asset), klass=pick(6), flag0=pick(2), flag1=pick(2), byte=pick(3), word=pick(2) * 0x99, sets=(pick(2), pick(2)), pre=(OK, REFUSAL)[pick(2)], post=(OK, REFUSAL)[pick(2)], counter=pick(9), dexes=1 + pick(2), **fields))
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
    'payload': 'not compared: copies of the status object past the tag; the body writes only the tag on these paths, so these bytes are stale stack bytes',
    'parser': 'not compared: copies of the decimal parser status object past the tag',
    'panic': 'same: panic argument, or the tag of a lookup value that is not used on the panic path',
    'dropped': 'same: tag of an unused status that the next call drops',
    'okcopy': 'same: a copy of an ok status is still an ok status',
    'bound': 'same: the second bound test of one dex index, after the first passed with the same value',
    'float': 'same: the product is finite and not negative here, and the clamp gives the same value inside its range',
    'handle': 'same: height word of a tree handle that is rebuilt before it is read',
    'second': 'not killed: with no position row the clone is refused empty, so the second tree copy is seen only through the free check',
    'empty': 'same: searching an empty table also misses',
    'shuffle': 'same: the four dwords of the tag vector are equal',
    'probe': 'not killed: probe step of a table search that never leaves a group end on the reached keys',
    'unused': 'same: word copied to a stack record that no reached row reads',
    'scan': 'not killed: scan bound on a node where the key is found or stale slots hold a higher key',
    'found': 'same: the key is present in the clone, so the leaf bound never fires',
    'dexone': 'not killed: the cross path ran local ids of dex 0 and 1 only with a low immediate bit that keeps them',
    'pastlist': 'not killed: an asset past the list panics later on the same case with this edit',
    'overwritten': 'same: the word is written over on every reached path',
    'tag': 'same: only the zero or nonzero state of this word is read on the reached path',
    'descent': 'not killed: first leaf descent details of a tier tree under 8 levels',
    'free49': 'not killed: table id 49 refusal path frees the same stack table under the edited bound',
}
SURVIVORS = {}
for address in (0x2721B55, 0x3709CF0, 0x4D26FC7, 0x4D27797,):
    SURVIVORS[address] = 'bound'
for address in (0x3709B35, 0x3709B7E,):
    SURVIVORS[address] = 'descent'
for address in (0x37098E4,):
    SURVIVORS[address] = 'dexone'
for address in (0x370A18F,):
    SURVIVORS[address] = 'found'
for address in (0x3709B9C,):
    SURVIVORS[address] = 'free49'
for address in (0x37099B1, 0x37099BA, 0x37099FC, 0x3709A08, 0x3709A14, 0x3709BE1, 0x3709FFC, 0x370A1C7,):
    SURVIVORS[address] = 'handle'
for address in (0x3709A34,):
    SURVIVORS[address] = 'overwritten'
for address in (0x2721EF1, 0x2721F12, 0x2721F1F, 0x2721F40, 0x4D2736A, 0x4D2738B, 0x4D27398, 0x4D273B9, 0x4D27B3A, 0x4D27B5B, 0x4D27B68, 0x4D27B89,):
    SURVIVORS[address] = 'panic'
for address in (0x370992C,):
    SURVIVORS[address] = 'pastlist'
for address in (0x21E0C66, 0x21E0C77, 0x21E0C80, 0x21E0C97, 0x21E0C9B, 0x2721CA2, 0x2721CAE, 0x2721CD2, 0x2721CD6, 0x2721CDA, 0x48977B6, 0x48977C7,
             0x48977D0, 0x48977E7, 0x48977EB, 0x48978F6, 0x4897907, 0x4897910, 0x4897927, 0x489792B, 0x4D2711B, 0x4D27127, 0x4D2714B, 0x4D2714F,
             0x4D27153, 0x4D278EB, 0x4D278F7, 0x4D2791B, 0x4D2791F, 0x4D27923,):
    SURVIVORS[address] = 'payload'
for address in (0x3709A65, 0x3709C4D, 0x3709DA8, 0x370A178,):
    SURVIVORS[address] = 'scan'
for address in (0x3709AD6,):
    SURVIVORS[address] = 'tag'
for address in (0x3709990,):
    SURVIVORS[address] = 'unused'


def survivor_reason(va, kind):
    key = SURVIVORS.get(va)
    return SURVIVOR_REASONS[key] if key else "unclassified"



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
            results.append((name, va, kind, "killed", hit.name) if hit is not None else (name, va, kind, "survived", survivor_reason(va, kind)))
    return results


REFERENCE = (
    ("status 67 cap", "`cap requested leverage against asset/table limits`", "table ids below 50 are not looked up: the rows build a one tier table whose max leverage is the id itself; ids from 50 read the tree at dex +0x38, a missing id panics, and an empty tier list means 3", "body small table id is the cap"),
    ("status 80", "named as too big for the position", "runs only with a nonzero size, uses tier helper slot 0x5775998 with the oracle price, and carries the helper byte in the status", "body cap helper refuses"),
    ("result of the post step", "doc comment says the status is logged and the leverage status returned", "the wrapper drops the refused object and returns the body status, as the comment says, in all three paths", "update a class 2 post refusal dropped"),
    ("margin on a mode switch", "`insert/update the per-asset position record`", "a change from cross to isolated with zero size writes margin 0, a change from isolated to cross keeps the old margin word", "body isolated to cross keeps the margin"),
    ("status 79", "named as margin table would increase requirement", "runs only when the row table differs from the asset table; carries a clone of the perp name; the check runs on a clone with the new leverage and table in mode 2", "body table change refused"),
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
    at = image.offset(CAP_TEXT)
    data = bytes(image.blob[at:at + len(CAP_WORDS)])
    if data != CAP_WORDS:
        raise EvidenceError("format text of tag 0x50")
    return [("%#x" % CAP_TEXT, data.decode(), "first format piece beside tag 0x50, the argument is the word at status +4")]


LOCATIONS = ((0x56F21C0, "asset of another dex or local past the perp list"), (0x56F21D8, "table id from 50 that is not in the tree"), (LOC_OPEN_SUB, "open word subtract recorder"), (LOC_OPEN_ADD, "open word add recorder"))


def location_rows(image):
    relative = image.relative()
    rows = []
    for record, use in LOCATIONS:
        path, line, column = image.location(record, relative)
        rows.append(("%#x" % record, path, line, column, use))
    return rows


def caller_rows(image):
    """Every `ff 15 disp32` call of the body slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        va = base + at
        if va + 6 + struct.unpack_from("<i", text, at + 2)[0] == SLOT_BODY:
            rows.append(("body", "%#x" % SLOT_BODY, "%#x" % va, "%#x" % image.fde(va)[0]))
        at = text.find(b"\xff\x15", at + 1)
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, use in ((SLOT_BODY, "leverage body"), (SLOT_MARGIN_CHECK, "margin check on the shadow copy, modes 1 and 2, not read here"), (SLOT_TIER_CAP, "tier cap for a price, not read here"), (SLOT_RECORD, "overflow recorder")):
        rows.append(("%#x" % slot, "%#x" % relative[slot], use))
    return rows


def subject_rows(image):
    return {name: rows_of(image, target) for name, target in FUNCTIONS.items()}


def copy_rows():
    return [(copy.name, "%#x" % copy.handler, "%#x" % copy.apply, "%#x" % copy.base, "%#x" % copy.byte, "%#x" % copy.tracker_at, "%#x" % copy.count_at) for copy in COPIES]


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
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), tags=tag_rows(image), copies=copy_rows(), locations=location_rows(image), callers=caller_rows(image), slots=slot_rows(image))
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
    return (case.name, cell(got["result"]), cell(state.get("account", "no user")), cell(state.get("rows", ())), "; ".join(cell(event) for event in got["events"]) if len(got["events"]) <= 24 else "%d events" % len(got["events"]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "bytes", "meaning"), result["constants"])
    tsv("tag-texts.tsv", ("tag", "display text"), result["tags"])
    tsv("locations.tsv", ("record", "path", "line", "column", "use"), result["locations"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "handler", "routing wrapper", "dex list field", "abstraction byte", "tracker field", "routed count field"), result["copies"])
    tsv("callers.tsv", ("callee", "slot or address", "call site", "function"), result["callers"])
    tsv("slots.tsv", ("slot", "target", "use"), result["slots"])
    tsv("outcomes.tsv", ("case", "result", "account", "rows", "callee events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
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

