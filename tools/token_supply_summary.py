#!/usr/bin/env python3
"""Pin the node #94 token supply path: the non-circulating set vote, the supply summary, read precompile 0x80d and the proposal reader.

Real rows run from the vote arm in all three dispatchers, the set body, the summary, the precompile with its ABI encoder and the
proposal handler in all three copies. A separately written rule list predicts every result, callee argument and written word, and
every reached conditional row, immediate and field offset of the subject code is edited. No objdump or readelf output is parsed and
the binary is never executed. Standard library only.

    python3 tools/token_supply_summary.py --out <dir>
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
TAG_TESTNET, TAG_ADD, TAG_TOKEN, TAG_NATIVE, TAG_LENGTH = 0x8D, 0xBE, 0xEA, 0xFB, 0x143
TAG_TEXTS = {TAG_TESTNET: "Action only allowed on testnet", TAG_ADD: "Add result error", TAG_TOKEN: "Invalid token", TAG_NATIVE: "Native token does not exist", TAG_LENGTH: "Invalid input length"}
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_BALANCES = 0x5773170
SLOT_STAKING = 0x5774F18
SLOT_RECORD = 0x5773190
SLOT_PROPOSE = 0x5773338
SLOT_ERROR_TEXT = 0x5775510
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048, 0x576EB38, 0x576E1B0)
MARK_BASE = 0x7700000000
HASH = 0x399C4A0
STAMP = 0x3987CB0
TOKEN_ERROR_TEXT = 0x37F3190
STATUS_DROP = 0x3C1ADA0
SUMMARY = 0x375E4C0
MODIFY = 0x37603E0
PRECOMPILE = 0x3248EA0
ENCODE = 0x3BAF8B0
SHARED_DROP = 0x15102C0
DECODE = 0x37E65F0
SLOT_BODY = 0x5773E48
LOC_WEI_SUB = 0x56DFD90
TOP = MASK[8]
HIGH = 1 << 63
BONUS_TOKEN = 1
BONUS = 40000000000000
LIST_CAP = 10000
TITLE_CAP = 100
DESC_CAP = 1000
BASE_GAS = 1000
WORD_GAS = 33
INPUT_CAP = 2000
HALT_WORD = HIGH
BUCKETS = 64
TOKEN_STRIDE = 0xE8
TOKEN_ROOM = 12
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x2000
SPOT = STATE + 0x80
META = STATE + 0x90
STAKING = STATE + 0x8F8
TOKENS = STATE + STATE_SIZE
LINK_ROOM = TOKENS + TOKEN_ROOM * TOKEN_STRIDE
LINK_CTRL = LINK_ROOM + BUCKETS * 0x10
OUT = HEAP_BASE + 0x40
ACTION = HEAP_BASE + 0xC0
USER = HEAP_BASE + 0x160
INPUT = HEAP_BASE + 0x180
CONTEXT = HEAP_BASE + 0x1A0
BLOCK = HEAP_BASE + 0x200
EMPTY_ROW = HEAP_BASE + 0x220
INPUT_BYTES = HEAP_BASE + 0x280
ARM_FRAME = 0x800
BUMP = LINK_CTRL + BUCKETS + 0x20
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
ZERO_USER = bytes(20)
DEAD_USER = bytes(18) + b"\xde\xad"
USER_A = bytes(range(1, 21))
USER_B = bytes(range(0x21, 0x35))
USER_C = bytes(range(0x41, 0x55))
PRECOMPILE_ADDRESS = bytes(18) + b"\x08\x0d"
STAMP_BYTES = bytes(range(0xA0, 0xC0))
REFUSAL_BYTES = bytes(0x80 | (index * 3 + 5) & 0xFF for index in range(0x5E))
TIME_WORDS = (0x1122334455667788, 0x99AABBCC)
HUGE = 0x0CCCCCCCCCCCCCCC

AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


SET_TREE = Layout(8, 20, 0xE4, 0, 0, 0xE4, 0xE6, 0xE8)
BALANCE_TREE = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
WORD_TREE = Layout(8, 8, 0x60, 8, 0, 0xB8, 0xBA, 0xC0)


class Copy:
    def __init__(self, name, proposal, arm, state_reg, ok_stop, error_stop, drop):
        self.name, self.proposal, self.arm, self.state_reg, self.ok_stop, self.error_stop, self.drop = name, proposal, arm, state_reg, ok_stop, error_stop, drop


COPIES = (Copy("a", 0x1F68BE0, 0x23567D8, R13, 0x235C713, 0x2359A4C, 0x1EAD7F0),
          Copy("b", 0x47BA820, 0x4CAB148, RDX, 0x4CB10B4, 0x4CAE35E, 0x472F840),
          Copy("c", 0x47BAC70, 0x4CB3AD8, RDX, 0x4CB9A44, 0x4CB6CEE, 0x472F840))
FUNCTIONS = dict(summary=SUMMARY, modify=MODIFY, precompile=PRECOMPILE, encode=ENCODE, proposal_a=COPIES[0].proposal, proposal_b=COPIES[1].proposal, proposal_c=COPIES[2].proposal)
DISPATCHERS = dict(arm_a=0x2355F40, arm_b=0x4CAA870, arm_c=0x4CB3200)


def link_user(token):
    return b"\x32" + bytes(11) + struct.pack(">Q", token)


def link_hash(token):
    return (token % BUCKETS) | ((token % 127) << 57)


class Case:
    DEFAULTS = dict(entry="summary", copy=0, token=0, count=4, maxima=(), fees=(), links=(), crowd=(), members=(), rows=(), native=None, staked=(), reserve=(0, 0), height=0, stale=0,
                    adds=(), removes=(), caps=(0, 0), stamped=0, chain=0, title=b"t", body=b"d", flag=0, propose=OK, data=None, limit=TOP, blocked=(), refuse=0, fast=0, ghost=0)

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


HOOKED = {RESUME, HASH, STAMP, TOKEN_ERROR_TEXT, STATUS_DROP, DECODE, SHARED_DROP} | {copy.drop for copy in COPIES}


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        self.base_frame = machine.frame
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_BALANCES, self.on_balances), (SLOT_STAKING, self.on_staking), (SLOT_RECORD, self.on_record), (SLOT_PROPOSE, self.on_propose), (SLOT_ERROR_TEXT, self.on_error_text))
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
        machine.calls = {RESUME: self.on_panic, HASH: self.on_hash, STAMP: self.on_stamp, TOKEN_ERROR_TEXT: self.on_error_text, STATUS_DROP: self.on_status_drop, DECODE: self.on_decode, SHARED_DROP: self.on_shared_drop}
        machine.slots[MARK_BASE + SLOT_BODY] = self.on_body
        machine.slots[SHARED_DROP] = self.on_shared_drop
        self.body_real = machine.memory.statics[SLOT_BODY]
        for copy in COPIES:
            machine.calls[copy.drop] = self.on_native_drop
        self.case = None
        self.copy = COPIES[0]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.user_rows = {}

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
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == SPOT + 0xA0, "hash seed of the link map")
        key = memory.read(regs[RSI], 8)
        self.events.append(("hash", key))
        regs[RAX] = link_hash(key)

    def on_balances(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == SPOT, "spot rows")
        user = self.user_key(regs[RSI])
        self.events.append(("row", user))
        regs[RAX] = self.user_rows.get(user, EMPTY_ROW)

    def on_staking(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == self.staking, "staking state")
        user = self.user_key(regs[RDX])
        self.events.append(("staking", user))
        words = dict(self.case.staked).get(user, (0, 0, 0, 0x5A5A))
        memory.put_bytes(regs[RDI], struct.pack("<4Q", *words))
        regs[RAX] = regs[RDI]

    def on_record(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] & MASK[4] == 0, "recorder first argument")
        self.events.append(("recorded", regs[RSI]))

    def on_stamp(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] & 0xFF == self.case.chain and regs[RCX] == 0x4444 and regs[RDX] == 0x5555 and regs[R8] & 0xFF == 0, "stamp arguments")
        memory.put_bytes(regs[RDI], STAMP_BYTES)
        regs[RAX] = regs[RDI]
        self.events.append(("stamp",))

    def on_native_drop(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == TAG_NATIVE, "dropped native status")
        self.events.append(("dropped",))

    def on_shared_drop(self, machine):
        memory = machine.memory
        self.take_shared(memory.read(machine.regs[RDI], 8))

    def take_shared(self, share):
        memory = self.machine.memory
        buffer, cap, count = struct.unpack("<3Q", memory.bytes_at(share, 24))
        self.expect(count == 1 and self.live.pop(share, None) == 24 and self.live.pop(buffer, None) == cap, "shared block")

    def on_decode(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == INPUT_BYTES and regs[RSI] == len(self.case.data), "decoder input")
        regs[RAX] = 0xABCD00 | (0 if self.case.refuse else 1)
        regs[RDX] = 0xFFFFFFFF00000000 | self.case.token
        machine.keep_rdx = True

    def on_body(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == META and regs[RSI] == self.case.token and regs[RDX] == ACTION + 8 and regs[RCX] == ACTION + 0x20, "set body arguments")
        self.events.append(("body", len(self.case.adds), len(self.case.removes)))

    def on_status_drop(self, machine):
        self.events.append(("status dropped", machine.memory.read(machine.regs[RDI], 2)))

    def on_error_text(self, machine):
        regs, memory = machine.regs, machine.memory
        tag = memory.read(regs[RSI], 2)
        text = b"status %d" % tag
        at = self.bump(len(text))
        memory.put_bytes(at, text)
        memory.put_bytes(regs[RDI], struct.pack("<3Q", len(text), at, len(text)))
        regs[RAX] = regs[RDI]
        self.events.append(("error text", tag, memory.read(regs[RSI] + 8, 8) if tag == TAG_TOKEN else 0))

    def on_propose(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == self.staking, "proposal state")
        frame = regs[RDX]
        title_cap, title_at, title_len, body_cap, body_at, body_len = struct.unpack("<6Q", memory.bytes_at(frame, 48))
        self.expect(title_cap == title_len and body_cap == body_len, "proposal text capacity")
        self.expect((title_len or title_at == 1) and (body_len or body_at == 1), "empty text pointer")
        title, body = memory.bytes_at(title_at, title_len) if title_len else b"", memory.bytes_at(body_at, body_len) if body_len else b""
        for at, size in ((title_at, title_len), (body_at, body_len)):
            if size:
                self.expect(self.live.pop(at, None) == size, "proposal text block")
        self.events.append(("propose", title, body, memory.bytes_at(frame + 0x30, 32), memory.read(frame + 0x50, 8), memory.read(frame + 0x58, 8), memory.read(frame + 0x60, 4), memory.bytes_at(frame + 0x64, 20), memory.read(frame + 0x78, 1), memory.read(frame + 0x79, 1)))
        if self.case.propose == OK:
            memory.write(regs[RDI], 2, OK)
        else:
            memory.put_bytes(regs[RDI], struct.pack("<H", self.case.propose) + REFUSAL_BYTES)
        regs[RAX] = regs[RDI]

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
        """Bytes for unused key slots; with `stale` they repeat a live key, as old rows do after a removal."""
        if not self.case.stale:
            return b"\xfe" * layout.key_size
        if layout is SET_TREE:
            return PRECOMPILE_ADDRESS if self.case.entry == "precompile" else USER_C
        return struct.pack("<Q", self.case.token)

    def put_tree(self, at, layout, items, height=0):
        root, level = self.tree_bytes(layout, items, height) if items else (0, 0xFEED)
        self.machine.memory.put_bytes(at, struct.pack("<2Q", root, level))

    def put_links(self, tokens):
        memory = self.machine.memory
        control = bytearray(b"\xff" * (BUCKETS + 16))
        for token in tokens:
            value = link_hash(token)
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
            memory.put_bytes(LINK_CTRL - 0x10 * (slot + 1), struct.pack("<2Q", token, 0xABAB + slot))
        memory.put_bytes(LINK_CTRL, bytes(control))
        memory.put_bytes(SPOT + 0x80, struct.pack("<4Q", LINK_CTRL, BUCKETS - 1, 0x4040, len(tokens)))

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        memory.statics[SLOT_BODY] = MARK_BASE + SLOT_BODY if case.fast else self.body_real
        self.case = case
        self.copy = COPIES[case.copy]
        self.live = {}
        self.cur = BUMP
        self.events = []
        self.user_rows = {}
        shift = 0xA80 if case.entry == "proposal" and case.copy == 1 else 0
        self.staking = STAKING + shift
        memory.write(META + 0x180, 8, TOKENS)
        memory.write(META + 0x188, 8, case.count)
        memory.write(SPOT, 1, 1 if case.native is not None else 0)
        memory.write(SPOT + 8, 8, case.ghost if case.native is None else case.native)
        memory.write(self.staking + 0x60, 1, case.reserve[0])
        memory.write(self.staking + 0x68, 8, case.reserve[1])
        self.put_tree(SPOT + 0x388, WORD_TREE, [(struct.pack("<Q", key), value) for key, value in sorted(case.maxima)], case.height)
        self.put_tree(SPOT + 0x3A0, WORD_TREE, [(struct.pack("<Q", key), value) for key, value in sorted(case.fees)], case.height)
        self.put_links(tuple(case.crowd) + tuple(case.links))
        memory.write(EMPTY_ROW + 0x10, 8, 0)
        memory.write(EMPTY_ROW + 0x18, 8, 0xFEED)
        for user, balances in case.rows:
            row = self.bump(0x20)
            memory.put_bytes(row, b"\x66" * 0x20)
            self.put_tree(row + 0x10, BALANCE_TREE, [(struct.pack("<Q", key), value | 0x7777 << 64 | 0x8888 << 128) for key, value in sorted(balances)], case.height)
            self.user_rows[user] = row
        items = [(key, 0) for key in sorted(set(case.members))]
        index = case.native if case.entry == "proposal" and case.native is not None else case.token
        if index < TOKEN_ROOM:
            at = TOKENS + index * TOKEN_STRIDE + 0x90
            self.put_tree(at, SET_TREE, items, case.height)
            memory.write(at + 0x10, 8, len(items))
        memory.write(STATE, 4, 1 if case.stamped else 0)
        memory.write(STATE + 8, 8, 0x4444)
        memory.write(STATE + 0x28, 8, 0x5555)
        memory.put_bytes(STATE + 0x60, struct.pack("<QI", *TIME_WORDS))
        memory.write(STATE + 0x8F2 + shift, 1, case.chain)
        memory.put_bytes(USER, USER_B)
        memory.put_bytes(BLOCK, struct.pack("<2Q", 0, 0))
        self.fixed = set(self.live)

    def vector(self, users, cap, keep=False):
        memory = self.machine.memory
        size = cap * 20
        at = self.bump(size) if size else 1
        if users:
            memory.put_bytes(at, b"".join(users))
        if size and keep:
            self.fixed.add(at)
        return struct.pack("<3Q", cap, at, len(users))

    def enter(self):
        case, copy, machine, memory = self.case, self.copy, self.machine, self.machine.memory
        memory.put_bytes(OUT, b"\x77" * 0x70)
        if case.entry == "summary":
            machine.run(SUMMARY, {RDI: OUT, RSI: META, RDX: case.token, RCX: SPOT, R8: STAKING})
            return self.summary_result(OUT)
        if case.entry == "modify":
            add, remove = self.vector(case.adds, len(case.adds), True), self.vector(case.removes, len(case.removes), True)
            memory.put_bytes(ACTION + 8, add + remove)
            machine.run(MODIFY, {RDI: META, RSI: case.token, RDX: ACTION + 8, RCX: ACTION + 0x20})
            return self.set_result()
        if case.entry == "arm":
            add, remove = self.vector(case.adds, len(case.adds) + case.caps[0]), self.vector(case.removes, len(case.removes) + case.caps[1])
            memory.put_bytes(ACTION + 8, add + remove)
            memory.write(ACTION + 0x38, 8, case.token)
            frame = STACK_TOP - 0x108 - ARM_FRAME
            memory.write(frame, 8, OUT)
            machine.frame = ARM_FRAME
            machine.stops = (copy.ok_stop, copy.error_stop)
            try:
                machine.run(copy.arm, {copy.state_reg: STATE, R15: ACTION})
            finally:
                machine.stops = ()
                machine.frame = self.base_frame
            self.expect(machine.regs[RSP] == frame, "frame at the join")
            tag = memory.read(OUT, 2)
            if tag == 0x7777:
                return ("ok",) + self.set_result()
            if tag == TAG_TOKEN:
                return ("error", tag, memory.read(OUT + 8, 8))
            return ("error", tag, memory.read(OUT + 8, 8) - frame)
        if case.entry == "precompile":
            memory.put_bytes(INPUT_BYTES, case.data)
            memory.write(INPUT, 8, 0x1234)
            memory.write(INPUT + 8, 8, INPUT_BYTES)
            memory.write(INPUT + 0x10, 8, len(case.data))
            memory.write(CONTEXT + 0x10, 8, SPOT)
            memory.write(CONTEXT + 0x20, 8, STAKING)
            memory.write(CONTEXT + 0x38, 8, BLOCK)
            self.put_tree(BLOCK, SET_TREE, sorted((key, 0) for key in case.blocked), case.height)
            self.fixed |= set(self.live)
            machine.run(PRECOMPILE, {RDI: OUT, RSI: CONTEXT, RDX: INPUT, RCX: case.limit})
            return self.precompile_result()
        title, body = self.bump(max(len(case.title), 1)), self.bump(max(len(case.body), 1))
        memory.put_bytes(title, case.title)
        memory.put_bytes(body, case.body)
        memory.put_bytes(ACTION, b"\xd1" * 0x60)
        memory.write(ACTION, 8, len(case.title))
        memory.write(ACTION + 8, 8, title)
        memory.write(ACTION + 0x10, 8, len(case.title))
        memory.write(ACTION + 0x18, 8, len(case.body))
        memory.write(ACTION + 0x20, 8, body)
        memory.write(ACTION + 0x28, 8, len(case.body))
        memory.write(ACTION + 0x59, 1, case.flag)
        self.fixed |= {title, body}
        machine.run(copy.proposal, {RDI: OUT, RSI: ACTION, RDX: USER, RCX: STATE})
        return self.proposal_result()

    def summary_result(self, at):
        memory = self.machine.memory
        tag = memory.read(at, 2)
        if tag != OK:
            return ("error", tag)
        cap, ptr, size, top, total, circulating, reserve = struct.unpack("<7Q", memory.bytes_at(at + 8, 56))
        rows = []
        for index in range(size):
            record = memory.bytes_at(ptr + index * 32, 32)
            rows.append((record[:20], struct.unpack("<Q", record[24:])[0]))
        if cap:
            self.expect(self.live.pop(ptr, None) == cap * 32, "row vector block")
        else:
            self.expect(ptr == 8, "empty row vector")
        return ("ok", tuple(rows), top, total, circulating, reserve)

    def walk(self, node, level):
        memory = self.machine.memory
        count = memory.read(node + SET_TREE.len_at, 2)
        out = []
        for index in range(count + 1):
            if level:
                out += self.walk(memory.read(node + SET_TREE.edge_at + 8 * index, 8), level - 1)
            if index < count:
                out.append(memory.bytes_at(node + SET_TREE.key_at + 20 * index, 20))
        return out

    def set_result(self):
        memory = self.machine.memory
        at = TOKENS + self.case.token * TOKEN_STRIDE + 0x90
        root, height, size = struct.unpack("<3Q", memory.bytes_at(at, 24))
        items = self.walk(root, height) if root else []
        self.expect(len(items) == size, "set length word")
        return (tuple(items),)

    def precompile_result(self):
        memory = self.machine.memory
        words = struct.unpack("<5Q", memory.bytes_at(OUT, 40))
        if words[0] == 0:
            if words[2] == HALT_WORD:
                return ("halt",)
            text = memory.bytes_at(words[3], words[4])
            self.expect(self.live.pop(words[3], None) == words[2], "error text block")
            return ("text", text, words[1])
        data = memory.bytes_at(words[1], words[2])
        self.take_shared(words[3])
        return ("bytes", data, words[4])

    def proposal_result(self):
        memory = self.machine.memory
        code = memory.read(OUT, 1)
        if code == 0x0A:
            return ("ok", memory.bytes_at(OUT + 1, 32))
        self.expect(code == 0x0E, "outer code")
        tag = memory.read(OUT + 8, 2)
        if tag == TAG_LENGTH:
            return ("error", tag, memory.read(OUT + 0x10, 8) - ACTION)
        if tag not in (TAG_TESTNET, TAG_NATIVE, TAG_ADD, OK):
            self.expect(memory.bytes_at(OUT + 10, 0x50) == REFUSAL_BYTES[:0x50], "refusal bytes")
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
        skips = [(OUT, 0x70), (ACTION, 0x60), (INPUT, 0x18), (CONTEXT, 0x40), (BLOCK, 0x10), (INPUT_BYTES, 0xD00)]
        if case.entry in ("modify", "arm") and case.token < TOKEN_ROOM:
            skips.append((TOKENS + case.token * TOKEN_STRIDE + 0x90, 24))
        for at, size in skips:
            now[at - HEAP_BASE:at - HEAP_BASE + size] = before[at - HEAP_BASE:at - HEAP_BASE + size]
        rest = bytes(now) == before
        return dict(result=result, events=list(self.events), rest=rest, leaked=self.leftovers(result, case))

    def leftovers(self, result, case):
        if result == ("panic",):
            return []
        keep = set(self.fixed)
        return sorted(at for at in self.live if at not in keep and not self.node_block(at, case))

    def node_block(self, at, case):
        return case.entry in ("modify", "arm") and self.live[at] in (SET_TREE.leaf, SET_TREE.inner)


def spec_summary(case, events, native=None):
    """Result tuple of the supply summary, with its callee events."""
    if case.token >= case.count:
        raise Panicked("token index")
    maxima, fees = dict(case.maxima), dict(case.fees)
    top = maxima.get(case.token, 0)
    total = max(top - fees.get(case.token, 0), 0)
    if case.links or case.crowd:
        events.append(("hash", case.token))
    native = case.native == case.token
    rows = dict(case.rows)
    staked = dict(case.staked)
    users = sorted(set(case.members)) + [ZERO_USER, DEAD_USER]
    if case.token in case.links:
        users.append(link_user(case.token))
    used = 0
    out = []
    for user in users:
        events.append(("row", user))
        amount = dict(rows.get(user, ())).get(case.token, 0)
        if native:
            events.append(("staking", user))
            for word in staked.get(user, (0, 0, 0, 0))[:3]:
                amount += word
                if amount > TOP:
                    return ("error", TAG_ADD)
        if amount == 0:
            continue
        used += amount
        if used > TOP:
            return ("error", TAG_ADD)
        out.append((user, amount))
    free = max(total - used, 0)
    if case.token == BONUS_TOKEN:
        if top + BONUS > TOP:
            return ("error", TAG_ADD)
        top += BONUS
    reserve = 0
    if native and case.reserve[0]:
        reserve = case.reserve[1]
        if reserve > free:
            events.append(("recorded", LOC_WEI_SUB))
            free = 0
        else:
            free -= reserve
    return ("ok", tuple(out), top, total, free, reserve)


def spec_set(case):
    if case.token >= case.count:
        raise Panicked("token index")
    items = set(case.members) | set(case.adds)
    items -= set(case.removes)
    return (tuple(sorted(items)),)


def spec_arm(case, events):
    if case.token >= case.count:
        return ("error", TAG_TOKEN, case.token)
    if len(case.adds) > LIST_CAP:
        return ("error", TAG_LENGTH, ARM_STACK[case.copy][0])
    if len(case.removes) > LIST_CAP:
        return ("error", TAG_LENGTH, ARM_STACK[case.copy][1])
    if case.fast:
        events.append(("body", len(case.adds), len(case.removes)))
        return ("ok", tuple(sorted(set(case.members))))
    return ("ok",) + spec_set(case)


ARM_STACK = ((0x130, 0x20), (0x140, 0x20), (0x140, 0x20))


def abi_word(value):
    return value.to_bytes(32, "big")


def spec_precompile(case, events):
    if PRECOMPILE_ADDRESS in case.blocked:
        return ("halt",)
    size = len(case.data)
    if size > INPUT_CAP:
        return ("halt",)
    gas = size * WORD_GAS + BASE_GAS
    if gas > case.limit:
        return ("halt",)
    if case.refuse:
        return ("text", b"Invalid input", 0)
    token = case.token
    if token >= case.count:
        events.append(("error text", TAG_TOKEN, token))
        events.append(("status dropped", TAG_TOKEN))
        return ("text", b"status %d" % TAG_TOKEN, 0)
    result = spec_summary(case, events)
    if result[0] == "error":
        events.append(("error text", result[1], 0))
        return ("text", b"status %d" % result[1], 0)
    _, rows, top, total, free, reserve = result
    data = abi_word(0x20) + abi_word(top) + abi_word(total) + abi_word(free) + abi_word(reserve) + abi_word(0xA0) + abi_word(len(rows))
    for user, amount in rows:
        data += bytes(12) + user + abi_word(amount)
    final = gas + WORD_GAS * len(data)
    if final > case.limit:
        return ("halt",)
    return ("bytes", data, final)


def spec_proposal(case, events):
    if case.chain == 3:
        return ("error", TAG_TESTNET)
    if case.stamped:
        events.append(("stamp",))
    if case.native is None:
        return ("error", TAG_NATIVE)
    events.append(("dropped",))
    summary = Case(case.name, **{key: getattr(case, key) for key in Case.DEFAULTS if key in ("count", "maxima", "fees", "links", "crowd", "members", "rows", "native", "staked", "reserve")}, token=case.native)
    result = spec_summary(summary, events)
    if result[0] == "error":
        return result
    if len(case.title) > TITLE_CAP:
        return ("error", TAG_LENGTH, 0)
    if len(case.body) > DESC_CAP:
        return ("error", TAG_LENGTH, 0x18)
    stamp = STAMP_BYTES if case.stamped else bytes(32)
    events.append(("propose", case.title, case.body, stamp, result[4], TIME_WORDS[0], TIME_WORDS[1], USER_B, case.chain, case.flag))
    if case.propose != OK:
        return ("error", case.propose)
    return ("ok", stamp)


def spec_for(case):
    want = dict(events=[])
    try:
        if case.entry == "summary":
            result = spec_summary(case, want["events"])
        elif case.entry == "modify":
            result = spec_set(case)
        elif case.entry == "arm":
            result = spec_arm(case, want["events"])
        elif case.entry == "precompile":
            result = spec_precompile(case, want["events"])
        else:
            result = spec_proposal(case, want["events"])
    except Panicked:
        result = ("panic",)
    want["result"] = result
    return want


def same(case, got, want):
    return got["result"] == want["result"] and got["events"] == want["events"] and got["rest"] and not got["leaked"]


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %r %r rest %s leaked %r want %r" % (case.name, got["result"], got["events"], got["rest"], got["leaked"], want))
        outcomes.append(got)
    return outcomes


def named_summary():
    out = []

    def add(name, **fields):
        out.append(Case("summary " + name, **fields))

    add("empty maps token 0")
    add("max only", maxima=((0, 1000),))
    add("max and fees", maxima=((0, 1000),), fees=((0, 300),))
    add("fees above max saturate", maxima=((0, 100),), fees=((0, 300),))
    add("fees equal max", maxima=((0, 100),), fees=((0, 100),))
    add("fees without max", fees=((0, 5),))
    add("other token rows are ignored", token=2, maxima=((0, 7), (1, 8), (3, 9)), fees=((0, 1), (3, 2)))
    add("own row among others", token=2, maxima=((0, 7), (2, 50), (3, 9)), fees=((1, 4), (2, 3), (3, 2)))
    add("tall trees", token=2, maxima=((0, 7), (2, 50), (3, 9)), fees=((1, 4), (2, 3), (3, 2)), height=2)
    add("token bound", token=4, count=4)
    add("token bound one past", token=5, count=5 - 1)
    add("last token", token=3, count=4, maxima=((3, 77),))
    add("zero user balance counts", maxima=((0, 1000),), rows=((ZERO_USER, ((0, 10),)),))
    add("dead user balance counts", maxima=((0, 1000),), rows=((DEAD_USER, ((0, 11),)),))
    add("both burn users", maxima=((0, 1000),), rows=((ZERO_USER, ((0, 10),)), (DEAD_USER, ((0, 11),))))
    add("other token balance of a burn user", maxima=((0, 1000),), rows=((DEAD_USER, ((3, 11),)),))
    add("own among other balances", token=2, maxima=((2, 1000),), rows=((DEAD_USER, ((0, 1), (2, 12), (3, 4))),))
    add("all balance keys below the token", token=2, maxima=((2, 1000),), rows=((DEAD_USER, ((0, 1), (1, 12))),))
    add("tall balance tree", token=2, maxima=((2, 1000),), rows=((DEAD_USER, ((0, 1), (2, 12), (3, 4))),), height=2)
    add("set member with balance", maxima=((0, 1000),), members=(USER_A,), rows=((USER_A, ((0, 40),)),))
    add("set member with no balance leaves no row", maxima=((0, 1000),), members=(USER_A,))
    add("two members sorted", maxima=((0, 1000),), members=(USER_B, USER_A), rows=((USER_A, ((0, 40),)), (USER_B, ((0, 2),))))
    add("zero user in the set counts twice", maxima=((0, 1000),), members=(ZERO_USER,), rows=((ZERO_USER, ((0, 10),)),))
    add("dead user in the set counts twice", maxima=((0, 1000),), members=(DEAD_USER,), rows=((DEAD_USER, ((0, 10),)),))
    add("sum above total saturates", maxima=((0, 10),), members=(USER_A,), rows=((USER_A, ((0, 40),)),))
    add("sum equal total", maxima=((0, 40),), members=(USER_A,), rows=((USER_A, ((0, 40),)),))
    add("sum one below total", maxima=((0, 41),), members=(USER_A,), rows=((USER_A, ((0, 40),)),))
    add("sum overflow", members=(USER_A, USER_B), rows=((USER_A, ((0, TOP),)), (USER_B, ((0, 1),))))
    add("sum exactly u64 max", members=(USER_A, USER_B), rows=((USER_A, ((0, TOP - 1),)), (USER_B, ((0, 1),))))
    add("overflow keeps first rows freed", members=(USER_A, USER_B, USER_C), rows=((USER_A, ((0, 5),)), (USER_B, ((0, TOP),))))
    many = tuple(bytes([index + 1]) * 20 for index in range(14))
    add("fourteen members force growth", maxima=((0, 10 ** 6),), members=many, rows=tuple((user, ((0, 100 + index),)) for index, user in enumerate(many)))
    add("fourteen members two levels", maxima=((0, 10 ** 6),), members=many, rows=tuple((user, ((0, 100 + index),)) for index, user in enumerate(many)), stale=1)
    add("members tall", maxima=((0, 10 ** 6),), members=many[:7], rows=tuple((user, ((0, 100 + index),)) for index, user in enumerate(many[:7])), height=2)
    add("members height three", maxima=((0, 10 ** 6),), members=many[:7], rows=tuple((user, ((0, 100 + index),)) for index, user in enumerate(many[:7])), height=3)
    for size in (1, 2, 3, 4, 5, 8, 9, 10, 11):
        add("members %d of a tall tree" % size, maxima=((0, 10 ** 6),), members=many[:size], rows=tuple((user, ((0, 7 + index),)) for index, user in enumerate(many[:size])), height=9 if size >= 3 else 0)
    add("members height eight", maxima=((0, 10 ** 6),), members=many[:7], rows=tuple((user, ((0, 100 + index),)) for index, user in enumerate(many[:7])), height=8)
    add("link token adds the 0x32 user", token=2, maxima=((2, 1000),), links=(2,), rows=((link_user(2), ((2, 25),)),))
    add("link token without balance", token=2, maxima=((2, 1000),), links=(2,))
    add("other token in the link map", token=2, maxima=((2, 1000),), links=(3,), rows=((link_user(2), ((2, 25),)),))
    add("same bucket other key", token=2, maxima=((2, 1000),), links=(2 + BUCKETS * 127,), rows=((link_user(2), ((2, 25),)),))
    add("same top bits other bucket", token=2, maxima=((2, 1000),), links=(2 + 127,), rows=((link_user(2), ((2, 25),)),))
    add("link found after a collision", token=2, maxima=((2, 1000),), crowd=(2 + BUCKETS * 127,), links=(2,), rows=((link_user(2), ((2, 25),)),))
    full = tuple(2 + BUCKETS * index for index in range(1, 20))
    add("link past a full group", token=2, maxima=((2, 1000),), crowd=full, links=(2,), rows=((link_user(2), ((2, 25),)),))
    add("absent past a full group", token=2, maxima=((2, 1000),), crowd=full, rows=((link_user(2), ((2, 25),)),))
    wrap = tuple(61 + BUCKETS * index for index in range(1, 24))
    add("link in the wrapped group", token=61, count=TOKEN_ROOM, maxima=((61, 9),), crowd=wrap, links=(61,)) if False else None
    add("bonus token adds to the top word only", token=1, maxima=((1, 1000),), fees=((1, 100),))
    add("bonus token with no max", token=1)
    add("bonus at the edge", token=1, maxima=((1, TOP - BONUS),))
    add("bonus past the edge", token=1, maxima=((1, TOP - BONUS + 1),))
    add("token 0 near the edge has no bonus", token=0, maxima=((0, TOP),))
    add("token 2 near the edge has no bonus", token=2, maxima=((2, TOP),))
    add("bonus error after rows", token=1, maxima=((1, TOP),), members=(USER_A,), rows=((USER_A, ((1, 5),)),))
    add("native reads staking for each user", token=2, native=2, maxima=((2, 10 ** 6),), members=(USER_A,), rows=((USER_A, ((2, 5),)),), staked=((USER_A, (1, 2, 3, 99)),))
    add("native staking only", token=2, native=2, maxima=((2, 10 ** 6),), members=(USER_A,), staked=((USER_A, (1, 0, 0, 99)),))
    add("native second word only", token=2, native=2, maxima=((2, 10 ** 6),), members=(USER_A,), staked=((USER_A, (0, 7, 0, 99)),))
    add("native third word only", token=2, native=2, maxima=((2, 10 ** 6),), members=(USER_A,), staked=((USER_A, (0, 0, 9, 99)),))
    add("native fourth word is not counted", token=2, native=2, maxima=((2, 10 ** 6),), members=(USER_A,), staked=((USER_A, (0, 0, 0, 99)),))
    add("native first add overflows", token=2, native=2, members=(USER_A,), rows=((USER_A, ((2, TOP),)),), staked=((USER_A, (1, 0, 0, 0)),))
    add("native second add overflows", token=2, native=2, members=(USER_A,), rows=((USER_A, ((2, TOP - 1),)),), staked=((USER_A, (1, 1, 0, 0)),))
    add("native third add overflows", token=2, native=2, members=(USER_A,), rows=((USER_A, ((2, TOP - 2),)),), staked=((USER_A, (1, 1, 1, 0)),))
    add("native adds reach u64 max", token=2, native=2, members=(USER_A,), rows=((USER_A, ((2, TOP - 3),)),), staked=((USER_A, (1, 1, 1, 0)),))
    add("native is another token", token=2, native=3, maxima=((2, 10 ** 6),), members=(USER_A,), rows=((USER_A, ((2, 5),)),), staked=((USER_A, (1, 2, 3, 99)),))
    add("native token equals token but flag clear is modelled by none", token=2, maxima=((2, 10 ** 6),), members=(USER_A,), rows=((USER_A, ((2, 5),)),), staked=((USER_A, (1, 2, 3, 99)),))
    add("native burn users read staking", token=2, native=2, maxima=((2, 10 ** 6),), staked=((ZERO_USER, (1, 0, 0, 0)), (DEAD_USER, (0, 2, 0, 0))))
    add("reserve taken from free", token=2, native=2, maxima=((2, 1000),), reserve=(1, 300))
    add("reserve equal free", token=2, native=2, maxima=((2, 1000),), reserve=(1, 1000))
    add("reserve above free records", token=2, native=2, maxima=((2, 1000),), reserve=(1, 1001))
    add("reserve flag clear", token=2, native=2, maxima=((2, 1000),), reserve=(0, 300))
    add("reserve on another token is unused", token=2, native=3, maxima=((2, 1000),), reserve=(1, 300))
    add("reserve after sum", token=2, native=2, maxima=((2, 1000),), members=(USER_A,), rows=((USER_A, ((2, 100),)),), reserve=(1, 300))
    add("native and bonus token", token=1, native=1, maxima=((1, 1000),), reserve=(1, 300))
    add("native bonus past the edge", token=1, native=1, maxima=((1, TOP),), reserve=(1, 300))
    add("link user on native", token=2, native=2, maxima=((2, 1000),), links=(2,), rows=((link_user(2), ((2, 25),)),), staked=((link_user(2), (1, 0, 0, 0)),))
    add("flag clear with the token in the native word", token=2, ghost=2, maxima=((2, 10 ** 6),), members=(USER_A,), staked=((USER_A, (1, 2, 3, 99)),), reserve=(1, 5))
    add("native token zero", token=0, native=0, maxima=((0, 1000),), reserve=(1, 300))
    add("link fourth among equal top bits", token=2, maxima=((2, 1000),), crowd=tuple(2 + BUCKETS * 127 * index for index in range(1, 4)), links=(2,), rows=((link_user(2), ((2, 25),)),))
    add("link sixth among equal top bits", token=2, maxima=((2, 1000),), crowd=tuple(2 + BUCKETS * 127 * index for index in range(1, 6)), links=(2,), rows=((link_user(2), ((2, 25),)),))
    add("link after three full groups", token=2, maxima=((2, 1000),), crowd=tuple(2 + BUCKETS * index for index in range(1, 51)), links=(2,), rows=((link_user(2), ((2, 25),)),))
    add("absent after three full groups", token=2, maxima=((2, 1000),), crowd=tuple(2 + BUCKETS * index for index in range(1, 51)), rows=((link_user(2), ((2, 25),)),))
    add("all four sources in order", token=2, maxima=((2, 10 ** 6),), links=(2,), members=(USER_A, USER_C), rows=((USER_A, ((2, 1),)), (USER_C, ((2, 2),)), (ZERO_USER, ((2, 3),)), (DEAD_USER, ((2, 4),)), (link_user(2), ((2, 5),))))
    return [case for case in out if case is not None]


def named_modify():
    out = []

    def add(name, **fields):
        out.append(Case("modify " + name, entry="modify", **fields))

    add("no change")
    add("one add", adds=(USER_A,))
    add("add twice", adds=(USER_A, USER_A))
    add("add existing", members=(USER_A,), adds=(USER_A,))
    add("remove existing", members=(USER_A,), removes=(USER_A,))
    add("remove absent", members=(USER_A,), removes=(USER_B,))
    add("remove from empty", removes=(USER_B,))
    add("add then remove in one vote", adds=(USER_A,), removes=(USER_A,))
    add("add order does not matter", adds=(USER_C, USER_A, USER_B))
    add("last token", token=3, adds=(USER_A,))
    add("token bound", token=4, adds=(USER_A,))
    add("token bound with empty lists", token=4)
    many = tuple(bytes([index + 1]) * 20 for index in range(30))
    add("thirty adds grow the tree", adds=many)
    add("removes shrink the tree", adds=many, removes=many[:25])
    add("removes empty the tree", members=many[:11], removes=many[:11])
    add("members and more", members=many[:6], adds=many[6:14], removes=many[3:9])
    add("stale key in a spare slot", members=many[:3], removes=(USER_C,), stale=1)
    add("zero user may be a member", adds=(ZERO_USER, DEAD_USER))
    return out


def named_arm(copy):
    out = []

    def add(name, **fields):
        out.append(Case("arm %s %s" % ("abc"[copy], name), entry="arm", copy=copy, **fields))

    add("empty lists")
    add("add and remove", members=(USER_B,), adds=(USER_A,), removes=(USER_B,))
    add("token bound", token=4, count=4, adds=(USER_A,), removes=(USER_B,))
    add("token bound with spare capacity", token=4, count=4, adds=(USER_A,), caps=(3, 2))
    add("token bound with empty lists", token=4, count=4)
    add("last token", token=3, adds=(USER_A,))
    add("add list has spare capacity", adds=(USER_A,), caps=(2, 0))
    add("remove list has spare capacity", removes=(USER_A,), caps=(0, 2))
    users = tuple(index.to_bytes(4, "big") * 5 for index in range(1, LIST_CAP + 2))
    add("add list at the cap", adds=users[:LIST_CAP], fast=1)
    add("add list past the cap", adds=users[:LIST_CAP + 1])
    add("add list past the cap with removes", adds=users[:LIST_CAP + 1], removes=(USER_A,))
    add("remove list at the cap", removes=users[:LIST_CAP], fast=1)
    add("remove list past the cap", removes=users[:LIST_CAP + 1])
    add("remove list past the cap with adds", adds=(USER_A,), removes=users[:LIST_CAP + 1])
    add("both past the cap", adds=users[:LIST_CAP + 1], removes=users[:LIST_CAP + 1])
    add("bad token beats lengths", token=4, count=4, adds=users[:LIST_CAP + 1])
    return [case for case in out if case is not None]


def word_input(token):
    return token.to_bytes(32, "big")


def named_precompile():
    out = []

    def add(name, **fields):
        out.append(Case("precompile " + name, entry="precompile", **fields))

    add("empty token", data=word_input(0))
    add("token with rows", token=2, data=word_input(2), maxima=((2, 1000),), fees=((2, 100),), members=(USER_A,), rows=((USER_A, ((2, 40),)),))
    add("two rows keep their order", token=2, data=word_input(2), maxima=((2, 1000),), members=(USER_A, USER_B), rows=((USER_A, ((2, 40),)), (USER_B, ((2, 3),))))
    add("three rows", token=2, data=word_input(2), maxima=((2, 1000),), members=(USER_A, USER_B, USER_C), rows=((USER_A, ((2, 40),)), (USER_B, ((2, 3),)), (USER_C, ((2, 9),))))
    add("nine rows", token=2, data=word_input(2), maxima=((2, 1000),), members=tuple(bytes([index + 1]) * 20 for index in range(9)), rows=tuple((bytes([index + 1]) * 20, ((2, index + 1),)) for index in range(9)))
    add("bonus word", token=1, data=word_input(1), maxima=((1, 7),))
    add("reserve word", token=2, native=2, data=word_input(2), maxima=((2, 1000),), reserve=(1, 300))
    add("large words", token=2, data=word_input(2), maxima=((2, TOP),), fees=((2, 1),))
    add("token bound", token=4, data=word_input(4))
    add("token far past", token=0xFFFFFFFF, data=word_input(0xFFFFFFFF))
    add("summary error text", token=2, data=word_input(2), members=(USER_A, USER_B), rows=((USER_A, ((2, TOP),)), (USER_B, ((2, 1),))))
    add("disabled address", data=word_input(0), blocked=(PRECOMPILE_ADDRESS,))
    add("other address in the set", data=word_input(0), blocked=(PRECOMPILE_ADDRESS[:-1] + b"\x0c",))
    add("sort neighbours in the set", data=word_input(0), blocked=(PRECOMPILE_ADDRESS[:-1] + b"\x0c", PRECOMPILE_ADDRESS[:-1] + b"\x0e", b"\xff" * 20))
    set_keys = (b"\x00" * 19 + b"\x01", PRECOMPILE_ADDRESS[:-1] + b"\x0c", PRECOMPILE_ADDRESS, PRECOMPILE_ADDRESS[:-1] + b"\x0e", b"\xff" * 20)
    add("disabled address in a tall set", data=word_input(0), blocked=set_keys, height=2)
    add("disabled address missing from a tall set", data=word_input(0), blocked=set_keys[:2] + set_keys[3:], height=2)
    add("disabled address one above a tall middle", data=word_input(0), blocked=set_keys[:3], height=2)
    add("disabled address second in a small set", data=word_input(0), blocked=set_keys[:3])
    add("disabled address in a spare slot", data=word_input(0), blocked=set_keys[:2], stale=1)
    add("disabled address last of three", data=word_input(0), blocked=(bytes(20), set_keys[0], PRECOMPILE_ADDRESS))
    add("input above the size cap", data=bytes(2001))
    add("input at the size cap", data=bytes(2000), refuse=1)
    add("decoder refuses", data=bytes(31), refuse=1)
    add("decoder refuses empty input", data=b"", refuse=1)
    add("decoder refuses at the gas edge", data=bytes(31), refuse=1, limit=BASE_GAS + 31 * WORD_GAS)
    add("gas equal base", data=word_input(0), limit=BASE_GAS + 32 * WORD_GAS + 192 * WORD_GAS)
    add("gas one short of the total", data=word_input(0), limit=BASE_GAS + 32 * WORD_GAS + 192 * WORD_GAS - 1)
    add("gas under the input charge", data=word_input(0), limit=BASE_GAS + 32 * WORD_GAS - 1)
    add("gas at the input charge", data=word_input(0), limit=BASE_GAS + 32 * WORD_GAS)
    add("bad token at the input charge", token=4, data=word_input(4), limit=BASE_GAS + 32 * WORD_GAS)
    return out


def named_proposal(copy):
    out = []

    def add(name, **fields):
        out.append(Case("proposal %s %s" % ("abc"[copy], name), entry="proposal", copy=copy, **fields))

    common = dict(native=2, maxima=((2, 1000),))
    add("testnet byte", chain=3, **common)
    add("no native token")
    add("no native token stamped", stamped=1)
    add("plain", **common)
    add("stamped", stamped=1, chain=1, **common)
    add("chain byte 2", chain=2, **common)
    add("uses free word", native=2, maxima=((2, 1000),), fees=((2, 100),), members=(USER_A,), rows=((USER_A, ((2, 200),)),), reserve=(1, 50))
    add("zero free word", native=2, maxima=((2, 10),), reserve=(1, 50))
    add("sum error", native=2, members=(USER_A, USER_B), rows=((USER_A, ((2, TOP),)), (USER_B, ((2, 1),))))
    add("native index past the list", native=9, count=4)
    add("flag byte", flag=1, **common)
    add("native token zero", native=0, maxima=((0, 1000),), stamped=1)
    add("native token zero plain", native=0, maxima=((0, 1000),))
    add("flag clear with a value in the native word", ghost=2)
    add("flag clear stamped with a value in the native word", ghost=2, stamped=1)
    add("title at the cap", title=b"x" * TITLE_CAP, **common)
    add("title past the cap", title=b"x" * (TITLE_CAP + 1), **common)
    add("body at the cap", body=b"y" * DESC_CAP, **common)
    add("body past the cap", body=b"y" * (DESC_CAP + 1), **common)
    add("both past the cap", title=b"x" * (TITLE_CAP + 1), body=b"y" * (DESC_CAP + 1), **common)
    add("empty texts", title=b"", body=b"", **common)
    add("sink refuses", propose=0x77, **common)
    add("sink refuses stamped", propose=0x77, stamped=1, **common)
    return out


def base_cases():
    out = named_summary() + named_modify() + named_precompile()
    for copy in range(3):
        out += named_arm(copy) + named_proposal(copy)
    return out


VECTORS = 200
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
    pool = tuple(bytes([index * 3 + 1]) * 20 for index in range(16)) + (ZERO_USER, DEAD_USER)
    for index in range(count):
        pick = lcg(index * 2 + 1)
        token = pick(5)
        count_field = 4 + pick(2)

        def wide():
            return pick(10 ** (pick(9) * 2 + 1)) + (pick(5) == 0) * pick(1 << 31) * pick(1 << 31) * 2

        members = tuple(pool[pick(16)] for _ in range(pick(14)))
        extra = (link_user(token),) if pick(3) == 0 else ()
        rows = tuple((user, tuple((key, wide()) for key in sorted({token, pick(5), pick(5)}))) for user in sorted(set(members + extra + (ZERO_USER, DEAD_USER))) if pick(4))
        fields = dict(token=token, count=count_field, maxima=tuple((key, wide() * 3) for key in sorted({token, pick(5)}) if pick(5)), fees=tuple((key, wide()) for key in sorted({token, pick(5)}) if pick(2)), links=(token,) if pick(3) == 0 else (), crowd=tuple(token + BUCKETS * (k + 1) for k in range(pick(3) * 9)),
                      members=members, rows=rows, native=(None, token, pick(5))[pick(3)], staked=tuple((user, (wide(), wide(), wide(), pick(99))) for user in sorted(set(members)) if pick(2)), reserve=(pick(2), wide()), stale=pick(2), height=pick(3))
        if index % 3 == 2:
            fields["data"] = word_input(token)
            fields["limit"] = (TOP, BASE_GAS + 32 * WORD_GAS + (6 + pick(20)) * 32 * WORD_GAS)[pick(2)]
            out.append(Case("vector %d" % index, entry="precompile", **fields))
        else:
            out.append(Case("vector %d" % index, **fields))
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


SURVIVORS = (
    (0x375E66D, 0x375EBE0, "immediate", "iterator state word: the loop compares these with 2 or tests bit 0 and keeps its own copies, so the edited value takes the same path"),
    (0x375E72E, 0x375E72F, "immediate", "equal dword shuffle: every dword holds the broadcast byte"),
    (0x375EA65, 0x375EB4C, "immediate", "unrolled tree descent: the edited bound takes the one step loop and reaches the same node"),
    (0x375EB84, 0x375EB8B, "displacement", "last pointer of the unrolled descent, not read again on the visited path"),
    (0x3249097, 0x324909B, "immediate", "low bytes of the first text word are written over by the second word"),
    (0x324936A, 0x32497E8, None, "ABI writer bookkeeping: capacity, reserve and offset stack words, or the zero top bytes of an amount word; the output bytes are the same"),
    (0x32498C2, 0x32498D0, None, "gas add cannot carry with these lengths, so the saturation rows have no effect"),
    (0x3BAF8C4, 0x3BAF8CE, "immediate", "size bound far above any row count"),
    (0x3BAF9E6, 0x3BAF9EB, "immediate", "dangling pointer of an empty vector, never read"),
    (0x1F68D14, 0x1F68D7E, "displacement", "status payload copy past the tag; the summary writes only the tag on error, so these bytes are stack bytes"),
    (0x47BA8A5, 0x47BA8A9, "displacement", "payload word of tag 0xfb; only the tag is compared, and the word is stack bytes"),
    (0x47BA960, 0x47BA9D0, "displacement", "status payload copy past the tag; the summary writes only the tag on error, so these bytes are stack bytes"),
    (0x47BACF5, 0x47BACF9, "displacement", "payload word of tag 0xfb; only the tag is compared, and the word is stack bytes"),
    (0x47BADB0, 0x47BAE20, "displacement", "status payload copy past the tag; the summary writes only the tag on error, so these bytes are stack bytes"),
)


def survivor_reason(va, kind):
    for low, high, want, reason in SURVIVORS:
        if low <= va < high and (want is None or want == kind):
            return reason
    return "unclassified"



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
    ("ModifyNonCirculatingSupply", "fields token, add u64, remove u64", "the action holds a token and two user lists (20 byte keys), each at most 10000 long; the body inserts all of the first list, then removes all of the second", "arm a add and remove"),
    ("circulating supply", "no function in the reference", "0x375e4c0 builds it: max minus token_fees_collected, minus the sum over non-circulating users, then minus native_token_reserve for the native token", "summary all four sources in order"),
    ("list length cap", "none", "both lists are refused above 10000 with tag 0x143, after the token bound", "arm a bad token beats lengths"),
    ("burn users", "none", "the zero address and the 0x...dead address are always counted, and a set member equal to one of them counts twice", "summary zero user in the set counts twice"),
    ("token 1", "none", "token id 1 reports max + 4e13 in the top word only; total and circulating do not move, and the add is checked with tag 0xbe", "summary bonus token adds to the top word only"),
    ("native staking", "none", "for the native token each counted user also adds the first three words of slot 0x5774f18; the fourth word is ignored", "summary native fourth word is not counted"),
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
    blob = image.blob
    at = image.offset(0x59962D)
    if bytes(blob[at:at + 18]) != bytes(16) + bytes(2) or bytes(blob[at + 18:at + 20]) != b"\xde\xad":
        raise EvidenceError("burn address constant")
    rows.append(("0x59962d", bytes(blob[at:at + 20]).hex(), "second burn user; the first is written as zeros at 0x375e6a4"))
    at = image.offset(0x582550)
    if bytes(blob[at:at + 20]) != PRECOMPILE_ADDRESS:
        raise EvidenceError("precompile address constant")
    rows.append(("0x582550", PRECOMPILE_ADDRESS.hex(), "address searched in the set at context +0x38"))
    return rows


FIELD_KEYS = (
    ("token_to_max_supply", 0x3721F09, 19, 0x3721F02, 4, "spot +0x388, u64 tree, first summary word"),
    ("token_fees_collected", 0x3721F37, 20, 0x3721F30, 4, "spot +0x3a0, u64 tree, subtracted from the first word"),
    ("non_circulating_users", 0x375AC3C, 21, 0x375AC35, 4, "token row +0x90, set of 20 byte users"),
    ("native_token_reserve", 0x238DA7E, 20, 0x238DA7A, 1, "staking +0x60, option word, fourth summary word"),
)


def field_rows(image):
    """Serde key beside the field offset, read from `lea disp(base),reg` then `lea key(%rip),%rsi` in the serializers."""
    rows = []
    for name, lea, size, row, width, meaning in FIELD_KEYS:
        at = image.offset(lea)
        key = lea + 7 + struct.unpack_from("<i", image.blob, at + 3)[0]
        text = bytes(image.blob[image.offset(key):image.offset(key) + size])
        if text != name.encode():
            raise EvidenceError("serde key %s: %r" % (name, text))
        place = image.offset(row)
        offset = struct.unpack_from("<i", image.blob, place + 3)[0] if width == 4 else image.blob[place + 3]
        rows.append((name, "%#x" % key, "%#x" % lea, "%#x" % row, "%#x" % offset, meaning))
    return rows


def location_rows(image):
    path, line, column = image.location(LOC_WEI_SUB, image.relative())
    return [("%#x" % LOC_WEI_SUB, path, line, column, "native_token_reserve subtract above the free word")]


def caller_rows(image):
    """Every slot call of the summary and of the set body, by fixed `ff 15 disp32` bytes."""
    base, text = image.text_bytes()
    rows = []
    for slot, name in ((0x5773330, "summary"), (0x5773E48, "set body")):
        at = text.find(b"\xff\x15")
        while at >= 0:
            va = base + at
            if va + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                rows.append((name, "%#x" % slot, "%#x" % va, "%#x" % image.fde(va)[0]))
            at = text.find(b"\xff\x15", at + 1)
    return rows


def subject_rows(image, seen):
    table = {}
    for name, target in FUNCTIONS.items():
        table[name] = rows_of(image, target)
    for name, target in DISPATCHERS.items():
        table[name] = [row for row in rows_of(image, target) if row.va in seen]
    return table


def copy_rows():
    return [(copy.name, "%#x" % copy.proposal, "%#x" % copy.arm, "%#x" % ARM_STACK[index][0], "%#x" % ARM_STACK[index][1]) for index, copy in enumerate(COPIES)]


def analyse(image, mutate=True, vectors=VECTORS):
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = subject_rows(image, seen)
    for name in table:
        for row in table[name]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {name: [row.va for row in table[name] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for name in table}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), tags=tag_rows(image), copies=copy_rows(), locations=location_rows(image), callers=caller_rows(image), fields=field_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def cell(value):
    if isinstance(value, bytes):
        return value.hex() if len(value) <= 40 else "%d bytes %s" % (len(value), hashlib.sha256(value).hexdigest()[:16])
    if isinstance(value, int):
        return "%#x" % value
    if isinstance(value, (tuple, list)):
        if len(value) > 16:
            return "%d items %s" % (len(value), hashlib.sha256(repr(value).encode()).hexdigest()[:16])
        return "(" + " ".join(cell(part) for part in value) + ")"
    return str(value)


def outcome_row(case, got):
    return (case.name, cell(got["result"]), "; ".join(cell(event) for event in got["events"]) if len(got["events"]) <= 24 else "%d events" % len(got["events"]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "bytes", "meaning"), result["constants"])
    tsv("field-keys.tsv", ("serde key", "key address", "key lea", "offset row", "offset", "meaning"), result["fields"])
    tsv("tag-texts.tsv", ("tag", "display text"), result["tags"])
    tsv("locations.tsv", ("record", "path", "line", "column", "use"), result["locations"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "proposal handler", "vote arm", "stack slot of first list", "stack slot of second list"), result["copies"])
    tsv("callers.tsv", ("callee", "slot", "call site", "function"), result["callers"])
    tsv("outcomes.tsv", ("case", "result", "callee events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
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

