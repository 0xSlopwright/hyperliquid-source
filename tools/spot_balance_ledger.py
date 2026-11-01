#!/usr/bin/env python3
"""Pin the node #94 spot balance row writers: update, hold, release, fee sweep, user sweep, and every call of the update.

Real rows run from each writer's entry on real tree and table memory. A separately written rule list predicts every row,
index entry, fee word and recorder call, and every reached conditional row, immediate and field offset of the subject
code is edited. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/spot_balance_ledger.py --out <dir>
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
UPDATE = 0x371D120
TRY_HOLD = 0x371B140
RELEASE = 0x372D5E0
FEE_SWEEP = 0x3721370
USER_SWEEP = 0x3721780
RESOLVE = 0x375E300
VALUE = 0x32814C0
TAG_LOG = 0x3762510
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_RECORD = 0x5773190
SLOT_TRY_HOLD = 0x5774730
SLOT_RESOLVE = 0x57747A0
SLOT_RELEASE = 0x57747E8
SLOT_USER_SWEEP = 0x5774940
SLOT_FEE_SWEEP = 0x5774948
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
ADD_LOCATION = 0x56DFD78
SUB_LOCATION = 0x56DFD90
CAP = 0x28F5C28F5C28F5C
ENTRY_SIZE = 0x58
ROW_SIZE = 0x18
TOKEN_STRIDE = 0xE8
TOKEN_COUNT = 40
SENTINEL = b"\xee" * 20
TABLE_AT = 0x298
FEES_AT = 0x3A0
INDEX_AT = 0x400
TOKENS_POINTER = 0x190
TOKENS_COUNT = 0x198
SPOTS_POINTER = 0x178
SPOTS_COUNT = 0x180
SPOT_COUNT = 8
SPOT_STRIDE = 0x20
HEAP_SIZE = 0x40000
STATE = HEAP_BASE + 0x100
STATE_SIZE = 0x600
TOKENS = HEAP_BASE + 0x800
TOTAL_STOP = 0x371D5E0
TAIL_START = 0x371D4F8
SPOTS = TOKENS + TOKEN_COUNT * TOKEN_STRIDE + 0x40
BUMP = SPOTS + SPOT_COUNT * SPOT_STRIDE + 0x100
BUMP_END = HEAP_BASE + HEAP_SIZE
MAP_REF = BUMP_END - 0x40
BUMP_END = MAP_REF
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000))
BUCKETS = 16
TOP = MASK[8]
SIGN_BIT = 1 << 63
TWO_63 = 9223372036854775808.0
SUBJECTS = (UPDATE, TRY_HOLD, RELEASE, FEE_SWEEP, USER_SWEEP)
NAMES = {UPDATE: "ledger_update", TRY_HOLD: "try_hold", RELEASE: "release_hold", FEE_SWEEP: "fee_sweep", USER_SWEEP: "user_sweep"}
AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000 and target != TAG_LOG


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


ROW_TREE = Layout(8, 8, 0x60, ROW_SIZE, 0, 0x168, 0x16A, 0x170)
FEE_TREE = Layout(8, 8, 0x60, 8, 0, 0xB8, 0xBA, 0xC0)
INDEX_TREE = Layout(0x110, 20, 8, ROW_SIZE, 0, 0x1EC, 0x1EE, 0x1F0)
SET_TREE = Layout(8, 8, 0, 0, 0, 0x60, 0x62, 0x68)
USER_MAP = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)


class Case:
    DEFAULTS = dict(steps=(), tokens=None, kind="steps", bits=0)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


def user_of(number):
    return bytes([number & 0xFF]) + bytes(((number + 3) * (index + 5) + index) & 0xFF for index in range(19))


def token_row(token, tokens):
    if tokens is not None and token in tokens:
        return tokens[token]
    return (2, 2 + token % 4)


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_RECORD, self.on_record))
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
        machine.calls = {RESUME: self.on_panic, TAG_LOG: self.on_tag}
        self.case = None
        self.live = {}
        self.events = []
        self.cur = BUMP

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        self.events.append("panic")
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

    def on_record(self, machine):
        self.expect(machine.regs[RDI] & 0xFF == 0, "recorder flag")
        self.events.append("record %#x" % machine.regs[RSI])

    def on_tag(self, machine):
        self.events.append("tag %#x" % machine.memory.read(machine.regs[RDI], 2))

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

    def walk(self, root, height, layout):
        memory = self.machine.memory
        rows = []

        def visit(at, level, parent, index):
            size = memory.read(at + layout.len_at, 2)
            self.expect(size <= 11, "node length")
            self.expect(memory.read(at + layout.parent_at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + layout.index_at, 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + layout.edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.bytes_at(at + layout.key_at + layout.key_size * slot, layout.key_size), at + layout.val_at + layout.val_size * slot))
        if root:
            visit(root, height, 0, 0)
        self.expect(all(rows[index][0][::-1 if layout.key_size == 8 else 1] < rows[index + 1][0][::-1 if layout.key_size == 8 else 1] for index in range(len(rows) - 1)), "keys in order")
        return rows

    def entries(self):
        """Every full bucket of the user table, by the real control bytes."""
        memory = self.machine.memory
        ctrl, mask, left, items = struct.unpack("<4Q", memory.bytes_at(STATE + TABLE_AT, 32))
        out = []
        for index in range(mask + 1):
            if memory.read(ctrl + index, 1) & 0x80 == 0:
                out.append(ctrl - (index + 1) * ENTRY_SIZE)
        self.expect(len(out) == items, "item count")
        return sorted(out, key=lambda at: memory.bytes_at(at, 20))

    def row_at(self, user, token):
        memory = self.machine.memory
        for at in self.entries():
            if memory.bytes_at(at, 20) == user:
                root, height = memory.read(at + 0x28, 8), memory.read(at + 0x30, 8)
                for key, value in self.walk(root, height, ROW_TREE):
                    if key == struct.pack("<Q", token):
                        return value
        raise EvidenceError("no such row")

    def view(self):
        memory = self.machine.memory
        users = {}
        for at in self.entries():
            root, height, size = struct.unpack("<3Q", memory.bytes_at(at + 0x28, 24))
            rows = self.walk(root, height, ROW_TREE)
            self.expect(len(rows) == size, "row tree length")
            users[memory.bytes_at(at, 20)] = dict(rows={struct.unpack("<Q", key)[0]: struct.unpack("<3Q", memory.bytes_at(value, ROW_SIZE)) for key, value in rows},
                                                  head=memory.bytes_at(at + 0x14, 0x14), tail=memory.bytes_at(at + 0x40, 0x18))
        root, height, size = struct.unpack("<3Q", memory.bytes_at(STATE + FEES_AT, 24))
        fees = self.walk(root, height, FEE_TREE)
        self.expect(len(fees) == size, "fee tree length")
        root, height, size = struct.unpack("<3Q", memory.bytes_at(STATE + INDEX_AT, 24))
        index = {}
        pairs = self.walk(root, height, INDEX_TREE)
        self.expect(len(pairs) == size, "index tree length")
        for key, value in pairs:
            top, level, count = struct.unpack("<3Q", memory.bytes_at(value, 24))
            members = self.walk(top, level, SET_TREE)
            self.expect(len(members) == count, "token set length")
            index[key] = sorted(struct.unpack("<Q", member)[0] for member, _ in members)
        return dict(users=users, fees={struct.unpack("<Q", key)[0]: memory.read(value, 8) for key, value in fees}, index=index, marks=memory.bytes_at(STATE, 0x10) + memory.bytes_at(STATE + 0x1A0, 0x20), tokens_seen=memory.read(STATE + TOKENS_COUNT, 8), events=list(self.events))

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:len(HEAP_FILL)] = HEAP_FILL
        memory.put_bytes(STATE, bytes([0xC7]) * STATE_SIZE)
        self.case = case
        self.events = []
        self.live = {}
        self.cur = BUMP
        self.machine.frame = 0
        block = self.bump((BUCKETS * ENTRY_SIZE + BUCKETS + 16 + 15) & ~15)
        ctrl = block + BUCKETS * ENTRY_SIZE
        memory.put_bytes(ctrl, b"\xff" * (BUCKETS + 16))
        seeds = (0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89)
        memory.put_bytes(STATE + TABLE_AT, struct.pack("<4Q", ctrl, BUCKETS - 1, 14, 0) + struct.pack("<4Q", *seeds))
        for at in (FEES_AT, INDEX_AT):
            memory.put_bytes(STATE + at, struct.pack("<3Q", 0, 0xFEED, 0))
        memory.write(STATE + TOKENS_POINTER, 8, TOKENS)
        memory.write(STATE + TOKENS_COUNT, 8, TOKEN_COUNT)
        memory.write(STATE + SPOTS_POINTER, 8, SPOTS)
        memory.write(STATE + SPOTS_COUNT, 8, SPOT_COUNT)
        for spot in range(SPOT_COUNT):
            base, quote = spot_row(spot)
            memory.put_bytes(SPOTS + SPOT_STRIDE * spot, struct.pack("<4Q", base, quote, 0x5151515151515151, 0x5252525252525252))
        for token in range(TOKEN_COUNT):
            sz, wei = token_row(token, case.tokens)
            memory.write(TOKENS + TOKEN_STRIDE * token + 0x48, 1, sz)
            memory.write(TOKENS + TOKEN_STRIDE * token + 0x49, 1, wei)

    def enter(self, target, registers):
        return self.machine.run(target, registers)

    def poke(self, user, token, total, hold, notional, indexed):
        """Create the row through the real update, then set its words."""
        memory = self.machine.memory
        memory.put_bytes(HEAP_BASE + 0x40, user)
        self.enter(UPDATE, {RDI: STATE, RSI: HEAP_BASE + 0x40, RDX: token, RCX: 1 if not indexed else 0, R8: 0, R9: 0})
        memory.put_bytes(self.row_at(user, token), struct.pack("<3Q", total, hold, notional))

    def step(self, step):
        memory = self.machine.memory
        kind = step[0]
        if kind == "poke":
            self.poke(*step[1:])
            return None
        if kind == "stale":
            _, user, key = step
            for at in self.entries():
                if memory.bytes_at(at, 20) == user:
                    root = memory.read(at + 0x28, 8)
                    for slot in range(memory.read(root + ROW_TREE.len_at, 2), 11):
                        memory.write(root + ROW_TREE.key_at + 8 * slot, 8, key)
            return None
        if kind == "update":
            _, user, token, debit, amount, price = step
            memory.put_bytes(HEAP_BASE + 0x40, user + b"\x55" * 12)
            self.enter(UPDATE, {RDI: STATE, RSI: HEAP_BASE + 0x40, RDX: token, RCX: debit | 0xABCD00, R8: amount, R9: price})
            return None
        if kind == "hold":
            _, user, token, amount = step
            memory.put_bytes(HEAP_BASE + 0x40, user + b"\x55" * 12)
            return self.enter(TRY_HOLD, {RDI: STATE, RSI: HEAP_BASE + 0x40, RDX: token, RCX: amount}) & 0xFF
        if kind == "release":
            _, user, spot, side, price, size = step
            memory.put_bytes(HEAP_BASE + 0x40, user + b"\x55" * 12)
            self.enter(RELEASE, {RDI: STATE, RSI: HEAP_BASE + 0x40, RDX: spot, RCX: side | 0xABCD00, R8: price, R9: size})
            return None
        if kind == "fees":
            _, token, price = step
            self.enter(FEE_SWEEP, {RDI: STATE, RSI: token, RDX: price})
            return None
        if kind == "sweep":
            _, token, users, price, height = step
            items = [(user, 0x6000 + index) for index, user in enumerate(sorted(users))]
            root, level = self.tree_bytes(USER_MAP, items, height)
            memory.write(MAP_REF, 8, root)
            memory.write(MAP_REF + 8, 8, level)
            memory.write(MAP_REF + 0x10, 8, len(items))
            self.enter(USER_SWEEP, {RDI: STATE, RSI: token, RDX: MAP_REF, RCX: price})
            return None
        raise EvidenceError("unknown step %s" % kind)

    def run(self, case):
        self.fresh(case)
        if case.kind == "tail":
            return self.run_tail(case)
        results = []
        for step in case.steps:
            try:
                results.append(self.step(step))
            except Panicked:
                results.append("panic")
                break
        got = self.view()
        got["results"] = results
        return got

    def run_tail(self, case):
        memory = self.machine.memory
        machine = self.machine
        machine.stop = TOTAL_STOP
        machine.xmm[0] = 0
        machine.xmm[2] = case.bits
        memory.write(HEAP_BASE + 0x60, 8, 0x4545)
        try:
            machine.run(TAIL_START, {R14: HEAP_BASE + 0x50})
        finally:
            machine.stop = None
        return dict(result=memory.read(HEAP_BASE + 0x60, 8))


def spot_row(spot):
    return (2 * spot + 1, 2 * spot + 2 if spot != 7 else 40)


def scale(token, tokens):
    """The value helper's divisor; None stands for its panic rows."""
    if token == 0:
        return 1
    if token >= TOKEN_COUNT:
        return None
    sz, wei = token_row(token, tokens)
    if sz > wei or wei - sz >= 20:
        return None
    return 10 ** (wei - sz)


def value_of(amount, token, price, tokens):
    divisor = scale(token, tokens)
    if divisor is None:
        return "panic"
    product = amount * price
    if product <= TOP:
        return product // divisor
    second = (amount // divisor) * price
    return second if second <= TOP else None


class Model:
    """A separately written rule list for the five writers; no addresses, no machine state."""

    def __init__(self, tokens):
        self.tokens = tokens
        self.users = {}
        self.index = {}
        self.fees = {}
        self.events = []

    def row(self, user, token):
        return self.users.setdefault(user, {}).setdefault(token, [0, 0, 0])

    def add_up(self, left, right):
        if left + right > TOP:
            self.events.append("record %#x" % ADD_LOCATION)
            return TOP
        return left + right

    def take(self, left, right):
        if left < right:
            self.events.append("record %#x" % SUB_LOCATION)
            return 0
        return left - right

    def panic(self):
        self.events.append("panic")
        raise Panicked("spec panic")

    def poke(self, user, token, total, hold, notional, indexed):
        self.users.setdefault(user, {})[token] = [total, hold, notional]
        if indexed:
            self.index.setdefault(user, set()).add(token)

    def update(self, user, token, debit, amount, price):
        row = self.row(user, token)
        old = row[0]
        if debit & 1:
            if amount > old:
                self.panic()
            row[0] = old - amount
            row[1] = self.take(row[1], amount)
            left = old - amount
        else:
            self.index.setdefault(user, set()).add(token)
            row[0] = self.add_up(old, amount)
        if price == 0 or token == 0:
            return
        if debit & 1:
            if row[2] == 0:
                worth = value_of(left, token, price, self.tokens)
                if worth == "panic":
                    self.panic()
                row[2] = worth or 0
                return
            if row[2] >= CAP:
                return
            ratio = float(left) / float(old) if old else 0.0
            row[2] = int(float(row[2]) * ratio)
            return
        whole = (old + amount) & TOP
        if whole <= amount:
            whole = amount
        worth = value_of(amount if row[2] else whole, token, price, self.tokens)
        if worth == "panic":
            self.panic()
        if worth is not None and row[2] + worth <= TOP:
            row[2] += worth

    def hold(self, user, token, amount):
        if token >= TOKEN_COUNT:
            self.events.append("tag 0xea")
            return 0
        if amount == 0:
            return 1
        if user not in self.users:
            return 0
        row = self.row(user, token)
        wanted = row[1] + amount
        if wanted > TOP or wanted > row[0]:
            return 0
        row[1] = wanted
        return 1

    def release(self, user, spot, side, price, size):
        if spot >= SPOT_COUNT:
            self.panic()
        base, quote = spot_row(spot)
        if side & 1:
            token = base
            if token >= TOKEN_COUNT:
                self.panic()
            sz, wei = token_row(token, self.tokens)
            if sz > wei or wei - sz >= 20:
                self.panic()
            amount = size * 10 ** (wei - sz)
        else:
            token, amount = quote, price * size
        if amount > TOP:
            return
        row = self.row(user, token)
        self.index.setdefault(user, set()).add(token)
        row[1] = self.take(row[1], amount)

    def fee_sweep(self, token, price):
        self.users.setdefault(SENTINEL, {})
        row = self.users[SENTINEL].get(token)
        if row is None or row[0] == 0:
            return
        amount = row[0]
        if not self.hold(SENTINEL, token, amount):
            return
        self.update(SENTINEL, token, 1, amount, price)
        self.fees[token] = self.add_up(self.fees.get(token, 0), amount)

    def user_sweep(self, token, users, price):
        total = 0
        for user in sorted(users):
            row = self.users.setdefault(user, {}).get(token, [0, 0, 0])
            amount = row[0]
            total = self.add_up(total, amount)
            hold = self.add_up(row[1], amount)
            self.take(hold, amount)
            self.users[user].pop(token, None)
        self.update(SENTINEL, token, 0, total, price)


def spec_for(harness, case):
    if case.kind == "tail":
        return dict(result=spec_tail(case.bits))
    model = Model(case.tokens)
    results = []
    for step in case.steps:
        kind = step[0]
        try:
            if kind == "stale":
                results.append(None)
            elif kind == "poke":
                model.poke(*step[1:])
                results.append(None)
            elif kind == "update":
                model.update(*step[1:])
                results.append(None)
            elif kind == "hold":
                results.append(model.hold(*step[1:]))
            elif kind == "release":
                model.release(*step[1:])
                results.append(None)
            elif kind == "fees":
                model.fee_sweep(*step[1:])
                results.append(None)
            else:
                model.user_sweep(step[1], step[2], step[3])
                results.append(None)
        except Panicked:
            results.append("panic")
            break
    return dict(users=model.users, index=model.index, fees=model.fees, events=model.events, results=results)


def spec_tail(bits):
    value = to_float(bits)
    if value != value or value in (math.inf, -math.inf):
        return 0
    if value >= TWO_63:
        return (1 << 63) - 1
    if value <= -TWO_63:
        return 0
    result = int(value)
    return result if result > 0 else 0


def same(case, got, want):
    if case.kind == "tail":
        return got == want
    if got["events"] != want["events"] or got["results"] != want["results"] or got["fees"] != want["fees"]:
        return False
    if set(got["users"]) != set(want["users"]):
        return False
    for user, entry in got["users"].items():
        if entry["head"][4:] != b"\x00" * 0x10 or entry["tail"][:8] != b"\x00" * 8 or entry["tail"][16:] != b"\x00" * 8:
            return False
        if entry["rows"] != {token: tuple(row) for token, row in want["users"][user].items()}:
            return False
    if got["marks"] != bytes([0xC7]) * 0x10 + bytes([0xC7]) * 0x20 or got["tokens_seen"] != TOKEN_COUNT:
        return False
    return got["index"] == {user: sorted(tokens) for user, tokens in want["index"].items() if tokens or user in got["index"]}


VECTORS = 200
MUTANT_VECTORS = 40
REACH_CAP = 12
SECOND_CAP = 40
THIRD_CAP = 300
GRID_NAMES = ("credit t", "debit t", "vector", "norm (", "scale sz")
MUTANT_STEP_LIMIT = 300000
ALICE = user_of(0x11)
BOB = user_of(0x22)
CAROL = user_of(0x33)
GRID = (0, 1, 2, 99, 100, 101, 10 ** 8, 10 ** 12, CAP - 1, CAP, CAP + 1, 1 << 53, (1 << 53) + 1, 1 << 63, TOP - 1, TOP)


def poke(user, token, total=0, hold=0, notional=0, indexed=True):
    return ("poke", user, token, total, hold, notional, indexed)


def credit(user, token, amount, price):
    return ("update", user, token, 0, amount, price)


def debit(user, token, amount, price):
    return ("update", user, token, 1, amount, price)


def credit_cases():
    out = []
    for total in (0, 1, 5000, 10 ** 12, TOP - 3, TOP):
        for amount in (0, 1, 3, 4, 7000, 10 ** 13, TOP):
            for notional in (0, 1, 777, CAP, TOP - 1, TOP):
                for price in (0, 123456, TOP):
                    out.append(Case("credit t %d a %d n %d p %d" % (total, amount, notional, price), steps=(poke(ALICE, 5, total, 9, notional), credit(ALICE, 5, amount, price))))
    for token, sz, wei in ((1, 2, 2), (2, 2, 3), (3, 0, 8), (4, 0, 15), (5, 0, 16), (6, 0, 19), (7, 3, 22), (8, 0, 20), (9, 0, 21), (10, 3, 2), (11, 0, 32), (12, 0, 37), (13, 0, 255), (14, 0, 31)):
        tokens = {token: (sz, wei)}
        for amount in (0, 9, 10 ** 9, 10 ** 12, TOP // 3):
            for price in (1, 987654321, 1 << 33):
                out.append(Case("scale sz %d wei %d a %d p %d" % (sz, wei, amount, price), tokens=tokens, steps=(credit(ALICE, token, amount, price),)))
    return out


def debit_cases():
    out = []
    for total in (0, 1, 1000, (1 << 53) + 1, TOP):
        for amount in (0, 1, 999, total // 2, total - 1 if total else 0, total, total + 1 if total < TOP else TOP):
            for notional in (0, 1000, 12345678901, CAP - 1, CAP, TOP):
                for price in (0, 777777):
                    for hold in (0, amount + 1 if amount < TOP else TOP):
                        out.append(Case("debit t %d a %d n %d p %d h %d" % (total, amount, notional, price, hold), steps=(poke(ALICE, 5, total, hold, notional), debit(ALICE, 5, amount, price))))
    for token in (0, 39):
        for price in (0, 5):
            out.append(Case("debit token %d p %d" % (token, price), steps=(poke(ALICE, token, 100, 7, 50), debit(ALICE, token, 30, price))))
            out.append(Case("credit token %d p %d" % (token, price), steps=(poke(ALICE, token, 100, 7, 50), credit(ALICE, token, 30, price))))
    out.append(Case("credit past the token table", steps=(credit(ALICE, 40, 5, 3),)))
    out.append(Case("debit past the token table", steps=(poke(ALICE, 41, 9), debit(ALICE, 41, 5, 3))))
    out.append(Case("credit past the table with no price", steps=(credit(ALICE, 40, 5, 0),)))
    out.append(Case("sz above wei on debit", tokens={3: (5, 2)}, steps=(poke(ALICE, 3, 9), debit(ALICE, 3, 5, 3))))
    out.append(Case("absent row debit zero", steps=(debit(ALICE, 3, 0, 9),)))
    out.append(Case("absent row debit one", steps=(debit(ALICE, 3, 1, 9),)))
    out.append(Case("row with no index then debit", steps=(poke(ALICE, 3, 9, indexed=False), debit(ALICE, 3, 5, 3))))
    out.append(Case("row with no index then credit", steps=(poke(ALICE, 3, 9, indexed=False), credit(ALICE, 3, 5, 3))))
    return out


def hold_cases():
    out = []
    for total in (0, 1, 100, TOP):
        for hold in (0, 1, 99, 100, TOP - 1, TOP):
            for amount in (0, 1, 100, TOP):
                out.append(Case("hold t %d h %d a %d" % (total, hold, amount), steps=(poke(ALICE, 5, total, hold), ("hold", ALICE, 5, amount))))
    for stale in (5, 4, 6):
        out.append(Case("hold past stale key %d" % stale, steps=(poke(ALICE, 4, 9), ("stale", ALICE, stale), ("hold", ALICE, 5, 3))))
        out.append(Case("release past stale key %d" % stale, steps=(poke(ALICE, 4, 9), ("stale", ALICE, stale), ("release", ALICE, 2, 0, 1, 1))))
        out.append(Case("sweep past stale key %d" % stale, steps=(poke(ALICE, 4, 9), ("stale", ALICE, stale), ("sweep", 5, (ALICE,), 0, 0))))
        out.append(Case("update past stale key %d" % stale, steps=(poke(ALICE, 4, 9), ("stale", ALICE, stale), credit(ALICE, 5, 3, 0))))
    out.append(Case("hold no user", steps=(("hold", ALICE, 5, 3),)))
    out.append(Case("hold no user zero", steps=(("hold", ALICE, 5, 0),)))
    out.append(Case("hold no row", steps=(poke(ALICE, 4, 9), ("hold", ALICE, 5, 3))))
    out.append(Case("hold no row zero", steps=(poke(ALICE, 4, 9), ("hold", ALICE, 5, 0))))
    for token in (39, 40, 41, TOP):
        for amount in (0, 1):
            out.append(Case("hold token %d a %d" % (token, amount), steps=(poke(ALICE, min(token, 39), 9), ("hold", ALICE, token, amount))))
    for spot in (0, 1, 3, 7, 8, 9):
        for side in (0, 1):
            for hold in (0, 5, 6, 7, 1200, TOP):
                for price, size in ((2, 3), (1, 6), (3, 400), (0, 0), (1 << 32, 1 << 32), ((1 << 32) - 1, (1 << 32) + 1), (1, 1 << 60), (1 << 60, 1)):
                    steps = [poke(ALICE, token, 9, hold) for token in spot_row(spot if spot < 8 else 0) if token < TOKEN_COUNT]
                    out.append(Case("release s %d f %d h %d p %d z %d" % (spot, side, hold, price, size), steps=tuple(steps) + (("release", ALICE, spot, side, price, size),)))
    tokens = {3: (5, 2)}
    out.append(Case("release sz above wei", tokens=tokens, steps=(("release", ALICE, 1, 1, 2, 3),)))
    for wei in (19, 20, 22):
        out.append(Case("release wei %d" % wei, tokens={3: (0, wei)}, steps=(("release", ALICE, 1, 1, 2, 3),)))
    out.append(Case("release fresh user", steps=(("release", BOB, 3, 0, 0, 0),)))
    out.append(Case("release fresh user over", steps=(("release", BOB, 3, 1, 1, 1),)))
    out.append(Case("release no row with index", steps=(poke(BOB, 3, 1), ("release", BOB, 0, 0, 1, 0))))
    return out


def sweep_cases():
    out = []
    for total in (0, 1, 500, TOP):
        for hold in (0, 1, total):
            for price in (0, 8):
                for fee in (None, 7, TOP - 3, TOP):
                    steps = [poke(SENTINEL, 5, total, hold, 40)]
                    if fee is not None:
                        steps.insert(0, ("fees", 6, 0))
                        steps.insert(0, poke(SENTINEL, 6, fee))
                        steps.insert(2, poke(SENTINEL, 6, 0))
                        steps.append(("feeseed", 5, fee))
                    out.append((total, hold, price, fee, steps))
    cases = []
    for total, hold, price, fee, steps in out:
        real = [step for step in steps if step[0] != "feeseed"]
        for step in steps:
            if step[0] == "feeseed":
                real[-1:-1] = [poke(SENTINEL, 5, step[2]), ("fees", 5, 0)]
                real.append(poke(SENTINEL, 5, total, hold, 40))
                real = real[:-2] + [real[-2] if False else real[-1]]
        real.append(("fees", 5, price))
        cases.append(Case("fee sweep t %d h %d p %d f %s" % (total, hold, price, fee), steps=tuple(real)))
    cases.append(Case("fee sweep no sentinel", steps=(("fees", 5, 9),)))
    cases.append(Case("fee sweep no row", steps=(poke(SENTINEL, 4, 9), ("fees", 5, 9))))
    cases.append(Case("fee sweep two tokens", steps=(poke(SENTINEL, 4, 9), poke(SENTINEL, 5, 8), poke(SENTINEL, 6, 7), ("fees", 5, 0), ("fees", 4, 0), ("fees", 6, 3))))
    many = tuple(poke(SENTINEL, value, value) for value in range(1, 30, 2))
    for token in (1, 13, 29, 2, 30):
        cases.append(Case("fee sweep deep row %d" % token, steps=many + (("fees", token, 0),)))
    fees = tuple(step for value in range(1, 30, 2) for step in (poke(SENTINEL, value, value), ("fees", value, 0)))
    for token in (1, 13, 29, 2, 30):
        cases.append(Case("fee sweep deep fee tree %d" % token, steps=fees + (poke(SENTINEL, token, 5), ("fees", token, 0))))
    return cases


def user_sweep_cases():
    out = []
    out.append(Case("sweep no users", steps=(("sweep", 5, (), 9, 0),)))
    out.append(Case("sweep no users no price", steps=(("sweep", 5, (), 0, 0),)))
    for total in (0, 1, 500, TOP):
        for hold in (0, 3, TOP):
            for notional in (0, 11):
                for price in (0, 8):
                    out.append(Case("sweep t %d h %d n %d p %d" % (total, hold, notional, price), steps=(poke(ALICE, 5, total, hold, notional), poke(ALICE, 4, 7, 1, 2), ("sweep", 5, (ALICE,), price, 0))))
    out.append(Case("sweep no row", steps=(poke(ALICE, 4, 7), ("sweep", 5, (ALICE,), 0, 0))))
    out.append(Case("sweep no user row", steps=(("sweep", 5, (ALICE,), 0, 0),)))
    out.append(Case("sweep overflow sum", steps=(poke(ALICE, 5, TOP), poke(BOB, 5, 2), poke(CAROL, 5, 9), ("sweep", 5, (ALICE, BOB, CAROL), 0, 0))))
    out.append(Case("sweep onto a sentinel row", steps=(poke(SENTINEL, 5, 50, 4, 30), poke(ALICE, 5, 7), ("sweep", 5, (ALICE,), 2, 0))))
    out.append(Case("sweep the sentinel", steps=(poke(SENTINEL, 5, 50, 4, 30), ("sweep", 5, (SENTINEL,), 2, 0))))
    for count, height in ((3, 0), (11, 0), (12, 1), (17, 1), (29, 1), (12, 2), (17, 3), (12, 4), (12, 7), (17, 8), (12, 9), (12, 15), (12, 16), (12, 17), (2, 5), (3, 8), (4, 9), (5, 10), (6, 11), (2, 12), (3, 16), (2, 17)):
        users = tuple(user_of(index * 3 + 1) for index in range(count))
        out.append(Case("sweep %d users height %d" % (count, height), steps=tuple(poke(user, 5, index + 1) for index, user in enumerate(users)) + (("sweep", 5, users, 0, height),)))
    return out


def shape_cases():
    out = []
    tokens = (3, 7, 12, 1, 39, 20, 21, 22, 23, 24, 25, 26, 27, 28, 2, 4, 5, 6, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18)
    out.append(Case("many tokens one user", steps=tuple(credit(ALICE, token, token * 3 + 1, 0) for token in tokens) + tuple(debit(ALICE, token, token, 0) for token in tokens)))
    users = [user_of(index * 5 + 2) for index in range(40)]
    out.append(Case("many users grow the table", steps=tuple(credit(user, 5, index + 1, 0) for index, user in enumerate(users)) + tuple(debit(user, 5, 1, 2) for user in users)))
    out.append(Case("many holds", steps=tuple(credit(user, 5, 9, 0) for user in users[:20]) + tuple(("hold", user, 5, 4) for user in users[:21]) + tuple(("release", user, 2, 0, 2, 2) for user in users[:22])))
    for count, seed in ((14, 0), (28, 0), (56, 0), (28, 1), (28, 2), (28, 3), (28, 4), (28, 5), (56, 1), (56, 2)):
        crowd = [user_of(index * 3 + 5 + seed) for index in range(count)]
        out.append(Case("%d users at the load limit seed %d" % (count, seed), steps=tuple(credit(user, 5, 9, 0) for user in crowd) + tuple(("hold", user, 5, 4) for user in crowd) + (("hold", user_of(250), 5, 1), ("hold", user_of(251), 5, 1))))
    deep = (3, 7, 12, 1, 39, 20, 21, 22, 23, 24, 25, 26, 27, 28, 2, 4)
    for token in (1, 3, 12, 22, 39, 18):
        out.append(Case("release deep row %d" % token, steps=tuple(credit(ALICE, value, 9, 0) for value in deep) + (("release", ALICE, min(token, 7), 0, 0, 0),)))
        out.append(Case("hold deep row %d" % token, steps=tuple(credit(ALICE, value, 9, 0) for value in deep) + (("hold", ALICE, token, 3),)))
        out.append(Case("sweep deep row %d" % token, steps=tuple(credit(ALICE, value, 9, 0) for value in deep) + (("sweep", token, (ALICE,), 0, 0),)))
        out.append(Case("fee sweep deep sentinel row %d" % token, steps=tuple(credit(SENTINEL, value, 9, 0) for value in deep) + (("fees", token, 0),)))
    twins = [bytes([0x40]) * 16 + bytes([index, 0, 0, 0]) for index in range(14)]
    out.append(Case("users differ in the last word", steps=tuple(credit(user, 6, 3, 0) for user in twins) + tuple(("hold", user, 6, 1) for user in twins)))
    twins = [bytes([index]) + bytes([0x40]) * 19 for index in range(14)]
    out.append(Case("users differ in the first byte", steps=tuple(credit(user, 6, 3, 0) for user in twins) + tuple(("hold", user, 6, 1) for user in twins)))
    return out


def tail_cases():
    words = (0, SIGN_BIT, 1, 0x3FF0000000000000, 0xBFF0000000000000, 0x3FEFFFFFFFFFFFFF, 0x4000000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0xFFF8000000000000, 0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF, 0x43E0000000000000, 0xC3E0000000000000, 0x43DFFFFFFFFFFFFF, 0xC3DFFFFFFFFFFFFF, 0x43E0000000000001, 0xC3E0000000000001, 0x7FF0000000000001, 0xFFF0000000000001, 0x7FEFFFFFFFFFFFFE, 0x4341C37937E08000)
    return [Case("tail %#x" % word, kind="tail", bits=word) for word in words]


def base_cases():
    return credit_cases() + debit_cases() + hold_cases() + sweep_cases() + user_sweep_cases() + shape_cases() + tail_cases()


def lcg(seed):
    state = [seed]

    def next_value(bound):
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state[0] >> 33) % bound
    return next_value


def vector_cases(count):
    out = []
    picks = [user_of(index * 9 + 4) for index in range(5)]
    sizes = (1, 3, 100, 10000, 10 ** 8, 10 ** 12, 10 ** 15, 10 ** 18)
    for index in range(count):
        pick = lcg(index * 2 + 1)
        steps = []
        for _ in range(pick(40) + 10):
            user = picks[pick(5)] if pick(8) else SENTINEL
            token = pick(9)
            amount = (pick(1000) * sizes[pick(8)]) & TOP
            price = (0, 1, 77, 123456, 10 ** 9)[pick(5)]
            what = pick(10)
            if what < 4:
                steps.append(credit(user, token, amount, price))
            elif what < 6:
                steps.append(debit(user, token, amount % 1000000, price))
            elif what < 8:
                steps.append(("hold", user, token, amount % 1000000))
            elif what == 8:
                steps.append(("release", user, pick(9), pick(2), amount % 1000, pick(1000)))
            else:
                steps.append(("fees", token, price))
            if steps[-1][0] == "update" and steps[-1][3] == 1 and pick(4):
                steps[-1:] = [credit(user, token, amount % 1000000, 0), steps[-1]]
        out.append(Case("vector %d" % index, steps=tuple(steps)))
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
    (0x371D529, "condition"): "equivalent: the clamp of an in-range value is that value, and past the low bound the conversion gives a negative word that stores 0",
    (0x371D533, "condition"): "equivalent: past the high bound the unclamped conversion gives the same MAX through the cmova",
    (0x371B1A6, "immediate"): "equivalent: pshufd over a register whose dwords are all equal",
    (0x371B2E1, "immediate"): "table reserve only: it changes when the table grows, not any key or row",
    (0x371B2E1, "displacement"): "table reserve only: it changes when the table grows, not any key or row",
    (0x371B2F6, "immediate"): "table reserve only: a larger reserve argument, no key or row changes",
    (0x371B2FE, "immediate"): "table reserve only: a larger reserve argument, no key or row changes",
    (0x3721886, "immediate"): "equivalent: at this row the height is 0 or above 8 once a remainder of 1 to 7 was taken off",
    (0x3721969, "immediate"): "equivalent: same unrolled step as the row before",
    (0x37218E3, "displacement"): "first leaf only: any nonzero word reads as a leaf that is not empty, and the walk starts at slot 0",
    (0x37217ED, "displacement"): "equivalent: the hold word is written back to a row the next call deletes",
    (0x3721AED, "displacement"): "equivalent: the hold word is written back to a row the next call deletes",
    (0x3721B73, "displacement"): "equivalent: the hold word is written back to a row the next call deletes",
    (0x3721BA3, "displacement"): "equivalent: the hold word is written back to a row the next call deletes",
}
HEIGHT_WORDS = (0x371D39C, 0x371D58D, 0x371B378, 0x372D806, 0x372D8C8, 0x3721563, 0x3721B37)
PROBES = (0x371B238, 0x371B23C)


def survivor_reason(va, kind):
    if va in HEIGHT_WORDS:
        return "equivalent: height word of a leaf handle, read only when a node splits to the root"
    if va in PROBES:
        return "not killed: a probe step of 17 still reaches the key or an empty byte in these tables"
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
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is None:
                hit = first_failure(harness, spread([case for case in reach[va] if not case.name.startswith(GRID_NAMES)], THIRD_CAP))
            results.append((va, kind, "killed", hit.name) if hit is not None else (va, kind, "survived", survivor_reason(va, kind)))
    return results


REFERENCE = (
    ("credit of available", "credit_saturating raises total and available", "credit raises total only; the second word is the order hold, and only try_hold raises it", "credit t 5000 a 7000 n 777 p 123456"),
    ("notional on debit", "u128 notional*new/old, floor, min u64::MAX; integer path", "f64: trunc(f64(n)*(f64(new)/f64(old))); n at or above 0x28f5c28f5c28f5c stays unchanged", "debit t 1000 a 999 n 12345678901 p 777777 h 0"),
    ("zero notional on debit", "stays 0", "the remaining balance is valued with the call's price and stored", "debit t 1000 a 1 n 0 p 777777 h 0"),
    ("notional on credit", "credit leaves notional alone", "adds the value of the amount, or of the whole new balance when notional was 0; an overflowing add is dropped", "credit t 5000 a 7000 n 0 p 123456"),
    ("gate", "update_notional bool and token != USDC", "a price word; price 0 or token 0 skips the notional step, the price is not a bool", "debit t 1000 a 999 n 1000 p 0 h 0"),
    ("user index", "user_token_index updated for every entry_mut", "only a credit or a hold release indexes the token; a debit or try_hold on a fresh row does not", "absent row debit zero"),
    ("sweep", "row.total = 0, credit the sentinel", "the row is deleted from the user tree, so hold and notional go with it; the index row stays", "sweep t 500 h 3 n 11 p 8"),
    ("sweep of an empty set", "not stated", "the sentinel still gets a credit of 0, which creates its row and index entry", "sweep no users"),
)


RELATIONS = (
    ("table", "user_states hash table of the spot struct", "+0x298", "ctrl pointer, +0x2a0 mask, +0x2a8 growth left, +0x2b0 items, +0x2b8 hasher"),
    ("entry", "bucket size 0x58", "0x58", "key 20 bytes, value at +0x18, row tree root +0x28, height +0x30, length +0x38"),
    ("row tree node", "u64 token to 0x18 byte row", "0x170 leaf", "keys +8, rows +0x60, parent index +0x168, length +0x16a, edges +0x170"),
    ("row", "three u64 words", "0x18", "+0 total, +8 hold, +0x10 entry notional"),
    ("fees", "token_fees_collected", "+0x3a0", "tree of u64 to u64: keys +8, values +0x60, length +0xba, edges +0xc0"),
    ("index", "user to token set", "+0x400", "keys +0x110 stride 0x14, sets +8 stride 0x18, length +0x1ee, edges +0x1f0"),
    ("swept users", "user map passed to user_sweep", "argument", "keys +0x60 stride 0x14, values +8 unread, length +0x13e, edges +0x140"),
)


def call_rows(image):
    """Every direct call of the update, and every slot call of the family, classed from fixed bytes before the call."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text) and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == UPDATE:
            site = base + at
            try:
                host = image.fde(site)[0]
            except EvidenceError:
                host = None
            if host is not None:
                window = text[max(0, at - 24):at].replace(b"\x45\x31\xc9", b"\x90\x90\x90")
                one, zero = window.rfind(b"\xb9\x01\x00\x00\x00"), window.rfind(b"\x31\xc9")
                direction = "debit" if one > zero else "credit" if zero >= 0 else "?"
                price = "none" if text[at - 3:at] == b"\x45\x31\xc9" else "value"
                token = "0" if window.rfind(b"\x31\xd2") >= 0 and window.rfind(b"\x31\xd2") >= len(window) - 16 else "value"
                rows.append(("%#x" % host, "%#x" % site, direction, token, price))
        at = text.find(b"\xe8", at + 1)
    return rows


def call_summary(rows):
    counts = collections.Counter((row[2], row[3], row[4]) for row in rows)
    return [(direction, token, price, count) for (direction, token, price), count in sorted(counts.items())]


def slot_callers(image):
    base, text = image.text_bytes()
    wanted = {SLOT_TRY_HOLD: "try_hold", SLOT_RELEASE: "release_hold", SLOT_USER_SWEEP: "user_sweep", SLOT_FEE_SWEEP: "fee_sweep"}
    rows = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
        if slot in wanted:
            try:
                rows.append((wanted[slot], "%#x" % (base + at), "%#x" % image.fde(base + at)[0]))
            except EvidenceError:
                pass
        at = text.find(b"\xff\x15", at + 1)
    return rows


def slot_rows(image):
    relative = image.relative()
    return [("%#x" % slot, "%#x" % relative.get(slot, 0), meaning) for slot, meaning in ((SLOT_TRY_HOLD, "try_hold, real"), (SLOT_RELEASE, "release_hold, real"), (SLOT_USER_SWEEP, "user_sweep, real"), (SLOT_FEE_SWEEP, "fee_sweep, real"), (SLOT_RESOLVE, "hold amount resolver, real"), (SLOT_RECORD, "overflow recorder, hook"), (0x5773788, "table reserve, real"))]


KEY_PINS = ((0x3721DC7, b"user_states"), (0x3721F37, b"token_fees_collected"), (0x2A3B552, b"entryNtl"))
OFFSET_PINS = ((0x3721F2F, 7, "lea of token_fees_collected", 0x3A0), (0x371D13F, 7, "user table", 0x298), (0x371D283, 7, "index tree", 0x400), (0x37214A5, 7, "fee tree height", 0x3A8), (0x2A3B54E, 4, "entryNtl field of the info row", 0x78))


def key_rows(image):
    rows = []
    for site, text in KEY_PINS:
        data = bytes(image.blob[image.offset(site):image.offset(site) + 7])
        if data[:3] != b"\x48\x8d\x35":
            raise EvidenceError("key pin at %#x" % site)
        where = site + 7 + struct.unpack_from("<i", data, 3)[0]
        found = bytes(image.blob[where:where + len(text)])
        if found != text:
            raise EvidenceError("key text at %#x" % site)
        rows.append(("%#x" % site, "%#x" % where, found.decode()))
    return rows


def constant_rows(image):
    rows = []
    for address, meaning in ((0x20ACB8, "low clamp"), (0x20A7F0, "high clamp"), (0x20A2C8, "bound of the MAX cmova")):
        rows.append(("%#x" % address, bytes(image.blob[address:address + 8]).hex(), repr(struct.unpack_from("<d", image.blob, address)[0]), meaning))
    data = bytes(image.blob[image.offset(0x371D486):image.offset(0x371D486) + 10])
    if data[:2] != b"\x48\xb9" or struct.unpack_from("<Q", data, 2)[0] != CAP:
        raise EvidenceError("cap immediate")
    rows.append(("0x371d486", data.hex(), "%#x" % CAP, "notional kept at or above this word"))
    data = bytes(image.blob[0x203CC0:0x203CD0])
    if data != SENTINEL[:16]:
        raise EvidenceError("sentinel bytes")
    rows.append(("0x203cc0", data.hex(), "0xee x 16, then the dword 0xeeeeeeee", "sentinel user"))
    return rows


def tail_rows(cases, outcomes):
    return [(case.name, "%#x" % got["result"]) for case, got in zip(cases, outcomes) if case.kind == "tail"]


def outcome_row(case, got):
    digest = hashlib.sha256(repr(sorted(got.items(), key=str)).encode()).hexdigest()[:16]
    if case.kind == "tail":
        return ("tail", case.name, "%#x" % got["result"], digest)
    label = "panic" if "panic" in got["events"] else "ok"
    return ("steps", case.name, label, digest)


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
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in SUBJECTS}
    calls = call_rows(image)
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, slots=slot_rows(image), constants=constant_rows(image), keys=key_rows(image), calls=calls, summary=call_summary(calls), slot_calls=slot_callers(image), tails=tail_rows(cases, outcomes))
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
    tsv("layouts.tsv", ("name", "meaning", "offset or size", "fields"), RELATIONS)
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("update-calls.tsv", ("function", "call", "direction", "token", "price"), result["calls"])
    tsv("update-call-summary.tsv", ("direction", "token", "price", "calls"), result["summary"])
    tsv("slot-calls.tsv", ("callee", "call", "function"), result["slot_calls"])
    tsv("tail-edges.tsv", ("case", "stored"), result["tails"])
    tsv("field-keys.tsv", ("site", "text_at", "key"), result["keys"])
    tsv("slots.tsv", ("slot", "target", "meaning"), result["slots"])
    tsv("outcomes.tsv", ("kind", "case", "result", "digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in SUBJECTS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "update_calls": len(result["calls"]), "slot_calls": len(result["slot_calls"]),
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

