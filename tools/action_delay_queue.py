#!/usr/bin/env python3
"""Pin the node #94 action delay queue: delay curve, enqueue host, window gate, release, wipe and the delayer votes.

Real rows run from the enqueue wrappers, the host, the curve, the release function and the vote dispatchers, with the real
B-tree code, time add, parser and fold. A separately written rule list predicts every result, tree row and field, and every
reached conditional row, immediate and field offset of the subject code is edited. No objdump or readelf output is parsed
and the binary is never executed. Standard library only.

    python3 tools/action_delay_queue.py --out <dir>
"""

import argparse
import datetime
import fractions
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
TAG_TEXTS = {0x13A: "Exceeded max number of delayed actions.", 0x13B: "Exceeded max number of delayed actions for user.", 0xCA: "Action already expired", 0x13C: "Invalid max number delayed actions.",
             0x13F: "Invalid input number", 0x140: "Invalid input", 0x143: "Invalid input length", 0x8D: "Action only allowed on testnet"}
TAG_TOTAL, TAG_USER, TAG_EXPIRED, TAG_MAX, TAG_NUMBER, TAG_INPUT, TAG_LENGTH, TAG_TESTNET = 0x13A, 0x13B, 0xCA, 0x13C, 0x13F, 0x140, 0x143, 0x8D
TAG_FLOAT = 0xAB
TAG_PARSE = 0xAC
RESUME = 0x5660110
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_FMA = 0x576F6E0
SLOT_WEIGHT = 0x57739C0
SLOT_FLAG = 0x57732E0
SLOT_TICK = 0x576F488
SLOT_NOTIFY = 0x5776688
CLASS_SLOTS = (0x5775C30, 0x5775C38, 0x5775C40, 0x5775C48)
CLASS_WORDS = {0x5775C30: 0x74 + 14, 0x5775C38: 0x74 + 35, 0x5775C40: 0x74 + 2, 0x5775C48: 0x74 + 12}
WORD_PLAIN, WORD_FOUR, WORD_NEST, WORD_LOW = 0x74, 0x74 + 43, 0x74 + 52, 0x10
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150, 0x576E048)
MARK_BASE = 0x7700000000
PARSE = 0x3799510
FLOAT = 0x4EAD680
CLONE = 0x39FE700
ACTION_DROP = 0x3BBBA10
ERROR_DROP = 0x3999770
CAP = 0x0CCCCCCCCCCCCCCC
TOP = MASK[8]
TEXT_CAP = 100
DELAYER = 0x31B8
CHAIN = 0x8F2
KNOBS = 0x3660
RECORD = 0x148
USER_CAP = 99
MAX_LOW, MAX_HIGH = 100, 300000
SCALE_MAX = 2.0
DEFAULT_DELAY = 0.2
MISS = 0.001
SCRATCH = HEAP_BASE + 0x1000
STATE = HEAP_BASE + 0x2000
STATE_SIZE = 0x4800
OUT = HEAP_BASE + 0x40
ACTION = HEAP_BASE + 0xC0
INNER = HEAP_BASE + 0x130
USER = HEAP_BASE + 0x160
HASH = HEAP_BASE + 0x180
NOW_AT = HEAP_BASE + 0x1B0
ROW = STATE + STATE_SIZE
BUMP = ROW + 0x80
BUMP_END = HEAP_BASE + HEAP_SIZE
FILL_END = BUMP - HEAP_BASE
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))
ARG_AT = STACK_TOP - 0x100


AccessError = (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError)


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at):
        self.key_at, self.key_size, self.val_at, self.val_size, self.parent_at, self.index_at, self.len_at, self.edge_at = key_at, key_size, val_at, val_size, parent_at, index_at, len_at, edge_at
        self.leaf, self.inner = edge_at, edge_at + 96


SET_TREE = Layout(8, 4, 8, 0, 0, 0x34, 0x36, 0x38)
WINDOW_TREE = Layout(0x60, 4, 8, 8, 0, 0x8C, 0x8E, 0x90)
USER_TREE = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)
VTY_TREE = Layout(0x588, 4, 0x60, 8, 0x580, 0x5B4, 0x5B6, 0x5B8)
QUEUE_TREE = Layout(0x110, 12, 8, 24, 0, 0x194, 0x196, 0x198)


class Wrap:
    def __init__(self, name, entry, shift, run_now, row):
        self.name, self.entry, self.shift, self.run_now, self.row = name, entry, shift, run_now, row


class Copy:
    def __init__(self, name, dispatch, table, shift):
        self.name, self.dispatch, self.table, self.shift = name, dispatch, table, shift


WRAPS = (Wrap("a", 0x27584A0, 0, 0x2759240, 0x1F849B0), Wrap("b", 0x4D81290, 0xA80, 0x4D83050, 0x47D7CA0), Wrap("c", 0x4D81660, 0, 0x4D84170, 0x47D7CA0))
COPIES = (Copy("a", 0x2355F40, 0x3DD1B8, 0), Copy("b", 0x4CAA870, 0x711064, 0), Copy("c", 0x4CB3200, 0x711244, 0xA80))
CURVE, GATE, HOST, RELEASE, CLASSIFY = 0x392FAB0, 0x392D140, 0x392C200, 0x392CE80, 0x3362E60
WIPE_START, WIPE_END = 0x2208481, 0x220853E
FUNCTIONS = dict(curve=CURVE, window_gate=GATE, queue_host=HOST, release=RELEASE, classify=CLASSIFY, enqueue_a=WRAPS[0].entry)
ARM_WINDOWS = (("word_79", 0x23583BE, 0x2358407), ("word_79_store", 0x235B77C, 0x235B788), ("word_104", 0x2358EAD, 0x2358ECB), ("word_104_clear", 0x2359DEF, 0x2359E15),
               ("word_106", 0x23562E0, 0x2356317), ("word_106_tail", 0x2359957, 0x23599B1), ("word_108", 0x235954B, 0x235972A), ("word_108_gate", 0x235DD56, 0x235DD8C), ("wipe_tail", WIPE_START, WIPE_END))
WORD_MAX, WORD_CLEAR, WORD_SCALE, WORD_BOUNDS = 79, 104, 106, 108
STEMS = {0x74, 0x75}
DATE_FLAGS = 0xA
YEAR = 2026
UNIX_DAY = 719163


def packed_date(ordinal, year=YEAR):
    return (year << 13 | ordinal << 4 | DATE_FLAGS) & MASK[4]


NOW = (packed_date(100), 45000, 250000000)
USER_A = bytes(range(1, 21))
USER_B = bytes(range(0x21, 0x35))
USER_C = bytes(range(0x41, 0x55))
HASH_BYTES = bytes(range(0x90, 0xB0))


def fma(x, y, z):
    values = (x, y, z)
    if any(value != value or value in (float("inf"), -float("inf")) for value in values):
        return x * y + z
    exact = fractions.Fraction(x) * fractions.Fraction(y) + fractions.Fraction(z)
    if exact == 0:
        return x * y + z
    try:
        return float(exact)
    except OverflowError:
        return float("inf") if exact > 0 else -float("inf")


def days_of(date):
    year = (date - (1 << 32) if date >> 31 else date) >> 13
    last = year - 1
    return ((date >> 4) & 0x1FF) + last * 365 + last // 4 - last // 100 + last // 400


def time_nanos(time):
    date, seconds, nanos = time
    days = days_of(date) - UNIX_DAY
    return (days * 86400 + seconds) * 10 ** 9 + nanos


def window_seconds(time):
    return max(0, time_nanos(time) // 10 ** 9)


def clamp_weight(weight):
    finite = abs(weight) <= sys.float_info.max
    value = weight
    if finite:
        value = 0.0 if 0.0 > weight else weight
        if value > 1.0:
            return 1.0
    if not value >= 0.0:
        raise Panicked("negative weight")
    return value


def curve(mode, kind, vty):
    special = None
    if mode >= 2:
        if mode == 2:
            if kind in (3, 4, 11054, 11137):
                special = 0.125 * fma(vty, 10000.0, -1.5)
            elif kind == 0:
                special = fma(vty, 10000.0, -3.0) / 12.0
        elif kind in (0, 1, 10142, 10151):
            special = 0.125 * fma(vty, 10000.0, -1.5)
        elif kind == 5:
            special = fma(vty, 10000.0, -3.0) / 12.0
    if special is not None:
        return (clamp_weight(special) * 1.8 + 0.76) * 0.65
    base = clamp_weight(fma(vty, 10000.0, -4.0) / 20.0) * 1.3 + 0.76
    if kind >= 100000000 or 10000 <= kind < 110000:
        return base * 0.2
    return base * 0.65


def fold(mode, keys, vty, start):
    best = start
    for key in keys:
        value = curve(mode, key, vty[key]) if key in vty else MISS
        if value != value or best != best:
            raise Panicked("unordered compare")
        if value >= best:
            best = value
    return best


def first_of(mode, keys, vty):
    key = keys[0]
    return curve(mode, key, vty[key]) if key in vty else MISS


def spec_window(windows, keys, seconds):
    """True when every id with a width sits in an odd window; None windows means the gate is off."""
    if windows is None:
        return False
    for key in keys:
        if key in windows:
            width = windows[key]
            if width == 0 or seconds // width & 1 == 0:
                return False
    return True


def add_seconds(nanos, delay):
    scaled = delay * 1e9
    if scaled != scaled or scaled in (float("inf"), -float("inf")):
        return nanos
    return nanos + int(min(scaled, 9223372036854775807.0)) if scaled < 9223372036854775807.0 else nanos + 9223372036854775807


class Case:
    DEFAULTS = dict(steps=(), wrap=0, copy=None, chain=3, now=NOW, knobs=(0.01, 1.0, 0.001), windows=None, vty=(), users=(), n_total=0, max_n=1000, scale=1.0, flag=0, sopt=(0, 0), stamp=7, row=(5, TOP - 1), height=0, deep=False)

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


HOOKED = {CLONE, ACTION_DROP, ERROR_DROP} | {wrap.run_now for wrap in WRAPS} | {wrap.row for wrap in WRAPS}


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_FMA, self.on_fma), (SLOT_WEIGHT, self.on_weight), (SLOT_FLAG, self.on_flag), (SLOT_TICK, self.on_tick), (SLOT_NOTIFY, self.on_notify))
        hooks += tuple((slot, self.classifier(slot)) for slot in CLASS_SLOTS)
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
        machine.calls = {RESUME: self.on_panic, CLONE: self.on_clone, ACTION_DROP: self.on_action_drop, ERROR_DROP: self.on_error_drop}
        for wrap in WRAPS:
            machine.calls[wrap.run_now] = self.on_run_now
            machine.calls[wrap.row] = self.on_row
        self.case = None
        self.live = {}
        self.inputs = set()
        self.cur = BUMP
        self.events = []
        self.sets = []
        self.action = None
        self.result = None
        self.drops = 0
        self.ticks = 0
        self.shift = 0

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

    def on_fma(self, machine):
        low = [to_float(machine.xmm[index] & MASK[8]) for index in range(3)]
        machine.xmm_result = to_bits(fma(*low))

    def on_weight(self, machine):
        self.expect(machine.regs[RDI] == ACTION, "weight of the action")
        machine.regs[RAX] = self.action["weight"]

    def on_flag(self, machine):
        self.expect(machine.regs[RDI] == ACTION, "flag of the action")
        machine.regs[RAX] = 0xABCDEF5A

    def on_tick(self, machine):
        self.ticks += 1

    def classifier(self, slot):
        def hook(machine):
            action = self.action
            self.expect(machine.regs[RSI] == action["payload"], "classifier payload")
            self.expect(self.class_slot == slot, "classifier arm")
            knobs = self.case.knobs
            self.expect(machine.memory.bytes_at(machine.regs[RDX], 24) == struct.pack("<3d", *knobs), "classifier knobs")
            at = machine.regs[RDI]
            memory = machine.memory
            if action["error"]:
                memory.put_bytes(at, struct.pack("<H", 0x77) + b"\x5e" * 0x5E)
                return
            memory.write(at, 2, OK)
            memory.write(at + 8, 8, to_bits(action["base"]))
            memory.put_bytes(at + 0x10, struct.pack("<3Q", *self.sets_built[0]))
            memory.put_bytes(at + 0x28, struct.pack("<3Q", *self.sets_built[1]))
            machine.regs[RAX] = at
        return hook

    def on_clone(self, machine):
        self.expect(machine.regs[RSI] == ACTION, "clone of the action")
        machine.memory.put_bytes(machine.regs[RDI], b"\xc3" * 0xF0)

    def on_action_drop(self, machine):
        self.drops += 1

    def on_error_drop(self, machine):
        self.expect(machine.memory.read(machine.regs[RDI], 2) == 0x77, "drop of the classifier error")
        self.events.append(("error dropped",))

    def on_run_now(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE and regs[RDX] & MASK[1] == 0 and regs[R8] == ACTION and regs[R9] == USER and regs[RCX] & 0xFF == 0x5A, "run now arguments")
        self.events.append(("run", memory.read(STATE + 0x50, 8), memory.read(STATE + 0x78, 1)))
        memory.write(regs[RDI], 1, 0x33)
        regs[RAX] = regs[RDI]

    def on_notify(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STATE + 0x5B8 and regs[RSI] == USER and regs[RCX] == HASH + 1 and regs[R8] == ACTION, "notify arguments")
        self.events.append(("notify", regs[RDX], machine.memory.read(STATE + 0x78, 1)))

    def on_row(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE + 0x740 + self.shift and memory.bytes_at(regs[RSI], 20) == self.action["user"], "row key")
        regs[RAX] = ROW

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

    def walk(self, layout, root, height):
        memory = self.machine.memory
        rows = []

        def visit(node, level):
            count = memory.read(node + layout.len_at, 2)
            self.expect(count <= 11, "node length")
            for slot in range(count + 1):
                if level:
                    visit(memory.read(node + layout.edge_at + 8 * slot, 8), level - 1)
                if slot < count:
                    rows.append((memory.bytes_at(node + layout.key_at + layout.key_size * slot, layout.key_size), node + layout.val_at + layout.val_size * slot))
        if root:
            visit(root, height)
        return rows

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

    def field(self, offset):
        return STATE + DELAYER + self.shift + offset

    def put_tree(self, at, layout, items, height=0):
        root, level = self.tree_bytes(layout, items, height) if items else (0, 0)
        self.machine.memory.put_bytes(at, struct.pack("<3Q", root, level, len(items)))

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.live = {}
        self.inputs = set()
        self.cur = BUMP
        self.events = []
        self.sets = []
        self.drops = 0
        self.ticks = 0
        self.shift = WRAPS[case.wrap].shift if case.copy is None else COPIES[case.copy].shift
        memory.write(STATE + CHAIN + self.shift, 1, case.chain)
        memory.put_bytes(STATE + KNOBS + self.shift, struct.pack("<3d", *case.knobs))
        memory.put_bytes(STATE + 0x60, struct.pack("<3I", *case.now))
        memory.write(STATE, 1, case.sopt[0])
        memory.write(STATE + 8, 8, case.sopt[1])
        memory.write(STATE + 0x28, 8, case.stamp)
        memory.write(STATE + 0x50, 8, 3)
        memory.write(STATE + 0x78, 1, 0)
        memory.write(self.field(0), 8, 0 if case.windows is None else 1)
        self.put_tree(self.field(8), WINDOW_TREE, [(struct.pack("<I", key), value) for key, value in sorted(dict(case.windows or ()).items())], case.height)
        memory.put_bytes(self.field(0x30), struct.pack("<3Q", 0, 0, 0))
        self.put_tree(self.field(0x48), USER_TREE, sorted(case.users))
        memory.write(self.field(0x60), 8, case.n_total)
        memory.write(self.field(0x68), 8, case.max_n)
        self.vty_tree()
        memory.write(self.field(0x88), 8, to_bits(case.scale))
        memory.put_bytes(ROW, struct.pack("<2Q", *case.row))
        self.window_root = memory.read(self.field(8), 8)
        self.fixed = set(self.live)

    def vty_tree(self):
        items = sorted(self.case.vty)
        memory = self.machine.memory
        if not items:
            memory.put_bytes(self.field(0x70), struct.pack("<3Q", 0, 0, 0))
            return
        layout = VTY_TREE
        at = self.bump(layout.leaf)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(layout.leaf)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            memory.write(at + layout.key_at + 4 * slot, 4, 0xFEFEFEFE)
        for slot, (key, bits) in enumerate(items):
            memory.write(at + layout.key_at + 4 * slot, 4, key)
            memory.write(at + 0x80 * slot + 0x68, 8, bits)
        if self.case.deep:
            middle = len(items) // 2
            memory.write(at + layout.len_at, 2, middle)
            other = self.bump(layout.leaf)
            top = self.bump(layout.inner)
            memory.put_bytes(other, bytes(layout.leaf))
            memory.put_bytes(top, bytes(layout.inner))
            for node in (other, top):
                for slot in range(11):
                    memory.write(node + layout.key_at + 4 * slot, 4, 0xFEFEFEFE)
            memory.write(other + layout.len_at, 2, len(items) - middle - 1)
            for slot, (key, bits) in enumerate(items[middle + 1:]):
                memory.write(other + layout.key_at + 4 * slot, 4, key)
                memory.write(other + 0x80 * slot + 0x68, 8, bits)
            memory.write(top + layout.len_at, 2, 1)
            memory.write(top + layout.key_at, 4, items[middle][0])
            memory.write(top + 0x68, 8, items[middle][1])
            for slot, kid in enumerate((at, other)):
                memory.write(top + layout.edge_at + 8 * slot, 8, kid)
                memory.write(kid + layout.parent_at, 8, top)
                memory.write(kid + layout.index_at, 2, slot)
            memory.put_bytes(self.field(0x70), struct.pack("<3Q", top, 1, len(items)))
            return
        memory.put_bytes(self.field(0x70), struct.pack("<3Q", at, 0, len(items)))

    def action_at(self, word, step):
        """Write the action word; the arm read from the classifier table picks the hook."""
        memory = self.machine.memory
        kind = step.get("kind", "plain")
        self.class_slot = None
        memory.put_bytes(ACTION, b"\xd1" * 0x40)
        memory.write(ACTION + 0x20, 8, INNER)
        if kind == "plain":
            memory.write(ACTION, 8, WORD_PLAIN)
        elif kind == "four":
            memory.write(ACTION, 8, WORD_FOUR)
        elif kind == "low":
            memory.write(ACTION, 8, WORD_LOW)
        else:
            self.class_slot = CLASS_SLOTS[step.get("arm", 0)]
            top = CLASS_WORDS[self.class_slot]
            if kind == "nest":
                memory.write(ACTION, 8, WORD_NEST)
                memory.write(INNER, 8, top)
                self.action["payload"] = INNER + 8
            else:
                memory.write(ACTION, 8, top)
                self.action["payload"] = ACTION + 8

    def enqueue(self, step):
        memory = self.machine.memory
        wrap = WRAPS[self.case.wrap]
        self.action = dict(step)
        self.action.setdefault("base", 0.0)
        self.action.setdefault("error", False)
        self.action.setdefault("weight", 3)
        self.action.setdefault("user", USER_A)
        self.sets_built = []
        for side in ("set1", "set2"):
            items = [(struct.pack("<I", key), 0) for key in sorted(step.get(side, ()))]
            root, level = self.tree_bytes(SET_TREE, items, 0) if items else (0, 0)
            self.sets_built.append((root, level, len(items)))
            self.sets.append(root)
        self.action_at(0, step)
        memory.put_bytes(USER, self.action["user"])
        memory.write(HASH, 1, self.case.flag)
        memory.put_bytes(HASH + 1, HASH_BYTES)
        expires = step.get("expires")
        memory.put_bytes(OUT, b"\x77" * 0x68)
        memory.write(ARG_AT, 8, expires or 0)
        memory.write(ARG_AT + 8, 8, HASH)
        self.machine.run(wrap.entry, {RDI: OUT, RSI: STATE, RDX: USER, RCX: ACTION, R8: step.get("byte", 0) | 0x7700, R9: 1 if expires is not None else 0})
        for root in self.sets:
            self.expect(root == 0 or root not in self.live, "set node freed")
        code = memory.read(OUT, 1)
        if code == 0x0C:
            return ("queued", memory.read(OUT + 8, 8), memory.read(OUT + 0x10, 8), time_nanos(struct.unpack("<3I", memory.bytes_at(OUT + 0x18, 12))))
        if code == 0x33:
            return ("ran",)
        self.expect(code == 0x0E, "outer code")
        return ("refused", memory.read(OUT + 8, 2))

    def release(self, step):
        memory = self.machine.memory
        memory.put_bytes(NOW_AT, struct.pack("<3I", *step[1]))
        memory.put_bytes(OUT, b"\x77" * 0x18)
        self.machine.run(RELEASE, {RDI: OUT, RSI: self.field(0), RDX: NOW_AT})
        cap, at, size = struct.unpack("<3Q", memory.bytes_at(OUT, 24))
        rows = [self.record(at + index * RECORD) for index in range(size)]
        if cap:
            self.expect(self.live.pop(at, None) == cap * RECORD, "output vector block")
        else:
            self.expect(size == 0, "empty output")
        return ("released", tuple(rows))

    def record(self, at):
        memory = self.machine.memory
        self.expect(memory.bytes_at(at + 0x10, 0xF0) == b"\xc3" * 0xF0, "cloned action in the record")
        return (memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 0x100, 8), memory.read(at + 0x108, 8), memory.bytes_at(at + 0x110, 20), memory.read(at + 0x124, 1) & 1, memory.read(at + 0x125, 1), memory.bytes_at(at + 0x126, 32))

    def wipe(self, step):
        machine = self.machine
        machine.frame = 0x100
        machine.stop = WIPE_END
        try:
            machine.run(WIPE_START, {RBX: STATE})
        finally:
            machine.frame = 0
            machine.stop = None
        self.expect(not set(self.live) - self.fixed, "wipe frees every queue block")
        return ("wiped",)

    def rename(self, step):
        memory = self.machine.memory
        root, height, _ = struct.unpack("<3Q", memory.bytes_at(self.field(0x48), 24))
        self.expect(height == 0 and memory.bytes_at(root + 0x60, 20) == step[1], "rename row")
        memory.put_bytes(root + 0x60, step[2])
        return ("renamed",)

    def error_view(self):
        memory = self.machine.memory
        tag = memory.read(OUT, 2)
        if tag == OK:
            return ("ok",)
        if tag == TAG_NUMBER and self.number_payload:
            return ("error", tag, memory.read(OUT + 8, 8))
        return ("error", tag)

    def vote(self, step):
        memory = self.machine.memory
        copy = COPIES[self.case.copy]
        word = step[1]
        memory.put_bytes(ACTION, b"\xd1" * 0x60)
        memory.write(ACTION, 8, word)
        self.number_payload = word == WORD_MAX
        if word == WORD_MAX:
            memory.write(ACTION + 8, 8, step[2])
        elif word == WORD_SCALE:
            memory.put_bytes(ACTION + 8, self.string(step[2]))
        elif word == WORD_BOUNDS:
            memory.put_bytes(ACTION + 8, self.string(step[2]) + self.string(step[3]) + self.string(step[4]))
        memory.put_bytes(OUT, b"\x77" * 0x60)
        self.machine.run(copy.dispatch, {RDI: OUT, RSI: ACTION, RDX: STATE})
        return self.error_view()

    def curve_step(self, step):
        _, mode, kind, bits = step
        self.machine.run(CURVE, {RDI: mode | 0x5500, RSI: kind | 0x77 << 32, 0x100: 0} if False else {RDI: mode | 0x5500, RSI: kind | 0x77 << 32})
        return ("value", self.machine.xmm[0] & MASK[8])

    def step(self, step):
        kind = step[0]
        if kind == "curve":
            self.machine.xmm[0] = step[3] | 0xFFFF << 64
            return self.curve_step(step)
        if kind == "enq":
            return self.enqueue(step[1])
        if kind == "rel":
            return self.release(step)
        if kind == "wipe":
            return self.wipe(step)
        if kind == "rename":
            return self.rename(step)
        return self.vote(step)

    def view(self, before):
        memory = self.machine.memory
        state = {}
        now = bytearray(memory.heap[:FILL_END])
        for at, size in ((OUT, 0x68), (ACTION, 0x60), (INNER, 0x20), (USER, 20), (HASH, 33), (NOW_AT, 12)):
            now[at - HEAP_BASE:at - HEAP_BASE + size] = before[at - HEAP_BASE:at - HEAP_BASE + size]
        for at, size, name in ((self.field(0), 8, "window flag"), (self.field(0x60), 8, "total"), (self.field(0x68), 8, "max"), (self.field(0x88), 8, "scale"), (STATE + 0x50, 8, "s50"), (STATE + 0x78, 1, "s78"), (ROW + 8, 8, "row"), (ROW + 0x30, 8, "row time"), (ROW + 0x38, 4, "row time tail"),
                               (STATE + KNOBS + self.shift, 8, "low"), (STATE + KNOBS + self.shift + 8, 8, "high"), (STATE + KNOBS + self.shift + 16, 8, "step")):
            state[name] = memory.read(at, size)
            now[at - HEAP_BASE:at - HEAP_BASE + size] = before[at - HEAP_BASE:at - HEAP_BASE + size]
        for offset in (8, 0x30, 0x48):
            at = self.field(offset)
            now[at - HEAP_BASE:at - HEAP_BASE + 24] = before[at - HEAP_BASE:at - HEAP_BASE + 24]
        root, height, count = struct.unpack("<3Q", memory.bytes_at(self.field(0x48), 24))
        users = {key: memory.read(at, 8) for key, at in self.walk(USER_TREE, root, height)}
        self.expect(len(users) == count, "user count")
        state["users"] = users
        root, height, count = struct.unpack("<3Q", memory.bytes_at(self.field(0x30), 24))
        queue = []
        for key, at in self.walk(QUEUE_TREE, root, height):
            cap, base, size = struct.unpack("<3Q", memory.bytes_at(at, 24))
            self.expect(self.live.get(base) == cap * RECORD, "queue vector block")
            queue.append((time_nanos(struct.unpack("<3I", key)), [self.record(base + index * RECORD) for index in range(size)]))
        self.expect(len(queue) == count, "queue count")
        state["queue"] = queue
        state["windows"] = memory.read(self.field(0x18), 8)
        state["window live"] = self.window_root in self.live
        state["events"] = list(self.events)
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
        return dict(results=results, state=state, rest=rest, kept=len(self.inputs) if results[-1] != ("panic",) else 0, ticks=self.ticks)


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


def spec_enqueue(case, step, want):
    shift = WRAPS[case.wrap].shift
    user = step.get("user", USER_A)
    kind = step.get("kind", "plain")
    base = DEFAULT_DELAY if step.get("error") else step.get("base", 0.0) if kind not in ("plain", "low", "four") else 4.0 if kind == "four" else 0.0
    set1, set2 = sorted(step.get("set1", ())), sorted(step.get("set2", ()))
    if kind in ("plain", "low", "four") or step.get("error"):
        set1, set2 = [], []
    vty = {key: to_float(bits) for key, bits in case.vty}
    mode = case.chain
    now_nanos = time_nanos(case.now)

    def run_now():
        if case.flag == 1:
            want["events"].append(("run", want["s50"], 0))
        else:
            want["s50"] = min(want["s50"] + 1, TOP)
            want["events"].append(("run", want["s50"], 1))
            if case.wrap == 1:
                want["events"].append(("notify", want["s50"], 0))
        return ("ran",)

    if case.flag & 1:
        if step.get("error"):
            want["events"].append(("error dropped",))
            return run_now()
        if spec_window(None if case.windows is None else dict(case.windows), sorted(set(set1) | set(set2)), window_seconds(case.now)):
            return run_now()
    elif step.get("error"):
        want["events"].append(("error dropped",))
    if set1:
        start = first_of(mode, set1, vty)
        best = fold(mode, set1[1:], vty, start)
    else:
        best = 0.0
    delay = best if best > base else base
    if not delay >= 0.0:
        raise Panicked("negative delay")
    if not case.scale >= 0.0:
        raise Panicked("negative scale")
    scaled = delay * case.scale
    if not scaled > 0.0:
        return run_now()
    if want["total"] >= want["max"]:
        return ("refused", TAG_TOTAL)
    count = want["users"].setdefault(user, 0)
    if count > USER_CAP:
        return ("refused", TAG_USER)
    at = add_seconds(now_nanos, scaled)
    if step.get("expires") is not None:
        millis = max(0, at // 10 ** 9 * 1000 + at % 10 ** 9 // 10 ** 6)
        millis = millis if at >= 0 else 0
        if millis > step["expires"]:
            amount = TOP if step.get("weight", 3) >> 62 else step.get("weight", 3) << 2
            want["row"] = min(want["row"] + amount, TOP)
            want["row time"], want["row time tail"] = case.now[0] | case.now[1] << 32, case.now[2]
            return ("refused", TAG_EXPIRED)
    record = (1 if step.get("expires") is not None else 0, step.get("expires") or 0, case.stamp, case.sopt[1] if case.sopt[0] else 0, user, step.get("byte", 0) & 1, case.flag, HASH_BYTES)
    want["queue"].setdefault(at, []).append(record)
    want["users"][user] = min(want["users"][user] + 1, TOP)
    want["total"] = min(want["total"] + 1, TOP)
    return ("queued", case.stamp, case.sopt[1] if case.sopt[0] else 0, at)


def spec_release(case, now, want):
    limit = time_nanos(now)
    rows = []
    for key in sorted(want["queue"]):
        if key < limit:
            rows.extend(want["queue"].pop(key))
    want["total"] = max(want["total"] - len(rows), 0)
    if want["users"]:
        for row in rows:
            user = row[4]
            if user in want["users"]:
                left = max(want["users"][user] - 1, 0)
                want["users"][user] = left
                if left == 0:
                    del want["users"][user]
                if not want["users"]:
                    break
    return ("released", tuple(rows))


def read_text(text):
    if len(text) > TEXT_CAP:
        return None, ("error", TAG_LENGTH)
    read = parsed(text)
    if read[0] == "tag":
        return None, ("error", read[1])
    return to_float(read[1]), None


def spec_vote(case, step, want):
    word = step[1]
    if word != WORD_BOUNDS and case.chain == 3:
        return ("error", TAG_TESTNET)
    if word == WORD_MAX:
        value = step[2]
        if value >= CAP:
            return ("error", TAG_NUMBER, value)
        if not MAX_LOW <= value <= MAX_HIGH:
            return ("error", TAG_MAX)
        want["max"] = value
    elif word == WORD_CLEAR:
        want["window flag"] = 0
    elif word == WORD_SCALE:
        value, refused = read_text(step[2])
        if refused:
            return refused
        if value <= 0.0 or value > SCALE_MAX:
            return ("error", TAG_NUMBER)
        want["scale"] = to_bits(value)
    else:
        step_value, refused = read_text(step[4])
        if refused:
            return refused
        low, refused = read_text(step[2])
        if refused:
            return refused
        high, refused = read_text(step[3])
        if refused:
            return refused
        if low > high or high > 1.0 or step_value > 0.01 or step_value <= 0.0 or low < 0.01:
            return ("error", TAG_INPUT)
        want["low"], want["high"], want["step"] = to_bits(low), to_bits(high), to_bits(step_value)
    return ("ok",)


def base_state(harness, case):
    shift = WRAPS[case.wrap].shift if case.copy is None else COPIES[case.copy].shift
    field = lambda offset: STATE + DELAYER + shift + offset
    fill = HEAP_FILL
    word = lambda at, size=8: int.from_bytes(fill[at - HEAP_BASE:at - HEAP_BASE + size], "little")
    return dict(total=case.n_total, max=case.max_n, scale=to_bits(case.scale), s50=3, s78=0, row=case.row[1], users=dict(case.users), queue={}, events=[], windows=len(dict(case.windows or ())), low=to_bits(case.knobs[0]), high=to_bits(case.knobs[1]), step=to_bits(case.knobs[2]),
                **{"window flag": 0 if case.windows is None else 1, "row time": word(ROW + 0x30), "row time tail": word(ROW + 0x38, 4)})


def spec_for(harness, case):
    want = base_state(harness, case)
    results = []
    panicked = False
    for step in case.steps:
        try:
            if step[0] == "curve":
                results.append(("value", to_bits(curve(step[1], step[2], to_float(step[3])))))
            elif step[0] == "enq":
                results.append(spec_enqueue(case, step[1], want))
            elif step[0] == "rel":
                results.append(spec_release(case, step[1], want))
            elif step[0] == "rename":
                want["users"][step[2]] = want["users"].pop(step[1])
                results.append(("renamed",))
            elif step[0] == "wipe":
                want["queue"], want["users"], want["total"] = {}, {}, 0
                results.append(("wiped",))
            else:
                results.append(spec_vote(case, step, want))
        except Panicked:
            results.append(("panic",))
            break
    if want["window flag"] == 0 and case.copy is not None:
        want["windows"] = 0
    want["queue"] = sorted(want["queue"].items())
    want["window live"] = bool(case.windows) and want["window flag"] == 1
    return dict(results=results, state=want, rest=True, kept=0)


def nan_equal(mine, theirs):
    return mine == theirs


def same(case, got, want):
    if want["state"]["windows"] == 0 and got["state"]["window flag"] == 0:
        got["state"]["windows"] = 0
    if got["state"] != want["state"] or got["rest"] != want["rest"] or got["kept"] != want["kept"]:
        return False
    return got["results"] == want["results"]


V_EDGES = (0.0, 1e-300, 1e-9, 1.5e-4, 2e-4, 3e-4, 4e-4, 0.00040000000000000002, 5e-4, 1e-3, 1.3e-3, 1.5e-3, 2.4e-3, 2.5e-3, 3e-3, 4e-3, 9.5e-3, 1.0, 1e300)
V_SPECIAL = (float("inf"), -float("inf"), float("nan"), -0.0, -1e-3, -1.0, 5e-324)
KINDS = (0, 1, 2, 3, 4, 5, 6, 9999, 10000, 10142, 10143, 10151, 11054, 11055, 11137, 11138, 109999, 110000, 99999999, 100000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)
MODES = (0, 1, 2, 3, 4, 0xFF)


def nudged(value):
    bits = to_bits(value)
    return (value, to_float(bits - 1), to_float(bits + 1))


def curve_cases():
    out = []
    points = tuple(to_bits(point) for value in V_EDGES if value > 0.0 for point in nudged(value)) + tuple(to_bits(value) for value in V_SPECIAL) + (0x7FF8000000000001, 0xFFF0000000000001)
    for mode in MODES:
        for kind in KINDS:
            for bits in (to_bits(1.5e-3), to_bits(1.0), to_bits(1e-5), to_bits(float("inf"))):
                out.append(Case("curve mode %d kind %d bits %#x" % (mode, kind, bits), steps=(("curve", mode, kind, bits),)))
    for mode in (0, 2, 3):
        for kind in (0, 3, 5, 6, 10000):
            for bits in points:
                out.append(Case("curve edge mode %d kind %d bits %#x" % (mode, kind, bits), steps=(("curve", mode, kind, bits),)))
    return out


def enq(**fields):
    return ("enq", fields)


def host_cases():
    out = []
    vty = tuple((key, to_bits(value)) for key, value in ((0, 1.5e-3), (3, 2e-3), (10000, 1e-3), (10142, 3e-3), (42, 5e-3)))
    for wrap in range(3):
        name = WRAPS[wrap].name
        case = lambda label, **fields: out.append(Case("%s %s" % (name, label), wrap=wrap, **fields))
        case("plain action runs now", steps=(enq(),))
        case("plain action with flag runs now", flag=1, steps=(enq(),))
        case("low word runs now", steps=(enq(kind="low"),))
        case("base four queues", steps=(enq(kind="four"),))
        case("nested arm queues", vty=vty, steps=(enq(kind="nest", arm=0, base=0.5, set1=(0,)),))
        case("arm one base", steps=(enq(kind="arm", arm=1, base=2.5),))
        case("arm two base", steps=(enq(kind="arm", arm=2, base=2.5, set2=(9,)),))
        case("arm three base", steps=(enq(kind="arm", arm=3, base=2.5),))
        case("sets with trackers", vty=vty, steps=(enq(kind="arm", set1=(0, 3, 10000, 10142, 42)),))
        case("first key misses", vty=vty, steps=(enq(kind="arm", set1=(1,)),))
        case("all keys miss", steps=(enq(kind="arm", set1=(1, 2, 3)),))
        case("set larger than base", vty=vty, steps=(enq(kind="arm", base=0.01, set1=(42,)),))
        case("base larger than set", vty=vty, steps=(enq(kind="arm", base=7.0, set1=(42,)),))
        case("zero scale runs now", scale=0.0, steps=(enq(kind="four"),))
        case("negative scale panics", scale=-1.0, steps=(enq(kind="four"),))
        case("negative base panics", steps=(enq(kind="arm", base=-1.0),))
        case("nan scale panics", scale=float("nan"), steps=(enq(kind="four"),))
        case("nan base panics", steps=(enq(kind="arm", base=float("nan")),))
        case("nan tracker panics", vty=((5, 0x7FF8000000000000),), steps=(enq(kind="arm", set1=(5,)),))
        case("infinite tracker queues at now", vty=((5, to_bits(float("inf"))),), steps=(enq(kind="arm", set1=(5,)),))
        case("nan in the fold panics", vty=((5, 0x7FF8000000000000), (6, 0)), steps=(enq(kind="arm", set1=(6, 5)),))
        case("deep tracker tree", deep=True, vty=vty, steps=(enq(kind="arm", set1=(0, 3, 42)),))
        case("half scale", scale=0.5, steps=(enq(kind="four"),))
        case("classifier error delays 0.2", steps=(enq(kind="arm", error=True),))
        case("classifier error with flag runs now", flag=1, steps=(enq(kind="arm", error=True),))
        case("total at the cap", n_total=5, max_n=5, steps=(enq(kind="four"),))
        case("total one below the cap", n_total=4, max_n=5, steps=(enq(kind="four"),))
        case("max zero refuses", n_total=0, max_n=0, steps=(enq(kind="four"),))
        case("zero delay ignores the cap", n_total=5, max_n=5, steps=(enq(),))
        case("user at 99", users=((USER_A, 99),), steps=(enq(kind="four"),))
        case("user at 100", users=((USER_A, 100),), steps=(enq(kind="four"),))
        case("user other row", users=((USER_B, 100),), steps=(enq(kind="four"),))
        case("user tops", users=((USER_B, 7), (USER_C, 8)), steps=(enq(kind="four", user=USER_A), enq(kind="four", user=USER_C)))
        case("total saturating add", n_total=TOP - 1, max_n=TOP, steps=(enq(kind="four"),))
        case("expires equal", steps=(enq(kind="four", expires=(time_nanos(NOW) + 4 * 10 ** 9) // 10 ** 6),))
        case("expires one short", steps=(enq(kind="four", expires=(time_nanos(NOW) + 4 * 10 ** 9) // 10 ** 6 - 1),))
        case("expires late", steps=(enq(kind="four", expires=(time_nanos(NOW) + 5 * 10 ** 9) // 10 ** 6),))
        case("expired weight top bits", row=(5, 1), steps=(enq(kind="four", expires=1, weight=1 << 62),))
        case("expired row saturates", steps=(enq(kind="four", expires=1, weight=9),))
        case("expired word zero", steps=(enq(kind="four", expires=0),))
        case("system option", sopt=(1, 0x1234), steps=(enq(kind="four"),))
        case("byte stored", steps=(enq(kind="four", byte=1),))
        case("flag stored", flag=2, steps=(enq(kind="four"),))
        case("same time twice", steps=(enq(kind="four"), enq(kind="four", user=USER_B)))
        case("day rollover", now=(packed_date(100), 86399, 999999999), steps=(enq(kind="four"),))
        for chain in (0, 1, 2, 3, 4):
            case("chain %d curve" % chain, chain=chain, vty=vty, steps=(enq(kind="arm", set1=(0,)), enq(kind="arm", set1=(3,)), enq(kind="arm", set1=(5,)), enq(kind="arm", set1=(10142,))))
    seconds = window_seconds(NOW)
    case = lambda label, **fields: out.append(Case(label, **dict(dict(flag=1), **fields)))
    ood = next(width for width in range(1, 100000) if seconds // width & 1)
    even = next(width for width in range(1, 100000) if not seconds // width & 1)
    case("window off", steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window empty map", windows=(), steps=(enq(kind="arm", base=1.0, set1=(5,), set2=(7,)),))
    case("window empty map low first", windows=(), steps=(enq(kind="arm", base=1.0, set1=(1, 3), set2=(2, 4)),))
    case("window empty map high first", windows=(), steps=(enq(kind="arm", base=1.0, set1=(2, 4), set2=(1, 3)),))
    case("window empty map shared", windows=(), steps=(enq(kind="arm", base=1.0, set1=(2,), set2=(2,)),))
    case("window empty sets", windows=((5, ood),), steps=(enq(kind="arm", base=1.0),))
    case("window odd", windows=((5, ood),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window even", windows=((5, even),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window zero width", windows=((5, 0),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window miss", windows=((6, even),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window second set", windows=((7, even),), steps=(enq(kind="arm", base=1.0, set1=(5,), set2=(7,)),))
    case("window both sets one key", windows=((5, ood),), steps=(enq(kind="arm", base=1.0, set1=(5,), set2=(5,)),))
    case("window both sets merged", windows=((5, ood), (6, ood), (7, even)), steps=(enq(kind="arm", base=1.0, set1=(5, 7), set2=(5, 6)),))
    case("window both sets all odd", windows=((5, ood), (6, ood), (7, ood)), steps=(enq(kind="arm", base=1.0, set1=(5, 7), set2=(3, 6, 8)),))
    case("window second set above", windows=((5, ood), (9, even)), steps=(enq(kind="arm", base=1.0, set1=(5,), set2=(5, 9)),))
    case("window first set above", windows=((5, ood), (9, even)), steps=(enq(kind="arm", base=1.0, set1=(5, 9), set2=(5,)),))
    case("window large width", windows=((5, 1 << 33),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window large seconds odd", windows=((5, 1 << 33),), now=(packed_date(100), 45000, 0), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("window tree height one", windows=tuple((key, ood) for key in range(1, 8)), height=1, steps=(enq(kind="arm", base=1.0, set1=(1, 4, 7)),))
    case("window tree height one even", windows=tuple((key, even if key == 4 else ood) for key in range(1, 8)), height=1, steps=(enq(kind="arm", base=1.0, set1=(1, 4, 7)),))
    for label, set1, set2 in (("low first", (1, 3), (2, 4)), ("high first", (2, 4), (1, 3)), ("overlap low", (1, 2), (2, 3)), ("overlap high", (2, 3), (1, 2)), ("long first", (1, 2, 3, 4), (2,)), ("long second", (2,), (1, 2, 3, 4)), ("first only", (1, 2, 3, 4), ()), ("second only", (), (1, 2, 3, 4))):
        for key in (1, 2, 3, 4):
            case("window merge %s even %d" % (label, key), windows=tuple((row, even if row == key else ood) for row in (1, 2, 3, 4)), steps=(enq(kind="arm", base=1.0, set1=set1, set2=set2),))
        case("window merge %s all odd" % label, windows=tuple((row, ood) for row in (1, 2, 3, 4)), steps=(enq(kind="arm", base=1.0, set1=set1, set2=set2),))
    case("window width two to the 32", windows=((5, 1 << 32),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    far = (packed_date(100, 200000), 45000, 0)
    far_seconds = window_seconds(far)
    for width in (1 << 32, 1 << 33, 1 << 34, (1 << 32) + 1, (1 << 33) + 1, (1 << 35) + 3):
        case("window far year width %d" % width, now=far, windows=((5, width),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    for year in (0, -1):
        case("window year %d floors at zero" % year, now=(packed_date(100, year), 45000, 0), windows=((5, 3),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    case("expiry far year", flag=0, now=far, steps=(enq(kind="four", expires=TOP),))
    case("expiry year zero floors", flag=0, now=(packed_date(100, 0), 45000, 0), steps=(enq(kind="four", expires=0),))
    case("expiry year minus one floors", flag=0, now=(packed_date(100, -1), 45000, 0), steps=(enq(kind="four", expires=0),))
    case("window miss above", windows=((6, even),), steps=(enq(kind="arm", base=1.0, set1=(7,)),))
    for ordinal in (100, 101, 102, 103):
        case("window day width ordinal %d" % ordinal, now=(packed_date(ordinal), 45000, 0), windows=((5, 86400),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
        case("expiry ordinal %d" % ordinal, flag=0, now=(packed_date(ordinal), 45000, 0), steps=(enq(kind="four", expires=(time_nanos((packed_date(ordinal), 45000, 0)) + 4 * 10 ** 9) // 10 ** 6 - 1),))
    for year in (2001, 2000, 2101, 2401):
        case("window year %d" % year, now=(packed_date(100, year), 45000, 0), windows=((5, 86400),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
        case("expiry year %d" % year, flag=0, now=(packed_date(100, year), 45000, 0), steps=(enq(kind="four", expires=(time_nanos((packed_date(100, year), 45000, 0)) + 4 * 10 ** 9) // 10 ** 6 - 1),))
    case("expiry exact year 2101", flag=0, now=(packed_date(100, 2101), 45000, 0), steps=(enq(kind="four", expires=(time_nanos((packed_date(100, 2101), 45000, 0)) + 4 * 10 ** 9) // 10 ** 6),))
    case("expired row plain", flag=0, row=(5, 100), steps=(enq(kind="four", expires=1, weight=3),))
    case("expired weight top bits from zero", flag=0, row=(5, 0), steps=(enq(kind="four", expires=1, weight=1 << 62),))
    case("window ignored without flag", flag=0, windows=((5, ood),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))
    return out


def later(seconds, nanos=0):
    total = time_nanos(NOW) + seconds * 10 ** 9 + nanos
    day = total // (86400 * 10 ** 9)
    rest = total - day * 86400 * 10 ** 9
    ordinal = day + UNIX_DAY - datetime.date(YEAR, 1, 1).toordinal() + 1
    return (packed_date(ordinal), rest // 10 ** 9, rest % 10 ** 9)


def release_cases():
    out = []
    pair = lambda: (enq(kind="arm", base=2.0), enq(kind="arm", base=4.0, user=USER_B), enq(kind="arm", base=4.0), enq(kind="arm", base=6.0, user=USER_C))
    for label, now in (("before all", later(1)), ("at the first key", later(2)), ("past the first key", later(2, 1)), ("at the second key", later(4)), ("past the second key", later(5)), ("past all", later(7)), ("far", later(100000))):
        out.append(Case("release %s" % label, steps=pair() + (("rel", now),)))
    out.append(Case("release empty", steps=(("rel", later(7)),)))
    out.append(Case("release twice", steps=pair() + (("rel", later(3)), ("rel", later(7)))))
    out.append(Case("release then enqueue", steps=pair() + (("rel", later(7)), enq(kind="four"))))
    out.append(Case("release total below rows", n_total=0, steps=pair()[:2] + (("wipe",), enq(kind="four"), ("rel", later(9)))))
    out.append(Case("release user rows gone", steps=pair()[:1] + (("wipe",), enq(kind="four", user=USER_B), ("rel", later(9)),)))
    out.append(Case("release user floor", users=((USER_B, 5),), steps=pair() + (("rel", later(7)),)))
    out.append(Case("release user missing above", steps=(enq(kind="four"), ("rename", USER_A, USER_B), ("rel", later(9)))))
    out.append(Case("release user missing below", steps=(enq(kind="four", user=USER_B), ("rename", USER_B, USER_A), ("rel", later(9)))))
    out.append(Case("wipe", steps=pair() + (("wipe",),)))
    out.append(Case("wipe empty", steps=(("wipe",),)))
    many = tuple(enq(kind="arm", base=float(index + 1)) for index in range(14))
    out.append(Case("release split tree", steps=many + (("rel", later(8)),)))
    out.append(Case("release whole tree", steps=many + (("rel", later(100)),)))
    out.append(Case("wipe tree", steps=many + (("wipe",),)))
    users = tuple(enq(kind="four", user=bytes([index + 1]) * 20) for index in range(14))
    out.append(Case("release many users", steps=users + (("rel", later(9)),)))
    return out


TEXTS = (b"0", b"0.5", b"1", b"2", b"2.0000000001", b"2.00000000000000001", b"0.0000000001", b"-1", b"abc", b"", b"1" * 100, b"1" * 101, b"0" * 100, b"0" * 99 + b"1")


def vote_cases():
    out = []
    for copy in range(3):
        name = COPIES[copy].name
        case = lambda label, **fields: out.append(Case("%s %s" % (name, label), copy=copy, **fields))
        for chain in (0, 2, 3):
            for value in (0, 1, 99, 100, 101, 299999, 300000, 300001, CAP - 1, CAP, TOP):
                case("max %d chain %d" % (value, chain), chain=chain, steps=(("vote", WORD_MAX, value),))
            case("clear chain %d" % chain, chain=chain, windows=((5, 7), (6, 8)), steps=(("vote", WORD_CLEAR),))
            case("clear none chain %d" % chain, chain=chain, steps=(("vote", WORD_CLEAR),))
        for text in TEXTS:
            case("scale %r" % text[:12] + " %d" % len(text), chain=2, steps=(("vote", WORD_SCALE, text),))
        case("scale mainnet", chain=3, steps=(("vote", WORD_SCALE, b"1"),))
        for label, low, high, step in (("ok", b"0.01", b"1", b"0.01"), ("mid", b"0.5", b"0.5", b"0.001"), ("low under", b"0.0099", b"1", b"0.01"), ("low above high", b"0.6", b"0.5", b"0.01"), ("high over", b"0.5", b"1.0001", b"0.01"), ("step zero", b"0.5", b"1", b"0"), ("step over", b"0.5", b"1", b"0.0101"),
                                       ("step negative", b"0.5", b"1", b"-0.01"), ("bad third", b"0.5", b"1", b"x"), ("bad first", b"x", b"1", b"0.01"), ("bad second", b"0.5", b"x", b"0.01"), ("long third", b"0.5", b"1", b"1" * 101), ("long first", b"1" * 101, b"1", b"0.01"), ("long second", b"0.5", b"1" * 101, b"0.01"), ("empty all", b"", b"", b""),
                                       ("edge first", b"0" * 97 + b".01", b"1", b"0.01"), ("edge second", b"0.5", b"0" * 99 + b"1", b"0.01"), ("edge third", b"0.5", b"1", b"0" * 97 + b".01")):
            for chain in (2, 3):
                case("bounds %s chain %d" % (label, chain), chain=chain, steps=(("vote", WORD_BOUNDS, low, high, step),))
    return out


def base_cases():
    return curve_cases() + host_cases() + release_cases() + vote_cases()


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(harness, case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %r want %r state %r want %r rest %r kept %r" % (case.name, got["results"], want["results"], got["state"], want["state"], got["rest"], got["kept"]))
        outcomes.append(got)
    return outcomes


VECTORS = 200
MUTANT_VECTORS = 40
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
        if index % 2:
            out.append(Case("vector %d" % index, steps=(("curve", pick(5), KINDS[pick(len(KINDS))], to_bits(pick(10 ** 6) / 1e8)),)))
            continue
        vty = tuple((key, to_bits(pick(10 ** 6) / 1e8)) for key in sorted({pick(12) for _ in range(5)}))
        steps = []
        for _ in range(pick(5) + 1):
            steps.append(enq(kind="arm", arm=pick(4), base=pick(9) / 3.0, set1=tuple(sorted({pick(14) for _ in range(pick(5))})), user=(USER_A, USER_B, USER_C)[pick(3)]))
        steps.append(("rel", later(pick(9))))
        out.append(Case("vector %d" % index, wrap=pick(3), chain=pick(4), vty=vty, scale=(pick(8) + 1) / 4.0, steps=tuple(steps)))
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
    "limit": "same except at one value: the edit moves the finite test by one step at the largest finite weight, which no case holds",
    "split": "same: this compare only splits ids above the listed values, both sides end in the default curve",
    "text": "same: panic message length, the panic text is not compared",
    "handle": "same: height word of a tree iterator handle, read only when it climbs from an empty handle",
    "floor": "same: only years at or below 0 use this constant and the seconds floor at 0",
    "merge": "not killed: the edited peek state of the two set iterators still visits every id in the cases run, and the result depends only on the ids",
    "length": "not killed: a node length or scan bound of a B-tree search; the fixtures hold a key that stops the scan first",
    "unused": "same: the fields written on this classifier error are unread once the gate returns 1",
    "empty": "same: with an empty map the walk only drains the iterators and always ends in result 1",
    "nanos": "same: the gate reads date and seconds only, this copies the nanosecond word",
    "ulp": "same: one bit in the last place of the constant rounds to the same nanosecond in the cases run",
    "fresh": "same: this branch only runs for a row just inserted at 0",
    "pad": "same: one extra copied byte is padding at the end of the record",
    "vec": "same: dangling pointer of an empty vector, never read",
    "top": "same: the saturated value needs a count of u64::MAX, and the caps stop counts before that",
    "root": "same: a nonzero length with a zero root is the panic row, no case holds it",
    "gone": "same: the row is removed right after this store",
    "arm": "same: index 0, index 0x14 and the edited index all reach the zero arm of the table",
    "zero": "same: a zero set root drains nothing, so its length and height words are unread",
    "stale": "same: these rows copy words behind the code and tag of the result, which the path leaves unset",
    "counter": "not killed: the S+0x50 counter starts at 3 in every case, so its saturation is not run",
    "tag": "same: the edited word is also nonzero or zero like the tag on cases run, and the drop of a zero root is empty",
    "sign": "same: sign fix of a division, positive for every year that reaches it above the floor",
    "century": "not killed: the low bit of the reciprocal moves year/100 only just past a multiple of 100, and the year/400 term can cancel it",
    "open": "not explained: left open",
}
SURVIVORS = {}
for group, addresses in (
    ("limit", (0x392FAE4, 0x392FAF1, 0x392FC20, 0x392FC2D)), ("split", (0x392FB7D, 0x392FB96)), ("text", (0x392FC96, 0x392CDD5, 0x392CDEE)),
    ("handle", (0x392D216, 0x392D265, 0x392C365, 0x392C47A, 0x392C4FF, 0x392C966, 0x392CD8B, 0x392CF26, 0x22084C4, 0x392C6B7)),
    ("floor", (0x392D2B1, 0x392D2B8, 0x392D2BF, 0x392D2C5, 0x392D2CB, 0x392CA8B, 0x392CA93, 0x392CA9A, 0x392CAA0, 0x392CAAA)),
    ("merge", (0x392D328, 0x392D339, 0x392D33D, 0x392D360, 0x392D362, 0x392D3A9, 0x392D3AC, 0x392D3C0)),
    ("length", (0x392D3F2, 0x392D3FC, 0x392D424, 0x392C57D, 0x392C588, 0x392C7C6, 0x392C7F4, 0x392CFFD)),
    ("unused", (0x392D529, 0x392D533, 0x392D550)), ("empty", (0x392D592, 0x392D59E, 0x392D600, 0x392D602, 0x392D62B, 0x392D631, 0x392D642, 0x392D645, 0x392D648, 0x392D651, 0x392D657)),
    ("nanos", (0x392C2B5,)), ("ulp", (0x392C45C, 0x3362EC0)), ("fresh", (0x392CA17,)), ("pad", (0x392CD0F,)), ("vec", (0x392CBFA,)), ("top", (0x392CD28,)), ("root", (0x392CEA6,)), ("gone", (0x392D09E,)),
    ("arm", (0x3362E68, 0x3362E6C, 0x3362E91)), ("zero", (0x3362EA3, 0x3362EB2, 0x3362ED6)),
    ("stale", (0x27586F6, 0x27586FA, 0x27586FE, 0x2758702, 0x2758706, 0x2758763, 0x2758773, 0x2758777, 0x275877B, 0x275877F, 0x2758787)), ("counter", (0x2758798,)), ("tag", (0x2359DEF,)), ("sign", (0x392D2FA, 0x392CAD1)), ("century", (0x392CAC7,)), ("open", (0x2208512,)),
):
    for address in addresses:
        SURVIVORS.setdefault(address, group)


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
    ("delay weight", "(vty / 10000.0).powf(-4.0) / 20.0 and two other powers, deterministic_delay_seconds", "fused multiply add fma(vty, 10000, -4) / 20, fma(vty, 10000, -3) / 12, fma(vty, 10000, -1.5) * 0.125: linear in vty; slot 0x576f6e0 resolves to vfmadd213sd", "curve edge mode 0 kind 6 bits 0x3f50624dd2f1a9fc"),
    ("curve selector", "ActionDelayerMode, delay_curve_byte 1 for Disabled and Enabled", "the byte is the chain byte passed in by the wrapper; below 2 every kind takes the default curve, 2 and above 3 have separate kind lists", "curve mode 1 kind 0 bits 0x3f589374bc6a7efa"),
    ("infinite weight", "clamp to 1.0", "a positive infinity skips the clamp and the delay stays infinite; NaN and negative infinity panic", "curve edge mode 0 kind 6 bits 0x7ff0000000000000"),
    ("queue shape", "BTreeMap keyed by DelayedActionId", "BTreeMap keyed by the 12-byte due time, value Vec of 0x148-byte records", "a same time twice"),
    ("due time", "integer now plus ceil(delay * scale) seconds", "now + f64 seconds through 0x1459ca0, no ceil, nanosecond resolution", "a set larger than base"),
    ("max zero", "max 0 means no cap", "n_total >= max refuses, so max 0 refuses every delayed action", "a max zero refuses"),
    ("per user cap", "no per-user bound", "count > 99 refuses with tag 0x13b; the row is created first", "a user at 100"),
    ("release bound", "expires_after <= now", "split at now, keys strictly below now leave, a key equal to now stays", "release at the first key"),
    ("delayer_mode", "Disabled, Enabled, DeterministicVty, DeterministicEma", "two tags: 0 Enabled, 1 PerAsset with a map of action id to window width; the host reads it only for the odd window gate", "window odd"),
    ("disabled mode", "Disabled error when the mode is off", "no mode test on this path: a delay <= 0 runs now, otherwise it queues", "a plain action runs now"),
    ("max votes", "set_max_n_delayed_actions(u64), no bounds", "word 79 refuses on chain byte 3, then 100 <= x <= 300000", "a max 99 chain 2"),
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
    for address, meaning in ((0x20A830, "multiplier of the tracker value"), (0x20A550, "default weight offset"), (0x20A380, "kind 5 or 0 weight offset"), (0x20A388, "listed kinds weight offset"), (0x20B038, "default divisor"), (0x20B100, "kind 5 or 0 divisor"), (0x20A6D8, "listed kinds factor"),
                             (0x20ADF0, "default slope"), (0x20B108, "special slope"), (0x20A250, "floor"), (0x20A768, "short factor"), (0x20A9F8, "long factor"), (0x20A730, "weight cap"), (0x20AFB8, "value of a set key without a tracker"), (0x20A2F8, "word 108 step cap and low floor"), (0x20A358, "word 106 upper bound")):
        rows.append(("%#x" % address, bytes(image.blob[address:address + 8]).hex(), repr(struct.unpack_from("<d", image.blob, address)[0]), meaning))
    return rows


FIELD_KEYS = ((0x27AEFA4, 14, "state", "action_delayer"), (0x23D0DA4, 12, "+0x00", "delayer_mode"), (0x2311D68, 12, "+0x20", "status_guard"), (0x2311C31, 15, "+0x30", "delayed_actions"), (0x2311C97, 25, "+0x48", "user_to_n_delayed_actions"),
              (0x2311D01, 23, "+0x60", "n_total_delayed_actions"), (0x2311D2C, 21, "+0x68", "max_n_delayed_actions"), (0x2311D9E, 11, "+0x88", "delay_scale"), (0x2313106, 7, "delayer_mode tag 0", "Enabled"), (0x2313159, 8, "delayer_mode tag 1", "PerAsset"))


def field_rows(image):
    rows = []
    for va, size, field, want in FIELD_KEYS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + 7])
        if data[:3] != b"\x48\x8d\x35":
            raise EvidenceError("key row %#x" % va)
        target = va + 7 + struct.unpack_from("<i", data, 3)[0]
        text = bytes(image.blob[image.offset(target):image.offset(target) + size]).decode("ascii")
        if text != want:
            raise EvidenceError("key text %#x: %r" % (va, text))
        rows.append(("%#x" % va, "%#x" % target, field, text))
    return rows


def classifier_rows(image):
    table = 0x5892BC
    rows = []
    known = {0x3362EA3: "zero base, empty sets", 0x3362EC0: "base 4.0, empty sets", 0x3362E86: "read the action at +0x20 and dispatch again", 0x3362EE3: "slot 0x5775c30", 0x3362EF5: "slot 0x5775c38", 0x3362F07: "slot 0x5775c40", 0x3362F19: "slot 0x5775c48"}
    for index in range(64):
        target = table + struct.unpack_from("<i", image.blob, table + 4 * index)[0]
        if target != 0x3362EA3:
            rows.append(("%#x" % (0x74 + index), index, "%#x" % target, known[target]))
    return rows


def subject_rows(image):
    table = {}
    for name, target in FUNCTIONS.items():
        table[name] = rows_of(image, target)
    for name, start, end in ARM_WINDOWS:
        table[name] = decode_range(image, start, end)
    return table


def copy_rows(image):
    rows = []
    for wrap in WRAPS:
        rows.append(("wrapper " + wrap.name, "%#x" % wrap.entry, "%#x" % (DELAYER + wrap.shift), "%#x" % (CHAIN + wrap.shift), "%#x" % (KNOBS + wrap.shift)))
    for copy in COPIES:
        rows.append(("vote dispatcher " + copy.name, "%#x" % copy.dispatch, "%#x" % (DELAYER + copy.shift), "%#x" % (CHAIN + copy.shift), "%#x" % (KNOBS + copy.shift)))
    return rows


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
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), tags=tag_rows(image), classifier=classifier_rows(image), copies=copy_rows(image), fields=field_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def outcome_row(case, got):
    digest = hashlib.sha256(repr(sorted(got["state"].items(), key=str)).encode()).hexdigest()[:16]
    return (case.name, " ; ".join(" ".join(("%#x" % part if isinstance(part, int) else str(part)) for part in result) if result[0] != "released" else "released %d" % len(result[1]) for result in got["results"]), digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("subject", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in result["table"] for row in result["table"][name]])
    tsv("constants.tsv", ("address", "bytes", "value", "meaning"), result["constants"])
    tsv("tag-texts.tsv", ("tag", "display text"), result["tags"])
    tsv("field-names.tsv", ("key row", "key address", "field", "text"), result["fields"])
    tsv("classifier-table.tsv", ("action word", "index", "arm", "effect"), result["classifier"])
    tsv("reference-diff.tsv", ("subject", "reference lead", "bytes", "case"), REFERENCE)
    tsv("copies.tsv", ("copy", "entry", "delayer offset", "chain byte offset", "bounds offset"), result["copies"])
    tsv("outcomes.tsv", ("case", "result", "state digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
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

