#!/usr/bin/env python3
"""Pin node #94 VoteGlobal staking arms: 14 raw tags of 0x2355f40 with their set, guard and refund helpers.

The real bytes run in an interpreter inside this tool, with six named boundary functions stubbed. A separately written rule list
predicts every status, every boundary call, every changed Exchange byte and the rows of every touched tree. Every reached conditional
row and immediate in the named functions is mutated. No external program is called and the binary is never executed. Standard library only.

    python3 tools/staking_vote_arms.py --out <dir>
"""

import argparse
import bisect
import collections
import datetime
import fractions
import hashlib
import json
import math
import multiprocessing
import pathlib
import random
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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
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
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


DISPATCH = 0x2355F40
TABLE = 0x3DD1B8
TABLE_ROWS = 0x62
TABLE_BASE_TAG = 0x12
LIST_CAP = 0x1E80420
UNJAIL = 0x2868D10
CLEAR_SET = 0x284BD00
CLEAR_VOTES = 0x284BD90
CLEAR_JAIL = 0x25A7EF0
MERGE_HOST = 0x3991E80
MERGE = 0x3BB4810
IP_INSERT = 0x284D320
IP_REMOVE = 0x2867E30
SET_INSERT = 0x285B5C0
SET_REMOVE = 0x2867270
BROAD_INSERT = 0x284CA00
BROAD_REMOVE = 0x2866560
GUARD_EPOCH = 0x325DC00
GUARD_BLOCK = 0x325DB20
HASH = 0x2840FB0
CVALIDATOR = 0x2768FF0
DROP_ACTION = 0x239E1C0
DROP_STATUS = 0x239D6C0
LAZY = 0x14385C0
VOTE_NEXT = 0x286A250
JAIL_DROP = 0x28A7F20
COPY_STUBS = {0x4D9E0D0: CVALIDATOR, 0x4D9DCD0: CVALIDATOR, 0x4DB1B80: DROP_STATUS, 0x4DB2DF0: DROP_ACTION, 0x494C310: VOTE_NEXT, 0x49A90C0: JAIL_DROP}
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
SLOT_LAZY = 0x576F488
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118, 0x576DFB8)
MARK_BASE = 0x7700000000
ACTION = HEAP_BASE + 0x200
OUT = HEAP_BASE + 0x800
EXCHANGE = HEAP_BASE + 0x1000
EXCHANGE_SIZE = 0x3C00
STATE_FROM = 0x700
SHIFT = 0xA80
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + 0x3F0000
HEAP_USED = 0x400000
LONG_STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 1200000
OK = 0x186
TOO_LONG = 0x143
BAD_WEI = 0x13F
BAD_SECONDS = 0x13E
WEI_CAP = 0xCCCCCCCCCCCCCCC
LONGEST_SECONDS = 0x2A300
STAKING = 0x8F8
E_TIME = 0x60
E_MODE = 0x80
E_LIMIT_CTRL = 0x740
E_LIMIT_MASK = 0x748
E_LIMIT_ITEMS = 0x758
E_LIMIT_SEED = 0x760
E_CHAIN = 0x8F2
E_MAX_TAG = STAKING
E_MAX_VALUE = STAKING + 8
E_STAKES_PERIOD = STAKING + 0x28
E_VOTES = STAKING + 0x88
E_DECAY = STAKING + 0xA0
E_JAIL_PERIOD = STAKING + 0xB0
E_JAILED = STAKING + 0xD8
E_REWARD = STAKING + 0x110
E_ALLOWED = STAKING + 0x120
E_BROADCASTERS = STAKING + 0x138
E_PROFILES = STAKING + 0x150
E_JAIL_UNTIL = STAKING + 0x1B0
E_FLOOR = STAKING + 0x240
E_DISABLED = STAKING + 0x248
E_IPS = STAKING + 0x260
E_ALLOW_ALL = STAKING + 0x290
VOTES_ROOT = 0x7A0000
JAIL_ROOT = 0x7B0000
JAN_1971_MS = 31536000000


class Layout:
    def __init__(self, key_size, key_at, val_size, val_at, parent_at, slot_at, len_at, edge_at, leaf, inner):
        self.key_size, self.key_at, self.val_size, self.val_at = key_size, key_at, val_size, val_at
        self.parent_at, self.slot_at, self.len_at, self.edge_at = parent_at, slot_at, len_at, edge_at
        self.leaf, self.inner = leaf, inner


ADDRESS_SET = Layout(20, 8, 0, 0, 0, 0xE4, 0xE6, 0xE8, 0xE8, 0x148)
IP_SET = Layout(5, 0xC, 0, 0, 0, 8, 0xA, 0x48, 0x48, 0xA8)
TOGGLES = Layout(20, 8, 1, 0xE8, 0, 0xE4, 0xE6, 0xF8, 0xF8, 0x158)
PROFILES = Layout(20, 0x3D0, 0x58, 8, 0, 0x4AC, 0x4AE, 0x4B0, 0x4B0, 0x510)
TREES = (("allowed_validators", E_ALLOWED, ADDRESS_SET), ("broadcasters", E_BROADCASTERS, ADDRESS_SET), ("jailed_signers.current", E_JAILED, ADDRESS_SET), ("disabled_validators", E_DISABLED, ADDRESS_SET), ("disabled_node_ips", E_IPS, IP_SET))


class StubRange:
    """Every code address runs for real but the named boundary functions."""

    def __contains__(self, va):
        return va < 0x6000000 and va not in (CVALIDATOR, DROP_ACTION, DROP_STATUS, LAZY, VOTE_NEXT, JAIL_DROP) and va not in COPY_STUBS


def real_set(self):
    return StubRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC, SLOT_LAZY) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = image.real_set()
        machine.step_limit = LONG_STEP_LIMIT
        machine.memory.statics = image.static_view()
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc, SLOT_LAZY: self.on_lazy}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        machine.calls = {CVALIDATOR: self.on_cvalidator, DROP_ACTION: self.on_drop_action, DROP_STATUS: self.on_drop_status, LAZY: self.on_lazy, VOTE_NEXT: self.on_vote_next, JAIL_DROP: self.on_jail_drop}
        for copy, base in COPY_STUBS.items():
            machine.calls[copy] = machine.calls[base]
        self.shift = 0
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.live = {}
        self.events = []
        self.case = None

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

    def on_cvalidator(self, machine):
        out, exchange, signer, action = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(exchange == EXCHANGE, "exchange pointer")
        self.events.append(("cvalidator", self.data(signer, 20).hex(), self.data(action, 0x60).hex()))
        self.write(out, self.case.cv_status, 2)
        self.put(out + 2, bytes((0x20 + at) & 0xFF for at in range(0x5E)))
        machine.regs[RAX] = out

    def on_drop_action(self, machine):
        self.events.append(("drop_action", machine.regs[RDI] - ACTION))

    def on_drop_status(self, machine):
        self.events.append(("drop_status", self.read(machine.regs[RDI], 1)))

    def on_lazy(self, machine):
        self.events.append(("lazy",))

    def on_vote_next(self, machine):
        out, state = machine.regs[RDI], machine.regs[RSI]
        live = self.read(state)
        self.events.append(("votes", live, self.read(state + 0x10) if live else 0, self.read(state + 0x18) if live else 0, self.read(state + 0x20), self.read(state + 0x30) if live else 0, self.read(state + 0x38) if live else 0, self.read(state + 0x40)))
        self.write(out, 0)

    def on_jail_drop(self, machine):
        state = machine.regs[RDI]
        self.events.append(("jail_map", self.read(state), self.read(state + 8), self.read(state + 0x10)))

    def build(self, layout, rows, height, parent=0, slot=0):
        """Rows are (key, value) sorted; height 0 is a leaf."""
        if height == 0:
            self.expect(len(rows) <= 11, "leaf row count")
            node = self.alloc(layout.leaf)
            for index, (key, value) in enumerate(rows):
                self.put(node + layout.key_at + index * layout.key_size, key)
                if layout.val_size:
                    self.put(node + layout.val_at + index * layout.val_size, value)
        else:
            parts = max(2, (len(rows) + 1 + 12 ** height - 1) // 12 ** height)
            self.expect(parts <= 12, "edge count")
            node = self.alloc(layout.inner)
            seps, chunks, used = [], [], 0
            for part in range(parts):
                end = (len(rows) + 1) * (part + 1) // parts - 1
                chunks.append(rows[used:end])
                if part < parts - 1:
                    seps.append(rows[end])
                used = end + 1
            for index, (key, value) in enumerate(seps):
                self.put(node + layout.key_at + index * layout.key_size, key)
                if layout.val_size:
                    self.put(node + layout.val_at + index * layout.val_size, value)
            rows = seps
            for index, chunk in enumerate(chunks):
                self.write(node + layout.edge_at + index * 8, self.build(layout, chunk, height - 1, node, index))
        self.write(node + layout.len_at, len(rows), 2)
        self.write(node + layout.parent_at, parent)
        self.write(node + layout.slot_at, slot, 2)
        return node

    def root(self, at, layout, rows):
        rows = list(rows)
        height = tree_height(len(rows))
        if rows:
            self.write(at, self.build(layout, rows, height))
            self.write(at + 8, height)
        else:
            self.write(at, 0)
            self.write(at + 8, 0)
        self.write(at + 0x10, len(rows))

    def walk(self, layout, node, height, parent=None, slot=None):
        rows = []
        count = self.read(node + layout.len_at, 2)
        self.expect(1 <= count <= 11, "node row count")
        if parent is not None:
            self.expect(self.read(node + layout.parent_at) == parent and self.read(node + layout.slot_at, 2) == slot, "parent link")
        for index in range(count + 1):
            if height:
                rows += self.walk(layout, self.read(node + layout.edge_at + index * 8), height - 1, node, index)
            if index < count:
                rows.append(self.data(node + layout.key_at + index * layout.key_size, layout.key_size))
        return rows

    def rows_at(self, at, layout):
        root = self.read(at)
        if not root or not self.read(at + 0x10):
            self.expect(self.read(at + 0x10) == 0, "empty map length")
            return []
        rows = self.walk(layout, root, self.read(at + 8))
        self.expect(len(rows) == self.read(at + 0x10), "map length word")
        return rows

    def place(self, at):
        return EXCHANGE + at + (self.shift if at >= STATE_FROM else 0)

    def view(self):
        return self.data(EXCHANGE, STATE_FROM) + self.data(self.place(STATE_FROM), EXCHANGE_SIZE - STATE_FROM)

    def hash_of(self, key):
        self.put(ACTION + 0x100, key)
        self.machine.run(HASH, {RDI: self.place(E_LIMIT_SEED), RSI: ACTION + 0x100})
        return self.machine.regs[RAX]

    def limit_table(self, rows):
        ctrl_size = 32
        slots = self.alloc(0x58 * 16 + ctrl_size)
        ctrl = slots + 0x58 * 16
        self.put(ctrl, b"\xFF" * ctrl_size)
        mask = 15
        for key, word in rows:
            value = self.hash_of(key)
            at = value & mask
            while self.read(ctrl + at, 1) != 0xFF:
                at = (at + 1) & mask
            self.write(ctrl + at, value >> 57, 1)
            if at < 16:
                self.write(ctrl + at + 16, value >> 57, 1)
            row = ctrl - 0x58 * (at + 1)
            self.put(row, key)
            self.put(row + 0x14, bytes((0x70 + index) & 0xFF for index in range(0x44)))
            self.write(row + 0x20, word)
        self.write(self.place(E_LIMIT_CTRL), ctrl)
        self.write(self.place(E_LIMIT_MASK), mask)
        return ctrl

    def limit_rows(self, ctrl):
        rows = []
        for at in range(16):
            if self.read(ctrl + at, 1) != 0xFF:
                row = ctrl - 0x58 * (at + 1)
                rows.append((self.data(row, 20), self.read(row + 0x20)))
        return sorted(rows)

    def fresh(self, case):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}
        self.events = []
        self.case = case


def tree_height(count):
    return 0 if count <= 11 else 1 if count <= 143 else 2 if count <= 1727 else 3


class Case:
    FIELDS = dict(raw=0, value=0, value2=0, flag=0, tag=0, who=None, ip=(0, b"\x0A\x00\x00\x01"), rows=(), lie_len=None, mode=0, chain=0, allowed=(), broadcasters=(), jailed=(), disabled=(), ips=(),
                  profiles=(), limits=(), limit_items=None, max_tag=1, floor=5, votes=0, votes_len=0, jail_map=0, date=(2026 << 13) | (300 << 4) | 2, secs=3661, nanos=7000000, cv_status=OK)

    def __init__(self, name, **fields):
        self.name = name
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise EvidenceError("unknown field %s" % sorted(unknown))
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.get(key, value))
        self.who = self.who if self.who is not None else address(0x77)


def address(seed):
    return hashlib.sha256(b"staking vote %d" % seed).digest()[:20]


FILLER = bytes(((at * 7 + 0x31 + (at >> 8)) & 0xFF) | 1 for at in range(EXCHANGE_SIZE))


def changed(old, new):
    rows = []
    for start in range(0, EXCHANGE_SIZE, 512):
        if old[start:start + 512] != new[start:start + 512]:
            rows += [(at, new[at]) for at in range(start, start + 512) if old[at] != new[at]]
    return rows


def base_image(case):
    """Exchange bytes before the call: a position pattern plus the scalars of the case; tree heads are placed apart."""
    data = bytearray(FILLER)
    data[E_TIME:E_TIME + 12] = struct.pack("<iII", case.date, case.secs, case.nanos)
    data[E_MODE:E_MODE + 4] = struct.pack("<I", case.mode)
    data[E_CHAIN] = case.chain
    data[E_MAX_TAG:E_MAX_TAG + 8] = struct.pack("<Q", case.max_tag)
    data[E_FLOOR:E_FLOOR + 8] = struct.pack("<Q", case.floor)
    data[E_LIMIT_ITEMS:E_LIMIT_ITEMS + 8] = struct.pack("<Q", len(case.limits) if case.limit_items is None else case.limit_items)
    data[E_VOTES:E_VOTES + 8] = struct.pack("<Q", case.votes)
    data[E_VOTES + 8:E_VOTES + 16] = struct.pack("<Q", 3 if case.votes else 0)
    data[E_VOTES + 16:E_VOTES + 24] = struct.pack("<Q", case.votes_len)
    data[E_JAIL_UNTIL:E_JAIL_UNTIL + 8] = struct.pack("<Q", case.jail_map)
    data[E_JAIL_UNTIL + 8:E_JAIL_UNTIL + 16] = struct.pack("<Q", 2 if case.jail_map else 0)
    data[E_JAIL_UNTIL + 16:E_JAIL_UNTIL + 24] = struct.pack("<Q", 9 if case.jail_map else 0)
    return data


def action_bytes(case):
    data = bytearray((0xB0 + at) & 0xFF for at in range(0x90))
    data[0:8] = struct.pack("<Q", case.raw)
    if case.raw == 0x24:
        data[8:0x20] = bytes(0x18)
    elif case.raw in (0x38, 0x43):
        data[8] = case.flag
        data[9:29] = case.who
    elif case.raw == 0x44:
        data[8] = case.ip[0]
        data[9:13] = case.ip[1]
        data[13] = case.flag
    elif case.raw == 0x39:
        data[8:0x18] = struct.pack("<QQ", case.value, case.value2)
    elif case.raw == 0x3C:
        data[8:0x18] = struct.pack("<QQ", case.tag, case.value)
    elif case.raw == 0x3E:
        data[8:28] = case.who
    elif case.raw == 0x3A:
        data[0x70:0x84] = case.who
    elif case.raw == 0x42:
        data[8] = case.flag
    else:
        data[8:0x10] = struct.pack("<Q", case.value)
    return data


def profile_value(signer):
    return bytes((0xC0 + at) & 0xFF for at in range(0x38)) + signer + bytes((0x90 + at) & 0xFF for at in range(12))


def run_arm(harness, case, entry=DISPATCH, shift=0):
    harness.fresh(case)
    harness.shift = shift
    machine = harness.machine
    before = bytes(base_image(case))
    harness.put(EXCHANGE, before[:STATE_FROM])
    harness.put(EXCHANGE + STATE_FROM, bytes((0xEE,)) * shift)
    harness.put(harness.place(STATE_FROM), before[STATE_FROM:])
    harness.put(ACTION, bytes(action_bytes(case)))
    harness.put(OUT, bytes(0x60))
    nodes = []
    if case.raw == 0x24:
        rows = [(key, bytes((flag,))) for key, flag in case.rows]
        harness.root(ACTION + 8, TOGGLES, rows)
        nodes = set(harness.live)
        if case.lie_len is not None:
            harness.write(ACTION + 0x18, case.lie_len)
    heads = {}
    for name, at, layout in TREES:
        rows = {"allowed_validators": case.allowed, "broadcasters": case.broadcasters, "jailed_signers.current": case.jailed, "disabled_validators": case.disabled, "disabled_node_ips": case.ips}[name]
        harness.root(harness.place(at), layout, [(key, b"") for key in rows])
    harness.root(harness.place(E_PROFILES), PROFILES, [(key, profile_value(signer)) for key, signer in case.profiles])
    ctrl = harness.limit_table(case.limits)
    start = harness.view()
    machine.run(entry, {RDI: OUT, RSI: ACTION, RDX: EXCHANGE})
    status = harness.read(OUT, 2)
    out = [("status", status)]
    if status == BAD_WEI:
        out.append(("payload", harness.read(OUT + 8)))
    if case.raw == 0x3A and status != OK:
        out.append(("copy", harness.data(OUT + 2, 0x5E).hex()))
    out += harness.events
    after = harness.view()
    holes = set()
    for name, at, layout in TREES:
        holes |= set(range(at, at + 24))
        out.append(("rows", name, tuple(key.hex() for key in harness.rows_at(harness.place(at), layout))))
    holes |= set(range(E_LIMIT_CTRL, E_LIMIT_CTRL + 16)) | set(range(E_PROFILES, E_PROFILES + 24))
    out.append(("diff", tuple(row for row in changed(start, after) if row[0] not in holes)))
    out.append(("limits", tuple((key.hex(), word) for key, word in harness.limit_rows(ctrl))))
    out.append(("left", sum(1 for at in nodes if at in harness.live)))
    return tuple(out)


def ip_order(key):
    return (key[0], key[1]) if key[0] & 1 else (key[0], int.from_bytes(key[1:5], "big"))


def seconds_of(date, secs, nanos):
    year = date >> 13
    ordinal = (date >> 4) & 0x1FF
    shift = 400 * (2 - year // 400)
    days = datetime.date(year + shift, 1, 1).toordinal() + ordinal - 1 - shift * 146097 // 400 - datetime.date(1970, 1, 1).toordinal()
    return max(0, (days * 86400 + secs) * 1000 + nanos // 1000000)


def spec_run(case, table=TABLE):
    state = base_image(case)
    trees = {"allowed_validators": list(case.allowed), "broadcasters": list(case.broadcasters), "jailed_signers.current": list(case.jailed), "disabled_validators": list(case.disabled), "disabled_node_ips": list(case.ips)}
    limits = dict(case.limits)
    status, payload, events, copy = OK, None, [], None

    def word(at, value):
        state[at:at + 8] = struct.pack("<Q", value & MASK[8])

    def toggle(name, key, add):
        rows = trees[name]
        if add and key not in rows:
            rows.append(key)
            rows.sort()
        if not add and key in rows:
            rows.remove(key)

    raw = case.raw
    if raw == 0x24:
        if case.lie_len is not None or len(case.rows) > 10000:
            status = TOO_LONG
        else:
            for key, flag in sorted(case.rows):
                toggle("allowed_validators", key, flag != 0)
    elif raw == 0x38:
        toggle("broadcasters", case.who, case.flag != 0)
    elif raw == 0x39:
        if case.value:
            if case.value >= WEI_CAP:
                status, payload = BAD_WEI, case.value
            else:
                word(E_STAKES_PERIOD, case.value)
        if status == OK and case.value2:
            if case.value2 >= WEI_CAP:
                status, payload = BAD_WEI, case.value2
            else:
                word(E_JAIL_PERIOD, case.value2)
    elif raw == 0x3A:
        events.append(("cvalidator", case.who.hex(), bytes((0xB8 + at) & 0xFF for at in range(0x60)).hex()))
        status = case.cv_status
        if status == OK:
            events.append(("drop_status", 0xD))
        else:
            copy = bytes((0x20 + at) & 0xFF for at in range(0x5E)).hex()
        events.append(("drop_action", 8))
    elif raw == 0x3B:
        trees["jailed_signers.current"] = []
        length = case.votes_len if case.votes else 0
        events.append(("votes", 1 if case.votes else 0, case.votes, 3 if case.votes else 0, 1 if case.votes else 0, case.votes, 3 if case.votes else 0, length))
        word(E_VOTES, 0)
        word(E_VOTES + 16, 0)
        events.append(("jail_map", case.jail_map, 2 if case.jail_map else 0, 9 if case.jail_map else 0))
        word(E_JAIL_UNTIL, 0)
        word(E_JAIL_UNTIL + 16, 0)
    elif raw == 0x3C:
        if case.tag == 1 and case.value >= WEI_CAP:
            status, payload = BAD_WEI, case.value
        else:
            word(E_MAX_TAG, case.tag)
            word(E_MAX_VALUE, case.value if case.tag == 1 else table)
    elif raw == 0x3E:
        toggle("jailed_signers.current", case.who, False)
    elif raw == 0x3F:
        book = dict(case.profiles)
        for key in sorted(set(case.allowed) | set(book)):
            if key not in book:
                continue
            if case.value >= WEI_CAP:
                status, payload = BAD_WEI, case.value
                break
            if (len(case.limits) if case.limit_items is None else case.limit_items) and book[key] in limits:
                limits[book[key]] = max(limits[book[key]] - case.value, 0)
    elif raw == 0x41:
        if case.value >= WEI_CAP:
            status, payload = BAD_WEI, case.value
        elif case.mode == 1:
            events.append(("lazy",))
            word(E_FLOOR, case.value)
    elif raw == 0x42:
        if case.floor and case.max_tag:
            state[E_ALLOW_ALL] = case.flag
    elif raw == 0x43:
        toggle("disabled_validators", case.who, case.flag != 0)
    elif raw == 0x44:
        key = bytes((case.ip[0],)) + case.ip[1]
        rows = trees["disabled_node_ips"]
        hit = [row for row in rows if ip_order(row) == ip_order(key)]
        if case.flag and not hit and case.ip[0] != 2:
            rows.append(key)
            rows.sort(key=ip_order)
        if not case.flag and hit:
            rows.remove(hit[0])
    elif raw == 0x45:
        if case.value >= WEI_CAP:
            status, payload = BAD_WEI, case.value
        else:
            width = min(case.value, LONGEST_SECONDS) * 1000
            word(E_DECAY, width)
            word(E_DECAY + 8, JAN_1971_MS // width)
    elif raw == 0x46:
        if case.value >= WEI_CAP:
            status, payload = BAD_WEI, case.value
        elif not 1 <= case.value <= LONGEST_SECONDS:
            status = BAD_SECONDS
        else:
            width = case.value * 1000
            word(E_REWARD, width)
            word(E_REWARD + 8, seconds_of(case.date, case.secs, case.nanos) // width)
    else:
        raise EvidenceError("raw %#x has no rule" % raw)
    out = [("status", status)]
    if payload is not None:
        out.append(("payload", payload))
    if copy is not None:
        out.append(("copy", copy))
    out += events
    for name, _, layout in TREES:
        out.append(("rows", name, tuple(key.hex() for key in trees[name])))
    start = base_image(case)
    out.append(("diff", tuple(row for row in changed(start, state) if not any(head <= row[0] < head + 24 for _, head, _ in TREES))))
    out.append(("limits", tuple((key.hex(), word_value) for key, word_value in sorted(limits.items()))))
    out.append(("left", 0))
    return tuple(out)


def compare(got, want, case):
    return got == want


def addresses(count, seed=1):
    return sorted(address(seed * 1000 + at) for at in range(count))


def run_case(harness, case):
    return run_arm(harness, case)


CONSTANTS = (
    (0x1e80430, 6, "list cap 10000", "483d10270000"),
    (0x1e80438, 5, "status 0x143", "66c7034301"),
    (0x2358ecb, 10, "wei cap 0xccccccccccccccc", "48b9cccccccccccccc0c"),
    (0x235c23f, 6, "status 0x13f", "6641c745003f"),
    (0x2358eeb, 7, "write stakes.period, Exchange +0x920", "49899520090000"),
    (0x2358f04, 7, "write jailed_signers.period, Exchange +0x9a8", "498985a8090000"),
    (0x2358fa7, 7, "write stakes.current.max_n_validators tag, Exchange +0x8f8", "49898df8080000"),
    (0x2358fae, 7, "write its value, Exchange +0x900", "49898500090000"),
    (0x2356cc8, 7, "jailed_signers.current, Exchange +0x9d0", "4981c5d0090000"),
    (0x23582ba, 7, "jail vote map, Exchange +0x980", "498dbd80090000"),
    (0x23582c6, 7, "jail_until, Exchange +0xaa8", "4981c5a80a0000"),
    (0x2358881, 7, "allowed_validators, Exchange +0xa18", "4981c5180a0000"),
    (0x2359134, 7, "broadcasters, Exchange +0xa30", "4981c5300a0000"),
    (0x2358ae6, 7, "validator_to_profile, Exchange +0xa48", "4d8bb5480a0000"),
    (0x2356937, 8, "gate byte word at Exchange +0x80 is 1", "4183bd8000000001"),
    (0x235694b, 7, "write self_delegation_requirement, Exchange +0xb38", "49899d380b0000"),
    (0x2356d8d, 8, "gate requirement word not zero", "4983bd380b000000"),
    (0x2356d9b, 8, "gate stakes tag not zero", "4983bdf808000000"),
    (0x2356dae, 7, "write allow_all_validators, Exchange +0xb88", "418885880b0000"),
    (0x23572bd, 7, "disabled_validators, Exchange +0xb40", "4981c5400b0000"),
    (0x23562ac, 7, "disabled_node_ips, Exchange +0xb58", "4981c5580b0000"),
    (0x23593c8, 7, "stakes_decay_bucket_guard width, Exchange +0x998", "49898598090000"),
    (0x23593cf, 7, "stakes_decay_bucket_guard bucket, Exchange +0x9a0", "498995a0090000"),
    (0x235928b, 7, "seconds less 0x2a301", "488d88ff5cfdff"),
    (0x2359292, 6, "range test, 1 to 172800", "4881f9ff5cfd"),
    (0x23592a3, 6, "status 0x13e", "6641c745003e"),
    (0x235aad2, 7, "seconds to milliseconds", "4869f0e8030000"),
    (0x235aaf0, 7, "distribute_reward_bucket_guard, Exchange +0xa08", "4981c5080a0000"),
    (0x2358bdf, 8, "limit map item count, Exchange +0x758", "4983bd5807000000"),
    (0x2358cb8, 5, "limit row word, 0x38 below row end", "4a8b4409c8"),
    (0x325dc04, 5, "date argument 719528, first day of 1971", "bfa8fa0a00"),
    (0x325dc47, 7, "clamp to 172800 seconds", "4881fb00a30200"),
    (0x325dc98, 7, "days to milliseconds", "4869d0005c2605"),
)
VARIANT_TAGS = (
    ("ModifyCStakingPeriods", 0x1bd5bc2, 0x108, 0x39),
    ("CValidator", 0x1bc38ec, 0x1a8, 0x3a),
    ("UnjailSigner", 0x1bca958, 0x110, 0x3e),
    ("DisableCValidator", 0x1bac883, 0x100, 0x43),
    ("DisableNodeIp", 0x1bad9a1, 0x100, 0x44),
)
CAP = WEI_CAP
TOP = MASK[8]
POOL = addresses(12000)
A = POOL[:600]


def spaced(count, offset=0):
    return A[offset:][::3][:count]


def between(rows, index):
    """A key that sorts just after rows[index]."""
    return rows[index][:19] + bytes(((rows[index][19] + 1) & 0xFF,))


def set_cases(prefix, raw, field):
    out = []

    def add(name, **fields):
        fields[field] = fields.pop("have", ())
        out.append(Case("%s_%s" % (prefix, name), raw=raw, **fields))

    add("insert_empty", flag=1, who=A[0])
    add("remove_empty", flag=0, who=A[0])
    for count in (1, 3, 10, 11, 12, 13, 24, 40, 143, 150):
        rows = spaced(count)
        for at in sorted({0, count // 2, count - 1}):
            add("insert_present_%d_%d" % (count, at), flag=1, who=rows[at], have=rows)
            add("remove_present_%d_%d" % (count, at), flag=0, who=rows[at], have=rows)
            add("insert_new_%d_%d" % (count, at), flag=1, who=between(rows, at), have=rows)
            add("remove_absent_%d_%d" % (count, at), flag=0, who=between(rows, at), have=rows)
        add("insert_first_%d" % count, flag=1, who=b"\x00" * 20, have=rows)
        add("insert_last_%d" % count, flag=1, who=b"\xFF" * 20, have=rows)
    rows = spaced(12)
    for at in range(12):
        add("merge_%d" % at, flag=0, who=rows[at], have=rows)
    rows = spaced(35)
    for at in (1, 5, 6, 7, 11, 12, 17, 18, 23, 28, 29, 33):
        add("tall_%d" % at, flag=0, who=rows[at], have=rows)
    return out


def jail_cases():
    out = []
    for case in set_cases("unjail", 0x3E, "jailed"):
        if case.flag == 0:
            case.name = case.name.replace("remove_", "")
            out.append(case)
    return out


def ip(tag, text):
    return (tag, bytes(text))


def ip_rows(count, odd=0):
    rows = [bytes((0,)) + (0x01020300 + at * 0x01000001 & 0xFFFFFFFF).to_bytes(4, "big") for at in range(count)]
    rows += [bytes((1, 10 + at, 0xA, 0xB, 0xC)) for at in range(odd)]
    return sorted(rows, key=ip_order)


def ip_cases():
    out = []

    def add(name, flag, key, rows):
        out.append(Case("node_ip_" + name, raw=0x44, flag=flag, ip=(key[0], key[1:5]), ips=rows))

    add("insert_empty", 1, b"\x00\x01\x02\x03\x04", [])
    add("remove_empty", 0, b"\x00\x01\x02\x03\x04", [])
    add("insert_empty_odd", 1, b"\x01\x05\x00\x00\x00", [])
    add("insert_none_tag", 1, b"\x02\x01\x02\x03\x04", [])
    add("remove_none_tag", 0, b"\x02\x01\x02\x03\x04", ip_rows(3))
    add("insert_none_tag_rows", 1, b"\x02\x00\x00\x00\x00", ip_rows(3, 2))
    add("order_big_endian", 1, b"\x00\x01\x00\x00\x00", [b"\x00\x00\x00\x00\x02", b"\x00\x02\x00\x00\x00"])
    add("order_big_endian_low", 1, b"\x00\x00\x00\x01\x00", [b"\x00\x00\x00\x00\x02", b"\x00\x02\x00\x00\x00"])
    add("odd_same_first_byte", 1, b"\x01\x0B\x01\x02\x03", ip_rows(2, 3))
    add("odd_remove_other_tail", 0, b"\x01\x0B\x01\x02\x03", ip_rows(2, 3))
    add("odd_before_tag_two", 1, b"\x01\xFF\x00\x00\x00", ip_rows(2, 3))
    add("even_after_low_odd", 1, b"\x00\xFF\xFF\xFF\xFF", ip_rows(2, 3))
    for count, odd in ((1, 0), (3, 0), (5, 3), (10, 1), (8, 4), (12, 0), (13, 3), (30, 10), (140, 10)):
        rows = ip_rows(count, odd)
        for at in sorted({0, len(rows) // 2, len(rows) - 1}):
            add("insert_present_%d_%d_%d" % (count, odd, at), 1, rows[at], rows)
            add("remove_present_%d_%d_%d" % (count, odd, at), 0, rows[at], rows)
            key = rows[at]
            new = key[:4] + bytes(((key[4] + 7) & 0xFF,)) if key[0] == 0 else key[:1] + bytes(((key[1] + 1) & 0xFF,)) + key[2:]
            if not any(ip_order(row) == ip_order(new) for row in rows):
                add("insert_new_%d_%d_%d" % (count, odd, at), 1, new, rows)
                add("remove_absent_%d_%d_%d" % (count, odd, at), 0, new, rows)
    rows = ip_rows(12)
    for at in range(12):
        add("merge_%d" % at, 0, rows[at], rows)
    return out


def toggle_cases():
    out = []

    def add(name, rows, have, **fields):
        out.append(Case("toggle_" + name, raw=0x24, rows=sorted(rows), allowed=have, **fields))

    add("none", [], [])
    add("none_keeps", [], A[:3])
    add("add_one", [(A[0], 1)], [])
    add("add_present", [(A[1], 1)], A[:3])
    add("drop_one", [(A[1], 0)], A[:3])
    add("drop_absent", [(A[5], 0)], A[:3])
    add("drop_from_empty", [(A[5], 0)], [])
    add("mix", [(A[0], 1), (A[1], 0), (A[2], 1), (A[3], 0)], A[1:3])
    for count in (11, 12, 13, 30, 143, 150):
        add("all_new_%d" % count, [(key, 1) for key in spaced(count)], [])
        add("all_drop_%d" % count, [(key, 0) for key in spaced(count)], spaced(count))
        add("half_%d" % count, [(key, index & 1) for index, key in enumerate(spaced(count))], spaced(count, 1))
    add("split_leaf", [(A[0], 1), (between(A, 9), 1)], A[:30][::2][:11])
    add("split_inner", [(key, 1) for key in A[1:220:3]], A[0:220:3])
    add("too_long_hollow", [], [], lie_len=10001)
    add("too_long_hollow_top", [], A[:2], lie_len=TOP)
    add("exact_cap", [(key, 0) for key in POOL[:10000]], A[:2])
    add("over_cap", [(key, 1) for key in POOL[:10001]], A[:2])
    return out


def period_cases():
    pairs = ((0, 0), (5, 0), (0, 6), (5, 6), (1, 1), (CAP - 1, CAP - 1), (CAP - 1, 0), (0, CAP - 1), (CAP, 0), (0, CAP), (5, CAP), (CAP, 5), (TOP, TOP), (0, TOP), (TOP, 0), (CAP + 1, CAP + 2))
    return [Case("periods_%x_%x" % pair, raw=0x39, value=pair[0], value2=pair[1]) for pair in pairs]


def cvalidator_cases():
    out = [Case("cvalidator_ok", raw=0x3A, who=A[1])]
    for status in (0, 1, 0x130, 0x91, 0x185, 0x187):
        out.append(Case("cvalidator_status_%x" % status, raw=0x3A, who=A[2], cv_status=status))
    return out


def unjail_all_cases():
    out = []
    for count in (0, 1, 3, 11, 12, 40, 150):
        for votes, length in ((0, 0), (0x7000, 2), (0x7000, 11)):
            for jail in (0, 0x7100):
                out.append(Case("unjail_all_%d_%d_%d_%x" % (count, votes, length, jail), raw=0x3B, jailed=spaced(count), votes=votes, votes_len=length, jail_map=jail))
    return out


def max_cases():
    rows = ((0, 0), (0, 21), (0, TOP), (1, 0), (1, 1), (1, 21), (1, CAP - 1), (1, CAP), (1, CAP + 1), (1, TOP))
    out = [Case("max_%x_%x" % pair, raw=0x3C, tag=pair[0], value=pair[1]) for pair in rows]
    out += [Case("max_from_none_%x_%x" % pair, raw=0x3C, tag=pair[0], value=pair[1], max_tag=0) for pair in rows[:6]]
    return out


def refund_cases():
    keys, signers = A[:40], A[100:140]
    out = []

    def add(name, value, allowed, profiles, limits, **fields):
        out.append(Case("refund_" + name, raw=0x3F, value=value, allowed=allowed, profiles=profiles, limits=limits, **fields))

    pair = [(keys[index], signers[index]) for index in range(40)]
    add("nothing", 4, [], [], [])
    add("nothing_over_cap", CAP, [], [], [])
    add("nothing_top", TOP, [], [], [(signers[0], 9)])
    add("allowed_only", 4, keys[:3], [], [(signers[0], 9)])
    add("allowed_only_over_cap", CAP, keys[:3], [], [(signers[0], 9)])
    add("one", 4, [], pair[:1], [(signers[0], 9)])
    add("one_exact", 9, [], pair[:1], [(signers[0], 9)])
    add("one_more", 10, [], pair[:1], [(signers[0], 9)])
    add("one_zero", 0, [], pair[:1], [(signers[0], 9)])
    add("one_top_row", CAP - 1, [], pair[:1], [(signers[0], TOP)])
    add("one_cap_edge", CAP - 1, [], pair[:1], [(signers[0], CAP - 1)])
    add("one_over_cap", CAP, [], pair[:1], [(signers[0], 9)])
    add("one_over_cap_top", TOP, [], pair[:1], [(signers[0], 9)])
    add("no_limit_row", 4, [], pair[:1], [(signers[1], 9)])
    add("empty_limits", 4, [], pair[:2], [])
    add("empty_limits_over_cap", CAP, [], pair[:2], [])
    add("item_word_zero", 4, [], pair[:1], [(signers[0], 9)], limit_items=0)
    add("item_word_zero_over_cap", CAP, [], pair[:1], [(signers[0], 9)], limit_items=0)
    add("validator_is_signer_key", 4, [], [(keys[0], keys[0])], [(keys[0], 9)])
    add("limit_row_is_validator_not_signer", 4, [], pair[:1], [(keys[0], 9)])
    add("both_sets", 3, keys[:2], pair[:3], [(signers[0], 7), (signers[1], 7), (signers[2], 2)])
    add("shared_signer", 3, [], [(keys[0], signers[5]), (keys[1], signers[5]), (keys[2], signers[5])], [(signers[5], 8)])
    add("mixed_rows", 5, keys[:8], pair[4:12], [(signers[at], at + 2) for at in (4, 5, 6, 9, 11)])
    add("over_cap_after_missing", CAP, keys[:2], pair[1:3], [(signers[1], 9)])
    for count in (11, 12, 13, 30, 40):
        add("many_%d" % count, 2, keys[:count // 2], pair[:count], [(signers[at], at) for at in range(10)])
        add("many_over_cap_%d" % count, TOP, keys[:count // 2], pair[:count], [(signers[at], at) for at in range(10)])
    add("full_table", 1, [], pair[:14], [(signers[at], at) for at in range(14)])
    return out


def floor_cases():
    out = []
    for value in (0, 1, 1000, CAP - 1, CAP, TOP):
        for mode in (0, 1, 2, 3, 0x101, 0x10001):
            out.append(Case("floor_%x_%x" % (value, mode), raw=0x41, value=value, mode=mode))
    return out


def allow_all_cases():
    out = []
    for floor in (0, 1, 256, 1 << 63):
        for tag in (0, 1, 2):
            for flag in (0, 1):
                out.append(Case("allow_all_%x_%x_%d" % (floor, tag, flag), raw=0x42, floor=floor, max_tag=tag, flag=flag))
    return out


def guard_cases():
    out = []
    for value in (1, 2, 59, 60, 3600, 86400, 172799, 172800, 172801, 1 << 31, 1 << 32, CAP - 1, CAP, CAP + 1, TOP):
        out.append(Case("decay_%x" % value, raw=0x45, value=value))
    for value in (0, 1, 2, 59, 60, 3600, 86400, 172799, 172800, 172801, 1 << 31, 1 << 32, CAP - 1, CAP, CAP + 1, TOP):
        out.append(Case("reward_%x" % value, raw=0x46, value=value))
    dates = ((2026, 300), (2024, 366), (2000, 60), (1971, 1), (1970, 2), (1970, 1), (1969, 365), (1900, 59), (1, 1), (0, 1), (-1, 1), (-400, 1), (-401, 200), (262000, 100))
    for year, ordinal in dates:
        for secs, nanos in ((0, 0), (1, 999999), (86399, 1000000), (86399, 1999999999), (43200, 500000000)):
            for value in (1, 3600, 172800):
                out.append(Case("reward_clock_%d_%d_%d_%d_%d" % (year, ordinal, secs, nanos, value), raw=0x46, value=value, date=(year << 13) | (ordinal << 4) | 2, secs=secs, nanos=nanos))
    return out


def named_cases():
    out = toggle_cases() + set_cases("broadcaster", 0x38, "broadcasters") + period_cases() + cvalidator_cases() + unjail_all_cases() + max_cases() + jail_cases() + refund_cases() + floor_cases() + allow_all_cases() + set_cases("disabled", 0x43, "disabled") + ip_cases() + guard_cases()
    seen = set()
    for case in out:
        if case.name in seen:
            raise EvidenceError("repeated case %s" % case.name)
        seen.add(case.name)
    return out


def vector_cases(count):
    picker = random.Random(0x94)
    out = []
    values = (0, 1, 2, 7, 60, 3600, 172800, 172801, 1 << 20, CAP - 1, CAP, TOP)
    for index in range(count):
        raw = picker.choice((0x24, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3E, 0x3F, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46))
        rows = sorted(picker.sample(A[:80], picker.choice((0, 1, 2, 5, 11, 12, 20, 30))))
        pick = picker.choice(A[:80])
        name = "vector_%d" % index
        value = picker.choice(values) if raw != 0x45 else picker.choice(values[1:])
        if raw == 0x24:
            out.append(Case(name, raw=raw, rows=[(key, picker.getrandbits(1)) for key in rows], allowed=sorted(picker.sample(A[:80], 10))))
        elif raw == 0x38:
            out.append(Case(name, raw=raw, flag=picker.getrandbits(1), who=pick, broadcasters=rows))
        elif raw == 0x39:
            out.append(Case(name, raw=raw, value=value, value2=picker.choice(values)))
        elif raw == 0x3A:
            out.append(Case(name, raw=raw, who=pick, cv_status=picker.choice((OK, 0x91, 0x130))))
        elif raw == 0x3B:
            out.append(Case(name, raw=raw, jailed=rows, votes=picker.choice((0, 0x7000)), votes_len=2, jail_map=picker.choice((0, 0x7100))))
        elif raw == 0x3C:
            out.append(Case(name, raw=raw, tag=picker.getrandbits(1), value=value))
        elif raw == 0x3E:
            out.append(Case(name, raw=raw, who=pick, jailed=rows))
        elif raw == 0x3F:
            keys = sorted(picker.sample(A[:40], picker.choice((0, 1, 3, 12, 14))))
            signers = [picker.choice(A[100:112]) for _ in keys]
            hold = picker.sample(A[100:112], picker.choice((0, 3, 8, 12)))
            out.append(Case(name, raw=raw, value=value, allowed=sorted(picker.sample(A[:40], 3)), profiles=list(zip(keys, signers)), limits=sorted((key, picker.choice(values)) for key in hold)))
        elif raw == 0x41:
            out.append(Case(name, raw=raw, value=value, mode=picker.choice((0, 1, 2))))
        elif raw == 0x42:
            out.append(Case(name, raw=raw, flag=picker.getrandbits(1), floor=picker.choice((0, 5)), max_tag=picker.choice((0, 1))))
        elif raw == 0x43:
            out.append(Case(name, raw=raw, flag=picker.getrandbits(1), who=pick, disabled=rows))
        elif raw == 0x44:
            have = ip_rows(picker.randrange(0, 20), picker.randrange(0, 6))
            key = picker.choice(have) if have and picker.getrandbits(1) else bytes((picker.randrange(0, 3), picker.randrange(256), 3, 4, picker.randrange(256)))
            out.append(Case(name, raw=raw, flag=picker.getrandbits(1), ip=(key[0], key[1:5]), ips=have))
        elif raw == 0x45:
            out.append(Case(name, raw=raw, value=value))
        else:
            out.append(Case(name, raw=raw, value=value, date=(picker.randrange(1960, 2100) << 13) | (picker.randrange(1, 366) << 4) | 2, secs=picker.randrange(86400), nanos=picker.randrange(2000000000)))
    return out


NAMES = {DISPATCH: "vote_global_apply", LIST_CAP: "toggle_list_cap", UNJAIL: "jailed_remove", CLEAR_SET: "jailed_clear", CLEAR_VOTES: "votes_clear", CLEAR_JAIL: "jail_until_clear", MERGE_HOST: "validator_keys_union_host", MERGE: "validator_keys_union",
         IP_INSERT: "node_ip_insert", IP_REMOVE: "node_ip_remove", SET_INSERT: "address_set_insert", SET_REMOVE: "address_set_remove", BROAD_INSERT: "broadcaster_insert", BROAD_REMOVE: "broadcaster_remove", GUARD_EPOCH: "guard_from_seconds", GUARD_BLOCK: "guard_from_block_time"}
ARMS = ((0x24, 0x235880C, "allowed_validators", "map of address to bool, inserts true rows, removes false rows, at most 10000 rows"), (0x38, 0x235911A, "broadcasters", "one address and a bool"), (0x39, 0x2358ECB, "stakes.period, jailed_signers.period", "two words, zero keeps the old value"),
        (0x3A, 0x2357356, "CValidator body", "calls 0x2768ff0 for a named validator"), (0x3B, 0x23582AE, "jailed_signers.current, jail vote map, jail_until", "drops all three"), (0x3C, 0x2358F86, "stakes.current.max_n_validators", "Option word pair"), (0x3E, 0x2356CB4, "jailed_signers.current", "removes one signer"),
        (0x3F, 0x23589E6, "request limit rows", "subtracts a word for the signer of every profile"), (0x41, 0x2356920, "self_delegation_requirement", "writes only when Exchange +0x80 is 1"), (0x42, 0x2356D8D, "allow_all_validators", "writes only when requirement and stakes tag are not zero"),
        (0x43, 0x23572A3, "disabled_validators", "one address and a bool"), (0x44, 0x2356295, "disabled_node_ips", "five byte key and a bool"), (0x45, 0x23593AB, "stakes_decay_bucket_guard", "guard width, bucket from a fixed date"), (0x46, 0x2359278, "distribute_reward_bucket_guard", "guard width, bucket from block time"))
COPIES = ((0x4CAA870, 0x711064, 0), (0x4CB3200, 0x711244, SHIFT))
TEXTS = ("stakes", "allowed_validators", "allow_all_validators", "broadcasters", "validator_to_profile", "stakes_decay_bucket_guard", "jailed_signers", "jvt", "jail_until", "distribute_reward_bucket_guard", "self_delegation_requirement", "disabled_validators", "disabled_node_ips", "max_n_validators", "struct CValidatorStakes with 2 elements", "struct EpochTracker with 5 elements", "tuple variant VoteGlobalAction::DisableCValidator with 2 elements", "tuple variant VoteGlobalAction::DisableNodeIp with 2 elements", "struct variant VoteGlobalAction::ModifyCStakingPeriods with 2 elements", "struct variant VoteGlobalAction::UnjailSigner with 1 element", "struct variant VoteGlobalAction::CValidator with 2 elements")
BOUNDARY = ((CVALIDATOR, "stub", "CValidator body, covered by the delegate entry packet; signer, action bytes recorded, status by case"), (DROP_ACTION, "stub", "drop of the action payload, offset recorded"), (DROP_STATUS, "stub", "drop of the success value, tag recorded"),
            (LAZY, "stub", "lazy read of a process wide value, result unused by the arm"), (VOTE_NEXT, "stub", "next row of the jail vote map, iterator words recorded, returns none"), (JAIL_DROP, "stub", "drop of the jail_until map, three words recorded"))
SAMPLE = 1
MUTANT_CASES = 12
WORKERS = 3
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a register choice or a word no rule reads"
MUTANT_STATE = {}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


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
            if not compare(run_case(harness, case), want, case):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, struct.error):
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
    harness = Harness(state["image"], patch, state["cache"])
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases, reach, cost, cache):
    wants = {case.name: spec_run(case) for case in cases}
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=cache)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return pool.map(mutant_job, jobs[::SAMPLE], 4)


def check_case(harness, case):
    got, want = run_case(harness, case), spec_run(case)
    if not compare(got, want, case):
        raise EvidenceError("%s: %r differs from %r" % (case.name, [item for item in got if item not in want][:3], [item for item in want if item not in got][:3]))
    return want


def describe(case, want):
    row = dict((item[0], item[1:]) for item in want if item[0] in ("status", "payload"))
    calls = " ".join(item[0] for item in want if item[0] in ("cvalidator", "drop_status", "drop_action", "lazy", "votes", "jail_map"))
    diff = [item for item in want if item[0] == "diff"][0][1]
    rows = " ".join("%d" % len(item[2]) for item in want if item[0] == "rows")
    return "raw %#x status %#x%s calls [%s] changed_bytes %d rows %s" % (case.raw, row["status"][0], " payload %#x" % row["payload"][0] if "payload" in row else "", calls, len(diff), rows)


def table_rows(image):
    blob = image.blob
    base = image.offset(TABLE)
    arms = [TABLE + struct.unpack_from("<i", blob, base + 4 * index)[0] for index in range(TABLE_ROWS)]
    if struct.unpack("<i", bytes(blob[image.offset(DISPATCH + 0x2F + 3):image.offset(DISPATCH + 0x2F + 7)]))[0] + DISPATCH + 0x2F + 7 != TABLE:
        raise EvidenceError("dispatcher table moved")
    rows = []
    low, high = image.exact_fde(DISPATCH)
    for raw, arm, field, note in ARMS:
        found = arms[raw - TABLE_BASE_TAG]
        if found != arm or not low <= found < high:
            raise EvidenceError("arm %#x at %#x, not %#x" % (raw, found, arm))
        rows.append(("%#x" % raw, "%#x" % arm, field, note))
    return rows


def copy_job(job):
    case, entry, shift, table = job
    harness = MUTANT_STATE.setdefault("copy_harness", None) or Harness(MUTANT_STATE["image"])
    MUTANT_STATE["copy_harness"] = harness
    return compare(run_arm(harness, case, entry, shift), spec_run(case, table), case)


def copy_rows(image, cases):
    """Each copy has its own jump table and its own helper copies; the same cases run through it."""
    rows = []
    blob = image.blob
    picked = [case for case in cases if len(case.rows) < 1000]
    MUTANT_STATE["image"] = image
    for copy, table, shift in COPIES:
        low, high = image.exact_fde(copy)
        offset = image.offset(table)
        arms = [table + struct.unpack_from("<i", blob, offset + 4 * index)[0] for index in range(TABLE_ROWS)]
        if not all(low <= arm < high for arm in arms):
            raise EvidenceError("copy table leaves %#x" % copy)
        with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
            same = pool.map(copy_job, [(case, copy, shift, table) for case in picked], 16)
        if not all(same):
            raise EvidenceError("copy %#x differs on %s" % (copy, picked[same.index(False)].name))
        rows.append(("%#x" % copy, high - low, "%#x" % table, "%#x" % shift, len(same), " ".join("%#x:%#x" % (raw, arms[raw - TABLE_BASE_TAG]) for raw, _, _, _ in ARMS)))
    return rows


def variant_rows(image):
    rows = []
    for name, va, slot, raw in VARIANT_TAGS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + 12])
        if data[:4] != bytes.fromhex("48c78424") or struct.unpack("<I", data[4:8])[0] != slot or struct.unpack("<i", data[8:12])[0] != raw:
            raise EvidenceError("tag store moved at %#x" % va)
        rows.append((name, "%#x" % va, "%#x" % image.fde(va)[0], "%#x" % raw))
    return rows


def text_rows(image):
    rows = []
    blob = bytes(image.blob)
    for text in TEXTS:
        at = blob.find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    return rows


def constant_rows(image):
    rows = []
    for va, size, meaning, want in CONSTANTS:
        data = bytes(image.blob[image.offset(va):image.offset(va) + size])
        if data.hex() != want:
            raise EvidenceError("constant moved at %#x: %s" % (va, data.hex()))
        rows.append(("%#x" % va, data.hex(), meaning))
    return rows


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    named, reach, cost = [], {}, {}
    for case in cases:
        harness.machine.seen = set()
        before = harness.machine.steps
        want = check_case(harness, case)
        named.append((case, want))
        reach[case.name], cost[case.name] = harness.machine.seen, harness.machine.steps - before
    seen = set()
    for rows in reach.values():
        seen |= rows
    generated = vector_cases(vectors)
    harness.machine.seen = seen
    outcomes = collections.Counter()
    for case in generated:
        want = check_case(harness, case)
        outcomes["%#x %#x" % (case.raw, want[0][1])] += 1
    table = {}
    for target in sorted(NAMES):
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    result = dict(table=table, named=named, vector_count=len(generated), outcomes=sorted(outcomes.items()), texts=text_rows(image), copies=copy_rows(image, cases), arms=table_rows(image), variants=variant_rows(image), constants=constant_rows(image), sizes={target: image.exact_fde(target)[1] - target for target in NAMES})
    if mutate:
        result["mutations"] = run_mutants(image, table, cases, reach, cost, harness.machine.cache)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table, sizes = result["table"], result["sizes"]
    order = sorted(NAMES)
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in order for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in order])
    tsv("boundary.tsv", ("address_or_slot", "kind", "meaning"), [("%#x" % va, kind, text) for va, kind, text in BOUNDARY])
    tsv("arms.tsv", ("raw_tag", "arm", "field", "rule"), result["arms"])
    tsv("copies.tsv", ("copy", "body_bytes", "jump_table", "state_shift", "cases_matched", "arms"), result["copies"])
    tsv("variant-tags.tsv", ("wire_variant", "tag_store", "reader", "raw_tag"), result["variants"])
    tsv("constants.tsv", ("address", "bytes", "meaning"), result["constants"])
    tsv("texts.tsv", ("file_offset", "text"), result["texts"])
    tsv("scenarios.tsv", ("case", "outcome"), [(case.name, describe(case, want)) for case, want in result["named"]])
    tsv("vector-outcomes.tsv", ("raw_and_status", "cases"), result["outcomes"])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "arms": len(result["arms"]), "copies": len(result["copies"])}
    if "mutations" in result:
        items = result["mutations"]
        summary["mutations"] = {"total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived"), "sample_every": SAMPLE}
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
