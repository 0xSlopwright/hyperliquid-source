#!/usr/bin/env python3
"""Pin node #94 CStaking state wire form both ways: msgpack and JSON writers, msgpack and JSON readers.

0x39908e0 and 0x3990470 write the 22 field state, 0x175f130 and 0x1d0cb80 read it. The real bytes run in an interpreter inside
this tool with every callee real: a state goes in through a real reader, comes back through the real writers, and a separately
written rule list predicts every byte and every error text. Every reached conditional row and immediate in the named functions
is mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/cstaking_state_wire.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import multiprocessing
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
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
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


SERIALIZE_RMP = 0x39908E0
SERIALIZE_JSON = 0x3990470
DECODE_RMP = 0x175F130
RMP_COPIES = (0x2BC6810, 0x3EDA980)
DECODE_JSON = 0x1D0CB80
JSON_COPIES = (0x318D7D0,)
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
MARK_BASE = 0x7700000000

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x400000
ARENA_END = HEAP_BASE + 0x2F0000
OUT = HEAP_BASE + 0x100
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
INDENT_AT = SERIALIZER + 0x80
DECODER = HEAP_BASE + 0x6000
DECODED = HEAP_BASE + 0x8000
INPUT = HEAP_BASE + 0x2F0000
STATUS_OK = 0x8000000000000004
ERROR_WORD = 2
STATE_SIZE = 0x298
LONG_STEP_LIMIT = 6000000
MUTANT_STEP_LIMIT = 900000


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = image.real_set()
        machine.step_limit = LONG_STEP_LIMIT
        machine.memory.statics = image.static_view()
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.live = {}

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

    def fresh(self):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}

    def decode_rmp(self, data, entry=DECODE_RMP):
        self.fresh()
        self.put(INPUT, data)
        self.write(DECODER + 0x10, INPUT)
        self.write(DECODER + 0x18, len(data))
        self.write(DECODER + 0x20, 1, 1)
        self.write(DECODER + 0x22, 1024, 2)
        self.machine.run(entry, {RDI: DECODED, RSI: DECODER, RDX: 0})
        if self.read(DECODED) != ERROR_WORD:
            return ("ok",)
        tag = self.read(DECODED + 8, 1)
        if tag == 6:
            return ("error", self.data(self.read(DECODED + 0x18), self.read(DECODED + 0x20)).decode())
        return ("kind", tag)

    def decode_json(self, text, entry=DECODE_JSON):
        self.fresh()
        data = text.encode()
        self.put(INPUT, data)
        for offset in range(0, 0x60, 8):
            self.write(DECODER + offset, 0)
        self.write(DECODER + 0x18, INPUT)
        self.write(DECODER + 0x20, len(data))
        self.write(DECODER + 0x48, 128, 1)
        self.machine.run(entry, {RDI: DECODED, RSI: DECODER})
        if self.read(DECODED) != ERROR_WORD:
            return ("ok",)
        box = self.read(DECODED + 8)
        self.expect(self.read(box) == 0, "serde_json error with a text")
        return ("error", self.data(self.read(box + 8), self.read(box + 0x10)).decode())

    def writer(self):
        pointer = self.alloc(0x20000)
        self.write(WRITER, 0x20000)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)

    def pack(self, named, human):
        self.writer()
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, 0)
        self.write(SERIALIZER + 0xA, human, 1)
        self.write(SERIALIZER + 0xB, named, 1)
        self.machine.run(SERIALIZE_RMP, {RDI: OUT, RSI: DECODED, RDX: SERIALIZER})
        self.expect(self.read(OUT) == STATUS_OK, "serializer status %#x" % self.read(OUT))
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).hex()

    def text(self, indent):
        self.writer()
        self.put(INDENT_AT, indent.encode())
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, INDENT_AT)
        self.write(SERIALIZER + 0x10, len(indent))
        self.write(SERIALIZER + 0x18, 0)
        self.write(SERIALIZER + 0x20, 0xEE, 1)
        self.machine.run(SERIALIZE_JSON, {RDI: DECODED, RSI: SERIALIZER})
        self.expect(self.machine.regs[RAX] == 0, "json status")
        self.expect(self.read(SERIALIZER + 0x18) == 0, "indent level back at its start")
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).decode()


REQUIRED = object()
ADDRESS_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 20 bytes"
HASH_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 32 bytes"
TIME_TEXT = "a formatted date and time string"
MAP_TEXT = "a map or a sequence of tuples"
ADDRESS = ("addr",)
HASH = ("hash",)
TIME = ("time",)
WEI = ("wei",)
U64 = ("u64",)
USIZE = ("usize",)
NONZERO = ("nonzero",)
BOOL = ("bool",)
TEXT = ("text",)
U16 = ("u16",)
IP = ("ip",)
UNIT = ("unit",)


def struct_of(name):
    return ("struct", name)


def map_of(key, value):
    return ("map", key, value)


def set_of(item):
    return ("set", item)


def seq_of(item):
    return ("seq", item)


def opt_of(item):
    return ("opt", item)


def tracker_of(name):
    return ("struct", name)


STAKES = struct_of("CValidatorStakes")
SIGNERS = set_of(ADDRESS)
STRUCTS = {
    "CStaking": (("stakes", struct_of("EpochTracker_stakes"), REQUIRED), ("allowed_validators", set_of(ADDRESS), REQUIRED), ("allow_all_validators", BOOL, REQUIRED), ("broadcasters", set_of(ADDRESS), REQUIRED), ("validator_to_profile", map_of(ADDRESS, struct_of("CValidatorProfile")), REQUIRED), ("delegations", struct_of("Delegations"), REQUIRED), ("proposals", map_of(HASH, struct_of("Proposal")), REQUIRED), ("stakes_decay_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("jailed_signers", struct_of("EpochTracker_signers"), REQUIRED), ("jvt", struct_of("RawSignatureTracker"), "jail vote tracker"), ("jail_until", map_of(ADDRESS, TIME), REQUIRED), ("signer_to_last_manual_unjail_time", map_of(ADDRESS, TIME), REQUIRED), ("native_token_reserve", opt_of(WEI), None), ("stage_reward_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("validator_to_staged_rewards", map_of(ADDRESS, WEI), REQUIRED), ("distribute_reward_bucket_guard", struct_of("BucketGuard"), REQUIRED), ("user_states", map_of(ADDRESS, struct_of("UserState")), REQUIRED), ("pending_withdrawals", struct_of("PendingWithdrawals"), REQUIRED), ("self_delegation_requirement", WEI, REQUIRED), ("disabled_validators", set_of(ADDRESS), ()), ("disabled_node_ips", set_of(IP), ()), ("validator_to_state", map_of(ADDRESS, struct_of("CValidatorState")), ())),
    "EpochTracker_stakes": (("epoch_values", struct_of("EpochValues_stakes"), REQUIRED), ("current", STAKES, REQUIRED), ("period", NONZERO, REQUIRED), ("n_keep", USIZE, REQUIRED), ("current_round", U64, REQUIRED)),
    "EpochValues_stakes": (("initial_round", U64, REQUIRED), ("round_to_val", map_of(U64, STAKES), REQUIRED)),
    "EpochTracker_signers": (("epoch_values", struct_of("EpochValues_signers"), REQUIRED), ("current", SIGNERS, REQUIRED), ("period", NONZERO, REQUIRED), ("n_keep", USIZE, REQUIRED), ("current_round", U64, REQUIRED)),
    "EpochValues_signers": (("initial_round", U64, REQUIRED), ("round_to_val", map_of(U64, SIGNERS), REQUIRED)),
    "CValidatorStakes": (("max_n_validators", opt_of(USIZE), None), ("validator_to_stake", map_of(ADDRESS, struct_of("CValidatorStake")), REQUIRED)),
    "CValidatorStake": (("effective", WEI, 0), ("target", WEI, 0)),
    "CValidatorProfile": (("node_ip", IP, REQUIRED), ("name", TEXT, REQUIRED), ("description", TEXT, REQUIRED), ("delegations_disabled", BOOL, False), ("commission_bps", U64, 10000), ("signer", ADDRESS, REQUIRED)),
    "Delegations": (("user_to_delegations", map_of(ADDRESS, map_of(ADDRESS, struct_of("Delegation"))), REQUIRED), ("validator_to_state", map_of(ADDRESS, struct_of("ValidatorState")), REQUIRED)),
    "Delegation": (("t", TIME, REQUIRED), ("w", WEI, REQUIRED)),
    "ValidatorState": (("total_delegated", WEI, REQUIRED), ("delegator_to_epoch_delegation", map_of(ADDRESS, struct_of("EpochDelegation")), REQUIRED)),
    "EpochDelegation": (("c", WEI, REQUIRED), ("m", WEI, REQUIRED), ("e", U64, REQUIRED)),
    "Proposal": (("title", TEXT, REQUIRED), ("description", TEXT, REQUIRED), ("end", TIME, REQUIRED), ("votes", map_of(ADDRESS, struct_of("Vote")), REQUIRED), ("proposer", ADDRESS, REQUIRED), ("quorum", U64, REQUIRED), ("category", ("names", ("accelerated", "constitutional", "ecosystem", "electoral")), REQUIRED)),
    "Vote": (("choice", ("names", ("yes", "no", "abstain")), REQUIRED), ("weight", U64, REQUIRED)),
    "BucketGuard": (("last_bucket", U64, REQUIRED), ("bucket_millis", NONZERO, REQUIRED)),
    "RawSignatureTracker": (("name", TEXT, REQUIRED), ("hsc", UNIT, None), ("i", map_of(ADDRESS, struct_of("UniqueKeyState")), REQUIRED)),
    "UserState": (("b", WEI, 0), ("l", opt_of(TIME), None)),
    "PendingWithdrawals": (("queue", map_of(TIME, seq_of(struct_of("CWithdrawal"))), REQUIRED), ("user_to_total_withdrawal", map_of(ADDRESS, struct_of("TotalWithdrawal")), REQUIRED)),
    "CWithdrawal": (("user", ADDRESS, REQUIRED), ("wei", WEI, REQUIRED)),
    "TotalWithdrawal": (("wei", WEI, REQUIRED), ("n", USIZE, REQUIRED)),
    "CValidatorState": (("register_time", TIME, REQUIRED), ("last_signer_change_time", TIME, REQUIRED), ("delegations_blocked", BOOL, REQUIRED)),
    "UniqueKeyState": (("arq", BOOL, REQUIRED), ("qst", ("names", ("Q", "N")), "N"), ("vts", map_of(("nil_key",), ("opaque",)), REQUIRED)),
}
NAME_OF = {"EpochTracker_stakes": "EpochTracker", "EpochTracker_signers": "EpochTracker", "EpochValues_stakes": "EpochValues", "EpochValues_signers": "EpochValues"}
SKIP_WHEN_DEFAULT = {"UserState"}
ARRAY_REQUIRED = {"native_token_reserve", "max_n_validators"}


def wire_name(name):
    return NAME_OF.get(name, name)


def stamp(text):
    """A time text in the shortest of the 0, 3, 6, 9 fraction forms."""
    if "." not in text:
        return text
    head, tail = text.split(".")
    nanos = int(tail.ljust(9, "0"))
    if nanos == 0:
        return head
    if nanos % 1000000 == 0:
        return "%s.%03d" % (head, nanos // 1000000)
    if nanos % 1000 == 0:
        return "%s.%06d" % (head, nanos // 1000)
    return "%s.%09d" % (head, nanos)


def order_of(kind, value):
    if kind == IP:
        return (0, value[1]) if value[0] == "Ip" else (1, value[1])
    return value


def default_for(kind, rule):
    if rule == "jail vote tracker":
        return dict(name=rule, hsc=None, i=[])
    if kind == opt_of(WEI) or kind[0] == "opt":
        return None
    if isinstance(rule, tuple):
        return []
    return rule


def canon(kind, value):
    """Fill defaults and put maps and sets in their sorted order."""
    tag = kind[0]
    if tag == "struct":
        out = {}
        for field, inner, rule in STRUCTS[kind[1]]:
            if field in value:
                out[field] = canon(inner, value[field])
            else:
                out[field] = default_for(inner, rule)
        return out
    if tag == "map":
        rows = [(canon(kind[1], key), canon(kind[2], item)) for key, item in value]
        return sorted(rows, key=lambda row: order_of(kind[1], row[0]))
    if tag == "set":
        return sorted({tuple(item) if kind[1] == IP else item for item in value}, key=lambda item: order_of(kind[1], item))
    if tag == "seq":
        return [canon(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else canon(kind[1], value)
    if kind == TIME:
        return stamp(value)
    if kind == IP:
        return tuple(value)
    if kind == ADDRESS or kind == HASH:
        return value.lower()
    return value


def mp_head(size, small, wide16, wide32):
    if size < 16:
        return bytes([small | size])
    if size < 0x10000:
        return bytes([wide16]) + size.to_bytes(2, "big")
    return bytes([wide32]) + size.to_bytes(4, "big")


def mp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_text(text):
    data = text.encode()
    if len(data) < 32:
        return bytes([0xA0 | len(data)]) + data
    if len(data) < 256:
        return bytes([0xD9, len(data)]) + data
    return b"\xda" + len(data).to_bytes(2, "big") + data


def emit(kind, value, named, human):
    """Canonical value to msgpack, by the rule list of this packet."""
    tag = kind[0]
    if tag == "struct":
        rows = STRUCTS[kind[1]]
        kept = [row for row in rows if not (kind[1] in SKIP_WHEN_DEFAULT and value[row[0]] == row[2])]
        size = len(kept)
        out = mp_head(size, 0x80, 0xDE, 0xDF) if named else mp_head(size, 0x90, 0xDC, 0xDD)
        for field, inner, _ in kept:
            if named:
                out += mp_text(field)
            out += emit(inner, value[field], named, human)
        return out
    if tag == "map":
        out = mp_head(len(value), 0x90, 0xDC, 0xDD)
        for key, item in value:
            out += b"\x92" + emit(kind[1], key, named, human) + emit(kind[2], item, named, human)
        return out
    if tag in ("set", "seq"):
        return mp_head(len(value), 0x90, 0xDC, 0xDD) + b"".join(emit(kind[1], item, named, human) for item in value)
    if tag == "opt":
        return b"\xc0" if value is None else emit(kind[1], value, named, human)
    if kind == UNIT:
        return b"\x90" if value is None else mp_text(value)
    if tag == "bool":
        return b"\xc3" if value else b"\xc2"
    if tag in ("u64", "usize", "nonzero", "wei", "u16"):
        return mp_uint(value)
    if kind == QST and value == "Q":
        return b"\x81" + mp_text("Q") + b"\xc0"
    if tag in ("addr", "hash", "time", "text", "names"):
        return mp_text(value)
    if kind == IP:
        if value[0] == "LocalNode":
            return b"\x81" + mp_text("LocalNode") + mp_uint(value[1])
        if human:
            return b"\x81" + mp_text("Ip") + mp_text(value[1])
        return b"\x81" + mp_text("Ip") + b"\x94" + b"".join(mp_uint(int(part)) for part in value[1].split("."))
    raise EvidenceError("no rule for %s" % (kind,))


def plain(kind, value):
    """Canonical value to the object tree of the JSON form."""
    tag = kind[0]
    if tag == "struct":
        return {field: plain(inner, value[field]) for field, inner, _ in STRUCTS[kind[1]] if not (kind[1] in SKIP_WHEN_DEFAULT and value[field] == _)}
    if tag == "map":
        return [[plain(kind[1], key), plain(kind[2], item)] for key, item in value]
    if tag in ("set", "seq"):
        return [plain(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else plain(kind[1], value)
    if kind == IP:
        return {value[0]: value[1]}
    if kind == QST and value == "Q":
        return {"Q": None}
    return value


ROOT = struct_of("CStaking")
QST = ("names", ("Q", "N"))


def wire_input(kind, value, named=True):
    """Input bytes for the msgpack decoder: friendly values, strings for Ip, no skipped fields."""
    tag = kind[0]
    if tag == "struct":
        rows = [row for row in STRUCTS[kind[1]] if row[0] in value]
        out = mp_head(len(rows), 0x80, 0xDE, 0xDF) if named else mp_head(len(rows), 0x90, 0xDC, 0xDD)
        for field, inner, _ in rows:
            if named:
                out += mp_text(field)
            out += wire_input(inner, value[field], named)
        return out
    if tag == "map":
        out = mp_head(len(value), 0x90, 0xDC, 0xDD)
        for key, item in value:
            out += b"\x92" + wire_input(kind[1], key, named) + wire_input(kind[2], item, named)
        return out
    if tag in ("set", "seq"):
        return mp_head(len(value), 0x90, 0xDC, 0xDD) + b"".join(wire_input(kind[1], item, named) for item in value)
    if tag == "opt":
        return b"\xc0" if value is None else wire_input(kind[1], value, named)
    if kind == IP:
        return b"\x81" + mp_text(value[0]) + (mp_text(value[1]) if value[0] == "Ip" else mp_uint(value[1]))
    if kind == UNIT:
        return b"\x90" if value is None else mp_text(value)
    return emit(kind, value, True, True)


def json_input(kind, value):
    tag = kind[0]
    if tag == "struct":
        return {field: json_input(inner, value[field]) for field, inner, _ in STRUCTS[kind[1]] if field in value}
    if tag == "map":
        return [[json_input(kind[1], key), json_input(kind[2], item)] for key, item in value]
    if tag in ("set", "seq"):
        return [json_input(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else json_input(kind[1], value)
    if kind == IP:
        return {value[0]: value[1]}
    if kind == QST and value == "Q":
        return {"Q": None}
    return value


def address(seed):
    return "0x" + bytes((seed * 7 + index * 13 + 1) & 0xFF for index in range(20)).hex()


def digest(seed):
    return "0x" + bytes((seed * 11 + index * 5 + 3) & 0xFF for index in range(32)).hex()


TIME_A = "2024-01-02T03:04:05.123456789"
TIME_B = "2025-11-30T23:59:59.5"
TIME_C = "2023-06-07T08:09:10"
GUARD_1 = dict(last_bucket=1700000000000, bucket_millis=60000)
GUARD_2 = dict(last_bucket=1700000001000, bucket_millis=70000)
GUARD_3 = dict(last_bucket=1700000002000, bucket_millis=80000)


def stakes_row(seed):
    return dict(max_n_validators=seed + 21, validator_to_stake=[[address(seed), dict(effective=seed * 1000 + 1, target=seed * 1000 + 2)], [address(seed + 1), dict(effective=seed * 1000 + 3, target=seed * 1000 + 4)]])


def full_state():
    return dict(
        stakes=dict(epoch_values=dict(initial_round=4001, round_to_val=[[4002, stakes_row(3)], [4003, dict(validator_to_stake=[[address(9), dict(effective=9, target=0)]])]]), current=stakes_row(5), period=86401, n_keep=7, current_round=4004),
        allowed_validators=[address(1), address(2)], allow_all_validators=True, broadcasters=[address(3)],
        validator_to_profile=[[address(4), dict(node_ip=("Ip", "10.20.30.40"), name="alpha", description="first", delegations_disabled=True, commission_bps=512, signer=address(5))], [address(6), dict(node_ip=("LocalNode", 9), name="b", description="", signer=address(7))]],
        delegations=dict(user_to_delegations=[[address(8), [[address(4), dict(t=TIME_A, w=900)], [address(6), dict(t=TIME_B, w=901)]]]], validator_to_state=[[address(4), dict(total_delegated=902, delegator_to_epoch_delegation=[[address(8), dict(c=903, m=904, e=905)]])]]),
        proposals=[[digest(1), dict(title="raise", description="more", end=TIME_B, votes=[[address(1), dict(choice="yes", weight=906)], [address(2), dict(choice="abstain", weight=907)]], proposer=address(1), quorum=908, category="ecosystem")]],
        stakes_decay_bucket_guard=dict(GUARD_1),
        jailed_signers=dict(epoch_values=dict(initial_round=5001, round_to_val=[[5002, [address(10), address(11)]]]), current=[address(12)], period=5003, n_keep=5004, current_round=5005),
        jvt=dict(name="votes", hsc=None, i=[[address(13), dict(arq=True, qst="N", vts=[])]]),
        jail_until=[[address(14), TIME_A], [address(15), TIME_C]], signer_to_last_manual_unjail_time=[[address(16), TIME_B]], native_token_reserve=909,
        stage_reward_bucket_guard=dict(GUARD_2), validator_to_staged_rewards=[[address(17), 910], [address(18), 911], [address(19), 912]], distribute_reward_bucket_guard=dict(GUARD_3),
        user_states=[[address(20), dict(b=913, l=TIME_A)], [address(21), dict(b=914)], [address(22), dict(l=TIME_B)], [address(23), dict()]],
        pending_withdrawals=dict(queue=[[TIME_B, [dict(user=address(24), wei=915), dict(user=address(25), wei=916)]], [TIME_A, [dict(user=address(26), wei=917)]]], user_to_total_withdrawal=[[address(24), dict(wei=1831, n=2)]]),
        self_delegation_requirement=10000000000000,
        disabled_validators=[address(27)], disabled_node_ips=[("Ip", "1.2.3.4"), ("LocalNode", 200), ("Ip", "1.2.3.3")],
        validator_to_state=[[address(28), dict(register_time=TIME_A, last_signer_change_time=TIME_B, delegations_blocked=True)]])


def least_state():
    return dict(
        stakes=dict(epoch_values=dict(initial_round=0, round_to_val=[]), current=dict(validator_to_stake=[]), period=1, n_keep=0, current_round=0),
        allowed_validators=[], allow_all_validators=False, broadcasters=[], validator_to_profile=[], delegations=dict(user_to_delegations=[], validator_to_state=[]), proposals=[],
        stakes_decay_bucket_guard=dict(last_bucket=0, bucket_millis=1), jailed_signers=dict(epoch_values=dict(initial_round=0, round_to_val=[]), current=[], period=1, n_keep=0, current_round=0),
        jail_until=[], signer_to_last_manual_unjail_time=[], stage_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1), validator_to_staged_rewards=[], distribute_reward_bucket_guard=dict(last_bucket=0, bucket_millis=1),
        user_states=[], pending_withdrawals=dict(queue=[], user_to_total_withdrawal=[]), self_delegation_requirement=0)


class Case:
    """form: rmp, array, json, raw. want: ok from the rule list, or an error row."""

    def __init__(self, name, state=None, data=None, form="rmp", want=None, entry=None):
        self.name, self.state, self.data, self.form, self.want, self.entry = name, state, data, form, want, entry


def spec_run(case):
    if case.want is not None:
        return case.want
    value = canon(ROOT, case.state)
    return ("ok", emit(ROOT, value, True, False).hex(), emit(ROOT, value, False, False).hex(), emit(ROOT, value, False, True).hex(), json.dumps(plain(ROOT, value), indent=2, ensure_ascii=False))


def payload(case):
    if case.data is not None:
        return case.data
    if case.form == "json":
        return json.dumps(json_input(ROOT, case.state), ensure_ascii=False)
    return wire_input(ROOT, case.state, case.form != "array")


def run_case(harness, case):
    data = payload(case)
    if case.form == "json" or isinstance(data, str):
        got = harness.decode_json(data, case.entry or DECODE_JSON)
    else:
        got = harness.decode_rmp(data, case.entry or DECODE_RMP)
    if got[0] != "ok":
        return got
    if case.want is not None and case.want[0] == "accepted":
        return ("accepted",)
    return ("ok", harness.pack(1, 0), harness.pack(0, 0), harness.pack(0, 1), harness.text("  "))


def check_all(harness, cases):
    out = []
    for case in cases:
        got = run_case(harness, case)
        want = spec_run(case)
        if got != want:
            detail = next((str(index) for index, (left, right) in enumerate(zip(got, want)) if left != right), "shape")
            raise EvidenceError("case %s differs at item %s: real %r spec %r" % (case.name, detail, str(got)[:400], str(want)[:400]))
        out.append((case, got))
    return out


def expected_text(kind):
    tag = kind[0]
    if tag == "struct":
        return "struct " + wire_name(kind[1])
    return {"addr": ADDRESS_TEXT, "hash": HASH_TEXT, "time": TIME_TEXT, "map": MAP_TEXT, "set": "a sequence", "seq": "a sequence", "bool": "a boolean", "text": "a string", "u64": "u64", "usize": "usize", "nonzero": "a nonzero u64", "wei": "u64 for WeiPriv", "u16": "u16", "ip": "variant identifier", "names": "variant identifier", "unit": "unit struct NoopHardQuorumPolicy", "nil_key": "unit", "opaque": "struct ValueState"}[tag]


def nil_outcome(kind):
    tag = kind[0]
    if tag == "opt" or kind == UNIT:
        return None
    return ("error", "invalid type: unit value, expected " + expected_text(kind))


def true_outcome(kind):
    tag = kind[0]
    if tag == "opt":
        return true_outcome(kind[1])
    if tag == "bool":
        return None
    return ("error", "invalid type: boolean `true`, expected " + expected_text(kind))


def walk(kind, value, path):
    """Every struct node of a friendly value, with its path and a setter chain."""
    tag = kind[0]
    if tag == "struct":
        yield kind, value, path
        for field, inner, _ in STRUCTS[kind[1]]:
            if field in value:
                yield from walk(inner, value[field], path + (field,))
    elif tag == "map" and value:
        yield from walk(kind[2], value[0][1], path + (0, 1))
    elif tag == "seq" and value:
        yield from walk(kind[1], value[0], path + (0,))


def edited(state, path, change):
    """A deep copy of the state with the node at path replaced by change(node)."""
    def go(node, rest):
        if not rest:
            return change(node)
        head = rest[0]
        if isinstance(node, dict):
            out = dict(node)
            out[head] = go(node.get(head), rest[1:])
            return out
        out = list(node)
        out[head] = go(node[head], rest[1:])
        return out
    return go(state, path)


class Raw:
    """Pre-packed bytes in a friendly value."""

    def __init__(self, data):
        self.data = data


def raw_bytes(kind, value, named=True):
    return wire_input(kind, value, named)


def forced(state, path, data):
    """Input bytes of the state with the node at path written as data."""
    def go(kind, node, rest):
        if not rest:
            return data
        tag = kind[0]
        if tag == "struct":
            rows = [row for row in STRUCTS[kind[1]] if row[0] in node]
            out = mp_head(len(rows), 0x80, 0xDE, 0xDF)
            for field, inner, _ in rows:
                out += mp_text(field)
                out += go(inner, node[field], rest[1:]) if field == rest[0] else wire_input(inner, node[field])
            return out
        if tag == "map":
            out = mp_head(len(node), 0x90, 0xDC, 0xDD)
            for index, (key, item) in enumerate(node):
                if index == rest[0]:
                    out += b"\x92" + wire_input(kind[1], key) + go(kind[2], item, rest[2:])
                else:
                    out += b"\x92" + wire_input(kind[1], key) + wire_input(kind[2], item)
            return out
        if tag == "seq":
            out = mp_head(len(node), 0x90, 0xDC, 0xDD)
            for index, item in enumerate(node):
                out += go(kind[1], item, rest[1:]) if index == rest[0] else wire_input(kind[1], item)
            return out
        raise EvidenceError("no path through %s" % (kind,))
    return go(ROOT, state, path)


def struct_cases(state):
    """Absent, doubled, nil, true and short or long array forms of every field of every struct."""
    cases = []
    seen = set()
    for kind, node, path in walk(ROOT, state, ()):
        name = kind[1]
        if name in seen:
            continue
        seen.add(name)
        rows = STRUCTS[name]
        label = name.lower()
        total = len(rows)
        wire = wire_name(name)
        for index, (field, inner, rule) in enumerate(rows):
            if field in node:
                smaller = edited(state, path, lambda item, gone=field: {k: v for k, v in item.items() if k != gone})
                if rule is REQUIRED:
                    want = ("error", "missing field `%s`" % field)
                    cases.append(Case("%s_%s_absent" % (label, field), data=wire_input(ROOT, smaller), want=want))
                    if index == 0:
                        cases.append(Case("%s_%s_absent_json" % (label, field), data=json.dumps(json_input(ROOT, smaller), ensure_ascii=False), form="json", want=want))
                else:
                    cases.append(Case("%s_%s_absent" % (label, field), smaller))
                body = wire_input(kind, node)
                head_size = 1 if len(node) < 16 else 3
                twice = wire_input(kind, {field: node[field]})[1:]
                count = len(node) + 1
                data = mp_head(count, 0x80, 0xDE, 0xDF) + body[head_size:] + twice
                cases.append(Case("%s_%s_twice" % (label, field), data=forced(state, path, data), want=("error", "duplicate field `%s`" % field)))
                cases.append(Case("%s_%s_nil" % (label, field), data=forced(state, path + (field,), b"\xc0"), want=nil_outcome(inner) or ("accepted",)))
                cases.append(Case("%s_%s_true" % (label, field), data=forced(state, path + (field,), b"\xc3"), want=true_outcome(inner) or ("accepted",)))
        complete = canon(kind, node)
        shape = []
        for field, inner, _ in rows:
            shape.append(wire_input(inner, node[field]) if field in node else emit_default(inner, complete[field]))
        for size in range(total):
            required = next((index for index in range(size, total) if rows[index][2] is REQUIRED or rows[index][0] in ARRAY_REQUIRED), None)
            data = mp_head(size, 0x90, 0xDC, 0xDD) + b"".join(shape[:size])
            if required is None:
                want = ("accepted",)
            else:
                want = ("error", "invalid length %d, expected struct %s with %d elements" % (required, wire, total))
            cases.append(Case("%s_array_%d_of_%d" % (label, size, total), data=forced(state, path, data), want=want))
        data = mp_head(total, 0x90, 0xDC, 0xDD) + b"".join(shape)
        cases.append(Case("%s_array_full" % label, data=forced(state, path, data), want=("accepted",)))
        data = mp_head(total + 1, 0x90, 0xDC, 0xDD) + b"".join(shape) + b"\x00"
        cases.append(Case("%s_array_long" % label, data=forced(state, path, data), want=("kind", 4)))
    return cases


def emit_default(kind, value):
    return wire_input(kind, plain_back(kind, value))


def plain_back(kind, value):
    if kind[0] == "struct":
        return value
    return value


def rule_cases():
    full = full_state()
    least = least_state()
    dense = edited(full, ("user_states",), lambda rows: rows[:2])
    out = [Case("full_named", full), Case("full_array", dense, data=emit(ROOT, canon(ROOT, dense), False, True)), Case("full_json", full, form="json"), Case("least_named", least), Case("least_json", least, form="json")]
    small = edited(least, ("proposals",), lambda _: full["proposals"])
    small = edited(small, ("jvt",), lambda _: full["jvt"])
    for name in ("accelerated", "constitutional", "ecosystem", "electoral"):
        out.append(Case("category_" + name, edited(small, ("proposals", 0, 1, "category"), lambda _, n=name: n)))
    for name in ("yes", "no", "abstain"):
        out.append(Case("choice_" + name, edited(small, ("proposals", 0, 1, "votes", 0, 1, "choice"), lambda _, n=name: n)))
    for name, value in (("zero_bytes_one", dict(b=1)), ("only_time", dict(l=TIME_C)), ("none", dict()), ("both", dict(b=1, l=TIME_C)), ("zero_explicit", dict(b=0, l=None))):
        out.append(Case("user_state_" + name, edited(least, ("user_states",), lambda _, v=value: [[address(1), v]])))
    root_errors = ((b"\xc0", "invalid type: unit value, expected struct CStaking"), (b"\x05", "invalid type: integer `5`, expected struct CStaking"), (b"\x90", "invalid length 0, expected struct CStaking with 22 elements"), (b"\x80", "missing field `stakes`"), (b"\xa1x", 'invalid type: string "x", expected struct CStaking'), (b"\xc2", "invalid type: boolean `false`, expected struct CStaking"))
    for index, (data, text) in enumerate(root_errors):
        out.append(Case("root_%d" % index, data=data, want=("error", text)))
    json_root = (("null", "invalid type: null, expected struct CStaking"), ("[]", "invalid length 0, expected struct CStaking with 22 elements"), ("{}", "missing field `stakes`"), ("5", "invalid type: integer `5`, expected struct CStaking"), ('"x"', 'invalid type: string "x", expected struct CStaking'))
    for index, (data, text) in enumerate(json_root):
        out.append(Case("root_json_%d" % index, data=data, form="json", want=("error", text)))
    base = least
    def setter(field, value, name, want=None, state=base):
        return Case(name, edited(state, (field,), lambda _, v=value: v), want=want)
    def forcing(path, value, name, want):
        return Case(name, data=forced(base, path, value), want=want)
    late = edited(least, ("user_states",), lambda _: [[address(1), dict(l=TIME_C)]])
    out.append(Case("array_form_of_time_only_row_refused", data=emit(ROOT, canon(ROOT, late), False, True), want=("error", 'invalid type: string "%s", expected u64 for WeiPriv' % TIME_C)))
    out.append(setter("allowed_validators", [address(2), address(1), address(2)], "set_sorted_and_deduped"))
    out.append(setter("broadcasters", [address(9), address(3)], "broadcasters_sorted"))
    out.append(setter("disabled_validators", [address(9), address(3), address(9)], "disabled_validators_sorted"))
    out.append(setter("disabled_node_ips", [("LocalNode", 2), ("Ip", "9.0.0.1"), ("Ip", "1.0.0.9"), ("LocalNode", 1), ("Ip", "1.0.0.9")], "ips_sorted_ip_before_local"))
    out.append(setter("jail_until", [[address(9), TIME_A], [address(3), TIME_B]], "map_rows_sorted_by_key"))
    out.append(setter("jail_until", [[address(9), TIME_A], [address(9), TIME_B]], "map_duplicate_key", ("error", "duplicate key")))
    out.append(setter("jail_until", [[address(index), TIME_C] for index in range(30, 0, -1)], "map_of_30_rows"))
    out.append(setter("validator_to_staged_rewards", [[address(index), index + 1] for index in range(40)], "map_of_40_rows"))
    out.append(setter("allowed_validators", [address(index) for index in range(10, 0, -1)], "set_of_10_rows"))
    out.append(setter("self_delegation_requirement", MASK[8], "wei_at_u64_max"))
    out.append(setter("native_token_reserve", 0, "reserve_zero_is_kept"))
    out.append(setter("native_token_reserve", None, "reserve_nil"))
    for name, text, want in (("seconds", "2024-01-02T03:04:05", None), ("tenths", "2024-01-02T03:04:05.1", None), ("micro", "2024-01-02T03:04:05.123456", None), ("seven_digits", "2024-01-02T03:04:05.1234567", None), ("zero_fraction", "2024-01-02T03:04:05.000", None), ("leap_day", "2024-02-29T00:00:00", None),
                             ("space", "2024-01-02 03:04:05", ("error", "input contains invalid characters")), ("zone", "2024-01-02T03:04:05Z", ("error", "trailing input")), ("month_13", "2024-13-02T03:04:05", ("error", "input is out of range")), ("hour_24", "2024-01-02T24:00:00", ("error", "input is out of range")), ("no_leap", "2023-02-29T00:00:00", ("error", "input is out of range")), ("empty", "", ("error", "premature end of input")), ("word", "x", ("error", "input contains invalid characters"))):
        out.append(Case("time_" + name, edited(least, ("jail_until",), lambda _, t=text: [[address(1), t]]), want=want))
    for name, text, want in (("no_prefix", "11" * 20, None), ("mixed_case", "0x" + "aB" * 20, None), ("upper_prefix", "0X" + "11" * 20, ("error", "invalid length 42, expected " + ADDRESS_TEXT)), ("short", "0x" + "11" * 19, ("error", "invalid length 38, expected " + ADDRESS_TEXT)), ("bad_digit", "0x" + "1g" * 20, ("error", "invalid hex character: g, at 3"))):
        kept = text[2:].lower() if text[:2] == "0x" else text.lower()
        data = forced(least, ("allowed_validators",), b"\x91" + mp_text(text))
        out.append(Case("address_" + name, edited(least, ("allowed_validators",), lambda _, k=kept: ["0x" + k]) if want is None else None, data=data, want=want))
    bytes_form = b"\x91\xc4\x14" + bytes(range(20))
    seq_form = b"\x91\xdc\x00\x14" + bytes(range(20))
    wide = b"\x91\xdc\x00\x15" + bytes(range(21))
    canon_address = "0x" + bytes(range(20)).hex()
    out.append(Case("address_bin8", edited(least, ("allowed_validators",), lambda _: [canon_address]), data=forced(least, ("allowed_validators",), bytes_form)))
    out.append(Case("address_u8_array", edited(least, ("allowed_validators",), lambda _: [canon_address]), data=forced(least, ("allowed_validators",), seq_form)))
    out.append(Case("address_21_u8", data=forced(least, ("allowed_validators",), wide), want=("error", "invalid length 21, expected " + ADDRESS_TEXT)))
    profile = dict(node_ip=("Ip", "1.2.3.4"), name="n", description="d", signer=address(1))
    plain_row = [[address(2), profile]]
    def ip_case(name, data, want):
        node = forced(least, ("validator_to_profile",), b"\x91\x92" + mp_text(address(2)) + b"\x84" + mp_text("node_ip") + data + mp_text("name") + mp_text("n") + mp_text("description") + mp_text("d") + mp_text("signer") + mp_text(address(1)))
        return Case(name, data=node, want=want)
    out.append(ip_case("ip_string", b"\x81" + mp_text("Ip") + mp_text("1.2.3.4"), ("accepted",)))
    out.append(ip_case("ip_tuple_refused", b"\x81" + mp_text("Ip") + b"\x94\x01\x02\x03\x04", ("error", "invalid type: sequence, expected IPv4 address")))
    out.append(ip_case("ip_three_parts", b"\x81" + mp_text("Ip") + mp_text("1.2.3"), ("error", "invalid IPv4 address syntax")))
    out.append(ip_case("ip_octet_256", b"\x81" + mp_text("Ip") + mp_text("256.2.3.4"), ("error", "invalid IPv4 address syntax")))
    out.append(ip_case("ip_leading_zero", b"\x81" + mp_text("Ip") + mp_text("01.2.3.4"), ("error", "invalid IPv4 address syntax")))
    out.append(ip_case("local_node_255", b"\x81" + mp_text("LocalNode") + b"\xcc\xff", ("accepted",)))
    out.append(ip_case("local_node_256", b"\x81" + mp_text("LocalNode") + b"\xcd\x01\x00", ("error", "invalid value: integer `256`, expected u8")))
    out.append(ip_case("ip_other_variant", b"\x81" + mp_text("Other") + b"\x00", ("error", "unknown variant `Other`, expected `Ip` or `LocalNode`")))
    out.append(ip_case("ip_unit_form", mp_text("Ip"), ("error", "invalid type: unit variant, expected newtype variant")))
    out.append(Case("category_other", data=forced(small, ("proposals", 0, 1, "category"), mp_text("other")), want=("error", "unknown variant `other`, expected one of `accelerated`, `constitutional`, `ecosystem`, `electoral`")))
    out.append(Case("choice_other", data=forced(small, ("proposals", 0, 1, "votes", 0, 1, "choice"), mp_text("maybe")), want=("error", "unknown variant `maybe`, expected one of `yes`, `no`, `abstain`")))
    out.append(Case("status_other", data=forced(small, ("jvt", "i", 0, 1, "qst"), mp_text("x")), want=("error", "unknown variant `x`, expected `Q` or `N`")))
    out.append(Case("status_q_is_a_newtype_of_unit", data=forced(small, ("jvt", "i", 0, 1, "qst"), b"\x81\xa1Q\xc0"), want=("accepted",)))
    out.append(Case("status_q_written_as_a_map", edited(small, ("jvt", "i", 0, 1, "qst"), lambda _: "Q"), data=forced(small, ("jvt", "i", 0, 1, "qst"), b"\x81\xa1Q\xc0")))
    out.append(Case("status_q_text_refused", data=forced(small, ("jvt", "i", 0, 1, "qst"), mp_text("Q")), want=("error", "invalid type: unit variant, expected newtype variant")))
    out.append(Case("period_zero", data=forced(base, ("stakes", "period"), b"\x00"), want=("error", "invalid value: integer `0`, expected a nonzero u64")))
    out.append(Case("bucket_millis_zero", data=forced(base, ("stakes_decay_bucket_guard", "bucket_millis"), b"\x00"), want=("error", "invalid value: integer `0`, expected a nonzero u64")))
    out.append(Case("wei_negative", data=forced(base, ("self_delegation_requirement",), b"\xff"), want=("error", "invalid value -1 for WeiPriv when visiting i64")))
    out.append(Case("wei_one_row_array", edited(base, ("self_delegation_requirement",), lambda _: 5), data=forced(base, ("self_delegation_requirement",), b"\x91\x05")))
    out.append(Case("wei_two_row_array_first_kept", edited(base, ("self_delegation_requirement",), lambda _: 5), data=forced(base, ("self_delegation_requirement",), b"\x92\x05\x06")))
    out.append(Case("wei_empty_array", data=forced(base, ("self_delegation_requirement",), b"\x90"), want=("error", "invalid length 0, expected u64 for WeiPriv")))
    unknown = dict(base)
    data = wire_input(ROOT, base)
    data = mp_head(len(base) + 1, 0x80, 0xDE, 0xDF) + data[3:] + mp_text("zzz") + b"\x92\x01\x81\xa1a\x02"
    out.append(Case("unknown_key_ignored", base, data=data))
    out.append(Case("trailing_byte_left", base, data=wire_input(ROOT, base) + b"\x00"))
    out.append(Case("text_escapes_json", edited(base, ("validator_to_profile",), lambda _: [[address(2), dict(profile, name='a"b\\c\n\t\x01', description="é")]])))
    out.append(Case("text_escapes_read_json", edited(base, ("validator_to_profile",), lambda _: [[address(2), dict(profile, name='a"b\\c\n\t\x01', description="é")]]), form="json"))
    out.append(Case("hsc_refuses_map", data=forced(small, ("jvt", "hsc"), b"\x80"), want=("error", "invalid type: map, expected unit struct NoopHardQuorumPolicy")))
    return out


class Draw:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return self.state >> 33

    def pick(self, items):
        return items[self.next() % len(items)]

    def wei(self):
        return self.pick((0, 1, 127, 128, 255, 256, 65535, 65536, 4294967295, 4294967296, MASK[8], self.next()))

    def address(self):
        return address(self.next() % 200)

    def time(self):
        return "20%02d-%02d-%02dT%02d:%02d:%02d%s" % (self.next() % 30 + 10, self.next() % 12 + 1, self.next() % 28 + 1, self.next() % 24, self.next() % 60, self.next() % 60, self.pick(("", ".5", ".123", ".123456", ".123456789", ".000001", ".100000000")))


def draw_value(draw, kind, depth=0):
    tag = kind[0]
    if tag == "struct":
        out = {}
        for field, inner, rule in STRUCTS[kind[1]]:
            if rule is not REQUIRED and draw.next() % 2:
                continue
            out[field] = draw_value(draw, inner, depth + 1)
        return out
    if tag in ("map", "set", "seq"):
        count = draw.next() % 3 if kind[1] != ("nil_key",) else 0
        if tag == "map":
            rows = {}
            for _ in range(count):
                key = draw_value(draw, kind[1], depth + 1)
                rows[key] = draw_value(draw, kind[2], depth + 1)
            return [[key, item] for key, item in rows.items()]
        return [draw_value(draw, kind[1], depth + 1) for _ in range(count)]
    if tag == "opt":
        return None if draw.next() % 2 else draw_value(draw, kind[1], depth + 1)
    if tag == "bool":
        return bool(draw.next() % 2)
    if tag == "addr":
        return draw.address()
    if tag == "hash":
        return digest(draw.next() % 50)
    if tag == "time":
        return draw.time()
    if tag == "text":
        return draw.pick(("", "x", "long words here", "q" * 40))
    if tag == "names":
        return "N" if kind[1] == ("Q", "N") else draw.pick(kind[1])
    if tag == "ip":
        return draw.pick((("Ip", "%d.%d.%d.%d" % (draw.next() % 256, draw.next() % 256, draw.next() % 256, draw.next() % 256)), ("LocalNode", draw.next() % 256)))
    if tag == "nonzero":
        return draw.wei() or 1
    if tag == "u16":
        return draw.pick((0, 1, 9999, 10000, 65535))
    if tag == "unit":
        return None
    return draw.wei()


def vector_cases(count):
    draw = Draw(20261031)
    out = []
    for index in range(count):
        state = draw_value(draw, ROOT)
        form = ("rmp", "json", "array")[index % 3]
        if form == "array":
            state = {field: state[field] if field in state else complete_default(inner, rule) for field, inner, rule in STRUCTS["CStaking"]}
        out.append(Case("vector_%d" % index, state, form="rmp" if form == "array" else form))
    return out


def complete_default(kind, rule):
    if rule == "jail vote tracker":
        return dict(name=rule, hsc=None, i=[])
    return default_for(kind, rule)


class TextRange:
    """Every code address runs for real."""

    def __contains__(self, va):
        return va < 0x6000000


def real_set(self):
    return TextRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        self.static_map = table
    return self.static_map


Image.real_set = real_set
Image.static_view = static_view
Image.static_map = None


ROOT_FIELDS = (("stakes", 0x0), ("allowed_validators", 0x120), ("allow_all_validators", 0x290), ("broadcasters", 0x138), ("validator_to_profile", 0x150), ("delegations", 0x168), ("proposals", 0x198), ("stakes_decay_bucket_guard", 0xA0), ("jailed_signers", 0xB0), ("jvt", 0x70), ("jail_until", 0x1B0), ("signer_to_last_manual_unjail_time", 0x1C8), ("native_token_reserve", 0x60), ("stage_reward_bucket_guard", 0x100), ("validator_to_staged_rewards", 0x1E0), ("distribute_reward_bucket_guard", 0x110), ("user_states", 0x1F8), ("pending_withdrawals", 0x210), ("self_delegation_requirement", 0x240), ("disabled_validators", 0x248), ("disabled_node_ips", 0x260), ("validator_to_state", 0x278))
MEMORY_CHECKS = (("allow_all_validators", 0x290, 1, 1), ("native_token_reserve tag", 0x60, 8, 1), ("native_token_reserve value", 0x68, 8, 909), ("self_delegation_requirement", 0x240, 8, 10000000000000),
                 ("stakes_decay_bucket_guard last_bucket", 0xA8, 8, 1700000000000), ("stakes_decay_bucket_guard bucket_millis", 0xA0, 8, 60000), ("stage_reward_bucket_guard last_bucket", 0x108, 8, 1700000001000), ("stage_reward_bucket_guard bucket_millis", 0x100, 8, 70000), ("distribute_reward_bucket_guard last_bucket", 0x118, 8, 1700000002000), ("distribute_reward_bucket_guard bucket_millis", 0x110, 8, 80000),
                 ("allowed_validators rows", 0x130, 8, 2), ("broadcasters rows", 0x148, 8, 1), ("validator_to_profile rows", 0x160, 8, 2), ("proposals rows", 0x1A8, 8, 1), ("jail_until rows", 0x1C0, 8, 2), ("signer_to_last_manual_unjail_time rows", 0x1D8, 8, 1), ("validator_to_staged_rewards rows", 0x1F0, 8, 3), ("user_states rows", 0x208, 8, 4), ("disabled_validators rows", 0x258, 8, 1), ("disabled_node_ips rows", 0x270, 8, 3), ("validator_to_state rows", 0x288, 8, 1))
ROUTE_ROW = 0x28EB25E
ROUTE_WORD = 0x01000400
RANGES = ((0x398E000, 0x3992000), (0x3A05000, 0x3A0E000), (0x37D9000, 0x37DA000))
ROOT_TARGETS = {SERIALIZE_RMP: "cstaking_msgpack_writer", SERIALIZE_JSON: "cstaking_json_writer", DECODE_RMP: "cstaking_msgpack_reader", DECODE_JSON: "cstaking_json_reader"}
EXCLUDED = ()
FIND_TEXTS = ("jail vote tracker", "struct CStaking with 22 elements", "struct EpochTracker with 5 elements", "struct EpochValues with 2 elements", "struct CValidatorStakes with 2 elements", "struct CValidatorProfile with 6 elements", "struct Delegations with 2 elements", "struct Delegation with 2 elements", "struct ValidatorState with 2 elements", "struct EpochDelegation with 3 elements", "struct Proposal with 7 elements", "struct Vote with 2 elements", "struct BucketGuard with 2 elements", "struct RawSignatureTracker with 3 elements", "struct PendingWithdrawals with 2 elements", "struct TotalWithdrawal with 2 elements", "struct CValidatorState with 3 elements", "struct UniqueKeyState with 3 elements", "struct ValueState with 2 elements", "NoopHardQuorumPolicy", "WeiPriv", "accelerated", "constitutional", "electoral", "abstain", "LocalNode", "delegator_to_epoch_delegation", "user_to_total_withdrawal", "last_signer_change_time", "max_n_validators")
SAMPLE = 12
MUTANT_CASES = 8
WORKERS = 3
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a spill slot, a register choice or a word no rule reads"
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
            if run_case(harness, case) != want:
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


def text_rows(image):
    rows = []
    blob = bytes(image.blob)
    for text in FIND_TEXTS + tuple(name for name, _ in ROOT_FIELDS):
        at = blob.find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    return rows


def type_text(kind):
    tag = kind[0]
    if tag == "struct":
        return wire_name(kind[1])
    if tag == "map":
        return "map %s to %s" % (type_text(kind[1]), type_text(kind[2]))
    if tag in ("set", "seq", "opt"):
        return "%s %s" % (tag, type_text(kind[1]))
    if tag == "names":
        return "one of " + " ".join(kind[1])
    return tag


def field_rows():
    rows = []
    for name in STRUCTS:
        for index, (field, kind, rule) in enumerate(STRUCTS[name]):
            if rule is REQUIRED:
                text = "required"
            elif field in ARRAY_REQUIRED:
                text = "absent keeps nil in a map, required in an array"
            else:
                text = "absent keeps " + json.dumps(rule if not isinstance(rule, tuple) else [])
            if name in SKIP_WHEN_DEFAULT:
                text += ", not written at its default"
            rows.append((wire_name(name), name, index, field, type_text(kind), text))
    return rows


def memory_rows(harness):
    if harness.decode_rmp(wire_input(ROOT, full_state())) != ("ok",):
        raise EvidenceError("full state refused")
    rows = []
    for name, offset, size, value in MEMORY_CHECKS:
        got = harness.read(DECODED + offset, size)
        if got != value:
            raise EvidenceError("%s at %#x is %#x" % (name, offset, got))
        rows.append((name, "%#x" % offset, size, value))
    return rows


def route_row(image):
    row = row_at(image, ROUTE_ROW)
    data = bytes(image.blob[image.offset(ROUTE_ROW):image.offset(ROUTE_ROW) + row.size])
    if struct.pack("<I", ROUTE_WORD) not in data:
        raise EvidenceError("options word moved")
    return ("%#x" % ROUTE_ROW, data.hex(), "%#x" % ROUTE_WORD, "byte +8 0, +9 4, +0xa human 0, +0xb named 1")


def copy_rows(image, harness, cases):
    rows = []
    for copy, base, kinds in [(entry, DECODE_RMP, "msgpack") for entry in RMP_COPIES] + [(entry, DECODE_JSON, "json") for entry in JSON_COPIES]:
        count = 0
        for case in cases:
            is_json = case.form == "json" or isinstance(case.data, str)
            if is_json != (kinds == "json"):
                continue
            twin = Case(case.name, case.state, case.data, case.form, case.want, copy)
            if run_case(harness, twin) != spec_run(case):
                raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
            count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, "%#x" % base, kinds, count))
    return rows


def targets_of(image, seen):
    found = dict(ROOT_TARGETS)
    for va in seen:
        if any(low <= va < high for low, high in RANGES):
            start = image.fde(va)[0]
            if start not in EXCLUDED:
                found.setdefault(start, "state_writer_%x" % start)
    return found


def sample_state():
    state = least_state()
    state["validator_to_profile"] = [[address(4), dict(node_ip=("Ip", "10.20.30.40"), name="a", description="b", signer=address(5))]]
    state["user_states"] = [[address(20), dict(b=913, l=TIME_A)], [address(21), dict()]]
    return state


def analyse(image, mutate=True, vectors=6, structs=True):
    harness = Harness(image)
    cases = rule_cases() + (struct_cases(full_state()) if structs else [])
    named, reach, cost = [], {}, {}
    for case in cases:
        harness.machine.seen = set()
        before = harness.machine.steps
        named += check_all(harness, [case])
        reach[case.name], cost[case.name] = harness.machine.seen, harness.machine.steps - before
    seen = set()
    for rows in reach.values():
        seen |= rows
    generated = vector_cases(vectors)
    harness.machine.seen = seen
    check_all(harness, generated)
    names = targets_of(image, seen)
    table = {}
    for target in sorted(names):
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    state = sample_state()
    if harness.decode_rmp(wire_input(ROOT, state)) != ("ok",):
        raise EvidenceError("sample refused")
    wire = [("named_human_0", harness.pack(1, 0)), ("array_human_0", harness.pack(0, 0)), ("named_human_1", harness.pack(1, 1)), ("json", harness.text("  ").encode().hex())]
    value = canon(ROOT, state)
    if wire[0][1] != emit(ROOT, value, True, False).hex() or wire[2][1] != emit(ROOT, value, True, True).hex():
        raise EvidenceError("sample differs from the rule list")
    ordered = [case for case, _ in named]
    light = [case for case in ordered if cost[case.name] < 60000][:30] + [case for case in ordered if case.form == "json" and cost[case.name] < 150000][:6]
    result = dict(names=names, table=table, named=named, vector_count=len(generated), texts=text_rows(image), fields=field_rows(), memory=memory_rows(harness), route=route_row(image), copies=copy_rows(image, harness, light), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in names})
    if mutate:
        pool = [case for case in cases if cost[case.name] < 200000]
        result["mutations"] = run_mutants(image, table, pool, reach, cost, harness.machine.cache)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table, sizes, names = result["table"], result["sizes"], result["names"]
    order = sorted(names)
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(names[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in order for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(names[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in order])
    tsv("fields.tsv", ("struct", "schema_key", "index", "key", "type", "rule"), result["fields"])
    tsv("root-offsets.tsv", ("index", "key", "state_offset"), [(index, name, "%#x" % offset) for index, (name, offset) in enumerate(ROOT_FIELDS)])
    tsv("memory-checks.tsv", ("item", "state_offset", "size", "value_after_real_decode"), result["memory"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("route-word.tsv", ("at", "bytes", "word", "meaning"), [result["route"]])
    tsv("copies.tsv", ("copy", "body_bytes", "same_rules_as", "form", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("case", "hex"), result["wire"])
    rows = []
    for case, trace in result["named"]:
        if trace[0] == "ok":
            rows.append((case.name, "ok sha256 " + hashlib.sha256("|".join(trace[1:]).encode()).hexdigest()[:16]))
        else:
            rows.append((case.name, " ".join(str(item) for item in trace)))
    tsv("scenarios.tsv", ("case", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    reached = sum(row.size for items in table.values() for row in items)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "structs": len(set(wire_name(name) for name in STRUCTS)), "fields": len(result["fields"]), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "error_cases": sum(1 for _, trace in named if trace[0] in ("error", "kind")), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "copies": len(result["copies"]), "state_bytes": STATE_SIZE}
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
