#!/usr/bin/env python3
"""Pin the node #94 BOLE index reset, the SetBole words 4, 5, 7, 16, 17 and the token parameter row.

Real rows run from the vote dispatcher entry, from the reset wrappers and from the token word read. A separately written
rule list predicts the status, every stored row, every user word and every state byte, and every reached conditional
row, immediate and field offset of the subject code is mutated. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/bole_reset_index.py --out <dir>
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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
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
            if row.target != 2:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left <= right else 0)
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
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


OK = 0x186
TAG_NUMBER = 0x13F
TAG_LENGTH = 0x143
TAG_TOKEN = 0xEA
TAG_NESTED = 0xE1
TAG_BAD_TEXT = 0xAC
TAG_NOT_FINITE = 0xAB
CAP = 0x0CCCCCCCCCCCCCCC
TEXT_LIMIT = 100
ONE = 10 ** 14
STATUS_OK = 0x11
STATUS_INVALID = 4
STATUS_PAST_64 = 3
STATUS_TOTAL = 7
STATUS_NO_ROW = 9
INNER_REFUSED = 0xA
SELECT_ENTRY = 0x4E
SUB_ARMS = 16
ROW_SIZE = 0xB0
TREE_AT = 0x568
USERS_AT = 0x598
PARAMS_AT = 0x4A8
PARAMS_END = 0x4D0
RATIO_AT = 0x560
OPTION_AT = 0x498
OPTION_VALUE_AT = 0x4A0
STATE_SIZE = 0x2000
SIDE_LEAF = 0x1C8
SIDE_INNER = 0x228
RESERVE_LEAF = 0x7F8
RESERVE_INNER = 0x858
USER_LEAF = 0x2F8
USER_INNER = 0x358
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_REALLOC = 0x576E030
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
SLOT_CMP = 0x576E488
SLOT_BCMP = 0x576E378
SLOT_SET = 0x576E1F8
SLOT_TEXT = 0x57731D8
SLOT_FLOAT = 0x5773968
SLOT_SCALED = 0x5773848
SLOT_PRICE = 0x5773E80
SLOT_USER = 0x5773E58
SLOT_ADL = 0x5773E68
SLOT_COMMIT = 0x5773E88
SLOT_FENCE = 0x576F488
SLOT_GROW_TABLE = 0x57736A8
SLOT_ROW_GATE = 0x5773E50
SLOT_READ = 0x5773E60
SLOT_NUMBER = 0x5773D90
SLOT_PARAMS = 0x5773E90
SLOT_PLAN = 0x5773D40
SLOT_APPLY = 0x5773D48
SLOT_RATIO = 0x5773E70
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128, 0x576E118, 0x576E150)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
S = HEAP_BASE + 0x1000
BUMP = HEAP_BASE + 0x6000
BUMP_END = HEAP_BASE + 0x3F000
LIMIT_MIN = 0x8000000000000000
PIECE_FILL = 0xAA
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x6000))
BUCKETS = 16
BUCKET_SIZE = 0x28
MAP_HOLD = 0x5000
SYSTEM_MARK = b"\xbb" * 20


class Copy:
    def __init__(self, name, table, wrapper):
        self.name, self.table, self.wrapper = name, table, wrapper

    def arm(self, image):
        return self.table + struct.unpack_from("<i", image.blob, image.offset(self.table + 4 * SELECT_ENTRY))[0]

    def entry(self, image):
        return image.fde(self.arm(image))[0]


class Layout:
    def __init__(self, key_at, val_at, val_size, parent_at, index_at, len_at, edge_at, leaf, inner, key_size=8):
        self.key_at, self.val_at, self.val_size, self.parent_at = key_at, val_at, val_size, parent_at
        self.index_at, self.len_at, self.edge_at, self.leaf, self.inner, self.key_size = index_at, len_at, edge_at, leaf, inner, key_size


L_RESERVE = Layout(0x798, 0, ROW_SIZE, 0x790, 0x7F0, 0x7F2, 0x7F8, RESERVE_LEAF, RESERVE_INNER)
L_SIDE = Layout(0x168, 0, 0x20, 0x160, 0x1C0, 0x1C2, 0x1C8, SIDE_LEAF, SIDE_INNER)
L_USER = Layout(0x218, 0, 0x30, 0x210, 0x2F4, 0x2F6, 0x2F8, USER_LEAF, USER_INNER, 20)
COPIES = (Copy("a", 0x3DD1B8, 0x232B460), Copy("b", 0x711064, 0x48CCFA0), Copy("c", 0x711244, 0x48CCF10))
PLAN = 0x373C280
APPLY = 0x373BE40
ROW_GATE = 0x3C0D830
TOKEN_READ = 0x3733540
PARAMS = 0x37350C0
PARAMS_ENTRY = 0x35971A0
NUMBER = 0x374FFA0
OPTION = 0x24CDFE0
WRAPPERS = (0x232B460, 0x48CCFA0, 0x48CCF10)
SUBJECTS = WRAPPERS + (PLAN, APPLY, ROW_GATE, TOKEN_READ, PARAMS, PARAMS_ENTRY, NUMBER, OPTION)
NAMES = {0x232B460: "reset_a", 0x48CCFA0: "reset_b", 0x48CCF10: "reset_c", PLAN: "reset_plan", APPLY: "reset_apply", ROW_GATE: "row_gate", TOKEN_READ: "token_read", PARAMS: "params_apply", PARAMS_ENTRY: "params_entry", NUMBER: "option_number", OPTION: "option_length"}
SERDE = (b"struct variant SetBole::ResetIndex with 2 elements", b"struct variant SetBole::BackstopLiquidatorTokenParams with 4 elements", b"struct variant SetBole::Adl with 2 elements", b"lybubusMpmpwpPu")


def object_bytes(tag):
    return struct.pack("<H", tag) + bytes((0x41 + index) & 0xFF for index in range(2, 0x60))


class Row:
    """One reserve row, 22 words; earlier packets name the fields this path touches."""
    NAMES = ("ltv_tag", "ltv", "seed", "balance", "held", "paid", "min_px", "max_px", "borrowed", "borrow_cap", "user_borrow_cap", "borrow_index", "supplied", "supply_cap", "user_supply_cap", "supply_index", "rate_0", "rate_1", "rate_2", "rate_3", "stamp_0", "stamp_1")

    def __init__(self, **fields):
        for name in self.NAMES:
            setattr(self, name, fields.pop(name, 0))
        if fields:
            raise EvidenceError("unknown row field %s" % sorted(fields))

    def words(self):
        return [getattr(self, name) for name in self.NAMES]

    def bytes(self):
        return struct.pack("<22Q", *self.words())

    def copy(self, **fields):
        return Row(**dict({name: getattr(self, name) for name in self.NAMES}, **fields))


BASE_ROW = dict(ltv_tag=1, ltv=0x7777, seed=0x5151, balance=7000, held=11, paid=13, min_px=3, max_px=9000, borrowed=50, borrow_cap=5, user_borrow_cap=6, borrow_index=ONE, supplied=70, supply_cap=1000, user_supply_cap=100, supply_index=ONE,
                rate_0=0x1001, rate_1=0x1002, rate_2=0x1003, rate_3=0x1004, stamp_0=0x7777, stamp_1=0x8888)


def base_row(**fields):
    return Row(**dict(BASE_ROW, **fields))


class Case:
    DEFAULTS = dict(kind="reset", copy=0, token=2, tokens=6, flag=0, rows=(), users=(), stale=None, amount=0, adl_tag=0, adl_byte=0x37, commit_ok=True, text=None, bad_text=False, float_bits=None, scaled=None, steps=(), wrapper=False, side=0, height=0)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


class Step:
    """One BackstopLiquidatorTokenParams action."""

    def __init__(self, token=2, w_given=0, w=0, low=None, low_value=0, high=None, high_value=0, bad_low=False, bad_high=False):
        self.token, self.w_given, self.w, self.low, self.low_value, self.high, self.high_value, self.bad_low, self.bad_high = token, w_given, w, low, low_value, high, high_value, bad_low, bad_high


class AllCode:
    def __contains__(self, target):
        return 0x1300000 < target < 0x5660000


class Harness:
    statics = None

    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        hooks = ((SLOT_FREE, self.on_free), (SLOT_ALLOC, self.on_alloc), (SLOT_REALLOC, self.on_realloc), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_CMP, self.on_cmp), (SLOT_BCMP, self.on_cmp), (SLOT_SET, self.on_set),
                 (SLOT_TEXT, self.on_text), (SLOT_FLOAT, self.on_float), (SLOT_SCALED, self.on_scaled), (SLOT_PRICE, self.on_price), (SLOT_USER, self.on_user), (SLOT_ADL, self.on_adl), (SLOT_COMMIT, self.on_commit), (SLOT_FENCE, self.on_fence), (SLOT_GROW_TABLE, self.on_panic))
        if Harness.statics is None:
            table = dict(image.relative())
            for slot, _ in hooks:
                table[slot] = MARK_BASE + slot
            for slot in PANIC_SLOTS:
                table[slot] = MARK_BASE + slot
            Harness.statics = table
        machine.memory.statics = Harness.statics
        for slot, hook in hooks:
            machine.slots[MARK_BASE + slot] = hook
        for slot in PANIC_SLOTS:
            machine.slots[MARK_BASE + slot] = self.on_panic
        machine.real = AllCode()
        machine.calls = {RESUME: self.on_panic}
        self.case = None
        self.live = {}
        self.events = []
        self.cur = BUMP
        self.step = None

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

    def on_fence(self, machine):
        self.events.append("fence")

    def on_text(self, machine):
        memory, case = machine.memory, self.case
        out, pointer, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(size <= TEXT_LIMIT, "length gate ran first")
        self.expect((memory.bytes_at(pointer, size) if size else b"") == case.text, "decimal text")
        self.events.append("text")
        if case.bad_text:
            memory.put_bytes(out, object_bytes(TAG_BAD_TEXT))
            return
        memory.write(out, 2, OK)
        memory.put_bytes(out + 4, bytes(range(0xA0, 0xB0)))

    def on_float(self, machine):
        self.expect(machine.memory.bytes_at(machine.regs[RDI], 16) == bytes(range(0xA0, 0xB0)), "decimal passed to the float call")
        self.events.append("float")
        machine.regs[RAX] = 0 if self.case.float_bits is None else 1
        if self.case.float_bits is not None:
            machine.xmm_result = self.case.float_bits

    def on_scaled(self, machine):
        memory = machine.memory
        out, record, rounding, exponent = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX] & 0xFF, machine.regs[RCX] & 0xFFFFFFFF
        self.expect(memory.bytes_at(record, 16) == bytes(range(0xA0, 0xB0)), "decimal passed to the scale call")
        self.expect(rounding == 0 and exponent == 14, "exact mode, 14 places")
        self.events.append("scaled")
        if self.case.scaled is None:
            memory.put_bytes(out, struct.pack("<H", 0xA8) + bytes(0x5E))
        else:
            memory.write(out, 2, OK)
            memory.write(out + 8, 8, self.case.scaled)

    def on_price(self, machine):
        memory = machine.memory
        out, record, token, meta = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        step = self.step
        self.expect(token == step.token, "price token")
        self.expect(meta == S + 0x90, "price state")
        cap, pointer, size = (memory.read(record + offset, 8) for offset in (0, 8, 0x10))
        which = sum(1 for event in self.events if event == "price")
        self.events.append("price")
        text, value, bad = (step.low, step.low_value, step.bad_low) if which == 0 else (step.high, step.high_value, step.bad_high)
        if text is None:
            self.expect(cap == LIMIT_MIN, "absent price text")
            memory.write(out, 2, OK)
            memory.write(out + 8, 8, 0)
            memory.write(out + 0x10, 8, 0x5A5A)
            return
        self.expect((memory.bytes_at(pointer, size) if size else b"") == text, "price text")
        if cap:
            self.expect(self.live.pop(pointer, None) == cap, "price text freed once")
        if bad:
            memory.put_bytes(out, object_bytes(TAG_BAD_TEXT))
            return
        memory.write(out, 2, OK)
        memory.write(out + 8, 8, 1 if value == 0 else 2)
        memory.write(out + 0x10, 8, value or 0x5C5C)

    def on_user(self, machine):
        memory = machine.memory
        self.expect(machine.regs[RDI] == S + OPTION_AT, "user map base")
        self.expect(memory.bytes_at(machine.regs[RSI], 20) == SYSTEM_MARK, "system key")
        self.events.append("user")
        machine.regs[RAX] = self.system_value

    def on_adl(self, machine):
        memory, case = machine.memory, self.case
        out, base, token, amount = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX], machine.regs[RCX]
        self.expect(base == S + OPTION_AT and token == case.token and amount == case.amount, "adl arguments")
        self.events.append("adl")
        memory.write(out, 8, case.adl_tag)
        memory.write(out + 8, 1, case.adl_byte)
        memory.put_bytes(out + 9, bytes(range(1, 0xC0)) + bytes(range(1, 0x39)))

    def on_commit(self, machine):
        memory, case = machine.memory, self.case
        out, base, record = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(base == S + OPTION_AT, "commit base")
        self.expect(memory.read(record, 8) == case.adl_tag and memory.read(record + 8, 1) == case.adl_byte, "commit record head")
        self.expect(memory.bytes_at(record + 9, 0xF7) == (bytes(range(1, 0xC0)) + bytes(range(1, 0x39)))[:0xF7], "commit record body")
        self.events.append("commit")
        memory.write(out + 8, 4, 0)

    def node(self, items, stale, size, layout):
        memory = self.machine.memory
        at = self.bump(size)
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(size)))
        memory.write(at + layout.parent_at, 8, 0)
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, stale)
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + layout.key_at + layout.key_size * slot, key)
            memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        return at

    def tree(self, items, stale, layout):
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(items, stale, layout.leaf, layout), 0, len(items)
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        kids = [self.node(part, stale, layout.leaf, layout) for part in parts]
        root = self.node(seps, stale, layout.inner, layout)
        for slot, kid in enumerate(kids):
            memory.write(root + layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + layout.parent_at, 8, root)
            memory.write(kid + layout.index_at, 2, slot)
        return root, 1, len(items)

    def deep(self, items, stale, layout, height):
        """A tree of the given height with three children per inner node."""
        memory = self.machine.memory
        if height == 0:
            return self.node(items, stale, layout.leaf, layout)
        size = (len(items) - 2) // 3
        first, second = items[:size], items[size + 1:2 * size + 1]
        third = items[2 * size + 2:]
        kids = [self.deep(part, stale, layout, height - 1) for part in (first, second, third)]
        root = self.node([items[size], items[2 * size + 1]], stale, layout.inner, layout)
        for slot, kid in enumerate(kids):
            memory.write(root + layout.edge_at + 8 * slot, 8, kid)
            memory.write(kid + layout.parent_at, 8, root)
            memory.write(kid + layout.index_at, 2, slot)
        return root

    def walk(self, root, height, layout):
        memory = self.machine.memory
        rows = []

        def visit(at, level, parent, index):
            size = memory.read(at + layout.len_at, 2)
            self.expect(memory.read(at + layout.parent_at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + layout.index_at, 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + layout.edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.bytes_at(at + layout.key_at + layout.key_size * slot, layout.key_size), memory.bytes_at(at + layout.val_at + layout.val_size * slot, layout.val_size)))
        if root:
            visit(root, height, 0, 0)
        return rows

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:len(HEAP_FILL)] = HEAP_FILL
        memory.put_bytes(S, bytes([PIECE_FILL]) * STATE_SIZE)
        self.case = case
        self.events = []
        self.live = {}
        self.cur = BUMP
        self.step = None
        self.system_value = 0
        self.machine.steps_at = self.machine.steps

    def text_of(self, value):
        """A heap string as (cap, pointer, length), or the None niche."""
        if value is None:
            return LIMIT_MIN, 0x7171, 0
        if not value:
            return 0, 1, 0
        at = self.bump(len(value))
        self.machine.memory.put_bytes(at, value)
        return len(value), at, len(value)

    def put_words(self, at, values):
        for index, value in enumerate(values):
            self.machine.memory.write(at + 8 * index, 8, value)

    def user_value(self, key, tokens, stale):
        memory = self.machine.memory
        items = sorted((struct.pack("<Q", token), struct.pack("<4Q", *words)) for token, words in tokens)
        root, height, count = self.tree(items, stale, L_SIDE)
        value = bytes((0x61 + index) & 0xFF for index in range(0x18)) + struct.pack("<3Q", root, height, count)
        return (key, value)

    def base_state(self, case):
        memory = self.machine.memory
        memory.write(S + 0x218, 8, case.tokens)
        stale = struct.pack("<Q", case.stale if case.stale is not None else 1)
        items = sorted((struct.pack("<Q", token), row.bytes()) for token, row in case.rows)
        root, height, count = self.tree(items, stale, L_RESERVE)
        self.put_words(S + TREE_AT, (root, height, count))
        users = sorted(self.user_value(key, tokens, stale) for key, tokens in case.users)
        if case.height:
            root, height, count = self.deep(users, b"\x01" * 20, L_USER, case.height), case.height, len(users)
        else:
            root, height, count = self.tree(users, b"\x01" * 20, L_USER)
        self.put_words(S + USERS_AT, (root, height, count))
        table = self.bump(MAP_HOLD)
        self.expect(table + MAP_HOLD <= BUMP_END, "map room")
        control = table + BUCKETS * BUCKET_SIZE
        memory.put_bytes(control, b"\xff" * (BUCKETS + 16))
        self.put_words(S + PARAMS_AT, (control, BUCKETS - 1, BUCKETS - 2, 0))
        self.put_words(S + PARAMS_AT + 0x20, (0x1234, 0x5678, 0x9ABC, 0xDEF0))
        self.table = table

    def params_view(self):
        memory = self.machine.memory
        control = memory.read(S + PARAMS_AT, 8)
        rows = []
        for index in range(BUCKETS):
            if memory.read(control + index, 1) & 0x80 == 0:
                at = control - (index + 1) * BUCKET_SIZE
                rows.append(struct.unpack("<5Q", memory.bytes_at(at, BUCKET_SIZE)))
        return tuple(sorted(rows))

    def view(self, before, nodes_before):
        memory = self.machine.memory
        after = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        changes = {}
        at = 0
        while at < STATE_SIZE:
            if after[at] != before[at] and not PARAMS_AT <= at < PARAMS_AT + 0x40:
                base = at & ~7
                changes[base] = struct.unpack_from("<Q", after, base)[0]
                at = base + 8
            else:
                at += 1
        root, height = memory.read(S + TREE_AT, 8), memory.read(S + TREE_AT + 8, 8)
        rows = tuple((struct.unpack("<Q", key)[0], row_view(value)) for key, value in self.walk(root, height, L_RESERVE))
        users = []
        root, height = memory.read(S + USERS_AT, 8), memory.read(S + USERS_AT + 8, 8)
        for key, value in self.walk(root, height, L_USER):
            inner_root, inner_height = struct.unpack_from("<2Q", value, 0x18)
            users.append((key, tuple((struct.unpack("<Q", token)[0], struct.unpack("<4Q", words)) for token, words in self.walk(inner_root, inner_height, L_SIDE))))
        return dict(status=memory.read(OUT, 2), word1=memory.read(OUT + 8, 8), nested=memory.read(OUT + 2, 1), changes=tuple(sorted(changes.items())), rows=rows, users=tuple(users), params=self.params_view(), events=tuple(self.events), left=tuple(sorted(at for at in self.live if at not in nodes_before)), out=memory.bytes_at(OUT, 0x60))

    def dispatch(self, case):
        self.machine.run(COPIES[case.copy].entry(self.image), {RDI: OUT, RSI: ACTION, RDX: S})

    def run_reset(self, case):
        self.base_state(case)
        keep = set(self.live)
        self.put_words(ACTION, (17, case.token, case.flag))
        before = bytes(self.machine.memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        self.dispatch(case)
        return self.view(before, keep)

    def run_wrapper(self, case):
        self.base_state(case)
        keep = set(self.live)
        before = bytes(self.machine.memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        result = self.machine.run(COPIES[case.copy].wrapper, {RDI: S + OPTION_AT, RSI: case.token, RDX: case.side})
        return dict(self.view(before, keep), status=result & 0xFF)

    def run_adl(self, case):
        self.base_state(case)
        self.system_value = HEAP_BASE + 0x800
        memory = self.machine.memory
        tokens = dict(case.users).get(SYSTEM_MARK)
        if tokens is None:
            self.put_words(self.system_value + 0x18, (0, 0xFEED))
        else:
            self.put_words(self.system_value + 0x18, self.tree(sorted((struct.pack("<Q", token), struct.pack("<4Q", *words)) for token, words in tokens), b"\x01" * 8, L_SIDE)[:2])
        keep = set(self.live)
        self.put_words(ACTION, (16, case.token, case.amount))
        before = bytes(memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        self.dispatch(case)
        return self.view(before, keep)

    def run_option(self, case):
        self.base_state(case)
        keep = set(self.live)
        self.put_words(ACTION, (4,) + self.text_of(case.text))
        before = bytes(self.machine.memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        self.dispatch(case)
        return self.view(before, keep)

    def run_ratio(self, case):
        self.base_state(case)
        keep = set(self.live)
        self.put_words(ACTION, (7,) + self.text_of(case.text))
        before = bytes(self.machine.memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        self.dispatch(case)
        return self.view(before, keep)

    def run_read(self, case):
        memory = self.machine.memory
        stale = struct.pack("<Q", case.stale if case.stale is not None else 1)
        items = sorted((struct.pack("<Q", token), struct.pack("<4Q", *words)) for token, words in case.users)
        at = HEAP_BASE + 0x800
        self.put_words(at + 0x18, self.tree(items, stale, L_SIDE)[:2])
        result = self.machine.run(TOKEN_READ, {RDI: at, RSI: case.token, RDX: case.side})
        return dict(status=result, left=(), out=b"", events=())

    def run_params(self, case):
        self.base_state(case)
        keep = set(self.live)
        before = bytes(self.machine.memory.heap[S - HEAP_BASE:S - HEAP_BASE + STATE_SIZE])
        statuses = []
        for step in case.steps:
            self.step = step
            self.events = []
            self.machine.memory.put_bytes(OUT, bytes([0x5A]) * 0x60)
            self.put_words(ACTION, (5, step.w_given, step.w) + self.text_of(step.low) + self.text_of(step.high) + (step.token,))
            self.dispatch(case)
            statuses.append(self.machine.memory.read(OUT, 2))
        memory = self.machine.memory
        return dict(self.view(before, keep), statuses=tuple(statuses), head=(memory.read(S + PARAMS_AT + 0x10, 8), memory.read(S + PARAMS_AT + 0x18, 8)))

    def run(self, case):
        self.fresh(case)
        return getattr(self, "run_" + case.kind)(case)


def row_view(value):
    """The last four bytes of a row are padding behind the 32-bit stamp."""
    return value[:ROW_SIZE - 4]


def scale(word, index, up):
    """The reset rule for one user word: the exact 128-bit product over 1e14, up for borrow, down for supply."""
    return -(-(word * index) // ONE) if up else word * index // ONE


def spec_plan(rows, users, token, up):
    """(status, new row, new user words) of the plan; a None row means nothing is stored."""
    row = rows.get(token)
    if row is None:
        return STATUS_NO_ROW, None, None
    index = row.borrow_index if up else row.supply_index
    total = 0
    new = {}
    for key, tokens in sorted(users, key=lambda item: item[0]):
        words = dict(tokens).get(token)
        if words is None:
            continue
        value = scale(words[1 if up else 3], index, up)
        if value >> 64:
            return STATUS_PAST_64, None, None
        total += value
        if total >> 64:
            return STATUS_TOTAL, None, None
        new[key] = value
    fields = dict(borrowed=total, borrow_index=ONE) if up else dict(supplied=total, supply_index=ONE)
    return STATUS_OK, row.copy(**fields), new


def state_rows(rows):
    return tuple((key, row_view(rows[key].bytes())) for key in sorted(rows))


def state_users(users, token=None, new=None, up=False):
    out = []
    for key, tokens in sorted(users, key=lambda item: item[0]):
        items = []
        for name, words in sorted(tokens):
            if new is not None and name == token and key in new:
                words = tuple(new[key] if at == (1 if up else 3) else word for at, word in enumerate(words))
            items.append((name, tuple(words)))
        out.append((key, tuple(items)))
    return tuple(out)


def resolve(case):
    """Rows and users as dictionaries of the case."""
    return {token: row for token, row in case.rows}, case.users


def spec_reset_after(case, up, ok_events=()):
    rows, users = resolve(case)
    status, row, new = spec_plan(rows, users, case.token, up)
    if status != STATUS_OK:
        return dict(status=TAG_NESTED, nested=INNER_REFUSED, rows=state_rows(rows), users=state_users(users), changes=(), events=ok_events)
    rows = dict(rows)
    rows[case.token] = row
    return dict(status=OK, rows=state_rows(rows), users=state_users(users, case.token, new, up), changes=(), events=ok_events)


def token_gate(case, keep_rows=True):
    """The refusals shared by words 5, 16 and 17: the count, then the row."""
    rows, users = resolve(case)
    common = dict(rows=state_rows(rows), users=state_users(users), changes=())
    if case.token >= case.tokens:
        return dict(common, status=TAG_TOKEN, word1=case.token)
    if case.token not in rows:
        return dict(common, status=TAG_NESTED, nested=0)
    return None


def spec_reset(case):
    return token_gate(case) or spec_reset_after(case, not case.flag & 1)


def spec_wrapper(case):
    rows, users = resolve(case)
    status, row, new = spec_plan(rows, users, case.token, bool(case.side & 1))
    if status != STATUS_OK:
        return dict(status=status, rows=state_rows(rows), users=state_users(users))
    rows = dict(rows)
    rows[case.token] = row
    return dict(status=status, rows=state_rows(rows), users=state_users(users, case.token, new, bool(case.side & 1)))


def spec_adl(case):
    refused = token_gate(case)
    if refused:
        return refused
    rows, users = resolve(case)
    common = dict(rows=state_rows(rows), users=state_users(users), changes=())
    if case.amount >= CAP:
        return dict(common, status=TAG_NUMBER, word1=case.amount, events=())
    if case.adl_tag == 3:
        return dict(common, status=TAG_NESTED, nested=case.adl_byte, events=("user", "adl"))
    if case.adl_tag == 2:
        return dict(common, status=OK, events=("user", "adl", "fence"))
    return spec_reset_after(case, False, ("user", "adl", "commit", "user"))


def spec_option(case):
    if case.text is None:
        return dict(status=OK, changes=((OPTION_AT, 0),), events=())
    if len(case.text) > TEXT_LIMIT:
        return dict(status=TAG_LENGTH, changes=(), events=())
    if case.bad_text:
        return dict(status=TAG_BAD_TEXT, changes=(), events=("text",))
    if case.float_bits is None:
        return dict(status=TAG_NOT_FINITE, changes=(), events=("text", "float"))
    return dict(status=OK, changes=((OPTION_AT, 1), (OPTION_VALUE_AT, case.float_bits)), events=("text", "float"))


def spec_ratio(case):
    if len(case.text) > TEXT_LIMIT:
        return dict(status=TAG_LENGTH, changes=(), events=())
    if case.bad_text:
        return dict(status=TAG_BAD_TEXT, changes=(), events=("text",))
    if case.scaled is None or case.scaled > ONE:
        return dict(status=TAG_NESTED, nested=INNER_REFUSED, changes=(), events=("text", "scaled"))
    return dict(status=OK, changes=((RATIO_AT, case.scaled),), events=("text", "scaled"))


def spec_params(case):
    rows, users = resolve(case)
    table = {}
    statuses = []
    for step in case.steps:
        if step.token >= case.tokens:
            statuses.append(TAG_TOKEN)
        elif step.token not in rows:
            statuses.append(TAG_NESTED)
        elif step.low is not None and step.bad_low:
            statuses.append(TAG_BAD_TEXT)
        elif step.high is not None and step.bad_high:
            statuses.append(TAG_BAD_TEXT)
        elif step.w_given & 1 and step.w >= CAP:
            statuses.append(TAG_NUMBER)
        else:
            old = table.setdefault(step.token, [0, 0, 0, 0])
            low = old[2] if step.low is None else step.low_value
            high = old[3] if step.high is None else step.high_value
            if high and high < low:
                statuses.append(TAG_NESTED)
                continue
            if step.w_given & 1:
                old[0], old[1] = (1, step.w) if step.w else (0, old[1])
            old[2], old[3] = low, high
            statuses.append(OK)
    return dict(statuses=tuple(statuses), params=tuple(sorted((token,) + tuple(words) for token, words in table.items())), changes=(), head=(BUCKETS - 2 - len(table), len(table)))


def spec_read(case):
    words = dict(case.users).get(case.token)
    return dict(status=0 if words is None else words[1 if case.side & 1 else 3])


def spec_for(case):
    return {"reset": spec_reset, "wrapper": spec_wrapper, "adl": spec_adl, "option": spec_option, "ratio": spec_ratio, "params": spec_params, "read": spec_read}[case.kind](case)


def open_rows(rows):
    """A clear flag leaves the value word open: a new row holds a stack word there."""
    return tuple(row if row[1] & 1 else (row[0], row[1], 0, row[3], row[4]) for row in rows)


def same(case, got, want):
    if case.kind == "option" and case.text is None:
        """The None path stores a stack word beside the flag, so only the flag is compared."""
        got = dict(got, changes=tuple(row for row in got["changes"] if row[0] != OPTION_VALUE_AT))
    if case.kind == "params":
        got, want = dict(got, params=open_rows(got["params"])), dict(want, params=open_rows(want["params"]))
    if not all(got.get(key) == value for key, value in want.items()):
        return False
    if got["left"]:
        return False
    if case.kind == "params" and case.steps:
        last = want["statuses"][-1]
        step = case.steps[-1]
        if last == TAG_BAD_TEXT and got["out"] != object_bytes(TAG_BAD_TEXT):
            return False
        if last == TAG_NESTED and got["out"][2] != (0 if step.token not in dict(case.rows) else INNER_REFUSED):
            return False
    if case.kind == "option" and want["status"] == TAG_LENGTH and got["out"][2:8] != bytes(6):
        return False
    if want.get("status") == TAG_BAD_TEXT and got["out"] != object_bytes(TAG_BAD_TEXT):
        return False
    return True


VECTORS = 300
MUTANT_VECTORS = 90
REACH_CAP = 8
SECOND_CAP = 300
TOP = MASK[8]
UNCLASSIFIED = "not classified"
SURVIVOR_GROUPS = (
    ("action field the arms here do not read", (0x2359404, 0x2359419, 0x4CADCFF, 0x4CADD14, 0x4CB668F, 0x4CB66A4)),
    ("selector row for words 0 to 2, other arms of the vote", (0x235940C, 0x2359410, 0x4CADD07, 0x4CADD0B, 0x4CB6697, 0x4CB669B)),
    ("side of the token read, whose result the next rows do not read", (0x235C104, 0x235D641, 0x4CB0A7B, 0x4CB2008, 0x4CB940B, 0x4CBA998)),
    ("drop flag of the arm: every case frees every string either way", (0x235C383, 0x4CB0D16, 0x4CB96A6)),
    ("rest of a length refusal: those words of the object are never written", (0x2359F0B, 0x4CAE7B1, 0x4CB7141, 0x235CA31, 0x235CA3B, 0x235CA45, 0x235CA4F, 0x4CB138F, 0x4CB1399, 0x4CB13A3, 0x4CB13AD, 0x4CB9D1F, 0x4CB9D29, 0x4CB9D33, 0x4CB9D3D)),
    ("second copy of the result: the bytes are the same either way", (0x235D5D6, 0x4CB1F9D, 0x4CBA92D)),
    ("register argument the reset wrapper does not read", (0x4CB16B4, 0x4CBA044, 0x4CB1F89, 0x4CBA919, 0x4CB16CA, 0x4CBA05A, 0x4CB2018, 0x4CBA9A8)),
    ("any status but 0x11 gives the same 0xe1 with inner 0xa at the dispatcher", (0x3735123,)),
    ("hasher key base: any stable words give the same table view", (0x35971B6,)),
    ("byte pattern shuffle: all lanes hold the same value", (0x35971E3,)),
    ("insert probe: the first group here always has a free slot", (0x3597287, 0x359729A)),
    ("apply search: the plan lists only users that hold the token, so it always hits", (0x373BF03, 0x373BF8A, 0x373BFAA, 0x373BFD8, 0x373BFE9, 0x373C03A, 0x373C053)),
    ("empty list pointer: not read before the first push", (0x373C3E4,)),
    ("map hit: the value pointer is never null, so these two loop words are rewritten", (0x373C487, 0x373C489)),
    ("height 8 guard: trees here are at most height 3", (0x373C505, 0x373C5E8)),
    ("descent ends on a nonempty leaf at slot 0: any nonzero word passes", (0x373C563,)),
    ("tag of a temporary passed to its drop: the drop acts the same", (0x3750001,)),
)
SURVIVORS = {address: reason for reason, addresses in SURVIVOR_GROUPS for address in addresses}


def survivor_reason(va, kind):
    return SURVIVORS.get(va, UNCLASSIFIED)



def key_of(number):
    return bytes([number & 0xFF, number >> 8]) * 10


def plain_users():
    return ((key_of(1), ((2, (5, 7, 9, 11)), (3, (1, 2, 3, 4)))), (key_of(2), ((2, (6, 0, 8, 12)),)), (key_of(3), ((3, (1, 2, 3, 4)),)), (key_of(4), ((1, (1, 1, 1, 1)), (2, (2, 3, 4, 5)), (4, (9, 9, 9, 9)))))


def indexed(borrow, supply):
    return ((2, base_row(borrow_index=borrow, supply_index=supply)),)


LADDER_INDEX = (0, 1, ONE // 3, ONE - 1, ONE, ONE + 1, ONE * 3 // 2, 2 * ONE, 2 * ONE + 1, TOP)
LADDER_WORD = (0, 1, 2, 3, ONE - 1, ONE, ONE + 1, 1 << 63, (1 << 63) - 1, TOP)


def ladder_cases():
    out = []
    for flag, index, word in itertools.product((0, 1), LADDER_INDEX, LADDER_WORD):
        users = ((key_of(1), ((2, (0x71, word, 0x72, word)),)),)
        out.append(Case("ladder flag %d index %#x word %#x" % (flag, index, word), rows=indexed(index, index), users=users, flag=flag))
    return out


def reset_cases():
    cases = []

    def add(label, **fields):
        fields.setdefault("rows", ((2, base_row()),))
        cases.append(Case("reset " + label, **fields))

    plain = plain_users()
    for flag in (0, 1, 2, 3, 0xFF, 0xFE, 0x100, 0x101):
        add("flag %#x" % flag, flag=flag, users=plain, rows=indexed(ONE * 3 // 2, ONE // 3))
    add("token at the count", token=6, users=plain)
    add("token past the count", token=TOP, users=plain)
    add("last token", token=5, rows=((5, base_row()),), users=((key_of(1), ((5, (0, 3, 0, 4)),)),))
    add("token zero", token=0, rows=((0, base_row(borrow_index=2 * ONE)),), users=((key_of(1), ((0, (0, 3, 0, 4)),)),), flag=0)
    add("no reserve row", token=3, users=plain)
    add("empty reserve tree", rows=(), users=plain)
    for flag in (0, 1):
        add("no users, flag %d" % flag, flag=flag, rows=indexed(5 * ONE, 7 * ONE))
        add("users without the token, flag %d" % flag, flag=flag, users=((key_of(1), ((3, (1, 2, 3, 4)),)),), rows=indexed(5 * ONE, 7 * ONE))
        add("user with an empty map, flag %d" % flag, flag=flag, users=((key_of(1), ()), (key_of(2), ((2, (0, 3, 0, 4)),))), rows=indexed(5 * ONE, 7 * ONE))
        add("index one keeps words, total replaced, flag %d" % flag, flag=flag, users=plain, rows=((2, base_row(borrowed=999, supplied=888)),))
        add("zero word user, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (1, 0, 2, 0)),)), (key_of(2), ((2, (1, 5, 2, 5)),))), rows=indexed(ONE * 3 // 2, ONE * 3 // 2))
        add("each user rounds alone, flag %d" % flag, flag=flag, users=tuple((key_of(n), ((2, (0, 1, 0, 1)),)) for n in range(1, 8)), rows=indexed(ONE // 3, ONE // 3))
        add("sum exact top, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, TOP - 5, 0, TOP - 5)),)), (key_of(2), ((2, (0, 5, 0, 5)),))))
        add("sum past top, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, TOP - 4, 0, TOP - 4)),)), (key_of(2), ((2, (0, 5, 0, 5)),))))
        add("first user fine, second past 64 bits, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, 5, 0, 5)),)), (key_of(2), ((2, (0, TOP, 0, TOP)),))), rows=indexed(2 * ONE, 2 * ONE))
        add("past 64 bits with a nonzero sum first, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, 1 << 63, 0, 1 << 63)),)), (key_of(2), ((2, (0, 1 << 63, 0, 1 << 63)),))), rows=indexed(2 * ONE - 1, 2 * ONE - 1))
        add("exact product of 2^64 ones, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, 1 << 62, 0, 1 << 62)),)),), rows=indexed(4 * ONE, 4 * ONE))
        add("one below the product of 2^64 ones, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, (1 << 62) - 1, 0, (1 << 62) - 1)),)),), rows=indexed(4 * ONE, 4 * ONE))
        add("one unit below the top quotient, flag %d" % flag, flag=flag, users=((key_of(1), ((2, (0, (1 << 63) - 1, 0, (1 << 63) - 1)),)),), rows=indexed(2 * ONE + 3, 2 * ONE + 3))
        add("row tall, flag %d" % flag, flag=flag, token=9, tokens=20, rows=tuple((key, base_row(seed=key, borrow_index=3 * ONE, supply_index=5 * ONE)) for key in range(1, 15)), users=plain + ((key_of(9), ((9, (0, 3, 0, 4)),)),))
        add("user tree of 14, flag %d" % flag, flag=flag, users=tuple((key_of(n), ((2, (0, n * 3, 0, n * 5)),)) for n in range(1, 15)), rows=indexed(ONE * 3 // 2, ONE * 2 // 3))
        add("user tree of 20, flag %d" % flag, flag=flag, users=tuple((key_of(n), ((2, (0, n, 0, n + 1)),)) for n in range(1, 21)), rows=indexed(ONE * 7, ONE * 9))
        add("user tree of 8 with gaps, flag %d" % flag, flag=flag, users=tuple((key_of(n), ((2 if n % 2 else 3, (0, n, 0, n + 1)),)) for n in range(1, 9)), rows=indexed(ONE * 7, ONE * 9))
        add("user tree of height 2, flag %d" % flag, flag=flag, height=2, users=tuple((key_of(n), ((2, (0, n, 0, n + 1)),)) for n in range(1, 21)), rows=indexed(ONE * 7, ONE * 9))
        add("user tree of height 2 with gaps, flag %d" % flag, flag=flag, height=2, users=tuple((key_of(n), ((2 if n % 3 else 3, (0, n, 0, n + 1)),)) for n in range(1, 25)), rows=indexed(ONE * 7, ONE * 9))
        add("inner map of 14, flag %d" % flag, flag=flag, token=7, tokens=20, rows=((7, base_row(borrow_index=3 * ONE, supply_index=5 * ONE)),), users=((key_of(1), tuple((n, (0, n, 0, n + 1)) for n in range(1, 15))),))
        add("inner map first key, flag %d" % flag, flag=flag, token=1, tokens=20, rows=((1, base_row(borrow_index=3 * ONE, supply_index=5 * ONE)),), users=((key_of(1), tuple((n, (0, n, 0, n + 1)) for n in range(1, 15))),))
        add("inner map last key, flag %d" % flag, flag=flag, token=14, tokens=20, rows=((14, base_row(borrow_index=3 * ONE, supply_index=5 * ONE)),), users=((key_of(1), tuple((n, (0, n, 0, n + 1)) for n in range(1, 15))),))
        add("stale inner key, flag %d" % flag, flag=flag, stale=2, users=((key_of(1), ((1, (0, 5, 0, 6)), (3, (0, 7, 0, 8)))),), rows=indexed(3 * ONE, 3 * ONE))
        add("stale reserve key, flag %d" % flag, flag=flag, stale=2, token=2, rows=((1, base_row()), (3, base_row())), users=plain)
        add("second key byte order, flag %d" % flag, flag=flag, users=((b"\x01" + bytes(19), ((2, (0, 3, 0, 3)),)), (b"\x00" + b"\xff" * 19, ((2, (0, 5, 0, 5)),)), (bytes(19) + b"\x02", ((2, (0, 7, 0, 7)),))), rows=indexed(2 * ONE, 2 * ONE))
    return cases


def wrapper_cases():
    cases = []
    tiny = plain_users()
    for side in (0, 1):
        for copy in (0, 1, 2):
            tag = "wrapper %s side %d" % (COPIES[copy].name, side)
            cases.append(Case(tag + " no row", kind="wrapper", copy=copy, side=side, token=3, rows=indexed(ONE, ONE), users=tiny))
            cases.append(Case(tag + " empty tree", kind="wrapper", copy=copy, side=side, rows=(), users=tiny))
            cases.append(Case(tag + " plain", kind="wrapper", copy=copy, side=side, rows=indexed(ONE * 3 // 2, ONE // 3), users=tiny))
            cases.append(Case(tag + " past 64 bits", kind="wrapper", copy=copy, side=side, rows=indexed(2 * ONE, 2 * ONE), users=((key_of(1), ((2, (0, TOP, 0, TOP)),)),)))
            cases.append(Case(tag + " past 64 bits after a first user", kind="wrapper", copy=copy, side=side, rows=indexed(2 * ONE, 2 * ONE), users=((key_of(1), ((2, (0, 5, 0, 5)),)), (key_of(2), ((2, (0, TOP, 0, TOP)),)))))
            cases.append(Case(tag + " sum past top", kind="wrapper", copy=copy, side=side, rows=indexed(ONE, ONE), users=((key_of(1), ((2, (0, TOP, 0, TOP)),)), (key_of(2), ((2, (0, 1, 0, 1)),)))))
            cases.append(Case(tag + " sum past top after growth", kind="wrapper", copy=copy, side=side, rows=indexed(ONE, ONE), users=tuple((key_of(n), ((2, (0, 7, 0, 7)),)) for n in range(1, 7)) + ((key_of(7), ((2, (0, TOP, 0, TOP)),)),)))
    return cases


def adl_cases():
    cases = []

    def add(label, **fields):
        fields.setdefault("rows", indexed(ONE // 3, ONE * 3 // 2))
        fields.setdefault("users", plain_users())
        cases.append(Case("adl " + label, kind="adl", **fields))

    for tag in (0, 1, 2, 3):
        add("result %d" % tag, adl_tag=tag, amount=9)
        add("result %d, amount edge" % tag, adl_tag=tag, amount=CAP - 1)
    add("result 3 with another byte", adl_tag=3, adl_byte=0xD5, amount=9)
    add("amount zero", amount=0)
    add("amount at the cap", amount=CAP)
    add("amount top", amount=TOP)
    add("token at the count", token=6, amount=9)
    add("token at the count over amount", token=6, amount=CAP)
    add("no row", token=3, amount=9)
    add("no row over amount", token=3, amount=CAP)
    add("reset refused after the commit", amount=9, users=((key_of(1), ((2, (0, 0, 0, TOP)),)),), rows=indexed(ONE, 2 * ONE))
    add("sum refused after the commit", amount=9, users=((key_of(1), ((2, (0, 0, 0, TOP)),)), (key_of(2), ((2, (0, 0, 0, 1)),))))
    add("system user present", amount=9, users=plain_users() + ((SYSTEM_MARK, ((2, (1, 2, 3, 4)),)),))
    return cases


def read_cases():
    cases = []
    full = tuple((n * 2, (0x10 + n, 0x20 + n, 0x30 + n, 0x40 + n)) for n in range(1, 15))
    for side in (0, 1):
        for token in (1, 2, 3, 12, 14, 15, 28, 29):
            cases.append(Case("read side %d token %d" % (side, token), kind="read", side=side, token=token, users=full))
        cases.append(Case("read side %d empty" % side, kind="read", side=side))
        cases.append(Case("read side %d stale" % side, kind="read", side=side, token=2, stale=2, users=((1, (1, 2, 3, 4)), (3, (5, 6, 7, 8)))))
        cases.append(Case("read side %d last slot" % side, kind="read", side=side, token=11, users=tuple((n, (n, n + 1, n + 2, n + 3)) for n in range(1, 12))))
    cases.append(Case("read high side byte", kind="read", side=0x100, token=2, users=((2, (1, 2, 3, 4)),)))
    return cases


def text_cases():
    cases = []
    rows = indexed(ONE, ONE)
    for text, bits in ((b"1.5", 0x3FF8000000000000), (b"", 0), (b"0" * 100, 0x7FEFFFFFFFFFFFFF), (b"3", 0x8000000000000001)):
        cases.append(Case("option %d bytes" % len(text), kind="option", rows=rows, text=text, float_bits=bits))
    cases.append(Case("option absent", kind="option", rows=rows))
    cases.append(Case("option 101 bytes", kind="option", rows=rows, text=b"0" * 101))
    cases.append(Case("option parse refused", kind="option", rows=rows, text=b"x", bad_text=True))
    cases.append(Case("option not finite", kind="option", rows=rows, text=b"1"))
    for value in (0, 1, ONE - 1, ONE, ONE + 1, TOP):
        cases.append(Case("word 7 value %#x" % value, kind="ratio", rows=rows, text=b"1", scaled=value))
    cases.append(Case("word 7 100 bytes", kind="ratio", rows=rows, text=b"0" * 100, scaled=5))
    cases.append(Case("word 7 101 bytes", kind="ratio", rows=rows, text=b"0" * 101))
    cases.append(Case("word 7 empty", kind="ratio", rows=rows, text=b"", scaled=5))
    cases.append(Case("word 7 parse refused", kind="ratio", rows=rows, text=b"x", bad_text=True))
    cases.append(Case("word 7 scale refused", kind="ratio", rows=rows, text=b"1"))
    return cases


def params_cases():
    cases = []
    rows = ((2, base_row()), (3, base_row()))

    def add(label, *steps, **fields):
        fields.setdefault("rows", rows)
        cases.append(Case("params " + label, kind="params", steps=steps, **fields))

    full = dict(w_given=1, w=5, low=b"1", low_value=4, high=b"2", high_value=9)
    add("all three", Step(**full))
    add("nothing given", Step())
    add("w only", Step(w_given=1, w=5))
    add("w zero clears the flag, keeps the word", Step(w_given=1, w=5), Step(w_given=1, w=0))
    add("w given bit 1 only is absent", Step(w_given=2, w=5))
    add("w given 3", Step(w_given=3, w=5))
    add("w given high byte", Step(w_given=0x100, w=5))
    add("w one below the cap", Step(w_given=1, w=CAP - 1))
    add("w at the cap", Step(w_given=1, w=CAP))
    add("w top", Step(w_given=1, w=TOP))
    add("w at the cap not given", Step(w_given=0, w=CAP))
    add("w over the cap leaves no row", Step(w_given=1, w=CAP, low=b"1", low_value=1))
    add("low only", Step(low=b"1", low_value=4))
    add("high only", Step(high=b"2", high_value=4))
    add("low equals high", Step(low=b"1", low_value=4, high=b"2", high_value=4))
    add("low one above high", Step(low=b"1", low_value=5, high=b"2", high_value=4))
    add("low above zero high", Step(low=b"1", low_value=5, high=b"2", high_value=0))
    add("refused pair leaves a default row", Step(w_given=1, w=7, low=b"1", low_value=5, high=b"2", high_value=4))
    add("refused pair keeps the old row", Step(**full), Step(w_given=1, w=7, low=b"1", low_value=50))
    add("patch high below the stored low", Step(**full), Step(high=b"2", high_value=3))
    add("patch low above the stored high", Step(**full), Step(low=b"2", low_value=10))
    add("patch low to the stored high", Step(**full), Step(low=b"2", low_value=9))
    add("clear high then raise low", Step(**full), Step(high=b"0", high_value=0), Step(low=b"3", low_value=99))
    add("clear low", Step(**full), Step(low=b"0", low_value=0))
    add("keep both, set w", Step(**full), Step(w_given=1, w=6))
    add("two tokens", Step(**full), Step(token=3, w_given=1, w=8, low=b"1", low_value=2, high=b"2", high_value=3), Step(token=2, w_given=1, w=0))
    add("token at the count", Step(token=6, **full))
    add("token past the count", Step(token=TOP, **full))
    add("no reserve row", Step(token=4, **full))
    add("low text refused", Step(w_given=1, w=5, low=b"x", bad_low=True, high=b"2", high_value=9))
    add("high text refused", Step(w_given=1, w=5, low=b"1", low_value=2, high=b"y", bad_high=True))
    add("low text refused over the cap", Step(w_given=1, w=CAP, low=b"x", bad_low=True))
    add("high text refused over the cap", Step(w_given=1, w=CAP, low=b"1", low_value=1, high=b"y", bad_high=True))
    add("low text refused, high absent", Step(low=b"x", bad_low=True))
    add("empty low text", Step(low=b"", low_value=4))
    add("empty high text", Step(high=b"", high_value=4))
    add("token refused drops both texts", Step(token=9, low=b"abc", low_value=1, high=b"abcd", high_value=2))
    many = tuple((key, base_row()) for key in range(1, 16))
    add("fourteen tokens", *[Step(token=key, w_given=1, w=key) for key in range(1, 15)], tokens=20, rows=many)
    add("fourteen tokens read back", *([Step(token=key, w_given=1, w=key) for key in range(1, 15)] + [Step(token=key, low=b"1", low_value=key) for key in range(1, 15)]), tokens=20, rows=many)
    return cases


def base_cases():
    copies = []
    for case in reset_cases() + adl_cases() + text_cases() + params_cases():
        for copy in (0, 1, 2):
            fields = {key: getattr(case, key) for key in Case.DEFAULTS}
            fields["copy"] = copy
            copies.append(Case("%s, copy %s" % (case.name, COPIES[copy].name), **fields))
    tall = [Case("reset user tree of height 3, flag %d" % flag, flag=flag, height=3, users=tuple((key_of(n), ((2, (0, n, 0, n + 1)),)) for n in range(1, 61)), rows=indexed(ONE * 7, ONE * 9)) for flag in (0, 1)]
    return copies + tall + ladder_cases() + wrapper_cases() + read_cases()


def lcg(seed):
    state = seed

    def next_value(bound):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state >> 16) % bound

    return next_value


def vector_cases(count):
    pick = lcg(0x312146)
    out = []

    def word():
        return (pick(1 << 16) << 48 | pick(1 << 16) << 32 | pick(1 << 16) << 16 | pick(1 << 16)) >> (pick(5) * 12)

    def index():
        return (ONE, ONE // 3, ONE * 3 // 2, ONE + 1, word() >> 20, 2 * ONE + 1)[pick(6)]

    def users():
        out_users = []
        for number in range(1, 2 + pick(6)):
            tokens = tuple((token, (word(), word() >> (pick(3) * 8), word(), word() >> (pick(3) * 8))) for token in range(1, 5) if pick(3))
            out_users.append((key_of(number * 7 + pick(3)), tokens))
        return tuple({key: tokens for key, tokens in out_users}.items())

    for number in range(count):
        kind = number % 3
        token = pick(5)
        rows = tuple((key, base_row(seed=key, borrow_index=index(), supply_index=index(), borrowed=word(), supplied=word())) for key in range(1, 5) if pick(4))
        if kind == 0:
            out.append(Case("vector reset %d" % number, copy=pick(3), token=token, flag=pick(2), rows=rows, users=users()))
        elif kind == 1:
            out.append(Case("vector adl %d" % number, kind="adl", copy=pick(3), token=token, amount=(9, CAP - 1, CAP)[pick(3)], adl_tag=pick(4), rows=rows, users=users()))
        else:
            steps = []
            for _ in range(1 + pick(5)):
                low = pick(3)
                high = pick(3)
                steps.append(Step(token=1 + pick(4), w_given=pick(2), w=(0, 5, 7, CAP)[pick(4)], low=None if low == 0 else b"1", low_value=(0, 3, 6, 9)[pick(4)], high=None if high == 0 else b"2", high_value=(0, 3, 6, 9)[pick(4)]))
            out.append(Case("vector params %d" % number, kind="params", copy=pick(3), rows=rows, steps=tuple(steps)))
    return out


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        got = harness.run(case)
        want = spec_for(case)
        if not same(case, got, want):
            raise EvidenceError("case %s: got %s want %s" % (case.name, {key: value for key, value in got.items() if key != "out"}, want))
        outcomes.append(got)
    return outcomes


def sub_table(image, copy):
    arm = copy.arm(image)
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 0x70])
    at = data.index(b"\x48\x8d\x05")
    return arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]


def word_rows(image):
    rows = []
    for copy in COPIES:
        table = sub_table(image, copy)
        for index in range(SUB_ARMS):
            arm = table + struct.unpack_from("<i", image.blob, image.offset(table + 4 * index))[0]
            word = "0,1" if index == 1 else str(index + 2)
            rows.append((copy.name, "%#x" % table, index, word, "%#x" % arm))
    return rows


def arm_windows(image, seen, cache):
    tables = {}
    for copy in COPIES:
        low, high = image.fde(copy.arm(image))
        head = low + 0x3F
        vas = sorted(va for va in seen if head <= va < high)
        rows = [cache[va] for va in vas]
        for row in rows:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        tables[copy.name] = rows
    return tables


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
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
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
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
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked, TypeError, AttributeError):
            return case
    return None


def spread(items, cap=REACH_CAP):
    step = max(1, len(items) // cap)
    return items[::step]


def run_mutants(image, table, window, seen, cases, vectors):
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
    groups = [table[target] for target in SUBJECTS] + [window["a"], window["b"], window["c"]]
    for rows in groups:
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, spread(reach[va]))
            if hit is None:
                hit = first_failure(harness, spread(reach[va], SECOND_CAP))
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", survivor_reason(va, kind)))
    return results


def serde_rows(image):
    out = []
    for text in SERDE:
        at = image.blob.find(text)
        if at < 0:
            raise EvidenceError("text not in the image: %r" % text)
        out.append(("%#x" % at, text.decode()))
    return out


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, meaning in ((SLOT_ROW_GATE, "row gate, real"), (SLOT_READ, "token word read, real"), (SLOT_PLAN, "reset plan, real"), (SLOT_APPLY, "reset apply, real"), (SLOT_NUMBER, "option number, real"), (SLOT_PARAMS, "params apply, real"), (SLOT_RATIO, "word 7 store, real"),
                          (SLOT_TEXT, "decimal text parser, hook"), (SLOT_FLOAT, "decimal to f64, hook"), (SLOT_SCALED, "decimal scaled, hook"), (SLOT_PRICE, "price text parser, hook"), (SLOT_USER, "user row by key, hook"), (SLOT_ADL, "adl body, hook"), (SLOT_COMMIT, "adl commit, hook"), (SLOT_FENCE, "tag 2 call, hook")):
        rows.append(("%#x" % slot, "%#x" % relative.get(slot, 0), meaning))
    return rows


def rounding_rows(cases, outcomes):
    rows = []
    for case, got in zip(cases, outcomes):
        if case.name.startswith("ladder "):
            word = case.users[0][1][0][1][1]
            index = case.rows[0][1].borrow_index
            up = not case.flag
            value = scale(word, index, up)
            rows.append(("up" if up else "down", "%#x" % index, "%#x" % word, "%#x" % value, "refused" if value >> 64 else "stored", "%#x" % got["status"]))
    return rows


def analyse(image, mutate=True, vectors=VECTORS):
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in SUBJECTS}
    window = arm_windows(image, seen, harness.machine.cache)
    for target in SUBJECTS:
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in SUBJECTS}
    result = dict(table=table, window=window, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, serde=serde_rows(image), slots=slot_rows(image), words=word_rows(image), rounding=rounding_rows(cases, outcomes))
    if mutate:
        result["mutations"] = run_mutants(image, table, window, seen, cases, vector_cases(MUTANT_VECTORS))
    return result


def outcome_row(case, got):
    label = "status %#x" % got["status"]
    if case.kind == "params":
        label = "statuses " + ",".join("%#x" % status for status in got["statuses"])
    digest = hashlib.sha256(repr(sorted((key, value) for key, value in got.items() if key not in ("out", "word1", "left"))).encode()).hexdigest()[:16]
    return (case.kind, COPIES[case.copy].name, case.name, label, digest)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in SUBJECTS for row in result["table"][target]])
    tsv("arm-rows.tsv", ("copy", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in sorted(result["window"]) for row in result["window"][name]])
    tsv("word-table.tsv", ("copy", "table", "index", "word", "arm"), result["words"])
    tsv("rounding.tsv", ("direction", "index", "word", "quotient", "result", "status"), result["rounding"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("slots.tsv", ("slot", "target", "meaning"), result["slots"])
    tsv("outcomes.tsv", ("kind", "copy", "case", "result", "digest"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in SUBJECTS},
        "arm_rows_reached": {name: len(rows) for name, rows in sorted(result["window"].items())},
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

