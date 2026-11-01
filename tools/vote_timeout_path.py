#!/usr/bin/env python3
"""Pin the node #94 vote and timeout path from ELF bytes: vote decision, vote receipt, stake quorum, QC record, timer, timeout join and TC.

The real rows run in a small x86-64 evaluator over fixtures; the binary is never executed. Standard library plus tools/elf_index.py and tools/fde_extents.py.
"""

import argparse
import bisect
import collections
import hashlib
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
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 1500000
MUTANT_STEP_LIMIT = 400000
VECTORS = 600


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
        for marker in ("/node/", "/library/"):
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
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        elif byte not in (0x2E, 0xF0):
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
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
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
        if two in (0xB0, 0xB1):
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1 if two == 0xB0 else width)
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
        self.left = 0
        self.stops = frozenset()
        self.stopped = None

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
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        self.left = self.step_limit
        self.loop(entry)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def loop(self, entry):
        pc = entry
        cache = self.cache
        stops = self.stops
        while pc != RETURN_SENTINEL:
            if pc in stops:
                self.stopped = pc
                return
            self.left -= 1
            if self.left < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)

    def call_real(self, entry, args):
        """Run a real function from inside a stub, on the stack below the caller."""
        regs, keep = list(self.regs), list(self.xmm)
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = (regs[RSP] - 0x1000) & ~15
        self.push(RETURN_SENTINEL)
        self.loop(entry)
        self.regs, self.xmm = regs, keep

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
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            source = self.get(row.b, width)
            product = (source - (1 << (8 * width)) if source & SIGN[width] else source) * row.target
            self.put(row.a, width, product)
            self.of = self.cf = not -SIGN[width] <= product < SIGN[width]
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            product = (left - (1 << 64) if left & SIGN[8] else left) * (right - (1 << 64) if right & SIGN[8] else right)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            self.add_sub(self.regs[RAX] & MASK[width], current, 0, width, True)
            if self.zf:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
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
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op == "shldc":
            bits = 8 * width
            count = self.regs[RCX] & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, (high << count | low >> (bits - count)) if count else high)
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right

MARK_BASE = 0x7700000000
REAL_FUNCTIONS = (0x1450A60, 0x151D1B0, 0x151F870, 0x15206E0, 0x41D9CD0, 0x41E8640, 0x42167A0, 0x42179A0, 0x4219FC0, 0x4230560, 0x42730A0, 0x4287B70, 0x428A610, 0x428D080, 0x42ACBE0, 0x42B1CC0, 0x42BA100, 0x42C9930, 0x4355DB0, 0x4356560, 0x435E130, 0x4450BB0, 0x44AA5A0, 0x44AB560, 0x44ADD70, 0x44B6130, 0x44C2380, 0x44C52B0, 0x454AA10, 0x454B020, 0x454B170, 0x454BA50, 0x47BE700, 0x47BF9C0, 0x4847500, 0x484EAA0, 0x4870470, 0x488B370, 0x4895BD0, 0x4897070, 0x48C4120, 0x48C4930, 0x48C4C10, 0x4913410, 0x49274B0, 0x49278B0, 0x4927F20, 0x4928080, 0x49309D0, 0x493D940, 0x49437F0, 0x494E540, 0x494F440, 0x4956720, 0x4959C70, 0x4984140, 0x49C28B0, 0x4AD90D0, 0x4B31D40, 0x4B33770, 0x4B33990)
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_ERROR = 0x576DFB8
SLOT_DEALLOC = 0x576E010
SLOT_LOG = 0x576E978
SLOT_FORMAT = 0x576E040
SLOT_RECOVER = 0x576FE58
SLOT_BTREE_PANIC = 0x576E470
SLOT_ASSERT = 0x576E108
SLOT_PANIC_FMT = 0x576E468
SLOT_LAZY = 0x576F488
SLOT_RECORD = 0x5773648
SLOT_LEADER = 0x5773628
SLOT_PROPOSER = 0x5773630
SLOT_SNAPSHOT = 0x57769E8
SLOT_QUORUM = 0x5776AE8
SLOT_GROW_OUT = 0x57769D0
SLOT_GROW_RING = 0x5776650
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_SECONDS = 0x576F6C8
SLOT_DURATION = 0x576EAA0
ONCE_WORD = 0x577AB98
NOW_INSTANT = 0x4EE3800
DISPATCH = 0x44ADFA0
MAYBE_VOTE = 0x44AA5A0
VOTE_RULE = 0x44ADD70
SIGN_VOTE = 0x454B020
VERIFY_VOTE = 0x454BA50
SNAPSHOT = 0x4B31D40
TRACK = 0x435E130
TRACK_CORE = 0x48C4C10
SLOT_QUORUM_CHECK = 0x48C4120
SIGNER_LIST = 0x4450BB0
QUORUM = 0x4AD90D0
VOTER_INSERT = 0x49309D0
PRUNE = 0x48C4930
KEY_LIST = 0x488B370
BUILD_ROWS = 0x47BF9C0
RECORD_QC = 0x44AB560
QC_MAP_INSERT = 0x4356560
CLONE_BLOCK = 0x44C52B0
SET_LOOKUP = 0x42C9930
SET_RANGE = 0x42BA100
OUTBOX_PUSH = 0x44C2380
SEEN_FIND = 0x4355DB0
TX_FIND = 0x4927F20
DIGEST = 0x454C050
SIGN_HASH = 0x14A2710
ADVANCE = 0x44B6670
ANCESTORS = 0x44B9800
THROTTLE = 0x44B8050
ANCESTOR_FIND = 0x4927CA0
DROP_ERROR = 0x447E690
DROP_ROW = 0x447E5C0
DROP_SET = 0x49AC240
DROP_VALUE = 0x4B1A270
STOP_TAIL = 0x44B181C
STOP_TIMER = 0x44B1F7A
SEND_TIMEOUT = 0x44B6130
SIGN_TIMEOUT = 0x454B170
VERIFY_TIMEOUT = 0x454AA10
VERIFY_QC = 0x4758D70
REARM = 0x4F79820
NONE_TAG = 1 << 63
PLACEHOLDER_TAG = NONE_TAG + 1
OK_TAG = NONE_TAG + 0x2A
NO_SET_TAG = NONE_TAG + 0x28
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0xB10
TABLE = STATE + 0x930
EVENT = HEAP_BASE + 0x2000
TIME_IN = HEAP_BASE + 0x2200
QC_IN = HEAP_BASE + 0x2240
ERROR_OBJECT = HEAP_BASE + 0x22C0
ERROR_VTABLE = HEAP_BASE + 0x22E0
RING = HEAP_BASE + 0x2300
OUTBOX = HEAP_BASE + 0x2800
NODES = HEAP_BASE + 0x8000
TX_VALUE = 0x58
BLOCK_VALUE = 0xF8
STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))
LOW_ROUNDS = 200
RECENT_SPAN = 2000
KEEP_ROUNDS = 95
SPACING_NS = 50000000
MAX_AGE = 3.5
SELF = 1
MAX_ROUND = 0xFFFFFFFFFFFFFFFF
RING_CAP = 8


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 8 * 12


TX_LAYOUT = Layout(0, 32, 0x168, TX_VALUE, 0x160, 0x530, 0x532, 0x538)
BLOCK_LAYOUT = Layout(0, 32, 0x168, BLOCK_VALUE, 0x160, 0xC10, 0xC12, 0xC18)
STAKE_LAYOUT = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)
TABLE_LAYOUT = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
ROUND_LAYOUT = Layout(0x2C8, 8, 0, 0x40, 0x2C0, 0x320, 0x322, 0x328)
SLOT_LAYOUT = Layout(0, 32, 0x160, 0x30, 0x370, 0x378, 0x37A, 0x380)
VOTER_LAYOUT = Layout(0x320, 20, 8, 0x48, 0, 0x3FC, 0x3FE, 0x400)
QC_LAYOUT = Layout(0x378, 8, 0, 0x50, 0x370, 0x3D0, 0x3D2, 0x3D8)
ANCESTOR_FREE = ()


def word_bytes(value):
    return value.to_bytes(32, "big")


def addr_bytes(value):
    return value.to_bytes(20, "big")


class Sig:
    """by: recovered signer, good: covers the digest, broken: recovery fails."""

    def __init__(self, by=None, good=True, broken=False):
        self.by, self.good, self.broken = by, good, broken


class Qc:
    def __init__(self, version=2, start=100, round=999, hash=0x77, votes=()):
        self.version, self.start, self.round, self.hash, self.votes = version, start, round, hash, tuple(votes)


class TcRow:
    def __init__(self, qc, round, signer):
        self.qc, self.round, self.signer = qc, round, signer


class Tc:
    def __init__(self, round, rows=()):
        self.round, self.rows = round, tuple(rows)


class Block:
    def __init__(self, key, round, qc, hashes=(), tc=None, time=(30, 40, 50)):
        self.key, self.round, self.qc, self.hashes, self.tc, self.time = key, round, qc, tuple(hashes), tc, time


class VoteMsg:
    def __init__(self, signer, round=1000, hash=0x99, version=2, start=100, sig=None):
        self.signer, self.round, self.hash, self.version, self.start = signer, round, hash, version, start
        self.sig = sig


class TimeoutMsg:
    def __init__(self, signer, round=1000, qc=None, sig=None):
        self.signer, self.round, self.sig = signer, round, sig
        self.qc = qc if qc is not None else Qc(round=995, hash=0x66, votes=(1, 2))


class TimerFire:
    pass


class Case:
    def __init__(self, name, **extra):
        self.name = name
        self.kind = "event"
        self.steps = ()
        self.current = 1000
        self.voted = 999
        self.committed = 900
        self.highest = 990
        self.floor = None
        self.seen_rounds = {}
        self.stakes = {0: {1: 10, 2: 10, 3: 10, 4: 10}}
        self.base = 0
        self.valid_until = 100000
        self.version = 2
        self.start = 100
        self.stored_qcs = {}
        self.limit = 4
        self.blocks = ()
        self.txs = {}
        self.ancestors = ()
        self.ancestor_error = False
        self.now = (30, 41, 50)
        self.last_vote = (30, 30, 0)
        self.timed_out = False
        self.throttle = "row"
        self.leader = 7
        self.leader_error = False
        self.qc = None
        self.prefill = ()
        self.bad_qcs = ()
        self.fires = 0
        self.last_tc = None
        self.wait = (0, 300000000)
        self.__dict__.update(extra)


def fixture_digest(variant, data):
    return hashlib.sha256(bytes([variant]) + data).digest()


def digest_vote_fields(hash_value, version, start, round):
    return fixture_digest(1, word_bytes(hash_value) + struct.pack("<QQQ", version, start, round))


def digest_timeout_fields(qc, round):
    return fixture_digest(2, struct.pack("<Q", qc.round) + word_bytes(qc.hash) + struct.pack("<Q", round))


def block_digest(block):
    return fixture_digest(0, word_bytes(block.key) + struct.pack("<Q", block.round))


def signature_bytes(sig, digest, claimed):
    """A fixture signature: 20 byte recovered address, 32 byte digest it covers, flag byte."""
    sig = sig or Sig()
    by = claimed if sig.by is None else sig.by
    covered = digest if sig.good else b"\x00" * 32
    data = addr_bytes(by) + covered + (b"\x01" if sig.broken else b"\x00")
    return data.ljust(0x48, b"\x5a")


def other_address(data):
    return bytes(byte ^ 0xFF for byte in data[:20])


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_ERROR: self.on_panic, SLOT_DEALLOC: self.on_nothing, SLOT_LOG: self.on_log, SLOT_FORMAT: self.on_format, SLOT_RECOVER: self.on_recover,
                 SLOT_BTREE_PANIC: self.on_panic, SLOT_ASSERT: self.on_panic, SLOT_PANIC_FMT: self.on_panic, SLOT_LAZY: self.on_nothing, SLOT_RECORD: self.on_nothing, SLOT_LEADER: self.on_leader, SLOT_PROPOSER: self.on_proposer, SLOT_GROW_OUT: self.on_grow_out, SLOT_GROW_RING: self.on_panic}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        self.error_mark = MARK_BASE + 0x1000
        machine.slots[self.error_mark] = self.on_nothing
        memory.statics[SLOT_SNAPSHOT] = SNAPSHOT
        memory.statics[SLOT_QUORUM] = QUORUM
        memory.statics[SLOT_TIME_ADD] = 0x15206E0
        memory.statics[SLOT_DATE_ADD] = 0x151F870
        memory.statics[SLOT_SECONDS] = 0x1450A60
        memory.statics[SLOT_DURATION] = image.relative()[SLOT_DURATION]
        memory.statics[ONCE_WORD] = 0
        machine.real = frozenset(REAL_FUNCTIONS)
        machine.calls = {REARM: self.on_rearm, VERIFY_QC: self.on_verify_qc, NOW_INSTANT: self.on_instant, DIGEST: self.on_digest, SIGN_HASH: self.on_sign, ADVANCE: self.on_advance, ANCESTORS: self.on_ancestors, THROTTLE: self.on_throttle, ANCESTOR_FIND: self.on_ancestor_find, DROP_ERROR: self.on_drop_error, DROP_ROW: self.on_nothing, DROP_SET: self.on_nothing,
                         DROP_VALUE: self.on_nothing, 0x49478B0: self.on_drain, 0x48FF470: self.on_nothing, 0x49B91C0: self.on_nothing, 0x4881A80: self.on_drop_list, 0x49B05E0: self.on_nothing}
        machine.step_limit = STEP_LIMIT
        self.case = None
        self.bump = NODES
        self.high = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("fixture heap exhausted")
        return at

    def on_nothing(self, machine):
        pass

    def on_panic(self, machine):
        raise Panicked("panic")

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_format(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_log(self, machine):
        text = machine.regs[RSI]
        self.expect(text in (0x1E8C48, 0x202514), "log text")
        self.trace.append(("log", "high round" if text == 0x1E8C48 else "bad qcs"))

    def on_recover(self, machine):
        regs, memory = machine.regs, machine.memory
        out = regs[RDI]
        data = memory.bytes_at(regs[RSI], 0x48)
        digest = memory.bytes_at(regs[RDX], 32)
        if data[52]:
            memory.write(out, 1, 1)
            memory.write(out + 8, 8, ERROR_OBJECT)
            return
        memory.write(out, 1, 0)
        memory.put_bytes(out + 1, data[:20] if data[20:52] == digest else other_address(data))

    def on_instant(self, machine):
        machine.regs[RAX] = 100
        machine.regs[RDX] = 900000000
        machine.keep_rdx = True

    def on_digest(self, machine):
        regs, memory = machine.regs, machine.memory
        variant, at = memory.read(regs[RSI], 8), memory.read(regs[RSI] + 8, 8)
        if variant == 0:
            block = self.block_at(at)
            digest = block_digest(block)
        elif variant == 2:
            digest = fixture_digest(2, memory.bytes_at(at + 0x28, 0x30))
        else:
            self.expect(variant == 1, "digest variant")
            digest = fixture_digest(1, memory.bytes_at(at, 0x38))
        memory.put_bytes(regs[RDI], digest)

    def block_at(self, at):
        memory = self.machine.memory
        return self.by_body[memory.bytes_at(at + 0x88, 8) + memory.bytes_at(at + 0x48, 32)]

    def on_sign(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0x9D0, "signing key")
        out = regs[RDI]
        digest = memory.bytes_at(regs[RDX], 32)
        if self.case.sign_error if hasattr(self.case, "sign_error") else False:
            memory.write(out, 4, 1)
            return
        memory.write(out, 4, 0)
        memory.put_bytes(out + 8, digest + digest)
        memory.write(out + 0x48, 1, 0x1B)

    def on_advance(self, machine):
        regs, memory = machine.regs, machine.memory
        round = regs[RSI]
        tag = memory.read(regs[RDX], 8)
        self.expect(regs[RDI] == STATE, "advance arguments")
        if tag != NONE_TAG:
            rows, count = memory.read(regs[RDX] + 8, 8), memory.read(regs[RDX] + 16, 8)
            self.trace.append(("tc", tuple(int.from_bytes(memory.bytes_at(rows + 0xB8 * index + 0x58, 20), "big") for index in range(count)), memory.read(regs[RDX] + 0x18, 8)))
        current = memory.read(STATE + 0x918, 8)
        moved = round >= current
        if moved:
            memory.write(STATE + 0x918, 8, min(round + 1, MAX_ROUND))
        self.trace.append(("advance", round, moved))
        regs[RAX] = 1 if moved else 0

    def on_rearm(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == 0x5151 and regs[RCX] & 0xFF == 1, "timer handle")
        self.trace.append(("rearm", regs[RSI], regs[RDX] & 0xFFFFFFFF))

    def on_verify_qc(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDX] == TABLE, "qc table")
        key = int.from_bytes(memory.bytes_at(regs[RSI] + 0x30, 32), "big")
        memory.write(regs[RDI], 8, NONE_TAG + 9 if key in self.case.bad_qcs else OK_TAG)

    def on_proposer(self, machine):
        self.expect(machine.regs[RDI] == STATE, "proposer state")
        self.trace.append(("propose",))

    def on_leader(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == TABLE, "leader table")
        self.trace.append(("leader", regs[RDX]))
        if self.case.leader_error:
            memory.write(regs[RDI], 8, NO_SET_TAG)
            memory.write(regs[RDI] + 8, 8, regs[RDX])
            return
        memory.write(regs[RDI], 8, OK_TAG)
        memory.put_bytes(regs[RDI] + 8, addr_bytes(self.case.leader))

    def on_ancestors(self, machine):
        regs, memory = machine.regs, machine.memory
        out = regs[RDI]
        self.expect(regs[RSI] == STATE, "ancestor state")
        self.trace.append(("ancestors", int.from_bytes(memory.bytes_at(regs[RDX] + 0x30, 32), "big")))
        memory.put_bytes(out, b"\x00" * 0x20)
        if self.case.ancestor_error:
            memory.write(out, 1, 1)

    def on_ancestor_find(self, machine):
        regs, memory = machine.regs, machine.memory
        key = int.from_bytes(memory.bytes_at(regs[RSI], 32), "big")
        regs[RAX] = 0x7000 if key in self.case.ancestors else 0

    def on_throttle(self, machine):
        regs, memory = machine.regs, machine.memory
        kind = regs[R9] & 0xFFFFFFFF
        key = memory.bytes_at(regs[RCX], 32)
        self.expect(regs[R8] & 0xFFFFFFFF == 1 and machine.xmm[0] & MASK[8] == to_bits(0.15), "throttle arguments")
        self.expect(memory.bytes_at(regs[RDX], 12) == struct.pack("<iII", *self.case.now), "throttle time")
        self.trace.append(("request", kind, key.hex()))
        out = regs[RDI]
        memory.put_bytes(out, b"\x00" * 0x30)
        memory.write(out, 1, 2 if self.case.throttle == "held" else 1)
        memory.put_bytes(out + 8, key)

    def on_drop_error(self, machine):
        regs, memory = machine.regs, machine.memory
        self.trace.append(("error", memory.read(regs[RDI], 8) - NONE_TAG))

    def on_drain(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_drop_list(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<QQQ", 0, 8, 0))

    def on_grow_out(self, machine):
        raise Panicked("outbox fixture too small")

    def build(self, layout, items):
        """Write sorted (key bytes, value bytes) rows as one leaf or one root over leaves; returns (root, height)."""
        if not items:
            return 0, 0
        memory = self.machine.memory

        def node(rows, edges=()):
            at = self.alloc(layout.size)
            memory.put_bytes(at, b"\xee" * layout.size)
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for index, (key, value) in enumerate(rows):
                memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
                memory.put_bytes(at + layout.val_at + layout.val_size * index, value)
            for index, child in enumerate(edges):
                memory.write(at + layout.edges_at + 8 * index, 8, child)
                memory.write(child + layout.parent_at, 8, at)
                memory.write(child + layout.pidx_at, 2, index)
            return at

        if len(items) <= 11:
            return node(items), 0
        leaves = (len(items) + 12) // 12
        each = (len(items) - (leaves - 1)) // leaves
        spare = (len(items) - (leaves - 1)) % leaves
        children, parents, at = [], [], 0
        for index in range(leaves):
            count = each + (1 if index < spare else 0)
            children.append(node(items[at:at + count]))
            at += count
            if index + 1 < leaves:
                parents.append(items[at])
                at += 1
        return node(parents, children), 1

    def write_qc(self, at, qc):
        memory = self.machine.memory
        rows = self.alloc(max(len(qc.votes), 1) * 0x60)
        digest = digest_vote_fields(qc.hash, qc.version, qc.start, qc.round)
        for index, signer in enumerate(qc.votes):
            memory.put_bytes(rows + 0x60 * index, b"\xbb" * 0x60)
            memory.put_bytes(rows + 0x60 * index, addr_bytes(signer))
            memory.put_bytes(rows + 0x60 * index + 0x18, signature_bytes(None, digest, signer))
        memory.put_bytes(at, struct.pack("<QQQQQQ", len(qc.votes), rows, len(qc.votes), qc.version, qc.start, qc.round))
        memory.put_bytes(at + 0x30, word_bytes(qc.hash))

    def write_block(self, at, block):
        memory = self.machine.memory
        hashes = self.alloc(max(len(block.hashes), 1) * 32)
        for index, key in enumerate(block.hashes):
            memory.put_bytes(hashes + 32 * index, word_bytes(key))
        memory.put_bytes(at, b"\xcc" * BLOCK_VALUE)
        memory.put_bytes(at, struct.pack("<QQQ", len(block.hashes), hashes, len(block.hashes)))
        self.write_qc(at + 0x18, block.qc)
        if block.tc is None:
            memory.write(at + 0x68, 8, NONE_TAG)
        else:
            rows = self.alloc(max(len(block.tc.rows), 1) * 0xB8)
            for index, row in enumerate(block.tc.rows):
                address = rows + 0xB8 * index
                memory.put_bytes(address, b"\xbc" * 0xB8)
                self.write_qc(address, row.qc)
                memory.write(address + 0x50, 8, row.round)
                memory.put_bytes(address + 0x58, addr_bytes(row.signer))
            memory.put_bytes(at + 0x68, struct.pack("<QQQQ", len(block.tc.rows), rows, len(block.tc.rows), block.tc.round))
        memory.write(at + 0x88, 8, block.round)
        memory.put_bytes(at + 0x90, struct.pack("<iII", *block.time))
        memory.put_bytes(at + 0x9C, addr_bytes(9))
        self.by_body[struct.pack("<Q", block.round) + word_bytes(block.qc.hash)] = block

    def slot_value(self, voters):
        """Value of a hash slot: voter map, second map left empty."""
        rows = [(addr_bytes(signer), (b"%c" % (signer & 0xFF)) * 0x48) for signer in sorted(voters)]
        root, height = self.build(VOTER_LAYOUT, rows)
        return struct.pack("<QQQQQQ", root, height, len(rows), 0, 0, 0)

    def write_prefill(self, case):
        """case.prefill: (round, decided hash or None, {hash: signers})."""
        memory = self.machine.memory
        rows = []
        for round, decided, slots in sorted(case.prefill, key=lambda item: item[0]):
            items = [(word_bytes(key), self.slot_value(slots[key])) for key in sorted(slots)]
            root, height = self.build(SLOT_LAYOUT, items)
            value = bytearray(struct.pack("<QQQ", root, height, len(items)) + b"\x77" * 0x28)
            value[0x18] = 1
            value[0x39] = 0
            if decided is not None:
                value[0x18] = 0
                value[0x19:0x39] = word_bytes(decided)
                value[0x39] = 1
            rows.append((round.to_bytes(8, "little"), bytes(value)))
        root, height = self.build(ROUND_LAYOUT, rows)
        memory.put_bytes(STATE + 0x238, struct.pack("<II", 0 if case.floor is None else 1, 0) + struct.pack("<Q", case.floor or 0))
        memory.put_bytes(STATE + 0x260, struct.pack("<QQQ", root, height, len(rows)))

    def set_state(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.high - HEAP_BASE)
        self.bump = NODES
        self.trace, self.by_body = [], {}
        self.case = case
        memory.put_bytes(STATE, STATE_FILL)

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0x918, case.current)
        word(0x920, case.voted)
        word(0x198, case.committed)
        word(0x460, case.highest)
        memory.write(STATE + 0xB01, 1, 1 if case.timed_out else 0)
        memory.put_bytes(STATE + 0xAEC, addr_bytes(SELF))
        memory.put_bytes(STATE + 0xAB0, struct.pack("<iII", *case.last_vote))
        memory.put_bytes(STATE + 0xAC8, struct.pack("<iII", *case.now))
        memory.put_bytes(STATE + 0x4D0, struct.pack("<QQQ", 32, OUTBOX, 0))
        self.write_qc(STATE + 0x438, Qc(round=case.highest, hash=0x66, votes=(1, 2)))
        word(0x9B0, case.fires)
        word(0x9B8, 0)
        word(0x9C0, 0)
        word(0x9C8, 0)
        word(0x8C0, case.wait[0])
        memory.write(STATE + 0x8C8, 4, case.wait[1])
        word(0x8D0, 0x5151)
        memory.write(STATE + 0x8D8, 1, 0)
        word(0x8A0, NONE_TAG)
        if case.last_tc is not None:
            rows = self.alloc(max(len(case.last_tc.rows), 1) * 0xB8)
            for index, row in enumerate(case.last_tc.rows):
                self.write_timeout(rows + 0xB8 * index, TimeoutMsg(row.signer, row.round, row.qc))
            memory.put_bytes(STATE + 0x8A0, struct.pack("<QQQQ", len(case.last_tc.rows), rows, len(case.last_tc.rows), case.last_tc.round))
        self.write_prefill(case)
        items = [(round.to_bytes(8, "little"), self.qc_value(case.stored_qcs[round])) for round in sorted(case.stored_qcs)]
        root, height = self.build(QC_LAYOUT, items)
        ring = sorted(case.stored_qcs)
        for index, round in enumerate(ring):
            memory.write(RING + 8 * index, 8, round)
        memory.put_bytes(STATE + 0x488, struct.pack("<QQQQQQQQ", RING_CAP, RING, 0, len(ring), root, height, len(items), case.limit))
        table_rows = []
        for start in sorted(case.stakes):
            items = [(addr_bytes(key), value.to_bytes(8, "little")) for key, value in sorted(case.stakes[start].items())]
            root, height = self.build(STAKE_LAYOUT, items)
            table_rows.append((start.to_bytes(8, "little"), struct.pack("<QQQ", root, height, len(items))))
        root, height = self.build(TABLE_LAYOUT, table_rows)
        memory.put_bytes(TABLE, b"\xab" * 0x60)
        memory.put_bytes(TABLE, struct.pack("<QQQ", case.base, root, height))
        memory.put_bytes(TABLE + 0x40, struct.pack("<QQ", case.version, case.start))
        memory.write(TABLE + 0x58, 8, case.valid_until)
        items = [(signer.to_bytes(20, "big"), value.to_bytes(8, "little")) for signer, value in sorted(case.seen_rounds.items())]
        root, height = self.build(STAKE_LAYOUT, items)
        memory.put_bytes(STATE + 0xA68, struct.pack("<QQQ", root, height, len(items)))
        rows = []
        for key in sorted(case.txs):
            value = bytearray(b"\xdd" * TX_VALUE)
            kind = case.txs[key]
            value[0:12] = struct.pack("<iII", 5, 6, 7)
            struct.pack_into("<Q", value, 0x10, PLACEHOLDER_TAG if kind == "placeholder" else 0x55)
            value[0x50] = 1 if kind == "flagged" else 0
            rows.append((word_bytes(key), bytes(value)))
        root, height = self.build(TX_LAYOUT, rows)
        word(0x1A0, root)
        word(0x1A8, height)
        word(0x1B0, len(rows))
        rows = []
        for block in sorted(case.blocks, key=lambda item: item.key):
            temp = self.alloc(BLOCK_VALUE)
            self.write_block(temp, block)
            rows.append((word_bytes(block.key), memory.bytes_at(temp, BLOCK_VALUE)))
        root, height = self.build(BLOCK_LAYOUT, rows)
        word(0x1B8, root)
        word(0x1C0, height)
        word(0x1C8, len(rows))
        word(0x58, 0)
        word(0x60, 0)
        word(0x68, 0)
        memory.write(ERROR_OBJECT, 8, ERROR_VTABLE)
        memory.write(ERROR_VTABLE, 8, self.error_mark)

    def qc_value(self, qc):
        memory = self.machine.memory
        at = self.alloc(0x50)
        self.write_qc(at, qc)
        return memory.bytes_at(at, 0x50)

    def write_timeout(self, at, item):
        memory = self.machine.memory
        memory.put_bytes(at, b"\xbc" * 0xB8)
        self.write_qc(at, item.qc)
        memory.write(at + 0x50, 8, item.round)
        memory.put_bytes(at + 0x58, addr_bytes(item.signer))
        memory.put_bytes(at + 0x70, signature_bytes(item.sig, digest_timeout_fields(item.qc, item.round), item.signer))

    def write_event(self, vote):
        memory = self.machine.memory
        if isinstance(vote, TimerFire):
            memory.put_bytes(EVENT, b"\xc3" * 0x180)
            memory.write(EVENT, 8, 0xC)
            return
        if isinstance(vote, TimeoutMsg):
            memory.put_bytes(EVENT, b"\xc3" * 0x180)
            memory.write(EVENT, 8, 8)
            self.write_timeout(EVENT + 8, vote)
            return
        memory.put_bytes(EVENT, b"\xc3" * 0x180)
        memory.write(EVENT, 8, 7)
        at = EVENT + 8
        memory.put_bytes(at, word_bytes(vote.hash))
        memory.put_bytes(at + 0x20, struct.pack("<QQQ", vote.version, vote.start, vote.round))
        memory.put_bytes(at + 0x38, addr_bytes(vote.signer))
        digest = digest_vote_fields(vote.hash, vote.version, vote.start, vote.round)
        memory.put_bytes(at + 0x50, signature_bytes(vote.sig, digest, vote.signer))

    def run_event(self, vote):
        machine = self.machine
        memory = machine.memory
        self.write_event(vote)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(TIME_IN, struct.pack("<iII", *self.case.now))
        machine.regs = [POISON] * 16
        machine.regs[RSP] = STACK_TOP - 0x100
        machine.regs[RDI] = HEAP_BASE + 0x2900
        machine.regs[RSI] = STATE
        machine.regs[RDX] = TIME_IN
        machine.regs[RCX] = EVENT
        machine.push(RETURN_SENTINEL)
        machine.stops = frozenset((STOP_TAIL, STOP_TIMER))
        machine.left = machine.step_limit
        machine.stopped = None
        machine.loop(DISPATCH)
        machine.stops = frozenset()
        if machine.stopped not in (STOP_TAIL, STOP_TIMER):
            raise Halt("event left the arm")

    def run(self, case):
        machine = self.machine
        self.set_state(case)
        out = []
        panicked = None
        try:
            if case.kind == "event":
                for vote in case.steps:
                    mark = len(self.trace)
                    self.run_event(vote)
                    out.append(self.trace[mark:])
            elif case.kind == "record":
                self.write_qc(QC_IN, case.qc)
                machine.xmm = [POISON | POISON << 64] * 16
                result = machine.run(RECORD_QC, {RDI: STATE, RSI: QC_IN})
                self.trace.append(("record", result & 0xFF))
            else:
                machine.xmm = [POISON | POISON << 64] * 16
                machine.run(MAYBE_VOTE, {RDI: STATE})
        except Panicked as error:
            panicked = str(error)
        self.high = max(self.high, self.bump)
        return self.observe(panicked)

    def walk(self, node, depth, layout, emit):
        memory = self.machine.memory
        count = memory.read(node + layout.len_at, 2)
        for index in range(count):
            if depth:
                self.walk(memory.read(node + layout.edges_at + 8 * index, 8), depth - 1, layout, emit)
            emit(memory.bytes_at(node + layout.key_at + layout.key_size * index, layout.key_size), node + layout.val_at + layout.val_size * index)
        if depth:
            self.walk(memory.read(node + layout.edges_at + 8 * count, 8), depth - 1, layout, emit)

    def rows_of(self, root, height, layout):
        rows = []
        if root:
            self.walk(root, height, layout, lambda key, at: rows.append((key, at)))
        return rows

    def tracker(self):
        memory = self.machine.memory
        out = {}
        for key, at in self.rows_of(memory.read(STATE + 0x260, 8), memory.read(STATE + 0x268, 8), ROUND_LAYOUT):
            slots = {}
            for name, slot in self.rows_of(memory.read(at, 8), memory.read(at + 8, 8), SLOT_LAYOUT):
                voters = [int.from_bytes(item, "big") for item, _ in self.rows_of(memory.read(slot, 8), memory.read(slot + 8, 8), VOTER_LAYOUT)]
                slots[int.from_bytes(name, "big")] = voters
            decided = int.from_bytes(memory.bytes_at(at + 0x19, 32), "big") if memory.read(at + 0x39, 1) else None
            out[int.from_bytes(key, "little")] = (decided, slots)
        return out

    def seen_map(self):
        memory = self.machine.memory
        return {int.from_bytes(key, "big"): memory.read(at, 8) for key, at in self.rows_of(memory.read(STATE + 0xA68, 8), memory.read(STATE + 0xA70, 8), STAKE_LAYOUT)}

    def qc_tuple(self, at):
        memory = self.machine.memory
        rows, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8)
        signers = [int.from_bytes(memory.bytes_at(rows + 0x60 * index, 20), "big") for index in range(count)]
        return (memory.read(at + 0x18, 8), memory.read(at + 0x20, 8), memory.read(at + 0x28, 8), int.from_bytes(memory.bytes_at(at + 0x30, 32), "big"), tuple(signers))

    def qc_map(self):
        memory = self.machine.memory
        return {int.from_bytes(key, "little"): self.qc_tuple(at) for key, at in self.rows_of(memory.read(STATE + 0x4A8, 8), memory.read(STATE + 0x4B0, 8), QC_LAYOUT)}

    def outbox(self):
        memory = self.machine.memory
        rows = []
        for index in range(memory.read(STATE + 0x4E0, 8)):
            at = OUTBOX + 0x168 * index
            tag = memory.read(at, 8)
            if tag == 5:
                rows.append(("timeout", self.qc_tuple(at + 8), memory.read(at + 0x58, 8), int.from_bytes(memory.bytes_at(at + 0x60, 20), "big"), memory.bytes_at(at + 0x78, 65).hex()))
            elif tag == 6:
                vector, count = memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)
                rows.append(("tc", tuple(int.from_bytes(memory.bytes_at(vector + 0xB8 * index + 0x58, 20), "big") for index in range(count)), memory.read(at + 0x20, 8)))
            elif tag == 4:
                rows.append(("vote", int.from_bytes(memory.bytes_at(at + 8, 32), "big"), memory.read(at + 0x28, 8), memory.read(at + 0x30, 8), memory.read(at + 0x38, 8), int.from_bytes(memory.bytes_at(at + 0x40, 20), "big"), memory.bytes_at(at + 0x58, 65).hex(), int.from_bytes(memory.bytes_at(at + 0xA0, 20), "big")))
            else:
                rows.append(("request", tag, memory.bytes_at(at + 8, 0x28).hex()))
        return rows

    def observe(self, panicked):
        memory = self.machine.memory
        words = {name: memory.read(STATE + at, 8) for name, at in (("current", 0x918), ("voted", 0x920), ("highest", 0x460), ("floor_on", 0x238), ("floor", 0x240), ("fires", 0x9B0), ("timeouts", 0x9C8))}
        words["timed_out"] = memory.read(STATE + 0xB01, 1)
        words["armed"] = memory.read(STATE + 0x8D8, 1)
        words["floor_on"] &= 0xFFFFFFFF
        return dict(panic=panicked, trace=list(self.trace), words=words, tracker=self.tracker(), seen=self.seen_map(), qcs=self.qc_map(), best=self.qc_tuple(STATE + 0x438) if memory.read(STATE + 0x440, 8) else None, outbox=self.outbox(),
                    last_vote=struct.unpack("<iII", memory.bytes_at(STATE + 0xAB0, 12)))


class SpecPanic(Exception):
    pass


def spec_set(case, round):
    """The stake set for a round: the last table key at or under the bound."""
    if not case.stakes:
        return None
    limit = min(case.base + RECENT_SPAN, MAX_ROUND)
    bound = case.base if round < limit else max(case.base, (round - LOW_ROUNDS) & MASK[8])
    keys = [key for key in case.stakes if key <= bound]
    return case.stakes[max(keys)] if keys else None


def spec_quorum(stakes, signers):
    signed = 0
    for address in sorted(set(signers)):
        signed += stakes.get(address, 0)
        if signed > MAX_ROUND:
            raise SpecPanic("stake overflow")
    total = 0
    for value in stakes.values():
        total += value
        if total > MAX_ROUND:
            raise SpecPanic("stake overflow")
    return 3 * signed > 2 * total


class Model:
    def __init__(self, case):
        self.case = case
        self.current, self.voted, self.highest = case.current, case.voted, case.highest
        self.floor_on, self.floor = (0, 0) if case.floor is None else (1, case.floor)
        self.tracker = {}
        for round, decided, slots in case.prefill:
            self.tracker[round] = [decided, {key: sorted(value) for key, value in slots.items()}]
        self.seen = dict(case.seen_rounds)
        self.qcs = {round: (qc.version, qc.start, qc.round, qc.hash, tuple(qc.votes)) for round, qc in case.stored_qcs.items()}
        self.ring = sorted(case.stored_qcs)
        self.best = (2, 100, case.highest, 0x66, (1, 2))
        self.fires = case.fires
        self.timeouts = []
        self.timed_out = 1 if case.timed_out else 0
        self.armed = 0
        self.trace = []
        self.outbox = []
        self.last_vote = case.last_vote
        self.panic = None

    def record(self, qc):
        """QC record: map keeps the first QC of a round, ring evicts, highest moves, round moves."""
        version, start, round, hash_value, signers = qc
        old = self.qcs.get(round)
        if old is not None:
            if old[:2] != qc[:2] or old[3] != hash_value:
                self.trace.append(("log", "bad qcs"))
        else:
            self.qcs[round] = qc
            self.ring.append(round)
            while len(self.ring) > self.case.limit:
                self.qcs.pop(self.ring.pop(0), None)
        if round > self.highest:
            self.highest, self.best = round, qc
        moved = round >= self.current
        if moved:
            self.current = min(round + 1, MAX_ROUND)
        self.trace.append(("advance", round, moved))
        return moved

    def send_timeout(self):
        case = self.case
        digest = fixture_digest(2, struct.pack("<Q", self.best[2]) + word_bytes(self.best[3]) + struct.pack("<Q", self.current))
        self.timed_out = 1
        self.outbox.append(("timeout", self.best, self.current, SELF, (digest + digest + b"\x1b").hex()))
        if case.last_tc is not None:
            self.outbox.append(("tc", tuple(row.signer for row in case.last_tc.rows), case.last_tc.round))

    def fire(self):
        self.fires = min(self.fires + 1, MAX_ROUND)
        if not self.timed_out:
            self.send_timeout()
        if self.fires >= 2:
            self.send_timeout()
        secs, ns = self.case.wait
        ns += 900000000
        secs += 100
        if ns >= 1000000000:
            ns -= 1000000000
            secs += 1
        self.trace.append(("rearm", secs, ns))
        self.armed = 1
        return "timer fired"

    def timeout(self, item):
        case = self.case
        ok = item.qc.hash not in case.bad_qcs
        if not ok:
            self.trace.append(("error", 9))
        else:
            qc = item.qc
            if self.record((qc.version, qc.start, qc.round, qc.hash, tuple(qc.votes))):
                return "qc in timeout moved round"
        if item.round != self.current:
            self.trace.append(("error", 0xF))
            return "timeout other round"
        if item.signer in self.timeouts:
            self.trace.append(("error", 0x10))
            return "timeout repeated"
        if item.round > case.valid_until:
            self.trace.append(("log", "high round"))
        stakes = spec_set(case, item.round)
        if stakes is None:
            self.trace.append(("error", 0x28))
            return "no stake set"
        if not ok:
            self.trace.append(("error", 9))
            return "timeout bad qc"
        sig = item.sig or Sig()
        if item.signer not in stakes:
            self.trace.append(("error", 1))
            return "unknown signer"
        if sig.broken:
            self.trace.append(("error", 1))
            return "recover failed"
        if not sig.good or (sig.by is not None and sig.by != item.signer):
            self.trace.append(("error", 1))
            return "other address"
        self.seen[item.signer] = max(self.seen.get(item.signer, 0), item.round)
        if item.round > case.valid_until:
            self.trace.append(("log", "high round"))
        self.timeouts.append(item.signer)
        self.timeouts.sort()
        signed = sum(stakes.get(signer, 0) for signer in self.timeouts)
        total = sum(stakes.values())
        joined = False
        if not self.timed_out and min(3 * signed, MAX_ROUND) > total:
            self.send_timeout()
            joined = True
        if 3 * signed <= 2 * total:
            return "timeout counted, joined" if joined else "timeout counted"
        self.trace.append(("tc", tuple(self.timeouts), self.current))
        round = self.current
        self.timeouts = []
        moved = round >= self.current
        self.current = min(round + 1, MAX_ROUND)
        self.trace.append(("advance", round, moved))
        self.trace.append(("propose",))
        return "tc formed"

    def vote(self, vote):
        case = self.case
        if isinstance(vote, TimerFire):
            return self.fire()
        if isinstance(vote, TimeoutMsg):
            return self.timeout(vote)
        if vote.round < self.current:
            return "stale round"
        if vote.round > case.valid_until:
            self.trace.append(("log", "high round"))
        stakes = spec_set(case, vote.round)
        if stakes is None:
            self.trace.append(("error", 0x28))
            return "no stake set"
        if (vote.version, vote.start) != (case.version, case.start):
            self.trace.append(("error", 0))
            return "version pair"
        sig = vote.sig or Sig()
        if vote.signer not in stakes:
            self.trace.append(("error", 1))
            return "unknown signer"
        if sig.broken:
            self.trace.append(("error", 1))
            return "recover failed"
        if not sig.good or (sig.by is not None and sig.by != vote.signer):
            self.trace.append(("error", 1))
            return "other address"
        self.seen[vote.signer] = max(self.seen.get(vote.signer, 0), vote.round)
        if vote.round < self.voted:
            return "under voted round"
        if vote.round > case.valid_until:
            self.trace.append(("log", "high round"))
        if self.floor_on and vote.round < self.floor:
            return "under floor"
        entry = self.tracker.setdefault(vote.round, [None, {}])
        slot = entry[1].setdefault(vote.hash, [])
        if entry[0] is not None:
            if vote.signer not in slot:
                slot.append(vote.signer)
                slot.sort()
            return "late vote"
        before = spec_quorum(stakes, slot)
        if vote.signer not in slot:
            slot.append(vote.signer)
            slot.sort()
        if before or not spec_quorum(stakes, slot):
            return "collected"
        entry[0] = vote.hash
        if vote.round >= KEEP_ROUNDS:
            cut = vote.round - KEEP_ROUNDS
            for round in [key for key in self.tracker if key < cut]:
                del self.tracker[round]
            self.floor = max(cut, self.floor) if self.floor_on else cut
            self.floor_on = 1
        qc = (vote.version, vote.start, vote.round, vote.hash, tuple(slot))
        if self.record(qc):
            self.trace.append(("propose",))
            return "qc formed, round moved"
        return "qc formed, round stays"


def time_tuple_add(time, nanos):
    date, secs, ns = time
    ns += nanos
    secs += ns // 1000000000
    ns %= 1000000000
    date += 16 * (secs // 86400)
    return (date, secs % 86400, ns)


def age_seconds(now, then):
    delta = ((now[0] - then[0]) // 16 * 86400 + now[1] - then[1]) * 1000000000 + now[2] - then[2]
    micros = abs(delta) // 1000
    return micros / 1000000.0


def spec_rule(block, voted):
    qc, round = block.qc.round, block.round
    direct = min(qc + 1, MAX_ROUND) == round
    if block.tc is None:
        allowed = direct
    elif not block.tc.rows:
        return False
    else:
        top = max(row.qc.round for row in block.tc.rows)
        allowed = direct or (min(block.tc.round + 1, MAX_ROUND) == round and qc >= top)
    return allowed and round > voted


def spec_request(model, kind, key):
    model.trace.append(("request", kind, key.hex()))
    if model.case.throttle == "row":
        model.outbox.append(("request", 10, (b"\x01" + b"\x00" * 7 + key).hex()))


def spec_maybe(case):
    model = Model(case)
    round = case.current
    if round > case.valid_until:
        model.trace.append(("log", "high round"))
    stakes = spec_set(case, round)
    if stakes is None:
        model.trace.append(("error", 0x28))
        return "no stake set", model
    if SELF not in stakes:
        return "not a validator", model
    if case.now < time_tuple_add(case.last_vote, SPACING_NS):
        return "under 50 ms", model
    if not case.blocks:
        return "no blocks", model
    blocks = {block.key: block for block in case.blocks}
    tip = None
    for block in sorted(case.blocks, key=lambda item: item.key):
        if tip is None or block.round >= tip.round:
            tip = block
    if tip.round <= case.voted:
        return "already voted", model
    if tip.round <= case.committed:
        return "under committed", model
    walk = tip
    while True:
        for key in walk.hashes:
            kind = case.txs.get(key)
            if kind is None or kind == "placeholder":
                spec_request(model, 3, block_digest(walk))
                return "fetch tx", model
        parent = blocks.get(walk.qc.hash)
        if parent is None:
            spec_request(model, 4, word_bytes(walk.qc.hash))
            return "fetch parent", model
        if not walk.time > parent.time:
            return "time not after parent", model
        if parent.round <= case.committed:
            break
        walk = parent
    model.trace.append(("ancestors", tip.qc.hash))
    if case.ancestor_error:
        return "ancestor walk failed", model
    for key in tip.hashes:
        if case.txs.get(key) in (None, "placeholder", "flagged") or key in case.ancestors:
            return "tx refused", model
    if tip.round != case.current or case.timed_out:
        return "not this round", model
    if age_seconds(case.now, tip.time) > MAX_AGE:
        return "over 3.5 s", model
    if not spec_rule(tip, case.voted):
        return "rule refused", model
    model.trace.append(("leader", min(tip.round + 1, MAX_ROUND)))
    if case.leader_error:
        model.trace.append(("error", 0x28))
        return "no leader", model
    digest = block_digest(tip)
    payload = digest + struct.pack("<QQQ", tip.qc.version, tip.qc.start, tip.round)
    signed = fixture_digest(1, payload)
    model.voted = tip.round
    model.last_vote = case.now
    model.outbox.append(("vote", int.from_bytes(digest, "big"), tip.qc.version, tip.qc.start, tip.round, SELF, (signed + signed + b"\x1b").hex(), case.leader))
    return "voted", model


def spec_run(case):
    if case.kind == "record":
        model = Model(case)
        qc = case.qc
        moved = model.record((qc.version, qc.start, qc.round, qc.hash, tuple(qc.votes)))
        model.trace.append(("record", 1 if moved else 0))
        return ("record moved" if moved else "record stays"), model
    if case.kind == "maybe":
        return spec_maybe(case)
    model = Model(case)
    labels = []
    try:
        for vote in case.steps:
            labels.append(model.vote(vote))
    except SpecPanic:
        model.panic = "panic"
        labels.append("panic")
    return labels[-1], model


def spec_view(model):
    tracker = {round: (entry[0], {key: list(value) for key, value in entry[1].items()}) for round, entry in model.tracker.items()}
    return dict(panic=model.panic, trace=model.trace, words=dict(current=model.current, voted=model.voted, highest=model.highest, floor_on=model.floor_on, floor=model.floor, fires=model.fires, timeouts=len(model.timeouts), timed_out=model.timed_out, armed=model.armed), tracker=tracker, seen=model.seen, qcs=model.qcs, best=model.best, outbox=model.outbox, last_vote=model.last_vote)


def same(got, want):
    return all(got[key] == want[key] for key in want)


def differ(got, want):
    return [(key, got[key], want[key]) for key in want if got[key] != want[key]]


DAY = (2026 << 13) | (100 << 4) | 10
NOW = (DAY, 1000, 500000000)


def good_block(round=1000, qc_round=999, key=0x11, parent=0x10, hashes=(), tc=None, time=(DAY, 999, 500000000)):
    return Block(key, round, Qc(round=qc_round, hash=parent, votes=(1, 2, 3)), hashes=hashes, tc=tc, time=time)


def parent_block(key=0x10, round=999, time=(DAY, 998, 0), hash=8):
    return Block(key, round, Qc(round=round - 1, hash=hash), time=time)


def send(name, tip=None, parent=None, **extra):
    tip = tip if tip is not None else good_block()
    blocks = (tip,) if parent is False else (parent or parent_block(), tip)
    options = dict(kind="maybe", blocks=blocks, committed=999, voted=999, current=1000, now=NOW, last_vote=(DAY, 900, 0))
    options.update(extra)
    return Case(name, **options)


def tc_row(qc_round, signer=1, round=999):
    return TcRow(Qc(round=qc_round, hash=0x70, votes=(1,)), round, signer)


def named_cases():
    cases = []

    def add(name, *votes, **extra):
        cases.append(Case(name, steps=votes, now=NOW, last_vote=(DAY, 900, 0), **extra))
    V = VoteMsg
    add("vote one", V(1))
    add("vote two of four", V(1), V(2))
    add("vote three of four forms qc", V(1), V(2), V(3))
    add("vote exactly two thirds stays", V(1), V(2), stakes={0: {1: 10, 2: 10, 3: 10}})
    add("vote one over two thirds forms", V(1), V(2), stakes={0: {1: 10, 2: 11, 3: 10}})
    add("vote stake not count", V(1), stakes={0: {1: 70, 2: 10, 3: 10, 4: 10}})
    add("vote repeated signer no weight", V(1), V(1), V(1), V(2))
    add("vote stale under current", V(1, round=999))
    add("vote at current", V(1, round=1000))
    add("vote future round", V(1, round=1005), V(2, round=1005), V(3, round=1005))
    add("vote under voted round", V(1, round=1000), voted=1001)
    add("vote equal voted round", V(1, round=1000), voted=1000)
    add("vote high round warning", V(1, round=1000), valid_until=999)
    add("vote high round at limit", V(1, round=1000), valid_until=1000)
    add("vote no stake set", V(1), stakes={})
    add("vote no stake key", V(1), base=0, stakes={2000: {1: 10}})
    add("vote version first word", V(1, version=3))
    add("vote version second word", V(1, start=101))
    add("vote unknown signer", V(9))
    add("vote recover failed", V(1, sig=Sig(broken=True)))
    add("vote other recovered address", V(1, sig=Sig(by=2)))
    add("vote signature over other digest", V(1, sig=Sig(good=False)))
    add("vote bad signature keeps seen map", V(1), V(2, sig=Sig(good=False)))
    add("vote seen map higher stays", V(1, round=1000), seen_rounds={1: 2000})
    add("vote seen map lower moves", V(1, round=1000), seen_rounds={1: 5})
    add("vote seen map under voted still moves", V(1, round=1000), voted=1002, seen_rounds={1: 5})
    add("vote two hashes split", V(1, hash=0x99), V(2, hash=0x98), V(3, hash=0x99), V(4, hash=0x98))
    add("vote two hashes one decides", V(1, hash=0x98), V(2), V(3), V(4))
    add("vote other round rows apart", V(1, round=1001), V(2, round=1002), V(3, round=1003))
    add("vote late same hash", V(1, round=1005), V(2, round=1005), V(3, round=1005), V(4, round=1005), current=1000)
    add("vote late other hash", V(4, hash=0x98, round=1005), prefill=((1005, 0x99, {0x99: (1, 2, 3)}),), current=1000)
    add("vote decided then third hash", V(4, hash=0x97, round=1005), V(2, hash=0x97, round=1005), prefill=((1005, 0x99, {0x99: (1, 2, 3)}),))
    add("vote undecided quorum slot", V(4, round=1005), prefill=((1005, None, {0x99: (1, 2, 3)}),))
    add("vote undecided quorum same signer", V(1, round=1005), prefill=((1005, None, {0x99: (1, 2, 3)}),))
    add("vote under floor", V(1, round=1000), floor=1001)
    add("vote at floor", V(1, round=1001), floor=1001)
    add("vote no floor", V(1, round=1))
    add("qc prunes under window", V(1), V(2), V(3), prefill=((904, None, {0x55: (1,)}), (905, None, {0x55: (2,)}), (906, None, {0x55: (3,)})))
    add("qc under 95 no prune", V(1, round=94), V(2, round=94), V(3, round=94), current=50, voted=40, prefill=((1, None, {0x55: (1,)}),))
    add("qc at 95 prunes to zero", V(1, round=95), V(2, round=95), V(3, round=95), current=50, voted=40, prefill=((0, None, {0x55: (1,)}), (1, None, {0x55: (1,)})))
    add("qc floor stays higher", V(1), V(2), V(3), floor=950)
    add("qc floor moves up", V(1), V(2), V(3), floor=800)
    add("qc highest not passed", V(1), V(2), V(3), highest=2000)
    add("qc equal highest", V(1), V(2), V(3), highest=1000)
    add("qc above highest", V(1), V(2), V(3), highest=999)
    add("qc round stays when stale after advance", V(1), V(2), V(3), V(1, round=1000))
    add("qc same round stored same", V(1), V(2), V(3), stored_qcs={1000: Qc(round=1000, hash=0x99, votes=(1, 2))})
    add("qc same round other hash logs", V(1), V(2), V(3), stored_qcs={1000: Qc(round=1000, hash=0x98, votes=(1, 2))})
    add("qc same round other version logs", V(1), V(2), V(3), stored_qcs={1000: Qc(round=1000, version=1, hash=0x99, votes=(1, 2))})
    add("qc same round other second word logs", V(1), V(2), V(3), stored_qcs={1000: Qc(round=1000, start=99, hash=0x99, votes=(1, 2))})
    add("qc ring under limit", V(1), V(2), V(3), stored_qcs={1: Qc(round=1), 2: Qc(round=2)}, limit=4)
    add("qc ring evicts oldest", V(1), V(2), V(3), stored_qcs={1: Qc(round=1), 2: Qc(round=2), 3: Qc(round=3), 4: Qc(round=4)}, limit=4)
    add("qc ring limit one", V(1), V(2), V(3), stored_qcs={7: Qc(round=7)}, limit=1)
    add("qc voters sorted", V(3), V(1), V(2))
    add("qc many voters tree split", *[V(index) for index in range(1, 16)], stakes={0: {index: 10 for index in range(1, 21)}})
    add("qc many rounds", *[V(1, round=1000 + index) for index in range(14)])
    add("round tree split then qc", *[V(1, round=1000 + index) for index in range(13)], V(2, round=1013), V(3, round=1013))
    add("hash tree split", *[V(1, hash=0x100 + index) for index in range(14)])
    add("qc many stake sets", V(1, round=3000), V(2, round=3000), V(3, round=3000), base=100, stakes={0: {5: 1}, 100: {1: 10, 2: 10, 3: 1}, 2800: {1: 10, 2: 10, 3: 10, 4: 10}}, current=3000, voted=2999)
    add("qc max round saturates", V(1, round=MAX_ROUND), V(2, round=MAX_ROUND), V(3, round=MAX_ROUND), base=MAX_ROUND - 10, stakes={MAX_ROUND - 10: {1: 10, 2: 10, 3: 10, 4: 10}}, valid_until=MAX_ROUND, current=MAX_ROUND - 1, voted=0)
    add("tracker 101 rounds no trim", *[V(1, round=1000 + index) for index in range(102)])

    T = TimeoutMsg
    F = TimerFire
    add("timer first fire", F())
    add("timer second fire", F(), F())
    add("timer third fire", F(), F(), F())
    add("timer fire after timed out", F(), timed_out=True)
    add("timer count two not timed out", F(), fires=1)
    add("timer fire saturates", F(), fires=MAX_ROUND)
    add("timer resend tc", F(), last_tc=Tc(998, (TcRow(Qc(round=990), 998, 2), TcRow(Qc(round=990), 998, 3))))
    add("timer wait carry", F(), wait=(5, 200000000))
    add("timer wait no carry", F(), wait=(5, 99999999))
    add("timer wait carry exact", F(), wait=(5, 100000000))
    add("timer uses higher qc", V(1), V(2), V(3), F())
    add("timeout one", T(1))
    add("timeout stale round", T(1, round=999))
    add("timeout future round", T(1, round=1001))
    add("timeout repeated", T(1), T(1))
    add("timeout one third no join", T(2), stakes={0: {1: 10, 2: 10, 3: 10}})
    add("timeout over one third joins", T(2), stakes={0: {1: 10, 2: 11, 3: 10}})
    add("timeout two of four joins", T(2), T(3))
    add("timeout three of four tc", T(2), T(3), T(4))
    add("timeout join once only", T(2), T(3), T(4), stakes={0: {1: 1, 2: 40, 3: 40, 4: 40}})
    add("timeout no join after own", T(2), T(3), timed_out=True)
    add("timeout exact two thirds no tc", T(2), T(3), stakes={0: {2: 10, 3: 10, 4: 10}})
    add("timeout over two thirds tc", T(2), T(3), stakes={0: {2: 10, 3: 11, 4: 10}})
    add("timeout tc rows sorted", T(3), T(2), T(4))
    add("timeout tc saves nothing else", T(2), T(3), T(4), F())
    add("timeout unknown signer", T(9))
    add("timeout recover failed", T(1, sig=Sig(broken=True)))
    add("timeout other address", T(1, sig=Sig(by=2)))
    add("timeout other digest", T(1, sig=Sig(good=False)))
    add("timeout bad qc", T(1), bad_qcs=(0x66,))
    add("timeout qc moves round", T(1, qc=Qc(round=1000, hash=0x65, votes=(1, 2))))
    add("timeout qc past round drops", T(1, round=1001, qc=Qc(round=1000, hash=0x65, votes=(1, 2))))
    add("timeout qc recorded", T(1, qc=Qc(round=995, hash=0x65, votes=(1, 2))))
    add("timeout qc above highest", T(1, qc=Qc(round=996, hash=0x65, votes=(1,))), highest=990)
    add("timeout high round warning", T(1, round=1000), valid_until=999)
    add("timeout no stake set", T(1), stakes={})
    add("timeout seen map", T(1), seen_rounds={1: 2000})
    add("timeout count before vote mix", V(1), T(2), V(2), T(3), V(3))
    add("timeout join product saturates", T(2), stakes={0: {1: 1 << 62, 2: 1 << 63}})
    add("timeout product past 64 bits after own", T(2), stakes={0: {1: 1 << 62, 2: 1 << 63}}, timed_out=True)
    add("timeout tc compare past 64 bits", T(1), T(2), T(3), stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1 << 62, 4: 5}}, timed_out=True)

    def rec(name, qc, **extra):
        cases.append(Case(name, kind="record", qc=qc, now=NOW, last_vote=(DAY, 900, 0), **extra))
    rec("record new above", Qc(round=1000, hash=0x99, votes=(1, 2, 3)))
    rec("record new under current", Qc(round=995, hash=0x99, votes=(1, 2, 3)))
    rec("record equal highest", Qc(round=990, hash=0x99, votes=(1,)))
    rec("record under highest", Qc(round=980, hash=0x99, votes=(1,)))
    rec("record same bytes", Qc(round=995, hash=0x99, votes=(1,)), stored_qcs={995: Qc(round=995, hash=0x99, votes=(2,))})
    rec("record other hash", Qc(round=995, hash=0x98, votes=(1,)), stored_qcs={995: Qc(round=995, hash=0x99, votes=(2,))})
    rec("record other hash high", Qc(round=1000, hash=0x98, votes=(1,)), stored_qcs={1000: Qc(round=1000, hash=0x99, votes=(2,))})
    rec("record empty votes", Qc(round=1001, hash=0x98))
    rec("record eviction", Qc(round=1000, hash=0x98, votes=(1,)), stored_qcs={1: Qc(round=1), 2: Qc(round=2), 3: Qc(round=3), 4: Qc(round=4)})
    rec("record evict self", Qc(round=5, hash=0x98, votes=(1,)), stored_qcs={7: Qc(round=7), 8: Qc(round=8)}, limit=2)

    def out(name, tip=None, parent=None, **extra):
        cases.append(send(name, tip, parent, **extra))
    out("send direct qc")
    out("send no block", parent=False, tip=None, blocks=())
    out("send high round warning", valid_until=999)
    out("send no stake set", stakes={})
    out("send not a validator", stakes={0: {2: 10}})
    out("send last vote 49 ms", last_vote=(DAY, 1000, 450000001))
    out("send last vote 50 ms", last_vote=(DAY, 1000, 450000000))
    out("send last vote over second", last_vote=(DAY, 999, 950000000))
    out("send last vote under second by one", last_vote=(DAY, 999, 950000001))
    out("send last vote midnight carry", last_vote=(DAY, 86399, 990000000), now=(DAY + 16, 0, 40000000), tip=good_block(time=(DAY + 16, 0, 0)), parent=parent_block(time=(DAY, 80000, 0)))
    out("send last vote midnight short", last_vote=(DAY, 86399, 990000000), now=(DAY + 16, 0, 39999999), tip=good_block(time=(DAY + 16, 0, 0)), parent=parent_block(time=(DAY, 80000, 0)))
    out("send last vote future date", last_vote=(DAY + 16, 0, 0))
    out("send already voted", voted=1000)
    out("send voted below", voted=998)
    out("send under committed", committed=1000, voted=5)
    out("send tip higher wins", tip=good_block(round=1001, qc_round=1000, parent=0x12), parent=parent_block(key=0x12, round=1000), current=1001, voted=1000, committed=1000, blocks=(parent_block(key=0x12, round=1000), good_block(round=1001, qc_round=1000, parent=0x12), parent_block(key=0x13, round=999)))
    out("send round tie later key", blocks=(parent_block(), good_block(key=0x11, hashes=(0x21,)), good_block(key=0x14)), committed=999)
    out("send round tie later key refused", blocks=(parent_block(), good_block(key=0x14, hashes=(0x21,)), good_block(key=0x11)), txs={})
    out("send tx missing", tip=good_block(hashes=(0x21,)))
    out("send tx placeholder", tip=good_block(hashes=(0x21,)), txs={0x21: "placeholder"})
    out("send tx held by throttle", tip=good_block(hashes=(0x21,)), throttle="held")
    out("send tx present", tip=good_block(hashes=(0x21,)), txs={0x21: "ok"})
    out("send tx flagged", tip=good_block(hashes=(0x21,)), txs={0x21: "flagged"})
    out("send tx in ancestors", tip=good_block(hashes=(0x21,)), txs={0x21: "ok"}, ancestors=(0x21,))
    out("send tx second missing", tip=good_block(hashes=(0x21, 0x22)), txs={0x21: "ok"})
    out("send tx second in ancestors", tip=good_block(hashes=(0x21, 0x22)), txs={0x21: "ok", 0x22: "ok"}, ancestors=(0x22,))
    out("send empty tx map", tip=good_block(hashes=(0x21,)), txs={})
    out("send parent missing", parent=False, tip=good_block(parent=0x55))
    out("send parent missing held", parent=False, tip=good_block(parent=0x55), throttle="held")
    out("send parent same time", tip=good_block(time=(DAY, 998, 0)))
    out("send parent later time", tip=good_block(time=(DAY, 997, 0)))
    out("send parent later nanos", tip=good_block(time=(DAY, 998, 0)), parent=parent_block(time=(DAY, 998, 1)))
    out("send parent earlier nanos", tip=good_block(time=(DAY, 998, 1)), parent=parent_block(time=(DAY, 998, 0)))
    out("send parent earlier date", tip=good_block(time=(DAY, 998, 0)), parent=parent_block(time=(DAY - 16, 86000, 0)))
    out("send parent later date", tip=good_block(time=(DAY, 998, 0)), parent=parent_block(time=(DAY + 16, 0, 0)))
    middle = parent_block(key=0x10, round=999, hash=0x0F, time=(DAY, 998, 0))
    deep = parent_block(key=0x0F, round=998, hash=0x0E, time=(DAY, 997, 0))
    out("send walks two", blocks=(deep, middle, good_block()), committed=998)
    out("send walk stops at committed", blocks=(middle, good_block()), committed=999)
    out("send walk parent missing deep", blocks=(middle, good_block()), committed=997)
    out("send walk grand tx missing", blocks=(Block(0x0F, 998, Qc(round=997, hash=0x0E), time=(DAY, 997, 0)), Block(0x10, 999, Qc(round=998, hash=0x0F), hashes=(0x33,), time=(DAY, 998, 0)), good_block()), committed=997)
    out("send walk time break deep", blocks=(Block(0x0F, 998, Qc(round=997, hash=0x0E), time=(DAY, 998, 0)), Block(0x10, 999, Qc(round=998, hash=0x0F), time=(DAY, 998, 0)), good_block()), committed=997)
    out("send ancestor walk fails", ancestor_error=True)
    out("send round behind current", current=1001)
    out("send round ahead of current", current=999, voted=998)
    out("send timed out flag", timed_out=True)
    out("send age 3.5 exact", now=(DAY, 1003, 0))
    out("send age over by one micro", now=(DAY, 1003, 1000))
    out("send age over under one micro", now=(DAY, 1003, 999))
    out("send age future 3.5", now=(DAY, 996, 0), tip=good_block(), parent=parent_block(time=(DAY, 990, 0)), last_vote=(DAY, 900, 0))
    out("send age future over", now=(DAY, 995, 0), parent=parent_block(time=(DAY, 990, 0)), last_vote=(DAY, 900, 0))
    out("send qc gap no tc", tip=good_block(qc_round=998))
    out("send qc high no tc", tip=good_block(qc_round=1001))
    out("send qc max saturates", tip=good_block(round=MAX_ROUND, qc_round=MAX_ROUND), current=MAX_ROUND, voted=5, base=0, valid_until=MAX_ROUND, stakes={0: {1: 10}})
    out("send tc next round ok", tip=good_block(qc_round=990, tc=Tc(999, (tc_row(990), tc_row(989, 2)))))
    out("send tc qc behind top", tip=good_block(qc_round=989, tc=Tc(999, (tc_row(990), tc_row(989, 2)))))
    out("send tc qc ahead of top", tip=good_block(qc_round=995, tc=Tc(999, (tc_row(990), tc_row(989, 2)))))
    out("send tc top in third row", tip=good_block(qc_round=989, tc=Tc(999, (tc_row(980), tc_row(985, 2), tc_row(990, 3)))))
    out("send tc top in fifth row", tip=good_block(qc_round=989, tc=Tc(999, (tc_row(980), tc_row(985, 2), tc_row(960, 3), tc_row(950, 4), tc_row(990, 5)))))
    out("send tc top second of six", tip=good_block(qc_round=989, tc=Tc(999, (tc_row(980), tc_row(990, 2), tc_row(960, 3), tc_row(950, 4), tc_row(940, 5), tc_row(930, 6)))))
    for at in range(9):
        rows = [tc_row(900 + index, index + 1) for index in range(9)]
        rows[at] = tc_row(995, at + 1)
        out("send tc nine rows top %d behind" % at, tip=good_block(qc_round=994, tc=Tc(999, rows)))
        out("send tc nine rows top %d equal" % at, tip=good_block(qc_round=995, tc=Tc(999, rows)))
    out("send tc wrong round", tip=good_block(qc_round=990, tc=Tc(998, (tc_row(990),))))
    out("send tc with direct qc", tip=good_block(qc_round=999, tc=Tc(998, (tc_row(990),))))
    out("send tc direct qc low top", tip=good_block(qc_round=999, tc=Tc(999, (tc_row(1500),))))
    out("send tc empty direct", tip=good_block(qc_round=999, tc=Tc(999, ())))
    out("send tc max round", tip=good_block(round=MAX_ROUND, qc_round=5, tc=Tc(MAX_ROUND, (tc_row(5),))), current=MAX_ROUND, voted=5, valid_until=MAX_ROUND, stakes={0: {1: 10}})
    out("send leader missing", leader_error=True)
    out("send leader other", leader=88)
    out("send vote carries qc pair", tip=Block(0x11, 1000, Qc(version=5, start=6, round=999, hash=0x10), time=(DAY, 999, 500000000)))
    return cases


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MAX_ROUND
        yield state >> 33


def vector_cases(count):
    rows = []
    source = lcg(0x5E)

    def pick(limit):
        return next(source) % limit
    for index in range(count):
        kind = index % 3
        if kind == 0:
            steps = []
            base_round = 1000
            for _ in range(2 + pick(9)):
                round = base_round + pick(3) - (1 if pick(6) == 0 else 0)
                sig = Sig(good=False) if pick(9) == 0 else None
                shape = pick(5)
                if shape == 0:
                    steps.append(TimeoutMsg(1 + pick(6), round=1000 + pick(2), sig=sig, qc=Qc(round=990 + pick(12), hash=0x64 + pick(3), votes=(1, 2))))
                elif shape == 1:
                    steps.append(TimerFire())
                else:
                    steps.append(VoteMsg(1 + pick(6), round=round, hash=0x98 + pick(2), sig=sig, version=2 if pick(11) else 3))
            stakes = {0: {signer: 1 + pick(30) for signer in range(1, 2 + pick(5))}}
            prefill = ((1000 - 96 - pick(3), None, {0x55: (1,)}),) if pick(2) else ()
            rows.append(Case("vector vote %d" % index, steps=steps, stakes=stakes, prefill=prefill, floor=(900 + pick(120)) if pick(3) == 0 else None, voted=998 + pick(4), highest=998 + pick(6), now=NOW, last_vote=(DAY, 900, 0)))
        elif kind == 1:
            stored = {round: Qc(round=round, hash=0x98 + pick(2), votes=(1,)) for round in sorted(990 + pick(12) for _ in range(pick(4)))}
            qc = Qc(round=990 + pick(12), hash=0x98 + pick(2), version=2 + pick(2), votes=(1, 2))
            rows.append(Case("vector record %d" % index, kind="record", qc=qc, stored_qcs=stored, limit=1 + pick(4), current=990 + pick(12), highest=990 + pick(12), now=NOW, last_vote=(DAY, 900, 0)))
        else:
            qc_round = 996 + pick(5)
            tc = None
            if pick(2):
                tc = Tc(998 + pick(3), [tc_row(994 + pick(6), 1 + pick(6)) for _ in range(pick(7))])
            hashes = tuple(0x21 + pick(3) for _ in range(pick(3)))
            txs = {key: ("ok", "ok", "ok", "placeholder", "flagged")[pick(5)] for key in (0x21, 0x22, 0x23) if pick(4)}
            tip = good_block(round=1000, qc_round=qc_round, hashes=hashes, tc=tc, time=(DAY, 999, pick(1000000000)))
            parent = parent_block(time=(DAY, 998 + pick(2), 0))
            rows.append(send("vector send %d" % index, tip, parent, txs=txs, current=999 + pick(3), voted=998 + pick(3), now=(DAY, 1000 + pick(6), pick(1000000000)), last_vote=(DAY, 999 + pick(3), pick(1000000000)), ancestors=(0x22,) if pick(5) == 0 else (), timed_out=pick(8) == 0))
    return rows


def check_all(harness, cases):
    rows = []
    for case in cases:
        got = harness.run(case)
        label, model = spec_run(case)
        want = spec_view(model)
        if not same(got, want):
            raise EvidenceError("case %s (%s): %r" % (case.name, label, differ(got, want)))
        rows.append((case, label, got))
    return rows


PINS = (
    ("constant", 0x44aa7ee, "b980f0fa02", "mov ecx, 50000000: 50 ms between votes"),
    ("constant", 0x44aa5c7, "483bb788090000", "cmp rsi, [rdi+0x988]: round against table +0x58"),
    ("constant", 0x44aabd1, "4839c80f86cffb", "cmp rax, rcx: tip round against state+0x920"),
    ("constant", 0x44aabde, "483b8198010000", "cmp rax, [rcx+0x198]: tip round against committed"),
    ("constant", 0x20aa08, "0000000000000c40", "f64 3.5, the age limit"),
    ("constant", 0x20a308, "333333333333c33f", "f64 0.15, the throttle wait"),
    ("constant", 0x20ae60, "0000000080842e41", "f64 1000000, microseconds per second"),
    ("constant", 0x44afddd, "4883fb5f", "cmp rbx, 0x5f: 95 rounds kept"),
    ("constant", 0x44afde4, "4c8d43a1", "lea r8, [rbx-0x5f]: the cut"),
    ("constant", 0x48c5b8c, "4883f865", "cmp rax, 0x65: over 100 rounds"),
    ("constant", 0x44aa8c6, "4080fe", "cmp sil, 1: both block map words non zero"),
    ("constant", 0x6f605b, "48797065726c697175696420436f6e73656e737573205061796c6f6164", "Hyperliquid Consensus Payload, the digest prefix"),
    ("vote", 0x44ab1b8, "660f2e0548f8d5fb", "ucomisd xmm0, [3.5]"),
    ("vote", 0x44ab1c0, "0f87e9020000", "ja: over the limit, no vote"),
    ("vote", 0x44ab16d, "493b9d18090000", "cmp rbx, [r13+0x918]: tip round is current"),
    ("vote", 0x44ab17a, "4180bd010b000000", "cmp byte [r13+0xb01], 0"),
    ("vote", 0x44ab25f, "4c89b720090000", "mov [rdi+0x920], r14: last voted round"),
    ("vote", 0x44ab2fe, "48c78424f000000004000000", "tag 4 of the outbox row"),
    ("vote", 0x44ab1f5, "48ffc3", "inc rbx: leader of the next round"),
    ("vote", 0x44ab33f, "4c8b2c244c89", "kind 3 fetch argument follows"),
    ("vote", 0x44ab346, "41b903000000", "mov r9d, 3: tx fetch"),
    ("vote", 0x44ab371, "41b904000000", "mov r9d, 4: parent fetch"),
    ("rule", 0x44adda6, "4c39e6", "cmp rsi, r12: qc + 1 == round"),
    ("rule", 0x44addb4, "0f80bd000000", "jo: TC None niche"),
    ("rule", 0x44addc1, "0f8420010000", "je: TC with no rows, no vote"),
    ("rule", 0x44ade34, "4c39df", "cmp rdi, r11: top of the row QCs"),
    ("rule", 0x44ade37, "490f46fb", "cmovbe rdi, r11"),
    ("rule", 0x44ade63, "4d39cc", "cmp r12, r9: tc + 1 == round"),
    ("rule", 0x44ade6a, "4839f9", "cmp rcx, rdi: qc round >= top"),
    ("rule", 0x44ade79, "4939c4", "cmp r12, rax: round > last voted"),
    ("sign", 0x454b039, "48c7042401000000", "digest variant 1"),
    ("sign", 0x454aef1, "e85a110000", "digest call of the variant 3 signer, a different payload"),
    ("sign", 0x44b62ec, "e87f4e0900", "call 0x454b170: timeout signer"),
    ("verify", 0x454bb26, "48c744243001000000", "digest variant 1 on receipt"),
    ("verify", 0x454bb55, "0f85fb000000", "jne: version pair"),
    ("verify", 0x454bc8c, "7531", "jne: recovery result"),
    ("verify", 0x454bc56, "4983c7d8", "tag 0"),
    ("arm", 0x44afc5f, "483b9818090000", "cmp rbx, [rax+0x918]: vote round against current"),
    ("arm", 0x44afc66, "0f82b01b0000", "jb: stale"),
    ("arm", 0x44afd83, "483b9820090000", "cmp rbx, [rax+0x920]: vote round against last voted"),
    ("arm", 0x44afd8a, "0f828c1a0000", "jb: under last voted"),
    ("arm", 0x44afd74, "4839cb480f47cb", "cmp rbx, rcx; cmova rcx, rbx: higher round kept"),
    ("arm", 0x44b26df, "e87c8effff", "call 0x44ab560"),
    ("arm", 0x44b26eb, "ff153f0f2c01", "call proposer"),
    ("tracker", 0x435e14c, "833e01", "cmp dword [rsi], 1: floor set"),
    ("tracker", 0x435e151, "493b5708", "cmp rdx, [r15+8]: round against floor"),
    ("tracker", 0x48c529a, "807d3900", "cmp byte [rbp+0x39], 0: decided"),
    ("tracker", 0x48c5548, "c6453901", "mov byte [rbp+0x39], 1"),
    ("tracker", 0x48c554c, "c6451800", "mov byte [rbp+0x18], 0"),
    ("tracker", 0x48c4192, "ff155029eb00", "call quorum"),
    ("tracker", 0x48c4297, "0f0b", "ud2: a row in the second map"),
    ("record", 0x44ab63c, "0f8402020000", "je: same version pair and hash"),
    ("record", 0x44ab84e, "4d3bb760040000", "cmp r14, [r15+0x460]: over the highest QC"),
    ("record", 0x44ab855, "0f869c000000", "jbe: highest stays"),
    ("record", 0x44ab8f0, "e87bad0000", "call 0x44b6670"),
    ("record", 0x43566ec, "483b4338", "cmp rax, [rbx+0x38]: ring over the limit"),
    ("timer", 0x44ae35a, "488b85b0090000", "fire count"),
    ("timer", 0x44ae3a4, "4883fb02", "cmp rbx, 2"),
    ("timer", 0x44ae38b, "7517", "jne: timeout already sent"),
    ("timer", 0x44ae433, "c680d808000001", "mov byte [rax+0x8d8], 1"),
    ("timeout", 0x44b62f1, "c683010b000001", "mov byte [rbx+0xb01], 1"),
    ("timeout", 0x44b62ff, "48c78424b000000005000000", "tag 5"),
    ("timeout", 0x44b639f, "48c78424b000000006000000", "tag 6"),
    ("timeout", 0x44b2524, "b903000000", "mov ecx, 3: join test"),
    ("timeout", 0x44b2535, "4839d8", "cmp rax, rbx: 3 * signed against total"),
    ("timeout", 0x44b2538, "760a", "jbe: no join"),
    ("timeout", 0x44b254e, "ba030000004c", "2 * total against 3 * signed"),
    ("timeout", 0x44b255c, "4819d1", "sbb rcx, rdx"),
    ("timeout", 0x44b255f, "0f83b7f2ffff", "jae: no TC"),
    ("timeout", 0x44b0368, "0f85df060000", "jne: other round"),
    ("timeout", 0x44b155b, "b901000000", "mov ecx, 1: verifier reads the QC"),
)
SLOTS = ((0x5773630, 0x44B4F80, "proposer, called at 0x44b26eb, 0x44b263b and 0x44b1816"), (SLOT_SNAPSHOT, 0x4B31D40, "stake snapshot for a round, called at 0x44afd9e and 0x44b15ea"), (SLOT_LEADER, 0x4B31E70, "leader of round + 1, called at 0x44ab213"), (SLOT_QUORUM, 0x4AD90D0, "quorum, called at 0x48c4192"),
         (SLOT_RECOVER, 0x14C6F50, "signature recovery, called at 0x454bc82"), (SLOT_TIME_ADD, 0x15206E0, "time add, called at 0x44aa7f3"), (SLOT_DATE_ADD, 0x151F870, "date add, called at 0x44aa850"), (SLOT_SECONDS, 0x1450A60, "seconds between two times, called at 0x44ab1b2"), (SLOT_DURATION, 0x151D1B0, "signed difference of two times, called at 0x1450a61"), (SLOT_RECORD, 0x4758390, "event record push, called at 0x44ae099"))
GATES = (
    ("maybe_vote", 1, 0x44AA5C7, "round = state+0x918; over table +0x58 logs `Querying stakes for high round` and goes on", "no stop", ""),
    ("maybe_vote", 2, 0x44AA686, "stake set for the round; none: drop tag 0x28, return", "return", "no stake set"),
    ("maybe_vote", 3, 0x44AA757, "this node (state+0xaec, 20 bytes) in the set by tree search", "return", "not a validator"),
    ("maybe_vote", 4, 0x44AA85E, "event time (state+0xac8) at or after last vote time (state+0xab0) + 50000000 ns; date, seconds, nanos compared in order", "return", "under 50 ms"),
    ("maybe_vote", 5, 0x44AA8C6, "block map root and count both non zero", "return", "no blocks"),
    ("maybe_vote", 6, 0x44AAAC4, "tip: highest round in key order, later key wins a tie", "no stop", ""),
    ("maybe_vote", 7, 0x44AABD1, "tip round > state+0x920 (last voted round)", "return", "already voted"),
    ("maybe_vote", 8, 0x44AABDE, "tip round > state+0x198 (committed round)", "return", "under committed"),
    ("maybe_vote", 9, 0x44AAD7A, "walk: each tx hash of the block has a row with a tag other than ...01; missing goes to 0x44b8050 kind 3 with the block digest, row tag 0xa, return", "request, return", "fetch tx"),
    ("maybe_vote", 10, 0x44AAE42, "walk: parent by QC hash in the block map; missing goes to 0x44b8050 kind 4 with that hash, row tag 0xa, return", "request, return", "fetch parent"),
    ("maybe_vote", 11, 0x44AAE73, "walk: block time strictly after parent time, date, seconds, nanos", "return", "time not after parent"),
    ("maybe_vote", 12, 0x44AAEB9, "walk: go on while parent round > committed round", "next parent", ""),
    ("maybe_vote", 13, 0x44AAEF3, "0x44b9800 ancestor walk over the tip QC; error byte set stops", "return", "ancestor walk failed"),
    ("maybe_vote", 14, 0x44AAF92, "tip tx rows: present, tag not ...01, byte +0x50 clear", "return", "tx refused"),
    ("maybe_vote", 15, 0x44AAFAF, "tip tx hash not in the ancestor set", "return", "tx refused"),
    ("maybe_vote", 16, 0x44AAFBD, "seen map lookup through 0x4355db0: the answer is not read", "no stop", ""),
    ("maybe_vote", 17, 0x44AB174, "tip round equals state+0x918", "return", "not this round"),
    ("maybe_vote", 18, 0x44AB182, "byte state+0xb01 clear: no timeout sent in this round", "return", "not this round"),
    ("maybe_vote", 19, 0x44AB1C0, "age through 0x1450a60 at or under 3.5 s; the age is an absolute value in whole microseconds, so a block from the future counts too", "return", "over 3.5 s"),
    ("maybe_vote", 20, 0x44AB1E7, "0x44add70 gave a vote", "return", "rule refused"),
    ("maybe_vote", 21, 0x44AB22F, "leader of saturated round + 1 resolves; error row dropped, nothing written", "return", "no leader"),
    ("maybe_vote", 22, 0x44AB25F, "state+0x920 = round, state+0xab0 = event time, outbox row tag 4: vote at +8, leader at +0xa0", "voted", "voted"),
    ("vote_rule", 1, 0x44ADDA6, "qc round + 1 (saturated) == block round", "no stop", ""),
    ("vote_rule", 2, 0x44ADDB4, "no TC (word +0x68 is the None niche): the first compare decides", "no stop", ""),
    ("vote_rule", 3, 0x44ADDC1, "TC with no rows: no vote, even with a direct QC", "no vote", "rule refused"),
    ("vote_rule", 4, 0x44ADE37, "top = highest QC round over every TC row", "no stop", ""),
    ("vote_rule", 5, 0x44ADE63, "with a TC: direct, or tc round + 1 (saturated) == block round and qc round >= top", "no vote", "rule refused"),
    ("vote_rule", 6, 0x44ADE7C, "block round > state+0x920", "no vote", ""),
    ("vote_rule", 7, 0x44ADEDB, "digest variant 0 of the block is the vote hash; QC version pair from block +0x30, round, this node; signed by 0x454b020 with digest variant 1 over the first 0x38 bytes", "vote", "voted"),
    ("vote_arm", 1, 0x44AFC66, "vote round at or over state+0x918, else dropped with no write", "drop", "stale round"),
    ("vote_arm", 2, 0x44AFCA5, "0x454ba50 passes, else its tag is dropped with no write", "drop", ""),
    ("vote_arm", 3, 0x44AFD77, "seen map state+0xa68: signer keeps the higher of old and vote round", "no stop", ""),
    ("vote_arm", 4, 0x44AFD8A, "vote round at or over state+0x920, else dropped after that write", "drop", "under voted round"),
    ("vote_arm", 5, 0x44AFDC1, "stake snapshot for the round", "drop", ""),
    ("vote_arm", 6, 0x44AFDDD, "cut = round - 95 when round >= 95, no cut under that", "no stop", ""),
    ("vote_arm", 7, 0x44AFE1A, "tracker returned a finished voter set", "stop", "collected"),
    ("vote_arm", 8, 0x44B2677, "voter map to rows of 0x60 in signer order: QC = rows, version pair of this vote, round, hash", "no stop", ""),
    ("vote_arm", 9, 0x44B26E6, "QC record gave true: proposer runs. The vote round passed the first gate, so 0x44b6670 moves the round for every QC built here", "no proposer", "qc formed, round moved"),
    ("verify_vote", 1, 0x454BA77, "round over table +0x58: warning, go on", "no stop", ""),
    ("verify_vote", 2, 0x454BB04, "stake set for the vote round", "tag 0x28", "no stake set"),
    ("verify_vote", 3, 0x454BB55, "vote pair +0x20,+0x28 equals table +0x40,+0x48", "tag 0 with both pairs", "version pair"),
    ("verify_vote", 4, 0x454BC36, "signer in the set; signature is not read for an unknown signer", "tag 1", "unknown signer"),
    ("verify_vote", 5, 0x454BC8C, "recovery of the signature at +0x50 over digest variant 1", "tag 1", "recover failed"),
    ("verify_vote", 6, 0x454BCF7, "recovered address equals the signer", "tag 1", "other address"),
    ("tracker", 1, 0x435E155, "floor set (+0 == 1) and round < floor (+8): nothing stored, no result", "stop", "under floor"),
    ("tracker", 2, 0x48C4E4A, "signer found in the stake tree, else nothing stored", "stop", ""),
    ("tracker", 3, 0x48C4F3B, "round row and hash slot made on first sight", "no stop", ""),
    ("tracker", 4, 0x48C529E, "row already decided (+0x39): voter added to its hash slot, no quorum read", "stop", "late vote"),
    ("tracker", 5, 0x48C54E6, "quorum before the insert", "no stop", ""),
    ("tracker", 6, 0x48C5523, "voter map insert: a repeated signer replaces its signature row", "no stop", ""),
    ("tracker", 7, 0x48C552A, "before was true: no decision. This is the only path with a quorum and no QC", "stop", "collected"),
    ("tracker", 8, 0x48C5542, "quorum after the insert", "stop", "collected"),
    ("tracker", 9, 0x48C5548, "row decided, hash stored at +0x19, voter map cloned to the result", "no stop", ""),
    ("tracker", 10, 0x48C5B90, "over 100 rounds: 0x488b370 lists 100 keys and the list is freed unread; rows stay", "no stop", ""),
    ("tracker", 11, 0x435E20C, "result and round >= 95: rows under the cut removed, floor = max(cut, old floor)", "no stop", ""),
    ("qc_record", 1, 0x44AB585, "QC map state+0x4a8 searched by round", "no stop", ""),
    ("qc_record", 2, 0x44AB63C, "stored QC: version pair and hash must match; the rows are not read", "log `: Bad QCs: `, go on, first QC stays", ""),
    ("qc_record", 3, 0x44AB83F, "new round: inserted through 0x4356560; ring at state+0x488 evicts oldest while its count > limit +0x38", "no stop", ""),
    ("qc_record", 4, 0x44AB855, "round > state+0x460: QC replaces the highest QC at state+0x438", "no write", ""),
    ("qc_record", 5, 0x44AB8F0, "0x44b6670 always runs with this round; its bool is the return value", "return", ""),
    ("timer", 1, 0x44AE36F, "fire count state+0x9b0 + 1, saturating", "no stop", ""),
    ("timer", 2, 0x44AE38B, "byte state+0xb01 clear: send a timeout", "no stop", ""),
    ("timer", 3, 0x44AE3A8, "count >= 2: send again, so count >= 2 with a clear byte sends twice in one fire", "no stop", ""),
    ("timer", 4, 0x44AE3F8, "deadline = now + state+0x8c0,+0x8c8 with one nanosecond carry", "no stop", ""),
    ("timer", 5, 0x44AE429, "timer at state+0x8d0 set, byte state+0x8d8 = 1", "no stop", "timer fired"),
    ("send_timeout", 1, 0x44B62EC, "timeout = clone of the highest QC at state+0x438, state+0x918, this node; signed by 0x454b170 with digest variant 2", "no stop", ""),
    ("send_timeout", 2, 0x44B62F1, "byte state+0xb01 = 1", "no stop", ""),
    ("send_timeout", 3, 0x44B62FF, "outbox row tag 5", "no stop", ""),
    ("send_timeout", 4, 0x44B6358, "state+0x8a0 holds a TC: clone it to an outbox row tag 6 with round +0x8b8", "no row", ""),
    ("timeout_arm", 1, 0x44AFF63, "the QC in the timeout passes 0x4758d70; failure does not stop the arm here", "no stop", ""),
    ("timeout_arm", 2, 0x44AFFD8, "QC record moved the round: the timeout is dropped and the proposer is not run", "drop", "qc in timeout moved round"),
    ("timeout_arm", 3, 0x44B0368, "timeout round equals state+0x918, tag 0xf", "drop", "timeout other round"),
    ("timeout_arm", 4, 0x44B038B, "signer not yet in state+0x9b8, tag 0x10", "drop", "timeout repeated"),
    ("timeout_arm", 5, 0x44B157D, "0x454aa10 with flag 1 reads the QC again, then the signature", "drop", "timeout bad qc"),
    ("timeout_arm", 6, 0x44B15D0, "seen map state+0xa68 keeps the higher round", "no stop", ""),
    ("timeout_arm", 7, 0x44B1657, "row stored by signer", "no stop", ""),
    ("timeout_arm", 8, 0x44B2522, "byte state+0xb01 clear and 3 * signed > total (0x44b2538): this node joins with its own timeout, one more than 1/3 of stake", "no join", "timeout counted, joined"),
    ("timeout_arm", 9, 0x44B255F, "3 * signed > 2 * total on 128 bits: rows move out of state+0x9b8", "stop", "timeout counted"),
    ("timeout_arm", 10, 0x44B2629, "TC of the rows at round state+0x918 goes to 0x44b6670; proposer on true", "no proposer", "tc formed"),
)
TAGS = ((0x00, 0x454BC56, "vote version pair differs: vote pair, table pair"), (0x01, 0x454BD44, "vote signature: unknown signer, recover failed, or other address; payload text"), (0x09, 0x44AFF63, "QC in a timeout short of quorum, from the verifier; the arm logs nothing and goes on"), (0x0F, 0x44B0A57, "timeout round differs from the current round: both rounds"), (0x10, 0x44B03B2, "second timeout from a signer in this round"), (0x28, 0x454BC4A, "no stake set for the round"))
LAYOUT = (("vote", 0x0, 0x20, "block hash, the digest variant 0 of the block", 0x44ADE9E), ("vote", 0x20, 0x10, "version pair, copied from block QC +0x18", 0x44ADEBB), ("vote", 0x30, 8, "round", 0x44ADEC5), ("vote", 0x38, 0x14, "signer", 0x44ADEA3), ("vote", 0x50, 0x41, "signature, r s v", 0x454BB83),
          ("timeout", 0x0, 0x50, "QC, the highest at the sender", 0x44B62B0), ("timeout", 0x50, 8, "round", 0x44B62A8), ("timeout", 0x58, 0x14, "signer", 0x44B6140), ("timeout", 0x70, 0x41, "signature", 0x454AB49),
          ("outbox row", 0x0, 8, "tag: 4 vote, 5 timeout, 6 TC, 0xa fetch, row size 0x168", 0x44AB2FE), ("outbox row", 0x8, 0x98, "vote", 0x44AB299), ("outbox row", 0xA0, 0x14, "leader of the next round, tag 4 only", 0x44AB253),
          ("tracker", 0x0, 8, "floor set", 0x435E14C), ("tracker", 0x8, 8, "floor round", 0x435E151), ("tracker", 0x28, 0x18, "round map root, height, count; value 0x40 bytes", 0x48C4C90),
          ("tracker row", 0x0, 0x18, "hash map: hash to voter map; value 0x30 bytes", 0x48C50C6), ("tracker row", 0x18, 1, "cleared when decided", 0x48C554C), ("tracker row", 0x19, 0x20, "decided hash", 0x48C5560), ("tracker row", 0x39, 1, "decided", 0x48C5548),
          ("hash slot", 0x0, 0x18, "voter map: signer to 0x48 byte signature row", 0x48C556B), ("hash slot", 0x18, 0x18, "second map, never filled here; its iterator hits ud2 at 0x48c4297 if it has a row", 0x48C5588),
          ("qc map", 0x0, 8, "ring capacity", 0x43566B8), ("qc map", 0x8, 8, "ring buffer of rounds", 0x43566E0), ("qc map", 0x10, 8, "ring head", 0x43566D0), ("qc map", 0x18, 8, "ring count", 0x43566BB), ("qc map", 0x20, 0x18, "map root, height, count", 0x435657B), ("qc map", 0x38, 8, "limit", 0x43566EC),
          ("state", 0x198, 8, "committed round", 0x44AABDE), ("state", 0x238, 0x40, "vote tracker", 0x44AFDD4), ("state", 0x438, 0x50, "highest QC, round at +0x460", 0x44AB85B), ("state", 0x488, 0x40, "QC map", 0x44AB7FE), ("state", 0x4D0, 0x18, "outbox vector", 0x44AB27F), ("state", 0x8A0, 0x20, "last TC, None niche in word 0", 0x44B6351), ("state", 0x8C0, 0x10, "timer wait", 0x44AE3D5),
          ("state", 0x8D0, 8, "timer handle", 0x44AE3BC), ("state", 0x8D8, 1, "timer armed", 0x44AE433), ("state", 0x918, 8, "current round", 0x44AFC5F), ("state", 0x920, 8, "last voted round", 0x44AB25F), ("state", 0x9B0, 8, "timer fires", 0x44AE35A), ("state", 0x9B8, 0x18, "timeouts by signer in this round", 0x44B0376), ("state", 0x9D0, 8, "signing key", 0x44ADECA), ("state", 0xA68, 0x18, "seen map: signer to highest round", 0x44AFD48), ("state", 0xAB0, 0xC, "last vote time", 0x44AB26E), ("state", 0xAC8, 0xC, "event time", 0x44AE00C), ("state", 0xAEC, 0x14, "this node", 0x44AA6CF), ("state", 0xB01, 1, "timeout sent in this round", 0x44B62F1))
STRINGS = ((0x6F605B, "Hyperliquid Consensus Payload"), (0x202516, ": Bad QCs: "), (0x202523, " and "), (0x1E8C49, "Querying stakes for high round, is execution behind? "), (0x1FD736, "payload="), (0x1FD740, " signature="))
LOCATIONS = ((0x44AB6A7, 0x571FFE8, "Bad QCs log"), (0x454BAD5, 0x5738668, "high round log"))
TRIGGERS = ((MAYBE_VOTE, 0x44AE32A, "after a tx event: 0x44b9a50, then commit walk, then this"), (MAYBE_VOTE, 0x44AE350, "event tag 0xe, nothing else in the arm"), (MAYBE_VOTE, 0x44B180C, "after a block event, after the commit walk"), (VOTE_RULE, 0x44AB1DA, "maybe_vote"),
            (RECORD_QC, 0x44AF4F3, "QC of a block event, only if 0x4758d70 passed"), (RECORD_QC, 0x44AF5EB, "QC of a TC event"), (RECORD_QC, 0x44AFFD1, "QC of a timeout event"), (RECORD_QC, 0x44B26DF, "QC built from votes"),
            (TRACK, 0x44AFE09, "vote arm"), (VERIFY_VOTE, 0x44AFC8B, "vote arm"), (BUILD_ROWS, 0x44B2677, "vote arm"), (SEND_TIMEOUT, 0x44AE393, "timer arm, byte clear"), (SEND_TIMEOUT, 0x44AE3B2, "timer arm, count >= 2"), (SEND_TIMEOUT, 0x44B253F, "timeout arm, more than 1/3 of stake"))
SUBJECTS = (MAYBE_VOTE, VOTE_RULE, SIGN_VOTE, VERIFY_VOTE, TRACK, TRACK_CORE, SLOT_QUORUM_CHECK, RECORD_QC, QC_MAP_INSERT, BUILD_ROWS, SEND_TIMEOUT, SIGN_TIMEOUT)
ARMS = ((0x44AE35A, 0x44AE44D), (0x44AFBCE, 0x44AFE83), (0x44AFE83, 0x44AFFED), (0x44B0356, 0x44B0391), (0x44B1548, 0x44B16BB), (0x44B24BA, 0x44B2703))
ROLES = {MAYBE_VOTE: "whole vote decision", VOTE_RULE: "QC or TC vote rule, builds the vote", SIGN_VOTE: "signs digest variant 1", VERIFY_VOTE: "vote check on receipt", TRACK: "tracker front: floor, cut", TRACK_CORE: "round row, hash slot, decision", SLOT_QUORUM_CHECK: "quorum of one hash slot",
         RECORD_QC: "first QC of a round, highest QC, round advance", QC_MAP_INSERT: "QC map with ring eviction", BUILD_ROWS: "voter map to QC rows", SEND_TIMEOUT: "timeout from the highest QC, TC resend", SIGN_TIMEOUT: "signs digest variant 2"}
HELPERS = {0x4B31D40: "stake snapshot", 0x4450BB0: "signer list", QUORUM: "quorum", VOTER_INSERT: "voter map insert", PRUNE: "drop rows under the cut", KEY_LIST: "100 keys, freed unread", CLONE_BLOCK: "block clone", SET_LOOKUP: "stake set by round", SET_RANGE: "table walk", OUTBOX_PUSH: "outbox push", SEEN_FIND: "seen map find", TX_FIND: "tx row find",
           0x15206E0: "time add", 0x151F870: "date add", 0x1450A60: "seconds between times", 0x151D1B0: "time difference", VERIFY_TIMEOUT: "timeout check", 0x47BE700: "timeout rows to TC rows", 0x4847500: "QC clone", 0x484EAA0: "TC clone", 0x4B33990: "stake of the timeout signers", 0x4B33770: "total stake", 0x493D940: "timeout map insert", 0x49278B0: "timeout map find"}
STUBS = {DIGEST: "signing digest: SHA-256 of named fixture fields per variant, real digest bytes are not modelled here", SIGN_HASH: "secp256k1 sign: fixture value from the digest, argument checked", ADVANCE: "round advance, bodied by RE-008-timeout-round-transition-94: the entry compare only", ANCESTORS: "ancestor walk of 0x44b9800, out of scope, fixture answer", THROTTLE: "fetch throttle, covered by the commit walk packet; arguments checked",
         ANCESTOR_FIND: "ancestor set find, fixture answer", VERIFY_QC: "QC check, covered by the block admission packet; outcome from the fixture", REARM: "timer set, arguments recorded", NOW_INSTANT: "clock, fixed value", DROP_ERROR: "drop of an error value, its tag recorded", DROP_ROW: "drop, no effect", DROP_SET: "drop, no effect", DROP_VALUE: "drop, no effect", 0x49478B0: "set drain ends at once, node free only", 0x48FF470: "drop, no effect", 0x49B91C0: "drop, no effect", 0x4881A80: "removed rows list, freed by the caller", 0x49B05E0: "drop, no effect"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_MEMMOVE: "memmove", SLOT_ALLOC: "fixture bump allocator", SLOT_ALLOC_ERROR: "panic", SLOT_DEALLOC: "dealloc, no effect", SLOT_LOG: "warning log, text address recorded", SLOT_FORMAT: "format, empty string", SLOT_RECOVER: "recovery of the fixture signature", SLOT_BTREE_PANIC: "panic", SLOT_ASSERT: "panic", SLOT_PANIC_FMT: "panic",
              SLOT_LAZY: "lazy init, no effect", SLOT_RECORD: "event record, no effect", SLOT_LEADER: "leader rule, out of scope, fixture answer", SLOT_PROPOSER: "proposer, call recorded", SLOT_GROW_OUT: "outbox growth, fixture never needs it", SLOT_GROW_RING: "ring growth, fixture never needs it"}
MUTANT_CAP = 12
BOUNDARY = frozenset(("send last vote 50 ms", "send last vote 49 ms", "send age 3.5 exact", "send age over by one micro", "qc prunes under window", "qc at 95 prunes to zero", "qc under 95 no prune", "vote exactly two thirds stays", "vote one over two thirds forms", "timeout one third no join",
                      "timeout over one third joins", "timeout exact two thirds no tc", "timeout over two thirds tc", "timer wait carry exact", "timer wait no carry", "qc ring evicts oldest"))


def survivor_reason(va, kind):
    if 0x44AAFB5 <= va < 0x44AAFC2:
        return "row of the seen map lookup whose answer is unused"
    if 0x48C5B80 <= va < 0x48C5C34:
        return "row of the 100 key list that is freed unread"
    if 0x48C5768 <= va < 0x48C5AE6:
        return "row of the drop of a replaced result, one result per run here"
    if 0x44AB48A <= va < 0x44AB4F0 or 0x44AA5D4 <= va < 0x44AA671 or 0x44AB642 <= va < 0x44AB6C1:
        return "row of a log or panic path"
    return "not classified"


def text_rows(image, start):
    begin, end = image.exact_fde(start)
    return {row.va: row for row in decode_range(image, begin, end)}


def scan_triggers(image):
    """Every e8 rel32 in .text landing on a target in TRIGGERS, one opcode byte plus a checked displacement."""
    start, data = image.text_bytes()
    wanted = {row[0] for row in TRIGGERS}
    sites = collections.defaultdict(list)
    for match in re.finditer(rb"\xe8", data):
        at = match.start()
        if at + 5 <= len(data):
            target = start + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
            if target in wanted:
                sites[target].append(start + at)
    relative = set(image.relative().values())
    for target in wanted:
        if sorted(sites[target]) != sorted(row[1] for row in TRIGGERS if row[0] == target):
            raise EvidenceError("call sites differ for %#x: %s" % (target, [hex(item) for item in sites[target]]))
        if target in relative:
            raise EvidenceError("a relocation names %#x" % target)
    return sum(len(rows) for rows in sites.values())


def check_pins(image):
    for _, va, text, _ in PINS:
        want = bytes.fromhex(text)
        at = image.offset(va)
        if bytes(image.blob[at:at + len(want)]) != want:
            raise EvidenceError("pin differs at %#x" % va)
    return len(PINS)


def check_slots(image):
    relative = image.relative()
    rows = []
    for slot, target, use in SLOTS:
        if relative.get(slot) != target:
            raise EvidenceError("slot differs at %#x" % slot)
        rows.append((slot, target, use))
    return rows


def check_strings(image):
    for va, text in STRINGS:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(text)]) != text.encode():
            raise EvidenceError("string differs at %#x" % va)
    return STRINGS


def check_locations(image):
    relative = image.relative()
    rows = []
    for site, slot, use in LOCATIONS:
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % site, "%#x" % slot, path, line, column, use))
    return rows


def check_gate_sites(image):
    """Every site named in a table starts a row inside its FDE, decoded from bytes."""
    rows = {}
    for va in [row[2] for row in GATES] + [row[4] for row in LAYOUT] + [row[1] for row in TAGS]:
        host = image.fde(va)[0]
        if host not in rows:
            rows[host] = text_rows(image, host)
        if va not in rows[host]:
            raise EvidenceError("gate site is not a row start: %#x" % va)
    return sum(len(item) for item in rows.values())


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


def first_failure(harness, cases):
    for case in cases:
        try:
            got = harness.run(case)
            if not same(got, spec_view(spec_run(case)[1])):
                return case
        except (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, OverflowError, TypeError, UnicodeDecodeError, struct.error):
            return case
    return None


def reach_table(image, cases):
    """For each case the rows it reaches and its step count, on the unedited image; cheap cases come first."""
    harness = Harness(image)
    rows = []
    for case in cases:
        harness.machine.seen = set()
        before = harness.machine.steps
        harness.run(case)
        rows.append((harness.machine.steps - before, len(rows), case, frozenset(harness.machine.seen), spec_run(case)[0]))
    rows.sort(key=lambda row: row[:2])
    return rows


def sample(table, va):
    """Cases reaching a row, one outcome at a time, cheapest first, then the named boundary cases: a row that fails most cheap cases still sees the rest."""
    groups = {}
    for row in table:
        if va in row[3]:
            groups.setdefault(row[4], []).append(row[2])
    chosen = []
    depth = 0
    while len(chosen) < MUTANT_CAP and any(depth < len(rows) for rows in groups.values()):
        for label in sorted(groups):
            if depth < len(groups[label]) and len(chosen) < MUTANT_CAP:
                chosen.append(groups[label][depth])
        depth += 1
    return chosen + [row[2] for row in table if va in row[3] and row[2].name in BOUNDARY and row[2] not in chosen]


def run_mutants(image, cases, rows):
    """Each edit runs only on cases that reach its row, at most MUTANT_CAP of them."""
    table = reach_table(image, cases)
    results = []
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    for va, kind, patch in edits_for(image, rows):
        chosen = sample(table, va)
        harness.machine.patches = patch
        for address in {va + index for index in range(16)} | set(patch):
            harness.machine.cache.pop(address, None)
        hit = first_failure(harness, chosen)
        harness.machine.patches = {}
        for address in {va + index for index in range(16)} | set(patch):
            harness.machine.cache.pop(address, None)
        host = image.fde(va)[0]
        if hit is not None:
            results.append((host, va, kind, "killed", hit.name))
        else:
            results.append((host, va, kind, "survived", survivor_reason(va, kind)))
    return results


def subject_row(image, va):
    if any(low <= va < high for low, high in ARMS):
        return DISPATCH
    host = image.fde(va)[0]
    return host if host in SUBJECTS else None


def analyse(image, mutate=True, vectors=VECTORS):
    triggers = scan_triggers(image)
    pins = check_pins(image)
    slots = check_slots(image)
    strings = check_strings(image)
    locations = check_locations(image)
    decoded = check_gate_sites(image)
    harness = Harness(image)
    cases = named_cases() + vector_cases(vectors)
    rows = check_all(harness, cases)
    machine = harness.machine
    reached = collections.Counter()
    selected = []
    for va in sorted(machine.seen):
        row = machine.cache[va]
        host = subject_row(image, va)
        if host is not None:
            reached[host] += row.size
            selected.append(row)
        else:
            reached[image.fde(va)[0]] += row.size
    labels = collections.Counter(label for _, label, _ in rows)
    result = dict(triggers=triggers, pins=pins, slots=slots, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels, decoded=decoded)
    for row in GATES:
        if row[5] and row[5] not in labels:
            raise EvidenceError("gate outcome never reached: %s" % row[5])
    if mutate:
        result["mutations"] = run_mutants(image, cases, selected)
    return result


def case_shape(case, label, got):
    return (case.name, case.kind, label, len(case.steps), got["words"]["current"], got["words"]["voted"], len(got["tracker"]), len(got["qcs"]), len(got["outbox"]))


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    labels = result["labels"]

    def count(label):
        return labels[label] if label else "-"
    tsv("gates.tsv", ("group", "order", "site", "rule", "otherwise", "outcome_label", "cases"), [(group, order, "%#x" % va, rule, other or "-", label or "-", count(label)) for group, order, va, rule, other, label in GATES])
    tsv("error-tags.tsv", ("tag_low_byte", "site", "meaning"), [("%#x" % tag, "%#x" % va, meaning) for tag, va, meaning in TAGS])
    functions = [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], "subject", ROLES[start]) for start in SUBJECTS]
    functions += [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], "helper", HELPERS.get(start, "B-tree or list helper")) for start in REAL_FUNCTIONS if start not in SUBJECTS]
    functions.append(("%#x" % DISPATCH, "%#x" % image.exact_fde(DISPATCH)[1], image.exact_fde(DISPATCH)[1] - DISPATCH, result["reached"][DISPATCH], "arms only", "rows of the vote, timeout and timer arms"))
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "use", "role"), functions)
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("triggers.tsv", ("target", "site", "context"), [("%#x" % target, "%#x" % site, text) for target, site, text in TRIGGERS])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("slots.tsv", ("slot", "target", "use"), [("%#x" % slot, "%#x" % target, use) for slot, target, use in result["slots"]])
    tsv("strings.tsv", ("address", "text"), [("%#x" % va, text) for va, text in result["strings"]])
    tsv("locations.tsv", ("site", "data", "path", "line", "column", "use"), result["locations"])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(labels.items()))
    tsv("cases.tsv", ("case", "kind", "last_outcome", "steps", "current_after", "voted_after", "tracker_rounds", "stored_qcs", "outbox_rows"), [case_shape(case, label, got) for case, label, got in result["rows"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    subject_bytes = sum(image.exact_fde(start)[1] - start for start in SUBJECTS)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "subject_functions": len(SUBJECTS), "helpers_run": len(REAL_FUNCTIONS) - len(SUBJECTS),
               "subject_bytes": subject_bytes, "subject_reached_bytes": sum(result["reached"][start] for start in SUBJECTS), "arm_reached_bytes": result["reached"][DISPATCH], "pins": result["pins"], "call_sites": result["triggers"], "gates": len(GATES), "rows_decoded": result["decoded"]}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived"), "named_survivors": sum(1 for r in rows if r[3] == "survived" and r[4] != "not classified")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image), image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
