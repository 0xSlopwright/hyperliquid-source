#!/usr/bin/env python3
"""Pin the node #94 automatic jail vote path from ELF bytes: event 0xf gates, target rules, heartbeat status query, config file, signed voteJail rows.

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
HEAP_SIZE = 0x1000000
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
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
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
REAL_FUNCTIONS = (0x1447130, 0x1459CA0, 0x151D1B0, 0x151F870, 0x15206E0, 0x42730A0, 0x428D080, 0x4296190, 0x42BA100, 0x42C9930, 0x42C9A30, 0x44507D0, 0x4476200, 0x44ADBF0, 0x454F420, 0x454F5D0, 0x4726A50, 0x474E510, 0x47C0AE0, 0x47C1F30, 0x4876F90, 0x4895050, 0x489DEC0, 0x4913410, 0x4913840, 0x49277E0, 0x4B314F0, 0x4B31660, 0x4B33770)
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_ERROR = 0x576DFB8
SLOT_DEALLOC = 0x576E010
SLOT_REALLOC = 0x576E030
SLOT_LOG = 0x576E978
SLOT_FORMAT = 0x576E040
SLOT_BTREE_PANIC = 0x576E470
SLOT_ASSERT = 0x576E108
SLOT_PANIC_FMT = 0x576E468
SLOT_PANIC_ADD = 0x576E118
SLOT_UNWRAP = 0x576E048
SLOT_MONOTONIC = 0x576F488
SLOT_RECORD = 0x5773648
SLOT_GROW_OUT = 0x57769D0
SLOT_WALL = 0x576E8A0
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_ELAPSED = 0x576E8C0
SLOT_DURATION = 0x576EAA0
SLOT_BACK = 0x576EFB8
SLOT_MILLIS = 0x576E9F8
SLOT_EXISTS = 0x576E9E8
SLOT_MTIME = 0x576E9F0
SLOT_SIGN_ACTION = 0x5773C88
SLOT_BUNDLE = 0x5775A48
SLOT_ACTION_WEIGHT = 0x57739C0
ONCE_WORD = 0x577AB98
NOW_INSTANT = 0x4EE3800
DISPATCH = 0x44ADFA0
JAIL_ARM = 0x44AE705
COLLECT = 0x47C1F30
RULE = 0x4476200
BUILD = 0x47C0AE0
QUERY = 0x474E510
QUERY_MAP = 0x489DEC0
QUERY_LIST = 0x4876F90
STATUS = 0x4726A50
SET_ITER = 0x4895050
STAKE_KEYS = 0x4B314F0
JAILED_AT = 0x4B31660
JAILED_FIND = 0x42C9A30
JAILED_MEMBER = 0x49277E0
SET_LOOKUP = 0x42C9930
TOTAL_STAKE = 0x4B33770
SEND_ACTIONS = 0x44ADBF0
PRUNE = 0x474F8A0
HOURLY = 0x474E8C0
LOAD_CONFIG = 0x4721BB0
DROP_ERROR = 0x447E690
DROP_VALUE = 0x4B1A270
DROP_ROWS = 0x4852950
DROP_SEND_ERROR = 0x447CB60
STOP_EXEC = 0x44B1F7A
EVENT_SIZE = 0x180
NONE_TAG = 1 << 63
OK_TAG = NONE_TAG + 0x2A
NO_SET_TAG = NONE_TAG + 0x28
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0xB10
TABLE = STATE + 0x930
TRACKER = STATE + 0x6F8
EVENT = HEAP_BASE + 0x2000
TIME_IN = HEAP_BASE + 0x2200
ERROR_OBJECT = HEAP_BASE + 0x22C0
ERROR_VTABLE = HEAP_BASE + 0x22E0
PATH = HEAP_BASE + 0x2340
OUTBOX = HEAP_BASE + 0x3000
NODES = HEAP_BASE + 0x10000
STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))
SELF = 1
MAX_ROUND = 0xFFFFFFFFFFFFFFFF
DAY = 2026 << 13 | 100 << 4 | 10
LOW_ROUNDS = 200
RECENT_SPAN = 2000
JAIL_FOR = 1800
LONG_ENOUGH = 900
LAG_FLOOR = 3000
WEIGHT_LIMIT = 9001
QUIET_SECONDS = 180.0
SIGN_MILLIS = 0x1234567
PATH_TEXT = b"file"
KEY_BYTE = 0x33
LOG_TEXT = {0x1E8C48: "high round", 0x1F4484: "high jail round", 0x1DF907: "config error", 0x1F3BF3: "stale config"}


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 8 * 12


STAKE_LAYOUT = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)
TABLE_LAYOUT = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
SET_LAYOUT = Layout(8, 20, 0xE4, 0, 0, 0xE4, 0xE6, 0xE8)
TIME_LAYOUT = Layout(8, 20, 0xE4, 12, 0, 0x168, 0x16A, 0x170)
STATS_LAYOUT = Layout(0x480, 20, 8, 0x68, 0, 0x55C, 0x55E, 0x560)


def addr_bytes(value):
    return value.to_bytes(20, "big")


class Snapshot:
    """The stored execution event at state+0x2e8: tag 1 reads times, tag 0 does not, members are always read."""

    def __init__(self, tag=1, times=None, members=()):
        self.tag, self.times, self.members = tag, dict(times or {}), frozenset(members)


class Sample:
    """A tracker row: ratio numerator and denominator, time of the last sample."""

    def __init__(self, num=0.0, den=1.0, time=None):
        self.num, self.den, self.time = num, den, time


class File:
    """The watched config file: exists, modified time, parser answer (value, flag) or None for a refused file."""

    def __init__(self, exists=True, modified=(1, 0, 0), parsed=(5.0, 0), broken=False):
        self.exists, self.modified, self.parsed, self.broken = exists, modified, parsed, broken


class Case:
    def __init__(self, name, **extra):
        self.name = name
        self.current = 5000
        self.base = 0
        self.valid_until = 100000
        self.jail_valid_until = 100000
        self.stakes = {0: {1: 10, 2: 10, 3: 10, 4: 10}}
        self.jailed = {0: frozenset()}
        self.flag = False
        self.seen = {1: 4999, 2: 4999, 3: 4999, 4: 4999}
        self.weight = {}
        self.snapshot = None
        self.stats = None
        self.limit = 1.0
        self.mute = 0
        self.interval = 60.0
        self.last_check = None
        self.modified = (0, 0, 0)
        self.file = None
        self.held_error = False
        self.now = (DAY, 40000, 500000000)
        self.wall = (DAY, 40000, 0)
        self.send_error = False
        self.steps = 1
        for name, value in extra.items():
            if not hasattr(self, name):
                raise ValueError(name)
            setattr(self, name, value)
        if self.stats is None:
            self.stats = {key: Sample(0.0, 1.0, self.wall) for keys in self.stakes.values() for key in keys}


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_ERROR: self.on_panic, SLOT_DEALLOC: self.on_nothing, SLOT_REALLOC: self.on_realloc, SLOT_LOG: self.on_log, SLOT_FORMAT: self.on_format,
                 SLOT_BTREE_PANIC: self.on_panic, SLOT_ASSERT: self.on_panic, SLOT_PANIC_FMT: self.on_panic, SLOT_PANIC_ADD: self.on_panic, SLOT_UNWRAP: self.on_panic, SLOT_MONOTONIC: self.on_clock, SLOT_RECORD: self.on_nothing, SLOT_GROW_OUT: self.on_panic,
                 SLOT_WALL: self.on_wall, SLOT_MILLIS: self.on_millis, SLOT_EXISTS: self.on_exists, SLOT_MTIME: self.on_mtime, SLOT_SIGN_ACTION: self.on_sign_action, SLOT_BUNDLE: self.on_bundle}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        self.error_mark = MARK_BASE + 0x1000
        machine.slots[self.error_mark] = self.on_error_drop
        relative = image.relative()
        for slot in (SLOT_TIME_ADD, SLOT_DATE_ADD, SLOT_ELAPSED, SLOT_DURATION, SLOT_BACK):
            memory.statics[slot] = relative[slot]
        memory.statics[ONCE_WORD] = 0
        machine.real = frozenset(REAL_FUNCTIONS)
        machine.calls = {NOW_INSTANT: self.on_instant, DROP_ERROR: self.on_drop_error, DROP_VALUE: self.on_nothing, DROP_ROWS: self.on_nothing, DROP_SEND_ERROR: self.on_send_error, PRUNE: self.on_prune, HOURLY: self.on_hourly, LOAD_CONFIG: self.on_load,
                         0x49A7D50: self.on_nothing, 0x49B05E0: self.on_nothing, 0x49A9C60: self.on_nothing}
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

    def on_realloc(self, machine):
        regs = machine.regs
        fresh = self.alloc(regs[RSI])
        machine.memory.copy(fresh, regs[RDI], regs[RSI])
        regs[RAX] = fresh

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
        self.expect(text in LOG_TEXT, "log text %#x" % text)
        self.trace.append(("log", LOG_TEXT[text]))

    def on_clock(self, machine):
        self.trace.append(("clock",))

    def on_instant(self, machine):
        machine.regs[RAX] = 100
        machine.regs[RDX] = 900000000
        machine.keep_rdx = True

    def on_wall(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<iII", *self.case.wall))

    def on_millis(self, machine):
        machine.regs[RAX] = SIGN_MILLIS

    def on_exists(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == PATH and regs[RSI] == len(PATH_TEXT), "watched path")
        self.trace.append(("exists",))
        regs[RAX] = 1 if self.case.file is not None and self.case.file.exists else 0

    def on_mtime(self, machine):
        regs, memory = machine.regs, machine.memory
        self.trace.append(("mtime",))
        file = self.case.file
        if file.broken:
            memory.write(regs[RDI], 4, 1)
            memory.write(regs[RDI] + 8, 8, ERROR_OBJECT)
            return
        memory.put_bytes(regs[RDI], struct.pack("<iiII", 0, *file.modified))

    def on_load(self, machine):
        regs, memory = machine.regs, machine.memory
        self.trace.append(("load",))
        parsed = self.case.file.parsed
        if parsed is None:
            memory.write(regs[RDI], 8, ERROR_OBJECT)
            memory.write(regs[RDI] + 8, 1, 2)
            return
        memory.write(regs[RDI], 8, to_bits(parsed[0]))
        memory.write(regs[RDI] + 8, 1, parsed[1])

    def on_error_drop(self, machine):
        self.trace.append(("drop held error",))

    def on_prune(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == TRACKER, "prune tracker")
        self.trace.append(("prune", self.read_set(regs[RSI])))

    def on_hourly(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == TRACKER, "hourly tracker")
        self.trace.append(("hourly", self.read_set(regs[RSI])))

    def on_sign_action(self, machine):
        regs, memory = machine.regs, machine.memory
        source = regs[RSI]
        row = regs[RBP]
        reason = memory.read(row + 0x18, 8)
        self.expect(memory.read(source + 0x100, 8) == STATE + 0x9D0, "signing key")
        self.trace.append(("vote", reason, memory.read(row + 0x20, 8) if reason else None, memory.read(source, 8), memory.read(source + 8, 8), memory.read(source + 0x10, 8), memory.read(source + 0x18, 1), int.from_bytes(memory.bytes_at(source + 0x19, 20), "big"), struct.unpack("<iII", memory.bytes_at(source + 0x30, 12)),
                           memory.read(source + 0x108, 1), memory.read(source + 0x11D, 1), memory.read(source + 0x11E, 1)))
        memory.put_bytes(regs[RDI], memory.bytes_at(source, 0x168))

    def on_bundle(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RCX] == SIGN_MILLIS and regs[R8] == STATE + 0x9D0, "bundle arguments")
        targets = [int.from_bytes(memory.bytes_at(regs[RSI] + 0x168 * index + 0x19, 20), "big") for index in range(regs[RDX])]
        self.trace.append(("bundle", tuple(targets)))
        out = regs[RDI]
        if self.case.send_error:
            memory.write(out, 2, 0x99)
            return
        memory.write(out, 2, 0x186)
        memory.put_bytes(out + 8, struct.pack("<QQQ", 0x11, 0x22, 0x33))

    def on_send_error(self, machine):
        self.trace.append(("send error",))

    def on_drop_error(self, machine):
        regs, memory = machine.regs, machine.memory
        self.trace.append(("error", memory.read(regs[RDI], 8) - NONE_TAG))

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
                if layout.val_size:
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

    def amount_words(self, amounts):
        items = [(addr_bytes(key), value.to_bytes(8, "little")) for key, value in sorted(amounts.items())]
        root, height = self.build(STAKE_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def set_words(self, members):
        items = [(addr_bytes(key), b"") for key in sorted(members)]
        root, height = self.build(SET_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def time_words(self, times):
        items = [(addr_bytes(key), struct.pack("<iII", *value)) for key, value in sorted(times.items())]
        root, height = self.build(TIME_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def stats_words(self, stats):
        rows = []
        for key, sample in sorted(stats.items()):
            value = bytearray(b"\x5c" * 0x68)
            struct.pack_into("<dd", value, 0x10, sample.num, sample.den)
            value[0x58:0x64] = struct.pack("<iII", *sample.time)
            rows.append((addr_bytes(key), bytes(value)))
        root, height = self.build(STATS_LAYOUT, rows)
        return struct.pack("<QQQ", root, height, len(rows))

    def set_state(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.high - HEAP_BASE)
        self.bump = NODES
        self.trace = []
        self.case = case
        memory.put_bytes(STATE, STATE_FILL)

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0, 0)
        word(0x918, case.current)
        memory.put_bytes(STATE + 0xAEC, addr_bytes(SELF))
        memory.write(STATE + 0xB04, 1, KEY_BYTE)
        memory.put_bytes(STATE + 0xAC8, struct.pack("<iII", *case.now))
        memory.put_bytes(STATE + 0x4D0, struct.pack("<QQQ", 32, OUTBOX, 0))
        memory.put_bytes(STATE + 0x1E8, self.amount_words(case.weight))
        snapshot = case.snapshot
        if snapshot is None:
            word(0x2E8, 2)
        else:
            memory.write(STATE + 0x2E8, 8, snapshot.tag)
            memory.put_bytes(STATE + 0x2E8 + 8, self.time_words(snapshot.times))
            memory.put_bytes(STATE + 0x2E8 + 0x100, self.set_words(snapshot.members))
        table = []
        for start in sorted(case.stakes):
            table.append((start.to_bytes(8, "little"), self.amount_words(case.stakes[start])))
        root, height = self.build(TABLE_LAYOUT, table)
        memory.put_bytes(TABLE, b"\xab" * 0x60)
        memory.put_bytes(TABLE, struct.pack("<QQQ", case.base, root, height))
        table = []
        for start in sorted(case.jailed):
            table.append((start.to_bytes(8, "little"), self.set_words(case.jailed[start])))
        root, height = self.build(TABLE_LAYOUT, table)
        memory.put_bytes(TABLE + 0x20, struct.pack("<QQQ", case.base, root, height))
        memory.write(TABLE + 0x58, 8, case.valid_until)
        memory.write(TABLE + 0x60, 8, case.jail_valid_until)
        memory.put_bytes(STATE + 0xA68, self.amount_words(case.seen))
        memory.put_bytes(TRACKER + 0x120, self.stats_words(case.stats))
        memory.put_bytes(PATH, PATH_TEXT)
        memory.write(TRACKER + 0xB8, 8, PATH)
        memory.write(TRACKER + 0xC0, 8, len(PATH_TEXT))
        memory.write(TRACKER + 0xC8, 8, to_bits(case.limit))
        memory.write(TRACKER + 0xD0, 1, case.mute)
        memory.write(TRACKER + 0xD8, 8, to_bits(case.interval))
        memory.put_bytes(TRACKER + 0xE0, struct.pack("<iII", *(case.last_check or (0, 0, 0))))
        memory.write(TRACKER + 0xF0, 8, ERROR_OBJECT if case.held_error else 0)
        memory.put_bytes(TRACKER + 0xF8, struct.pack("<iII", *case.modified))
        memory.write(ERROR_OBJECT, 8, ERROR_VTABLE)
        memory.write(ERROR_VTABLE, 8, self.error_mark)

    def run_event(self, case):
        machine = self.machine
        memory = machine.memory
        memory.put_bytes(EVENT, b"\xc3" * EVENT_SIZE)
        memory.write(EVENT, 8, 0xF)
        memory.write(EVENT + 8, 1, 1 if case.flag else 0)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(TIME_IN, struct.pack("<iII", *case.now))
        machine.regs = [POISON] * 16
        machine.regs[RSP] = STACK_TOP - 0x100
        machine.regs[RDI] = HEAP_BASE + 0x2900
        machine.regs[RSI] = STATE
        machine.regs[RDX] = TIME_IN
        machine.regs[RCX] = EVENT
        machine.push(RETURN_SENTINEL)
        machine.stops = frozenset((STOP_EXEC,))
        machine.left = machine.step_limit
        machine.stopped = None
        machine.loop(DISPATCH)
        machine.stops = frozenset()
        if machine.stopped != STOP_EXEC:
            raise Halt("event left the arm")
        self.trace.append(("answer", memory.read(machine.regs[RSP] + 0x38, 1), memory.read(machine.regs[RSP] + 0x10, 1)))

    def run(self, case):
        self.set_state(case)
        panicked = None
        try:
            for _ in range(case.steps):
                self.run_event(case)
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

    def map_at(self, at, layout):
        memory = self.machine.memory
        return self.rows_of(memory.read(at, 8), memory.read(at + 8, 8), layout)

    def read_set(self, at):
        return tuple(int.from_bytes(key, "big") for key, _ in self.map_at(at, SET_LAYOUT))

    def outbox(self):
        memory = self.machine.memory
        rows = []
        for index in range(memory.read(STATE + 0x4E0, 8)):
            at = OUTBOX + 0x168 * index
            arc = memory.read(at + 8, 8)
            rows.append((memory.read(at, 8), memory.read(arc, 8), memory.read(arc + 8, 8), memory.read(arc + 0x10, 8), memory.read(arc + 0x18, 8), memory.read(arc + 0x20, 8)))
        return rows

    def observe(self, panicked):
        memory = self.machine.memory
        weight = {int.from_bytes(key, "big"): memory.read(at, 8) for key, at in self.map_at(STATE + 0x1E8, STAKE_LAYOUT)}
        return dict(panic=panicked, trace=list(self.trace), weight=weight, weight_len=memory.read(STATE + 0x1F8, 8), limit=memory.read(TRACKER + 0xC8, 8), mute=memory.read(TRACKER + 0xD0, 1), last_check=struct.unpack("<iII", memory.bytes_at(TRACKER + 0xE0, 12)),
                    modified=struct.unpack("<iII", memory.bytes_at(TRACKER + 0xF8, 12)), held_error=memory.read(TRACKER + 0xF0, 8) != 0, outbox=self.outbox())


class SpecPanic(Exception):
    pass


def spec_table(table, case, round):
    """A round table row: the last key at or under the bound."""
    if not table:
        return None
    limit = min(case.base + RECENT_SPAN, MAX_ROUND)
    bound = case.base if round < limit else max(case.base, (round - LOW_ROUNDS) & MASK[8])
    keys = [key for key in table if key <= bound]
    return table[max(keys)] if keys else None


def seconds(time):
    return time[0] * 86400 + time[1] + time[2] / 1e9


def forward(time, amount):
    """Shift a time forward; a whole day step moves the ordinal field of the fixture date by one."""
    day, secs, nanos = time
    secs += amount
    while secs >= 86400:
        secs -= 86400
        day += 16
    return (day, secs, nanos)


def elapsed(later, earlier):
    micro = (later[1] - earlier[1]) * 1000000 + (later[2] - earlier[2]) // 1000
    return micro / 1000000.0


class Model:
    def __init__(self, case):
        self.case = case
        self.trace = []
        self.label = None
        self.weight = dict(case.weight)
        self.limit, self.mute, self.last_check, self.modified, self.held = case.limit, case.mute, case.last_check or (0, 0, 0), case.modified, case.held_error
        self.outbox = []
        self.panicked = None

    def high_round(self):
        if self.case.current > self.case.valid_until:
            self.trace.append(("log", "high round"))

    def config(self):
        """0x474e510, the head of it: a watched file gives the ratio limit and the mute flag."""
        case = self.case
        if self.last_check != (0, 0, 0) and not elapsed(case.wall, self.last_check) > case.interval:
            return
        self.last_check = case.wall
        self.trace.append(("exists",))
        file = case.file
        if file is None or not file.exists:
            return
        self.trace.append(("mtime",))
        if file.broken:
            raise SpecPanic()
        if not file.modified > self.modified:
            return
        self.trace.append(("load",))
        if file.parsed is None:
            self.trace.append(("log", "config error"))
            if self.held:
                self.trace.append(("drop held error",))
            self.held = True
            return
        self.limit, self.mute = file.parsed
        self.modified = file.modified
        if self.held:
            self.trace.append(("drop held error",))
        self.held = False

    def status(self, key):
        """Tag and value of 0x4726a50 for one validator, 3 is no row."""
        case = self.case
        sample = case.stats.get(key)
        if sample is None:
            return 0, None
        ratio = 0.0
        if sample.den != 0.0:
            if not sample.den > 0.0:
                raise SpecPanic()
            ratio = sample.num / sample.den
        if self.held:
            self.trace.append(("log", "stale config"))
        if ratio > self.limit:
            if self.held:
                self.trace.append(("log", "stale config"))
            if self.mute == 0:
                return 2, ratio
        passed = elapsed(case.wall, sample.time)
        if passed > QUIET_SECONDS:
            return 1, passed
        return 3, None

    def reason(self, key, lag, held, kept, cutoff):
        """0x4476200: the first rule that speaks for one validator, None when it is left alone."""
        case = self.case
        snapshot = case.snapshot
        if snapshot is not None:
            if key in snapshot.members:
                return None
            if snapshot.tag & 1 and key in snapshot.times and snapshot.times[key] > cutoff:
                return None
        seen = case.seen.get(key)
        if seen is not None and min(seen + lag, MAX_ROUND) < case.current:
            return 3, seen
        if held is not None and held.get(key, -1) >= WEIGHT_LIMIT:
            return 5, held[key]
        return kept.get(key)

    def event(self):
        case = self.case
        self.high_round()
        stakes = spec_table(case.stakes, case, case.current)
        if stakes is None:
            self.trace.append(("error", 0x28))
            self.label = "no stake row"
            return
        if SELF not in stakes:
            self.label = "not a member"
            return
        held = None
        if case.flag:
            held, self.weight = self.weight, {}
            self.trace.append(("clock",))
        self.high_round()
        total = sum(stakes.values())
        if total >= 1 << 64:
            raise SpecPanic()
        doubled = MAX_ROUND if total >= 1 << 63 else 2 * total
        lag = max(LAG_FLOOR, doubled)
        self.high_round()
        keys = tuple(sorted(stakes))
        self.trace.append(("prune", keys))
        self.trace.append(("hourly", keys))
        self.config()
        kept = {}
        for key in keys:
            tag, value = self.status(key)
            if tag != 3:
                kept[key] = (tag, None if value is None else to_bits(value))
        when = forward(case.now, JAIL_FOR)
        cutoff = forward(case.now, JAIL_FOR - LONG_ENOUGH)
        rows = []
        for key in keys:
            reason = self.reason(key, lag, held, kept, cutoff)
            if reason is not None:
                rows.append((key, reason))
        self.reasons = tuple(rows)
        if not rows:
            self.label = "no target"
            return
        if case.current > case.jail_valid_until:
            self.trace.append(("log", "high jail round"))
        jailed = spec_table(case.jailed, case, case.current)
        if jailed is None:
            self.trace.append(("error", 0x28))
            self.label = "no jail row"
            return
        if SELF in jailed:
            self.label = "this node jailed"
            return
        for key, reason in rows:
            self.trace.append(("vote", reason[0], reason[1], 1, SIGN_MILLIS, 0xB0, 2, key, when, 0, 0, KEY_BYTE))
        self.trace.append(("bundle", tuple(key for key, _ in rows)))
        if case.send_error:
            self.trace.append(("send error",))
            self.label = "send refused"
            return
        self.outbox.append((9, 1, 1, 0x11, 0x22, 0x33))
        self.label = "votes sent"


def spec_run(case):
    model = Model(case)
    model.reasons = ()
    try:
        for _ in range(case.steps):
            model.event()
            model.trace.append(("answer", 0xD, 1))
    except SpecPanic:
        model.panicked = "panic"
        model.label = "panic"
    return model.label, model


def spec_view(model):
    return dict(panic=model.panicked, trace=model.trace, weight=model.weight, weight_len=len(model.weight), limit=to_bits(model.limit), mute=model.mute, last_check=model.last_check, modified=model.modified, held_error=model.held, outbox=model.outbox)


def same(got, want):
    return got == want


def differ(got, want):
    return {key: (got.get(key), want.get(key)) for key in sorted(want) if got.get(key) != want.get(key)}


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


FOUR = {1: 10, 2: 10, 3: 10, 4: 10}
CALM = {1: 4999, 2: 4999, 3: 4999, 4: 4999}
NOW = (DAY, 40000, 500000000)
WALL = (DAY, 40000, 0)
CUT = (DAY, 40900, 500000000)


def fine(*keys):
    return {key: Sample(0.0, 1.0, WALL) for key in keys}


def named_cases():
    cases = [
        Case("calm, nobody picked"),
        Case("no stake row", stakes={7000: dict(FOUR)}),
        Case("no stake row, flag keeps the map", stakes={7000: dict(FOUR)}, flag=True, weight={2: 9001}),
        Case("not a member", stakes={0: {2: 10, 3: 10, 4: 10}}),
        Case("not a member, flag keeps the map", stakes={0: {2: 10, 3: 10, 4: 10}}, flag=True, weight={2: 9001}),
        Case("high round logged three times", valid_until=4999),
        Case("round at the log limit", valid_until=5000),
        Case("lag rule at the floor", seen={1: 4999, 2: 1999, 3: 4999, 4: 4999}),
        Case("lag rule one short", seen={1: 4999, 2: 2000, 3: 4999, 4: 4999}),
        Case("lag rule one over", seen={1: 4999, 2: 1998, 3: 4999, 4: 4999}),
        Case("no seen row is not a lag", seen={1: 4999, 3: 4999, 4: 4999}),
        Case("seen zero", seen={1: 4999, 2: 0, 3: 4999, 4: 4999}),
        Case("seen near the top saturates", seen={1: 4999, 2: MAX_ROUND - 5, 3: 4999, 4: 4999}),
        Case("lag floor beats doubled stake", stakes={0: {1: 700, 2: 400, 3: 300, 4: 100}}, seen={1: 4999, 2: 1999, 3: 4999, 4: 4999}),
        Case("doubled stake just at the floor", stakes={0: {1: 750, 2: 250, 3: 250, 4: 250}}, seen={1: 4999, 2: 1999, 3: 4999, 4: 4999}),
        Case("doubled stake over the floor", stakes={0: {1: 1000, 2: 500, 3: 500, 4: 501}}, seen={1: 4999, 2: 1999, 3: 4999, 4: 4999}),
        Case("doubled stake opens the window", stakes={0: {1: 1000, 2: 500, 3: 500, 4: 501}}, seen={1: 4999, 2: 0, 3: 4999, 4: 4999}, current=5003),
        Case("stake sum top bit gives no lag rule", stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1, 4: 1}}, seen={1: 4999, 2: 0, 3: 4999, 4: 4999}),
        Case("stake sum overflows", stakes={0: {1: 1 << 63, 2: 1 << 63}}, seen={1: 4999, 2: 4999}),
        Case("weight at the limit, flag", flag=True, weight={2: 9001}),
        Case("weight one under, flag", flag=True, weight={2: 9000}),
        Case("weight over, no flag", flag=False, weight={2: 20000}),
        Case("weight cleared with flag and nobody picked", flag=True, weight={2: 5}),
        Case("flag with empty map", flag=True),
        Case("two events, flag empties the first", flag=True, weight={2: 9001}, steps=2),
        Case("no tracker row is a target", stats=fine(1, 3, 4)),
        Case("empty tracker votes for the set", stats={}),
        Case("quiet exactly at the limit", stats={**fine(1, 3, 4), 2: Sample(0.0, 1.0, (DAY, 39820, 0))}),
        Case("quiet just under", stats={**fine(1, 3, 4), 2: Sample(0.0, 1.0, (DAY, 39820, 1000))}),
        Case("quiet over", stats={**fine(1, 3, 4), 2: Sample(0.0, 1.0, (DAY, 39819, 0))}),
        Case("ratio over limit", stats={**fine(1, 3, 4), 2: Sample(3.0, 2.0, WALL)}),
        Case("ratio at limit", stats={**fine(1, 3, 4), 2: Sample(2.0, 2.0, WALL)}),
        Case("ratio over limit, muted", mute=1, stats={**fine(1, 3, 4), 2: Sample(3.0, 2.0, WALL)}),
        Case("ratio over limit, muted, quiet", mute=1, stats={**fine(1, 3, 4), 2: Sample(3.0, 2.0, (DAY, 30000, 0))}),
        Case("zero denominator", stats={**fine(1, 3, 4), 2: Sample(9.0, 0.0, WALL)}),
        Case("negative denominator panics", stats={**fine(1, 3, 4), 2: Sample(9.0, -1.0, WALL)}),
        Case("self is picked too", stats={**fine(2, 3, 4), 1: Sample(3.0, 2.0, WALL)}),
        Case("snapshot member left alone", snapshot=Snapshot(1, {}, (2,)), stats=fine(1, 3, 4)),
        Case("snapshot member beats the lag", snapshot=Snapshot(0, {}, (2,)), seen={1: 4999, 2: 0, 3: 4999, 4: 4999}),
        Case("recent time left alone", snapshot=Snapshot(1, {2: (DAY, 40900, 500000001)}), stats=fine(1, 3, 4)),
        Case("recent time exact cut is picked", snapshot=Snapshot(1, {2: CUT}), stats=fine(1, 3, 4)),
        Case("recent time older is picked", snapshot=Snapshot(1, {2: (DAY, 40899, 0)}), stats=fine(1, 3, 4)),
        Case("recent time by seconds", snapshot=Snapshot(1, {2: (DAY, 40901, 0)}), stats=fine(1, 3, 4)),
        Case("recent time by date", snapshot=Snapshot(1, {2: (DAY + 16, 0, 0)}), stats=fine(1, 3, 4)),
        Case("older date is picked", snapshot=Snapshot(1, {2: (DAY - 16, 86399, 0)}), stats=fine(1, 3, 4)),
        Case("time tag zero is not read", snapshot=Snapshot(0, {2: (DAY + 16, 0, 0)}), stats=fine(1, 3, 4)),
        Case("snapshot other key", snapshot=Snapshot(1, {3: (DAY + 16, 0, 0)}, (4,)), stats=fine(1, 3, 4)),
        Case("cut crosses midnight", now=(DAY, 86000, 0), wall=(DAY, 86000, 0), snapshot=Snapshot(1, {2: (DAY + 16, 501, 0), 3: (DAY + 16, 500, 0)}), stats={1: Sample(0.0, 1.0, (DAY, 86000, 0))}),
        Case("no jail row", jailed={7000: frozenset()}, stats=fine(1, 3, 4)),
        Case("no jail row, nobody picked", jailed={7000: frozenset()}),
        Case("high jail round log", jail_valid_until=4000, stats=fine(1, 3, 4)),
        Case("jail round at limit", jail_valid_until=5000, stats=fine(1, 3, 4)),
        Case("this node jailed", jailed={0: frozenset((1,))}, stats=fine(1, 3, 4)),
        Case("other node jailed still votes", jailed={0: frozenset((3,))}, stats=fine(1, 3, 4)),
        Case("all four rules at once", flag=True, weight={3: 9500}, seen={1: 4999, 2: 10, 3: 4999, 4: 4999}, stats=fine(1), snapshot=Snapshot(1, {}, ())),
        Case("lag wins over weight", flag=True, weight={2: 9500}, seen={1: 4999, 2: 10, 3: 4999, 4: 4999}),
        Case("send refused", stats=fine(1, 3, 4), send_error=True),
        Case("config first look, no file"),
        Case("config checked inside the interval", last_check=(DAY, 39990, 0), file=File()),
        Case("config at the interval edge", last_check=(DAY, 39940, 0), file=File()),
        Case("config past the interval", last_check=(DAY, 39939, 0), file=File()),
        Case("config missing file", last_check=(DAY, 39000, 0), file=File(exists=False)),
        Case("config same time", modified=(1, 0, 0), file=File()),
        Case("config older date", modified=(2, 0, 0), file=File(modified=(1, 9, 9))),
        Case("config newer date", modified=(1, 9, 9), file=File(modified=(2, 0, 0))),
        Case("config newer seconds", modified=(1, 1, 9), file=File(modified=(1, 2, 0))),
        Case("config older seconds", modified=(1, 2, 0), file=File(modified=(1, 1, 9))),
        Case("config newer frac", modified=(1, 1, 1), file=File(modified=(1, 1, 2))),
        Case("config negative date older", modified=(1, 0, 0), file=File(modified=(-1, 0, 0))),
        Case("config clears a held error", held_error=True, file=File()),
        Case("config parse refused", file=File(parsed=None)),
        Case("config parse refused replaces held", held_error=True, file=File(parsed=None)),
        Case("config stale error logged", held_error=True, last_check=(DAY, 39990, 0)),
        Case("config stale error, ratio over", held_error=True, last_check=(DAY, 39990, 0), stats={**fine(1, 3, 4), 2: Sample(3.0, 2.0, WALL)}),
        Case("config new limit picks", file=File(parsed=(0.25, 0)), stats={**fine(1, 3, 4), 2: Sample(1.0, 2.0, WALL)}),
        Case("config new limit spares", limit=0.25, file=File(parsed=(0.75, 0)), stats={**fine(1, 3, 4), 2: Sample(1.0, 2.0, WALL)}),
        Case("config new mute spares", file=File(parsed=(0.25, 1)), stats={**fine(1, 3, 4), 2: Sample(1.0, 2.0, WALL)}),
        Case("config metadata error panics", file=File(broken=True)),
        Case("twelve validators", stakes={0: dict.fromkeys(range(1, 13), 10)}, seen={key: 4999 for key in range(1, 13)}, stats=fine(1, 2, 3, 5, 7, 11)),
        Case("twenty validators", stakes={0: dict.fromkeys(range(1, 21), 10)}, seen={key: 4999 for key in range(1, 21)}, stats=fine(1, 2, 3, 5, 7, 11)),
        Case("large maps", stakes={0: dict.fromkeys(range(1, 17), 10)}, flag=True, seen={key: 4999 for key in range(1, 17)}, stats={key: Sample(0.0, 1.0, WALL) for key in range(1, 15)},
             snapshot=Snapshot(1, {key: (DAY, 40000, 0) for key in range(3, 16)} | {15: (DAY + 16, 0, 0)}, range(2, 15)), weight={key: 9500 for key in range(2, 16)}),
        Case("large maps, two targets", stakes={0: dict.fromkeys(range(1, 17), 10)}, flag=True, seen={key: 4999 for key in range(1, 17)}, stats=fine(*range(1, 17)),
             snapshot=Snapshot(1, {key: (DAY + 16, 0, 0) for key in range(3, 15)}, range(3, 15)), weight={key: 9500 + key for key in range(2, 17)}),
        Case("status map over a leaf", stakes={0: dict.fromkeys(range(1, 19), 10)}, seen={key: 4999 for key in range(1, 19)}, stats=fine(1, 18)),
        Case("saturated seen at the top round", current=MAX_ROUND, valid_until=MAX_ROUND, jail_valid_until=MAX_ROUND, seen={1: MAX_ROUND, 2: MAX_ROUND - 5, 3: MAX_ROUND, 4: MAX_ROUND}),
        Case("cut steps back over midnight", now=(DAY, 85000, 0), wall=(DAY, 85000, 0), snapshot=Snapshot(1, {2: (DAY, 85901, 0), 3: (DAY, 85900, 0)}), stats={1: Sample(0.0, 1.0, (DAY, 85000, 0))}),
        Case("two bundles", steps=2, stats=fine(1, 3, 4)),
        Case("two stake rows pick the later", stakes={0: {2: 10}, 4000: dict(FOUR)}),
    ]
    return cases


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state >> 33


def vector_cases(count):
    draw = lcg(94)
    rows = []
    for index in range(count):
        def pick(limit):
            return next(draw) % limit
        members = tuple(sorted(set((1,) * (pick(4) > 0) + tuple(1 + pick(9) for _ in range(2 + pick(9))))))
        stakes = {key: 1 + pick(900) for key in members}
        seen = {}
        for key in members:
            choice = pick(4)
            if choice:
                seen[key] = (4999, 2000, 1990 - pick(30))[choice - 1]
        stats = {}
        for key in members:
            choice = pick(5)
            if choice == 0:
                continue
            when = (DAY, 40000 - (0, 100, 180, 181)[pick(4)], 0)
            stats[key] = Sample((1.0, 2.0, 3.0, 0.5)[pick(4)], (1.0, 2.0, 0.0)[pick(3)], when)
        weight = {key: (9000, 9001, 12, 70000)[pick(4)] for key in members if pick(3) == 0}
        snapshot = None
        if pick(2):
            snapshot = Snapshot(pick(2), {key: ((DAY, 40899 + pick(3), 500000000), (DAY + 16, 0, 0), (DAY - 16, 5, 0))[pick(3)] for key in members if pick(3) == 0}, [key for key in members if pick(5) == 0])
        jailed = frozenset(key for key in members if pick(6) == 0)
        file = None
        if pick(3) == 0:
            file = File(modified=(1 + pick(2), pick(2), 0), parsed=(0.75, pick(2)))
        rows.append(Case("vector %d" % index, stakes={0: stakes}, seen=seen, stats=stats, weight=weight, snapshot=snapshot, jailed={0: jailed}, flag=pick(2) == 1, file=file, mute=pick(4) == 0 and 1 or 0, steps=1 + (pick(5) == 0)))
    return rows


PINS = (('arm', 0X44AE705, '0fb64608', 'flag byte at event +8'),
        ('arm', 0X44AE725, '483bb588090000', 'round against table+0x58'),
        ('arm', 0X44AE7E8, 'e843b1e1ff', 'stake row'),
        ('arm', 0X44AE7FA, '0f84b5030000', 'no row'),
        ('arm', 0X44AEC3D, '4c8b7c2428', 'flag read'),
        ('arm', 0X44AEC42, '0f84d6000000', 'no flag'),
        ('arm', 0X44AEC6E, '49c785e801000000000000', 'weight map root cleared'),
        ('arm', 0X44AEC79, '49c785f801000000000000', 'weight map length cleared'),
        ('arm', 0X44AEC84, '48c784241002000001000000', 'Some tag of the taken map'),
        ('arm', 0X44AEC90, 'ff15f2072c01', 'clock, answer unused'),
        ('arm', 0X44AED41, '48c78424f0070000b80b0000', '3000'),
        ('arm', 0X44AEE4E, 'e81d496800', 'total stake'),
        ('arm', 0X44AEE56, '0f881f3a0000', 'top bit'),
        ('arm', 0X44AEE5E, '4801c0', 'doubling'),
        ('arm', 0X44AEE6C, '480f47c8', 'max with 3000'),
        ('arm', 0X44B287B, '48c7c0ffffffff', 'top bit gives all ones'),
        ('arm', 0X44AEE8E, 'e85d266800', 'keys of the row'),
        ('arm', 0X44AEEE7, 'e8b4092a00', 'prune'),
        ('arm', 0X44AEEF4, 'e8c7f92900', 'hourly'),
        ('arm', 0X44AEF0C, 'e8fff52900', 'query'),
        ('arm', 0X44AEF3B, 'f20f10055db8d5fb', '1800.0'),
        ('arm', 0X44AEF43, 'ff156f002c01', 'time add'),
        ('arm', 0X44AF048, 'e8e32e3100', 'collect'),
        ('arm', 0X44AF058, '0f849a220000', 'no rows'),
        ('arm', 0X44AF079, 'e8e2256800', 'jail row'),
        ('arm', 0X44AF086, '0f855f220000', 'no jail row'),
        ('arm', 0X44AF09C, 'e83f874700', 'own jail member'),
        ('arm', 0X44AF0A4, '0f854e220000', 'own jailed'),
        ('arm', 0X44AF100, 'e8db193100', 'build rows'),
        ('arm', 0X44AF11B, 'e8d0eaffff', 'send'),
        ('arm', 0X44B13C4, 'c64424380d', 'event answer 0xd'),
        ('rule', 0X4476225, '4883f902', 'tag 2 compare'),
        ('rule', 0X4476229, '0f85bc000000', 'tag gate'),
        ('rule', 0X44762FF, '0f84af010000', 'empty set'),
        ('rule', 0X4476374, '0f84fe030000', 'set member leaves'),
        ('rule', 0X44764BE, '0f846bfdffff', 'time tag bit'),
        ('rule', 0X44766E4, '48c7c27cfcffff', 'minus 900 seconds'),
        ('rule', 0X4476768, '0f86c1faffff', 'fraction compare'),
        ('rule', 0X4476778, '488b442428', 'None'),
        ('rule', 0X44763BA, '4801fa', 'seen plus lag'),
        ('rule', 0X44763C4, '480f43f2', 'saturates'),
        ('rule', 0X44763CC, '483b31', 'against round'),
        ('rule', 0X44763CF, '7324', 'lag rule'),
        ('rule', 0X44763E4, '48c7401803000000', 'reason 3'),
        ('rule', 0X44763FE, '833801', 'Some taken map'),
        ('rule', 0X4476584, '4881fa29230000', '9001'),
        ('rule', 0X447658B, '7224', 'under 9001'),
        ('rule', 0X44765A0, '48c7401805000000', 'reason 5'),
        ('rule', 0X4476648, '7431', 'status row'),
        ('build', 0X47C0C1B, '48c7842490010000b0000000', 'action tag 0xb0'),
        ('build', 0X47C0C27, 'c684249801000002', 'inner tag 2, voteJail'),
        ('build', 0X47C0C55, 'ff159dddfa00', 'signing time'),
        ('build', 0X47C0C5B, '48c744247001000000', 'first word 1'),
        ('build', 0X47C0CA4, '4889842470010000', 'key pointer at +0x100'),
        ('build', 0X47C0CBC, '4488ac248e010000', 'state+0xb04 byte at +0x11e'),
        ('build', 0X47C0CCC, 'ff15b62ffb00', 'sign row'),
        ('build', 0X47C0CD2, 'ba68010000', 'row 0x168'),
        ('collect', 0X47C1F79, 'e88242cbff', 'rule, first'),
        ('collect', 0X47C1F83, '4883f906', 'none tag 6'),
        ('collect', 0X47C230C, 'e8ef3ecbff', 'rule, next'),
        ('collect', 0X47C2319, '4883f906', 'none tag 6'),
        ('send', 0X44ADC26, '66813c248601', 'ok 0x186'),
        ('send', 0X44ADC75, '48c744246009000000', 'outbox tag 9'),
        ('query', 0X474E5AA, '660f2e442418', 'elapsed against tracker+0xd8'),
        ('query', 0X474E5B0, '0f8691010000', 'inside interval'),
        ('query', 0X474E5E0, '84c0', 'exists'),
        ('query', 0X474E5E2, '0f845f010000', 'missing'),
        ('query', 0X474E601, '837c244001', 'metadata answer'),
        ('query', 0X474E666, '3c02', 'parser tag 2'),
        ('query', 0X474E6F8, 'f20f1183c8000000', 'limit stored'),
        ('query', 0X474E700, '8883d0000000', 'mute stored'),
        ('query', 0X474E7DB, 'e8e0f61400', 'status map'),
        ('feed', 0X44AF8B1, '4939cd', 'seen map max, heartbeat arm'),
        ('feed', 0X44B048B, '4939cc', 'seen map max, second writer'),
        ('feed', 0X44B9F53, '41ffd6', 'action weight per signed row'),
        ('feed', 0X44BA0CA, '488ba8e8010000', 'weight map read at bundle intake'),
        ('feed', 0X44BA1F8, '4c0320', 'weight map add'),
        ('feed', 0X44BA202, '490f43cc', 'saturating'),
        ('feed', 0X44B0A11, '83bde802000002', 'stored event tag test'),
        ('feed', 0X44B0A32, 'ff15a8d52b01', 'stored event write'),)
OUTER_TABLE = 0x6F2A34
INNER_TABLE = 0x6F2A50
BUNDLE_INTAKE = 0x44B9A50
DISPATCH_TAGS = ((0xF, JAIL_ARM, "this path; the byte at event +8 is the flag"),)
SLOTS = ((SLOT_BACK, 0x1459CA0, "time plus a float number of seconds, event time plus 1800.0 at 0x44aef43"), (SLOT_MILLIS, 0x13CCE80, "signing time, called once per target and once per bundle"), (SLOT_SIGN_ACTION, 0x3341AF0, "signs one action row, stubbed"), (SLOT_BUNDLE, 0x3340100, "bundles signed rows, stubbed"), (SLOT_EXISTS, 0x144A710, "does the watched file exist"), (SLOT_MTIME, 0x144C930, "modified time of the watched file"), (SLOT_MONOTONIC, 0x14385C0, "lazy process clock, its answer is not used at 0x44aec90"), (SLOT_WALL, 0x151CBA0, "wall clock now"), (SLOT_ELAPSED, 0x1447130, "seconds between two times"), (SLOT_TIME_ADD, 0x15206E0, "time of day add"), (SLOT_DATE_ADD, 0x151F870, "date add"), (SLOT_ACTION_WEIGHT, 0x33632E0, "action weight of one signed row, summed per bundle at 0x44b9f53"))
NUMBERS = ((0x20A7A0, 1800.0, "seconds added to the event time: vote time and base of the 900 second cut, loaded at 0x44aef3b"), (0x20ACD8, 180.0, "seconds of silence that make reason 1, loaded at 0x4726c87, pinned before by RE-001-heartbeat-status-94"))
GATES = (
    ("arm", 1, 0x44AE72C, "state+0x918 over table+0x58: warning only, three times on this path (the arm twice, 0x4b314f0 once)", "no log", None),
    ("arm", 2, 0x44AE7FA, "no stake row for the round: error 0x28 dropped, leave", "go on", "no stake row"),
    ("arm", 3, 0x44AE913, "row key equal to this node at state+0xaec found: go on", "walk on", None),
    ("arm", 4, 0x44AE930, "tree walk ends: this node has no stake row, leave without touching state+0x1e8", "go on", "not a member"),
    ("arm", 5, 0x44AEC42, "flag zero: no weight map for this event", "take state+0x1e8 by value, leave it empty, clock read", None),
    ("arm", 6, 0x44AED41, "lag floor word set to 3000", "-", None),
    ("arm", 7, 0x44AEE56, "2 * total stake; a sum with the top bit set gives u64::MAX", "-", None),
    ("arm", 8, 0x44AEE6C, "lag = max(3000, doubled total)", "-", None),
    ("arm", 9, 0x44AEEE7, "0x474f8a0 prune of the tracker over the keys of the row, stubbed here", "-", None),
    ("arm", 10, 0x44AEEF4, "0x474e8c0 hourly file row over the keys, stubbed here", "-", None),
    ("arm", 11, 0x44AEF0C, "0x474e510 config look and status map of the keys", "-", None),
    ("arm", 12, 0x44AEF43, "time word = event time + 1800.0 seconds", "-", None),
    ("arm", 13, 0x44AF048, "0x47c1f30 keeps the keys 0x4476200 speaks for, in key order", "-", None),
    ("arm", 14, 0x44AF058, "no row: leave", "go on", "no target"),
    ("arm", 15, 0x44AF086, "no jail row for the round: error dropped, no vote", "go on", "no jail row"),
    ("arm", 16, 0x44AF0A4, "this node in the jail row: no vote", "go on", "this node jailed"),
    ("arm", 17, 0x44AF100, "0x47c0ae0 one signed row per target", "-", None),
    ("arm", 18, 0x44AF11B, "0x44adbf0 sends all rows as one bundle", "-", None),
    ("send", 1, 0x44ADC2C, "bundle answer not 0x186: answer dropped, nothing in the outbox", "go on", "send refused"),
    ("send", 2, 0x44ADC75, "outbox row tag 9 holding an Arc of the bundle, the same sink as the arm at 0x44aeb8d", "-", "votes sent"),
    ("rule", 1, 0x4476229, "stored event tag 2: no jail rules", "rule 2", None),
    ("rule", 2, 0x4476374, "key in stored event set at +0x100: left alone", "rule 3", None),
    ("rule", 3, 0x44764BE, "stored event tag bit 0 clear: no time rule", "rule 4", None),
    ("rule", 4, 0x4476768, "row time in stored event map at +8 over event time + 900 s: left alone; equal goes on; order is date, seconds, fraction", "rule 5", None),
    ("rule", 5, 0x44763CF, "seen map row and saturating seen + lag under the round: reason 3; a key with no seen row skips this rule", "rule 6", None),
    ("rule", 6, 0x447658B, "flag given, weight map row of 9001 or more: reason 5", "rule 7", None),
    ("rule", 7, 0x4476648, "status map row: reason tag 0, 1 or 2 from the query", "left alone", None),
    ("query", 1, 0x474E5B0, "a last look exists and elapsed is at or under tracker+0xd8: skip the file", "last look = now, go on", None),
    ("query", 2, 0x474E5E2, "file missing: skip", "go on", None),
    ("query", 3, 0x474E606, "metadata error: unwrap panic", "go on", "panic"),
    ("query", 4, 0x474E63F, "modified time not newer than tracker+0xf8 (date signed, then seconds and fraction): skip", "load", None),
    ("query", 5, 0x474E668, "parser refused: log, held error replaced at tracker+0xf0, limit and time stay", "store", None),
    ("query", 6, 0x474E700, "limit at +0xc8, mute at +0xd0, time at +0xf8 stored, held error cleared", "-", None),
)
REASONS = ((0, 0x4726CB4, "not written", "no tracker row"), (1, 0x4726CD3, "elapsed seconds, float", "tracker row older than 180 s"), (2, 0x4726CF7, "ratio, float", "ratio over the limit and mute byte zero"), (3, 0x44763E4, "seen round", "seen map lags the round by over max(3000, 2 * total)"), (5, 0x44765A0, "bundle weight", "weight map value of 9001 or more, flag only"))
LAYOUT = (('event', 0X0, 0X8, 'tag 0xf', 0X44AE02B),
          ('event', 0X8, 0X1, 'flag', 0X44AE705),
          ('target row', 0X0, 0X14, 'validator', 0X44763DD),
          ('target row', 0X18, 0X8, 'reason tag; 6 means no row', 0X44763E4),
          ('target row', 0X20, 0X8, 'reason value', 0X44763EC),
          ('action row', 0X0, 0X8, 'word 1', 0X47C0C5B),
          ('action row', 0X8, 0X8, 'signing time word from slot 0x576e9f8', 0X47C0C64),
          ('action row', 0X10, 0X8, 'action tag 0xb0', 0X47C0C69),
          ('action row', 0X18, 0X1, 'inner tag 2, voteJail', 0X47C0C75),
          ('action row', 0X19, 0X14, 'target', 0X47C0C8A),
          ('action row', 0X30, 0XC, 'vote time, event time + 1800 s, inner +0x18', 0X47C0C97),
          ('action row', 0X100, 0X8, 'pointer to the key block at state+0x9d0', 0X47C0CA4),
          ('action row', 0X108, 0X1, 'zero', 0X47C0CAC),
          ('action row', 0X11D, 0X1, 'zero', 0X47C0CB4),
          ('action row', 0X11E, 0X1, 'byte of state+0xb04', 0X47C0CBC),
          ('tracker', 0XB8, 0X10, 'watched path', 0X474E5D3),
          ('tracker', 0XC8, 0X8, 'ratio limit', 0X474E6F8),
          ('tracker', 0XD0, 0X1, 'mute byte', 0X474E700),
          ('tracker', 0XD8, 0X8, 'look interval, seconds', 0X474E546),
          ('tracker', 0XE0, 0XC, 'last look', 0X474E53C),
          ('tracker', 0XF0, 0X8, 'held error', 0X474E6E9),
          ('tracker', 0XF8, 0XC, 'file time in use', 0X474E706),
          ('tracker', 0X120, 0X18, 'validator rows', 0X474E76D),
          ('tracker row', 0X10, 0X8, 'ratio numerator', 0X4726B54),
          ('tracker row', 0X18, 0X8, 'ratio denominator', 0X4726B38),
          ('tracker row', 0X58, 0XC, 'time of the last sample', 0X4726C4A),
          ('stored event', 0X0, 0X8, 'tag, 2 none; bit 0 times are read', 0X4476222),
          ('stored event', 0X8, 0X10, 'validator to time', 0X44764C4),
          ('stored event', 0X100, 0X10, 'validator set', 0X44762F5),
          ('state', 0X1E8, 0X18, 'weight map: key of a bundle to the sum of its action weights', 0X44AEC4D),
          ('state', 0X2E8, 0X150, 'stored execution event', 0X44B0A11),
          ('state', 0X6F8, 0X160, 'heartbeat tracker', 0X44AEED8),
          ('state', 0X918, 0X8, 'round', 0X44AE70D),
          ('state', 0XA68, 0X18, 'seen map', 0X44AF882),
          ('state', 0XAEC, 0X14, 'this node', 0X44AE853),
          ('state', 0XB04, 0X1, 'byte at action row +0x11e', 0X44AF0C1),
          ('state', 0X9D0, 0X8, 'key block', 0X44AF0BA),)
STRINGS = ((0X3C0091, 'struct variant CSignerAction::VoteJail'), (0X1DF908, 'Error updating FileModTimeTracker for '), (0X1E8C49, 'Querying stakes for high round, is execution behind?'),)
LOCATIONS = ((0x44AE7B1, 0x5738668, "stake table high round log"), (0x4B316D4, 0x5738650, "jail table high round log"), (0x474E6BC, 0x572EEC0, "FileModTimeTracker error log"))
TRIGGERS = ((COLLECT, 0x44AF048, "arm 0xf"), (RULE, 0x47C1F79, "collector first row"), (RULE, 0x47C230C, "collector next rows"), (BUILD, 0x44AF100, "arm 0xf"), (PRUNE, 0x44AEEE7, "arm 0xf"), (HOURLY, 0x44AEEF4, "arm 0xf"), (QUERY, 0x44AEF0C, "arm 0xf"), (QUERY_MAP, 0x474E7DB, "query"), (STATUS, 0x4876FD9, "status list first row"), (STATUS, 0x487734C, "status list next rows"), (STAKE_KEYS, 0x44AEE8E, "arm 0xf"), (STAKE_KEYS, 0x44A895E, "constructor side, not in this packet"), (STAKE_KEYS, 0x44B3425, "dispatcher, not in this packet"),
            (LOAD_CONFIG, 0x474E65C, "query"), (LOAD_CONFIG, 0x474F1C8, "second reader in the tracker constructor range, not in this packet"))
SUBJECTS = (RULE, COLLECT, BUILD, QUERY, QUERY_MAP, STAKE_KEYS, SEND_ACTIONS)
ARMS = ((0x44AE705, 0x44AE943), (0x44AEBB5, 0x44AEBDB), (0x44AEC38, 0x44AEC96), (0x44AED1E, 0x44AF1AC), (0x44AF2E5, 0x44AF2F2), (0x44B12EB, 0x44B13D1), (0x44B287B, 0x44B2887))
ROLES = {RULE: "target rules for one validator", COLLECT: "collects the targets in key order", BUILD: "one voteJail row per target", QUERY: "config look, then status map", QUERY_MAP: "status list into a map", STAKE_KEYS: "keys of the stake row", SEND_ACTIONS: "sends a signed bundle"}
STUBS = {NOW_INSTANT: "event start instant", DROP_ERROR: "error drop, the tag is recorded", DROP_VALUE: "error value drop", DROP_ROWS: "drop of the signed rows", DROP_SEND_ERROR: "drop of a refused bundle answer, recorded", PRUNE: "tracker prune, the key list is recorded", HOURLY: "hourly file row, the key list is recorded", LOAD_CONFIG: "config file parser, fixture answer", 0x49A7D50: "drop", 0x49B05E0: "drop", 0x49A9C60: "drop"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_MEMMOVE: "memmove", SLOT_ALLOC: "fixture bump allocator", SLOT_ALLOC_ERROR: "panic", SLOT_DEALLOC: "dealloc, no effect", SLOT_REALLOC: "realloc in the bump area", SLOT_LOG: "warning log, text address recorded", SLOT_FORMAT: "format, empty string", SLOT_BTREE_PANIC: "panic", SLOT_ASSERT: "panic", SLOT_PANIC_FMT: "panic", SLOT_PANIC_ADD: "panic", SLOT_UNWRAP: "panic", SLOT_MONOTONIC: "recorded, no answer", SLOT_RECORD: "event record, no effect", SLOT_GROW_OUT: "panic, fixture outbox is large enough", SLOT_WALL: "fixture wall clock", SLOT_MILLIS: "fixture signing time", SLOT_EXISTS: "fixture file", SLOT_MTIME: "fixture file", SLOT_SIGN_ACTION: "records the action row, copies it", SLOT_BUNDLE: "records the targets, fixture answer"}
HELPERS = {STATUS: "status query, read in RE-001-heartbeat-status-94", QUERY_LIST: "status list, read in RE-001-heartbeat-status-94", 0x42C9930: "stake row lookup", JAILED_AT: "jail row of a round", JAILED_FIND: "jail row lookup", JAILED_MEMBER: "set member", TOTAL_STAKE: "total of the row values", SET_ITER: "set iterator", 0x1447130: "seconds between two times"}
FIELDS = ((0x1E8, "weight map"), (0x2E8, "stored execution event"), (0xA68, "seen map"), (0xB04, "byte at action row +0x11e"), (0x6F8, "heartbeat tracker"))
MUTANT_CAP = 12
VECTORS = 300
BOUNDARY = frozenset(("lag rule at the floor", "lag rule one short", "lag rule one over", "weight at the limit, flag", "weight one under, flag", "quiet exactly at the limit", "quiet over", "ratio at limit", "ratio over limit", "recent time exact cut is picked", "recent time left alone", "config at the interval edge", "config past the interval", "doubled stake opens the window", "doubled stake just at the floor", "stake sum top bit gives no lag rule", "cut crosses midnight", "cut steps back over midnight", "large maps", "large maps, two targets", "status map over a leaf", "twelve validators", "saturated seen at the top round", "two bundles", "config parse refused", "config parse refused replaces held", "config new limit picks", "config clears a held error", "config newer seconds", "config older seconds", "config newer frac", "config negative date older", "send refused"))


def survivor_reason(va, kind):
    if 0x44AE732 <= va < 0x44AE7D6 or 0x44AED6E <= va < 0x44AEE0A or 0x4B31511 <= va < 0x4B31596 or 0x474E66E <= va < 0x474E6D3:
        return "row of a log path, the text is the only output"
    if 0x44AEBB5 <= va < 0x44AEC38:
        return "row of the once cell after an error"
    if 0x44B12EB <= va < 0x44B13BE or 0x44AF12D <= va < 0x44AF1AC:
        return "row of a drop, the fixture free has no effect"
    if 0x47C0D30 <= va:
        return "row of an unwind path"
    if 0x44AE7ED <= va < 0x44AE82F:
        return "row after a helper that cannot fail once the same lookup passed"
    if va in (0x47C1F83, 0x47C231D, 0x47C1FAC, 0x47C2003, 0x47C2366, 0x47C23A8):
        return "row of the Option check over the rule answer"
    if va in (0x47C0C1B, 0x47C0C27):
        return "scratch copy at rsp+0x190, read only on the unwind path; the row at 0x47c0c69 carries the same value"
    if va in (0x47C0CD2, 0x44ADC41, 0x44ADCAE, 0x47C0B12):
        return "copy or allocation size, one byte more is not observed"
    if va in (0x4476364, 0x4476537, 0x4476638, 0x44AE903):
        return "end count of a key walk: the fixture fill after the last key compares above every key, so the walk stops at the same place"
    if va == 0x47C0B19:
        return "capacity overflow limit, not reachable with fixture sizes"
    if va in (0x44AEFBC, 0x474E797):
        return "back handle of a range, a forward walk does not read it"
    if va in (0x44AE7E2, 0x44B13C9):
        return "drop flag in r13b, read only by unwind"
    if va == 0x44AEE5C:
        return "zero total skips the max, 3000 stays either way"
    if va == 0x44B287B:
        return "all ones or nearly: no round is over it"
    if va in (0x474E576, 0x474E591, 0x474E819):
        return "Location or message length argument, read only on a diagnostic"
    if 0x4476704 <= va < 0x447671E:
        return "TimeDelta range guard constant, fixture shifts are far inside it"
    if va in (0x447672C, 0x447673C):
        return "seconds to days reciprocal, exact for a shift of one day"
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


def scan_fields(image):
    """Each disp32 equal to a state field offset, in the dispatcher and the constructor, by a mod 2 modrm byte in a decoded row."""
    rows = []
    for host in (DISPATCH, image.fde(0x44A9AE2)[0], BUNDLE_INTAKE):
        begin, end = image.exact_fde(host)
        at = image.offset(begin)
        data = bytes(image.blob[at:at + end - begin])
        for offset, meaning in FIELDS:
            for match in re.finditer(re.escape(struct.pack("<I", offset)), data):
                modrm = data[match.start() - 1]
                if modrm >> 6 == 2 and modrm & 7 != 4:
                    rows.append((offset, begin + match.start() - 1, host, data[match.start() - 3:match.start() + 4].hex(), meaning))
    return sorted(rows)


def read_dispatch(image):
    rows = []
    for tag, want, use in DISPATCH_TAGS:
        if tag >= 0xB:
            base, index = OUTER_TABLE, tag - 0xA
        else:
            base, index = INNER_TABLE, 7 if tag < 2 else tag - 2
        at = image.offset(base + 4 * index)
        target = base + struct.unpack_from("<i", image.blob, at)[0]
        if target != want:
            raise EvidenceError("dispatch differs for tag %#x: %#x" % (tag, target))
        rows.append((tag, base, index, target, use))
    return rows


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
    for va in [row[2] for row in GATES] + [row[4] for row in LAYOUT] + [row[1] for row in REASONS]:
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
        except (Halt, Panicked, EvidenceError, AttributeError, KeyError, IndexError, ValueError, OverflowError, TypeError, UnicodeDecodeError, struct.error):
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


def check_numbers(image):
    rows = []
    for va, want, use in NUMBERS:
        at = image.offset(va)
        value = struct.unpack_from("<d", image.blob, at)[0]
        if value != want:
            raise EvidenceError("number differs at %#x" % va)
        rows.append((va, want, use))
    return rows


def analyse(image, mutate=True, vectors=VECTORS):
    triggers = scan_triggers(image)
    pins = check_pins(image)
    numbers = check_numbers(image)
    slots = check_slots(image)
    strings = check_strings(image)
    locations = check_locations(image)
    decoded = check_gate_sites(image)
    fields = scan_fields(image)
    dispatch = read_dispatch(image)
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
    result = dict(triggers=triggers, pins=pins, slots=slots, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels, decoded=decoded, fields=fields, dispatch=dispatch, numbers=numbers)
    for row in GATES:
        if row[5] and row[5] not in labels:
            raise EvidenceError("gate outcome never reached: %s" % row[5])
    if mutate:
        result["mutations"] = run_mutants(image, cases, selected)
    return result


def case_shape(case, label, got):
    votes = [row for row in got["trace"] if row[0] == "vote"]
    return (case.name, label, case.steps, int(case.flag), ",".join("%d:%d" % (row[7], row[1]) for row in votes) or "-", len(got["outbox"]), len(got["weight"]))


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    labels = result["labels"]

    def count(label):
        return labels[label] if label else "-"
    tsv("gates.tsv", ("group", "order", "site", "rule", "otherwise", "outcome_label", "cases"), [(group, order, "%#x" % va, rule, other or "-", label or "-", count(label)) for group, order, va, rule, other, label in GATES])
    tsv("reasons.tsv", ("reason_tag", "site", "value_at_row_0x20", "meaning"), [("%#x" % tag, "%#x" % va, value, meaning) for tag, va, value, meaning in REASONS])
    tsv("numbers.tsv", ("address", "double", "use"), [("%#x" % va, value, use) for va, value, use in result["numbers"]])
    functions = [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], "subject", ROLES[start]) for start in SUBJECTS]
    functions += [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], "helper", HELPERS.get(start, "B-tree or list helper")) for start in REAL_FUNCTIONS if start not in SUBJECTS]
    functions.append(("%#x" % DISPATCH, "%#x" % image.exact_fde(DISPATCH)[1], image.exact_fde(DISPATCH)[1] - DISPATCH, result["reached"][DISPATCH], "arms only", "rows of arm 0xf only"))
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "use", "role"), functions)
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("triggers.tsv", ("target", "site", "context"), [("%#x" % target, "%#x" % site, text) for target, site, text in TRIGGERS])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("slots.tsv", ("slot", "target", "use"), [("%#x" % slot, "%#x" % target, use) for slot, target, use in result["slots"]])
    tsv("strings.tsv", ("address", "text"), [("%#x" % va, text) for va, text in result["strings"]])
    tsv("locations.tsv", ("site", "data", "path", "line", "column", "use"), result["locations"])
    tsv("dispatch.tsv", ("event_tag", "table", "index", "target", "use"), [("%#x" % tag, "%#x" % base, index, "%#x" % target, use) for tag, base, index, target, use in result["dispatch"]])
    tsv("field-uses.tsv", ("field_offset", "site", "function", "bytes", "field"), [("%#x" % offset, "%#x" % site, "%#x" % host, text, meaning) for offset, site, host, text, meaning in result["fields"]])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(labels.items()))
    tsv("cases.tsv", ("case", "last_outcome", "events", "flag", "target_and_reason", "outbox_rows", "weight_rows_left"), [case_shape(case, label, got) for case, label, got in result["rows"]])
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    subject_bytes = sum(image.exact_fde(start)[1] - start for start in SUBJECTS)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "subject_functions": len(SUBJECTS), "helpers_run": len(REAL_FUNCTIONS) - len(SUBJECTS),
               "subject_bytes": subject_bytes, "subject_reached_bytes": sum(result["reached"][start] for start in SUBJECTS), "arm_reached_bytes": result["reached"][DISPATCH], "pins": result["pins"], "call_sites": result["triggers"], "gates": len(GATES), "rows_decoded": result["decoded"], "field_uses": len(result["fields"])}
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
