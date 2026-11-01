#!/usr/bin/env python3
"""Pin the node #94 heartbeat path from ELF bytes: send gates, receipt, snapshot stake tracker, ack, ack match.

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
HEAP_SIZE = 0x400000
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
REAL_FUNCTIONS = (0x41D7DC0, 0x41E8640, 0x42044C0, 0x42067B0, 0x4223F90, 0x4227AA0, 0x422DC70, 0x4233BB0, 0x4257220, 0x4287F30, 0x42898A0, 0x428D080, 0x42A9B50, 0x42AE440, 0x42B19E0, 0x42B6C60, 0x42B7C70, 0x42B8500, 0x42BA100, 0x42C9930, 0x42C9A30, 0x4355E90, 0x43563B0, 0x435DE00, 0x4450BB0, 0x4452160, 0x454AEC0, 0x454B300, 0x454B430, 0x454BD70, 0x474E1B0, 0x474FA50, 0x4880130, 0x4895B30, 0x4896C90, 0x48C3F80, 0x48C4470, 0x48C4A30, 0x48C6A10, 0x4908E20, 0x490A450, 0x4913410, 0x49277E0, 0x4928080, 0x49281D0, 0x492DC40, 0x492EA70, 0x493FBC0, 0x4942E30, 0x4946620, 0x4947330, 0x494A910, 0x494B020, 0x49524E0, 0x4956720, 0x4956C00, 0x49594F0, 0x495ABD0, 0x497C710, 0x497E070, 0x4982D60, 0x4986A50, 0x49A4F20, 0x49A4F70, 0x49A5060, 0x49A5470, 0x49A58F0, 0x49B0D00, 0x49BA060, 0x4AD90D0, 0x4AD9850, 0x4B31660, 0x4B31D40)
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
SLOT_PANIC_ADD = 0x576E118
SLOT_MONOTONIC = 0x576F488
SLOT_RECORD = 0x5773648
SLOT_STAKE = 0x57769E8
SLOT_MEMBER = 0x57769F0
SLOT_QUORUM = 0x5776AE8
SLOT_GROW_OUT = 0x57769D0
SLOT_GROW_ROWS = 0x57769E0
SLOT_GROW_RING = 0x5776650
SLOT_WALL = 0x576E8A0
SLOT_TABLE_UPDATE = 0x5773B98
ONCE_WORD = 0x577AB98
NOW_INSTANT = 0x4EE3800
DISPATCH = 0x44ADFA0
EXEC_ARM = 0x44AE470
SEND_GATE = 0x44AF1AC
SEND_BODY = 0x44B0639
RECV_ARM = 0x44AF6A4
ACK_ARM = 0x44AFFED
VERIFY_BEAT = 0x454BD70
VERIFY_ACK = 0x454B430
SIGN_BEAT = 0x454AEC0
SIGN_ACK = 0x454B300
NOTE_SENT = 0x474E1B0
NOTE_ACK = 0x474FA50
ACK_ROW = 0x493FBC0
TRACK = 0x435DE00
TRACK_CORE = 0x48C6A10
SLOT_QUORUM_CHECK = 0x48C3F80
JAILED_AT = 0x4B31660
JAILED_FIND = 0x42C9A30
SET_LOOKUP = 0x42C9930
SEEN_MAPS = 0x492DC40
EXEC_MAP_INSERT = 0x43563B0
OWN_FIND = 0x4355E90
BUFFER_ENTRY = 0x49281D0
BUFFER_TAKE = 0x4942E30
BUFFER_FIRST = 0x4947330
SAME_STAKES = 0x49A5470
SAME_JAILED = 0x49A58F0
JAILED_MEMBER = 0x49277E0
QUORUM = 0x4AD90D0
DIGEST = 0x454C050
SIGN_HASH = 0x14A2710
RANDOM = 0x4A11190
EVENT_SIZE = 0x180
DROP_ERROR = 0x447E690
DROP_VALUE = 0x4B1A270
SLOW_UPDATE = 0x4548A50
DROP_EXEC = 0x4482260
STOP_TAIL = 0x44B181C
STOP_EXEC = 0x44B1F7A
NONE_TAG = 1 << 63
OK_TAG = NONE_TAG + 0x2A
NO_SET_TAG = NONE_TAG + 0x28
BAD_SIG_TAG = NONE_TAG + 1
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0xB10
TABLE = STATE + 0x930
EVENT = HEAP_BASE + 0x2000
TIME_IN = HEAP_BASE + 0x2200
ERROR_OBJECT = HEAP_BASE + 0x22C0
ERROR_VTABLE = HEAP_BASE + 0x22E0
RING = HEAP_BASE + 0x2300
OUTBOX = HEAP_BASE + 0x3000
NODES = HEAP_BASE + 0x10000
STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))
LOW_ROUNDS = 200
RECENT_SPAN = 2000
BEAT_EVERY = 10
SNAPSHOT_EVERY = 100
QC_LAG = 1000
KEEP_ROUNDS = 1000
SELF = 1
MAX_ROUND = 0xFFFFFFFFFFFFFFFF
RING_CAP = 32
LOG_TEXT = {0x1E8C48: "high round", 0x1ED6D3: "behind", 0x1F4484: "high jail round"}


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 8 * 12


STAKE_LAYOUT = Layout(0x60, 20, 8, 8, 0, 0x13C, 0x13E, 0x140)
TABLE_LAYOUT = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
SET_LAYOUT = Layout(8, 20, 0xE4, 0, 0, 0xE4, 0xE6, 0xE8)
PEER_MAPS_LAYOUT = Layout(0x110, 20, 8, 0x18, 0, 0x1EC, 0x1EE, 0x1F0)
BUFFER_LAYOUT = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
OWN_LAYOUT = Layout(0x6E8, 8, 0, 0xA0, 0x6E0, 0x740, 0x742, 0x748)
SENT_LAYOUT = Layout(8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
ACK_LAYOUT = Layout(8, 20, 0xE4, 12, 0, 0x168, 0x16A, 0x170)
ROUND_LAYOUT = Layout(0x428, 8, 0, 0x60, 0x420, 0x480, 0x482, 0x488)
SLOT_LAYOUT = Layout(0, 0x40, 0x2C0, 0x30, 0x4D0, 0x4D8, 0x4DA, 0x4E0)


def addr_bytes(value):
    return value.to_bytes(20, "big")


class Sig:
    """by: recovered signer, good: covers the digest, broken: recovery fails."""

    def __init__(self, by=None, good=True, broken=False):
        self.by, self.good, self.broken = by, good, broken


class Snap:
    """A heartbeat snapshot: stakes and jailed may each be absent; lt is a one byte stand-in for the 0x90 byte hash block."""

    def __init__(self, stakes=None, jailed=None, lt=None, evm=0):
        self.stakes, self.jailed, self.lt, self.evm = stakes, jailed, lt, evm

    def key(self):
        return (None if self.stakes is None else tuple(sorted(self.stakes.items())), None if self.jailed is None else tuple(sorted(self.jailed)))


class Exec:
    def __init__(self, round, lt=None, evm=7):
        self.round, self.lt, self.evm = round, lt, evm


class Beat:
    def __init__(self, signer, round, random=0x51, peers=None, snap=None, sig=None):
        self.signer, self.round, self.random, self.peers, self.snap, self.sig = signer, round, random, peers, snap, sig


class Ack:
    def __init__(self, signer, round, random=0x51, sig=None):
        self.signer, self.round, self.random, self.sig = signer, round, random, sig


class Case:
    def __init__(self, name, steps, **extra):
        self.name, self.steps = name, tuple(steps)
        self.current = 5000
        self.highest = 5000
        self.base = 0
        self.valid_until = 100000
        self.stakes = {0: {1: 10, 2: 10, 3: 10, 4: 10}}
        self.jailed = {0: frozenset()}
        self.seen_rounds = {}
        self.own = ()
        self.buffered = {}
        self.sent = {}
        self.first = None
        self.last_sent = None
        self.last_snap = None
        self.floor = None
        self.prefill = {}
        self.limit = 16
        self.randoms = (0xABC0, 0xABC1, 0xABC2, 0xABC3, 0xABC4)
        self.sign_error = False
        self.now = (2026, 1000, 500000000)
        self.wall = (7, 8, 9)
        for name, value in extra.items():
            if not hasattr(self, name):
                raise ValueError(name)
            setattr(self, name, value)


def fixture_digest(variant, data):
    return hashlib.sha256(bytes([variant]) + data).digest()


def beat_digest(signer, round, random):
    return fixture_digest(3, struct.pack("<Q", round) + addr_bytes(signer) + struct.pack("<I", random))


def ack_digest(signer, round, random):
    return fixture_digest(4, struct.pack("<Q", round) + addr_bytes(signer) + struct.pack("<I", random))


def signature_bytes(sig, digest, claimed):
    """A fixture signature: 20 byte recovered address, 32 byte digest it covers, flag byte."""
    sig = sig or Sig()
    by = claimed if sig.by is None else sig.by
    covered = digest if sig.good else b"\x00" * 32
    data = addr_bytes(by) + covered + (b"\x01" if sig.broken else b"\x00")
    return data.ljust(0x41, b"\x5a")


def other_address(data):
    return bytes(byte ^ 0xFF for byte in data[:20])


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_MEMMOVE: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_ALLOC_ERROR: self.on_panic, SLOT_DEALLOC: self.on_nothing, SLOT_LOG: self.on_log, SLOT_FORMAT: self.on_format, SLOT_RECOVER: self.on_recover,
                 SLOT_BTREE_PANIC: self.on_panic, SLOT_ASSERT: self.on_panic, SLOT_PANIC_FMT: self.on_panic, SLOT_PANIC_ADD: self.on_panic, SLOT_MONOTONIC: self.on_nothing, SLOT_RECORD: self.on_nothing, SLOT_GROW_OUT: self.on_grow_out, SLOT_GROW_ROWS: self.on_grow_rows, SLOT_GROW_RING: self.on_panic,
                 SLOT_WALL: self.on_wall, SLOT_TABLE_UPDATE: self.on_table_update}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        self.error_mark = MARK_BASE + 0x1000
        machine.slots[self.error_mark] = self.on_nothing
        relative = image.relative()
        for slot in (SLOT_STAKE, SLOT_MEMBER, SLOT_QUORUM):
            memory.statics[slot] = relative[slot]
        memory.statics[0x576E8A8] = relative[0x576E8A8]
        memory.statics[0x576E8B0] = relative[0x576E8B0]
        memory.statics[ONCE_WORD] = 0
        machine.real = frozenset(REAL_FUNCTIONS)
        machine.calls = {NOW_INSTANT: self.on_instant, DIGEST: self.on_digest, SIGN_HASH: self.on_sign, RANDOM: self.on_random, DROP_ERROR: self.on_drop_error, DROP_VALUE: self.on_nothing, SLOW_UPDATE: self.on_nothing, DROP_EXEC: self.on_nothing,
                         0x49478B0: self.on_drain, 0x48FF470: self.on_nothing, 0x49B91C0: self.on_nothing, 0x49B05E0: self.on_nothing, 0x49B5080: self.on_nothing, 0x49A9C60: self.on_nothing, 0x4907CE0: self.on_nothing, 0x447C050: self.on_nothing, 0x49A90C0: self.on_nothing, 0x4874570: self.on_drop_list}
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
        self.expect(text in LOG_TEXT, "log text %#x" % text)
        self.trace.append(("log", LOG_TEXT[text]))

    def on_recover(self, machine):
        regs, memory = machine.regs, machine.memory
        out = regs[RDI]
        data = memory.bytes_at(regs[RSI], 0x41)
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

    def on_wall(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<iII", *self.case.wall))

    def on_table_update(self, machine):
        self.expect(machine.regs[RDI] == TABLE, "table update")

    def on_digest(self, machine):
        regs, memory = machine.regs, machine.memory
        variant, at = memory.read(regs[RSI], 8), memory.read(regs[RSI] + 8, 8)
        if variant == 3:
            digest = beat_digest(int.from_bytes(memory.bytes_at(at + 0x108, 20), "big"), memory.read(at + 0x100, 8), memory.read(at + 0x11C, 4))
        else:
            self.expect(variant == 4, "digest variant")
            digest = ack_digest(int.from_bytes(memory.bytes_at(at + 8, 20), "big"), memory.read(at, 8), memory.read(at + 0x1C, 4))
        memory.put_bytes(regs[RDI], digest)

    def on_sign(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0x9D0, "signing key")
        out = regs[RDI]
        digest = memory.bytes_at(regs[RDX], 32)
        memory.write(out, 4, 0)
        memory.put_bytes(out + 8, digest + digest)
        memory.write(out + 0x48, 1, 0x1B)

    def on_random(self, machine):
        self.expect(self.randoms, "random draw")
        machine.regs[RAX] = self.randoms.pop(0)

    def on_drop_error(self, machine):
        regs, memory = machine.regs, machine.memory
        self.trace.append(("error", memory.read(regs[RDI], 8) - NONE_TAG))

    def on_drain(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_drop_list(self, machine):
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<QQQ", 0, 8, 0))

    def on_grow_out(self, machine):
        raise Panicked("outbox fixture too small")

    def on_grow_rows(self, machine):
        regs, memory = machine.regs, machine.memory
        vector = regs[RDI]
        cap, rows, count = struct.unpack("<QQQ", memory.bytes_at(vector, 24))
        fresh = self.alloc(0xB8 * (cap + 4))
        if cap:
            memory.copy(fresh, rows, 0xB8 * count)
        memory.put_bytes(vector, struct.pack("<QQ", cap + 4, fresh))

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

    def stake_words(self, stakes):
        items = [(addr_bytes(key), value.to_bytes(8, "little")) for key, value in sorted(stakes.items())]
        root, height = self.build(STAKE_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def set_words(self, members):
        items = [(addr_bytes(key), b"") for key in sorted(members)]
        root, height = self.build(SET_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def seen_words(self, seen):
        items = [(addr_bytes(key), value.to_bytes(8, "little")) for key, value in sorted(seen.items())]
        root, height = self.build(STAKE_LAYOUT, items)
        return struct.pack("<QQQ", root, height, len(items))

    def option_words(self, value, writer):
        if value is None:
            return struct.pack("<QQQQ", 0, 0, 0, 0)
        return struct.pack("<Q", 1) + writer(value)

    def write_key(self, key):
        stakes, jailed = key
        return self.option_words(None if stakes is None else dict(stakes), self.stake_words) + self.option_words(None if jailed is None else jailed, self.set_words)

    def write_prefill(self, case):
        memory = self.machine.memory
        rows = []
        for round in sorted(case.prefill):
            decided, slots = case.prefill[round]
            items = sorted((self.write_key(key), self.set_words(slots[key]) + struct.pack("<QQQ", 0, 0, 0)) for key in slots)
            root, height = self.build(SLOT_LAYOUT, items)
            value = bytearray(b"\x77" * 0x60)
            struct.pack_into("<Q", value, 0, 2)
            if decided is not None:
                value[:0x40] = self.write_key(decided)
            value[0x40:0x58] = struct.pack("<QQQ", root, height, len(items))
            value[0x58] = 0 if decided is None else 1
            rows.append((round.to_bytes(8, "little"), bytes(value)))
        root, height = self.build(ROUND_LAYOUT, rows)
        memory.put_bytes(STATE + 0x278, struct.pack("<II", 0 if case.floor is None else 1, 0) + struct.pack("<Q", case.floor or 0))
        memory.put_bytes(STATE + 0x288, b"\x00" * 0x18)
        memory.put_bytes(STATE + 0x2A0, struct.pack("<QQQ", root, height, len(rows)))

    def set_state(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(self.high - HEAP_BASE)
        self.bump = NODES
        self.trace = []
        self.randoms = list(case.randoms)
        self.case = case
        memory.put_bytes(STATE, STATE_FILL)

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0, 0)
        word(0x918, case.current)
        word(0x460, case.highest)
        memory.put_bytes(STATE + 0xAEC, addr_bytes(SELF))
        memory.put_bytes(STATE + 0xAC8, struct.pack("<iII", *case.now))
        memory.put_bytes(STATE + 0x4D0, struct.pack("<QQQ", 32, OUTBOX, 0))
        for offset, value in ((0x2B8, case.last_sent), (0x2C8, case.last_snap), (0x2D8, case.first)):
            word(offset, 0 if value is None else 1)
            word(offset + 8, value or 0)
        word(0x2E8, 2)
        self.write_prefill(case)
        table = []
        for start in sorted(case.stakes):
            table.append((start.to_bytes(8, "little"), self.stake_words(case.stakes[start])))
        root, height = self.build(TABLE_LAYOUT, table)
        memory.put_bytes(TABLE, b"\xab" * 0x60)
        memory.put_bytes(TABLE, struct.pack("<QQQ", case.base, root, height))
        table = []
        for start in sorted(case.jailed):
            table.append((start.to_bytes(8, "little"), self.set_words(case.jailed[start])))
        root, height = self.build(TABLE_LAYOUT, table)
        memory.put_bytes(TABLE + 0x20, struct.pack("<QQQ", case.base, root, height))
        memory.write(TABLE + 0x58, 8, case.valid_until)
        memory.write(TABLE + 0x60, 8, case.valid_until)
        memory.put_bytes(STATE + 0xA68, self.seen_words(case.seen_rounds))
        memory.put_bytes(STATE + 0xA80, struct.pack("<QQQ", 0, 0, 0))
        rows = []
        for round in sorted(case.buffered):
            at = self.alloc(0xB8 * max(len(case.buffered[round]), 1))
            for index, (evm, signer, lt) in enumerate(case.buffered[round]):
                self.write_row(at + 0xB8 * index, evm, signer, lt)
            rows.append((round.to_bytes(8, "little"), struct.pack("<QQQ", max(len(case.buffered[round]), 1), at, len(case.buffered[round]))))
        root, height = self.build(BUFFER_LAYOUT, rows)
        memory.put_bytes(STATE + 0xA98, struct.pack("<QQQ", root, height, len(rows)))
        rows = [(round.to_bytes(8, "little"), self.own_value(7, None)) for round in sorted(case.own)]
        root, height = self.build(OWN_LAYOUT, rows)
        for index, round in enumerate(sorted(case.own)):
            memory.write(RING + 8 * index, 8, round)
        memory.put_bytes(STATE + 0x858, struct.pack("<QQQQQQQQ", RING_CAP, RING, 0, len(rows), root, height, len(rows), case.limit))
        rows = []
        for round in sorted(case.sent):
            random, acks = case.sent[round]
            items = [(addr_bytes(signer), struct.pack("<iII", *when)) for signer, when in sorted(acks.items())]
            ack_root, ack_height = self.build(ACK_LAYOUT, items)
            rows.append((round.to_bytes(8, "little"), struct.pack("<QQQ", ack_root, ack_height, len(items)) + struct.pack("<I", random) + struct.pack("<iII", 1, 2, 3)))
        root, height = self.build(SENT_LAYOUT, rows)
        memory.put_bytes(STATE + 0x6F8 + 0x108, struct.pack("<QQQ", root, height, len(rows)))
        memory.write(ERROR_OBJECT, 8, ERROR_VTABLE)
        memory.write(ERROR_VTABLE, 8, self.error_mark)

    def own_value(self, evm, lt):
        body = bytes([0 if lt is None else lt]) * 0x90
        return struct.pack("<QQ", evm, 0 if lt is None else 1) + body

    def write_row(self, at, evm, signer, lt):
        memory = self.machine.memory
        memory.put_bytes(at, b"\xbd" * 0xB8)
        memory.write(at, 8, evm)
        memory.put_bytes(at + 8, addr_bytes(signer))
        memory.write(at + 0x20, 8, 0 if lt is None else 1)
        memory.put_bytes(at + 0x28, bytes([0 if lt is None else lt]) * 0x90)

    def write_event(self, step):
        memory = self.machine.memory
        memory.put_bytes(EVENT, b"\xc3" * EVENT_SIZE)
        if isinstance(step, Exec):
            memory.write(EVENT, 8, 0xB)
            at = EVENT + 8
            memory.put_bytes(at, b"\xc4" * 0x150)
            memory.write(at + 0x20, 8, 0 if step.lt is None else 1)
            memory.put_bytes(at + 0x28, bytes([0 if step.lt is None else step.lt]) * 0x90)
            memory.write(at + 0xF8, 8, step.round)
            memory.write(at + 0x148, 8, step.evm)
            return
        if isinstance(step, Ack):
            memory.write(EVENT, 8, 0xA)
            at = EVENT + 8
            memory.write(at, 8, step.round)
            memory.put_bytes(at + 8, addr_bytes(step.signer))
            memory.write(at + 0x1C, 4, step.random)
            memory.put_bytes(at + 0x20, signature_bytes(step.sig, ack_digest(step.signer, step.round, step.random), step.signer))
            return
        peers = step.peers
        memory.write(EVENT, 8, 0 if peers is None else 1)
        if peers is not None:
            memory.put_bytes(EVENT + 8, self.seen_words(peers))
        snap = step.snap
        if snap is None:
            memory.write(EVENT + 0x20, 8, 2)
        else:
            memory.put_bytes(EVENT + 0x20, self.write_key(snap.key()))
            memory.write(EVENT + 0x60, 8, 0 if snap.lt is None else 1)
            memory.put_bytes(EVENT + 0x68, bytes([0 if snap.lt is None else snap.lt]) * 0x90)
            memory.write(EVENT + 0xF8, 8, snap.evm)
        memory.write(EVENT + 0x100, 8, step.round)
        memory.put_bytes(EVENT + 0x108, addr_bytes(step.signer))
        memory.write(EVENT + 0x11C, 4, step.random)
        memory.put_bytes(EVENT + 0x120, signature_bytes(step.sig, beat_digest(step.signer, step.round, step.random), step.signer))

    def run_event(self, step):
        machine = self.machine
        memory = machine.memory
        self.write_event(step)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(TIME_IN, struct.pack("<iII", *self.case.now))
        machine.regs = [POISON] * 16
        machine.regs[RSP] = STACK_TOP - 0x100
        machine.regs[RDI] = HEAP_BASE + 0x2900
        machine.regs[RSI] = STATE
        machine.regs[RDX] = TIME_IN
        machine.regs[RCX] = EVENT
        machine.push(RETURN_SENTINEL)
        machine.stops = frozenset((STOP_TAIL, STOP_EXEC))
        machine.left = machine.step_limit
        machine.stopped = None
        machine.loop(DISPATCH)
        machine.stops = frozenset()
        if machine.stopped not in (STOP_TAIL, STOP_EXEC):
            raise Halt("event left the arm")

    def run(self, case):
        self.set_state(case)
        panicked = None
        try:
            for step in case.steps:
                self.run_event(step)
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

    def read_stakes(self, at):
        memory = self.machine.memory
        return tuple((int.from_bytes(key, "big"), memory.read(value, 8)) for key, value in self.map_at(at, STAKE_LAYOUT))

    def read_set(self, at):
        return tuple(int.from_bytes(key, "big") for key, _ in self.map_at(at, SET_LAYOUT))

    def read_key(self, at):
        memory = self.machine.memory
        return (self.read_stakes(at + 8) if memory.read(at, 8) & 1 else None, self.read_set(at + 0x28) if memory.read(at + 0x20, 8) & 1 else None)

    def tracker(self):
        memory = self.machine.memory
        out = {}
        for key, at in self.map_at(STATE + 0x2A0, ROUND_LAYOUT):
            slots = {}
            for name, slot in self.map_at(at + 0x40, SLOT_LAYOUT):
                slots[self.key_from_bytes(name)] = self.read_set(slot)
            decided = memory.read(at + 0x58, 1)
            outcome = self.read_key(at) if decided and memory.read(at, 4) != 2 else None
            out[int.from_bytes(key, "little")] = (decided, outcome, slots)
        return out

    def key_from_bytes(self, data):
        left = struct.unpack("<QQQQ", data[:32])
        right = struct.unpack("<QQQQ", data[32:64])
        memory = self.machine.memory
        stakes = None
        jailed = None
        if left[0] & 1:
            stakes = tuple((int.from_bytes(key, "big"), memory.read(value, 8)) for key, value in self.rows_of(left[1], left[2], STAKE_LAYOUT))
        if right[0] & 1:
            jailed = tuple(int.from_bytes(key, "big") for key, _ in self.rows_of(right[1], right[2], SET_LAYOUT))
        return (stakes, jailed)

    def outbox(self):
        memory = self.machine.memory
        rows = []
        for index in range(memory.read(STATE + 0x4E0, 8)):
            at = OUTBOX + 0x168 * index
            tag = memory.read(at, 8)
            if tag == 8:
                rows.append(("ack", memory.read(at + 8, 8), int.from_bytes(memory.bytes_at(at + 0x10, 20), "big"), memory.read(at + 0x24, 4), memory.bytes_at(at + 0x28, 0x41).hex(), int.from_bytes(memory.bytes_at(at + 0x70, 20), "big")))
                continue
            peers = None
            if tag & 1:
                peers = tuple((int.from_bytes(key, "big"), memory.read(value, 8)) for key, value in self.map_at(at + 8, STAKE_LAYOUT))
            snap = None
            if memory.read(at + 0x20, 8) != 2:
                lt_on = memory.read(at + 0x60, 8)
                snap = (self.read_key(at + 0x20), memory.read(at + 0x68, 1) if lt_on else None, memory.read(at + 0xF8, 8))
            rows.append(("beat", tag, peers, snap, memory.read(at + 0x100, 8), int.from_bytes(memory.bytes_at(at + 0x108, 20), "big"), memory.read(at + 0x11C, 4), memory.bytes_at(at + 0x120, 0x41).hex()))
        return rows

    def observe(self, panicked):
        memory = self.machine.memory

        def option(offset):
            return memory.read(STATE + offset + 8, 8) if memory.read(STATE + offset, 8) & 1 else None
        seen = {int.from_bytes(key, "big"): memory.read(at, 8) for key, at in self.map_at(STATE + 0xA68, STAKE_LAYOUT)}
        peers = {int.from_bytes(key, "big"): tuple((int.from_bytes(item, "big"), memory.read(value, 8)) for item, value in self.map_at(at, STAKE_LAYOUT)) for key, at in self.map_at(STATE + 0xA80, PEER_MAPS_LAYOUT)}
        buffered = {}
        for key, at in self.map_at(STATE + 0xA98, BUFFER_LAYOUT):
            rows, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8)
            buffered[int.from_bytes(key, "little")] = [(memory.read(rows + 0xB8 * index, 8), int.from_bytes(memory.bytes_at(rows + 0xB8 * index + 8, 20), "big"), memory.read(rows + 0xB8 * index + 0x28, 1) if memory.read(rows + 0xB8 * index + 0x20, 8) else None) for index in range(count)]
        own = {}
        for key, at in self.map_at(STATE + 0x878, OWN_LAYOUT):
            own[int.from_bytes(key, "little")] = (memory.read(at, 8), memory.read(at + 0x10, 1) if memory.read(at + 8, 8) else None)
        sent = {}
        for key, at in self.map_at(STATE + 0x6F8 + 0x108, SENT_LAYOUT):
            acks = {int.from_bytes(item, "big"): struct.unpack("<iII", memory.bytes_at(value, 12)) for item, value in self.map_at(at, ACK_LAYOUT)}
            sent[int.from_bytes(key, "little")] = (memory.read(at + 0x18, 4), struct.unpack("<iII", memory.bytes_at(at + 0x1C, 12)), acks)
        return dict(panic=panicked, trace=list(self.trace), first=option(0x2D8), last_sent=option(0x2B8), last_snap=option(0x2C8), floor=memory.read(STATE + 0x280, 8) if memory.read(STATE + 0x278, 4) == 1 else None, tracker=self.tracker(), seen=seen, peers=peers, buffered=buffered, own=own, sent=sent, outbox=self.outbox())


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
        self.trace = []
        self.first, self.last_sent, self.last_snap = case.first, case.last_sent, case.last_snap
        self.floor = case.floor
        self.tracker = {}
        for round, (decided, slots) in case.prefill.items():
            self.tracker[round] = [0 if decided is None else 1, decided, {key: tuple(sorted(value)) for key, value in slots.items()}]
        self.seen = dict(case.seen_rounds)
        self.peers = {}
        self.buffered = {round: list(rows) for round, rows in case.buffered.items()}
        self.own = {round: (7, None) for round in case.own}
        self.ring = sorted(case.own)
        self.sent = {round: (random, (1, 2, 3), dict(acks)) for round, (random, acks) in case.sent.items()}
        self.outbox = []
        self.randoms = list(case.randoms)
        self.label = "none"
        self.panicked = None

    def stake_at(self, round):
        return spec_table(self.case.stakes, self.case, round)

    def jailed_at(self, round):
        return spec_table(self.case.jailed, self.case, round)

    def high(self, round):
        if round > self.case.valid_until:
            self.trace.append(("log", "high round"))

    def high_jail(self, round):
        if round > self.case.valid_until:
            self.trace.append(("log", "high jail round"))

    def exec_event(self, step):
        case = self.case
        round = step.round
        if self.first is None:
            self.first = round
        if self.last_sent is not None and self.last_sent // BEAT_EVERY == round // BEAT_EVERY:
            self.label = "same ten block"
        else:
            self.send(step)
        self.own[round] = (step.evm, step.lt)
        if round not in self.ring:
            self.ring.append(round)
        while len(self.ring) > case.limit:
            self.own.pop(self.ring.pop(0), None)
        self.buffered.pop(round, None)
        for key in sorted(self.buffered):
            if key <= round:
                del self.buffered[key]

    def send(self, step):
        round = step.round
        self.high(round)
        stakes = self.stake_at(round)
        if stakes is None:
            self.trace.append(("error", 0x28))
            self.label = "no stake set"
            return
        if SELF not in stakes:
            self.label = "not in stake set"
            return
        if self.case.highest > min(round + QC_LAG, MAX_ROUND):
            self.trace.append(("log", "behind"))
            self.label = "execution behind qc"
            return
        self.last_sent = round
        due = self.last_snap is None or self.last_snap // SNAPSHOT_EVERY != round // SNAPSHOT_EVERY
        snap = None
        peers = None
        if due:
            self.high(round)
            self.high_jail(round)
            jailed = self.jailed_at(round)
            if jailed is None:
                self.trace.append(("error", 0x28))
            snap = ((tuple(sorted(stakes.items())), None if jailed is None else tuple(sorted(jailed))), step.lt, step.evm)
        random = self.randoms.pop(0)
        if due:
            peers = tuple(sorted(self.seen.items()))
        self.sent[round] = (random, self.case.wall, {})
        digest = beat_digest(SELF, round, random)
        self.outbox.append(("beat", 1 if due else 0, peers, snap, round, SELF, random, (digest + digest + b"\x1b").hex()))
        if due:
            self.last_snap = round
        self.label = "sent with snapshot" if due else "sent"

    def verify(self, signer, round, sig, digest):
        self.high(round)
        stakes = self.stake_at(round)
        if stakes is None:
            self.trace.append(("error", 0x28))
            return "no set"
        if signer not in stakes:
            self.trace.append(("error", 1))
            return "bad"
        sig = sig or Sig()
        if sig.broken or (sig.by is not None and sig.by != signer) or not sig.good:
            self.trace.append(("error", 1))
            return "bad"
        return None

    def beat_event(self, step):
        failed = self.verify(step.signer, step.round, step.sig, None)
        if failed:
            self.label = "beat refused: " + failed
            return
        signer, round = step.signer, step.round
        if step.peers is not None:
            self.peers[signer] = tuple(sorted(step.peers.items()))
        self.seen[signer] = max(self.seen.get(signer, 0), round)
        label = "beat no snapshot"
        snap = step.snap
        if snap is not None:
            label = self.snapshot(step)
        self.high(round)
        stakes = self.stake_at(round)
        if SELF not in stakes:
            self.label = label + ", no ack"
            return
        digest = ack_digest(SELF, round, step.random)
        self.outbox.append(("ack", round, SELF, step.random, (digest + digest + b"\x1b").hex(), signer))
        self.label = label + ", ack"

    def snapshot(self, step):
        signer, round, snap = step.signer, step.round, step.snap
        if round not in self.own:
            self.buffered.setdefault(round, []).append((snap.evm, signer, snap.lt))
        self.high_jail(self.case.current)
        now_jailed = self.jailed_at(self.case.current)
        if now_jailed is None:
            self.trace.append(("error", 0x28))
            return "jail set missing"
        if signer in now_jailed:
            return "jailed sender"
        self.high_jail(round)
        at_round = self.jailed_at(round)
        if at_round is None:
            self.trace.append(("error", 0x28))
        self.high(round)
        stakes = self.stake_at(round)
        cut = round - KEEP_ROUNDS if round >= KEEP_ROUNDS else None
        if self.floor is not None and round < self.floor:
            return "under floor"
        key = snap.key()
        row = self.tracker.setdefault(round, [0, None, {}])
        row[2].setdefault(key, ())
        slot = set(row[2][key])
        before = bool(row[0]) or spec_quorum(stakes, slot)
        slot.add(signer)
        row[2][key] = tuple(sorted(slot))
        if before or not spec_quorum(stakes, slot):
            return "counted"
        row[0], row[1] = 1, key
        if cut is not None:
            for other in sorted(self.tracker):
                if other < cut:
                    del self.tracker[other]
            self.floor = cut if self.floor is None or cut >= self.floor else self.floor
        return "decided"

    def ack_event(self, step):
        failed = self.verify(step.signer, step.round, step.sig, None)
        if failed:
            self.label = "ack refused: " + failed
            return
        row = self.sent.get(step.round)
        if row is None:
            self.label = "ack no row"
            return
        if row[0] != step.random:
            self.label = "ack other random"
            return
        row[2][step.signer] = self.case.wall
        self.label = "ack stored"


def spec_run(case):
    model = Model(case)
    panicked = None
    try:
        for step in case.steps:
            if isinstance(step, Exec):
                model.exec_event(step)
            elif isinstance(step, Ack):
                model.ack_event(step)
            else:
                model.beat_event(step)
    except SpecPanic:
        model.panicked = "panic"
        model.label = "stake overflow"
    return model.label, model


def spec_view(model):
    tracker = {round: (row[0], row[1], dict(row[2])) for round, row in model.tracker.items()}
    return dict(panic=model.panicked, trace=model.trace, first=model.first, last_sent=model.last_sent, last_snap=model.last_snap, floor=model.floor, tracker=tracker, seen=model.seen, peers=model.peers, buffered=model.buffered, own=model.own, sent=model.sent, outbox=model.outbox)


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


BIG = {1: 10, 2: 10, 3: 10, 4: 10}
FAR = 100000


def rows_of_keys(count, start):
    """Tracker prefill of `count` undecided rounds, each with no slot."""
    return {start + index: (None, {}) for index in range(count)}


def named_cases():
    snap = Snap(stakes=BIG, jailed=frozenset(), lt=9, evm=33)
    other = Snap(stakes={1: 10, 2: 10, 3: 10, 4: 11}, jailed=frozenset(), lt=9, evm=33)
    bare = Snap(evm=2)
    key = snap.key()
    rows = [
        Case("send first", [Exec(5000)]),
        Case("send keeps first", [Exec(5012)], first=4000, last_sent=4000, last_snap=4000),
        Case("send same ten low", [Exec(5001)], last_sent=5000, last_snap=5000),
        Case("send same ten high", [Exec(5009)], last_sent=5000, last_snap=5000),
        Case("send same round", [Exec(5000)], last_sent=5000, last_snap=5000),
        Case("send next ten", [Exec(5010)], last_sent=5009, last_snap=5000),
        Case("send older ten", [Exec(4990)], last_sent=5009, last_snap=4950),
        Case("send last zero", [Exec(9)], last_sent=0, last_snap=0, highest=0),
        Case("send high round log", [Exec(5000)], valid_until=4999),
        Case("send at table end no log", [Exec(5000)], valid_until=5000),
        Case("send no set", [Exec(5000)], stakes={FAR: {1: 1}}),
        Case("send no table", [Exec(5000)], stakes={}),
        Case("send not member", [Exec(5000)], stakes={0: {2: 1}}),
        Case("send member order high", [Exec(5000)], stakes={0: {1: 1, 0xFF: 2}}),
        Case("send member order low", [Exec(5000)], stakes={0: {0: 3, 1: 1}}),
        Case("send qc lag exact", [Exec(4000)], highest=5000),
        Case("send qc lag over", [Exec(3999)], highest=5000),
        Case("send qc lag behind ok", [Exec(4001)], highest=5000),
        Case("send qc lag saturates", [Exec(MAX_ROUND - 500)], highest=MAX_ROUND, base=0),
        Case("send qc lag sat edge", [Exec(MAX_ROUND - 999)], highest=MAX_ROUND, base=0),
        Case("send qc lag sat one under", [Exec(MAX_ROUND - 1000)], highest=MAX_ROUND, base=0),
        Case("send behind keeps last", [Exec(3990)], highest=5000, last_sent=3980, last_snap=3900),
        Case("send snapshot next hundred", [Exec(5100, lt=4, evm=12)], last_sent=5099, last_snap=5099, seen_rounds={2: 77, 3: 99}),
        Case("send snapshot same hundred", [Exec(5110, lt=4, evm=12)], last_sent=5099, last_snap=5100, seen_rounds={2: 77}),
        Case("send snapshot old hundred", [Exec(5110)], last_sent=4000, last_snap=4099),
        Case("send snapshot no lt", [Exec(5000, evm=12)]),
        Case("send snapshot jailed set", [Exec(5000, lt=3)], jailed={0: frozenset((3, 4))}),
        Case("send snapshot no jail table", [Exec(5000)], jailed={}),
        Case("send snapshot high round", [Exec(5000)], valid_until=4000),
        Case("send snapshot empty seen", [Exec(5000)]),
        Case("send replaces sent row", [Exec(5010)], sent={5010: (0x77, {2: (1, 1, 1)})}, last_sent=5000, last_snap=5000),
        Case("send two rows", [Exec(5000), Exec(5010), Exec(5020)]),
        Case("send and hundred in a row", [Exec(5090, lt=1), Exec(5100, lt=2), Exec(5110, lt=3), Exec(5200, lt=4)]),
        Case("tail own stored", [Exec(5001, lt=5, evm=6)], last_sent=5000, last_snap=5000),
        Case("tail own replace", [Exec(5001, lt=5, evm=6)], last_sent=5000, last_snap=5000, own=(5001,)),
        Case("tail own limit", [Exec(5001)], last_sent=5000, last_snap=5000, own=(4997, 4998, 4999), limit=3),
        Case("tail own limit one", [Exec(5001)], last_sent=5000, last_snap=5000, own=(4999,), limit=1),
        Case("tail own under limit", [Exec(5001)], last_sent=5000, last_snap=5000, own=(4999,), limit=2),
        Case("tail buffer exact", [Exec(5001)], last_sent=5000, last_snap=5000, buffered={5001: [(1, 2, None)]}),
        Case("tail buffer older", [Exec(5001)], last_sent=5000, last_snap=5000, buffered={4990: [(1, 2, 3)], 5000: [(1, 3, None)]}),
        Case("tail buffer newer stays", [Exec(5001)], last_sent=5000, last_snap=5000, buffered={4990: [(1, 2, 3)], 5002: [(1, 3, None)]}),
        Case("tail buffer many", [Exec(5001)], last_sent=5000, last_snap=5000, buffered={4000 + index: [(1, 2, None)] for index in range(14)}),
        Case("beat plain", [Beat(2, 5000)]),
        Case("beat random copied", [Beat(2, 5000, random=0xFFFFFFFF)]),
        Case("beat round high log", [Beat(2, 5000)], valid_until=4000),
        Case("beat with peers", [Beat(2, 5000, peers={3: 8})]),
        Case("beat peers replaced", [Beat(2, 5000, peers={3: 8}), Beat(2, 5001, peers={4: 9, 5: 1})]),
        Case("beat peers kept", [Beat(2, 5000, peers={3: 8}), Beat(2, 5001)]),
        Case("beat peers two signers", [Beat(2, 5000, peers={3: 8}), Beat(3, 5000, peers={})]),
        Case("beat seen raises", [Beat(2, 5000)], seen_rounds={2: 4000}),
        Case("beat seen stays", [Beat(2, 5000)], seen_rounds={2: 6000}),
        Case("beat self", [Beat(1, 5000)]),
        Case("beat unknown signer", [Beat(9, 5000)]),
        Case("beat broken sig", [Beat(2, 5000, sig=Sig(broken=True))]),
        Case("beat other signer", [Beat(2, 5000, sig=Sig(by=3))]),
        Case("beat wrong digest", [Beat(2, 5000, sig=Sig(good=False))]),
        Case("beat no set", [Beat(2, 5000)], stakes={FAR: {2: 1}}),
        Case("beat no table", [Beat(2, 5000)], stakes={}),
        Case("beat refused keeps maps", [Beat(2, 5000, peers={3: 1}, sig=Sig(by=3))], seen_rounds={2: 1}),
        Case("beat no ack when not member", [Beat(2, 5000)], stakes={0: {2: 1, 3: 1}}),
        Case("beat snapshot one", [Beat(2, 5000, snap=snap)]),
        Case("beat snapshot buffered", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=snap)]),
        Case("beat snapshot own known", [Beat(2, 5000, snap=snap)], own=(5000,)),
        Case("beat snapshot jailed now", [Beat(2, 5000, snap=snap)], jailed={0: frozenset((2,))}),
        Case("beat snapshot jailed now unsorted", [Beat(2, 5000, snap=snap)], jailed={0: frozenset((1, 3))}),
        Case("beat snapshot jail table missing", [Beat(2, 5000, snap=snap)], jailed={}),
        Case("beat snapshot jail by round", [Beat(2, 4000, snap=snap)], jailed={0: frozenset(), 4500: frozenset((2,))}, current=5000),
        Case("beat snapshot jail set new at round", [Beat(2, 6000, snap=snap)], jailed={4900: frozenset()}, current=5000),
        Case("beat snapshot quorum", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=snap), Beat(4, 5000, snap=snap)]),
        Case("beat snapshot exactly two thirds", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=snap)], stakes={0: {1: 10, 2: 10, 3: 10}}),
        Case("beat snapshot over two thirds", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=snap)], stakes={0: {1: 9, 2: 10, 3: 10}}),
        Case("beat snapshot repeat signer", [Beat(2, 5000, snap=snap), Beat(2, 5000, snap=snap), Beat(2, 5000, snap=snap)]),
        Case("beat snapshot two keys no add", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=other), Beat(4, 5000, snap=snap)]),
        Case("beat snapshot key differs from table", [Beat(2, 5000, snap=other), Beat(3, 5000, snap=other), Beat(4, 5000, snap=other)]),
        Case("beat snapshot bare key", [Beat(2, 5000, snap=bare), Beat(3, 5000, snap=bare), Beat(4, 5000, snap=bare)]),
        Case("beat snapshot lt not in key", [Beat(2, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), lt=1, evm=1)), Beat(3, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), lt=2, evm=2)), Beat(4, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), evm=3))]),
        Case("beat snapshot jail key", [Beat(2, 5000, snap=Snap(stakes=BIG, jailed=frozenset((7,)))), Beat(3, 5000, snap=Snap(stakes=BIG, jailed=frozenset((8,)))), Beat(4, 5000, snap=Snap(stakes=BIG, jailed=frozenset((7,))))]),
        Case("beat snapshot one option", [Beat(2, 5000, snap=Snap(stakes=BIG)), Beat(3, 5000, snap=Snap(jailed=frozenset()))]),
        Case("beat snapshot after decided", [Beat(2, 5000, snap=snap), Beat(3, 5000, snap=snap), Beat(4, 5000, snap=snap), Beat(1, 5000, snap=snap)]),
        Case("beat snapshot decided row prefill", [Beat(2, 5000, snap=other)], prefill={5000: (key, {key: (3, 4)})}),
        Case("beat snapshot slot held quorum", [Beat(2, 5000, snap=snap), Beat(1, 5000, snap=snap)], prefill={5000: (None, {key: (3, 4, 9)})}, stakes={0: {1: 1, 2: 1, 3: 10, 4: 10}}),
        Case("beat snapshot under floor", [Beat(2, 5000, snap=snap)], floor=5001),
        Case("beat snapshot at floor", [Beat(2, 5000, snap=snap)], floor=5000),
        Case("beat snapshot prune", [Beat(4, 5000, snap=snap)], prefill={3999: (None, {}), 4000: (None, {}), 4001: (None, {}), 5000: (None, {key: (2, 3)})}),
        Case("beat snapshot prune floor kept", [Beat(4, 5000, snap=snap)], prefill={5000: (None, {key: (2, 3)})}, floor=4500),
        Case("beat snapshot prune floor moves", [Beat(4, 5000, snap=snap)], prefill={5000: (None, {key: (2, 3)})}, floor=3000),
        Case("beat snapshot under 1000 no prune", [Beat(4, 999, snap=snap)], prefill={1: (None, {}), 999: (None, {key: (2, 3)})}, current=1000, highest=1000),
        Case("beat snapshot at 1000 prune zero", [Beat(4, 1000, snap=snap)], prefill={0: (None, {}), 1000: (None, {key: (2, 3)})}, current=1000, highest=1000),
        Case("beat snapshot not counted row no prune", [Beat(2, 5000, snap=snap)], prefill={1: (None, {})}),
        Case("beat snapshot key list row count", [Beat(2, 5000, snap=snap)], prefill=rows_of_keys(101, 4800)),
        Case("beat snapshot key list under", [Beat(2, 5000, snap=snap)], prefill=rows_of_keys(99, 4800)),
        Case("beat snapshot stake overflow", [Beat(2, 5000, snap=snap)], stakes={0: {1: 1, 2: MAX_ROUND}}),
        Case("beat snapshot then no ack", [Beat(2, 5000, snap=snap)], stakes={0: {2: 1, 3: 1}}),
        Case("beat own then exec drops row", [Beat(2, 5001, snap=snap), Exec(5001)], last_sent=5000, last_snap=5000),
        Case("ack match", [Ack(2, 5000)], sent={5000: (0x51, {})}),
        Case("ack other random", [Ack(2, 5000, random=0x52)], sent={5000: (0x51, {})}),
        Case("ack no row", [Ack(2, 5000)]),
        Case("ack other round", [Ack(2, 5001)], sent={5000: (0x51, {})}),
        Case("ack row second of many", [Ack(2, 5005)], sent={5000 + index: (0x51, {}) for index in range(14)}),
        Case("ack replaces", [Ack(2, 5000)], sent={5000: (0x51, {2: (1, 2, 3)})}),
        Case("ack adds", [Ack(2, 5000), Ack(3, 5000), Ack(4, 5000)], sent={5000: (0x51, {})}),
        Case("ack many", [Ack(2, 5000)], sent={5000: (0x51, {index: (1, 2, 3) for index in range(3, 9)})}),
        Case("ack twelfth grows", [Ack(2, 5000)], sent={5000: (0x51, {index: (1, 2, 3) for index in range(3, 13)})}),
        Case("ack leaf full", [Ack(2, 5000)], sent={5000: (0x51, {index: (1, 2, 3) for index in range(3, 14)})}),
        Case("ack unknown signer", [Ack(9, 5000)], sent={5000: (0x51, {})}),
        Case("ack broken", [Ack(2, 5000, sig=Sig(broken=True))], sent={5000: (0x51, {})}),
        Case("ack other signer", [Ack(2, 5000, sig=Sig(by=3))], sent={5000: (0x51, {})}),
        Case("ack wrong digest", [Ack(2, 5000, sig=Sig(good=False))], sent={5000: (0x51, {})}),
        Case("ack no set", [Ack(2, 5000)], sent={5000: (0x51, {})}, stakes={FAR: {2: 1}}),
        Case("ack high round log", [Ack(2, 5000)], sent={5000: (0x51, {})}, valid_until=10),
        Case("ack from send", [Exec(5000), Ack(2, 5000, random=0xABC0)]),
        Case("ack from send other random", [Exec(5000), Ack(2, 5000, random=0xABC1)]),
    ]
    return rows


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MAX_ROUND
        yield state >> 33


def vector_cases(count):
    cases = []
    rng = lcg(0x8EA7)
    snaps = (Snap(stakes=BIG, jailed=frozenset(), lt=5, evm=1), Snap(stakes=BIG, jailed=frozenset((3,)), evm=2), Snap(), Snap(stakes={1: 1}, lt=1))
    for index in range(count):
        steps = []
        for _ in range(2 + next(rng) % 6):
            round = 4950 + next(rng) % 260
            kind = next(rng) % 5
            signer = 1 + next(rng) % 5
            if kind == 0:
                steps.append(Exec(round, lt=None if next(rng) % 2 else 1 + next(rng) % 9, evm=next(rng) % 100))
            elif kind == 1:
                steps.append(Ack(signer, round, random=0x51 + next(rng) % 2, sig=None if next(rng) % 4 else Sig(by=2)))
            else:
                steps.append(Beat(signer, round, random=0x51 + next(rng) % 2, peers=None if next(rng) % 2 else {2 + next(rng) % 4: round}, snap=None if next(rng) % 3 == 0 else snaps[next(rng) % 4], sig=None if next(rng) % 6 else Sig(broken=True)))
        extra = dict(sent={4990 + 10 * item: (0x51, {}) for item in range(next(rng) % 4)}, seen_rounds={2: next(rng) % 6000} if next(rng) % 2 else {}, jailed={0: frozenset((3,))} if next(rng) % 3 == 0 else {0: frozenset()},
                     last_sent=None if next(rng) % 3 == 0 else 4990 + next(rng) % 40, last_snap=None if next(rng) % 3 == 0 else 4990 + next(rng) % 40, highest=5000 + next(rng) % 2000, randoms=tuple(0xABC0 + item for item in range(12)))
        cases.append(Case("vector %d" % index, steps, **extra))
    return cases


PINS = (('send', 0X44AE4F1, '48b9cdcccccccccccccc', 'movabs reciprocal of 10'),
        ('send', 0X44AE50E, '48c1ef03', 'shift of the first quotient'),
        ('send', 0X44AE516, '4839d7', 'ten block compare'),
        ('send', 0X44AE519, '0f84a7220000', 'same ten block leaves'),
        ('send', 0X44AECE3, '4981fc18fcffff', 'saturation guard of round + 1000'),
        ('send', 0X44AECF8, '4881c1e8030000', 'round + 1000'),
        ('send', 0X44AF1AC, '498d8424e8030000', 'round + 1000, plain arm'),
        ('send', 0X44AF1BE, '48398560040000', 'highest QC against the limit'),
        ('send', 0X44AF1C5, '0f869e000000', 'sends when QC is at or under the limit'),
        ('send', 0X44AF240, '488d358ce4d3fb', 'not sending text'),
        ('send', 0X44AF269, '48c785b802000001000000', 'last sent tag'),
        ('send', 0X44AF274, '4c89a5c0020000', 'last sent round'),
        ('send', 0X44AF27B, '80bdc802000000', 'last snapshot tag'),
        ('send', 0X44AF293, '48bec3f5285c8fc2f528', 'reciprocal of 25 after shift 2: divide by 100'),
        ('send', 0X44AF2C9, '4839d1', 'hundred block compare'),
        ('send', 0X44AF2D2, '48c784242006000002000000', 'tag 2: no snapshot'),
        ('send', 0X44B0639, 'e8520b5600', 'random id'),
        ('send', 0X44B0659, 'e8c2484f00', 'clone of the seen map'),
        ('send', 0X44B06F4, '899c249c030000', 'random id at +0x11c'),
        ('send', 0X44B070F, 'e89cda2900', 'sent row'),
        ('send', 0X44B0744, 'e877a70900', 'sign'),
        ('send', 0X44B07B4, '48c785c802000001000000', 'last snapshot tag set'),
        ('send', 0X44B07BF, '4c89a5d0020000', 'last snapshot round set'),
        ('tail', 0X44B0874, 'e8375beaff', 'own round insert'),
        ('tail', 0X44B0893, 'e898254900', 'buffer take of this round'),
        ('tail', 0X44B098C, '483b842410040000', 'first buffer key against round'),
        ('tail', 0X44B0994, '7759', 'stop at a newer key'),
        ('tail', 0X44B099C, 'e88f694900', 'buffer pop'),
        ('tail', 0X44A9B19, '49c78690080000a0860100', 'constructor: own ring limit 100000'),
        ('receive', 0X44AF790, 'e8dbc50900', 'verify'),
        ('receive', 0X44AF805, '41f6c601', 'peer map tag'),
        ('receive', 0X44AF849, 'e8f2e34700', 'peer map insert'),
        ('receive', 0X44AF8B1, '4939cd', 'max with the stored round'),
        ('receive', 0X44AF8B4, '490f47cd', 'max with the stored round'),
        ('receive', 0X44AF8C8, '4883f902', 'no snapshot tag'),
        ('receive', 0X44AF939, 'e85265eaff', 'own round find'),
        ('receive', 0X44AF941, '0f85c1000000', 'known round skips the buffer'),
        ('receive', 0X44AF95E, 'e86d884700', 'buffer entry'),
        ('receive', 0X44AF9C4, '4969cfb8000000', 'row stride 0xb8'),
        ('receive', 0X44AFA1F, 'e83c1c6800', 'jail row of the current round'),
        ('receive', 0X44AFA4F, 'e88c7d4700', 'member of it'),
        ('receive', 0X44AFA5B, '0f85b8260000', 'jailed sender skips'),
        ('receive', 0X44AFA6F, 'e8ec1b6800', 'jail row of the heartbeat round'),
        ('receive', 0X44AFAB6, 'ff152c6f2c01', 'stake set'),
        ('receive', 0X44AFAEE, 'e87d594f00', 'stake compare'),
        ('receive', 0X44AFB09, '7412', 'second compare guard'),
        ('receive', 0X44AFB18, 'e8d35d4f00', 'jail compare, answer dropped'),
        ('receive', 0X44AFB2B, '4981fde8030000', 'cut flag'),
        ('receive', 0X44AFB35, '4d8d8518fcffff', 'cut'),
        ('receive', 0X44AFB98, 'e863e2eaff', 'tracker'),
        ('receive', 0X44B21B0, 'ff153a482c01', 'member test of this node'),
        ('receive', 0X44B21E8, '4c89ac24a0000000', 'ack round'),
        ('receive', 0X44B220A, 'e8f1900900', 'sign ack'),
        ('receive', 0X44B22A3, '48c78424a000000008000000', 'outbox tag 8'),
        ('verify', 0X454BE4E, '48c744243003000000', 'heartbeat digest variant 3'),
        ('verify', 0X454BF6E, 'ff15e43e2201', 'recover'),
        ('verify', 0X454C048, '4983c602', 'ok tag'),
        ('verify', 0X454AED6, '48c744245003000000', 'signing digest variant 3'),
        ('verify', 0X454B319, '48c7042404000000', 'ack digest variant 4'),
        ('verify', 0X4B31676, '483b5660', 'jail row high round compare'),
        ('verify', 0X4B3171F, '4983c702', 'ok tag of the jail row'),
        ('tracker', 0X435DE20, '833e01', 'floor tag'),
        ('tracker', 0X435DE25, '493b542408', 'round against floor'),
        ('tracker', 0X435DF1A, '837c241002', 'answer tag 2 is none'),
        ('tracker', 0X435DF25, '7460', 'prune only with an answer and the flag'),
        ('tracker', 0X435DF3A, 'e8f16a5600', 'prune'),
        ('tracker', 0X435DF71, '4c0f45f9', 'floor keeps a higher value'),
        ('tracker', 0X48C7613, '41807c245800', 'decided byte'),
        ('tracker', 0X48C7626, 'e855c9ffff', 'quorum before'),
        ('tracker', 0X48C790B, 'e870c6ffff', 'quorum after'),
        ('tracker', 0X48C7918, '41c644245801', 'decided byte set'),
        ('tracker', 0X48C7E7E, '4883f865', 'over 100 rows'),
        ('tracker', 0X48C7EED, '48c784247802000064000000', '100 keys'),
        ('ack', 0X44B006D, 'e8def92900', 'ack matcher'),
        ('ack', 0X474FA79, 'e8b2b9dfff', 'verify ack'),
        ('ack', 0X474FB51, '413b4e18', 'random id compare'),
        ('ack', 0X474FB5F, 'ff153bed0101', 'wall clock'),
        ('ack', 0X474FB73, 'e848001f00', 'ack row'),
        ('ack', 0X474E1BB, '4c8bb600010000', 'round at +0x100'),
        ('ack', 0X474E1C2, '8bae1c010000', 'random at +0x11c'),
        ('ack', 0X474E1E8, '4881c308010000', 'sent map at tracker+0x108'),)
OUTER_TABLE = 0x6F2A34
INNER_TABLE = 0x6F2A50
DISPATCH_TAGS = ((0x0, 0x44AF6A4, "Heartbeat, no peer round map (first word is the Option tag of the map)"), (0x1, 0x44AF6A4, "Heartbeat, with peer round map"), (0x9, 0x44AF6A4, "same table row as tags 0 and 1, the niche slot of the Heartbeat variant, no sender seen"), (0xA, 0x44AFFED, "HeartbeatAck"), (0xB, 0x44AE470, "execution state event, the only source of Heartbeat"))
SLOTS = ((SLOT_STAKE, 0x4B31D40, "stake set for a round, Result form"), (SLOT_MEMBER, 0x4AD9850, "is this address in a stake set"), (SLOT_QUORUM, 0x4AD90D0, "quorum, called at 0x48c3ff2"), (SLOT_MONOTONIC, 0x14385C0, "lazy read of a process clock, its answer is not used at 0x44afbc3"), (SLOT_WALL, 0x151CBA0, "wall clock now, called at 0x474e1cd and 0x474fb5f"), (SLOT_TABLE_UPDATE, 0x4B31A70, "stake table update from the execution event, not run"))
GATES = (
    ("send", 1, 0x44AE4D4, "state+0x2d8 empty: store this execution round as the first one", "keep it", None),
    ("send", 2, 0x44AE519, "last sent round / 10 equals this round / 10: no heartbeat", "go on; no last round also goes on", "same ten block"),
    ("send", 3, 0x44AE52E, "round over table+0x58: warning only, goes on", "no log", None),
    ("send", 4, 0x44AE5F1, "no stake set for the execution round: error dropped, no heartbeat", "go on", "no stake set"),
    ("send", 5, 0x44AE647, "this node (state+0xaec) not in that set: no heartbeat, nothing logged", "go on", "not in stake set"),
    ("send", 6, 0x44AF1C5, "highest QC round over round + 1000, saturating: log and no heartbeat, last sent round left as it was", "go on; a lag of exactly 1000 sends", "execution behind qc"),
    ("send", 7, 0x44AF269, "last sent round becomes this round, before the snapshot choice", "-", None),
    ("send", 8, 0x44AF2CC, "last snapshot round / 100 differs from round / 100, or none yet: this heartbeat has a snapshot", "no snapshot, tag 2 at +0x20", "sent with snapshot"),
    ("send", 9, 0x44B00D1, "snapshot stakes: the set at the execution round", "None in the snapshot", None),
    ("send", 10, 0x44B0519, "snapshot jailed set: the row at the execution round; a miss drops the error and leaves None", "Some", None),
    ("send", 11, 0x44B0643, "peer round map: a clone of state+0xa68, only with a snapshot", "None, tag 0", None),
    ("send", 12, 0x44B070F, "0x474e1b0: row round -> random id, wall clock, empty ack map; a row at the same round is replaced", "-", None),
    ("send", 13, 0x44B0744, "0x454aec0 signs digest variant 3; outbox row whose first word is the Option tag", "-", "sent"),
    ("send", 14, 0x44B07B4, "last snapshot round written only here, after the send", "-", None),
    ("tail", 1, 0x44B0874, "every execution event, sent or not: round -> (evm block, lt block) stored by 0x43563b0, ring keeps at most state+0x890 (100000 from the constructor)", "-", None),
    ("tail", 2, 0x44B0893, "buffer row of exactly this round is taken and freed unread", "-", None),
    ("tail", 3, 0x44B0994, "buffer rows at or under this round are popped and freed unread", "-", None),
    ("receive", 1, 0x454BE27, "no stake set for heartbeat round: error tag 0x28", "go on", "beat refused: no set"),
    ("receive", 2, 0x454BF95, "signer not in the set: error tag 1 with no recovery", "go on", "beat refused: bad"),
    ("receive", 3, 0x454BFE3, "recovered address over digest variant 3 equals the claimed signer", "error tag 1", None),
    ("receive", 4, 0x44AF809, "peer map present: stored at state+0xa80 under the signer, replacing the last one; absent keeps it", "-", None),
    ("receive", 5, 0x44AF8B4, "state+0xa68 seen map keeps max(old, heartbeat round), the map the vote arm writes too", "-", None),
    ("receive", 6, 0x44AF8CF, "no snapshot: go to the ack", "snapshot steps", "beat no snapshot, ack"),
    ("receive", 7, 0x44AF941, "heartbeat round absent from state+0x858: (evm block, signer, lt block) pushed on the buffer row of that round", "nothing, the stored value is not compared", None),
    ("receive", 8, 0x44AFA36, "no jail row for the current round: error dropped, skip the tracker, ack stays", "go on", "jail set missing, ack"),
    ("receive", 9, 0x44AFA5B, "signer jailed at the current round (state+0x918, not the heartbeat round): skip the tracker, ack stays", "go on", "jailed sender, ack"),
    ("receive", 10, 0x44AFA99, "no jail row for the heartbeat round: error dropped, the tracker still runs", "go on", None),
    ("receive", 11, 0x44AFAD9, "no stake set for the heartbeat round: error dropped and no ack; the verifier has just read the same set", "go on", None),
    ("receive", 12, 0x44AFB09, "snapshot compared with the local stake set and jailed set: both answers are dropped, no gate at all", "-", None),
    ("receive", 13, 0x44AFB32, "cut flag is round >= 1000, cut is round - 1000", "no prune", None),
    ("receive", 14, 0x44B21B8, "ack only if this node is in the stake set of the heartbeat round", "no ack", "beat no snapshot, no ack"),
    ("receive", 15, 0x44B22A3, "outbox row tag 8: ack at +8, sender of the heartbeat at +0x70", "-", "beat no snapshot, ack"),
    ("tracker", 1, 0x435DE2A, "floor set and round under floor: nothing stored", "go on", "under floor, ack"),
    ("tracker", 2, 0x48C6DFC, "signer in the stake set passed in", "no row", None),
    ("tracker", 3, 0x48C7619, "before: decided byte row+0x58, or the slot's quorum read", "-", None),
    ("tracker", 4, 0x48C7853, "before true: voter added, no second read", "after read", "counted, ack"),
    ("tracker", 5, 0x48C7912, "after false: stop", "row+0x58 set, key stored at the row head", "decided, ack"),
    ("tracker", 6, 0x435DF25, "a decision and cut flag: rows under cut removed by 0x48c4a30", "no prune", None),
    ("tracker", 7, 0x435DF71, "floor stays if set and over the cut, else becomes the cut", "-", None),
    ("tracker", 8, 0x48C7E82, "over 100 rows: a list of 100 keys is built and freed unread", "no list", None),
    ("ack", 1, 0x474FA83, "0x454b430 verdict: same rules as heartbeat over digest variant 4, tags 0x28 and 1, dropped at 0x44b008a", "go on", "ack refused: bad"),
    ("ack", 2, 0x474FB17, "no row for this round: nothing", "go on", "ack no row"),
    ("ack", 3, 0x474FB55, "random id differs from row+0x18: nothing", "go on", "ack other random"),
    ("ack", 4, 0x474FB73, "ack map row: signer -> wall clock now, a repeat replaces", "-", "ack stored"),
)
TAGS = ((0x01, 0x454C02C, "heartbeat signature: unknown signer, recover failed, or other address"), (0x28, 0x454BF52, "no stake set for the heartbeat round"), (0x2A, 0x454C048, "heartbeat verified"))
LAYOUT = (('heartbeat', 0X0, 0X20, 'Option tag then peer round map: validator to last message round', 0X44AF805),
          ('heartbeat', 0X20, 0XE0, 'Option snapshot; tag 2 at +0x20 means none', 0X44AF8C8),
          ('heartbeat', 0X20, 0X20, 'snapshot stakes, Option map', 0X44AFAE6),
          ('heartbeat', 0X40, 0X20, 'snapshot jailed set, Option set', 0X44AFB0B),
          ('heartbeat', 0X60, 0X98, 'Option 0x90 byte concise lt hash block, from the execution event +0x20', 0X44B0598),
          ('heartbeat', 0XF8, 0X8, 'evm block number, from the execution event +0x148', 0X44B0586),
          ('heartbeat', 0X100, 0X8, 'round: the execution round, not the consensus round', 0X454BD8A),
          ('heartbeat', 0X108, 0X14, 'validator', 0X454BE6B),
          ('heartbeat', 0X11C, 0X4, 'random id', 0X474E1C2),
          ('heartbeat', 0X120, 0X41, 'signature, recovered over digest variant 3', 0X454BE85),
          ('ack', 0X0, 0X8, 'round', 0X454B44A),
          ('ack', 0X8, 0X14, 'validator', 0X474FA89),
          ('ack', 0X1C, 0X4, 'random id', 0X474FAAA),
          ('ack', 0X20, 0X41, 'signature over digest variant 4', 0X454B37B),
          ('outbox ack row', 0X0, 0X8, 'tag 8', 0X44B22A3),
          ('outbox ack row', 0X70, 0X14, 'sender of the heartbeat', 0X44B228C),
          ('sent row', 0X0, 0X18, 'ack map signer to wall clock', 0X474FB6D),
          ('sent row', 0X18, 0X4, 'random id', 0X474FB51),
          ('sent row', 0X1C, 0XC, 'wall clock at send', 0X474E1CD),
          ('buffer row', 0X0, 0X8, 'evm block number', 0X44AF9CB),
          ('buffer row', 0X8, 0X14, 'signer', 0X44AF9D8),
          ('buffer row', 0X20, 0X98, 'Option lt block', 0X44AF9FB),
          ('own row', 0X0, 0X8, 'evm block number', 0X44B082F),
          ('own row', 0X8, 0X98, 'Option lt block', 0X44B0837),
          ('tracker row', 0X0, 0X40, 'decided key, tag 2 when none', 0X48C7AD5),
          ('tracker row', 0X40, 0X18, 'key to voter sets', 0X48C70ED),
          ('tracker row', 0X58, 0X1, 'decided byte', 0X48C7613),
          ('state', 0X278, 0X10, 'tracker floor', 0X435DE20),
          ('state', 0X2A0, 0X18, 'tracker round map', 0X48C6E38),
          ('state', 0X2B8, 0X10, 'last sent round', 0X44AF269),
          ('state', 0X2C8, 0X10, 'last snapshot round', 0X44AF27B),
          ('state', 0X2D8, 0X10, 'first execution round', 0X44AE4D6),
          ('state', 0X6F8, 0X160, 'heartbeat tracker; sent map at +0x108', 0X474E1E8),
          ('state', 0XA68, 0X18, 'seen map, signer to highest round', 0X44AF87D),
          ('state', 0XA80, 0X18, 'peer round maps by signer', 0X44AF80B),
          ('state', 0XA98, 0X18, 'snapshot buffer by round', 0X44AF947),
          ('state', 0X858, 0X40, 'own execution rounds, ring and map', 0X44AF925),)
STRINGS = ((0X1ED6D4, 'Not sending heartbeat because execution round is far behind qc'), (0X6F4F46, 'validator_to_last_msg_round'), (0X6F4F61, 'random_id'), (0X3E5F13, 'HeartbeatSnapshot'), (0X6F4C02, 'validator_set_snapshot'), (0X6FBD97, 'concise_lt_hashes'), (0X3E5EE6, 'core::option::Option<node::consensus::types::HeartbeatSnapshot>'),)
LOCATIONS = ((0x44AF247, 0x5720030, "not sending heartbeat log"), (0x44B0862, 0x5720048, "execution round map insert"), (0x4B316D4, 0x5738650, "jail table high round log"))
TRIGGERS = ((VERIFY_BEAT, 0x44AF790, "receive arm"), (TRACK, 0x44AFB98, "receive arm"), (TRACK_CORE, 0x435DF15, "tracker front"), (SIGN_ACK, 0x44B220A, "receive arm"), (NOTE_ACK, 0x44B006D, "ack arm"), (NOTE_SENT, 0x44B070F, "send body"), (SIGN_BEAT, 0x44B0744, "send body"),
            (VERIFY_ACK, 0x474FA79, "ack matcher"), (ACK_ROW, 0x474FB73, "ack matcher"), (SEEN_MAPS, 0x44AF849, "receive arm"), (RANDOM, 0x44B0639, "send body"),
            (JAILED_AT, 0x44AF079, "arm 0xf, not in this packet"), (JAILED_AT, 0x44AFA1F, "receive arm, current round"), (JAILED_AT, 0x44AFA6F, "receive arm, heartbeat round"), (JAILED_AT, 0x44B050C, "send body"))
SUBJECTS = (VERIFY_BEAT, VERIFY_ACK, SIGN_BEAT, SIGN_ACK, NOTE_SENT, NOTE_ACK, ACK_ROW, TRACK, TRACK_CORE, SLOT_QUORUM_CHECK, JAILED_AT, EXEC_MAP_INSERT)
ARMS = ((0x44AE470, 0x44AE705), (0x44AECAD, 0x44AED0F), (0x44AF1AC, 0x44AF2E5), (0x44AF6A4, 0x44AFBCE), (0x44AFFED, 0x44B00F7), (0x44B0285, 0x44B0356), (0x44B04DF, 0x44B0A4D), (0x44B0AEA, 0x44B0B1F), (0x44B2108, 0x44B2313), (0x44B2444, 0x44B24BA))
ROLES = {VERIFY_BEAT: "heartbeat check", VERIFY_ACK: "ack check", SIGN_BEAT: "signs digest variant 3", SIGN_ACK: "signs digest variant 4", NOTE_SENT: "sent row", NOTE_ACK: "ack match", ACK_ROW: "ack map row", TRACK: "tracker front: floor, cut", TRACK_CORE: "round row, key slot, decision", SLOT_QUORUM_CHECK: "quorum of one key slot", JAILED_AT: "jail row of a round", EXEC_MAP_INSERT: "own execution round map"}
STUBS = {DIGEST: "signing digest: SHA-256 of named fixture fields per variant, real digest bytes are not modelled here", SIGN_HASH: "secp256k1 sign: fixture value from the digest, key argument checked", RANDOM: "random id: next fixture value, in case order", NOW_INSTANT: "event start instant", DROP_ERROR: "error drop, the tag is recorded", DROP_VALUE: "error value drop", SLOW_UPDATE: "state[0] == 1 branch of the execution tail, not taken in fixtures", DROP_EXEC: "drop of the stored execution event",
         0x49478B0: "tree drain", 0x48FF470: "drop", 0x49B91C0: "drop", 0x49B05E0: "drop", 0x49B5080: "drop", 0x49A9C60: "drop", 0x4907CE0: "drop", 0x447C050: "drop of the tracker answer", 0x49A90C0: "drop", 0x4874570: "the 100 key list, returns an empty list"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_MEMMOVE: "memmove", SLOT_ALLOC: "fixture bump allocator", SLOT_ALLOC_ERROR: "panic", SLOT_DEALLOC: "dealloc, no effect", SLOT_LOG: "warning log, text address recorded", SLOT_FORMAT: "format, empty string", SLOT_RECOVER: "recovery of the fixture signature", SLOT_BTREE_PANIC: "panic", SLOT_ASSERT: "panic", SLOT_PANIC_FMT: "panic", SLOT_PANIC_ADD: "panic", SLOT_MONOTONIC: "no effect", SLOT_RECORD: "event record, no effect", SLOT_GROW_OUT: "panic, fixture outbox is large enough", SLOT_GROW_ROWS: "vector growth", SLOT_GROW_RING: "panic, fixture ring is large enough", SLOT_WALL: "fixture wall clock", SLOT_TABLE_UPDATE: "address check only"}
HELPERS = {0x4B31D40: "stake set, Result form", 0x42C9930: "stake row lookup", JAILED_FIND: "jail row lookup", QUORUM: "quorum", 0x4AD9850: "stake member", SEEN_MAPS: "peer map insert", OWN_FIND: "own round find", BUFFER_ENTRY: "buffer entry", BUFFER_TAKE: "buffer remove", BUFFER_FIRST: "buffer pop first", SAME_STAKES: "stake map equality", SAME_JAILED: "set equality", JAILED_MEMBER: "set member", 0x48C4A30: "prune under cut", 0x4880130: "free pruned rows", 0x42B8500: "key slot entry"}
FIELDS = ((0x858, "own execution rounds ring"), (0x878, "own execution rounds map root"), (0x890, "own ring limit"), (0xA80, "peer round maps root"), (0xA98, "snapshot buffer root"), (0xAA0, "snapshot buffer height"))
MUTANT_CAP = 12
VECTORS = 300
BOUNDARY = frozenset(("send same ten high", "send next ten", "send qc lag exact", "send qc lag over", "send snapshot next hundred", "send snapshot same hundred", "beat snapshot exactly two thirds", "beat snapshot over two thirds", "beat snapshot under floor", "beat snapshot at floor", "beat snapshot at 1000 prune zero", "beat snapshot under 1000 no prune", "beat snapshot key list row count", "beat snapshot prune floor kept", "beat snapshot prune floor moves", "tail own limit", "tail own under limit"))


def survivor_reason(va, kind):
    if 0x44AFADF <= va < 0x44AFB1D:
        return "row of the snapshot compare whose answer is dropped"
    if 0x48C7E72 <= va < 0x48C7F2F:
        return "row of the 100 key list that is freed unread"
    if va in (0x44AFBBA, 0x44AFBBD, 0x44AFBC3, 0x44AFBC9):
        return "row of the tracker answer test, only the clock read depends on it"
    if 0x44AE534 <= va < 0x44AE5D5 or 0x44AF1CB <= va < 0x44AF264 or 0x454BD9C <= va < 0x454BE12 or 0x454B458 <= va < 0x454B4CE or 0x4B3167C <= va < 0x4B316EF:
        return "row of a log path"
    if 0x44B02D2 <= va < 0x44B0311 or 0x44B2119 <= va < 0x44B2140 or 0x44B08A0 <= va < 0x44B08C5 or 0x44B09AC <= va < 0x44B09CF:
        return "row of a drop, the fixture free has no effect"
    if 0x44B0A0A <= va < 0x44B0A4D:
        return "row of the store of the event at state+0x2e8, not observed"
    if va in (0x44AE486, 0x44AF766, 0x44AF7F0, 0x44AF9A3, 0x44AF9F6, 0x44B05A8, 0x44B060E, 0x44B0724, 0x44B0759, 0x44B0797, 0x44B09FF, 0x44B0A2A, 0x44B081B, 0x44B084F):
        return "copy size, the changed byte is not observed"
    if va in (0x44B07DB, 0x44B07DF):
        return "state word 0 branch of the tail, stubbed"
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
    for host in (DISPATCH, image.fde(0x44A9AE2)[0]):
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
    result = dict(triggers=triggers, pins=pins, slots=slots, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels, decoded=decoded, fields=fields, dispatch=dispatch)
    for row in GATES:
        if row[5] and row[5] not in labels:
            raise EvidenceError("gate outcome never reached: %s" % row[5])
    if mutate:
        result["mutations"] = run_mutants(image, cases, selected)
    return result


def case_shape(case, label, got):
    return (case.name, label, len(case.steps), len(got["sent"]), len(got["tracker"]), len(got["buffered"]), len(got["own"]), len(got["outbox"]), got["floor"] if got["floor"] is not None else "-")


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
    functions.append(("%#x" % DISPATCH, "%#x" % image.exact_fde(DISPATCH)[1], image.exact_fde(DISPATCH)[1] - DISPATCH, result["reached"][DISPATCH], "arms only", "rows of the execution event arm, heartbeat receive arm and ack arm"))
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
    tsv("cases.tsv", ("case", "last_outcome", "steps", "sent_rows", "tracker_rounds", "buffer_rounds", "own_rounds", "outbox_rows", "floor"), [case_shape(case, label, got) for case, label, got in result["rows"]])
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
