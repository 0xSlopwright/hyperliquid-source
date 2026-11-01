#!/usr/bin/env python3
"""Pin node #94 registerValidator join path: 0x3367800 with its allowed set, ed25519 proof, cold user signature and state row.

The real bytes run in an interpreter inside this tool, with four named boundary functions stubbed. A separately written rule list
predicts every status, every boundary call and the validator_states rows afterwards. Every reached conditional row and immediate in
the named functions is mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_register_validator.py --out <dir>
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
                  (0xDB, True): "andpd", (0xDF, True): "pandn", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
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
        elif op == "pandn":
            self.xmm[row.a[1]] = ~self.xmm[row.a[1]] & self.vector(row.b) & ((1 << 128) - 1)
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


JOIN = 0x3367800
CONTAINS = 0x2FDCE10
SEED = 0x33A6920
PLACE = 0x33C1820
DELEGATE_INSERT = 0x2F38B80
STATE_INSERT = 0x2F43990
VERIFY = 0x158F830
DECOMPRESS = 0x1583680
EQUATION = 0x158F600
AGENT = 0x37F2940
ERROR_BOX = 0x365EB00
SHA_DONE = 0x4EC47D0
SLOT_SHA_UPDATE = 0x57708D0
SLOT_KECCAK_UPDATE = 0x576E1D8
SLOT_KECCAK_DONE = 0x576E1E0
SLOT_RECOVER = 0x576FE58
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118, 0x576DFB8)
MARK_BASE = 0x7700000000
ARENA = HEAP_BASE + 0x10000
ARENA_END = HEAP_BASE + 0x200000
NODES = HEAP_BASE + 0x200000
NODES_END = HEAP_BASE + 0x3F0000
HEAP_USED = 0x400000
STAKING = HEAP_BASE + 0x1000
SIGNER = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
OUT = HEAP_BASE + 0x800
MAP = HEAP_BASE + 0x900
LONG_STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 900000
OK = 0x186
NOT_ALLOWED = 0x94
BAD_PROOF = 0x96
RECOVER_FAIL = 0x7A
COLD_MISMATCH = 0x11F
PRESENT = 0x93
BOX = 0x7777000
JOIN_TEXT = b"VALIDATOR_JOIN"
CHAIN = 1337
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
ROUND = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
         0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
         0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
TURN = (1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)
LANE = (10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1)


def keccak256(data):
    state = [0] * 25
    rate = 136
    padded = bytearray(data) + b"\x01" + bytes((rate - (len(data) + 1) % rate) % rate)
    padded[-1] |= 0x80
    for start in range(0, len(padded), rate):
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(padded[start + index * 8:start + index * 8 + 8], "little")
        for constant in ROUND:
            column = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            for x in range(5):
                rotated = (column[(x + 1) % 5] << 1 | column[(x + 1) % 5] >> 63) & MASK[8]
                for y in range(0, 25, 5):
                    state[y + x] ^= column[(x + 4) % 5] ^ rotated
            last = state[1]
            for at, turn in zip(LANE, TURN):
                last, state[at] = state[at], (last << turn | last >> (64 - turn)) & MASK[8]
            for y in range(0, 25, 5):
                row = state[y:y + 5]
                for x in range(5):
                    state[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5] & MASK[8])
            state[0] ^= constant
    return b"".join(value.to_bytes(8, "little") for value in state[:4])


def point_of(key):
    """Edwards point of a 32 byte key, or None when the x square root does not exist. No canonical test."""
    y = (int.from_bytes(key, "little") & (2 ** 255 - 1)) % P
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    check = v * x * x % P
    if check == P - u or check == (P - u * 1) % P and u:
        x = x * I % P
        check = v * x * x % P
    if check != u:
        return None
    if x & 1 != key[31] >> 7:
        x = (P - x) % P
    return x, y


def limbs(words):
    return sum(word << (51 * index) for index, word in enumerate(words))


class Layout:
    def __init__(self, key_size, key_at, val_size, val_at, parent_at, slot_at, len_at, edge_at):
        self.key_size, self.key_at, self.val_size, self.val_at = key_size, key_at, val_size, val_at
        self.parent_at, self.slot_at, self.len_at, self.edge_at = parent_at, slot_at, len_at, edge_at


ALLOWED = Layout(32, 0, 0, 0, 0x160, 0x168, 0x16A, 0x170)
STATES = Layout(32, 0x2C0, 0x40, 0, 0x420, 0x428, 0x42A, 0x430)
DELEGATIONS = Layout(20, 0x60, 8, 8, 0, 0x13C, 0x13E, 0x140)


class StubRange:
    """Every code address runs for real but the named boundary functions."""

    def __contains__(self, va):
        return va < 0x6000000 and va not in (EQUATION, AGENT, ERROR_BOX, SHA_DONE)


def real_set(self):
    return StubRange()


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC, SLOT_SHA_UPDATE, SLOT_KECCAK_UPDATE, SLOT_KECCAK_DONE, SLOT_RECOVER) + STOP_SLOTS:
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
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc,
                 SLOT_SHA_UPDATE: self.on_sha, SLOT_KECCAK_UPDATE: self.on_keccak, SLOT_KECCAK_DONE: self.on_keccak_done, SLOT_RECOVER: self.on_recover}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        machine.calls = {EQUATION: self.on_equation, AGENT: self.on_agent, ERROR_BOX: self.on_box, SHA_DONE: self.on_sha_done}
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.nodes = NODES
        self.live = {}
        self.events = []
        self.sha = bytearray()
        self.keccak = bytearray()
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

    def on_sha(self, machine):
        if not self.sha:
            self.expect(self.read(machine.regs[RDI]) == 0x6A09E667F3BCC908, "sha512 first initial word")
        self.sha += self.data(machine.regs[RSI], machine.regs[RDX])

    def on_sha_done(self, machine):
        digest = hashlib.sha512(bytes(self.sha)).digest()
        self.sha = bytearray()
        for index in range(8):
            self.write(machine.regs[RDI] + index * 8, int.from_bytes(digest[index * 8:index * 8 + 8], "big"))

    def on_equation(self, machine):
        key_struct, signature, scalar = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        words = [self.read(key_struct + 0x20 + index * 8) for index in range(20)]
        x, y, z, t = (limbs(words[at:at + 5]) % P for at in (0, 5, 10, 15))
        zi = pow(z, P - 2, P)
        self.events.append(("equation", self.data(key_struct, 32).hex(), "%x" % (x * zi % P), "%x" % (y * zi % P), "%x" % (t * zi % P), self.data(signature, 64).hex(), self.data(scalar, 32).hex()))
        machine.regs[RAX] = 4 if self.case.proof_ok else 2

    def on_keccak(self, machine):
        self.keccak += self.data(machine.regs[RSI], machine.regs[RDX])

    def on_keccak_done(self, machine):
        state, out, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.expect(size == 32 and self.read(state + 0xD0) == 0x88 and self.read(state + 0xD8, 2) == 1, "keccak 256 rate and delimiter")
        self.put(out, keccak256(bytes(self.keccak)))
        self.keccak = bytearray()

    def on_agent(self, machine):
        out, row = machine.regs[RDI], machine.regs[RSI]
        source = self.data(self.read(row + 8), self.read(row + 0x10))
        self.events.append(("agent", self.read(row), source.hex(), self.data(row + 0x18, 32).hex(), self.read(row + 0x38), self.read(row + 0x40), self.read(row + 0x48), self.read(row + 0x50)))
        if self.case.agent_error:
            self.write(out, 1, 1)
            self.put(out + 8, bytes(range(0x30, 0x48)))
        else:
            self.write(out, 0, 1)
            self.put(out + 1, agent_digest(source, self.data(row + 0x18, 32)))

    def on_box(self, machine):
        self.events.append(("box", self.data(machine.regs[RDI], 24).hex()))
        machine.regs[RAX] = BOX

    def on_recover(self, machine):
        out, signature, digest = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        self.events.append(("recover", self.data(signature, 0x41).hex(), self.data(digest, 32).hex()))
        if self.case.recover_error:
            self.write(out, 1, 1)
            self.write(out + 8, 0x4242)
        else:
            self.write(out, 0, 1)
            self.put(out + 1, self.case.recovered)

    def node(self, size):
        at = self.nodes
        self.nodes += (size + 15) & ~15
        if self.nodes > NODES_END:
            raise Halt("fixture node area full")
        return at

    def build(self, layout, rows, height, parent=0, slot=0):
        """Rows are (key, value) sorted; height 0 is a leaf."""
        if height == 0:
            self.expect(len(rows) <= 11, "leaf row count")
            node = self.node(layout.edge_at)
            for index, (key, value) in enumerate(rows):
                self.put(node + layout.key_at + index * layout.key_size, key)
                if layout.val_size:
                    self.put(node + layout.val_at + index * layout.val_size, value)
        else:
            parts = max(2, (len(rows) + 1 + 12 ** height - 1) // 12 ** height)
            self.expect(parts <= 12, "edge count")
            node = self.node(layout.edge_at + 12 * 8)
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

    def root(self, at, layout, rows, height):
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
                rows.append((self.data(node + layout.key_at + index * layout.key_size, layout.key_size), self.data(node + layout.val_at + index * layout.val_size, layout.val_size)))
        return rows

    def rows_at(self, at, layout):
        root = self.read(at)
        if not root:
            self.expect(self.read(at + 0x10) == 0, "empty map length")
            return []
        rows = self.walk(layout, root, self.read(at + 8))
        self.expect(len(rows) == self.read(at + 0x10), "map length word")
        return rows

    def fresh(self, case):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.nodes = NODES
        self.live = {}
        self.events = []
        self.sha = bytearray()
        self.keccak = bytearray()
        self.case = case


class Case:
    FIELDS = dict(kind="join", key=None, proof=bytes((0x40 + at) & 0xFF for at in range(64)), nonce=1700000000123, signer=None, cold=None, recovered=None, cold_sig=bytes((0x90 + at) & 0xFF for at in range(0x48)),
                  mode=3, allowed=(), allowed_height=0, states=(), states_height=0, proof_ok=True, agent_error=False, recover_error=False,
                  rows=(), height=0, value=7, entry=None, data=None, want=None, form=None, copy=False)

    def __init__(self, name, **fields):
        self.name = name
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise EvidenceError("unknown field %s" % sorted(unknown))
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.get(key, value))
        self.key = self.key if self.key is not None else GOOD_KEY
        self.signer = self.signer if self.signer is not None else address(1)
        self.cold = self.cold if self.cold is not None else address(2)
        self.recovered = self.recovered if self.recovered is not None else self.cold


def address(seed):
    return bytes([0x20 + seed % 0x60]) + bytes((0xA0 + seed * 3 + at * 5) & 0xFF for at in range(18)) + bytes([seed & 0xFF])


def good_key(seed):
    """First key at or after a seed whose y has a square root, sign bit clear."""
    value = seed
    while True:
        key = value.to_bytes(32, "little")
        if point_of(key) is not None:
            return key
        value += 1


def bad_key(seed):
    value = seed
    while True:
        key = value.to_bytes(32, "little")
        if point_of(key) is None:
            return key
        value += 1


GOOD_KEY = good_key(0x51525354555657584142434445464748)


def agent_digest(source, connection):
    return keccak256(b"agent" + source + connection)


def state_value(hot, cold):
    return bytes(0x18) + hot + cold


def run_join(harness, case, decoded=None):
    if decoded is None:
        harness.fresh(case)
    harness.put(SIGNER, case.signer + b"\xEE" * 12)
    harness.put(ACTION, case.proof + case.key + case.cold_sig)
    harness.write(ACTION + 0xA8, case.nonce)
    harness.put(ACTION + 0xB0, case.cold + b"\xDD" * 4)
    harness.root(STAKING + 8, STATES, case.states, case.states_height)
    harness.root(STAKING + 0x58, ALLOWED, case.allowed, case.allowed_height)
    harness.write(OUT, 0)
    harness.machine.run(JOIN, {RDI: OUT, RSI: STAKING, RDX: SIGNER, RCX: ACTION, R8: case.mode})
    status = harness.read(OUT, 2)
    rows = harness.rows_at(STAKING + 8, STATES)
    out = [("status", status)]
    if status == RECOVER_FAIL:
        out.append(("payload", harness.read(OUT + 8)))
    out += harness.events
    for key, value in rows:
        root = int.from_bytes(value[:8], "little")
        delegations = harness.rows_at_value(value, DELEGATIONS) if root else ()
        out.append(("row", key.hex(), value[0x18:0x2C].hex(), value[0x2C:0x40].hex(), tuple((who.hex(), int.from_bytes(word, "little")) for who, word in delegations)))
    harness.expect(harness.rows_at(STAKING + 0x58, ALLOWED) == [(key, b"") for key, _ in case.allowed], "allowed set untouched")
    out.append(("live", tuple(sorted(harness.live.values()))))
    return tuple(out)


def rows_at_value(self, value, layout):
    at = HEAP_BASE + 0x980
    self.put(at, value[:0x18])
    return self.rows_at(at, layout)


Harness.rows_at_value = rows_at_value


def run_seed(harness, case):
    harness.fresh(case)
    harness.put(SIGNER, case.signer)
    harness.root(MAP, DELEGATIONS, case.rows, case.height)
    result = harness.machine.run(SEED, {RDI: MAP, RSI: SIGNER, RDX: case.value})
    replaced = result & MASK[1]
    old = harness.machine.regs[RDX] if replaced else None
    rows = harness.rows_at(MAP, DELEGATIONS)
    return (("result", replaced, old), ("rows", tuple((who.hex(), int.from_bytes(word, "little")) for who, word in rows)))


def run_case(harness, case):
    return {"seed": run_seed, "join": run_join, "read": run_read, "write": run_write, "chain": run_chain}[case.kind](harness, case)


def spec_join(case):
    events = []
    if case.key not in [key for key, _ in case.allowed]:
        return (("status", NOT_ALLOWED), ("live", ())) if not case.states else (("status", NOT_ALLOWED),) + rows_out(case.states) + (("live", ()),)
    point = point_of(case.key)
    if point is None:
        return (("status", NOT_ALLOWED),) + rows_out(case.states) + (("live", ()),)
    x, y = point
    message = JOIN_TEXT + b"%d" % case.nonce
    scalar = int.from_bytes(hashlib.sha512(case.proof[:32] + case.key + message).digest(), "little") % L
    events.append(("equation", case.key.hex(), "%x" % ((P - x) % P), "%x" % y, "%x" % ((P - x) * y % P), case.proof.hex(), scalar.to_bytes(32, "little").hex()))
    if not case.proof_ok:
        return (("status", BAD_PROOF),) + tuple(events) + rows_out(case.states) + (("live", ()),)
    encoded = case.key + (0x60).to_bytes(32, "big") + case.nonce.to_bytes(32, "big") + len(JOIN_TEXT).to_bytes(32, "big") + JOIN_TEXT + bytes(32 - len(JOIN_TEXT))
    connection = keccak256(encoded)
    source = b"a" if case.mode & 0xFF == 3 else b"b"
    events.append(("agent", 1, source.hex(), connection.hex(), CHAIN, 0, 0, 0))
    if case.agent_error:
        events.append(("box", bytes(range(0x30, 0x48)).hex()))
        return (("status", RECOVER_FAIL), ("payload", BOX)) + tuple(events) + rows_out(case.states) + (("live", ()),)
    events.append(("recover", case.cold_sig[:0x41].hex(), agent_digest(source, connection).hex()))
    if case.recover_error:
        return (("status", RECOVER_FAIL), ("payload", 0x4242)) + tuple(events) + rows_out(case.states) + (("live", ()),)
    if case.recovered != case.cold:
        return (("status", COLD_MISMATCH),) + tuple(events) + rows_out(case.states) + (("live", ()),)
    if case.key in [key for key, _ in case.states]:
        return (("status", PRESENT),) + tuple(events) + rows_out(case.states) + (("live", ()),)
    rows = sorted(list(case.states) + [(case.key, None)], key=lambda row: row[0])
    return (("status", OK),) + tuple(events) + tuple(("row", key.hex()) + (fresh_row(case) if value is None else stored_row(value)) for key, value in rows)


def fresh_row(case):
    return (case.signer.hex(), case.cold.hex(), ((case.signer.hex(), 1),))


def stored_row(value):
    return (value[0x18:0x2C].hex(), value[0x2C:0x40].hex(), ())


def rows_out(rows):
    return tuple(("row", key.hex()) + stored_row(value) for key, value in rows)


def spec_seed(case):
    rows = dict(case.rows)
    old = rows.get(case.signer)
    rows[case.signer] = case.value.to_bytes(8, "little")
    return (("result", int(old is not None), None if old is None else int.from_bytes(old, "little")), ("rows", tuple((who.hex(), int.from_bytes(rows[who], "little")) for who in sorted(rows))))


def spec_run(case):
    return {"seed": spec_seed, "join": spec_join, "read": spec_read, "write": spec_write, "chain": spec_join}[case.kind](case)


def compare(got, want, case):
    """The live list of a success depends on node splits; only the one seed node is claimed."""
    if case.kind in ("join", "chain") and got and got[-1][0] == "live" and want[-1:] != got[-1:] and want[0] == ("status", OK):
        sizes = got[-1][1]
        if sizes.count(0x140) == 1 and set(sizes) <= {0x140, 0x430, 0x490}:
            got = got[:-1]
    return got == want


def key_rows(count, seed=1):
    return sorted((good_key(int.from_bytes(hashlib.sha256(b"k%d-%d" % (seed, index)).digest()[:30], "little")), b"") for index in range(count))


def state_rows(keys, seed=1):
    return [(key, state_value(address(seed + index), address(seed + index + 50))) for index, (key, _) in enumerate(keys)]


def delegate_rows(count):
    return sorted((address(index * 2 + 3), (1000 + index).to_bytes(8, "little")) for index in range(count))


READ_OWNED = 0x21321C0
READ_BORROWED = 0x210BC10
READ_OWNED_COPY = 0x3A60780
READ_BORROWED_COPY = 0x3AC7770
WRITE_COMPACT = 0x1E953B0
WRITE_PRETTY = 0x1E95540
WRITE_PACK = 0x1E95110
WRITE_BUFFER = 0x1E95830
WRITE_PRETTY_COPY = 0x3345CD0
WRITE_PACK_COPY = 0x3345A30
WRITE_BUFFER_COPY = 0x3346010
DECODED = HEAP_BASE + 0x4000
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
TAGGED = HEAP_BASE + 0x2800
INDENT_AT = HEAP_BASE + 0x2100
PAYLOAD_SIZE = 0xC8
C_BOOL, C_U64, C_STRING, C_SEQ, C_MAP = 0, 4, 12, 20, 21
HASH_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 32 bytes"
ADDRESS_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 20 bytes"
QUANTITY_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing between (0; 32] bytes"
ARRAY_TEXT = "an array of length 32"
SHAPE_TEXT = "struct RegisterValidatorAction with 5 elements"
TAG_TEXT = b"type"
VARIANT_TEXT = b"RegisterValidatorAction"


def text_row(value):
    return (C_STRING, value.encode())


def uint_row(value):
    return (C_U64, value)


def array_row(data):
    return (C_SEQ, [uint_row(byte) for byte in data])


def hex_of(data):
    return "0x" + data.hex()


def quantity(data):
    return "0x%x" % int.from_bytes(data, "little")


def signature_row(proof):
    return (C_MAP, [("R_bytes", array_row(proof[:32])), ("s_bytes", array_row(proof[32:64]))])


def cold_row(sig):
    return (C_MAP, [("r", text_row(quantity(sig[:32]))), ("s", text_row(quantity(sig[32:64]))), ("v", uint_row(sig[64]))])


def fields_of(case):
    return [("validator", text_row(hex_of(case.key))), ("signature", signature_row(case.proof)), ("coldUser", text_row(hex_of(case.cold))), ("coldUserSignature", cold_row(case.cold_sig)), ("nonce", uint_row(case.nonce))]


def content(harness, at, value):
    """One serde Content row of 0x20 bytes with its tag in byte 0."""
    kind = value[0]
    harness.write(at, kind, 1)
    if kind == C_U64:
        harness.write(at + 8, value[1])
    elif kind == C_BOOL:
        harness.write(at + 1, value[1], 1)
    elif kind == C_STRING:
        block = harness.alloc(max(len(value[1]), 1))
        harness.put(block, value[1])
        harness.write(at + 8, max(len(value[1]), 1))
        harness.write(at + 0x10, block)
        harness.write(at + 0x18, len(value[1]))
    elif kind == C_SEQ:
        block = harness.alloc(max(len(value[1]), 1) * 0x20)
        for index, row in enumerate(value[1]):
            content(harness, block + index * 0x20, row)
        harness.write(at + 8, max(len(value[1]), 1))
        harness.write(at + 0x10, block)
        harness.write(at + 0x18, len(value[1]))
    elif kind == C_MAP:
        block = harness.alloc(max(len(value[1]), 1) * 0x40)
        for index, (name, row) in enumerate(value[1]):
            content(harness, block + index * 0x40, text_row(name))
            content(harness, block + index * 0x40 + 0x20, row)
        harness.write(at + 8, max(len(value[1]), 1))
        harness.write(at + 0x10, block)
        harness.write(at + 0x18, len(value[1]))
    else:
        raise EvidenceError("content kind")


def decode_owned(harness, case, value, entry):
    root = HEAP_BASE + 0x3000
    content(harness, root, value)
    harness.machine.run(entry, {RDI: DECODED, RSI: root})
    if harness.read(DECODED) == 0:
        return None
    if entry in (READ_OWNED, READ_OWNED_COPY):
        box = harness.read(DECODED + 8)
        harness.expect(harness.read(box) == 0, "reader error with a text")
        return harness.data(harness.read(box + 8), harness.read(box + 0x10)).decode()
    harness.expect(harness.read(DECODED + 8, 1) == 6, "reader error kind")
    return harness.data(harness.read(DECODED + 0x18), harness.read(DECODED + 0x20)).decode()


def decoded_fields(harness):
    base = DECODED + 8
    return tuple(harness.data(base + at, size).hex() for at, size in ((0, 32), (32, 32), (0x40, 32), (0x60, 32), (0x80, 32), (0xA0, 1), (0xA8, 8), (0xB0, 20)))


def wanted_fields(proof, key, sig, nonce, cold):
    return (proof[:32].hex(), proof[32:64].hex(), key.hex(), sig[:32].hex(), sig[32:64].hex(), sig[64:65].hex(), nonce.to_bytes(8, "little").hex(), cold.hex())


def run_read(harness, case):
    harness.fresh(case)
    text = decode_owned(harness, case, case.data, case.entry or READ_OWNED)
    return ("error", text) if text is not None else ("ok",) + decoded_fields(harness)


def spec_read(case):
    return case.want


def setup_writer(harness, case, form):
    harness.fresh(case)
    harness.put(ACTION, case.proof + case.key + case.cold_sig)
    harness.write(ACTION + 0xA8, case.nonce)
    harness.put(ACTION + 0xB0, case.cold + b"\xDD" * 4)
    harness.put(TAGGED + 0x100, TAG_TEXT)
    harness.put(TAGGED + 0x110, VARIANT_TEXT)
    harness.write(TAGGED + 0x20, TAGGED + 0x100)
    harness.write(TAGGED + 0x28, len(TAG_TEXT))
    harness.write(TAGGED + 0x30, TAGGED + 0x110)
    harness.write(TAGGED + 0x38, len(VARIANT_TEXT))
    harness.write(TAGGED + 0x40, SERIALIZER)
    pointer = harness.alloc(0x8000)
    if form.startswith("buffer"):
        harness.write(SERIALIZER, 0x8000)
        harness.write(SERIALIZER + 8, pointer)
        harness.write(SERIALIZER + 0x10, 0)
        harness.write(SERIALIZER + 0x18, 0)
        harness.write(SERIALIZER + 0x1A, 0, 1)
        harness.write(SERIALIZER + 0x1B, int(form.endswith("named")), 1)
        return SERIALIZER
    harness.write(WRITER, 0x8000)
    harness.write(WRITER + 8, pointer)
    harness.write(WRITER + 0x10, 0)
    harness.write(SERIALIZER, WRITER)
    if form.startswith("pack"):
        harness.write(SERIALIZER + 8, 0)
        harness.write(SERIALIZER + 0xA, 0, 1)
        harness.write(SERIALIZER + 0xB, int(form.endswith("named")), 1)
    else:
        harness.put(INDENT_AT, b"  ")
        harness.write(SERIALIZER + 8, INDENT_AT)
        harness.write(SERIALIZER + 0x10, 2)
        harness.write(SERIALIZER + 0x18, 0)
        harness.write(SERIALIZER + 0x20, 0, 1)
    return WRITER


def run_write(harness, case):
    form = case.form
    sink = setup_writer(harness, case, form)
    if form in ("compact", "pretty"):
        entry = {"compact": WRITE_COMPACT, "pretty": WRITE_PRETTY_COPY if case.copy else WRITE_PRETTY}[form]
        harness.machine.run(entry, {RDI: ACTION, RSI: TAGGED})
        harness.expect(harness.machine.regs[RAX] == 0, "json writer status")
    else:
        entry = {"pack": WRITE_PACK_COPY if case.copy else WRITE_PACK, "buffer": WRITE_BUFFER_COPY if case.copy else WRITE_BUFFER}[form.split("_")[0]]
        harness.machine.run(entry, {RDI: OUT, RSI: ACTION, RDX: TAGGED})
        harness.expect(harness.read(OUT) == 0x8000000000000004, "msgpack writer status")
    return (harness.data(harness.read(sink + 8), harness.read(sink + 0x10)).hex(),)


def pack_text(data):
    size = len(data)
    if size < 32:
        return bytes([0xA0 | size]) + data
    return b"\xD9" + bytes([size]) + data


def pack_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return b"\xCC" + bytes([value])
    if value < 0x10000:
        return b"\xCD" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xCE" + value.to_bytes(4, "big")
    return b"\xCF" + value.to_bytes(8, "big")


def pack_array(data):
    return b"\xDC\x00\x20" + b"".join(pack_uint(byte) for byte in data)


def spec_write(case):
    sig = case.cold_sig
    if case.form in ("compact", "pretty"):
        value = collections.OrderedDict((("type", VARIANT_TEXT.decode()), ("validator", hex_of(case.key)), ("signature", collections.OrderedDict((("R_bytes", list(case.proof[:32])), ("s_bytes", list(case.proof[32:64]))))),
                                         ("coldUser", hex_of(case.cold)), ("coldUserSignature", collections.OrderedDict((("r", quantity(sig[:32])), ("s", quantity(sig[32:64])), ("v", sig[64])))), ("nonce", case.nonce)))
        text = json.dumps(value, separators=(",", ":")) if case.form == "compact" else json.dumps(value, indent=2, separators=(",", ": "))
        return (text.encode().hex(),)
    named = case.form.endswith("named")
    tail = (pack_text(hex_of(case.key).encode()), None, pack_text(hex_of(case.cold).encode()), None, pack_uint(case.nonce))
    if named:
        inner = b"\x82\xA7R_bytes" + pack_array(case.proof[:32]) + b"\xA7s_bytes" + pack_array(case.proof[32:64])
        cold = b"\x83\xA1r" + pack_text(quantity(sig[:32]).encode()) + b"\xA1s" + pack_text(quantity(sig[32:64]).encode()) + b"\xA1v" + pack_uint(sig[64])
        return ((b"\x86" + pack_text(TAG_TEXT) + pack_text(VARIANT_TEXT) + pack_text(b"validator") + tail[0] + pack_text(b"signature") + inner + pack_text(b"coldUser") + tail[2] + pack_text(b"coldUserSignature") + cold + pack_text(b"nonce") + tail[4]).hex(),)
    inner = b"\x92" + pack_array(case.proof[:32]) + pack_array(case.proof[32:64])
    cold = b"\x93" + pack_text(quantity(sig[:32]).encode()) + pack_text(quantity(sig[32:64]).encode()) + pack_uint(sig[64])
    return ((b"\x96" + pack_text(VARIANT_TEXT) + tail[0] + inner + tail[2] + cold + tail[4]).hex(),)


def run_chain(harness, case):
    harness.fresh(case)
    text = decode_owned(harness, case, (C_MAP, fields_of(case)), case.entry or READ_OWNED)
    harness.expect(text is None, "chain action refused")
    harness.live = {}
    return run_join(harness, case, harness.data(DECODED + 8, PAYLOAD_SIZE))


def tree_case(name, count, height, spot, **fields):
    """An allowed set of count rows, height as given, holding the action key at sorted position spot."""
    rows = key_rows(count)
    key = rows[spot][0]
    return Case(name, key=key, allowed=rows, allowed_height=height, **fields)


def state_case(name, count, height, spot, present=False, **fields):
    keys = key_rows(count, 2)
    if present:
        key = keys[spot][0]
        rows = state_rows(keys)
    else:
        pivot = int.from_bytes(keys[spot][0], "little") if False else None
        key = bytes(bytearray(keys[spot][0])[:31]) + bytes([keys[spot][0][31]])
        key = good_key(int.from_bytes(hashlib.sha256(b"new%d" % spot).digest()[:30], "little"))
        rows = state_rows(keys)
    return Case(name, key=key, allowed=[(key, b"")], states=rows, states_height=height, **fields)


def between(keys, spot):
    """A good key that sorts just after row spot, or before the first row with spot -1."""
    base = keys[max(spot, 0)][0]
    return None


def join_cases():
    out = []
    keys = key_rows(5)
    allowed = sorted(keys + [(GOOD_KEY, b"")])
    out.append(Case("join_ok_chain3", allowed=allowed))
    for mode in (0, 1, 2, 4, 0xFF):
        out.append(Case("join_ok_mode_%d" % mode, allowed=allowed, mode=mode))
    out.append(Case("join_mode_high_bytes", allowed=allowed, mode=0xABCD03))
    out.append(Case("join_set_empty", allowed=()))
    out.append(Case("join_key_absent_leaf", allowed=keys))
    low, high = keys[0][0], keys[-1][0]
    out.append(Case("join_key_below_all", key=bytes(32), allowed=[(bytes([0xF0]) + bytes(31), b"")]))
    out.append(Case("join_key_above_all", key=b"\xF1" + bytes(31), allowed=[(b"\x01" + bytes(31), b"")]))
    for count, height in ((1, 0), (11, 0), (40, 1), (140, 1), (200, 2)):
        for spot in sorted(set((0, count // 3, count // 2, count - 1))):
            out.append(tree_case("join_set_%d_%d_hit_%d" % (count, height, spot), count, height, spot))
    for count, height in ((40, 1), (200, 2)):
        out.append(Case("join_set_%d_%d_miss" % (count, height), key=b"\xFF" * 31 + b"\x7F", allowed=key_rows(count), allowed_height=height))
    for name, key in (("undecodable_a", bad_key(7)), ("undecodable_b", bad_key(0x123456789ABCDEF0)), ("undecodable_top", bad_key(1 << 200))):
        out.append(Case("join_" + name, key=key, allowed=[(key, b"")]))
    sign = bytearray(GOOD_KEY)
    sign[31] |= 0x80
    y_one = (1).to_bytes(32, "little")
    y_sign = bytearray(y_one)
    y_sign[31] |= 0x80
    high_y = (P + 1).to_bytes(32, "little")
    all_ones = b"\xFF" * 31 + b"\x7F"
    for name, key in (("sign_set", bytes(sign)), ("y_one", y_one), ("y_one_sign", bytes(y_sign)), ("y_above_p", high_y), ("y_zero", bytes(32)), ("y_top_ones", all_ones)):
        if point_of(key) is not None:
            out.append(Case("join_key_" + name, key=key, allowed=[(key, b"")]))
    out.append(Case("join_proof_refused", allowed=allowed, proof_ok=False))
    for nonce in (0, 1, 9, 10, 1000, 1700000000123, MASK[8]):
        out.append(Case("join_nonce_%d" % nonce, allowed=allowed, nonce=nonce))
        out.append(Case("join_nonce_refused_%d" % nonce, allowed=allowed, nonce=nonce, proof_ok=False))
    out.append(Case("join_agent_error", allowed=allowed, agent_error=True))
    out.append(Case("join_recover_error", allowed=allowed, recover_error=True))
    out.append(Case("join_agent_error_mode_0", allowed=allowed, agent_error=True, mode=0))
    good = address(2)
    for at in (0, 1, 7, 8, 15, 16, 17, 19):
        other = bytearray(good)
        other[at] ^= 0x40
        out.append(Case("join_cold_differs_%d" % at, allowed=allowed, recovered=bytes(other)))
    state_keys = key_rows(30, 2)
    for count, height in ((1, 0), (11, 0), (40, 1), (140, 1), (200, 2)):
        rows = key_rows(count, 2)
        for spot in sorted(set((0, count // 2, count - 1))):
            key = rows[spot][0]
            out.append(Case("join_present_%d_%d_%d" % (count, height, spot), key=key, allowed=[(key, b"")], states=state_rows(rows), states_height=height))
    for count, height in ((1, 0), (5, 0), (10, 0), (11, 0), (12, 1), (40, 1), (130, 1), (143, 1), (200, 2)):
        rows = key_rows(count, 2)
        for name, key in (("low", good_key(1)), ("high", good_key(0xFFFFFFFF << 216)), ("mid", good_key(int.from_bytes(rows[count // 2][0], "little") + 1))):
            if key not in [row[0] for row in rows]:
                out.append(Case("join_insert_%d_%d_%s" % (count, height, name), key=key, allowed=[(key, b"")], states=state_rows(rows), states_height=height))
    out.append(Case("join_same_hot_cold", allowed=allowed, signer=address(2)))
    return out


def seed_cases():
    out = [Case("seed_empty", kind="seed", value=1), Case("seed_zero_value", kind="seed", value=0), Case("seed_top_value", kind="seed", value=MASK[8])]
    for count, height in ((1, 0), (6, 0), (11, 0), (40, 1), (140, 1)):
        rows = delegate_rows(count)
        for spot in sorted(set((0, count // 2, count - 1))):
            out.append(Case("seed_replace_%d_%d_%d" % (count, height, spot), kind="seed", signer=rows[spot][0], rows=rows, height=height))
        out.append(Case("seed_new_low_%d_%d" % (count, height), kind="seed", signer=b"\x00" * 19 + b"\x01", rows=rows, height=height))
        out.append(Case("seed_new_high_%d_%d" % (count, height), kind="seed", signer=b"\xFF" * 20, rows=rows, height=height))
        mid = bytearray(rows[count // 2][0])
        mid[19] ^= 1
        if bytes(mid) not in [row[0] for row in rows]:
            out.append(Case("seed_new_mid_%d_%d" % (count, height), kind="seed", signer=bytes(mid), rows=rows, height=height))
    return out


READ_KEYS = ("validator", "signature", "coldUser", "coldUserSignature", "nonce")


def read_cases():
    base = Case("base", key=bytes(range(0x60, 0x80)), cold=bytes(range(0xB0, 0xC4)))
    fields = fields_of(base)
    good = ("ok",) + wanted_fields(base.proof, base.key, base.cold_sig, base.nonce, base.cold)
    named = dict(fields)
    out = []

    def add(name, value, want):
        out.append((name, value, want))

    def edited(key, row):
        return (C_MAP, [(name, row if name == key else old) for name, old in fields])

    add("read_good", (C_MAP, fields), good)
    add("read_reverse_keys", (C_MAP, fields[::-1]), good)
    add("read_unknown_key_refused", (C_MAP, fields[:2] + [("extra", uint_row(1))] + fields[2:]), ("error", "unknown field `extra`, expected one of `validator`, `signature`, `coldUser`, `coldUserSignature`, `nonce`"))
    add("read_seq_form", (C_SEQ, [row for _, row in fields]), good)
    add("read_empty_map", (C_MAP, []), ("error", "missing field `validator`"))
    add("read_empty_seq", (C_SEQ, []), ("error", "invalid length 0, expected " + SHAPE_TEXT))
    add("read_short_seq", (C_SEQ, [row for _, row in fields][:4]), ("error", "invalid length 4, expected " + SHAPE_TEXT))
    add("read_long_seq", (C_SEQ, [row for _, row in fields] + [uint_row(1)]), ("error", "invalid length 6, expected 5 elements in sequence"))
    add("read_root_integer", uint_row(1), ("error", "invalid type: integer `1`, expected struct RegisterValidatorAction"))
    add("read_root_text", text_row("x"), ("error", 'invalid type: string "x", expected struct RegisterValidatorAction'))
    for at, key in enumerate(READ_KEYS):
        add("read_missing_" + key, (C_MAP, fields[:at] + fields[at + 1:]), ("error", "missing field `%s`" % key))
        add("read_duplicate_" + key, (C_MAP, fields + [(key, named[key])]), ("error", "duplicate field `%s`" % key))
    add("read_missing_two", (C_MAP, [fields[0], fields[2], fields[3]]), ("error", "missing field `signature`"))
    add("read_no_prefix", edited("validator", text_row(base.key.hex())), good)
    add("read_upper_hex", edited("validator", text_row("0x" + base.key.hex().upper())), good)
    add("read_validator_integer", edited("validator", uint_row(7)), ("error", "invalid type: integer `7`, expected " + HASH_TEXT))
    add("read_validator_long", edited("validator", text_row("ab" * 33)), ("error", "invalid length 66, expected " + HASH_TEXT))
    add("read_validator_short", edited("validator", text_row("0xab")), ("error", "invalid length 2, expected " + HASH_TEXT))
    add("read_cold_integer", edited("coldUser", uint_row(7)), ("error", "invalid type: integer `7`, expected " + ADDRESS_TEXT))
    add("read_cold_long", edited("coldUser", text_row("ab" * 21)), ("error", "invalid length 42, expected " + ADDRESS_TEXT))
    add("read_signature_text", edited("signature", text_row("x")), ("error", 'invalid type: string "x", expected struct Signature'))
    add("read_signature_integer", edited("signature", uint_row(1)), ("error", "invalid type: integer `1`, expected struct Signature"))
    add("read_signature_seq", edited("signature", (C_SEQ, [array_row(base.proof[:32]), array_row(base.proof[32:])])), good)
    add("read_signature_short_seq", edited("signature", (C_SEQ, [array_row(base.proof[:32])])), ("error", "invalid length 1, expected struct Signature with 2 elements"))
    add("read_signature_no_r", edited("signature", (C_MAP, [("s_bytes", array_row(base.proof[32:]))])), ("error", "missing field `R_bytes`"))
    add("read_signature_no_s", edited("signature", (C_MAP, [("R_bytes", array_row(base.proof[:32]))])), ("error", "missing field `s_bytes`"))
    add("read_r_short", edited("signature", (C_MAP, [("R_bytes", array_row(base.proof[:31])), ("s_bytes", array_row(base.proof[32:]))])), ("error", "invalid length 31, expected " + ARRAY_TEXT))
    add("read_r_long", edited("signature", (C_MAP, [("R_bytes", array_row(base.proof[:32] + b"\x01")), ("s_bytes", array_row(base.proof[32:]))])), ("error", "invalid length 33, expected 32 elements in sequence"))
    add("read_r_text", edited("signature", (C_MAP, [("R_bytes", text_row("0xab")), ("s_bytes", array_row(base.proof[32:]))])), ("error", 'invalid type: string "0xab", expected ' + ARRAY_TEXT))
    add("read_r_byte_range", edited("signature", (C_MAP, [("R_bytes", (C_SEQ, [uint_row(300)] + [uint_row(1)] * 31)), ("s_bytes", array_row(base.proof[32:]))])), ("error", "invalid value: integer `300`, expected u8"))
    add("read_nonce_text", edited("nonce", text_row("x")), ("error", 'invalid type: string "x", expected u64'))
    add("read_nonce_top", edited("nonce", uint_row(MASK[8])), ("ok",) + wanted_fields(base.proof, base.key, base.cold_sig, MASK[8], base.cold))
    add("read_sig_integer", edited("coldUserSignature", uint_row(1)), ("error", "invalid type: integer `1`, expected struct Signature"))
    add("read_sig_no_v", edited("coldUserSignature", (C_MAP, cold_row(base.cold_sig)[1][:2])), ("error", "missing field `v`"))
    add("read_sig_no_r", edited("coldUserSignature", (C_MAP, cold_row(base.cold_sig)[1][1:])), ("error", "missing field `r`"))
    add("read_sig_v_300", edited("coldUserSignature", (C_MAP, cold_row(base.cold_sig)[1][:2] + [("v", uint_row(300))])), ("error", "invalid value: integer `300`, expected u8"))
    add("read_sig_r_long", edited("coldUserSignature", (C_MAP, [("r", text_row("ab" * 33))] + cold_row(base.cold_sig)[1][1:])), ("error", "invalid length 66, expected " + QUANTITY_TEXT))
    for name, text in (("zero", "0x0"), ("bare", "0x"), ("empty", ""), ("one", "1"), ("odd", "0xabc"), ("wide", "0x" + "f" * 64), ("bad", "0xzz"), ("lead", "0x00" + "ab" * 31)):
        if name == "bad":
            want = ("error", "invalid hex character: z, at 2")
        elif text.replace("0x", "") == "":
            want = ("error", "invalid length 0, expected " + QUANTITY_TEXT)
        else:
            value = int(text.replace("0x", ""), 16).to_bytes(32, "little")
            want = ("ok",) + wanted_fields(base.proof, base.key, value + base.cold_sig[32:], base.nonce, base.cold)
        add("read_sig_r_" + name, edited("coldUserSignature", (C_MAP, [("r", text_row(text))] + cold_row(base.cold_sig)[1][1:])), want)
    add("read_validator_bad_hex", edited("validator", text_row("0x" + "zz" * 32)), ("error", "invalid hex character: z, at 2"))
    cases = []
    for entry, tag in ((READ_OWNED, "owned"), (READ_BORROWED, "borrowed")):
        for name, value, want in out:
            cases.append(Case(name + "_" + tag, kind="read", entry=entry, data=value, want=want))
    return cases


def write_cases():
    out = []
    samples = [("base", Case("x", key=bytes(range(0x60, 0x80)), cold=bytes(range(0xB0, 0xC4)))), ("zero_lead", Case("x", key=bytes(16) + bytes(range(16)), cold=bytes(10) + bytes(range(10))))]
    for nonce in (0, 127, 128, 255, 256, 65535, 65536, 0xFFFFFFFF, 1 << 32, MASK[8]):
        samples.append(("nonce_%d" % nonce, Case("x", nonce=nonce)))
    for v in (0, 27, 28, 127, 128, 255):
        samples.append(("v_%d" % v, Case("x", cold_sig=bytes(64) + bytes([v]) + bytes(7))))
    samples.append(("proof_high", Case("x", proof=bytes(0xF0 + at % 16 for at in range(64)))))
    for form in ("compact", "pretty", "pack_named", "pack_array", "buffer_named", "buffer_array"):
        for name, sample in samples:
            out.append(Case("write_%s_%s" % (form, name), kind="write", form=form, key=sample.key, cold=sample.cold, nonce=sample.nonce, cold_sig=sample.cold_sig, proof=sample.proof))
    return out


def chain_cases():
    allowed = sorted(key_rows(3) + [(GOOD_KEY, b"")])
    return [Case("chain_ok_owned", kind="chain", allowed=allowed, cold_sig=bytes(0x90 + at for at in range(0x41)) + bytes(7)), Case("chain_ok_borrowed", kind="chain", entry=READ_BORROWED, allowed=allowed, cold_sig=bytes(0x90 + at for at in range(0x41)) + bytes(7), mode=1),
            Case("chain_absent", kind="chain", allowed=key_rows(3), cold_sig=bytes(0x90 + at for at in range(0x41)) + bytes(7)), Case("chain_refused", kind="chain", allowed=allowed, proof_ok=False, cold_sig=bytes(0x90 + at for at in range(0x41)) + bytes(7))]


def vector_cases(count):
    draw = random.Random(0x3367800)
    out = []
    keys = key_rows(60, 3)
    for index in range(count):
        size = draw.choice((0, 1, 5, 11, 12, 40, 60))
        rows = keys[:size]
        allowed = [row for row in keys if draw.random() < 0.3]
        pick = draw.choice(keys)[0] if draw.random() < 0.8 else good_key(draw.getrandbits(250))
        fields = dict(key=pick, allowed=allowed, allowed_height=0 if len(allowed) <= 11 else 1, states=state_rows(rows), states_height=0 if size <= 11 else 1, nonce=draw.getrandbits(draw.choice((8, 32, 64))), mode=draw.randrange(5),
                      signer=address(draw.randrange(200)), cold=address(draw.randrange(200)), proof_ok=draw.random() < 0.8, agent_error=draw.random() < 0.1, recover_error=draw.random() < 0.1)
        if draw.random() < 0.15:
            fields["recovered"] = address(draw.randrange(200) + 300)
        out.append(Case("vector_%d" % index, **fields))
    return out


def named_cases():
    return join_cases() + seed_cases() + read_cases() + write_cases() + chain_cases()


NAMES = {JOIN: "register_validator_join", CONTAINS: "allowed_or_state_search", SEED: "delegation_upsert", PLACE: "state_row_place", DELEGATE_INSERT: "delegation_tree_insert", STATE_INSERT: "state_tree_insert",
         VERIFY: "ed25519_verify_host", DECOMPRESS: "ed25519_key_decode", READ_OWNED: "action_reader_owned", READ_BORROWED: "action_reader_borrowed", WRITE_COMPACT: "action_json_compact", WRITE_PRETTY: "action_json_pretty",
         WRITE_PACK: "action_msgpack_pack", WRITE_BUFFER: "action_msgpack_buffer", 0x1E79AC0: "key_names_text", 0x1E79BD0: "key_names_bytes", 0x33DE270: "nonce_display"}
READER_COPIES = ((READ_OWNED_COPY, READ_OWNED), (READ_BORROWED_COPY, READ_BORROWED))
WRITER_COPIES = ((WRITE_PRETTY_COPY, WRITE_PRETTY, "pretty"), (WRITE_PACK_COPY, WRITE_PACK, "pack_named"), (WRITE_BUFFER_COPY, WRITE_BUFFER, "buffer_named"))
ARMS = ((0x275971C, 0x2759240), (0x4D8352C, 0x4D83050), (0x4D8464C, 0x4D84170))
SLOT_JOIN = 0x5773160
ARM_PATTERN = re.compile(re.escape(bytes.fromhex("4983c408")) + b"(?:\\x41\\x0f\\xb6\\x87|\\x45\\x0f\\xb6\\x87)(....)" + re.escape(bytes.fromhex("4981c7")) + b"(....)", re.S)
TEXTS = ("VALIDATOR_JOIN", "struct RegisterValidatorAction with 5 elements", "coldUserSignature", "R_bytes", "s_bytes", "struct Signature", "RegisterValidatorAction")
BOUNDARY = ((EQUATION, "stub", "ed25519 equation: checks the point words and scalar passed in, returns 4 or 2 by case"), (AGENT, "stub", "typed data digest of the L1 action, covered by other packets; arguments recorded"),
            (SLOT_RECOVER, "stub", "secp256k1 recovery through slot 0x576fe58; arguments recorded, address by case"), (ERROR_BOX, "stub", "boxes an error of the digest step"),
            (SHA_DONE, "stub", "sha512 finish; python hashlib, first initial word checked"), (SLOT_SHA_UPDATE, "stub", "sha512 update through its slot"), (SLOT_KECCAK_UPDATE, "stub", "keccak update through its slot"), (SLOT_KECCAK_DONE, "stub", "keccak finish; rate 0x88 and delimiter 1 checked"))
SAMPLE = 1
MUTANT_CASES = 6
WORKERS = 3
SURVIVED = "class: equal outcome on every picked case that reaches the row"
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
        raise EvidenceError("%s: %r differs from %r" % (case.name, got[:3], want[:3]))
    return want


def describe(case, want):
    if case.kind == "read":
        return "ok" if want[0] == "ok" else want[1]
    if case.kind == "write":
        return "bytes %d sha256 %s" % (len(want[0]) // 2, hashlib.sha256(want[0].encode()).hexdigest()[:16])
    if case.kind == "seed":
        return "replaced %d old %s rows %d" % (want[0][1], want[0][2], len(want[1][1]))
    row = dict((item[0], item[1:]) for item in want if item[0] in ("status", "payload"))
    calls = " ".join(item[0] for item in want if item[0] in ("equation", "agent", "box", "recover"))
    return "status %#x%s calls [%s] rows %d" % (row["status"][0], " payload %#x" % row["payload"][0] if "payload" in row else "", calls, sum(1 for item in want if item[0] == "row"))


def copy_rows(image, harness, cases):
    rows = []
    read = [case for case in cases if case.kind == "read"]
    for copy, base in READER_COPIES:
        count = 0
        for case in read:
            if case.entry != base:
                continue
            twin = Case(case.name, kind="read", entry=copy, data=case.data, want=case.want)
            if run_case(harness, twin) != case.want:
                raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
            count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, "%#x" % base, count))
    for copy, base, form in WRITER_COPIES:
        count = 0
        for case in cases:
            if case.kind != "write" or case.form != form:
                continue
            twin = Case(case.name, kind="write", form=form, key=case.key, cold=case.cold, nonce=case.nonce, cold_sig=case.cold_sig, proof=case.proof, copy=True)
            if run_case(harness, twin) != spec_write(case):
                raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
            count += 1
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, "%#x" % base, count))
    return rows


def arm_rows(image):
    rows = []
    for site, host in ARMS:
        data = bytes(image.blob[image.offset(site - 0x28):image.offset(site + 6)])
        if data[-6:-4] != b"\xFF\x15" or site + 6 + struct.unpack("<i", data[-4:])[0] != SLOT_JOIN:
            raise EvidenceError("no call through the join slot at %#x" % site)
        found = ARM_PATTERN.search(data)
        if found is None:
            raise EvidenceError("arm shape moved at %#x" % site)
        mode, state = struct.unpack("<I", found[1])[0], struct.unpack("<I", found[2])[0]
        if state - 0x3840 != mode - 0x8F2:
            raise EvidenceError("arm shift differs at %#x" % site)
        rows.append(("%#x" % host, "%#x" % site, "%#x" % mode, "%#x" % state, "%#x" % (state - 0x3840)))
    return rows


def text_rows(image):
    rows = []
    blob = bytes(image.blob)
    for text in TEXTS:
        at = blob.find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    if blob.count(b"registerValidator"):
        raise EvidenceError("lower case tag text exists")
    rows.append(("absent", "registerValidator"))
    for site in (0x281F22C, 0x2821911, 0x2823E2C, 0x2826511):
        target = site + 5 + struct.unpack("<i", bytes(image.blob[image.offset(site + 1):image.offset(site + 5)]))[0]
        if target != 0x3F3C59:
            raise EvidenceError("tag text site moved at %#x" % site)
        rows.append(("site %#x" % site, "tag text at %#x" % target))
    return rows


def constant_rows(image):
    rows = []
    for va, size, meaning, want in ((0x3367C6A, 10, "TOR_JOIN, stored at text +6", "48b8544f525f4a4f494e"), (0x3367C78, 10, "VALIDATO, stored at text +0", None), (0x3367F66, 12, "chain id 1337 in the agent row", None), (0x3367F03, 2, "source letter 0x62 less one when mode is 3", "b162"), (0x3367D7C, 5, "status 0x94", None), (0x3367D87, 5, "status 0x96", None), (0x336802F, 6, "status 0x7a", None), (0x33680C6, 6, "status 0x11f", None), (0x336824F, 4, "status 0x93", None)):
        data = bytes(image.blob[image.offset(va):image.offset(va) + size])
        if want and data.hex() != want:
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
        outcomes["%#x" % check_case(harness, case)[0][1]] += 1
    table = {}
    for target in sorted(NAMES):
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    result = dict(table=table, named=named, vector_count=len(generated), outcomes=sorted(outcomes.items()), texts=text_rows(image), copies=copy_rows(image, harness, cases), arms=arm_rows(image), constants=constant_rows(image), sizes={target: image.exact_fde(target)[1] - target for target in NAMES})
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
    tsv("dispatch-arms.tsv", ("host", "call_site", "mode_offset", "staking_offset", "shift"), result["arms"])
    tsv("copies.tsv", ("copy", "body_bytes", "same_rules_as", "cases_matched"), result["copies"])
    tsv("constants.tsv", ("address", "bytes", "meaning"), result["constants"])
    tsv("texts.tsv", ("file_offset", "text"), result["texts"])
    tsv("scenarios.tsv", ("case", "outcome"), [(case.name, describe(case, want)) for case, want in result["named"]])
    tsv("vector-outcomes.tsv", ("status", "cases"), result["outcomes"])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(order), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "copies": len(result["copies"]), "dispatch_arms": len(result["arms"])}
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
