#!/usr/bin/env python3
"""Pin node #94 validator state wire forms both ways: Staking, ValidatorL1VoteTracker and ValidatorL1StreamTracker.

The readers 0x19e1e60, 0x196d180 and 0x1867f60 take msgpack, 0x1c04690, 0x1c0ffa0 and 0x1bf7fc0 take JSON, and the writers 0x2219450,
0x22196a0, 0x2204ae0, 0x2204dc0, 0x2444740 and 0x24444e0 give the state back. The real bytes run in an interpreter inside this tool
with every callee real: a state goes in through a real reader, comes back through the real writers, and a separately written rule
list predicts every byte and every error text. Every reached conditional row and immediate in the named functions is mutated, one
in every SAMPLE rows. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/validator_state_wire.py --out <dir>
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
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
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
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
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
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
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
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
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
        self.writer_rmp, self.writer_json = None, None

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

    def failed(self, root):
        offset, size, value = root.marker
        return self.read(DECODED + offset, size) == value

    def decode_rmp(self, data, root, entry=None):
        self.fresh()
        self.put(INPUT, data)
        self.write(DECODER + 0x10, INPUT)
        self.write(DECODER + 0x18, len(data))
        self.write(DECODER + 0x20, 1, 1)
        self.write(DECODER + 0x22, 1024, 2)
        self.machine.run(entry or root.read_rmp, {RDI: DECODED, RSI: DECODER, RDX: 0})
        if not self.failed(root):
            return ("ok",)
        at = DECODED + root.base
        tag = self.read(at, 1)
        if tag == 6:
            return ("error", self.data(self.read(at + 0x10), self.read(at + 0x18)).decode())
        return ("kind", tag)

    def decode_json(self, text, root, entry=None):
        self.fresh()
        data = text.encode()
        self.put(INPUT, data)
        for offset in range(0, 0x60, 8):
            self.write(DECODER + offset, 0)
        self.write(DECODER + 0x18, INPUT)
        self.write(DECODER + 0x20, len(data))
        self.write(DECODER + 0x48, 128, 1)
        self.machine.run(entry or root.read_json, {RDI: DECODED, RSI: DECODER})
        if not self.failed(root):
            return ("ok",)
        box = self.read(DECODED + root.base)
        self.expect(self.read(box) == 0, "serde_json error with a text")
        return ("error", self.data(self.read(box + 8), self.read(box + 0x10)).decode())

    def writer(self):
        pointer = self.alloc(0x20000)
        self.write(WRITER, 0x20000)
        self.write(WRITER + 8, pointer)
        self.write(WRITER + 16, 0)

    def pack(self, root, named, human):
        self.writer()
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, 0)
        self.write(SERIALIZER + 0xA, human, 1)
        self.write(SERIALIZER + 0xB, named, 1)
        self.machine.run(self.writer_rmp or root.write_rmp, {RDI: OUT, RSI: DECODED, RDX: SERIALIZER})
        self.expect(self.read(OUT) == STATUS_OK, "serializer status %#x" % self.read(OUT))
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).hex()

    def text(self, root, indent):
        self.writer()
        self.put(INDENT_AT, indent.encode())
        self.write(SERIALIZER, WRITER)
        self.write(SERIALIZER + 8, INDENT_AT)
        self.write(SERIALIZER + 0x10, len(indent))
        self.write(SERIALIZER + 0x18, 0)
        self.write(SERIALIZER + 0x20, 0xEE, 1)
        self.machine.run(self.writer_json or root.write_json, {RDI: DECODED, RSI: SERIALIZER})
        self.expect(self.machine.regs[RAX] == 0, "json status")
        self.expect(self.read(SERIALIZER + 0x18) == 0, "indent level back at its start")
        return self.data(self.read(WRITER + 8), self.read(WRITER + 16)).decode()


ADDRESS_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 20 bytes"
HASH_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 32 bytes"
TIME_TEXT = "a formatted date and time string"
MAP_TEXT = "a map or a sequence of tuples"
ADDRESS = ("addr",)
HASH = ("hash",)
TIME = ("time",)
U64 = ("u64",)
USIZE = ("usize",)
NONZERO = ("nonzero",)
WEI = ("wei",)
F64 = ("f64",)
BOOL = ("bool",)
TEXT = ("text",)
UNIT = ("unit",)
VOTE = ("vote",)


def struct_of(name):
    return ("struct", name)


def map_of(key, value):
    return ("map", key, value)


def set_of(item):
    return ("set", item)


def opt_of(item):
    return ("opt", item)


STRUCTS = {
    "Staking": (("epoch_states", map_of(U64, struct_of("EpochState"))), ("active_epoch", U64), ("cur_epoch_state", struct_of("EpochState")), ("cur_epoch", U64), ("epoch_duration_seconds", NONZERO), ("allowed_validators", set_of(HASH))),
    "EpochState": (("validator_states", map_of(HASH, struct_of("ValidatorState"))), ("start_time", TIME)),
    "ValidatorState": (("delegations", map_of(ADDRESS, U64)), ("hot_user", ADDRESS), ("cold_user", ADDRESS)),
    "ValidatorL1VoteTracker": (("prune_bucket_guard", struct_of("BucketGuard")), ("atT", map_of(VOTE, struct_of("ActionTracker"))), ("active", BOOL), ("hvs", set_of(ADDRESS)), ("hc", struct_of("ValidatorHardPolicy"))),
    "BucketGuard": (("last_bucket", U64), ("bucket_millis", NONZERO)),
    "ValidatorHardPolicy": (("q", F64), ("i", F64)),
    "ActionTracker": (("eti", TIME), ("vtr", struct_of("RawSignatureTracker")), ("qre", BOOL), ("sta", struct_of("L1VoteStakes"))),
    "RawSignatureTracker": (("name", TEXT), ("hsc", struct_of("ValidatorHardPolicy")), ("i", map_of(UNIT, UNIT))),
    "L1VoteStakes": (("vas", map_of(ADDRESS, WEI)), ("qsf", F64)),
    "ValidatorL1StreamTracker": (("risk_free_rate", struct_of("MedianStreamTracker")),),
    "MedianStreamTracker": (("v", map_of(ADDRESS, struct_of("LatestValue"))), ("m", opt_of(F64)), ("b", struct_of("BucketGuard"))),
    "LatestValue": (("t", TIME), ("v", F64)),
    "ModifyAqav2": (("token", USIZE), ("technicalStaker", ADDRESS), ("treasuryStaker", ADDRESS), ("treasuryEvmAddress", ADDRESS), ("evmRebalanceContract", ADDRESS)),
}
VARIANTS = {"D": (TEXT,), "Q": (ADDRESS, BOOL), "C": (TEXT, ADDRESS), "P": (TEXT, BOOL), "A": (USIZE, BOOL), "G": (TEXT, BOOL), "E": (struct_of("ModifyAqav2"),)}
VARIANT_ORDER = "DQCPAGOE"
VARIANT_NAMES = {"Q": "QuarantineUser", "C": "CanonicalTokenDeployer", "P": "DisablePerpDex", "A": "AlignedQuoteToken", "G": "AllowHip3GrowthMode", "E": "ModifyAqav2"}
OUTCOME_VARIANTS = (("registerOutcomeToken", "RegisterOutcomeToken", 1, "maxGas"), ("registerOutcome", "RegisterOutcome", 3, "tokenAndNames"), ("registerTokensAndStandaloneOutcome", "RegisterTokensAndStandaloneOutcome", 3, "quoteToken"), ("registerTokensAndQuestion", "RegisterTokensAndQuestion", 4, "quoteToken"), ("settleOutcome", "SettleOutcome", 3, "outcome"), ("settleQuestion", "SettleQuestion", 2, "question"), ("changeOutcomeDescription", "ChangeOutcomeDescription", 2, "outcome"), ("registerQuestion", "RegisterQuestion", 2, "fallbackOutcome"), ("registerNamedOutcome", "RegisterNamedOutcome", 2, "question"), ("changeQuestionDescription", "ChangeQuestionDescription", 2, "question"))
HUNDRED_YEARS = 36500 * 86400
ARRAY_REQUIRED = {("MedianStreamTracker", "m")}
ARRAY_REQUIRED = {("MedianStreamTracker", "m")}
ARRAY_REQUIRED = {("MedianStreamTracker", "m")}
HC_Q, HC_I = 0.5, 0.5
EPOCH_START = "1970-01-01T00:00:00"
DEFAULTS = {("Staking", "epoch_duration_seconds"): HUNDRED_YEARS, ("Staking", "allowed_validators"): [], ("EpochState", "start_time"): EPOCH_START, ("MedianStreamTracker", "m"): None, ("ValidatorL1VoteTracker", "atT"): [], ("ValidatorL1VoteTracker", "hvs"): [], ("ValidatorL1VoteTracker", "hc"): dict(q=HC_Q, i=HC_I), ("RawSignatureTracker", "hsc"): dict(q=0.0, i=0.0)}


class Root:
    """One state root: entries, how a failed result is marked, where the error sits."""

    def __init__(self, name, read_rmp, read_copies, read_json, json_copies, write_rmp, write_json, writer_copies, marker, base, size):
        self.name, self.read_rmp, self.read_copies, self.read_json, self.json_copies = name, read_rmp, read_copies, read_json, json_copies
        self.write_rmp, self.write_json, self.writer_copies, self.marker, self.base, self.size = write_rmp, write_json, writer_copies, marker, base, size
        self.kind = struct_of(name)


ROOTS = {
    "Staking": Root("Staking", 0x19E1E60, (0x2BDE060, 0x3EFD7D0), 0x1C04690, (0x31330C0,), 0x2219450, 0x22196A0, ((0x4327E90, 0x43280E0),), (0, 8, 0), 8, 0x70),
    "ValidatorL1VoteTracker": Root("ValidatorL1VoteTracker", 0x196D180, (0x2E37250, 0x3FE15B0), 0x1C0FFA0, (0x314DE40,), 0x2204AE0, 0x2204DC0, ((0x42E28D0, 0x42E2620),), (0x50, 1, 2), 0, 0x58),
    "ValidatorL1StreamTracker": Root("ValidatorL1StreamTracker", 0x1867F60, (0x2CA5050, 0x3DFF950), 0x1BF7FC0, (0x3146030,), 0x2444740, 0x24444E0, ((0x3B476E0, 0x3B477C0), (0x42E3950, 0x42E36F0)), (0, 8, 2), 8, 0x38),
}


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


def order_of(kind, key):
    if kind == VOTE:
        fields = key[1:]
        if key[0] == "E":
            fields = tuple(fields[0][name] for name, _ in STRUCTS["ModifyAqav2"])
        return (VARIANT_ORDER.index(key[0]),) + tuple(fields)
    return key


def canon(kind, value):
    """Fill defaults, put maps and sets in their sorted order and texts in their written form."""
    tag = kind[0]
    if tag == "struct":
        return {field: canon(inner, value[field] if field in value else DEFAULTS[kind[1], field]) for field, inner in STRUCTS[kind[1]]}
    if tag == "map":
        return sorted(([canon(kind[1], key), canon(kind[2], item)] for key, item in value), key=lambda row: order_of(kind[1], row[0]))
    if tag == "set":
        return sorted({canon(kind[1], item) for item in value})
    if tag == "seq":
        return [canon(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else canon(kind[1], value)
    if kind == VOTE:
        return (value[0],) + tuple(canon(inner, item) for inner, item in zip(VARIANTS[value[0]], value[1:]))
    if kind == TIME:
        return stamp(value)
    if kind == ADDRESS or kind == HASH:
        return value.lower()
    return float(value) if kind == F64 else value


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


def emit(kind, value, named):
    """Canonical value to msgpack, by the rule list of this packet. A partial struct gives the input form."""
    tag = kind[0]
    if tag == "struct":
        rows = [row for row in STRUCTS[kind[1]] if row[0] in value]
        out = mp_head(len(rows), 0x80, 0xDE, 0xDF) if named else mp_head(len(rows), 0x90, 0xDC, 0xDD)
        for field, inner in rows:
            if named:
                out += mp_text(field)
            out += emit(inner, value[field], named)
        return out
    if tag == "map":
        out = mp_head(len(value), 0x90, 0xDC, 0xDD)
        for key, item in value:
            out += b"\x92" + emit(kind[1], key, named) + emit(kind[2], item, named)
        return out
    if tag in ("set", "seq"):
        return mp_head(len(value), 0x90, 0xDC, 0xDD) + b"".join(emit(kind[1], item, named) for item in value)
    if tag == "opt":
        return b"\xc0" if value is None else emit(kind[1], value, named)
    if tag == "vote":
        kinds = VARIANTS[value[0]]
        if len(kinds) == 1:
            return b"\x81" + mp_text(value[0]) + emit(kinds[0], value[1], named)
        return b"\x81" + mp_text(value[0]) + b"\x92" + b"".join(emit(inner, item, named) for inner, item in zip(kinds, value[1:]))
    if tag == "bool":
        return b"\xc3" if value else b"\xc2"
    if tag == "f64":
        return b"\xcb" + struct.pack(">d", value)
    if tag in ("u64", "usize", "nonzero", "wei"):
        return mp_uint(value)
    return mp_text(value)


def plain(kind, value):
    """Canonical or partial value to the object tree of the JSON form."""
    tag = kind[0]
    if tag == "struct":
        return {field: plain(inner, value[field]) for field, inner in STRUCTS[kind[1]] if field in value}
    if tag == "map":
        return [[plain(kind[1], key), plain(kind[2], item)] for key, item in value]
    if tag in ("set", "seq"):
        return [plain(kind[1], item) for item in value]
    if tag == "opt":
        return None if value is None else plain(kind[1], value)
    if tag == "vote":
        kinds = VARIANTS[value[0]]
        if len(kinds) == 1:
            return {value[0]: plain(kinds[0], value[1])}
        return {value[0]: [plain(inner, item) for inner, item in zip(kinds, value[1:])]}
    return value


def address(seed):
    return "0x" + bytes((seed * 7 + index * 13 + 1) & 0xFF for index in range(20)).hex()


def digest(seed):
    return "0x" + bytes((seed * 11 + index * 5 + 3) & 0xFF for index in range(32)).hex()


TIME_A = "2024-01-02T03:04:05.123456789"
TIME_B = "2025-11-30T23:59:59.5"
TIME_C = "2023-06-07T08:09:10"
GUARD_1 = dict(last_bucket=1700000000000, bucket_millis=60000)
POLICY = dict(q=0.5, i=0.25)


def validator_row(seed):
    return [digest(seed), dict(delegations=[[address(seed + 1), seed * 1000 + 1], [address(seed + 2), seed * 1000 + 2]], hot_user=address(seed + 3), cold_user=address(seed + 4))]


def full_staking():
    return dict(
        epoch_states=[[3001, dict(validator_states=[validator_row(10), validator_row(20)], start_time=TIME_A)], [3002, dict(validator_states=[validator_row(30)], start_time=TIME_B)]],
        active_epoch=3002,
        cur_epoch_state=dict(validator_states=[validator_row(40)], start_time=TIME_C),
        cur_epoch=3003,
        epoch_duration_seconds=86401,
        allowed_validators=[digest(1), digest(2)])


def least_staking():
    return dict(epoch_states=[], active_epoch=0, cur_epoch_state=dict(validator_states=[], start_time=TIME_C), cur_epoch=0, epoch_duration_seconds=1, allowed_validators=[])


def tracker_row(seed):
    return dict(eti=TIME_A, vtr=dict(name="vote %d" % seed, hsc=dict(POLICY), i=[]), qre=bool(seed % 2), sta=dict(vas=[[address(seed), seed * 7 + 1], [address(seed + 1), seed * 7 + 2]], qsf=seed + 0.75))


AQAV2 = dict(token=9, technicalStaker=address(60), treasuryStaker=address(61), treasuryEvmAddress=address(62), evmRebalanceContract=address(63))


def full_votes():
    keys = [("D", "dex one"), ("Q", address(50), True), ("C", "PURR", address(51)), ("P", "xyz", True), ("A", 7, False), ("G", "abc", True), ("E", AQAV2)]
    return dict(prune_bucket_guard=dict(GUARD_1), atT=[[key, tracker_row(index + 1)] for index, key in enumerate(keys)], hvs=[address(52), address(53)], hc=dict(POLICY), active=True)


def least_votes():
    return dict(prune_bucket_guard=dict(last_bucket=0, bucket_millis=1), atT=[], hvs=[], hc=dict(q=0.0, i=0.0), active=False)


def full_stream():
    return dict(risk_free_rate=dict(v=[[address(70), dict(t=TIME_A, v=1.5)], [address(71), dict(t=TIME_B, v=0.25)]], b=dict(GUARD_1), m=0.75))


def least_stream():
    return dict(risk_free_rate=dict(v=[], b=dict(last_bucket=0, bucket_millis=1)))


FULL = {"Staking": full_staking, "ValidatorL1VoteTracker": full_votes, "ValidatorL1StreamTracker": full_stream}
LEAST = {"Staking": least_staking, "ValidatorL1VoteTracker": least_votes, "ValidatorL1StreamTracker": least_stream}


class Case:
    """state: friendly value of the root. data: raw input. want: ok from the rule list, or an outcome row."""

    def __init__(self, name, root, state=None, data=None, form="rmp", want=None, entry=None):
        self.name, self.root, self.state, self.data, self.form, self.want, self.entry = name, root, state, data, form, want, entry


def spec_run(case):
    if case.want is not None:
        return case.want
    kind = ROOTS[case.root].kind
    value = canon(kind, case.state)
    return ("ok", emit(kind, value, True).hex(), emit(kind, value, False).hex(), json.dumps(plain(kind, value), indent=2, ensure_ascii=False))


def payload(case):
    if case.data is not None:
        return case.data
    kind = ROOTS[case.root].kind
    if case.form == "json":
        return json.dumps(plain(kind, case.state), ensure_ascii=False)
    return emit(kind, case.state, True)


def run_case(harness, case):
    data = payload(case)
    root = ROOTS[case.root]
    if case.form == "json" or isinstance(data, str):
        got = harness.decode_json(data, root, case.entry)
    else:
        got = harness.decode_rmp(data, root, case.entry)
    if got[0] != "ok":
        return got
    if case.want is not None and case.want[0] == "accepted":
        return ("accepted",)
    named, array, other = harness.pack(root, 1, 0), harness.pack(root, 0, 0), harness.pack(root, 0, 1)
    harness.expect(other == array, "human flag changes the array form")
    return ("ok", named, array, harness.text(root, "  "))


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
        return "struct " + kind[1]
    if tag == "opt":
        return expected_text(kind[1])
    return {"addr": ADDRESS_TEXT, "hash": HASH_TEXT, "time": TIME_TEXT, "map": MAP_TEXT, "set": "a sequence", "seq": "a sequence", "u64": "u64", "usize": "usize", "nonzero": "a nonzero u64", "wei": "u64 for WeiPriv", "f64": "f64", "bool": "a boolean", "text": "a string"}[tag]


def nil_outcome(kind):
    if kind[0] == "opt":
        return ("accepted",)
    return ("error", "invalid type: unit value, expected " + expected_text(kind))


def true_outcome(kind):
    if kind == BOOL:
        return ("accepted",)
    return ("error", "invalid type: boolean `true`, expected " + expected_text(kind))


def walk(kind, value, path):
    """Every struct node of a friendly value, with its path."""
    tag = kind[0]
    if tag == "struct":
        yield kind, value, path
        for field, inner in STRUCTS[kind[1]]:
            if field in value:
                yield from walk(inner, value[field], path + (field,))
    elif tag == "map" and value:
        yield from walk(kind[2], value[0][1], path + (0, 1))


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


def forced(root, state, path, data):
    """Input bytes of the state with the node at path written as data."""
    def go(kind, node, rest):
        if not rest:
            return data
        tag = kind[0]
        if tag == "struct":
            rows = [row for row in STRUCTS[kind[1]] if row[0] in node]
            out = mp_head(len(rows), 0x80, 0xDE, 0xDF)
            for field, inner in rows:
                out += mp_text(field)
                out += go(inner, node[field], rest[1:]) if field == rest[0] else emit(inner, node[field], True)
            return out
        if tag == "map":
            out = mp_head(len(node), 0x90, 0xDC, 0xDD)
            for index, (key, item) in enumerate(node):
                if index == rest[0]:
                    out += b"\x92" + emit(kind[1], key, True) + go(kind[2], item, rest[2:])
                else:
                    out += b"\x92" + emit(kind[1], key, True) + emit(kind[2], item, True)
            return out
        raise EvidenceError("no path through %s" % (kind,))
    return go(ROOTS[root].kind, state, path)


def struct_cases(root):
    """Absent, doubled, nil, true and short or long array forms of every field of every struct."""
    cases = []
    seen = set()
    state = FULL[root]()
    kind_root = ROOTS[root].kind
    for kind, node, path in walk(kind_root, state, ()):
        name = kind[1]
        if name in seen:
            continue
        seen.add(name)
        rows = STRUCTS[name]
        label = name.lower() if name != "BucketGuard" else root.lower() + "_guard"
        total = len(rows)
        for field, inner in rows:
            smaller = edited(state, path, lambda item, gone=field: {k: v for k, v in item.items() if k != gone})
            if (name, field) in DEFAULTS:
                cases.append(Case("%s_%s_absent" % (label, field), root, smaller))
                cases.append(Case("%s_%s_absent_json" % (label, field), root, smaller, form="json"))
            else:
                want = ("error", "missing field `%s`" % field)
                cases.append(Case("%s_%s_absent" % (label, field), root, data=emit(kind_root, smaller, True), want=want))
                cases.append(Case("%s_%s_absent_json" % (label, field), root, data=json.dumps(plain(kind_root, smaller), ensure_ascii=False), form="json", want=want))
            body = emit(kind, node, True)
            twice = emit(kind, {field: node[field]}, True)[1:]
            data = mp_head(len(node) + 1, 0x80, 0xDE, 0xDF) + body[1:] + twice
            cases.append(Case("%s_%s_twice" % (label, field), root, data=forced(root, state, path, data), want=("error", "duplicate field `%s`" % field)))
            cases.append(Case("%s_%s_nil" % (label, field), root, data=forced(root, state, path + (field,), b"\xc0"), want=nil_outcome(inner)))
            cases.append(Case("%s_%s_true" % (label, field), root, data=forced(root, state, path + (field,), b"\xc3"), want=true_outcome(inner)))
        shape = [emit(inner, node[field], True) for field, inner in rows]
        noun = "element" if total == 1 else "elements"
        for size in range(total):
            data = mp_head(size, 0x90, 0xDC, 0xDD) + b"".join(shape[:size])
            shorter = edited(state, path, lambda item, keep=size: {field: item[field] for field, _ in rows[:keep]})
            needed = next((index for index in range(size, total) if (name, rows[index][0]) not in DEFAULTS or (name, rows[index][0]) in ARRAY_REQUIRED), None)
            if needed is None:
                cases.append(Case("%s_array_%d_of_%d" % (label, size, total), root, shorter, data=forced(root, state, path, data)))
            else:
                want = ("error", "invalid length %d, expected struct %s with %d %s" % (needed, name, total, noun))
                cases.append(Case("%s_array_%d_of_%d" % (label, size, total), root, data=forced(root, state, path, data), want=want))
        data = mp_head(total, 0x90, 0xDC, 0xDD) + b"".join(shape)
        cases.append(Case("%s_array_full" % label, root, data=forced(root, state, path, data), want=("accepted",)))
        data = mp_head(total + 1, 0x90, 0xDC, 0xDD) + b"".join(shape) + b"\x00"
        cases.append(Case("%s_array_long" % label, root, data=forced(root, state, path, data), want=("kind", 4)))
    return cases


def root_cases(root):
    full, least = FULL[root](), LEAST[root]()
    kind = ROOTS[root].kind
    label = root.lower()
    first = STRUCTS[root][0][0]
    total = len(STRUCTS[root])
    noun = "element" if total == 1 else "elements"
    out = [Case(label + "_full_named", root, full), Case(label + "_full_array", root, full, data=emit(kind, canon(kind, full), False)), Case(label + "_written_array_read_back", root, least, data=emit(kind, canon(kind, least), False)), Case(label + "_full_json", root, full, form="json"), Case(label + "_least_named", root, least), Case(label + "_least_json", root, least, form="json")]
    errors = ((b"\xc0", "invalid type: unit value, expected struct " + root), (b"\x05", "invalid type: integer `5`, expected struct " + root), (b"\x90", "invalid length 0, expected struct %s with %d %s" % (root, total, noun)), (b"\x80", "missing field `%s`" % first), (b"\xa1x", 'invalid type: string "x", expected struct ' + root), (b"\xc2", "invalid type: boolean `false`, expected struct " + root))
    for index, (data, text) in enumerate(errors):
        out.append(Case("%s_root_%d" % (label, index), root, data=data, want=("error", text)))
    json_errors = (("null", "invalid type: null, expected struct " + root), ("[]", "invalid length 0, expected struct %s with %d %s" % (root, total, noun)), ("{}", "missing field `%s`" % first), ("5", "invalid type: integer `5`, expected struct " + root), ('"x"', 'invalid type: string "x", expected struct ' + root))
    for index, (data, text) in enumerate(json_errors):
        out.append(Case("%s_root_json_%d" % (label, index), root, data=data, form="json", want=("error", text)))
    data = emit(kind, least, True)
    out.append(Case(label + "_unknown_key_ignored", root, least, data=bytes([data[0] + 1]) + data[1:] + mp_text("zzz") + b"\x92\x01\x81\xa1a\x02"))
    out.append(Case(label + "_trailing_byte_left", root, least, data=data + b"\x00"))
    out.append(Case(label + "_json_trailing_text_left", root, least, data=json.dumps(plain(kind, least)) + " x", form="json"))
    out.append(Case(label + "_json_array_root", root, least, data=json.dumps([plain(inner, least[field]) for field, inner in STRUCTS[root] if field in least]), form="json"))
    return out


def staking_cases():
    root = "Staking"
    base = least_staking()
    out = []

    def setter(path, value, name, want=None):
        return Case(name, root, edited(base, path, lambda _, v=value: v), want=want)

    def forcing(path, value, name, want):
        return Case(name, root, data=forced(root, base, path, value), want=want)

    empty = dict(validator_states=[], start_time=TIME_C)
    one = validator_row(50)
    states = ("cur_epoch_state", "validator_states")
    out.append(setter(("allowed_validators",), [digest(2), digest(1), digest(2)], "set_sorted_and_deduped"))
    out.append(setter(("allowed_validators",), [digest(index) for index in range(10, 0, -1)], "set_of_10_rows"))
    out.append(setter(("epoch_states",), [[1000, empty], [20, empty], [300, empty]], "epoch_rows_sorted_as_numbers"))
    out.append(setter(("epoch_states",), [[index, empty] for index in range(30, 0, -1)], "epoch_map_of_30_rows"))
    out.append(setter(("epoch_states",), [[7, empty], [7, empty]], "epoch_duplicate_key", ("error", "duplicate key")))
    out.append(setter(("epoch_states",), [[MASK[8], empty], [0, empty]], "epoch_keys_zero_and_max"))
    out.append(setter(states, [validator_row(70), validator_row(60), validator_row(90)], "validators_sorted_by_key"))
    out.append(setter(states, [[digest(index), one[1]] for index in range(14, 0, -1)], "validator_map_of_14_rows"))
    out.append(setter(states, [one, one], "validators_duplicate_key", ("error", "duplicate key")))
    out.append(setter(states, [[digest(1), dict(one[1], delegations=[[address(9), 5], [address(3), 6]])]], "delegations_sorted_by_address"))
    out.append(setter(states, [[digest(1), dict(one[1], delegations=[[address(9), 5], [address(9), 6]])]], "delegations_duplicate_key", ("error", "duplicate key")))
    out.append(setter(states, [[digest(1), dict(one[1], delegations=[[address(index), index] for index in range(13, 0, -1)])]], "delegations_map_of_13_rows"))
    out.append(setter(states, [[digest(1), dict(one[1], delegations=[[address(1), 0], [address(2), MASK[8]]])]], "delegation_zero_and_max"))
    out.append(setter(states, [[digest(1), dict(one[1], delegations=[])]], "validator_without_delegations"))
    out.append(setter(states, [[digest(1), dict(one[1], cold_user=one[1]["hot_user"])]], "hot_equals_cold"))
    for name, value in (("127", 127), ("128", 128), ("255", 255), ("256", 256), ("65536", 65536), ("2e32", 1 << 32), ("max", MASK[8])):
        out.append(setter(("active_epoch",), value, "active_epoch_" + name))
        out.append(setter(("cur_epoch",), value, "cur_epoch_" + name))
        out.append(setter(("epoch_duration_seconds",), value, "duration_" + name))
    out.append(setter(("active_epoch",), 9, "active_above_cur_kept"))
    out.append(setter(("epoch_states",), [[5, empty]], "active_row_absent_kept"))
    out.append(forcing(("epoch_duration_seconds",), b"\x00", "duration_zero", ("error", "invalid value: integer `0`, expected a nonzero u64")))
    for name, data, want in (("i8_five", b"\xd0\x05", None), ("negative_fix", b"\xff", ("error", "invalid value: integer `-1`, expected u64")), ("negative_i16", b"\xd1\xff\x00", ("error", "invalid value: integer `-256`, expected u64")), ("float", b"\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00", ("error", "invalid type: floating point `1.5`, expected u64")), ("text", mp_text("5"), ("kind", 2)), ("one_row_array", b"\x91\x05", ("kind", 2)), ("empty_map", b"\x80", ("kind", 2))):
        out.append(Case("u64_" + name, root, edited(base, ("active_epoch",), lambda _: 5) if want is None else None, data=forced(root, base, ("active_epoch",), data), want=want))
    for name, text, want in (("seconds", "2024-01-02T03:04:05", None), ("tenths", "2024-01-02T03:04:05.1", None), ("micro", "2024-01-02T03:04:05.123456", None), ("seven_digits", "2024-01-02T03:04:05.1234567", None), ("zero_fraction", "2024-01-02T03:04:05.000", None), ("leap_day", "2024-02-29T00:00:00", None),
                             ("space", "2024-01-02 03:04:05", ("error", "input contains invalid characters")), ("zone", "2024-01-02T03:04:05Z", ("error", "trailing input")), ("month_13", "2024-13-02T03:04:05", ("error", "input is out of range")), ("hour_24", "2024-01-02T24:00:00", ("error", "input is out of range")), ("no_leap", "2023-02-29T00:00:00", ("error", "input is out of range")), ("empty", "", ("error", "premature end of input")), ("word", "x", ("error", "input contains invalid characters"))):
        out.append(setter(("cur_epoch_state", "start_time"), text, "time_" + name, want))
    good = dict(one[1])
    keyed = lambda text: [[digest(1), dict(good, hot_user=text)]]
    for name, text, want in (("no_prefix", "11" * 20, None), ("mixed_case", "0x" + "aB" * 20, None), ("upper_prefix", "0X" + "11" * 20, ("error", "invalid length 42, expected " + ADDRESS_TEXT)), ("short", "0x" + "11" * 19, ("error", "invalid length 38, expected " + ADDRESS_TEXT)), ("bad_digit", "0x" + "1g" * 20, ("error", "invalid hex character: g, at 3"))):
        kept = text[2:].lower() if text[:2] == "0x" else text.lower()
        data = forced(root, base, states, emit(map_of(HASH, struct_of("ValidatorState")), keyed(text), True))
        out.append(Case("address_" + name, root, edited(base, states, lambda _, k=kept: keyed("0x" + k)) if want is None else None, data=data, want=want))
    for name, text, want in (("no_prefix", "22" * 32, None), ("mixed_case", "0x" + "cD" * 32, None), ("upper_prefix", "0X" + "22" * 32, ("error", "invalid length 66, expected " + HASH_TEXT)), ("address_length", address(1), ("error", "invalid length 40, expected " + HASH_TEXT)), ("bad_digit", "0x" + "2z" * 32, ("error", "invalid hex character: z, at 3"))):
        kept = text[2:].lower() if text[:2] == "0x" else text.lower()
        data = forced(root, base, ("allowed_validators",), b"\x91" + mp_text(text))
        out.append(Case("key_" + name, root, edited(base, ("allowed_validators",), lambda _, k=kept: ["0x" + k]) if want is None else None, data=data, want=want))
    canon_key = "0x" + bytes(range(32)).hex()
    out.append(Case("key_bin8", root, edited(base, ("allowed_validators",), lambda _: [canon_key]), data=forced(root, base, ("allowed_validators",), b"\x91\xc4\x20" + bytes(range(32)))))
    out.append(Case("key_u8_array", root, edited(base, ("allowed_validators",), lambda _: [canon_key]), data=forced(root, base, ("allowed_validators",), b"\x91\xdc\x00\x20" + bytes(range(32)))))
    out.append(Case("key_33_u8", root, data=forced(root, base, ("allowed_validators",), b"\x91\xdc\x00\x21" + bytes(range(33))), want=("error", "invalid length 33, expected " + HASH_TEXT)))
    out.append(Case("map_as_msgpack_map", root, edited(base, ("epoch_states",), lambda _: [[7, empty]]), data=forced(root, base, ("epoch_states",), b"\x81\x07" + emit(struct_of("EpochState"), empty, True))))
    out.append(Case("map_row_three_items", root, data=forced(root, base, ("epoch_states",), b"\x91\x93\x07" + emit(struct_of("EpochState"), empty, True) + b"\x00"), want=("kind", 4)))
    out.append(Case("map_row_one_item", root, data=forced(root, base, ("epoch_states",), b"\x91\x91\x07"), want=("error", "invalid length 1, expected a tuple of size 2")))
    out.append(Case("map_row_scalar", root, data=forced(root, base, ("epoch_states",), b"\x91\x07"), want=("error", "invalid type: integer `7`, expected a tuple of size 2")))
    out.append(Case("json_map_object_form", root, edited(base, states, lambda _: [one]), data=json.dumps(dict(plain(ROOTS[root].kind, base), cur_epoch_state=dict(validator_states={one[0]: plain(struct_of("ValidatorState"), one[1])}, start_time=TIME_C))), form="json"))
    return out


def vote_key_data(data):
    """Input with one atT row whose key is the given bytes and whose value is a valid tracker."""
    return forced("ValidatorL1VoteTracker", least_votes(), ("atT",), b"\x91\x92" + data + emit(struct_of("ActionTracker"), tracker_row(1), True))


def vote_cases():
    root = "ValidatorL1VoteTracker"
    base = least_votes()
    out = []
    row = tracker_row(1)

    def keyed(key, name, want=None):
        return Case(name, root, edited(base, ("atT",), lambda _, k=key: [[k, row]]), want=want)

    for key, name in ((("D", ""), "vote_d_empty"), (("D", "q" * 40), "vote_d_long"), (("Q", address(1), False), "vote_q_false"), (("Q", address(1), True), "vote_q_true"), (("C", "TOK", address(2)), "vote_c"), (("P", "dex", False), "vote_p_false"), (("A", 0, True), "vote_a_zero"), (("A", MASK[8], False), "vote_a_max"), (("A", 200, True), "vote_a_200"), (("G", "dex", False), "vote_g_false"), (("E", dict(AQAV2, token=0)), "vote_e_zero"), (("E", dict(AQAV2, token=70000)), "vote_e_wide")):
        out.append(keyed(key, name))
    mixed = [("E", AQAV2), ("G", "z", True), ("A", 2, True), ("A", 1, True), ("P", "a", True), ("C", "b", address(3)), ("C", "a", address(3)), ("Q", address(4), True), ("Q", address(4), False), ("D", "b"), ("D", "a")]
    out.append(Case("vote_keys_sort_by_variant_index_then_fields", root, edited(base, ("atT",), lambda _: [[key, row] for key in mixed])))
    out.append(Case("vote_key_json_all_variants", root, edited(base, ("atT",), lambda _: [[key, row] for key in mixed]), form="json"))
    out.append(Case("vote_key_duplicate", root, edited(base, ("atT",), lambda _: [[("D", "a"), row], [("D", "a"), row]]), want=("error", "duplicate key")))
    out.append(Case("vote_key_unknown_variant", root, data=vote_key_data(b"\x81" + mp_text("Z") + b"\x00"), want=("error", "unknown variant `Z`, expected one of `D`, `Q`, `C`, `P`, `A`, `G`, `O`, `E`")))
    out.append(Case("vote_key_nil", root, data=vote_key_data(b"\xc0"), want=("error", "invalid type: unit value, expected variant identifier")))
    for short, full_name in VARIANT_NAMES.items():
        kind = "struct" if short == "E" else "tuple"
        total = 5 if short == "E" else 2
        out.append(Case("vote_%s_nil" % short, root, data=vote_key_data(b"\x81" + mp_text(short) + b"\xc0"), want=("error", "invalid type: unit value, expected %s variant ValidatorL1VoteAction::%s" % (kind, full_name))))
        out.append(Case("vote_%s_empty" % short, root, data=vote_key_data(b"\x81" + mp_text(short) + b"\x90"), want=("error", "invalid length 0, expected %s variant ValidatorL1VoteAction::%s with %d elements" % (kind, full_name, total))))
    out.append(Case("vote_e_unknown_field", root, data=vote_key_data(b"\x81" + mp_text("E") + b"\x81" + mp_text("x") + b"\x00"), want=("error", "unknown field `x`, expected one of `token`, `technicalStaker`, `treasuryStaker`, `treasuryEvmAddress`, `evmRebalanceContract`")))
    out.append(Case("vote_e_missing_token", root, data=vote_key_data(b"\x81" + mp_text("E") + b"\x80"), want=("error", "missing field `token`")))
    out.append(Case("vote_o_unknown_operation", root, data=vote_key_data(b"\x81" + mp_text("O") + mp_text("x")), want=("error", "unknown variant `x`, expected one of " + ", ".join("`%s`" % row[0] for row in OUTCOME_VARIANTS))))
    for wire, name, total, first in OUTCOME_VARIANTS:
        body = b"\x81" + mp_text("O") + b"\x81" + mp_text(wire)
        noun = "element" if total == 1 else "elements"
        out.append(Case("outcome_%s_nil" % wire, root, data=vote_key_data(body + b"\xc0"), want=("error", "invalid type: unit value, expected struct variant OutcomeDeploy::" + name)))
        out.append(Case("outcome_%s_first_field" % wire, root, data=vote_key_data(body + b"\x80"), want=("error", "missing field `%s`" % first)))
        out.append(Case("outcome_%s_array_0" % wire, root, data=vote_key_data(body + b"\x90"), want=("error", "invalid length 0, expected struct variant OutcomeDeploy::%s with %d %s" % (name, total, noun))))
    out.append(Case("hvs_sorted_and_deduped", root, edited(base, ("hvs",), lambda _: [address(9), address(3), address(9)])))
    out.append(Case("policy_values", root, edited(base, ("hc",), lambda _: dict(q=0.6666666666666666, i=0.2))))
    out.append(Case("policy_integer_read_as_float", root, edited(base, ("hc",), lambda _: dict(q=1.0, i=0.0)), data=forced(root, base, ("hc",), b"\x82" + mp_text("q") + b"\x01" + mp_text("i") + b"\x00")))
    out.append(Case("policy_text_refused", root, data=forced(root, base, ("hc", "q"), mp_text("x")), want=("kind", 2)))
    out.append(Case("guard_zero_millis", root, data=forced(root, base, ("prune_bucket_guard", "bucket_millis"), b"\x00"), want=("error", "invalid value: integer `0`, expected a nonzero u64")))
    stakes = lambda rows: dict(row, sta=dict(vas=rows, qsf=0.5))
    out.append(keyed(("D", "a"), "stakes_row_shape"))
    out.append(Case("stakes_sorted", root, edited(base, ("atT",), lambda _: [[("D", "a"), stakes([[address(9), 1], [address(3), 2]])]])))
    out.append(Case("stakes_duplicate", root, edited(base, ("atT",), lambda _: [[("D", "a"), stakes([[address(9), 1], [address(9), 2]])]]), want=("error", "duplicate key")))
    out.append(Case("stakes_zero_and_max", root, edited(base, ("atT",), lambda _: [[("D", "a"), stakes([[address(1), 0], [address(2), MASK[8]]])]])))
    out.append(Case("signature_row_key_is_unit", root, data=forced(root, base, ("atT",), b"\x91\x92" + emit(VOTE, ("D", "a"), True) + emit(struct_of("ActionTracker"), dict(row, vtr=dict(row["vtr"], i=[]), sta=row["sta"]), True)[:0] + b"\x80"), want=("error", "missing field `eti`")))
    return out


def stream_cases():
    root = "ValidatorL1StreamTracker"
    base = least_stream()
    tracker = ("risk_free_rate",)
    out = []
    row = dict(t=TIME_C, v=2.5)
    for name, value in (("zero", 0.0), ("half", 0.5), ("negative", -2.5), ("big", 1048576.0)):
        out.append(Case("median_" + name, root, edited(base, tracker + ("m",), lambda _, v=value: v)))
        out.append(Case("latest_" + name, root, edited(base, tracker + ("v",), lambda _, v=value: [[address(1), dict(row, v=v)]])))
    out.append(Case("median_nil_written_as_nil", root, edited(base, tracker + ("m",), lambda _: None)))
    out.append(Case("median_integer_read_as_float", root, edited(base, tracker + ("m",), lambda _: 5.0), data=forced(root, edited(base, tracker + ("m",), lambda _: 5.0), tracker + ("m",), b"\x05")))
    out.append(Case("median_text_refused", root, data=forced(root, edited(base, tracker + ("m",), lambda _: 5.0), tracker + ("m",), mp_text("x")), want=("kind", 2)))
    out.append(Case("median_array_refused", root, data=forced(root, edited(base, tracker + ("m",), lambda _: 5.0), tracker + ("m",), b"\x90"), want=("kind", 2)))
    out.append(Case("latest_rows_sorted", root, edited(base, tracker + ("v",), lambda _: [[address(9), row], [address(3), row]])))
    out.append(Case("latest_duplicate", root, edited(base, tracker + ("v",), lambda _: [[address(9), row], [address(9), row]]), want=("error", "duplicate key")))
    out.append(Case("latest_map_of_14_rows", root, edited(base, tracker + ("v",), lambda _: [[address(index), row] for index in range(14, 0, -1)])))
    out.append(Case("guard_zero_millis_stream", root, data=forced(root, base, tracker + ("b", "bucket_millis"), b"\x00"), want=("error", "invalid value: integer `0`, expected a nonzero u64")))
    return out


def rule_cases():
    out = []
    for root in ROOTS:
        out += root_cases(root)
    return out + staking_cases() + vote_cases() + stream_cases()


def all_struct_cases():
    out = []
    for root in ROOTS:
        out += struct_cases(root)
    seen, kept = set(), []
    for case in out:
        if case.name not in seen:
            seen.add(case.name)
            kept.append(case)
    return kept


class Draw:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return self.state >> 33

    def pick(self, items):
        return items[self.next() % len(items)]

    def number(self):
        return self.pick((0, 1, 127, 128, 255, 256, 65535, 65536, 4294967295, 4294967296, MASK[8], self.next()))

    def time(self):
        return "20%02d-%02d-%02dT%02d:%02d:%02d%s" % (self.next() % 30 + 10, self.next() % 12 + 1, self.next() % 28 + 1, self.next() % 24, self.next() % 60, self.next() % 60, self.pick(("", ".5", ".123", ".123456", ".123456789", ".000001", ".100000000")))


def draw_value(draw, kind):
    tag = kind[0]
    if tag == "struct":
        return {field: draw_value(draw, inner) for field, inner in STRUCTS[kind[1]]}
    if tag == "map":
        rows = {}
        for _ in range(0 if kind[1] == UNIT else draw.next() % 3):
            key = draw_value(draw, kind[1])
            rows[json.dumps(key)] = (key, draw_value(draw, kind[2]))
        return [[key, item] for key, item in rows.values()]
    if tag in ("set", "seq"):
        return [draw_value(draw, kind[1]) for _ in range(draw.next() % 3)]
    if tag == "opt":
        return None if draw.next() % 2 else draw_value(draw, kind[1])
    if tag == "vote":
        name = draw.pick(tuple(VARIANTS))
        return (name,) + tuple(draw_value(draw, inner) for inner in VARIANTS[name])
    if tag == "bool":
        return bool(draw.next() % 2)
    if tag == "f64":
        return draw.pick((0.0, 0.5, 0.25, 1.5, 2.75, -0.125, 1024.5))
    if tag == "addr":
        return address(draw.next() % 200)
    if tag == "hash":
        return digest(draw.next() % 50)
    if tag == "time":
        return draw.time()
    if tag == "text":
        return draw.pick(("", "x", "long words here", "q" * 40))
    if tag == "nonzero":
        return draw.number() or 1
    return draw.number()


def vector_cases(count):
    draw = Draw(20261101)
    out = []
    names = tuple(ROOTS)
    for index in range(count):
        root = names[index % 3]
        kind = ROOTS[root].kind
        state = draw_value(draw, kind)
        if index // 3 % 3 == 2:
            out.append(Case("vector_%d" % index, root, state, data=emit(kind, canon(kind, state), False)))
        else:
            out.append(Case("vector_%d" % index, root, state, form=("rmp", "json")[index // 3 % 3]))
    return out


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


ROOT_FIELDS = (("Staking", "epoch_duration_seconds", 0x0), ("Staking", "cur_epoch_state", 0x8), ("Staking", "epoch_states", 0x30), ("Staking", "active_epoch", 0x48), ("Staking", "cur_epoch", 0x50), ("Staking", "allowed_validators", 0x58),
               ("ValidatorL1VoteTracker", "prune_bucket_guard", 0x0), ("ValidatorL1VoteTracker", "atT", 0x10), ("ValidatorL1VoteTracker", "hvs", 0x28), ("ValidatorL1VoteTracker", "hc", 0x40), ("ValidatorL1VoteTracker", "active", 0x50),
               ("ValidatorL1StreamTracker", "risk_free_rate", 0x0))
MEMORY_CHECKS = (("Staking", "epoch_duration_seconds", 0x0, 8, 86401), ("Staking", "cur_epoch_state rows", 0x18, 8, 1), ("Staking", "epoch_states rows", 0x40, 8, 2), ("Staking", "active_epoch", 0x48, 8, 3002), ("Staking", "cur_epoch", 0x50, 8, 3003), ("Staking", "allowed_validators rows", 0x68, 8, 2),
                 ("ValidatorL1VoteTracker", "prune_bucket_guard bucket_millis", 0x0, 8, 60000), ("ValidatorL1VoteTracker", "prune_bucket_guard last_bucket", 0x8, 8, 1700000000000), ("ValidatorL1VoteTracker", "atT rows", 0x20, 8, 7), ("ValidatorL1VoteTracker", "hvs rows", 0x38, 8, 2), ("ValidatorL1VoteTracker", "hc q bits", 0x40, 8, 0x3FE0000000000000), ("ValidatorL1VoteTracker", "hc i bits", 0x48, 8, 0x3FD0000000000000), ("ValidatorL1VoteTracker", "active", 0x50, 1, 1),
                 ("ValidatorL1StreamTracker", "m tag", 0x0, 8, 1), ("ValidatorL1StreamTracker", "m bits", 0x8, 8, 0x3FE8000000000000), ("ValidatorL1StreamTracker", "b bucket_millis", 0x10, 8, 60000), ("ValidatorL1StreamTracker", "b last_bucket", 0x18, 8, 1700000000000), ("ValidatorL1StreamTracker", "v rows", 0x30, 8, 2))
RANGES = ((0x1860000, 0x1870000), (0x1960000, 0x19F0000), (0x1BF0000, 0x1C40000), (0x2200000, 0x2230000), (0x2440000, 0x2450000))
EXCLUDED = (0x2204220, 0x2204460)
ROUTES = ((0x27B436C, 0xE9, 0x2219450, "staking", 0x3EF2E4, "msgpack field wrapper, tail jump"), (0x27B0F9A, 0xE8, 0x22196A0, "staking", 0x3EF2E4, "JSON field wrapper, call"))
FIND_TEXTS = ("struct Staking with 6 elements", "struct EpochState with 2 elements", "struct ValidatorState with 3 elements", "struct ValidatorL1VoteTracker with 5 elements", "struct ActionTracker with 4 elements", "struct RawSignatureTracker with 3 elements", "struct L1VoteStakes with 2 elements", "struct ValidatorHardPolicy with 2 elements", "struct ValidatorL1StreamTracker with 1 element", "struct MedianStreamTracker with 3 elements", "struct LatestValue with 2 elements", "struct BucketGuard with 2 elements", "epoch_states", "active_epoch", "cur_epoch_state", "epoch_duration_seconds", "allowed_validators", "validator_states", "cold_user", "prune_bucket_guard", "risk_free_rate", "technicalStaker", "evmRebalanceContract", "ValidatorL1VoteAction::QuarantineUser", "ValidatorL1VoteAction::CanonicalTokenDeployer", "ValidatorL1VoteAction::DisablePerpDex", "ValidatorL1VoteAction::AlignedQuoteToken", "ValidatorL1VoteAction::AllowHip3GrowthMode", "ValidatorL1VoteAction::ModifyAqav2", "OutcomeDeploy::RegisterOutcomeToken")
SAMPLE = 14
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
    for text in FIND_TEXTS:
        at = blob.find(text.encode())
        if at < 0:
            raise EvidenceError("no text %s" % text)
        rows.append(("%#x" % at, text))
    return rows


def type_text(kind):
    tag = kind[0]
    if tag == "struct":
        return kind[1]
    if tag == "map":
        return "map %s to %s" % (type_text(kind[1]), type_text(kind[2]))
    if tag in ("set", "opt"):
        return "%s %s" % (tag, type_text(kind[1]))
    return tag


def field_rows():
    rows = []
    for name in STRUCTS:
        for index, (field, kind) in enumerate(STRUCTS[name]):
            if (name, field) in ARRAY_REQUIRED:
                text = "absent keeps nil in a map, required in an array"
            elif (name, field) in DEFAULTS:
                text = "absent keeps " + json.dumps(DEFAULTS[name, field], sort_keys=True)
            else:
                text = "required"
            rows.append((name, index, field, type_text(kind), text))
    return rows


def variant_rows():
    rows = []
    for index, short in enumerate(VARIANT_ORDER):
        if short == "O":
            rows.append((index, short, "OutcomeDeploy", "newtype of a 10 row enum, row rules in outcome-variants.tsv"))
        elif short == "D":
            rows.append((index, short, "name not printed by any error text", "newtype of string"))
        else:
            rows.append((index, short, VARIANT_NAMES[short], "struct ModifyAqav2" if short == "E" else "tuple %s" % " ".join(kind[0] for kind in VARIANTS[short])))
    return rows


def memory_rows(harness):
    rows = []
    for root in ROOTS:
        info = ROOTS[root]
        if harness.decode_rmp(emit(info.kind, FULL[root](), True), info) != ("ok",):
            raise EvidenceError("full state refused")
        for owner, name, offset, size, value in MEMORY_CHECKS:
            if owner != root:
                continue
            got = harness.read(DECODED + offset, size)
            if got != value:
                raise EvidenceError("%s at %#x is %#x" % (name, offset, got))
            rows.append((root, name, "%#x" % offset, size, value))
    return rows


def route_rows(image):
    rows = []
    for at, opcode, target, key, key_at, meaning in ROUTES:
        data = bytes(image.blob[image.offset(at):image.offset(at) + 5])
        if data[0] != opcode or at + 5 + struct.unpack("<i", data[1:])[0] != target:
            raise EvidenceError("route row moved at %#x" % at)
        if bytes(image.blob[image.offset(key_at):image.offset(key_at) + len(key)]) != key.encode():
            raise EvidenceError("key text moved")
        rows.append(("%#x" % at, data.hex(), "%#x" % target, key, "%#x" % key_at, meaning))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for root in ROOTS:
        info = ROOTS[root]
        for copy, kinds in [(entry, "msgpack reader") for entry in info.read_copies] + [(entry, "json reader") for entry in info.json_copies]:
            count = 0
            for case in cases:
                is_json = case.form == "json" or isinstance(case.data, str)
                if case.root != root or is_json != (kinds == "json reader"):
                    continue
                twin = Case(case.name, case.root, case.state, case.data, case.form, case.want, copy)
                if run_case(harness, twin) != spec_run(case):
                    raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
                count += 1
            rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, root, kinds, count))
        for packer, texter in info.writer_copies:
            count = 0
            harness.writer_rmp, harness.writer_json = packer, texter
            for case in cases:
                if case.root != root or spec_run(case)[0] != "ok":
                    continue
                if run_case(harness, case) != spec_run(case):
                    raise EvidenceError("writer copy %#x differs on %s" % (packer, case.name))
                count += 1
            harness.writer_rmp, harness.writer_json = None, None
            rows.append(("%#x" % packer, image.exact_fde(packer)[1] - packer, root, "msgpack writer", count))
            rows.append(("%#x" % texter, image.exact_fde(texter)[1] - texter, root, "json writer", count))
    return rows


def targets_of(image, seen):
    found = {}
    for root, info in ROOTS.items():
        found[info.read_rmp] = root + "_msgpack_reader"
        found[info.read_json] = root + "_json_reader"
        found[info.write_rmp] = root + "_msgpack_writer"
        found[info.write_json] = root + "_json_writer"
    for va in seen:
        if any(low <= va < high for low, high in RANGES):
            start = image.fde(va)[0]
            if start not in EXCLUDED:
                found.setdefault(start, "nested_%x" % start)
    return found


def analyse(image, mutate=True, vectors=30, structs=True):
    harness = Harness(image)
    cases = rule_cases() + (all_struct_cases() if structs else [])
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
    wire = []
    for root, info in ROOTS.items():
        state = LEAST[root]()
        if harness.decode_rmp(emit(info.kind, state, True), info) != ("ok",):
            raise EvidenceError("sample refused")
        rows = [(root + "_named", harness.pack(info, 1, 0)), (root + "_array", harness.pack(info, 0, 0)), (root + "_json", harness.text(info, "  ").encode().hex())]
        if rows[0][1] != emit(info.kind, canon(info.kind, state), True).hex():
            raise EvidenceError("sample differs from the rule list")
        wire += rows
    ordered = [case for case, _ in named]
    light = [case for case in ordered if cost[case.name] < 100000]
    light = [case for root in ROOTS for case in [item for item in light if item.root == root][:14]]
    result = dict(names=names, table=table, named=named, vector_count=len(generated), texts=text_rows(image), fields=field_rows(), variants=variant_rows(), memory=memory_rows(harness), routes=route_rows(image), copies=copy_rows(image, harness, light), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in names})
    if mutate:
        pool = [case for case in cases if cost[case.name] < 400000]
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
    tsv("fields.tsv", ("struct", "index", "key", "type", "rule"), result["fields"])
    tsv("vote-variants.tsv", ("index", "wire_name", "name", "payload"), result["variants"])
    tsv("outcome-variants.tsv", ("index", "wire_name", "name", "elements", "first_required_key"), [(index, wire, name, total, first) for index, (wire, name, total, first) in enumerate(OUTCOME_VARIANTS)])
    tsv("root-offsets.tsv", ("root", "key", "state_offset"), [(root, name, "%#x" % offset) for root, name, offset in ROOT_FIELDS])
    tsv("roots.tsv", ("root", "state_bytes", "msgpack_reader", "json_reader", "msgpack_writer", "json_writer", "failed_marker", "error_at"), [(root, "%#x" % info.size, "%#x" % info.read_rmp, "%#x" % info.read_json, "%#x" % info.write_rmp, "%#x" % info.write_json, "offset %#x size %d value %d" % info.marker, "%#x" % info.base) for root, info in ROOTS.items()])
    tsv("memory-checks.tsv", ("root", "item", "state_offset", "size", "value_after_real_decode"), result["memory"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("route-rows.tsv", ("at", "bytes", "target", "key", "key_at", "meaning"), result["routes"])
    tsv("copies.tsv", ("copy", "body_bytes", "root", "form", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("case", "hex"), result["wire"])
    rows = []
    for case, trace in result["named"]:
        if trace[0] == "ok":
            rows.append((case.name, case.root, "ok sha256 " + hashlib.sha256("|".join(trace[1:]).encode()).hexdigest()[:16]))
        else:
            rows.append((case.name, case.root, " ".join(str(item) for item in trace)))
    tsv("scenarios.tsv", ("case", "root", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    reached = sum(row.size for items in table.values() for row in items)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "roots": len(ROOTS), "functions": len(order), "structs": len(STRUCTS), "fields": len(result["fields"]), "vote_variants": len(VARIANT_ORDER), "outcome_variants": len(OUTCOME_VARIANTS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "error_cases": sum(1 for _, trace in named if trace[0] in ("error", "kind")), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "copies": len(result["copies"])}
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
