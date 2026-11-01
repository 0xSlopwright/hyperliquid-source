#!/usr/bin/env python3
"""Pin node #94 staking action wire forms both ways: tokenDelegate, cDeposit, cWithdraw, linkStakingUser, cUserModify, govVote, govPropose, CValidator.

The serde Content readers of seven tagged actions, the CValidatorProfile reader and the msgpack reader 0x190d510 of VoteGlobalAction::CValidator
run as real bytes in an interpreter inside this tool, with every callee real, and the writers give the decoded action back. A separately written
rule list predicts each decoded field at its offset, each output byte and each error text. Every reached conditional row and immediate in the
named functions is mutated, one in every SAMPLE rows. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/staking_action_wire.py --out <dir>
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



C_BOOL, C_U8, C_U64, C_I64, C_F64, C_STRING, C_NONE, C_UNIT, C_SEQ, C_MAP = 0, 1, 4, 8, 10, 12, 16, 18, 20, 21
ROOT_ROW = HEAP_BASE + 0x3000
TAGGED = HEAP_BASE + 0x2800
ACTION_BASE = 8
ADDRESS_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 20 bytes"
HASH_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing 32 bytes"
QUANTITY_TEXT = "a (both 0x-prefixed or not) hex string or byte array containing between (0; 32] bytes"
NILLED = 0x8000000000000000
CHAINS = ("Local", "Sandbox", "Testnet", "Mainnet")
CHOICES = ("yes", "no", "abstain")
CATEGORIES = ("accelerated", "constitutional", "ecosystem", "electoral")
ENUMS = {"chain": CHAINS, "choice": CHOICES, "category": CATEGORIES}
HEAD = (("signatureChainId", "quantity"), ("hyperliquidChain", "chain"))


class Shape:
    def __init__(self, name, tag, fields, offsets, marker, error_at, readers, writers, writer_copies=()):
        self.name, self.tag, self.fields, self.offsets = name, tag, fields, offsets
        self.marker, self.error_at, self.readers = marker, error_at, readers
        self.writers, self.writer_copies = writers, writer_copies


SHAPES = {shape.name: shape for shape in (
    Shape("TokenDelegateAction", "tokenDelegate", HEAD + (("validator", "address"), ("wei", "u64"), ("isUndelegate", "bool"), ("nonce", "u64")),
          {"signatureChainId": 0, "wei": 0x20, "nonce": 0x28, "validator": 0x30, "hyperliquidChain": 0x44, "isUndelegate": 0x45}, (0x45, 1, 2), 0,
          (0x212D750, 0x20FD7C0, 0x3AAFC90, 0x3A5A100, 0x4BBDE50), dict(compact=0x1E90360, buffer=0x1E90520, pack=0x1E909B0, pretty=0x1E90C90),
          (dict(buffer=0x3979CE0, pack=0x397A170, pretty=0x397A450), dict(compact=0x46D8190, buffer=0x46D7D00, pack=0x46D8350, pretty=0x46D7A80))),
    Shape("CDepositAction", "cDeposit", HEAD + (("wei", "u64"), ("nonce", "u64")),
          {"signatureChainId": 0, "wei": 0x20, "nonce": 0x28, "hyperliquidChain": 0x30}, (0x30, 1, 4), 0,
          (0x211B960, 0x20F6800, 0x3AA6420, 0x3A72B90, 0x4BBCFA0), dict(compact=0x1E88C30, buffer=0x1E88610, pack=0x1E889E0, pretty=0x1E88460)),
    Shape("CWithdrawAction", "cWithdraw", HEAD + (("wei", "u64"), ("nonce", "u64")),
          {"signatureChainId": 0, "wei": 0x20, "nonce": 0x28, "hyperliquidChain": 0x30}, (0x30, 1, 4), 0,
          (0x21217A0, 0x2117D50, 0x3A5D6C0, 0x3A875C0, 0x4BBA0E0), dict(compact=0x1E88C30, buffer=0x1E88610, pack=0x1E889E0, pretty=0x1E88460)),
    Shape("LinkStakingUserAction", "linkStakingUser", HEAD + (("user", "address"), ("isFinalize", "bool"), ("nonce", "u64")),
          {"signatureChainId": 0, "nonce": 0x20, "user": 0x28, "hyperliquidChain": 0x3C, "isFinalize": 0x3D}, (0x3D, 1, 2), 0,
          (0x21153D0, 0x209EB90, 0x3A8A790, 0x3A8CA70, 0x4BC4060), dict(compact=0x1E94630, buffer=0x1E947C0, pack=0x1E94C10, pretty=0x1E94EC0),
          (dict(buffer=0x397AB60, pack=0x397AFB0, pretty=0x397B260), dict(compact=0x46D9DA0, buffer=0x46DA1E0, pack=0x46D9F30, pretty=0x46DA630))),
    Shape("CUserModifyAction", "cUserModify", HEAD + (("extendLongTermStaking", "bool"), ("nonce", "u64")),
          {"signatureChainId": 0, "nonce": 0x20, "hyperliquidChain": 0x28, "extendLongTermStaking": 0x29}, (0x29, 1, 2), 0,
          (0x20D2000, 0x20A53C0, 0x3A9A3A0, 0x3ABF060, 0x4BB7EB0), dict(compact=0x1E8D650, buffer=0x1E8D240, pack=0x1E8D7B0, pretty=0x1E8D090),
          (dict(pack=0x3979980, pretty=0x39793C0), dict(compact=0x46D4340, pack=0x46D44A0, pretty=0x46D4800))),
    Shape("GovVoteAction", "govVote", HEAD + (("id", "hash"), ("choice", "choice"), ("nonce", "u64")),
          {"signatureChainId": 0, "id": 0x20, "nonce": 0x40, "hyperliquidChain": 0x48, "choice": 0x49}, (0x49, 1, 3), 0,
          (0x2122460, 0x20EE9B0, 0x3AD9E60, 0x3A7AB20, 0x4C5B1B0), {}),
    Shape("GovProposeAction", "govPropose", HEAD + (("title", "string"), ("description", "string"), ("category", "category"), ("nonce", "u64")),
          {"title": 0, "description": 0x18, "signatureChainId": 0x30, "nonce": 0x50, "hyperliquidChain": 0x58, "category": 0x59}, (0, 8, NILLED), 8,
          (0x211A4D0, 0x2111CF0, 0x3ADAC50, 0x3A52340, 0x4BBF3A0), dict(buffer=0x1E8AB00, compact=0x1E8AF40, pack=0x1E8B2C0, pretty=0x1E8B0E0)),
)}
VOTE_ENTRY = 0x190D510
VOTE_OK = 0x3A
VOTE_FAILED = 0x74
PROFILE_READERS = (0x20E7BC0, 0x20AE470, 0x3A53D90, 0x3A805B0, 0x4C0F480)
PROFILE_ERROR_AT = 8
PROFILE_KEYS = ("node_ip", "name", "description", "delegations_disabled", "commission_bps", "signer")
CHANGE_KEYS = ("node_ip", "name", "description", "unjailed", "disable_delegations", "commission_bps", "signer")
LAYOUT_ROWS = (("CValidatorAction", "word 0", 0, "at or above 2^63: 2^63 is changeProfile, 2^63 + 1 is unregister; below 2^63: register, the word is the name capacity"),
               ("Register", "profile.name", 0, "capacity, pointer, length"), ("Register", "profile.description", 0x18, "capacity, pointer, length"), ("Register", "profile.commission_bps", 0x30, "u64"), ("Register", "profile.signer", 0x38, "20 bytes"),
               ("Register", "profile.node_ip tag", 0x4C, "0 Ip, 1 LocalNode"), ("Register", "profile.node_ip value", 0x4D, "4 bytes for Ip, 1 byte for LocalNode"), ("Register", "profile.delegations_disabled", 0x51, "bool"), ("Register", "initial_wei", 0x58, "u64"), ("Register", "unjailed", 0x60, "bool"),
               ("ChangeProfile", "commission_bps", 8, "word tag 0 or 1, value at +0x10"), ("ChangeProfile", "name", 0x18, "capacity 2^63 for nil, pointer, length"), ("ChangeProfile", "description", 0x30, "capacity 2^63 for nil, pointer, length"), ("ChangeProfile", "unjailed", 0x48, "bool"),
               ("ChangeProfile", "signer tag", 0x49, "bool"), ("ChangeProfile", "signer", 0x4A, "20 bytes"), ("ChangeProfile", "node_ip tag", 0x5E, "0 Ip, 1 LocalNode, 2 nil"), ("ChangeProfile", "node_ip value", 0x5F, "4 bytes or 1 byte"), ("ChangeProfile", "disable_delegations", 0x63, "0, 1, or 2 for nil"),
               ("VoteGlobalAction::CValidator", "c", 0x68, "20 bytes, key after a"))
FIND_TEXTS = ("struct TokenDelegateAction", "struct CDepositAction", "struct CWithdrawAction", "struct LinkStakingUserAction", "struct CUserModifyAction", "struct GovVoteAction", "struct GovProposeAction", "struct CValidatorProfile", "enum CValidatorAction", "struct variant VoteGlobalAction::CValidator",
              "isUndelegate", "isFinalize", "extendLongTermStaking", "changeProfile", "initial_wei", "disable_delegations", "delegations_disabled", "commission_bps", "unjailed", "signatureChainId", "hyperliquidChain")


class Case:
    def __init__(self, name, shape, mode, data=None, want=None, entry=None, form=None, values=None):
        self.name, self.shape, self.mode, self.data, self.want = name, shape, mode, data, want
        self.entry, self.form, self.values = entry, form, values


def text_row(value):
    return (C_STRING, value.encode())


def uint_row(value):
    return (C_U64, value)


def bool_row(value):
    return (C_BOOL, int(value))


def content(harness, at, value):
    """One serde Content row of 0x20 bytes with its tag in byte 0."""
    kind = value[0]
    harness.write(at, kind, 1)
    if kind in (C_U64, C_I64):
        harness.write(at + 8, value[1])
    elif kind == C_F64:
        harness.write(at + 8, to_bits(value[1]))
    elif kind in (C_BOOL, C_U8):
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
    elif kind in (C_NONE, C_UNIT):
        return
    else:
        raise EvidenceError("content kind")


def field_row(kind, value):
    if kind == "quantity":
        return text_row("0x%x" % value)
    if kind in ("chain", "choice", "category"):
        return text_row(value)
    if kind in ("address", "hash"):
        return text_row("0x" + value.hex())
    if kind == "u64":
        return uint_row(value)
    if kind == "bool":
        return bool_row(value)
    if kind == "string":
        return text_row(value)
    raise EvidenceError("field kind")


def tree_of(shape, values):
    return (C_MAP, [(key, field_row(kind, values[key])) for key, kind in shape.fields])


def seq_of(shape, values):
    return (C_SEQ, [field_row(kind, values[key]) for key, kind in shape.fields])


def seeded(index, seed, size):
    return bytes((seed * 37 + index * (seed | 1) * 13 + (index * index) // 3 + 1) & 0xFF for index in range(size))


def values_of(shape, seed=1):
    out = {}
    for index, (key, kind) in enumerate(shape.fields):
        turn = seed * 3 + index
        if kind == "quantity":
            out[key] = 0x66EEE + seed
        elif kind == "chain":
            out[key] = CHAINS[turn % 4]
        elif kind == "choice":
            out[key] = CHOICES[turn % 3]
        elif kind == "category":
            out[key] = CATEGORIES[turn % 4]
        elif kind == "address":
            out[key] = seeded(0, turn + 3, 20)
        elif kind == "hash":
            out[key] = seeded(0, turn + 5, 32)
        elif kind == "u64":
            out[key] = (0x1234567890 * (turn + 1) + seed) & MASK[8]
        elif kind == "bool":
            out[key] = bool(turn % 2)
        elif kind == "string":
            out[key] = "t%d" % turn * (1 + seed % 3)
    return out


def row_text(harness, at):
    size = harness.read(at + 0x10)
    return harness.data(harness.read(at + 8), size).decode() if size else ""


def decoded_values(harness, shape):
    out = []
    for key, kind in shape.fields:
        at = DECODED + shape.offsets[key]
        if kind == "quantity":
            out.append((key, "%x" % int.from_bytes(harness.data(at, 32), "little")))
        elif kind in ENUMS:
            out.append((key, ENUMS[kind][harness.read(at, 1)]))
        elif kind == "address":
            out.append((key, harness.data(at, 20).hex()))
        elif kind == "hash":
            out.append((key, harness.data(at, 32).hex()))
        elif kind == "u64":
            out.append((key, str(harness.read(at))))
        elif kind == "bool":
            flag = harness.read(at, 1)
            harness.expect(flag in (0, 1), "bool byte")
            out.append((key, str(bool(flag)).lower()))
        else:
            out.append((key, row_text(harness, at)))
    return tuple("%s=%s" % row for row in out)


def wanted_values(shape, values):
    out = []
    for key, kind in shape.fields:
        value = values[key]
        if kind == "quantity":
            out.append("%s=%x" % (key, value))
        elif kind in ("address", "hash"):
            out.append("%s=%s" % (key, value.hex()))
        elif kind == "bool":
            out.append("%s=%s" % (key, str(value).lower()))
        else:
            out.append("%s=%s" % (key, value))
    return tuple(out)


def failure_of(harness, entry, error_at, readers):
    at = DECODED + error_at
    if entry in (readers[0], readers[2]):
        box = harness.read(at)
        if harness.read(box):
            return ("kind", harness.read(box))
        return ("error", harness.data(harness.read(box + 8), harness.read(box + 0x10)).decode())
    tag = harness.read(at, 1)
    if tag != 6:
        return ("kind", tag)
    return ("error", harness.data(harness.read(at + 0x10), harness.read(at + 0x18)).decode())


def check_blocks(harness, blocks, moved=()):
    """Both reader forms take the Content tree by value: every block is freed, or moved into a decoded text field."""
    harness.expect(not [block for block in blocks if block in harness.live and block not in moved], "content blocks after a read")


def read_action(harness, shape, entry, tree):
    harness.fresh()
    content(harness, ROOT_ROW, tree)
    blocks = list(harness.live)
    harness.machine.run(entry, {RDI: DECODED, RSI: ROOT_ROW})
    offset, size, value = shape.marker
    if harness.read(DECODED + offset, size) == value:
        check_blocks(harness, blocks)
        return failure_of(harness, entry, shape.error_at, shape.readers)
    check_blocks(harness, blocks, [harness.read(DECODED + shape.offsets[key] + 8) for key, kind in shape.fields if kind == "string"])
    return ("ok",) + decoded_values(harness, shape)


def profile_values(harness, base):
    tag = harness.read(base + 0x4C, 1)
    node = "ip=" + harness.data(base + 0x4D, 4).hex() if tag == 0 else "local=%d" % harness.read(base + 0x4D, 1)
    return ("name=" + row_text(harness, base), "description=" + row_text(harness, base + 0x18), "commission_bps=%d" % harness.read(base + 0x30), "signer=" + harness.data(base + 0x38, 20).hex(), "node_ip=" + node, "delegations_disabled=%d" % harness.read(base + 0x51, 1))


def read_profile(harness, entry, tree):
    harness.fresh()
    content(harness, ROOT_ROW, tree)
    blocks = list(harness.live)
    harness.machine.run(entry, {RDI: DECODED, RSI: ROOT_ROW})
    if harness.read(DECODED) == NILLED:
        check_blocks(harness, blocks)
        return failure_of(harness, entry, PROFILE_ERROR_AT, PROFILE_READERS)
    check_blocks(harness, blocks, (harness.read(DECODED + 8), harness.read(DECODED + 0x20)))
    return ("ok",) + profile_values(harness, DECODED)


def option_text(harness, at):
    return "nil" if harness.read(at) == NILLED else row_text(harness, at)


def change_values(harness, base):
    tag = harness.read(base + 0x5E, 1)
    node = "nil" if tag == 2 else "ip=" + harness.data(base + 0x5F, 4).hex() if tag == 0 else "local=%d" % harness.read(base + 0x5F, 1)
    commission = "nil" if harness.read(base + 8) == 0 else str(harness.read(base + 0x10))
    signer = harness.data(base + 0x4A, 20).hex() if harness.read(base + 0x49, 1) else "nil"
    return ("node_ip=" + node, "name=" + option_text(harness, base + 0x18), "description=" + option_text(harness, base + 0x30), "unjailed=%d" % harness.read(base + 0x48, 1), "disable_delegations=%d" % harness.read(base + 0x63, 1), "commission_bps=" + commission, "signer=" + signer)


def read_vote(harness, data):
    harness.fresh()
    harness.put(INPUT, data)
    harness.write(DECODER + 0x10, INPUT)
    harness.write(DECODER + 0x18, len(data))
    harness.write(DECODER + 0x20, 1, 1)
    harness.write(DECODER + 0x22, 1024, 2)
    harness.machine.run(VOTE_ENTRY, {RDI: DECODED, RSI: DECODER, RDX: 0})
    tag = harness.read(DECODED)
    if tag == VOTE_FAILED:
        kind = harness.read(DECODED + 8, 1)
        if kind != 6:
            return ("kind", kind)
        return ("error", harness.data(harness.read(DECODED + 0x18), harness.read(DECODED + 0x20)).decode())
    harness.expect(tag == VOTE_OK, "variant tag")
    base = DECODED + ACTION_BASE
    target = "c=" + harness.data(base + 0x68, 20).hex()
    word = harness.read(base)
    if word == NILLED + 1:
        return ("ok", "unregister", target)
    if word == NILLED:
        return ("ok", "changeProfile") + change_values(harness, base) + (target,)
    return ("ok", "register") + profile_values(harness, base) + ("initial_wei=%d" % harness.read(base + 0x58), "unjailed=%d" % harness.read(base + 0x60, 1), target)


def setup_writer(harness, shape, form):
    harness.put(TAGGED + 0x100, b"type")
    harness.put(TAGGED + 0x110, shape.tag.encode())
    harness.write(TAGGED + 0x20, TAGGED + 0x100)
    harness.write(TAGGED + 0x28, 4)
    harness.write(TAGGED + 0x30, TAGGED + 0x110)
    harness.write(TAGGED + 0x38, len(shape.tag))
    harness.write(TAGGED + 0x40, SERIALIZER)
    pointer = harness.alloc(0x8000)
    if form.startswith("buffer"):
        harness.write(SERIALIZER, 0x8000)
        harness.write(SERIALIZER + 8, pointer)
        harness.write(SERIALIZER + 0x10, 0)
        harness.write(SERIALIZER + 0x18, 0, 2)
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


def write_action(harness, shape, form, values, table=None):
    table = table or shape.writers
    harness.fresh()
    content(harness, ROOT_ROW, tree_of(shape, values))
    harness.machine.run(shape.readers[0], {RDI: DECODED, RSI: ROOT_ROW})
    offset, size, value = shape.marker
    harness.expect(harness.read(DECODED + offset, size) != value, "writer sample refused")
    sink = setup_writer(harness, shape, form)
    entry = table[form.split("_")[0]]
    if form in ("compact", "pretty"):
        harness.machine.run(entry, {RDI: DECODED, RSI: TAGGED})
        harness.expect(harness.machine.regs[RAX] == 0, "json writer status")
    else:
        harness.machine.run(entry, {RDI: OUT, RSI: DECODED, RDX: TAGGED})
        harness.expect(harness.read(OUT) == STATUS_OK, "msgpack writer status")
    return ("ok", harness.data(harness.read(sink + 8), harness.read(sink + 0x10)).hex())


def pack_text(data):
    size = len(data)
    if size < 32:
        return bytes([0xA0 | size]) + data
    if size < 256:
        return b"\xD9" + bytes([size]) + data
    return b"\xDA" + size.to_bytes(2, "big") + data


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


def wire_value(kind, value):
    if kind == "quantity":
        return "0x%x" % value
    if kind in ("address", "hash"):
        return "0x" + value.hex()
    return value


def pack_value(kind, value):
    plain = wire_value(kind, value)
    if isinstance(plain, bool):
        return b"\xC3" if plain else b"\xC2"
    if isinstance(plain, int):
        return pack_uint(plain)
    return pack_text(plain.encode())


def spec_write(shape, form, values):
    if form in ("compact", "pretty"):
        row = collections.OrderedDict([("type", shape.tag)] + [(key, wire_value(kind, values[key])) for key, kind in shape.fields])
        text = json.dumps(row, separators=(",", ":")) if form == "compact" else json.dumps(row, indent=2, separators=(",", ": "))
        return ("ok", text.encode().hex())
    count = len(shape.fields) + 1
    if form.endswith("named"):
        body = bytes([0x80 | count]) + pack_text(b"type") + pack_text(shape.tag.encode()) + b"".join(pack_text(key.encode()) + pack_value(kind, values[key]) for key, kind in shape.fields)
    else:
        body = bytes([0x90 | count]) + pack_text(shape.tag.encode()) + b"".join(pack_value(kind, values[key]) for key, kind in shape.fields)
    return ("ok", body.hex())


def run_case(harness, case):
    if case.mode == "read":
        return read_action(harness, SHAPES[case.shape], case.entry or SHAPES[case.shape].readers[0], case.data)
    if case.mode == "profile":
        return read_profile(harness, case.entry or PROFILE_READERS[0], case.data)
    if case.mode == "vote":
        return read_vote(harness, case.data)
    return write_action(harness, SHAPES[case.shape], case.form, case.values)


def spec_run(case):
    return case.want


def edited(shape, tree, key, row):
    return (C_MAP, [(name, row if name == key else old) for name, old in tree[1]])


def bad_rows(shape, key, kind):
    """Rows of one field and the outcome each must give; None keeps the wanted value of the row."""
    if kind == "u64":
        return (("zero", uint_row(0), 0), ("top", uint_row(MASK[8]), MASK[8]), ("small_int", (C_U8, 200), 200),
                ("text", text_row("x"), 'invalid type: string "x", expected u64'), ("flag", bool_row(True), "invalid type: boolean `true`, expected u64"),
                ("negative", (C_I64, MASK[8]), "invalid value: integer `-1`, expected u64"), ("float", (C_F64, 1.5), "invalid type: floating point `1.5`, expected u64"), ("unit", (C_UNIT,), "invalid type: null, expected u64"))
    if kind == "bool":
        return (("false", bool_row(False), False), ("true", bool_row(True), True), ("integer", uint_row(1), "invalid type: integer `1`, expected a boolean"), ("text", text_row("true"), 'invalid type: string "true", expected a boolean'))
    if kind == "string":
        return (("empty", text_row(""), ""), ("one_k", text_row("a" * 1000), "a" * 1000), ("integer", uint_row(1), "invalid type: integer `1`, expected a string"), ("flag", bool_row(True), "invalid type: boolean `true`, expected a string"))
    if kind in ("address", "hash"):
        size, words = (20, ADDRESS_TEXT) if kind == "address" else (32, HASH_TEXT)
        data = seeded(0, 0x41, size)
        return (("bare_hex", text_row(data.hex()), data), ("upper_hex", text_row("0x" + data.hex().upper()), data), ("short", text_row("0x" + data.hex()[2:]), "invalid length %d, expected %s" % (size * 2 - 2, words)), ("long", text_row("0x" + data.hex() + "ab"), "invalid length %d, expected %s" % (size * 2 + 2, words)),
                ("empty", text_row(""), "invalid length 0, expected " + words), ("bad_hex", text_row("0x" + "zz" * size), "invalid hex character: z, at 2"), ("integer", uint_row(1), "invalid type: integer `1`, expected " + words))
    if kind == "quantity":
        return (("zero", text_row("0x0"), 0), ("one_digit", text_row("1"), 1), ("odd", text_row("0xabc"), 0xABC), ("wide", text_row("0x" + "f" * 64), 2 ** 256 - 1), ("lead", text_row("0x00" + "ab" * 31), int("ab" * 31, 16)),
                ("bare", text_row("0x"), "invalid length 0, expected " + QUANTITY_TEXT), ("empty", text_row(""), "invalid length 0, expected " + QUANTITY_TEXT), ("too_long", text_row("ab" * 33), "invalid length 66, expected " + QUANTITY_TEXT), ("bad_hex", text_row("0xzz"), "invalid hex character: z, at 2"), ("integer", uint_row(1), "invalid type: integer `1`, expected " + QUANTITY_TEXT))
    if kind in ENUMS:
        names = ENUMS[kind]
        listing = "`" + "`, `".join(names) + "`"
        rows = [("variant_" + name, text_row(name), name) for name in names]
        rows.append(("map_form", (C_MAP, [(names[1], (C_UNIT,))]), names[1]))
        rows.append(("lower_case_miss", text_row(names[0].upper()), "unknown variant `%s`, expected one of %s" % (names[0].upper(), listing)))
        rows.append(("unknown", text_row("nope"), "unknown variant `nope`, expected one of " + listing))
        rows.append(("integer", uint_row(1), "invalid type: integer `1`, expected string or map"))
        return tuple(rows)
    raise EvidenceError("field kind")


def shape_cases(name):
    shape = SHAPES[name]
    values = values_of(shape)
    tree = tree_of(shape, values)
    good = ("ok",) + wanted_values(shape, values)
    keys = [key for key, _ in shape.fields]
    count = len(keys)
    words = "struct %s with %d elements" % (name, count)
    listing = "`" + "`, `".join(keys) + "`"
    prefix = name.lower()
    out = [Case(prefix + "_map", name, "read", tree, good), Case(prefix + "_reverse_keys", name, "read", (C_MAP, tree[1][::-1]), good), Case(prefix + "_seq_form", name, "read", seq_of(shape, values), good),
           Case(prefix + "_empty_map", name, "read", (C_MAP, []), ("error", "missing field `%s`" % keys[0])), Case(prefix + "_empty_seq", name, "read", (C_SEQ, []), ("error", "invalid length 0, expected " + words)),
           Case(prefix + "_short_seq", name, "read", (C_SEQ, seq_of(shape, values)[1][:-1]), ("error", "invalid length %d, expected %s" % (count - 1, words))),
           Case(prefix + "_long_seq", name, "read", (C_SEQ, seq_of(shape, values)[1] + [uint_row(1)]), ("error", "invalid length %d, expected %d elements in sequence" % (count + 1, count))),
           Case(prefix + "_unknown_key", name, "read", (C_MAP, tree[1] + [("extra", uint_row(1))]), ("error", "unknown field `extra`, expected one of " + listing)),
           Case(prefix + "_type_key_refused", name, "read", (C_MAP, [("type", text_row(shape.tag))] + tree[1]), ("error", "unknown field `type`, expected one of " + listing)),
           Case(prefix + "_integer_root", name, "read", uint_row(1), ("error", "invalid type: integer `1`, expected struct " + name)),
           Case(prefix + "_text_root", name, "read", text_row("x"), ("error", 'invalid type: string "x", expected struct ' + name))]
    for at, key in enumerate(keys):
        out.append(Case("%s_missing_%s" % (prefix, key), name, "read", (C_MAP, tree[1][:at] + tree[1][at + 1:]), ("error", "missing field `%s`" % key)))
        out.append(Case("%s_duplicate_%s" % (prefix, key), name, "read", (C_MAP, tree[1] + [(key, tree[1][at][1])]), ("error", "duplicate field `%s`" % key)))
    for key, kind in shape.fields:
        for label, row, result in bad_rows(shape, key, kind):
            if isinstance(result, str) and kind not in ("string",) and not (kind in ENUMS and result in ENUMS[kind]):
                want = ("error", result)
            elif kind == "string" and label in ("integer", "flag"):
                want = ("error", result)
            else:
                want = ("ok",) + wanted_values(shape, dict(values, **{key: result}))
            out.append(Case("%s_%s_%s" % (prefix, key, label), name, "read", edited(shape, tree, key, row), want))
    return out


def profile_tree(node=None, name="nm", description="dd", disabled=None, commission=None, signer=b"\x33" * 20):
    rows = [("node_ip", node or (C_MAP, [("Ip", text_row("1.2.3.4"))])), ("name", text_row(name)), ("description", text_row(description))]
    if disabled is not None:
        rows.append(("delegations_disabled", bool_row(disabled)))
    if commission is not None:
        rows.append(("commission_bps", uint_row(commission)))
    rows.append(("signer", text_row("0x" + signer.hex())))
    return (C_MAP, rows)


def profile_want(node="ip=01020304", name="nm", description="dd", disabled=0, commission=10000, signer=b"\x33" * 20):
    return ("ok", "name=" + name, "description=" + description, "commission_bps=%d" % commission, "signer=" + signer.hex(), "node_ip=" + node, "delegations_disabled=%d" % disabled)


def profile_cases():
    full = profile_tree(disabled=True, commission=77)
    out = [Case("profile_least", "CValidatorProfile", "profile", profile_tree(), profile_want()), Case("profile_full", "CValidatorProfile", "profile", full, profile_want(disabled=1, commission=77)),
           Case("profile_local_node", "CValidatorProfile", "profile", profile_tree(node=(C_MAP, [("LocalNode", (C_U8, 9))])), profile_want(node="local=9")),
           Case("profile_unknown_key_ignored", "CValidatorProfile", "profile", (C_MAP, full[1] + [("disable_delegations", bool_row(True)), ("extra", uint_row(1))]), profile_want(disabled=1, commission=77)),
           Case("profile_commission_zero", "CValidatorProfile", "profile", profile_tree(commission=0), profile_want(commission=0)), Case("profile_commission_over_bps_kept", "CValidatorProfile", "profile", profile_tree(commission=99999), profile_want(commission=99999)),
           Case("profile_empty_map", "CValidatorProfile", "profile", (C_MAP, []), ("error", "missing field `node_ip`")), Case("profile_integer_root", "CValidatorProfile", "profile", uint_row(1), ("error", "invalid type: integer `1`, expected struct CValidatorProfile")),
           Case("profile_empty_seq", "CValidatorProfile", "profile", (C_SEQ, []), ("error", "invalid length 0, expected struct CValidatorProfile with 6 elements")),
           Case("profile_node_text", "CValidatorProfile", "profile", profile_tree(node=text_row("Ip")), ("error", "invalid type: unit variant, expected newtype variant")),
           Case("profile_node_unknown", "CValidatorProfile", "profile", profile_tree(node=text_row("x")), ("error", "unknown variant `x`, expected `Ip` or `LocalNode`")),
           Case("profile_node_integer", "CValidatorProfile", "profile", profile_tree(node=uint_row(1)), ("error", "invalid type: integer `1`, expected string or map")),
           Case("profile_ip_bad", "CValidatorProfile", "profile", profile_tree(node=(C_MAP, [("Ip", text_row("1.2.3"))])), ("error", "invalid IPv4 address syntax"))]
    for key in ("node_ip", "name", "description", "signer"):
        rows = [row for row in full[1] if row[0] != key]
        out.append(Case("profile_missing_" + key, "CValidatorProfile", "profile", (C_MAP, rows), ("error", "missing field `%s`" % key)))
    return out


def pack(value):
    if value is None:
        return b"\xC0"
    if value is True:
        return b"\xC3"
    if value is False:
        return b"\xC2"
    if isinstance(value, int):
        return pack_uint(value)
    if isinstance(value, str):
        return pack_text(value.encode())
    if isinstance(value, dict):
        return bytes([0x80 | len(value)]) + b"".join(pack(key) + pack(item) for key, item in value.items())
    if isinstance(value, list):
        return bytes([0x90 | len(value)]) + b"".join(pack(item) for item in value)
    raise EvidenceError("pack value")


SIGNER = bytes(range(0x30, 0x44))
TARGET = bytes(range(0x60, 0x74))
TARGET_TEXT = "0x" + TARGET.hex()
SIGNER_TEXT = "0x" + SIGNER.hex()


def vote(action):
    return pack({"a": action, "c": TARGET_TEXT})


def wire_profile(**edits):
    row = {"node_ip": {"Ip": "9.8.7.6"}, "name": "alpha", "description": "beta", "delegations_disabled": True, "commission_bps": 123, "signer": SIGNER_TEXT}
    row.update(edits)
    return {key: item for key, item in row.items() if item != "absent"}


def register_want(node="ip=09080706", disabled=1, commission=123, wei=0x1234, unjailed=1):
    return ("ok", "register", "name=alpha", "description=beta", "commission_bps=%d" % commission, "signer=" + SIGNER.hex(), "node_ip=" + node, "delegations_disabled=%d" % disabled, "initial_wei=%d" % wei, "unjailed=%d" % unjailed, "c=" + TARGET.hex())


def change_want(node="nil", name="nil", description="nil", unjailed=0, disable=2, commission="nil", signer="nil"):
    return ("ok", "changeProfile", "node_ip=" + node, "name=" + name, "description=" + description, "unjailed=%d" % unjailed, "disable_delegations=%d" % disable, "commission_bps=" + commission, "signer=" + signer, "c=" + TARGET.hex())


def vote_cases():
    listing = "unknown variant `nope`, expected one of `register`, `changeProfile`, `unregister`"
    out = []

    def add(name, data, want):
        out.append(Case("cvalidator_" + name, "CValidatorAction", "vote", data, want))

    full = {"profile": wire_profile(), "unjailed": True, "initial_wei": 0x1234}
    add("unregister_text", vote("unregister"), ("ok", "unregister", "c=" + TARGET.hex()))
    add("unregister_map_nil", vote({"unregister": None}), ("ok", "unregister", "c=" + TARGET.hex()))
    add("register_full", vote({"register": full}), register_want())
    add("register_jailed", vote({"register": dict(full, unjailed=False)}), register_want(unjailed=0))
    add("register_zero_wei", vote({"register": dict(full, initial_wei=0)}), register_want(wei=0))
    add("register_top_wei", vote({"register": dict(full, initial_wei=MASK[8])}), register_want(wei=MASK[8]))
    add("register_local_node", vote({"register": dict(full, profile=wire_profile(node_ip={"LocalNode": 7}))}), register_want(node="local=7"))
    add("register_default_commission", vote({"register": dict(full, profile=wire_profile(commission_bps="absent"))}), register_want(commission=10000))
    add("register_default_disabled", vote({"register": dict(full, profile=wire_profile(delegations_disabled="absent"))}), register_want(disabled=0))
    add("register_seq", vote({"register": [full["profile"], True, 0x1234]}), register_want())
    add("register_missing_profile", vote({"register": {"unjailed": True, "initial_wei": 1}}), ("error", "missing field `profile`"))
    add("register_unjailed_absent_is_false", vote({"register": {"profile": wire_profile(), "initial_wei": 0x1234}}), register_want(unjailed=0))
    add("register_missing_wei", vote({"register": {"profile": wire_profile(), "unjailed": True}}), ("error", "missing field `initial_wei`"))
    add("register_unknown_key", vote({"register": dict(full, extra=1)}), ("error", "unknown field `extra`, expected one of `profile`, `unjailed`, `initial_wei`"))
    add("register_missing_signer", vote({"register": dict(full, profile=wire_profile(signer="absent"))}), ("error", "missing field `signer`"))
    add("register_empty_seq", vote({"register": []}), ("error", "invalid length 0, expected struct variant CValidatorAction::Register with 3 elements"))
    add("change_empty", vote({"changeProfile": {}}), change_want())
    add("change_all_nil", vote({"changeProfile": {"node_ip": None, "name": None, "description": None, "disable_delegations": None, "commission_bps": None, "signer": None}}), change_want())
    add("change_full", vote({"changeProfile": {"node_ip": {"Ip": "5.6.7.8"}, "name": "nn", "description": "ee", "unjailed": True, "disable_delegations": False, "commission_bps": 88, "signer": SIGNER_TEXT}}), change_want(node="ip=05060708", name="nn", description="ee", unjailed=1, disable=0, commission="88", signer=SIGNER.hex()))
    add("change_name", vote({"changeProfile": {"name": "nn"}}), change_want(name="nn"))
    add("change_empty_name", vote({"changeProfile": {"name": ""}}), change_want(name=""))
    add("change_description", vote({"changeProfile": {"description": "ee"}}), change_want(description="ee"))
    add("change_commission_zero", vote({"changeProfile": {"commission_bps": 0}}), change_want(commission="0"))
    add("change_disable_true", vote({"changeProfile": {"disable_delegations": True}}), change_want(disable=1))
    add("change_local_node", vote({"changeProfile": {"node_ip": {"LocalNode": 3}}}), change_want(node="local=3"))
    add("change_signer", vote({"changeProfile": {"signer": SIGNER_TEXT}}), change_want(signer=SIGNER.hex()))
    add("change_unjailed_nil_refused", vote({"changeProfile": {"unjailed": None}}), ("error", "invalid type: unit value, expected a boolean"))
    add("change_unknown_key", vote({"changeProfile": {"c": 1}}), ("error", "unknown field `c`, expected one of `node_ip`, `name`, `description`, `unjailed`, `disable_delegations`, `commission_bps`, `signer`"))
    add("change_profile_key_name_refused", vote({"changeProfile": {"delegations_disabled": True}}), ("error", "unknown field `delegations_disabled`, expected one of `node_ip`, `name`, `description`, `unjailed`, `disable_delegations`, `commission_bps`, `signer`"))
    add("change_bad_signer", vote({"changeProfile": {"signer": "0xab"}}), ("error", "invalid length 2, expected " + ADDRESS_TEXT))
    add("change_commission_text", vote({"changeProfile": {"commission_bps": "x"}}), ("kind", 2))
    add("unknown_variant", vote({"nope": None}), ("error", listing))
    add("seq_action", vote([]), ("error", "invalid type: sequence, expected variant identifier"))
    add("missing_a", pack({"c": TARGET_TEXT}), ("error", "missing field `a`"))
    add("missing_c", pack({"a": "unregister"}), ("error", "missing field `c`"))
    add("bad_c", pack({"a": "unregister", "c": 1}), ("error", "invalid type: integer `1`, expected " + ADDRESS_TEXT))
    add("unknown_key_ignored", pack({"a": "unregister", "c": TARGET_TEXT, "d": 1}), ("ok", "unregister", "c=" + TARGET.hex()))
    add("text_root", pack("x"), ("error", 'invalid type: string "x", expected struct variant VoteGlobalAction::CValidator'))
    add("integer_root", pack(5), ("error", "invalid type: integer `5`, expected struct variant VoteGlobalAction::CValidator"))
    add("seq_root", pack(["unregister", TARGET_TEXT]), ("ok", "unregister", "c=" + TARGET.hex()))
    add("short_seq_root", pack(["unregister"]), ("error", "invalid length 1, expected struct variant VoteGlobalAction::CValidator with 2 elements"))
    return out


FORMS = ("compact", "pretty", "pack_named", "pack_array", "buffer_named", "buffer_array")


def write_cases():
    out = []
    for name, shape in SHAPES.items():
        for form in FORMS:
            if form.split("_")[0] not in shape.writers:
                continue
            for seed in (1, 2, 3):
                values = values_of(shape, seed)
                out.append(Case("%s_write_%s_%d" % (name.lower(), form, seed), name, "write", None, spec_write(shape, form, values), None, form, values))
            values = dict(values_of(shape, 4))
            for key, kind in shape.fields:
                if kind == "u64":
                    values[key] = MASK[8]
                elif kind == "quantity":
                    values[key] = 2 ** 256 - 1
            out.append(Case("%s_write_%s_top" % (name.lower(), form), name, "write", None, spec_write(shape, form, values), None, form, values))
    return out


def rule_cases():
    out = []
    for name in SHAPES:
        cases = shape_cases(name)
        for case in cases:
            out.append(case)
            want = ("error", "invalid type: unit value, expected u64") if case.name.endswith("_unit") else case.want
            twin = Case(case.name + "_inline", case.shape, case.mode, case.data, want, SHAPES[name].readers[1])
            out.append(twin)
    for case in profile_cases():
        out.append(case)
        out.append(Case(case.name + "_inline", case.shape, case.mode, case.data, case.want, PROFILE_READERS[1]))
    return out + vote_cases() + write_cases()


class Draw:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return self.state ^ (self.state >> 29)

    def below(self, limit):
        return self.next() % limit

    def data(self, size):
        return bytes(self.next() & 0xFF for _ in range(size))


def draw_values(draw, shape):
    out = {}
    for key, kind in shape.fields:
        if kind == "quantity":
            out[key] = (draw.next() << draw.below(190)) & (2 ** 256 - 1) or 1
        elif kind in ENUMS:
            out[key] = ENUMS[kind][draw.below(len(ENUMS[kind]))]
        elif kind == "address":
            out[key] = draw.data(20)
        elif kind == "hash":
            out[key] = draw.data(32)
        elif kind == "u64":
            out[key] = draw.next() >> draw.below(64)
        elif kind == "bool":
            out[key] = bool(draw.below(2))
        else:
            out[key] = "".join(chr(0x61 + draw.below(26)) for _ in range(draw.below(40)))
    return out


def vector_cases(count):
    draw = Draw(0x5A17)
    out = []
    names = list(SHAPES)
    for index in range(count):
        name = names[index % len(names)]
        shape = SHAPES[name]
        values = draw_values(draw, shape)
        if index % 2 == 0:
            entry = shape.readers[index // 2 % len(shape.readers)]
            out.append(Case("vector_%d" % index, name, "read", tree_of(shape, values), ("ok",) + wanted_values(shape, values), entry))
        else:
            forms = [form for form in FORMS if form.split("_")[0] in shape.writers] or None
            if forms is None:
                out.append(Case("vector_%d" % index, name, "read", seq_of(shape, values), ("ok",) + wanted_values(shape, values)))
            else:
                form = forms[draw.below(len(forms))]
                out.append(Case("vector_%d" % index, name, "write", None, spec_write(shape, form, values), None, form, values))
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


def check_all(harness, cases):
    out = []
    for case in cases:
        got = run_case(harness, case)
        if got != case.want:
            raise EvidenceError("%s: got %r want %r" % (case.name, got, case.want))
        out.append((case, got))
    return out


VOTE_WRITERS = dict(pack=0x2346860, buffer=0x2347960, pretty=0x2347F90)
VOTE_FORMS = ("pack_named", "pack_array", "buffer_named", "buffer_array", "pretty")
RANGES = ((0x190D000, 0x1910000), (0x1BF5000, 0x1BF8000), (0x2346000, 0x234A000))
SAMPLE = 1
MUTANT_CASES = 12
WORKERS = 3
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a spill slot, a register choice or a word no rule reads"
MUTANT_STATE = {}


def node_wire(kind, value, human):
    if kind == "ip":
        return {"Ip": ".".join(str(byte) for byte in value) if human else list(value)}
    return {"LocalNode": value}


def vote_write(harness, data, form):
    if read_vote(harness, data)[0] != "ok":
        raise EvidenceError("writer sample refused")
    sink = setup_writer(harness, SHAPES["CDepositAction"], form)
    action = DECODED + ACTION_BASE
    if form == "pretty":
        harness.machine.run(VOTE_WRITERS["pretty"], {RDI: action, RSI: SERIALIZER})
        harness.expect(harness.machine.regs[RAX] == 0, "json writer status")
    else:
        harness.machine.run(VOTE_WRITERS[form.split("_")[0]], {RDI: OUT, RSI: action, RDX: SERIALIZER})
        harness.expect(harness.read(OUT) == STATUS_OK, "msgpack writer status")
    return ("ok", harness.data(harness.read(sink + 8), harness.read(sink + 0x10)).hex())


def vote_spec(row, form):
    human = form == "pretty"

    def out(value):
        if isinstance(value, dict) and value.get("node"):
            return node_wire(value["node"], value["value"], human)
        if isinstance(value, dict):
            return collections.OrderedDict((key, out(item)) for key, item in value.items())
        return value

    def packed(value):
        if isinstance(value, dict):
            if form.endswith("array") and "\0keep" not in value and not (len(value) == 1 and next(iter(value)) in ("register", "changeProfile", "Ip", "LocalNode")):
                return b"".join([bytes([0x90 | len(value)])] + [packed(item) for item in value.values()])
            return bytes([0x80 | len(value)]) + b"".join(pack_text(key.encode()) + packed(item) for key, item in value.items())
        if isinstance(value, list):
            return bytes([0x90 | len(value)]) + b"".join(packed(item) for item in value)
        return pack(value)

    value = out(row)
    if human:
        return ("ok", json.dumps(value, indent=2, separators=(",", ": ")).encode().hex())
    return ("ok", packed(value).hex())


def vote_rows():
    profile = collections.OrderedDict((("node_ip", dict(node="ip", value=bytes((9, 8, 7, 6)))), ("name", "alpha"), ("description", "beta"), ("delegations_disabled", True), ("commission_bps", 123), ("signer", SIGNER_TEXT)))
    local = collections.OrderedDict(profile, node_ip=dict(node="local", value=7))
    plain = lambda row: collections.OrderedDict((key, ({"LocalNode": item["value"]} if item["node"] == "local" else {"Ip": ".".join(str(byte) for byte in item["value"])}) if isinstance(item, dict) else item) for key, item in row.items())
    empty = collections.OrderedDict((key, None) for key in CHANGE_KEYS)
    full = collections.OrderedDict((("node_ip", dict(node="ip", value=bytes((5, 6, 7, 8)))), ("name", "nn"), ("description", "ee"), ("unjailed", True), ("disable_delegations", False), ("commission_bps", 88), ("signer", SIGNER_TEXT)))
    rows = [("unregister", "unregister", "unregister"),
            ("register", {"register": {"profile": plain(profile), "unjailed": True, "initial_wei": 0x1234}}, {"register": collections.OrderedDict((("profile", profile), ("unjailed", True), ("initial_wei", 0x1234)))}),
            ("register_local", {"register": {"profile": plain(local), "unjailed": False, "initial_wei": 7}}, {"register": collections.OrderedDict((("profile", local), ("unjailed", False), ("initial_wei", 7)))}),
            ("change_empty", {"changeProfile": {}}, {"changeProfile": collections.OrderedDict(empty, unjailed=False)}),
            ("change_full", {"changeProfile": plain(full)}, {"changeProfile": full})]
    return rows


def vote_write_cases():
    out = []
    for label, action, shown in vote_rows():
        data = vote(action)
        for form in VOTE_FORMS:
            out.append(Case("cvalidator_write_%s_%s" % (label, form), "CValidatorAction", "vote_write", data, vote_spec(shown, form), None, form))
    return out


base_rule_cases = rule_cases


def rule_cases():
    return base_rule_cases() + vote_write_cases()


base_run_case = run_case


def run_case(harness, case):
    if case.mode == "vote_write":
        return vote_write(harness, case.data, case.form)
    return base_run_case(harness, case)


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


def field_rows():
    rows = []
    for name, shape in SHAPES.items():
        for index, (key, kind) in enumerate(shape.fields):
            rows.append((name, index, key, kind, "%#x" % shape.offsets[key]))
    return rows


def root_rows():
    rows = []
    for name, shape in SHAPES.items():
        readers = shape.readers
        rows.append((name, shape.tag, "%#x" % readers[0], "%#x" % readers[1], " ".join("%#x" % at for at in readers[2:]), " ".join("%s %#x" % (form, shape.writers[form]) for form in sorted(shape.writers)) or "not found", "offset %#x size %d value %#x" % shape.marker, "%#x" % shape.error_at))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for name, shape in SHAPES.items():
        picked = [case for case in cases if case.shape == name and case.mode == "read" and case.entry is None]
        for copy in shape.readers[2:]:
            for case in picked:
                twin = Case(case.name, case.shape, case.mode, case.data, case.want, copy)
                got = run_case(harness, twin)
                if got != case.want and not (case.name.endswith("_unit") and got == ("error", "invalid type: unit value, expected u64")):
                    raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
            rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, name, "content reader", len(picked)))
        for table in shape.writer_copies:
            for form in FORMS:
                if form.split("_")[0] not in table:
                    continue
                values = values_of(shape, 2)
                if write_action(harness, shape, form, values, table) != spec_write(shape, form, values):
                    raise EvidenceError("writer copy differs for %s" % name)
            for key, at in sorted(table.items()):
                rows.append(("%#x" % at, image.exact_fde(at)[1] - at, name, key + " writer", 2 if key != "pretty" and key != "compact" else 1))
    picked = [case for case in cases if case.mode == "profile" and case.entry is None]
    for copy in PROFILE_READERS[2:]:
        for case in picked:
            twin = Case(case.name, case.shape, case.mode, case.data, case.want, copy)
            if run_case(harness, twin) != case.want:
                raise EvidenceError("copy %#x differs on %s" % (copy, case.name))
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, "CValidatorProfile", "content reader", len(picked)))
    return rows


def targets_of(image, seen):
    found = {}
    for name, shape in SHAPES.items():
        found[shape.readers[0]] = name + "_boxed_error_reader"
        found[shape.readers[1]] = name + "_inline_error_reader"
        for form, at in shape.writers.items():
            found.setdefault(at, ("CDepositCWithdrawAction" if at in (0x1E88610, 0x1E889E0, 0x1E88460, 0x1E88C30) else name) + "_%s_writer" % form)
    found[PROFILE_READERS[0]] = "CValidatorProfile_boxed_error_reader"
    found[PROFILE_READERS[1]] = "CValidatorProfile_inline_error_reader"
    found[VOTE_ENTRY] = "VoteGlobalCValidator_msgpack_reader"
    for form, at in VOTE_WRITERS.items():
        found[at] = "CValidatorAction_%s_writer" % form
    for va in seen:
        if any(low <= va < high for low, high in RANGES):
            start = image.fde(va)[0]
            found.setdefault(start, "nested_%x" % start)
    return found


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = rule_cases()
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
    for name, shape in SHAPES.items():
        for form in FORMS:
            if form.split("_")[0] in shape.writers:
                wire.append(("%s_%s" % (name, form), spec_write(shape, form, values_of(shape))[1]))
    for case in vote_write_cases():
        wire.append((case.name, case.want[1]))
    result = dict(names=names, table=table, named=named, vector_count=len(generated), texts=text_rows(image), fields=field_rows(), roots=root_rows(), copies=copy_rows(image, harness, cases), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in names})
    if mutate:
        result["mutations"] = run_mutants(image, table, cases, reach, cost, harness.machine.cache)
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table, sizes, names = result["table"], result["sizes"], result["names"]
    order = sorted(names)
    tsv("branch-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(names[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in order for row in table[target] if row.op in ("jcc", "set", "cmov")])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(names[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in order])
    tsv("fields.tsv", ("action", "wire_index", "key", "type", "action_offset"), result["fields"])
    tsv("cvalidator-layout.tsv", ("struct", "field", "action_offset", "form"), [(owner, field, "%#x" % at, form) for owner, field, at, form in LAYOUT_ROWS])
    tsv("roots.tsv", ("action", "tag_used_in_cases", "boxed_error_reader", "inline_error_reader", "reader_copies", "writers", "failed_marker", "error_at"), result["roots"])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("copies.tsv", ("copy", "body_bytes", "action", "form", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("case", "hex"), result["wire"])
    rows = []
    for case, trace in result["named"]:
        if trace[0] == "ok":
            rows.append((case.name, case.shape, case.mode, "ok sha256 " + hashlib.sha256("|".join(trace[1:]).encode()).hexdigest()[:16]))
        else:
            rows.append((case.name, case.shape, case.mode, " ".join(str(item) for item in trace)))
    tsv("scenarios.tsv", ("case", "action", "mode", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "actions": len(SHAPES), "functions": len(order), "fields": len(result["fields"]), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "error_cases": sum(1 for _, trace in named if trace[0] in ("error", "kind")), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": sum(row.size for items in table.values() for row in items), "copies": len(result["copies"])}
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
