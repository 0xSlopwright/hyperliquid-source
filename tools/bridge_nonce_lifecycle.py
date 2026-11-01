#!/usr/bin/env python3
"""Evaluate the node #94 action nonce lifecycle from ELF bytes: signed action hosts, the signer gate, the candidate test, retention caps, bundle nonces, proposer reverify and the agent removal prune.

The three signed action hosts, the three gate copies, the candidate test, the signer hash table, the shared set insert and pop, the proposer reverify and the agent removal prune run as real bytes in a Python evaluator.
A separately written rule list predicts each outcome, text, event and final table, and conditions, immediates and offsets of the reached rows are flipped to show the run can tell.
Tables, names and call sites are read from section bytes. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
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
HANDLERS = ROOT / "research" / "work-items" / "RE-010-exchange-handlers" / "exchange-dispatch.json"

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_BCMP = 0x576E378
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_REALLOC = 0x576E030
SLOT_MEMSET = 0x576E1F8
SLOT_SMALL = 0x576E290
SLOT_ALIGNED = 0x576E298
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E020, 0x576E118, 0x576E1B0, 0x576E098, 0x576E468, 0x576EB38)
SLOT_PANIC_TEXT = 0x576E468
SLOT_VALIDATE = 0x5774DC8
SLOT_ADMIT = 0x5774360
SLOT_WEIGHT = 0x57739C0
SLOT_ALLOWED = 0x57739C8
SLOT_ASSETS = 0x57739D0
SLOT_DONE = 0x5773238
SLOT_UTC_NOW = 0x576E8A0
SLOT_REHASH = 0x57736E8
SLOT_LIST = 0x5773228
SLOT_PRUNE = 0x5773A68
EMPTY_TABLE = 0x5732CE8

GATES = (0x4D9B6B0, 0x4D9B820, 0x2767BB0)
VALIDATE = 0x3986CC0
LOOKUP = 0x379AE30
INSERT = 0x3577AE0
HASHER = 0x399C7A0
SET_INSERT = (0x49400F0, 0x49400F0, 0x2863EF0)
SET_POP = (0x4946CC0, 0x4946CC0, 0x2869060)
LIST = 0x37E4FB0
PRUNE = 0x3422CE0
PRUNE_COLLECT = 0x37A0860
DRAIN = 0x33BA840
BUNDLE_HOSTS = (0x42E4600, 0x42E5D40, 0x2209D40)
STATUS_TAGS = (0xC1, 0xC6, 0xC7, 0xCA, 0x111, 0x158, 0x186)
BOUND_TIMES = (1700000000123, 1704067199999, 1709208000000, 951782400000, 172800001, 4102444800000)
MUTANT_STEP_LIMIT = 40000
MUTANT_CASES = 8
MUTANT_CASE_COST = 9000
WORKERS = 4
SET_ITER = 0x33B1E80
SET_DROP = 0x33F4320
REMOVAL_DROP = 0x33F3FC0

STATUS_OK = 0x186
STATUS_NONCE = 0xC6
STATUS_DUPLICATE = 0xC7
STATUS_TABLE = 0x59A8D0
DAY_MS = 86400000

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
USED = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000

HEAP_FREE = HEAP_BASE + 0x40000
OUT_AT = HEAP_BASE + 0x1000
ADDRESS_AT = HEAP_BASE + 0x2000
TIME_AT = HEAP_BASE + 0x2100
KEY_AT = HEAP_BASE + 0x2140
STATE_AT = HEAP_BASE + 0x10000
GATE_MAP = (0x41E0, 0x3760, 0x3760)
GATE_COUNT = (0x12E8, 0x868, 0x868)

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

    def rodata_bytes(self):
        data = self.named[".rodata"]
        return data["address"], bytes(self.blob[data["offset"]:data["offset"] + data["size"]])

    def text_bytes(self):
        text = self.named[".text"]
        return text["address"], bytes(self.blob[text["offset"]:text["offset"] + text["size"]])

    def relocations(self):
        """Yield (slot, type, addend, symbol index) for .rela.dyn."""
        rela = self.named[".rela.dyn"]
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            yield slot, info & 0xFFFFFFFF, addend, info >> 32

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/", "/base/", "/chrono-"):
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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {0: "rol", 4: "shl", 5: "shr", 7: "sar"}


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
        elif byte not in (0x2E, 0x64):
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
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x90:
        return finish("nop")
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
            return finish("pushi", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
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
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0xFB, True): "psubq", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
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
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, width)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
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
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0x3F
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
        if two == 0xBD and not rep:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
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
        self.tails = {}
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.watch = {}

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
        self.keep_rdx = self.keep_float = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        kept = self.xmm[0]
        self.xmm = [POISON | POISON << 64] * 16
        if self.keep_float:
            self.xmm[0] = kept

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
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                if self.read_code(pc, 1)[0] == 0x64:
                    raise Halt("thread local read at %#x" % pc)
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
        elif op == "pushi":
            self.push(self.get(row.a, 8))
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            right = self.get(row.a, 8)
            right = right - (1 << 64) if right & SIGN[8] else right
            product = (left * right) & ((1 << 128) - 1)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
        elif op == "jmp":
            hook = self.tails.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                if target in self.watch:
                    self.watch[target](self)
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.call_site = row.va
            self.call_target = target
            self.stub(hook)
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            if target not in self.real:
                raise Halt("indirect jump out of the text at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
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
        elif op in ("shl", "shr", "sar", "rol"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "shl":
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
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            left, right = self.get(row.a, width), self.get(row.b, width)
            left = left - (1 << (8 * width)) if left & SIGN[width] else left
            right = right - (1 << (8 * width)) if right & SIGN[width] else right
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "shld":
            count = row.target
            if count:
                self.put(row.a, width, self.get(row.a, width) << count | self.get(row.b, width) >> (8 * width - count))
        elif op == "bswap":
            self.regs[row.a[1]] = int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big")
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
                self.xmm[row.a[1]] = self.low(row.b) if row.b[0] != "r" else self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "cmpeqsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], MASK[8] if left == right else 0)
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
            elif op == "divsd":
                result = left / right if right else math.copysign(math.inf, left) * math.copysign(1.0, right) if left == left and left else math.nan
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
        elif op == "andnpd":
            self.xmm[row.a[1]] = (~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * at)) & 0xFF) | ((right >> (8 * at)) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = sum(((source >> (16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source >> 64) << 64 | words
        elif op == "pshufd":
            source = self.vector(row.b)
            self.xmm[row.a[1]] = sum(((source >> (32 * ((row.target >> (2 * at)) & 3))) & MASK[4]) << (32 * at) for at in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            bits = 8 * size
            self.xmm[row.a[1]] = sum((MASK[size] if (left >> at) & MASK[size] == (right >> at) & MASK[size] else 0) << at for at in range(0, 128, bits))
        elif op == "pmovmskb":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, sum(((source >> (8 * at + 7)) & 1) << at for at in range(16)))
        elif op == "tzcnt":
            value = self.get(row.b, row.width)
            result = 8 * row.width if value == 0 else (value & -value).bit_length() - 1
            self.cf = value == 0
            self.zf = result == 0
            self.put(row.a, row.width, result)
        elif op == "bsr":
            value = self.get(row.b, row.width)
            self.zf = value == 0
            if value:
                self.put(row.a, row.width, value.bit_length() - 1)
        elif op == "psubq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left - right) & MASK[8]) | ((((left >> 64) - (right >> 64)) & MASK[8]) << 64)
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left >> (64 * (row.target & 1))) & MASK[8]) | (((right >> (64 * ((row.target >> 1) & 1))) & MASK[8]) << 64)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# ---- harness: real bytes through .text; the allocator and memory slots are hooked, the hash table starts empty and grows by its own real code ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


def body_rows(image, begin, end):
    """Linear rows of a body up to the first opcode the decoder has no form for."""
    base = image.offset(begin)
    data = image.blob[base:base + (end - begin) + 16]

    def read(va, count):
        return data[va - begin:va - begin + count]

    rows = []
    va = begin
    while va < end:
        try:
            row = decode(read, va)
        except EvidenceError:
            break
        rows.append(row)
        va = row.next
    return rows


class Layout:
    """B-tree node layout: key offset, key size, value offset, value size, count offset, leaf size."""

    def __init__(self, name, key_at, key_size, value_at, value_size, parent_at, index_at, count_at, leaf):
        self.name = name
        self.key_at = key_at
        self.key_size = key_size
        self.value_at = value_at
        self.value_size = value_size
        self.parent_at = parent_at
        self.index_at = index_at
        self.count_at = count_at
        self.leaf = leaf


NONCES = Layout("nonce set", 8, 8, 0, 0, 0, 0x60, 0x62, 0x68)
LAYOUTS = (NONCES,)


def days_from_civil(year, month, day):
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def is_leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def year_flags(year):
    weekday = (days_from_civil(year, 1, 1) + 4) % 7  # 0 is Sunday
    low = {0: 5, 6: 4, 5: 3, 4: 2, 3: 1, 2: 7, 1: 6}[weekday]
    return low | (0 if is_leap(year) else 8)


def naive_time(ms):
    """Twelve byte date time words for a Unix millisecond value: date word, seconds of day, nanoseconds."""
    days, rest = divmod(ms, DAY_MS)
    seconds, millis = divmod(rest, 1000)
    year = 1970 + days // 366 - 1
    while days_from_civil(year + 1, 1, 1) <= days:
        year += 1
    while days_from_civil(year, 1, 1) > days:
        year -= 1
    ordinal = days - days_from_civil(year, 1, 1) + 1
    return struct.pack("<iII", (year << 13) | (ordinal << 4) | year_flags(year), seconds, millis * 1000000)


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare,
                 SLOT_REALLOC: self.on_realloc, SLOT_MEMSET: self.on_fill, SLOT_ALIGNED: self.on_aligned, SLOT_SMALL: self.on_small}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {}
        machine.tails = machine.calls
        machine.slots[relative.setdefault(SLOT_UTC_NOW, SLOT_UTC_NOW)] = self.on_utc_now
        install_host_stubs(self)
        machine.watch = {}
        self.tally = collections.Counter()
        self.panic_text = ""
        self.utc_now = bytes(12)
        self.reset()

    def reset(self):
        self.machine.memory.reset(USED)
        self.brk = HEAP_FREE
        self.live = {}
        self.events = []

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + USED:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x80000:
            raise Halt("allocation size %#x" % size)
        m.regs[RAX] = self.allocate(size)

    def on_aligned(self, m):
        m.regs[RAX] = self.allocate(m.regs[RSI])

    def on_small(self, m):
        m.regs[RAX] = self.allocate(m.regs[RDI])

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if at not in self.live:
            raise Halt("free %#x size %#x" % (at, size))
        del self.live[at]

    def on_realloc(self, m):
        regs = m.regs
        old, new = regs[RDI], regs[RSI]
        if old not in self.live:
            raise Halt("realloc %#x" % old)
        size = self.live.pop(old)
        at = self.allocate(new)
        m.memory.copy(at, old, min(size, new))
        regs[RAX] = at

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x80000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_fill(self, m):
        regs = m.regs
        if regs[RDX] > 0x80000:
            raise Halt("fill size")
        m.memory.put_bytes(regs[RDI], bytes([regs[RSI] & 0xFF]) * regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, m):
        regs = m.regs
        left = m.memory.bytes_at(regs[RDI], regs[RDX])
        right = m.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_utc_now(self, m):
        m.memory.put_bytes(m.regs[RDI], self.utc_now)

    def on_nothing(self, m):
        pass

    def on_admit(self, m):
        record = self.pending[self.index]
        m.regs[RAX] = int(record.admit)

    def on_weight(self, m):
        m.regs[RAX] = self.pending[self.index].weight
        m.regs[RDX] = 0

    def on_budget(self, m):
        address = m.memory.bytes_at(m.regs[RSI], 20)
        self.events.append(("budget", address.hex()))
        if address not in self.rows:
            at = self.allocate(0x40)
            m.memory.put_bytes(at, bytes(0x40))
            self.rows[address] = at
        m.regs[RAX] = self.rows[address]

    def on_allowed(self, m):
        m.regs[RAX] = int(self.pending[self.index].allowed)

    def on_assets(self, m):
        m.memory.write(m.regs[RDI], 4, 0)

    def on_broadcaster(self, m):
        self.events.append(("broadcaster", m.memory.bytes_at(m.regs[RSI], 20).hex()))

    def on_status(self, m):
        self.events.append(("status", m.memory.read(m.regs[RSI], 2)))
        m.memory.put_bytes(m.regs[RDI], bytes(0x18))
        self.index += 1

    def on_reply(self, m):
        self.events.append(("reply", m.memory.read(m.regs[RSI], 2), m.regs[RDX] & 0xFF))
        m.memory.put_bytes(m.regs[RDI], bytes(0x18))
        self.index += 1

    def on_error_drop(self, m):
        self.events.append(("error drop",))

    def on_bundle_drop(self, m):
        self.events.append(("bundle drop", m.memory.read(m.regs[RDI], 2)))

    def on_exec(self, m):
        record = self.pending[self.index]
        regs = m.regs
        out = regs[RDI]
        stack = regs[RSP]
        self.events.append(("exec", m.memory.bytes_at(regs[RDX], 20).hex(), m.memory.read(regs[RCX] + 0x138, 8), regs[R9] == 1, m.memory.read(stack + 8, 8) if regs[R9] == 1 else 0))
        m.memory.put_bytes(out, bytes(0x60))
        m.memory.write(out, 1, record.done)
        if record.done == 0xE:
            m.memory.write(out + 8, 2, 0x77)

    def on_done(self, m):
        self.events.append(("done", m.regs[RDX] & 0xFF))
        m.memory.put_bytes(m.regs[RDI], bytes(0x20))
        m.memory.write(m.regs[RDI], 1, m.memory.read(m.regs[RSI], 1))
        self.index += 1

    def run_range(self, entry, stop, regs):
        machine = self.machine
        machine.regs = [POISON] * 16
        for reg, value in regs.items():
            machine.regs[reg] = value
        pc = entry
        limit = machine.step_limit
        cache = machine.cache
        while pc != stop:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                cache[pc] = row
            machine.seen.add(pc)
            machine.steps += 1
            pc = machine.step(row)

    def on_panic(self, m, slot):
        if slot == SLOT_PANIC_TEXT:
            self.panic_text = m.memory.bytes_at(m.regs[RDI], m.regs[RSI]).decode("ascii")
        raise Panicked("%#x" % slot)

    # fixtures and table reads

    def empty_table(self, at, seed=(0x0706050403020100, 0x0F0E0D0C0B0A0908)):
        memory = self.machine.memory
        for offset, word in ((0, self.relative[EMPTY_TABLE]), (8, 0), (0x10, 0), (0x18, 0), (0x20, seed[0]), (0x28, seed[1])):
            memory.write(at + offset, 8, word)

    def walk(self, layout, root, height):
        memory = self.machine.memory
        if not root:
            return []
        rows = []

        def visit(node, level):
            count = memory.read(node + layout.count_at, 2)
            for index in range(count):
                if level:
                    visit(memory.read(node + layout.leaf + 8 * index, 8), level - 1)
                rows.append(memory.bytes_at(node + layout.key_at + layout.key_size * index, layout.key_size))
            if level:
                visit(memory.read(node + layout.leaf + 8 * count, 8), level - 1)
        visit(root, height)
        return rows

    def table_rows(self, at, size):
        """(key, bucket end) rows of a hash table, unordered; size is the bucket size."""
        memory = self.machine.memory
        ctrl, mask = memory.read(at, 8), memory.read(at + 8, 8)
        rows = []
        if mask == 0 and memory.read(at + 0x18, 8) == 0:
            return rows
        for index in range(mask + 1):
            if not memory.bytes_at(ctrl + index, 1)[0] & 0x80:
                end = ctrl - index * size
                rows.append((memory.bytes_at(end - size, 20), end))
        return rows

    def nonce_map(self, at):
        memory = self.machine.memory
        out = {}
        for key, end in self.table_rows(at, 0x30):
            root, height, count = memory.read(end - 0x18, 8), memory.read(end - 0x10, 8), memory.read(end - 8, 8)
            values = [int.from_bytes(raw, "little") for raw in self.walk(NONCES, root, height)]
            if len(values) != count:
                raise Halt("set length differs from its walk")
            out[key] = values
        return out


# ---- rule list: written from the reading, checked against the real run ----

LIST_ADDRESSES = []
ADDRESSES = tuple(bytes([0x10 + index]) * 19 + bytes([index]) for index in range(6))
A, B, C = ADDRESSES[:3]
BASE_NOW = 1700000000123


class Case:
    __slots__ = ("kind", "label", "ops", "copy", "now")

    def __init__(self, kind, label, ops, copy=0, now=BASE_NOW):
        self.kind, self.label, self.ops, self.copy, self.now = kind, label, ops, copy, now


def ms_of(now):
    return max(now, 0)


def decide(now, flag, nonce, values):
    """Outcome of the candidate test on a sorted set; the set is read first, then the two time bounds, then duplicates."""
    cap = 400 if flag else 100
    if len(values) >= cap and values and nonce < values[0]:
        return "low", nonce, values[0]
    high = ms_of(now + DAY_MS)
    if nonce > high:
        return "high", nonce, high
    low = ms_of(now - 2 * DAY_MS)
    if nonce < low:
        return "low", nonce, low
    if nonce in values:
        return "duplicate", nonce
    return "ok", cap


def apply_gate(sets, counters, now, address, flag, nonce):
    """One gate call; a first sight of the address leaves an empty set even when the nonce fails."""
    values = sets.setdefault(address, [])
    counters[0] += 1
    verdict = decide(now, flag, nonce, values)
    if verdict[0] == "ok":
        bisect.insort(values, nonce)
        del values[:max(len(values) - verdict[1], 0)]
        counters[1] += 1
    return verdict


def read_verdict(harness, at):
    memory = harness.machine.memory
    tag = memory.read(at, 2)
    if tag == STATUS_OK:
        return "ok",
    if tag == STATUS_DUPLICATE:
        return "duplicate", memory.read(at + 8, 8)
    if tag == STATUS_NONCE:
        text = memory.bytes_at(memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)).decode("ascii")
        parts = text.split(" ")
        if parts[:2] == ["nonce", "too"] and parts[2] in ("low", "high") and parts[4] == ("<" if parts[2] == "low" else ">"):
            return parts[2], int(parts[3]), int(parts[5])
        raise Halt("error text " + text)
    return "status", tag


def gate_call(harness, copy, address, flag, nonce):
    memory = harness.machine.memory
    memory.put_bytes(ADDRESS_AT, address + filled("after address", 12))
    harness.machine.run(GATES[copy], {RDI: OUT_AT, RSI: STATE_AT, RDX: flag, RCX: ADDRESS_AT, R8: nonce})
    return read_verdict(harness, OUT_AT)


def build_set(harness, values):
    """Balanced node tree over sorted values; returns root, height."""
    memory = harness.machine.memory

    def capacity(level):
        return 11 if level == 0 else 11 + 12 * capacity(level - 1)

    def node(chunk, level):
        if level == 0:
            at = harness.allocate(0x68)
            memory.put_bytes(at, bytes(0x68))
            for index, value in enumerate(chunk):
                memory.write(at + 8 + 8 * index, 8, value)
            memory.write(at + 0x62, 2, len(chunk))
            return at
        parts = 2
        while (len(chunk) - (parts - 1)) / parts > capacity(level - 1) * 0.8:
            parts += 1
        size, extra = divmod(len(chunk) - (parts - 1), parts)
        at = harness.allocate(0xC8)
        memory.put_bytes(at, bytes(0xC8))
        where = 0
        for index in range(parts):
            take = size + (1 if index < extra else 0)
            child = node(chunk[where:where + take], level - 1)
            memory.write(at + 0x68 + 8 * index, 8, child)
            memory.write(child, 8, at)
            memory.write(child + 0x60, 2, index)
            where += take
            if index < parts - 1:
                memory.write(at + 8 + 8 * index, 8, chunk[where])
                where += 1
        memory.write(at + 0x62, 2, parts - 1)
        return at
    level = 0
    while capacity(level) < len(values):
        level += 1
    return node(list(values), level), level


def seed_set(harness, map_at, address, values, model):
    """Fill one bucket of the real table: the first value passes the real gate shape through a table insert, then the node tree is installed."""
    memory = harness.machine.memory
    for key, end in harness.table_rows(map_at, 0x30):
        if key == address:
            root, height = build_set(harness, values)
            memory.write(end - 0x18, 8, root)
            memory.write(end - 0x10, 8, height)
            memory.write(end - 8, 8, len(values))
            model[address] = list(values)
            return
    raise Halt("seed of an absent key")


def filled(name, size):
    """Distinct bytes for a field no rule reads, so a wrong offset shows."""
    seed = hashlib.sha256(name.encode()).digest()
    return (seed * (size // 32 + 1))[:size]


def compare_gate(harness, case):
    machine = harness.machine
    memory = machine.memory
    copy = case.copy
    harness.reset()
    map_at = STATE_AT + GATE_MAP[copy]
    memory.put_bytes(STATE_AT, filled("state head", 0x60))
    harness.empty_table(map_at)
    memory.write(STATE_AT + GATE_COUNT[copy], 8, 0)
    memory.write(STATE_AT + GATE_COUNT[copy] + 8, 8, 0)
    model = {}
    counters = [0, 0]
    now = case.now
    memory.put_bytes(STATE_AT + 0x60, naive_time(now))
    for op in case.ops:
        name = op[0]
        if name == "now":
            now = op[1]
            memory.put_bytes(STATE_AT + 0x60, naive_time(now))
        elif name == "seed":
            address, count = op[1], op[2]
            gate_call(harness, copy, address, 0, now)
            apply_gate(model, counters, now, address, 0, now)
            first = op[3] if len(op) > 3 else now
            seed_set(harness, map_at, address, [first + index for index in range(count)], model)
        elif name == "counts":
            memory.write(STATE_AT + GATE_COUNT[copy], 8, op[1])
            memory.write(STATE_AT + GATE_COUNT[copy] + 8, 8, op[2])
            counters[0], counters[1] = op[1], op[2]
        else:
            _, address, flag, nonce = op
            before = {key: list(value) for key, value in model.items()}
            try:
                got = gate_call(harness, copy, address, flag, nonce)
            except Panicked as error:
                if len(op) and case.kind != "panic":
                    return "panic %s" % error
                want = expected_panic(now)
                if harness.panic_text != want:
                    return "panic text %r, want %r" % (harness.panic_text, want)
                harness.tally["panic"] += 1
                return None
            want = apply_gate(model, counters, now, address, flag, nonce)
            harness.tally[want[0]] += 1
            if got != (want[:1] if want[0] == "ok" else want):
                return "%r: got %r, want %r" % (op[2:], got, want)
            if memory.read(STATE_AT + GATE_COUNT[copy], 8) != saturated(counters[0]) or memory.read(STATE_AT + GATE_COUNT[copy] + 8, 8) != saturated(counters[1]):
                return "counters %d %d, want %r" % (memory.read(STATE_AT + GATE_COUNT[copy], 8), memory.read(STATE_AT + GATE_COUNT[copy] + 8, 8), counters)
    found = harness.nonce_map(map_at)
    if found != model:
        return "sets differ: %r" % sorted((key.hex()[:8], len(value), value[:2], key in model and model[key][:2]) for key, value in found.items())
    return None


def saturated(value):
    return min(value, MASK[8])


def expected_panic(now):
    return "`NaiveDateTime + TimeDelta` overflowed" if now > 0 else "`NaiveDateTime - TimeDelta` overflowed"


def compare(harness, _unused, case):
    return COMPARE[case.kind](harness, case)


def gate_cases():
    out = []
    now = BASE_NOW
    day = DAY_MS
    def one(label, ops, copy=0, kind="gate", at=now):
        out.append(Case(kind, label, ops, copy, at))
    for copy in range(3):
        one("first_nonce_makes_set_%d" % copy, [("gate", A, 0, now)], copy)
        one("exact_upper_bound_passes_%d" % copy, [("gate", A, 0, now + day)], copy)
        one("one_above_upper_bound_%d" % copy, [("gate", A, 0, now + day + 1)], copy)
        one("two_days_back_passes_%d" % copy, [("gate", A, 0, now - 2 * day)], copy)
        one("one_below_two_days_%d" % copy, [("gate", A, 0, now - 2 * day - 1)], copy)
        one("one_day_back_passes_%d" % copy, [("gate", A, 0, now - day - 1)], copy)
        one("duplicate_is_0xc7_%d" % copy, [("gate", A, 0, now), ("gate", A, 0, now)], copy)
        one("two_addresses_separate_%d" % copy, [("gate", A, 0, now), ("gate", B, 0, now), ("gate", A, 0, now + 1)], copy)
        one("full_set_below_smallest_%d" % copy, [("seed", A, 100), ("gate", A, 0, now - 1)], copy)
        one("full_set_at_smallest_is_duplicate_%d" % copy, [("seed", A, 100), ("gate", A, 0, now)], copy)
        one("full_set_new_top_evicts_smallest_%d" % copy, [("seed", A, 100), ("gate", A, 0, now + 1000)], copy)
        one("full_set_gap_inside_%d" % copy, [("seed", A, 100, now - 500), ("gate", A, 0, now + 1000), ("gate", A, 0, now - 498)], copy)
        one("cap_400_full_%d" % copy, [("seed", A, 400), ("gate", A, 1, now - 1)], copy)
        one("cap_400_evicts_%d" % copy, [("seed", A, 400), ("gate", A, 1, now + 1000)], copy)
        one("failed_first_nonce_leaves_empty_set_%d" % copy, [("gate", A, 0, now + day + 1)], copy)
        one("empty_set_then_good_%d" % copy, [("gate", A, 0, 0), ("gate", A, 0, now)], copy)
        one("counters_saturate_%d" % copy, [("counts", MASK[8] - 1, MASK[8] - 1), ("gate", A, 0, now), ("gate", A, 0, now + 1), ("gate", A, 0, now + 2)], copy)
        one("evict_many_when_flag_drops_%d" % copy, [("seed", A, 150), ("gate", A, 0, now + 1000)], copy)
        one("flag_ups_cap_keeps_all_%d" % copy, [("seed", A, 100), ("gate", A, 1, now - 1), ("gate", A, 1, now + 1000)], copy)
    for label, ops, at in (
        ("nonce_zero_after_epoch", [("gate", A, 0, 0)], now),
        ("nonce_max_word", [("gate", A, 0, MASK[8])], now),
        ("nonce_sign_bit", [("gate", A, 0, 1 << 63)], now),
        ("early_time_floor_zero", [("gate", A, 0, 0), ("gate", A, 0, 1)], 5),
        ("before_epoch_upper_zero", [("gate", A, 0, 0), ("gate", A, 0, 1)], -3 * day),
        ("just_before_epoch_upper_positive", [("gate", A, 0, day - 1), ("gate", A, 0, day)], -1),
        ("time_moves_window", [("gate", A, 0, now), ("now", now + 3 * day), ("gate", A, 0, now + 3 * day), ("gate", A, 0, now)], now),
        ("year_end_rollover", [("gate", A, 0, 1704067199999 + day)], 1704067199999),
        ("leap_day", [("gate", A, 0, 1709208000000 - day)], 1709208000000),
        ("leap_century", [("gate", A, 0, 951782400000 + day)], 951782400000),
    ):
        one(label, ops, 0, "gate", at)
    out.append(Case("panic", "date_end_panics_on_add", [("gate", A, 0, 1)], 0, MAX_MS))
    out.append(Case("panic", "date_start_panics_on_subtract", [("gate", A, 0, 1)], 0, MIN_MS))
    rng = random.Random(0x4E4F4E43)
    for index in range(60):
        ops = []
        for _ in range(rng.randint(3, 24)):
            address = rng.choice(ADDRESSES[:3])
            flag = rng.randint(0, 1)
            nonce = now + rng.choice((-3 * day, -2 * day, -2 * day - 1, -1, 0, 1, 2, 3, day, day + 1, rng.randint(-2 * day, day)))
            ops.append(("gate", address, flag, nonce))
        out.append(Case("gate", "random_%d" % index, ops, index % 3))
    return out


COMPARE = {"gate": compare_gate, "panic": compare_gate}
MAX_MS = days_from_civil(262142, 12, 31) * DAY_MS
MIN_MS = days_from_civil(-262143, 1, 1) * DAY_MS
SENTINELS = frozenset(label + "_%d" % copy for copy in range(3) for label in ("exact_upper_bound_passes", "one_above_upper_bound", "two_days_back_passes", "one_below_two_days", "full_set_below_smallest", "cap_400_full", "cap_400_evicts", "duplicate_is_0xc7", "counters_saturate", "evict_many_when_flag_drops",
                       "nonce_key_is_third_address", "expired_burns_nonce_and_five_weights", "expired_equal_now_runs", "reduce_only_second_address_refused", "reduce_only_third_address_runs", "list_user_cap_400", "plain_user_cap_100", "list_key_alone_gives_no_400", "exec_rejected_keeps_nonce", "bundle_duplicate_dropped_list_kept")) | frozenset(("three_agents_mixed", "ready_equal_now_removed", "real_user_keeps_set", "no_user_rows", "row_60_kind_1_refused", "full_set_low_text", "cap_100_not_400", "second_key_found", "before_epoch_upper_zero", "nonce_sign_bit"))


# ---- host loop of signed actions ----

HOSTS = (
    {"entry": 0x444B430, "shift": 0, "exec": 0x4D81290, "budget": 0x47D7CA0, "single": False},
    {"entry": 0x444C310, "shift": 0xA80, "exec": 0x4D81660, "budget": 0x47D7CA0, "single": False},
    {"entry": 0x2208580, "shift": 0xA80, "exec": 0x27584A0, "budget": 0x1F849B0, "single": True},
)
RECORDS_AT = HEAP_BASE + 0x3000
ENV_AT = HEAP_BASE + 0x4000
SUB_AT = HEAP_BASE + 0x2200
OUTS_AT = HEAP_BASE + 0x8000
ROWS_AT = HEAP_BASE + 0xA000
VECTOR_AT = HEAP_BASE + 0x2800
ITER_AT = HEAP_BASE + 0x2900
CONTEXT_AT = HEAP_BASE + 0x2A00
LISTED_AT = HEAP_BASE + 0xC000
LISTED = Layout("twenty byte address set", 8, 0x14, 0, 0, 0, 0xE4, 0xE6, 0xE8)


class Record:
    __slots__ = ("status", "admit", "a1", "a2", "a3", "nonce", "expires", "weight", "allowed", "done")

    def __init__(self, a1=A, a2=B, a3=C, nonce=BASE_NOW, status=STATUS_OK, admit=True, expires=None, weight=3, allowed=True, done=13):
        self.status, self.admit, self.a1, self.a2, self.a3, self.nonce = status, admit, a1, a2, a3, nonce
        self.expires, self.weight, self.allowed, self.done = expires, weight, allowed, done


def host_stub_ids():
    return frozenset(item["exec"] for item in HOSTS) | {0x47D7CA0, 0x1F849B0, 0x492F290, 0x37F3190, 0x3379490, 0x4B011C0, 0x472F840, 0x447CB60, 0x4344430, 0x2249CA0}


def install_host_stubs(harness):
    """Everything after the nonce gate in the host is a stub that records its call: the weight, the listed test, the order path and the replies have packets of their own."""
    machine = harness.machine
    relative = harness.relative
    calls = machine.calls
    for item in HOSTS:
        calls[item["exec"]] = harness.on_exec
        calls[item["budget"]] = harness.on_budget
    calls.update({0x492F290: harness.on_broadcaster, 0x37F3190: harness.on_status, 0x3379490: harness.on_nothing, 0x4B011C0: harness.on_reply, 0x472F840: harness.on_nothing, 0x447CB60: harness.on_error_drop,
                  0x4344430: harness.on_bundle_drop, 0x2249CA0: harness.on_bundle_drop})
    for slot, hook in ((SLOT_ADMIT, harness.on_admit), (SLOT_WEIGHT, harness.on_weight), (SLOT_ALLOWED, harness.on_allowed), (SLOT_ASSETS, harness.on_assets), (SLOT_DONE, harness.on_done)):
        machine.slots[relative[slot]] = hook
    harness.real.stubs = frozenset(machine.slots) | frozenset(calls)


def write_record(harness, index, record):
    memory = harness.machine.memory
    at = RECORDS_AT + index * 0x70
    env = ENV_AT + index * 0x180
    memory.put_bytes(env, filled("envelope %d" % index, 0x170))
    memory.write(env, 8, 0 if record.expires is None else 1)
    memory.write(env + 8, 8, record.expires or 0)
    memory.write(env + 0x148, 8, record.nonce)
    memory.write(at, 8, env)
    memory.write(at + 8, 8, 0x5157000 + index)
    memory.put_bytes(at + 0x10, filled("verify %d" % index, 0x60))
    memory.write(at + 0x10, 2, record.status)
    memory.put_bytes(at + 0x13, record.a1 + record.a2 + record.a3)
    return at, env


def list_member(address):
    return address in LIST_ADDRESSES


def expected_host(case, records, sets, counters, shift):
    """Events of one run from the rule list."""
    events = []
    rows = {}
    results = []
    now = case.now
    single = HOSTS[case.copy]["single"]
    for index, record in enumerate(records):
        env_byte = filled("envelope %d" % index, 0x170)[0x165]
        if not single and not record.admit:
            events.append(("broadcaster", SUB_ADDRESS.hex()))
            events.append(("status", 0xC1))
            if record.status != STATUS_OK:
                events.append(("error drop",))
            results.append(0xE)
            continue
        if record.status != STATUS_OK:
            if not single:
                events.append(("reply", record.status, env_byte))
            results.append(0xE)
            continue
        flag = int(list_member(record.a1))
        verdict = apply_gate(sets, counters, now, record.a3, flag, record.nonce)
        if verdict[0] != "ok":
            status = STATUS_DUPLICATE if verdict[0] == "duplicate" else STATUS_NONCE
            if not single:
                events.append(("reply", status, env_byte))
            results.append(0xE)
            continue
        if record.expires is not None and record.expires < max(now, 0):
            charge(rows, events, record.a1, min(record.weight * 5, MASK[8]))
            if not single:
                events.append(("reply", 0xCA, env_byte))
            results.append(0xE)
            continue
        charge(rows, events, record.a1, record.weight)
        if case.listed and (record.a1 in case.listed or record.a2 in case.listed):
            if not record.allowed:
                if not single:
                    events.append(("reply", 0x111, env_byte))
                results.append(0xE)
                continue
        events.append(("exec", record.a1.hex(), record.nonce, record.expires is not None, record.expires or 0))
        if record.done == 0xE:
            if not single:
                events.append(("reply", 0x77, env_byte))
            results.append(0xE)
        else:
            if not single:
                events.append(("done", env_byte))
            results.append(record.done)
    return events, rows, results


def charge(rows, events, address, amount):
    events.append(("budget", address.hex()))
    rows[address] = min(rows.get(address, 0) + amount, MASK[8])


SUB_ADDRESS = bytes(range(0x30, 0x44))


class HostCase(Case):
    __slots__ = ("records", "listed")

    def __init__(self, label, records, copy=0, now=BASE_NOW, listed=(), ops=()):
        Case.__init__(self, "host", label, ops, copy, now)
        self.records, self.listed = records, sorted(listed)


def compare_host(harness, case):
    if not LIST_ADDRESSES:
        raise EvidenceError("list not read")
    machine = harness.machine
    memory = machine.memory
    host = HOSTS[case.copy]
    shift = host["shift"]
    harness.reset()
    harness.rows = {}
    harness.pending = list(case.records)
    harness.index = 0
    memory.put_bytes(STATE_AT, filled("state head", 0x60))
    memory.write(STATE_AT, 8, 0)
    memory.put_bytes(STATE_AT + 0x60, naive_time(case.now))
    map_at = STATE_AT + GATE_MAP[case.copy]
    harness.empty_table(map_at)
    count = STATE_AT + GATE_COUNT[case.copy]
    memory.write(count, 8, 0)
    memory.write(count + 8, 8, 0)
    memory.write(STATE_AT + 0x1338 - shift, 8, 0)
    memory.write(STATE_AT + 0x1340 - shift, 8, 0)
    memory.write(STATE_AT + 0x4508 - shift, 8, 0)
    memory.write(STATE_AT + 0x1372 - shift, 1, 3)
    if case.listed:
        node = harness.allocate(LISTED.leaf)
        memory.put_bytes(node, bytes(LISTED.leaf))
        for index, key in enumerate(case.listed):
            memory.put_bytes(node + 8 + 20 * index, key)
        memory.write(node + LISTED.count_at, 2, len(case.listed))
        memory.write(STATE_AT + 0x1338 - shift, 8, node)
    memory.put_bytes(SUB_AT, filled("sub head", 0x20) + SUB_ADDRESS + filled("sub tail", 0x20))
    sets = {}
    counters = [0, 0]
    for op in case.ops:
        _, address, size = op
        gate_call(harness, case.copy, address, 0, case.now)
        apply_gate(sets, counters, case.now, address, 0, case.now)
        seed_set(harness, map_at, address, [case.now + index for index in range(size)], sets)
    events, rows, results = expected_host(case, case.records, sets, counters, shift)
    if host["single"]:
        outcome = []
        for index, record in enumerate(case.records):
            at, env = write_record(harness, index, record)
            harness.index = index
            machine.run(host["entry"], {RDI: OUTS_AT, RSI: STATE_AT, RDX: env, RCX: at + 0x10, R8: SUB_AT})
            outcome.append(memory.read(OUTS_AT, 1))
    else:
        for index, record in enumerate(case.records):
            write_record(harness, index, record)
        memory.write(ITER_AT + 8, 8, RECORDS_AT)
        memory.write(ITER_AT + 0x18, 8, RECORDS_AT + 0x70 * len(case.records))
        memory.write(CONTEXT_AT, 8, STATE_AT)
        memory.write(CONTEXT_AT + 8, 8, SUB_AT)
        memory.write(CONTEXT_AT + 0x10, 8, VECTOR_AT)
        machine.run(host["entry"], {RDI: ITER_AT, RSI: OUTS_AT, RDX: OUTS_AT, RCX: CONTEXT_AT})
        outcome = [memory.read(OUTS_AT + 0x48 * index, 1) for index in range(len(case.records))]
        for index in range(len(case.records)):
            if memory.read(OUTS_AT + 0x48 * index + 0x40, 8) != 0x5157000 + index:
                return "record word %d" % index
        if memory.read(STATE_AT, 8) != (1 if case.records else 0) or memory.read(STATE_AT + 8, 8) != len(case.records):
            return "action count %d %d" % (memory.read(STATE_AT, 8), memory.read(STATE_AT + 8, 8))
    if outcome != results:
        return "results %r, want %r" % (outcome, results)
    if harness.events != events:
        return "events %r, want %r" % (harness.events[:9], events[:9])
    found = harness.nonce_map(map_at)
    if found != sets:
        return "sets differ"
    if memory.read(count, 8) != counters[0] or memory.read(count + 8, 8) != counters[1]:
        return "gate counters"
    now_bytes = naive_time(case.now)
    for address, amount in rows.items():
        row = harness.rows.get(address)
        if row is None or memory.read(row + 8, 8) != amount or memory.bytes_at(row + 0x30, 12) != now_bytes:
            return "budget row of %s" % address.hex()[:8]
    harness.tally[case.kind] += 1
    return None


# ---- signed bundle loop ----

BUNDLE_LOOPS = (
    {"start": 0x42E48DB, "stop": 0x42E4A35, "state": 8, "lists": (0xC8, 0x78)},
    {"start": 0x42E5FEB, "stop": 0x42E614B, "state": 8, "lists": (0xD0, 0x80)},
    {"start": 0x2209FEB, "stop": 0x220A14E, "state": 0, "lists": (0x188, 0x78)},
)
ITEMS_AT = HEAP_BASE + 0x3000
BUNDLES_AT = HEAP_BASE + 0x5000
LIST_A_AT = HEAP_BASE + 0x8000
LIST_B_AT = HEAP_BASE + 0x9000


def compare_bundle(harness, case):
    machine = harness.machine
    memory = machine.memory
    loop = BUNDLE_LOOPS[case.copy]
    harness.reset()
    memory.put_bytes(STATE_AT, filled("state head", 0x60))
    memory.put_bytes(STATE_AT + 0x60, naive_time(case.now))
    map_at = STATE_AT + GATE_MAP[case.copy]
    harness.empty_table(map_at)
    count = STATE_AT + GATE_COUNT[case.copy]
    memory.write(count, 8, 0)
    memory.write(count + 8, 8, 0)
    sets = {}
    counters = [0, 0]
    drops = []
    for index, (address, nonce) in enumerate(case.ops):
        item = ITEMS_AT + 0x28 * index
        bundle = BUNDLES_AT + 0x60 * index
        memory.put_bytes(item, filled("hash %d" % index, 0x20))
        memory.write(item + 0x20, 8, bundle)
        memory.put_bytes(bundle, filled("bundle %d" % index, 0x60))
        memory.write(bundle + 0x28, 8, nonce)
        memory.put_bytes(bundle + 0x30, address)
        verdict = apply_gate(sets, counters, case.now, address, 0, nonce)
        if verdict[0] != "ok":
            drops.append(("bundle drop", STATUS_DUPLICATE if verdict[0] == "duplicate" else STATUS_NONCE))
    frame = STACK_TOP - 0x2000
    memory.write(frame + loop["state"], 8, STATE_AT)
    for at, store in zip(loop["lists"], (LIST_A_AT, LIST_B_AT)):
        memory.write(frame + at, 8, 100)
        memory.write(frame + at + 8, 8, store)
        memory.write(frame + at + 0x10, 8, 0)
    harness.run_range(loop["start"], loop["stop"], {RSP: frame, R14: ITEMS_AT + 0x20, R15: 0x28 * len(case.ops), RBP: 0, R12: 0, RBX: 0})
    if harness.events != drops:
        return "drops %r, want %r" % (harness.events, drops)
    if memory.read(frame + loop["lists"][0] + 0x10, 8) != len(case.ops) or memory.read(frame + loop["lists"][1] + 0x10, 8) != len(case.ops):
        return "list lengths"
    for index in range(len(case.ops)):
        if memory.read(LIST_A_AT + 0x28 * index, 8) != index or memory.bytes_at(LIST_A_AT + 0x28 * index + 8, 0x20) != filled("hash %d" % index, 0x20):
            return "hash list row %d" % index
        if memory.read(LIST_B_AT + 8 * index, 8) != BUNDLES_AT + 0x60 * index + 0x10:
            return "body list row %d" % index
    if harness.nonce_map(map_at) != sets:
        return "sets differ"
    if memory.read(count, 8) != counters[0] or memory.read(count + 8, 8) != counters[1]:
        return "counters"
    harness.tally[case.kind] += 1
    return None


# ---- proposer reverify ----

SIGNED_MAP = Layout("signer to nonce set", 0x110, 0x14, 8, 0x18, 0, 0x1EC, 0x1EE, 0x1F0)
VIEW_AT = HEAP_BASE + 0x2C00
BUNDLE_AT = HEAP_BASE + 0x2D00
HASH_AT = HEAP_BASE + 0x2E00
ACTIONS_AT = HEAP_BASE + 0x6000
REVERIFY = 0x45485A0
TAG_REFUSED = 0x8000000000000026
TAG_PASSED = 0x800000000000002A


def compare_reverify(harness, case):
    machine = harness.machine
    memory = machine.memory
    spec = case.ops[0]
    harness.reset()
    harness.utc_now = naive_time(case.now)
    node = harness.allocate(SIGNED_MAP.leaf)
    memory.put_bytes(node, bytes(SIGNED_MAP.leaf))
    keys = sorted(spec["nonces"])
    for index, key in enumerate(keys):
        memory.put_bytes(node + 0x110 + 0x14 * index, key)
        values = spec["nonces"][key]
        root, height = build_set(harness, values) if values else (0, 0)
        memory.write(node + 8 + 0x18 * index, 8, root)
        memory.write(node + 0x10 + 0x18 * index, 8, height)
        memory.write(node + 0x18 + 0x18 * index, 8, len(values))
    memory.write(node + 0x1EE, 2, len(keys))
    memory.put_bytes(VIEW_AT, filled("view", 0x40))
    memory.write(VIEW_AT + 0x18, 8, node if keys else 0)
    memory.write(VIEW_AT + 0x20, 8, 0)
    listed = sorted(spec["listed"])
    if listed:
        tree = harness.allocate(LISTED.leaf)
        memory.put_bytes(tree, bytes(LISTED.leaf))
        for index, key in enumerate(listed):
            memory.put_bytes(tree + 8 + 20 * index, key)
        memory.write(tree + LISTED.count_at, 2, len(listed))
        memory.write(VIEW_AT, 8, tree)
    else:
        memory.write(VIEW_AT, 8, 0)
    memory.write(VIEW_AT + 8, 8, 0)
    memory.put_bytes(HASH_AT, filled("bundle hash", 0x20))
    memory.put_bytes(BUNDLE_AT, filled("bundle", 0x40))
    memory.write(BUNDLE_AT + 8, 8, ACTIONS_AT)
    memory.write(BUNDLE_AT + 0x10, 8, len(spec["actions"]))
    memory.write(BUNDLE_AT + 0x18, 8, spec["nonce"])
    memory.put_bytes(BUNDLE_AT + 0x20, spec["signer"])
    for index, (row, sub) in enumerate(spec["actions"]):
        at = ACTIONS_AT + 0x168 * index
        memory.write(at + 0x10, 8, row + 0x74 if row is not None else 3)
        memory.write(at + 0x18, 1, sub)
    machine.run(REVERIFY, {RDI: OUT_AT, RSI: VIEW_AT, RDX: HASH_AT, RCX: BUNDLE_AT, R8: spec["check"]})
    verdict = None
    signer = spec["signer"]
    good = signer in spec["nonces"] and (signer in spec["listed"] or all(row == 0x57 or (row == 0x3C and sub == 2) for row, sub in spec["actions"]))
    if good and spec["check"]:
        verdict = decide(case.now, 0, spec["nonce"], spec["nonces"][signer])
        if verdict[0] == "ok":
            verdict = None
    word = memory.read(OUT_AT, 8)
    if not good:
        if word != TAG_REFUSED or memory.bytes_at(OUT_AT + 8, 0x20) != filled("bundle hash", 0x20) or memory.bytes_at(OUT_AT + 0x28, 20) != signer:
            return "refusal %#x" % word
        harness.tally["reverify refused"] += 1
    elif verdict is None:
        if word != TAG_PASSED:
            return "pass %#x" % word
        harness.tally["reverify passed"] += 1
    else:
        text = memory.bytes_at(memory.read(OUT_AT + 8, 8), memory.read(OUT_AT + 0x10, 8)).decode("ascii")
        want = status_text(verdict)
        if text != want:
            return "text %r, want %r" % (text, want)
        if memory.bytes_at(OUT_AT + 0x18, 0x20) != filled("bundle hash", 0x20) or memory.bytes_at(OUT_AT + 0x38, 20) != signer:
            return "hash or signer beside the text"
        harness.tally["reverify nonce text"] += 1
    return None


def status_text(verdict):
    if verdict[0] == "duplicate":
        return "Invalid nonce: duplicate nonce %d" % verdict[1]
    return "Invalid nonce: nonce too %s %d %s %d" % (verdict[0], verdict[1], "<" if verdict[0] == "low" else ">", verdict[2])


# ---- agent removal prune ----

PENDING = Layout("pending removals", 0, 0x20, 0, 0, 0x160, 0x168, 0x16A, 0x170)
TRACKER_AT = STATE_AT + 0x36D0
USERS_AT = STATE_AT + 0x740
BUCKET_AGENT = 0x28
BUCKET_USER = 0x58
BUCKET_SET = 0x30


def table_hash(harness, at, key):
    memory = harness.machine.memory
    memory.put_bytes(KEY_AT, key)
    return harness.machine.run(HASHER, {RDI: at + 0x20, RSI: KEY_AT})


def build_table(harness, at, size, rows, seed):
    """A sixteen bucket table written byte by byte at the hash the real hasher gives."""
    memory = harness.machine.memory
    harness.empty_table(at, seed)
    buckets = 32
    block = harness.allocate(buckets * size + buckets + 16)
    ctrl = block + buckets * size
    memory.put_bytes(block, bytes(buckets * size))
    memory.put_bytes(ctrl, b"\xff" * (buckets + 16))
    memory.write(at, 8, ctrl)
    memory.write(at + 8, 8, buckets - 1)
    memory.write(at + 0x10, 8, 28 - len(rows))
    memory.write(at + 0x18, 8, len(rows))
    harness.blocks[at] = block
    for key, value in rows:
        digest = table_hash(harness, at, key)
        spot = digest & (buckets - 1)
        probe = 0
        while True:
            free = [(spot + step) & (buckets - 1) for step in range(16) if memory.bytes_at(ctrl + ((spot + step) & (buckets - 1)), 1)[0] == 0xFF]
            if free:
                break
            probe += 16
            spot = (spot + probe) & (buckets - 1)
        index = free[0]
        memory.write(ctrl + index, 1, digest >> 57)
        if index < 16:
            memory.write(ctrl + buckets + index, 1, digest >> 57)
        else:
            memory.write(ctrl + index - 16 + 0, 1, memory.read(ctrl + index - 16, 1))
        end = ctrl - index * size
        memory.put_bytes(end - size, key)
        value(end)


def pending_tree(harness, rows):
    memory = harness.machine.memory
    node = harness.allocate(PENDING.leaf)
    memory.put_bytes(node, bytes(PENDING.leaf))
    for index, (address, ready) in enumerate(sorted(rows)):
        memory.put_bytes(node + 0x20 * index, address + naive_time(ready))
    memory.write(node + 0x16A, 2, len(rows))
    return node


def compare_prune(harness, case):
    machine = harness.machine
    memory = machine.memory
    spec = case.ops[0]
    harness.reset()
    harness.blocks = {}
    memory.put_bytes(TIME_AT, naive_time(case.now))
    memory.put_bytes(TRACKER_AT, filled("tracker head", 0x60))

    def pending_row(rows):
        def put(end):
            memory.write(end - 0x18, 8, pending_tree(harness, rows))
            memory.write(end - 0x10, 8, 0)
            memory.write(end - 8, 8, len(rows))
        return put

    def agent_row(user):
        return lambda end: memory.put_bytes(end - 0x14, user)

    def set_row(values):
        def put(end):
            root, height = build_set(harness, values)
            memory.write(end - 0x18, 8, root)
            memory.write(end - 0x10, 8, height)
            memory.write(end - 8, 8, len(values))
        return put

    build_table(harness, TRACKER_AT + 0xC0, BUCKET_SET, [(user, pending_row(rows)) for user, rows in sorted(spec["pending"].items())], (11, 12))
    build_table(harness, TRACKER_AT + 0x60, BUCKET_AGENT, [(agent, agent_row(user)) for agent, user in sorted(spec["agents"].items())], (21, 22))
    build_table(harness, TRACKER_AT + 0x90, BUCKET_SET, [(address, set_row(values)) for address, values in sorted(spec["sets"].items())], (31, 32))
    build_table(harness, USERS_AT, BUCKET_USER, [(user, lambda end: None) for user in sorted(spec["users"])], (41, 42))
    machine.run(PRUNE, {RDI: TRACKER_AT, RSI: TIME_AT, RDX: USERS_AT})
    pending = {}
    expired = set()
    for user, rows in spec["pending"].items():
        left = [row for row in rows if row[1] > case.now]
        expired |= {row[0] for row in rows if row[1] <= case.now}
        if left:
            pending[user] = sorted(left)
    agents = {key: value for key, value in spec["agents"].items() if key not in expired}
    sets = {key: value for key, value in spec["sets"].items() if key not in expired or key in spec["users"]}
    found = {}
    for key, end in harness.table_rows(TRACKER_AT + 0xC0, BUCKET_SET):
        raw = harness.walk(PENDING, memory.read(end - 0x18, 8), memory.read(end - 0x10, 8))
        found[key] = [(item[:20], item[20:32]) for item in raw]
    if found != {user: [(a, naive_time(ready)) for a, ready in rows] for user, rows in pending.items()}:
        return "pending differs: %d %d" % (len(found), len(pending))
    got = {key: memory.bytes_at(end - 0x14, 20) for key, end in harness.table_rows(TRACKER_AT + 0x60, BUCKET_AGENT)}
    if got != agents:
        return "agent rows differ"
    if harness.nonce_map(TRACKER_AT + 0x90) != sets:
        return "nonce sets differ"
    harness.tally["prune"] += 1
    return None


# ---- fixed list ----

def read_list(image):
    """Addresses of the retention list, from the rodata operands of the sixteen byte compares."""
    begin, end = image.exact_fde(LIST)
    data = bytes(image.blob[image.offset(begin):image.offset(begin) + (end - begin)])
    tails, heads = [], []
    at = 0
    while True:
        at = data.find(b"\x66\x0f\x74", at)
        if at < 0:
            break
        reg = data[at + 3]
        target = begin + at + 8 + struct.unpack_from("<i", data, at + 4)[0]
        if reg == 0x0D:
            tails.append(target)
        elif reg == 0x05:
            heads.append(target)
        at += 8
    if len(tails) != len(heads):
        raise EvidenceError("uneven list compares")
    out = []
    for head, tail in zip(heads, tails):
        out.append(bytes(image.blob[image.offset(head):image.offset(head) + 16]) + bytes(image.blob[image.offset(tail):image.offset(tail) + 4]))
    return tuple(out)


def compare_list(harness, case):
    memory = harness.machine.memory
    harness.reset()
    for address, want in case.ops:
        memory.put_bytes(ADDRESS_AT, address + filled("list tail", 12))
        got = harness.machine.run(LIST, {RDI: ADDRESS_AT}) & 0xFF
        if got != int(want):
            return "%s: %d" % (address.hex(), got)
    harness.tally["list"] += len(case.ops)
    return None


def host_cases():
    out = []
    now = BASE_NOW
    day = DAY_MS
    listed = LIST_ADDRESSES[0]
    for copy in range(3):
        rows = (
            ("verified_runs_exec", [Record()], ()),
            ("verify_error_never_reaches_gate", [Record(status=0x7A), Record()], ()),
            ("wrong_broadcaster_never_reaches_gate", [Record(admit=False), Record()], ()),
            ("wrong_broadcaster_and_verify_error", [Record(admit=False, status=0x7A)], ()),
            ("nonce_key_is_third_address", [Record(a1=A, a2=B, a3=C), Record(a1=B, a2=C, a3=C, nonce=now), Record(a1=B, a2=A, a3=A, nonce=now)], ()),
            ("duplicate_charges_nothing", [Record(), Record()], ()),
            ("too_high_charges_nothing", [Record(nonce=now + day + 1)], ()),
            ("too_low_charges_nothing", [Record(nonce=now - 2 * day - 1)], ()),
            ("expired_burns_nonce_and_five_weights", [Record(expires=now - 1), Record(expires=now + 5)], ()),
            ("expired_equal_now_runs", [Record(expires=now)], ()),
            ("expired_after_duplicate_no_charge", [Record(), Record(expires=now - 1)], ()),
            ("expiry_weight_overflow_saturates", [Record(expires=now - 1, weight=MASK[8] // 4)], ()),
            ("weight_adds_up", [Record(weight=7), Record(nonce=now + 1, weight=9)], ()),
            ("reduce_only_first_address_refused", [Record(allowed=False)], (A,)),
            ("reduce_only_second_address_refused", [Record(allowed=False)], (B,)),
            ("reduce_only_third_address_runs", [Record(allowed=False)], (C,)),
            ("reduce_only_and_allowed_runs", [Record(allowed=True)], (A,)),
            ("reduce_only_refused_nonce_burned", [Record(allowed=False), Record(allowed=False)], (A,)),
            ("exec_rejected_keeps_nonce", [Record(done=0xE), Record()], ()),
        )
        for label, records, names in rows:
            out.append(HostCase("%s_%d" % (label, copy), records, copy, now, names))
        seeded = [("seed", C, 100)]
        out.append(HostCase("list_user_cap_400_%d" % copy, [Record(a1=listed, a3=C, nonce=now - 1)], copy, now, (), seeded))
        out.append(HostCase("plain_user_cap_100_%d" % copy, [Record(a1=A, a3=C, nonce=now - 1)], copy, now, (), seeded))
        out.append(HostCase("list_key_alone_gives_no_400_%d" % copy, [Record(a1=A, a3=listed, nonce=now - 1)], copy, now, (), [("seed", listed, 100)]))
        out.append(HostCase("list_second_address_gives_no_400_%d" % copy, [Record(a1=A, a2=listed, a3=C, nonce=now - 1)], copy, now, (), seeded))
    return out


def bundle_cases():
    out = []
    now = BASE_NOW
    day = DAY_MS
    for copy in range(3):
        for label, ops in (
            ("bundle_passes", [(A, now)]),
            ("bundle_duplicate_dropped_list_kept", [(A, now), (A, now), (A, now + 1)]),
            ("bundle_too_high_dropped", [(A, now + day + 1), (B, now)]),
            ("bundle_too_low_dropped", [(A, now - 2 * day - 1)]),
            ("bundle_two_signers", [(A, now), (B, now), (A, now - 1)]),
        ):
            case = Case("bundle", "%s_%d" % (label, copy), ops, copy)
            out.append(case)
    return out


def reverify_spec(signer=A, nonce=BASE_NOW, nonces=None, listed=(), actions=(), check=1):
    return {"signer": signer, "nonce": nonce, "nonces": {A: [BASE_NOW + 5]} if nonces is None else nonces, "listed": listed, "actions": list(actions), "check": check}


def reverify_cases():
    now = BASE_NOW
    day = DAY_MS
    rows = (
        ("signer_absent", reverify_spec(signer=B)),
        ("signer_map_empty", reverify_spec(nonces={})),
        ("signer_listed_no_map_row", reverify_spec(signer=B, listed=(B,))),
        ("listed_signer_skips_action_test", reverify_spec(listed=(A,), actions=((3, 0),))),
        ("vote_row_only_passes", reverify_spec(actions=((0x57, 0), (0x57, 1)))),
        ("row_60_kind_2_passes", reverify_spec(actions=((0x3C, 2),))),
        ("row_60_kind_1_refused", reverify_spec(actions=((0x3C, 1),))),
        ("other_row_refused", reverify_spec(actions=((0x57, 0), (3, 0)))),
        ("no_actions_passes", reverify_spec()),
        ("no_check_skips_nonce", reverify_spec(nonce=now + 5, check=0)),
        ("duplicate_text", reverify_spec(nonce=now + 5)),
        ("too_high_text", reverify_spec(nonce=now + day + 1)),
        ("too_low_text", reverify_spec(nonce=now - 2 * day - 1)),
        ("full_set_low_text", reverify_spec(nonce=now - 1, nonces={A: [now + index for index in range(100)]})),
        ("cap_100_not_400", reverify_spec(nonce=now - 1, nonces={A: [now + index for index in range(100)]}, listed=(A,))),
        ("empty_set_passes", reverify_spec(nonces={A: []})),
        ("second_key_found", reverify_spec(signer=B, nonces={A: [now + 5], B: [now + 7]})),
    )
    return [Case("reverify", label, [spec], 0, now) for label, spec in rows]


def prune_spec(pending=None, agents=None, sets=None, users=()):
    return {"pending": pending or {}, "agents": agents or {}, "sets": sets or {}, "users": users}


def prune_cases():
    now = BASE_NOW
    d = ADDRESSES[3]
    e = ADDRESSES[4]
    rows = (
        ("nothing_pending", prune_spec(agents={B: A}, sets={B: [1]})),
        ("ready_equal_now_removed", prune_spec({A: [(B, now)]}, {B: A}, {B: [1, 2]})),
        ("ready_after_now_kept", prune_spec({A: [(B, now + 1)]}, {B: A}, {B: [1, 2]})),
        ("ready_before_now_removed", prune_spec({A: [(B, now - 1)]}, {B: A}, {B: [1, 2]})),
        ("real_user_keeps_set", prune_spec({A: [(B, now)]}, {B: A}, {B: [1]}, (B,))),
        ("other_user_row_no_help", prune_spec({A: [(B, now)]}, {B: A}, {B: [1]}, (C,))),
        ("no_nonce_set", prune_spec({A: [(B, now)]}, {B: A})),
        ("no_agent_row", prune_spec({A: [(B, now)]}, {}, {B: [1]})),
        ("no_user_rows", prune_spec({A: [(B, now)]}, {B: A}, {B: [1], C: [2]})),
        ("partial_expiry_keeps_bucket", prune_spec({A: [(B, now), (C, now + 1)]}, {B: A, C: A}, {B: [1], C: [2]})),
        ("two_users_same_agent", prune_spec({A: [(B, now)], d: [(B, now - 5)]}, {B: A}, {B: [1]})),
        ("three_agents_mixed", prune_spec({A: [(B, now), (C, now - 1)], d: [(e, now + 9)]}, {B: A, C: A, e: d}, {B: [1], C: [2], e: [3], A: [4]}, (C,))),
        ("user_own_set_untouched", prune_spec({A: [(B, now)]}, {B: A}, {A: [9], B: [1]}, (A,))),
    )
    return [Case("prune", label, [spec], 0, now) for label, spec in rows]


def list_cases():
    rows = [(address, True) for address in LIST_ADDRESSES]
    near = []
    for address in LIST_ADDRESSES:
        for at in (0, 7, 15, 16, 19):
            near.append((address[:at] + bytes([address[at] ^ 1]) + address[at + 1:], False))
    near.append((bytes(20), False))
    near.append((b"\xff" * 20, False))
    return [Case("list", "listed_addresses", rows), Case("list", "near_addresses", near)]


COMPARE.update({"host": compare_host, "bundle": compare_bundle, "reverify": compare_reverify, "prune": compare_prune, "list": compare_list})


def all_cases():
    return gate_cases() + host_cases() + bundle_cases() + reverify_cases() + prune_cases() + list_cases()


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def status_row(image, tag):
    """Display arm of a status tag: a direct text, a format piece, or a shape this reader leaves unnamed."""
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE) + 4 * tag)[0]
    data = code(image, arm, 64)
    at = data.find(b"\x48\x8d\x35")
    if at >= 0 and data[at + 7] == 0xBA:
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        return tag, arm, "text", code(image, text, size).decode("ascii")
    at = data.find(b"\x48\x8d\x15")
    if at >= 0:
        piece = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = code(image, piece, 1)[0]
        return tag, arm, "piece", code(image, piece + 1, size).decode("ascii", "replace") + "{}"
    return tag, arm, "other", ""


def slot_sites(image, slot):
    """FF 15 sites through one slot, by byte scan of .text."""
    base, text = image.text_bytes()
    out = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            out.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return out


def direct_sites(image, target):
    base, text = image.text_bytes()
    out = []
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text) and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            out.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return out


# ---- mutation ----

def displacement_at(image, row):
    """Offset inside the instruction of a non-stack field displacement, or None."""
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, offset in instruction, kind) for every conditional, immediate and field offset."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, "immediate"


def mutate_patch(image, row_va, at, kind="branch"):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ (8 if kind == "offset" else 1)}


MUTANT_STATE = {}
FAULTS = (Halt, Panicked, EvidenceError, KeyError, ValueError, IndexError, OverflowError, TypeError, RecursionError, struct.error)


def worker_start():
    image = load_image()
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    LIST_ADDRESSES.extend(read_list(image))
    MUTANT_STATE.update(harness=harness, cases=all_cases())


def run_one(task):
    function, va, at, kind, indices = task
    harness = MUTANT_STATE["harness"]
    cases = MUTANT_STATE["cases"]
    machine = harness.machine
    machine.patches = mutate_patch(harness.image, va, at, kind)
    machine.cache.pop(va, None)
    failed = None
    for index in indices:
        try:
            trouble = compare(harness, None, cases[index])
        except FAULTS as error:
            trouble = type(error).__name__
        if trouble:
            failed = cases[index].label + ": " + trouble
            break
    machine.patches = {}
    machine.cache.pop(va, None)
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:60].replace("\t", " ") if failed else ""}


def run_mutants(image, targets, reached, costs, labels):
    by_va = {}
    sentinels = frozenset(index for index, label in enumerate(labels) if label in SENTINELS)
    for index in sorted(range(len(reached)), key=lambda item: (costs[item], item)):
        for va in reached[index]:
            by_va.setdefault(va, []).append(index)
    tasks = []
    results = []
    for start, _ in targets:
        begin, end = image.exact_fde(start)
        for va, at, kind in mutation_targets(image, body_rows(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            chosen = indices[:3]
            rest = [index for index in indices[3:] if costs[index] < MUTANT_CASE_COST] or indices[3:4]
            if rest:
                step = max(len(rest) / (MUTANT_CASES - 3), 1)
                chosen += [rest[int(step * item)] for item in range(MUTANT_CASES - 3) if int(step * item) < len(rest)]
            tasks.append((start, va, at, kind, sorted(set(chosen) | (sentinels & set(indices)))))
    with multiprocessing.Pool(WORKERS, worker_start) as pool:
        results += pool.map(run_one, tasks, 8)
    return sorted(results, key=lambda row: (row["function"], row["va"], row["kind"]))


# ---- evidence ----

CORE_FUNCTIONS = ((GATES[0], "nonce gate, primary layout", True), (GATES[1], "nonce gate, secondary layout", True), (GATES[2], "nonce gate, third copy", True), (VALIDATE, "candidate test", True), (LOOKUP, "hash table probe of the signer", True), (INSERT, "hash table slot write", True),
                  (HOSTS[0]["entry"], "signed action loop, primary", True), (HOSTS[1]["entry"], "signed action loop, secondary", True), (HOSTS[2]["entry"], "one signed action, third copy", True),
                  (REVERIFY, "proposer reverify of a signed bundle", True), (PRUNE, "agent removal prune", True), (PRUNE_COLLECT, "pending removal drain per user", True), (DRAIN, "pending tree drain step", True),
                  (SET_INSERT[0], "nonce set insert, shared", False), (SET_INSERT[2], "nonce set insert copy, shared", False), (SET_POP[0], "nonce set pop first, shared", False), (SET_POP[2], "nonce set pop first copy, shared", False), (LIST, "fixed eight address list, shared", False), (HASHER, "SipHash 1-3 of twenty bytes, shared", False),
                  (BUNDLE_HOSTS[0], "block step, bundle loop only", False), (BUNDLE_HOSTS[1], "block step copy, bundle loop only", False), (BUNDLE_HOSTS[2], "block step copy, bundle loop only", False))

KEY_ROWS = ((0x3986CDE, "b890010000", "cap 400 when the flag word is set"), (0x3986CE3, "41bc64000000", "cap 100 otherwise"), (0x3986CED, "4d396010", "set length against the cap, before any time test"),
            (0x3986E09, "ba80510100", "first date step, plus 86400 seconds"), (0x3986F73, "48c7c280aefeff", "second date step, minus 86400 seconds"), (0x3987005, "48c7c280aefeff", "third date step on the result of the second, minus 86400 seconds again"),
            (0x3987168, "66c703c600", "status 0xc6 with a text"), (0x3987209, "66c703c700", "status 0xc7 with the nonce"), (0x398721B, "66c7038601", "status 0x186, cap in the next word"))

TEXTS = ((0x1EC082, "nonce too low piece, used by two arms"), (0x1F581F, "nonce too high piece"), (0x21A01F, "NaiveDateTime add overflow panic"), (0x21A045, "NaiveDateTime subtract overflow panic"))

TRACKER_FIELDS = (("user_to_main_agent", 0x36D0, 0x4D78522), ("user_to_extra_agents", 0x3700, 0x4D78533), ("agent_to_user", 0x3730, 0x4D78577), ("address_to_nonce_set", 0x3760, 0x4D785BB), ("user_to_pending_agent_removals", 0x3790, 0x4D785FF))


def text_lines(image):
    lines = ["address\tmeaning\tbytes_hex\ttext"]
    for va, meaning in TEXTS:
        if meaning.startswith("nonce"):
            size = code(image, va, 1)[0]
            raw = code(image, va + 1, size)
        else:
            raw = code(image, va, 0x26 if "add" in meaning else 0x25)
        lines.append("%#x\t%s\t%s\t%s" % (va, meaning, raw.hex(), raw.decode("ascii").replace("`", "")))
    return lines


def key_row_lines(image):
    lines = ["address\tbytes\tmeaning"]
    for va, hexed, meaning in KEY_ROWS:
        found = code(image, va, len(hexed) // 2).hex()
        if found != hexed:
            raise EvidenceError("row moved at %#x: %s" % (va, found))
        lines.append("%#x\t%s\t%s" % (va, hexed, meaning))
    return lines


def tracker_lines(image):
    """Field order from the serde name run in .rodata, state offsets from the lea rows of the snapshot routine."""
    base, data = image.rodata_bytes()
    run = "".join(name for name, _, _ in TRACKER_FIELDS).encode("ascii")
    at = data.find(run)
    if at < 0:
        raise EvidenceError("field name run moved")
    lines = ["position\tname\tname_run_address\tstate_offset\tlea_address\tlea_bytes"]
    for index, (name, offset, va) in enumerate(TRACKER_FIELDS):
        raw = code(image, va, 7)
        if raw[:3] != b"\x49\x8d\xb6" or struct.unpack_from("<i", raw, 3)[0] != offset:
            raise EvidenceError("snapshot row moved at %#x" % va)
        lines.append("%d\t%s\t%#x\t%#x\t%#x\t%s" % (index, name, base + at, offset, va, raw.hex()))
    if data.find(b"struct AgentTracker with 5 elements") < 0:
        raise EvidenceError("struct text moved")
    return lines


def list_lines(image):
    lines = ["position\taddress"]
    for index, address in enumerate(LIST_ADDRESSES):
        lines.append("%d\t0x%s" % (index, address.hex()))
    return lines


def site_lines(image):
    """Sites by one pass over .text: rel32 calls for the direct targets, FF 15 for the slots."""
    base, text = image.text_bytes()
    direct = {gate: "gate %d call" % index for index, gate in enumerate(GATES)}
    direct.update({REVERIFY: "reverify call", PRUNE_COLLECT: "drain call", LOOKUP: "hash probe call", INSERT: "hash slot write call"})
    slots = {SLOT_VALIDATE: "candidate test through slot", SLOT_PRUNE: "prune through slot", SLOT_LIST: "list test through slot"}
    found = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text):
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in direct:
                found.append((direct[target], base + at))
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text):
            target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if target in slots:
                found.append((slots[target], base + at))
    hosts = (HOSTS[0]["entry"], HOSTS[1]["entry"], HOSTS[2]["entry"])
    lines = ["relation\tsite\thost"]
    for name, site in sorted(found):
        host = image.fde(site)[0]
        if name.startswith("list test") and host not in hosts:
            continue
        lines.append("%s\t%#x\t%#x" % (name, site, host))
    return lines


def bounds_lines(harness):
    """Window edges printed by the real text arms, one row per clock value."""
    machine = harness.machine
    memory = machine.memory
    lines = ["now_ms\tupper_from_text\tlower_from_text\tupper_minus_now\tnow_minus_lower"]
    for now in BOUND_TIMES:
        harness.reset()
        memory.put_bytes(STATE_AT + 0x60, naive_time(now))
        map_at = STATE_AT + GATE_MAP[0]
        harness.empty_table(map_at)
        memory.write(STATE_AT + GATE_COUNT[0], 8, 0)
        memory.write(STATE_AT + GATE_COUNT[0] + 8, 8, 0)
        high = gate_call(harness, 0, A, 0, MASK[8])
        low = gate_call(harness, 0, A, 0, 0) if now > 2 * DAY_MS else ("low", 0, 0)
        lines.append("%d\t%d\t%d\t%d\t%d" % (now, high[2], low[2], high[2] - now, now - low[2]))
    return lines


def analyse(image, full=True):
    harness = Harness(image)
    cases = all_cases()
    machine = harness.machine
    mismatches = []
    reached = []
    costs = []
    seen = set()
    lines = []
    for case in cases:
        machine.seen = set()
        before = machine.steps
        harness.tally = collections.Counter()
        try:
            trouble = compare(harness, None, case)
        except (Halt, Panicked) as error:
            trouble = "%s %s" % (type(error).__name__, error)
        if trouble:
            mismatches.append("%s: %s" % (case.label, trouble))
        reached.append(frozenset(machine.seen))
        costs.append(machine.steps - before)
        seen |= machine.seen
        lines.append("\t".join((case.kind, case.label, str(case.copy), " ".join("%s=%d" % item for item in sorted(harness.tally.items())) or "-", "fail" if trouble else "match")))
        for key, value in harness.tally.items():
            OUTCOMES[key] += value
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    for start, role, _ in CORE_FUNCTIONS:
        begin, end = image.exact_fde(start)
        rows = body_rows(image, begin, end)
        hit = sum(1 for row in rows if row.va in seen)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "instructions": len(rows), "stepped": hit})
        function_lines.append("%#x\t%#x\t%d\t%d\t%d\t%s" % (begin, end, end - begin, len(rows), hit, role))
    targets = [(start, role) for start, role, claimed in CORE_FUNCTIONS if claimed]
    results_rows = run_mutants(image, targets, reached, costs, [case.label for case in cases]) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    status_lines = ["tag\tarm\tform\ttext"]
    for tag, status_arm, form, text in (status_row(image, tag) for tag in STATUS_TAGS):
        status_lines.append("%#x\t%#x\t%s\t%s" % (tag, status_arm, form, text))
    layout_lines = ["tree\tkey_at\tkey_size\tvalue_at\tvalue_size\tparent_at\tindex_at\tcount_at\tleaf_size"]
    for item in LAYOUTS + (LISTED, SIGNED_MAP, PENDING):
        layout_lines.append("%s\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x" % (item.name, item.key_at, item.key_size, item.value_at, item.value_size, item.parent_at, item.index_at, item.count_at, item.leaf))
    kinds = collections.Counter(case.kind for case in cases)
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": dict(sorted(kinds.items())),
        "cases_total": len(cases),
        "outcomes": dict(sorted(OUTCOMES.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0][:200] if mismatches else "",
        "instructions_stepped": steps,
        "functions": functions,
        "mutations": tally,
        "constants": {"cap_plain": 100, "cap_listed": 400, "upper_window_ms": DAY_MS, "lower_window_ms": 2 * DAY_MS, "bucket_size": 0x30, "tracker_state_offset": "0x36d0", "copy_map_shift": "0xa80"},
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_sites": site_lines(image), "_status": status_lines, "_layouts": layout_lines, "_keys": key_row_lines(image), "_texts": text_lines(image),
        "_tracker": tracker_lines(image), "_list": list_lines(image), "_bounds": bounds_lines(harness),
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, the table growth branch of a full group, the sink or asset arm of a host, or a tree edge step with no fixture"
SURVIVOR_REASON = "not hand checked row by row: copy size, stack base, record copy words no rule reads, tree edge test, or a value only a stub reads"
OUTCOMES = collections.Counter()


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\tcopy\toutcomes\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "call-sites.tsv": evidence.pop("_sites"), "status-text.tsv": evidence.pop("_status"),
              "node-layouts.tsv": evidence.pop("_layouts"), "key-rows.tsv": evidence.pop("_keys"), "texts.tsv": evidence.pop("_texts"), "tracker-fields.tsv": evidence.pop("_tracker"), "fixed-list.tsv": evidence.pop("_list"), "window-bounds.tsv": evidence.pop("_bounds")}
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    for name, lines in tables.items():
        files[name] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else (UNREACHED_REASON if row["result"] == "unreached" else SURVIVOR_REASON))) for row in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


def write_outputs(folder, files):
    folder = pathlib.Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (folder / name).write_text(text, encoding="ascii", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder")
    options = parser.parse_args(argv)
    image = load_image()
    LIST_ADDRESSES.extend(read_list(image))
    files = render(analyse(image))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
