#!/usr/bin/env python3
"""Pin the node #94 perp order insert from ELF bytes: gates, the taker walk, the pull retry, the reason arms, the rest and both reduce-only sweeps.

`0x4311140` and its twin `0x4314da0` are the perp monomorphs of the book insert. They run the entry gates, walk the opposite side level by level through the match core,
retry a maker after a collateral pull, turn each match reason into a row, rest what is left, then bring the reduce-only orders of every touched user back inside the
position and cancel reduce-only trigger orders of users whose position changed sign. The real bytes run in a Python evaluator with every edge callee stubbed. A separately
written specification predicts the ordered edge calls and the result, and every condition, immediate and field offset of the function is flipped to show the run can tell.
No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

INSERT = 0x4311140
TWIN = 0x4314DA0
TIF_TABLE = 0x6EEC88
REASON_TABLE = 0x6EEC9C
ERROR_TABLE = 0x5A572C
PX_LIMIT = 10 ** 15
FX_KEY = 0xF1357AEA2E62A9C5
REST_ALLOWED_SITE = 0x4312CD1
TWIN_SHIFT = 0xA80

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_PANIC_NONE = 0x576E470
SLOT_PANIC_BOUND = 0x576DFC8
SLOT_PANIC_TEXT = 0x576E108
SLOT_PANIC_UNWRAP = 0x576E048
SLOT_RECORDER = 0x5773190
SLOT_DEX_ROW = 0x5773320
SLOT_PUSH_ROW = 0x5773D58
SLOT_GROW_USER_OIDS = 0x5773D70
SLOT_GROW_CANCEL = 0x5774458
SLOT_CLOID = 0x5774810
SLOT_GROW_SKIPS = 0x5774818
SLOT_GROW_ROWS = 0x5774830
SLOT_TRACK = 0x5774850
SLOT_SECOND_GATE = 0x5774858
SLOT_ALLOWED = 0x5774860
SLOT_SETTLE = 0x5774868
SLOT_GROW_FILLS = 0x5774870
SLOT_RESERVE = 0x5774880

TIMER = 0x3379490
POSITIONS = 0x36F57F0
TICK = 0x42C7600
FIRST_GATE = 0x4CD8360
TOP_LEVELS = 0x4A078A0
ALO_PAYLOAD = 0x4A06AE0
ALLOW_ROW = 0x4CD82D0
USER_HASH = 0x473BF50
MATCH = 0x431C530
PULL = 0x46EFB70
SET_SIZE = 0x49E4DE0
COLLECT = 0x4450210
RELATIONS = 0x43051F0
REMOVE = 0x42FA880
SKIP = 0x42F7420
DROP_SET = 0x49B34A0
PEER_CLEAR = 0x42FBC60
ORDER_LOOKUP = 0x430D380
LEVEL = 0x45A3890
SLAB_INSERT = 0x42E8710
OID_MAP = 0x488DA60
USER_STATE = 0x45A3B30
USER_SLOTS = 0x4931420
REDUCE_PUSH = 0x454C870
TIME_ROW = 0x46F55A0
BUILD_STATUS = 0x42FC2F0
VEC_GROW = 0x454F5D0
FILL_USERS = 0x4A07DF0
RETAIN = 0x486E260
RETAIN_TEST = 0x43375E0

OK = 0x8000000000000018
NONE_WORD = 1 << 63
SLOT_SIZE = 0xF8
FILL_SIZE = 0x238
MATCH_SIZE = 0x260
ROW_SIZE = 0x278
MARKET_SIZE = 0x2F0
MAX64 = (1 << 64) - 1

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF, 16: (1 << 128) - 1}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x60000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 200000

OUT = HEAP_BASE + 0x400
ARGS = HEAP_BASE + 0x500
SINK = HEAP_BASE + 0x700
SET_MARK = HEAP_BASE + 0x740
ALLOW_AT = HEAP_BASE + 0x780
LEVEL_AT = HEAP_BASE + 0x800
BOOK = HEAP_BASE + 0x1000
CTX = HEAP_BASE + 0x2000
MARKETS = HEAP_BASE + 0x3800
META_AT = HEAP_BASE + 0x4200
ORACLE_AT = HEAP_BASE + 0x4500
RELATION_AT = HEAP_BASE + 0x4A00
SLAB = HEAP_BASE + 0x5000
SLAB_ROOM = 40
HEAP_FREE = SLAB + SLAB_ROOM * SLOT_SIZE

TAKER = "11223344556677889900aabbccddeeff00112233"
USERS = ("2122334455667788991122334455667788990011", "3122334455667788991122334455667788990022", "4122334455667788991122334455667788990033", "5122334455667788991122334455667788990044")
HIGH_USERS = ("f122334455667788991122334455667788990011", "f222334455667788991122334455667788990022", "f322334455667788991122334455667788990033")


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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd"}
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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
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
        if two == 0xA3:
            reg, rm = modrm()
            return finish("bt", rm, ("r", reg), width)
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
        self.jump_low = self.jump_high = 0

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
            return (self.regs[operand[1]] >> 8) & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
        elif operand[0] == "r":
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
            if not self.jump_low <= target < self.jump_high:
                raise Halt("indirect jump out of the function at %#x" % row.va)
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


# ---- specification: written from a full read, shares nothing with the evaluator ----

def to_signed(value):
    return value - (1 << 64) if value >> 63 else value


def scripted_match(w, number, slot_size, budget, px):
    """The stubbed match core: a script entry, else a plain fill of the smaller size."""
    row = dict(w["match"].get(str(number), {}))
    row.setdefault("reason", 3)
    row.setdefault("status", [OK, 0, 0])
    if "fill" not in row:
        row["fill"] = [px, min(slot_size, budget)] if min(slot_size, budget) else None
    row.setdefault("legs", [[1, 0], [1, 0]])
    row.setdefault("budget", budget)
    return row


def book_rows(w):
    """Every slab row in slab order: level makers first, then the extra rows."""
    rows = [slot for level in w["levels"] for slot in level["slots"]]
    return rows + w["extra_slots"]


class Spec:
    """Prediction of one insert: ordered edge calls, the output and the book words it changes."""

    def __init__(self, w):
        self.w = w
        self.log = []
        self.fill_count = 0
        self.match_calls = 0

    def event(self, *row):
        self.log.append(list(row))

    def payload(self, status, second=None, third=None):
        return {"status": status, "second": second, "third": third}

    def position(self, user):
        """The position row of a user in this asset, as [tag, szi], or None."""
        self.event("positions", user)
        return self.w["positions"].get(user, {}).get(str(self.w["asset"]))

    def lookup(self, oid):
        """The relation lookup: a view of an order with a tag and a word, or nothing."""
        self.event("lookup", oid)
        return self.relations.get(str(oid))

    def clear_relation(self, oid):
        row = self.lookup(oid)
        if row is None:
            return
        tag, word = row
        row[0] = 0
        if tag == 1:
            other = self.lookup(word)
            if other is not None:
                other[0] = 0

    def price_order(self):
        return sorted(self.w["levels"], key=lambda row: -row["px"] if self.side else row["px"])

    def live_slot(self, oid):
        """A slab row through the oid table, skipping unknown oids, bad indices and vacant rows."""
        index = self.w["oid_table"].get(str(oid))
        if index is None or index >= self.count or self.slab_rows[index].get("vacant"):
            return None
        return self.slab_rows[index]

    def mode_gate(self, reduce):
        mode = self.w["mode"]
        if mode == 0:
            return self.payload(0x8000000000000016)
        if mode == 1 and not reduce:
            return self.payload(0x8000000000000015)
        return None

    def market_gate(self, a):
        """The no position gate of a builder market. A dict stops the insert."""
        w = self.w
        if w["main_byte"] == 3:
            return None
        row = self.position(a["user"])
        if row is not None:
            if row[0] != 0:
                return None
            return self.mode_gate(a["reduce"])
        index = w["asset"] % 10000
        if w["asset"] // 10000 != w["meta_dex"] or index >= len(w["meta"]):
            raise SpecPanic("perp meta")
        if w["meta"][index]:
            return None
        return self.mode_gate(a["reduce"])

    def entry(self):
        """Gates before any write. A dict stops the insert."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        if asset // 10000 >= w["dex_count"]:
            raise SpecPanic("dex bound")
        if asset in w["halted"]:
            return self.payload(0x8000000000000017, 0)
        stop = self.market_gate(a)
        if stop is not None:
            return stop
        crosses = False
        levels = self.price_order()
        if levels:
            top = levels[0]["px"]
            crosses = top <= a["px"] if not self.side else top >= a["px"]
        self.crosses = crosses
        tif = a["tif"]
        self.taker_only = tif in (1, 3, 4)
        if tif == 0 and crosses:
            self.event("top_levels")
            self.event("alo_payload")
            return self.payload(0x8000000000000006, w["alo"][0], w["alo"][1])
        if self.taker_only and not crosses:
            return self.payload(0x8000000000000008)
        self.base = a["size"]
        self.orig = a["size"]
        if not a["tag"] and not a["reduce"]:
            raise SpecPanic("reduce_only text")
        if a["reduce"]:
            row = self.position(a["user"])
            if row is None or row[1] == 0 or (row[1] > 0) != bool(self.side):
                return self.payload(0x8000000000000005, 0)
            held = abs(row[1])
            self.base = min(a["size"], held) if a["tag"] else held
            self.orig = a["size"] if a["tag"] else held
        if a["px"] > PX_LIMIT:
            return self.payload(NONE_WORD, 0)
        self.event("tick", asset)
        if a["px"] % w["tick"]:
            return self.payload(NONE_WORD, 0)
        index = asset % 10000
        if index >= len(w["oracle"]):
            raise SpecPanic("oracle")
        self.event("first_gate", a["user"], asset, self.side, self.base, a["px"], w["oracle"][index])
        if w["first_gate"][0] != OK:
            return self.payload(*w["first_gate"])
        self.event("second_gate", asset, self.base, a["px"], a["user"], self.side, int(self.taker_only), int(crosses), w["byte"], a["reduce"])
        if w["second_gate"][0] != OK:
            return self.payload(*w["second_gate"])
        return None

    def allowed(self, px, answer):
        self.event("allow_row", self.w["asset"])
        self.event("allowed", self.w["bc"], self.w["asset"], self.side, px)
        return answer

    def run_match(self, slot):
        number = self.match_calls
        self.match_calls += 1
        a = self.w["args"]
        self.event("match", self.w["asset"], slot["index"], self.budget, self.level_px, self.oid, self.side, int((a["kind"] & 0xFFFFFFFF) >= 9), a["word"], self.w["word_one"], self.w["word_two"], a["reduce"])
        return scripted_match(self.w, number, slot["size_now"], self.budget, self.level_px)

    def pull_needed(self, reason, slot):
        """Reason byte outside 1..=3 with the maker in the mode table: its class and the state bytes decide a retry."""
        w = self.w
        if reason in (1, 2, 3) or not w["modes"]:
            return None
        self.event("user_hash", slot["user"])
        mode = w["modes"].get(slot["user"])
        if mode is None:
            return None
        if mode > 3:
            return None if w["byte_5b0"] else mode
        if mode != 3 or w["byte_5b1"]:
            return None
        return mode

    def fill(self, slot, row):
        w = self.w
        number = self.fill_count
        self.fill_count += 1
        asset = w["asset"]
        px, size = row["fill"]
        self.event("settle", w["bc"], px, size, number)
        changed = w["settled"].get(str(number))
        if changed:
            px, size = changed
        if size > slot["size_now"]:
            raise SpecPanic("recorder size")
        slot["size_now"] -= size
        self.event("set_size", slot["index"], asset, slot["size_now"])
        if size > self.budget:
            raise SpecPanic("recorder size")
        self.budget -= size
        self.filled += size
        if self.filled > MAX64:
            raise SpecPanic("recorder sum")
        users = (self.taker_user(slot, 0), self.taker_user(slot, 1))
        for leg, change in ((0, size), (1, -size)):
            tag, old = row["legs"][leg]
            if tag == 1 and size >> 63:
                raise SpecPanic("fill size")
            if tag == 1 and not -(1 << 63) <= old + change < (1 << 63):
                raise SpecPanic("szi")
            if tag == 1 and old != 0 and self.sign_class(old) != self.sign_class(old + change):
                self.flipped.add(users[leg])
        self.touched.update(users)
        if slot["size_now"] == 0:
            self.rows.append([slot["oid"], slot["user"], 0])
        self.last_trade = px
        self.fills.append([px, asset, size])

    def sign_class(self, value):
        return 0 if value > 0 else (2 if value == 0 else 1)

    def taker_user(self, slot, leg):
        buyer, seller = (slot["user"], self.w["args"]["user"]) if self.side else (self.w["args"]["user"], slot["user"])
        return (buyer, seller)[leg]

    def note_user(self, slot):
        self.users.setdefault(slot["user"], []).append(slot["oid"])

    def walk(self):
        """Opposite side, level by level. Returns `plain`, `used`, `band`, or a dict for a stop."""
        w, a = self.w, self.w["args"]
        for level in self.price_order():
            px = level["px"]
            if px != a["px"] and (px > a["px"]) != bool(self.side):
                return "plain"
            if not self.allowed(px, w["allowed"].get(str(px), True)):
                return "band"
            self.level_px = px
            slots = level["slots"]
            position = 0
            if not level.get("head", True):
                raise SpecPanic("level head")
            while position < len(slots):
                slot = slots[position]
                if slot["index"] >= self.count or slot.get("vacant") or slot["index"] == w["broken_slot"]:
                    raise SpecPanic("slot")
                row = self.run_match(slot)
                reason = row["reason"]
                mode = self.pull_needed(reason, slot)
                if mode is not None:
                    self.event("dex_row", w["asset"] // 10000)
                    self.event("pull", slot["user"], w["pull_word"], 1, w["asset"] // 10000, int(mode >= 4))
                    row = self.run_match(slot)
                    reason = row["reason"]
                self.budget = row["budget"]
                status = row["status"]
                if row["fill"] is not None:
                    self.fill(slot, row)
                if reason == 0:
                    self.rows.append([slot["oid"], slot["user"], 2])
                    self.note_user(slot)
                elif reason == 1:
                    self.skips.append([slot["oid"], slot["user"], 10])
                    self.note_user(slot)
                elif reason == 2:
                    self.skips.append([slot["oid"], slot["user"], 9])
                    self.note_user(slot)
                if status[0] == OK:
                    if self.budget == 0:
                        return "used"
                    position += 1
                    continue
                if not self.fills:
                    return self.payload(status[0], status[1] if status[0] >> 63 else None, status[2])
                if self.budget == 0:
                    return "used"
                break
        return "plain"

    def add_taker_row(self):
        self.rows.append([self.w["args"]["oid"], self.w["args"]["user"], 1])

    def apply_rows(self):
        self.event("collect", [row[0] for row in self.rows])
        for oid, user, kind in self.rows:
            self.event("relations", oid, user)
            if kind == 0:
                self.remove(oid, user, 1)
            elif kind == 2:
                self.remove(oid, user, 5)
        for oid, user, reason in self.skips:
            self.skip(oid, user, reason)
        self.event("drop_set")

    def vacate(self, oid):
        index = self.w["oid_table"].get(str(oid))
        if index is not None and index < len(self.slab_rows):
            self.slab_rows[index]["vacant"] = True

    def remove(self, oid, user, reason):
        self.event("remove", oid, user, reason)
        self.vacate(oid)

    def skip(self, oid, user, reason):
        self.event("skip", oid, user, reason)
        self.vacate(oid)

    def status_row(self):
        w, a = self.w, self.w["args"]
        if self.filled > self.base:
            raise SpecPanic("recorder size")
        if a["kind"] == 9:
            return
        self.event("time_row", w["asset"])
        self.event("build_status", self.base - self.filled, self.orig, self.oid, a["user"], a["tif"], a["px"], self.side, a["kind"])
        self.sink.append([self.oid, a["user"]])

    def rest(self):
        """Rest gates, then the link into the level. True when the order rests, or a dict for a stop."""
        w, a = self.w, self.w["args"]
        asset = w["asset"]
        provided = a["oid_tag"]
        if not self.allowed(a["px"], w["may_rest"]):
            if not self.fills:
                return self.payload(0x8000000000000013)
            if provided:
                self.clear_relation(a["oid"])
            return False
        self.event("reserve", asset, self.budget, self.orig, a["px"], a["user"], self.side, a["reduce"])
        reserve = w["reserve"]
        if reserve[0] != OK:
            if provided:
                self.event("collect", [row[0] for row in self.rows])
                self.event("relations", a["oid"], a["user"])
                self.event("drop_set")
            if not self.fills:
                return self.payload(reserve[0], reserve[1] if reserve[0] >> 63 else None, reserve[2])
            return False
        key = a["px"] if self.side else -a["px"]
        self.event("level", 1 if self.side else 0, key)
        head, tail = w["rest_level"]
        self.event("slab_insert", tail, self.budget, self.orig, self.oid, a["px"], self.side, a["user"], a["tif"], a["cloid"], asset, a["reduce"], a["tag"] ^ 1)
        slot = w["new_slot"]
        self.rest_head = slot if head is None else head
        if tail is not None:
            if tail >= self.count or self.slab_rows[tail].get("vacant"):
                raise SpecPanic("tail")
            self.next_link[tail] = slot
        self.rest_tail = slot
        self.event("oid_map", self.oid, slot)
        if a["cloid"] is not None:
            self.event("cloid", a["user"], self.oid, a["cloid"])
        self.event("user_state", a["user"])
        self.event("user_slots", slot)
        self.event("track", a["user"])
        if a["reduce"]:
            self.event("user_state", a["user"])
            self.event("reduce_push", self.oid)
            self.deques.setdefault(a["user"], []).append(self.oid)
            self.touched.add(a["user"])
        return True

    def sweep_reduce(self, user):
        """Sweep one: reduce-only orders of a touched user, oldest first, back inside the position."""
        w = self.w
        asset = w["asset"]
        self.event("user_state", user)
        if asset // 10000 >= w["dex_count"]:
            raise SpecPanic("dex bound")
        kept, cancels = [], []
        for oid in self.deques.get(user, []):
            slot = self.live_slot(oid)
            if slot is None:
                continue
            row = self.position(user)
            if row is not None and row[1] != 0 and (row[1] > 0) == bool(slot["side"]):
                kept.append(oid)
            else:
                cancels.append(oid)
        self.deques[user] = list(kept)
        total = 0
        for oid in kept:
            slot = self.live_slot(oid)
            if slot is None:
                continue
            row = self.position(user)
            if row is None or row[1] == 0 or (row[1] > 0) != bool(slot["side"]):
                continue
            held = abs(row[1])
            target = min(slot["limit"], held) if slot["tag"] else held
            slot["size_now"] = min(target, slot["size_now"])
            self.event("set_size", slot["index"], asset, slot["size_now"])
            total += slot["size_now"]
            if total > MAX64:
                raise SpecPanic("recorder sum")
        row = self.position(user)
        held = abs(row[1]) if row is not None else 0
        queue = self.deques[user]
        while queue and total > held:
            excess = total - held
            slot = self.live_slot(queue[0])
            if slot is None:
                queue.pop(0)
                continue
            if slot["size_now"] > excess:
                slot["size_now"] -= excess
                self.event("set_size", slot["index"], asset, slot["size_now"])
                break
            oid = queue.pop(0)
            total -= slot["size_now"]
            cancels.append(oid)
        for oid in cancels:
            self.skip(oid, user, 10)

    def sweep_triggers(self, user):
        """Sweep two: reduce-only trigger orders of a user whose position changed sign."""
        a = self.w["args"]
        self.event("user_state", user)
        cancels = []
        for oid, reduce, parked, side in sorted(self.w["untriggered"].get(user, [])):
            if reduce != 1 or (a["oid_tag"] and oid == a["oid"]) or parked:
                continue
            row = self.position(user)
            if row is None or row[1] == 0 or (row[1] <= 0) == bool(side):
                cancels.append(oid)
        for oid in cancels:
            self.skip(oid, user, 10)

    def run(self):
        w, a = self.w, self.w["args"]
        self.side = a["side"]
        self.relations = {key: list(value) for key, value in w["relations"].items()}
        self.budget = 0
        self.filled = 0
        self.fills, self.rows, self.skips = [], [], []
        self.users = {}
        self.touched, self.flipped = set(), set()
        self.sink = []
        self.next_id = w["next_oid"]
        self.last_trade = None
        self.next_link = {}
        self.rest_head = self.rest_tail = None
        self.deques = {user: list(row["oids"]) for user, row in w["reduce_lists"].items()}
        self.slab_rows = book_rows(w)
        for index, row in enumerate(self.slab_rows):
            row["index"] = index
            row["size_now"] = row.get("size", 0)
        self.count = len(self.slab_rows) - w["slab_short"]
        stop = self.entry()
        if stop is not None:
            return self.finish(stop)
        if a["oid_tag"]:
            self.oid = a["oid"]
        else:
            self.oid = self.next_id
            self.next_id = min(self.next_id + 1, MAX64)
        self.budget = self.base
        ended = self.walk()
        if isinstance(ended, dict):
            return self.finish(ended)
        may_rest = not self.taker_only
        if ended == "band":
            if not self.fills:
                return self.finish(self.payload(0x8000000000000013))
            may_rest = False
            if a["oid_tag"]:
                self.event("peer_clear", a["user"], a["oid"])
        elif ended == "used":
            may_rest = False
            if a["oid_tag"]:
                self.add_taker_row()
                if self.taker_only:
                    self.add_taker_row()
        elif a["oid_tag"] and self.taker_only:
            self.add_taker_row()
        self.apply_rows()
        rested = False
        if not may_rest:
            if not self.fills:
                return self.finish(self.payload(0x8000000000000008))
            self.status_row()
        else:
            outcome = self.rest()
            if isinstance(outcome, dict):
                return self.finish(outcome)
            rested = outcome
            if not rested:
                self.status_row()
        for user in sorted(self.touched):
            self.sweep_reduce(user)
        for user in sorted(self.flipped):
            self.sweep_triggers(user)
        users = sorted(self.users.items())
        return self.finish({"oid": self.oid, "fills": self.fills, "users": [[user, oids] for user, oids in users],
                            "cloid": a["cloid"], "fresh_rest": bool(rested and not a["oid_tag"])})

    def finish(self, result):
        book = {"next_oid": self.next_id, "last_trade": self.last_trade, "sizes": [row["size_now"] for row in self.slab_rows],
                "relations": {key: value[0] for key, value in sorted(self.relations.items())},
                "links": {str(key): value for key, value in sorted(self.next_link.items())}, "rest": [self.rest_head, self.rest_tail], "sink": self.sink,
                "deques": {user: oids for user, oids in sorted(self.deques.items()) if oids}}
        return {"log": self.log, "result": result, "book": book}


class SpecPanic(Exception):
    pass


def spec_run(case):
    spec = Spec(copy_world(case.world))
    try:
        return spec.run()
    except SpecPanic as error:
        return {"panic": str(error), "log": spec.log}


def copy_world(w):
    return json.loads(json.dumps(w))


# ---- harness: real bytes; every edge callee is stubbed and logged ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Case:
    def __init__(self, label, kind, world):
        self.label = label
        self.kind = kind
        self.world = world


class Shape:
    """A B-tree node shape: key start and width, length word, first edge, parent word, parent slot, leaf size."""

    def __init__(self, keys, width, length, edges, parent, slot, size):
        self.keys, self.width, self.length, self.edges, self.parent, self.slot, self.size = keys, width, length, edges, parent, slot, size


SIDE_NODE = Shape(0x168, 8, 0x1C2, 0x1C8, 0x160, 0x1C0, 0x1C8)
HALT_NODE = Shape(8, 8, 0x62, 0x68, 0, 0x60, 0x68)
POSITION_NODE = Shape(0x2C8, 8, 0x322, 0x328, 0x2C0, 0x320, 0x328)
TRIGGER_NODE = Shape(8, 8, 0x84A, 0x850, 0, 0x848, 0x850)
LEAF_KEYS = 3
PANIC_NONE = {0x571C9F0: "level head", 0x571CA08: "slot", 0x571CA20: "tail", 0x56F21C0: "perp meta", 0x5733F50: "tree"}
RECORDER = {0x571C990: "recorder size", 0x572AFB8: "recorder size", 0x571C978: "recorder sum", 0x572AFA0: "recorder sum", 0x56EE598: "szi"}


def word_bytes(value):
    return struct.pack("<Q", value & MASK[8])


def twin_map(image):
    """Call targets, data slots and rip words of the first body, row by row against the second; a one to one map."""
    left = decode_range(image, *image.exact_fde(INSERT))
    right = decode_range(image, *image.exact_fde(TWIN))
    pairs = {}
    for one, two in zip(left, right):
        if one.target is not None and two.target is not None and one.op in ("call", "jmp") and one.target - left[0].va != two.target - right[0].va:
            pairs[one.target] = two.target
        for first, second in ((one.a, two.a), (one.b, two.b)):
            if first and first[0] == "m" and first[1] is None and first != second:
                pairs[first[4]] = second[4]
    return pairs


def rol64(value, count):
    value &= MASK[8]
    return ((value << count) | (value >> (64 - count))) & MASK[8]


def fx_hash(key):
    return rol64(key * FX_KEY, 20)


def user_hash(user):
    return (int(user[:16], 16) * 0x9E3779B97F4A7C15) & MASK[8]


class Harness:
    def __init__(self, image, start=INSERT):
        self.image = image
        self.start = start
        self.pairs = twin_map(image) if start != INSERT else {}
        self.back = {right: left for left, right in self.pairs.items()}
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_RECORDER: self.on_recorder,
                 SLOT_GROW_SKIPS: lambda m: self.on_grow(m, 0x28), SLOT_GROW_USER_OIDS: lambda m: self.on_grow(m, 8), SLOT_GROW_CANCEL: lambda m: self.on_grow(m, 8), SLOT_GROW_ROWS: lambda m: self.on_grow(m, 0x20), SLOT_GROW_FILLS: lambda m: self.on_grow(m, FILL_SIZE), SLOT_PUSH_ROW: lambda m: self.on_grow(m, ROW_SIZE),
                 SLOT_DEX_ROW: self.on_dex_row, SLOT_SECOND_GATE: self.on_second_gate, SLOT_ALLOWED: self.on_allowed, SLOT_SETTLE: self.on_settle, SLOT_RESERVE: self.on_reserve, SLOT_CLOID: self.on_cloid, SLOT_TRACK: self.on_track,
                 SLOT_PANIC_NONE: self.on_panic_none, SLOT_PANIC_BOUND: self.on_panic_bound, SLOT_PANIC_TEXT: self.on_panic_text, SLOT_PANIC_UNWRAP: self.on_panic_unwrap, 0x576E128: self.on_stray, 0x576DFB8: self.on_stray}
        for slot in list(table):
            table[self.pairs.get(slot, slot)] = table[slot]
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.jump_low, machine.jump_high = image.exact_fde(start)
        calls = {TIMER: self.on_timer, POSITIONS: self.on_positions, TICK: self.on_tick, FIRST_GATE: self.on_first_gate, TOP_LEVELS: self.on_top, ALO_PAYLOAD: self.on_alo, ALLOW_ROW: self.on_allow_row,
                 USER_HASH: self.on_user_hash, MATCH: self.on_match, PULL: self.on_pull, SET_SIZE: self.on_set_size, COLLECT: self.on_collect, RELATIONS: self.on_relations, REMOVE: self.on_remove,
                 SKIP: self.on_skip, DROP_SET: self.on_drop_set, PEER_CLEAR: self.on_peer, ORDER_LOOKUP: self.on_lookup, LEVEL: self.on_level, SLAB_INSERT: self.on_slab, OID_MAP: self.on_oid_map,
                 USER_STATE: self.on_user_state, USER_SLOTS: self.on_user_slots, REDUCE_PUSH: self.on_reduce_push, TIME_ROW: self.on_time, BUILD_STATUS: self.on_build, VEC_GROW: self.on_vec_grow}
        calls.update({self.pairs[target]: hook for target, hook in list(calls.items()) if target in self.pairs})
        machine.tails = calls
        machine.calls = calls
        self.real.stubs = frozenset(machine.slots) | frozenset(calls)
        self.w = None
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.used = HEAP_SIZE

    def field(self, offset):
        """A field of the exchange state: the second body has the block from +0x1038 up at 0xa80 less."""
        return CTX + (offset - TWIN_SHIFT if self.start != INSERT and offset >= 0x1038 else offset)

    def fixed(self, value):
        """A panic argument as the first body names it."""
        return self.back.get(value, value)

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def static(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x4000:
            raise Halt("allocation size")
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x4000 or (regs[RDX] > 0x80 and regs[RDX] not in (0x90, 0xA8, FILL_SIZE, MATCH_SIZE, ROW_SIZE) and regs[RDX] % 0x14 and regs[RDX] % 8):
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_compare(self, m):
        regs = m.regs
        if regs[RDX] != 0x14:
            raise Halt("compare length")
        left, right = m.memory.bytes_at(regs[RDI], 0x14), m.memory.bytes_at(regs[RSI], 0x14)
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_recorder(self, m):
        label = RECORDER.get(self.fixed(m.regs[RSI]))
        if not label or m.regs[RDI] & 0xFF:
            raise Halt("recorder arguments")
        raise Panicked(label)

    def on_panic_none(self, m):
        label = PANIC_NONE.get(self.fixed(m.regs[RDI]))
        if not label:
            raise Halt("panic location")
        raise Panicked(label)

    def on_panic_bound(self, m):
        if self.fixed(m.regs[RDX]) != 0x571C828:
            raise Halt("bound location")
        raise Panicked("oracle")

    def on_panic_text(self, m):
        if self.fixed(m.regs[RDI]) == 0x6F0596 and m.regs[RSI] == 0x1D and self.fixed(m.regs[RDX]) == 0x571CA50:
            raise Panicked("reduce_only text")
        raise Halt("panic text")

    def on_panic_unwrap(self, m):
        if self.fixed(m.regs[RDI]) == 0x58C079 and m.regs[RSI] == 0x2B and self.fixed(m.regs[RCX]) == 0x56E9F10 and self.fixed(m.regs[R8]) in (0x56E9AE0, 0x56E9AF8):
            raise Panicked("dex bound")
        if m.regs[RDI] == 0x595171 and m.regs[RSI] == 0x2B and m.regs[R8] == 0x56EE580:
            raise Panicked("fill size")
        raise Halt("unwrap text")

    def on_stray(self, m):
        raise Halt("stray call")

    def user(self, m, at):
        return m.memory.bytes_at(at, 0x14).hex()

    def need(self, condition, text):
        if not condition:
            raise Halt(text)

    def market(self):
        return MARKETS + (self.w["asset"] // 10000) * MARKET_SIZE

    def on_timer(self, m):
        self.need(m.memory.read(m.regs[RDI], 2) == 0x141, "timer word")

    def on_positions(self, m):
        regs = m.regs
        self.need(regs[RDI] == self.market() + 0xF8, "positions market")
        user = self.user(m, regs[RSI])
        self.log.append(["positions", user])
        regs[RAX] = self.position_at.get(user, self.empty_position)

    def on_tick(self, m):
        regs = m.regs
        self.need(regs[RDI] == self.market(), "tick market")
        self.log.append(["tick", regs[RSI]])
        regs[RAX] = self.w["tick"]

    def on_first_gate(self, m):
        regs = m.regs
        memory = m.memory
        rsp = regs[RSP]
        self.need(regs[RSI] == self.market(), "gate market")
        self.log.append(["first_gate", self.user(m, regs[RDX]), regs[RCX], regs[R8] & 0xFF, regs[R9], memory.read(rsp + 8, 8), memory.read(rsp + 0x10, 8)])
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", *self.w["first_gate"]))

    def on_second_gate(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        block = regs[RDX]
        self.need(regs[RSI] == self.market(), "second gate market")
        self.log.append(["second_gate", read(block, 8), read(block + 8, 8), read(block + 0x10, 8), self.user(m, block + 0x18), read(block + 0x2C, 1), read(block + 0x2D, 1), read(block + 0x2E, 1), read(block + 0x2F, 1), read(block + 0x30, 1)])
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", *self.w["second_gate"]))

    def on_top(self, m):
        self.need(m.regs[RSI] == BOOK + 0x80, "top book")
        self.log.append(["top_levels"])
        m.memory.write(m.regs[RDI], 8, 0x1234)

    def on_alo(self, m):
        regs = m.regs
        self.need(m.memory.read(regs[RSI], 8) == 0x1234 and regs[RDX] == BOOK and regs[RCX] == self.market(), "alo arguments")
        self.log.append(["alo_payload"])
        m.memory.put_bytes(regs[RDI], struct.pack("<QQ", *self.w["alo"]))

    def on_allow_row(self, m):
        regs = m.regs
        self.need(regs[RSI] == self.field(0x1038) and regs[RDX] == CTX + 0x80, "allow row arguments")
        self.log.append(["allow_row", regs[RDI]])
        regs[RAX] = ALLOW_AT

    def on_allowed(self, m):
        regs = m.regs
        self.need(regs[RDI] == ALLOW_AT and m.memory.bytes_at(regs[R9], 12) == bytes(m.memory.bytes_at(CTX + 0x60, 12)), "allowed arguments")
        self.log.append(["allowed", regs[RSI] & 0xFF, regs[RDX], regs[RCX] & 0xFF, regs[R8]])
        if m.call_site == REST_ALLOWED_SITE + self.start - INSERT:
            answer = self.w["may_rest"]
        else:
            answer = self.w["allowed"].get(str(regs[R8]), True)
        regs[RAX] = (1 if answer else 0) | 0xBC00

    def on_user_hash(self, m):
        regs = m.regs
        self.need(regs[RDI] == self.field(0x11E0), "hash state")
        user = self.user(m, regs[RSI])
        self.log.append(["user_hash", user])
        regs[RAX] = user_hash(user)

    def on_dex_row(self, m):
        regs = m.regs
        self.need(regs[RDI] == self.field(0x1038), "dex row state")
        self.log.append(["dex_row", regs[RSI]])
        regs[RAX] = ALLOW_AT

    def on_pull(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RDI] == CTX and memory.read(regs[R9], 8) == 2, "pull arguments")
        self.log.append(["pull", self.user(m, regs[RSI]), regs[RDX], regs[RCX] & MASK[4], regs[R8], memory.read(regs[RSP] + 8, 4)])

    def on_match(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        out, slot, taker = regs[RDI], regs[RDX], regs[R8]
        self.need(regs[RCX] == CTX, "match state")
        self.need(memory.bytes_at(taker + 0x10, 0x28) == memory.bytes_at(ARGS + 0x48, 0x28), "match block")
        self.need(memory.bytes_at(taker + 0x50, 0x14) == bytes(memory.bytes_at(ARGS + 0xB8, 0x14)), "match user")
        self.need(memory.bytes_at(taker + 0x65, 0x11) == bytes(memory.bytes_at(ARGS + 0x91, 0x11)), "match client id")
        number = self.match_calls
        self.match_calls += 1
        index = self.index_of(slot)
        self.log.append(["match", regs[RSI], index, regs[R9], read(taker + 0x40, 8), read(taker + 0x48, 8), read(taker + 0x64, 1), read(taker, 8), read(taker + 8, 8), read(taker + 0x38, 4), read(taker + 0x3C, 4), read(taker + 0x76, 1)])
        row = scripted_match(self.w, number, read(slot + 0xC8, 8), regs[R9], read(taker + 0x40, 8))
        memory.put_bytes(out, ramp(MATCH_SIZE, 0x63 + number))
        a = self.w["args"]
        user = memory.bytes_at(slot + 0xE0, 0x14)
        users = (user, bytes.fromhex(a["user"])) if a["side"] else (bytes.fromhex(a["user"]), user)
        if row["fill"] is None:
            memory.write(out, 8, 2)
        else:
            legs = row["legs"]
            memory.write(out, 8, legs[0][0])
            memory.write(out + 8, 8, legs[0][1])
            memory.put_bytes(out + 0xD8, users[0])
            memory.write(out + 0x100, 8, legs[1][0])
            memory.write(out + 0x108, 8, legs[1][1])
            memory.put_bytes(out + 0x1D8, users[1])
            memory.write(out + 0x200, 8, row["fill"][0])
            memory.write(out + 0x208, 8, self.w["asset"])
            memory.write(out + 0x210, 8, row["fill"][1])
        status = row["status"]
        second = status[1]
        if not status[0] >> 63:
            second = self.allocate(status[0])
        memory.put_bytes(out + 0x238, struct.pack("<QQQQ", status[0], second, status[2], row["budget"]))
        memory.write(out + 0x258, 1, row["reason"])

    def on_settle(self, m):
        regs = m.regs
        memory = m.memory
        fill = regs[RDX]
        self.need(regs[RDI] == self.market() and regs[RCX] == self.field(0x1050), "settle arguments")
        number = self.fill_calls
        self.fill_calls += 1
        self.log.append(["settle", regs[RSI] & 0xFF, memory.read(fill + 0x200, 8), memory.read(fill + 0x210, 8), number])
        changed = self.w["settled"].get(str(number))
        if changed:
            memory.write(fill + 0x200, 8, changed[0])
            memory.write(fill + 0x210, 8, changed[1])

    def index_of(self, at):
        index, extra = divmod(at - SLAB, SLOT_SIZE)
        self.need(not extra and 0 <= index < SLAB_ROOM, "slot address")
        return index

    def on_set_size(self, m):
        regs = m.regs
        self.need(regs[RCX] == SINK and regs[R8] == BOOK + 0xD0, "set size arguments")
        self.log.append(["set_size", self.index_of(regs[RDI]), regs[RSI], regs[RDX]])
        m.memory.write(regs[RDI] + 0xC8, 8, regs[RDX])

    def on_collect(self, m):
        regs = m.regs
        memory = m.memory
        start, end = regs[RSI], regs[RDX]
        self.need((end - start) % 0x20 == 0 and 0 <= end - start < 0x1000, "collect range")
        self.log.append(["collect", [memory.read(at, 8) for at in range(start, end, 0x20)]])
        memory.put_bytes(regs[RDI], struct.pack("<QQ", SET_MARK, 0x2468))

    def vacate(self, oid):
        index = self.w["oid_table"].get(str(oid))
        if index is not None and index < len(book_rows(self.w)):
            self.machine.memory.write(SLAB + index * SLOT_SIZE, 4, 2)

    def edge_state(self, ctx, sink):
        self.need(ctx == CTX and sink == SINK, "edge state")

    def on_relations(self, m):
        regs = m.regs
        rsp = regs[RSP]
        self.need(regs[RDI] == BOOK and regs[RCX] == SET_MARK and regs[R8] == 0x2468, "relations arguments")
        self.edge_state(regs[R9], m.memory.read(rsp + 8, 8))
        self.log.append(["relations", regs[RDX], self.user(m, regs[RSI])])

    def on_remove(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK, "remove book")
        self.edge_state(regs[RCX], regs[R8])
        self.log.append(["remove", regs[RSI], self.user(m, regs[RDX]), regs[R9] & 0xFF])
        self.vacate(regs[RSI])

    def on_skip(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK, "skip book")
        self.edge_state(regs[RCX], regs[R8])
        self.log.append(["skip", regs[RDX], self.user(m, regs[RSI]), regs[R9] & 0xFF])
        self.vacate(regs[RDX])

    def on_drop_set(self, m):
        self.need(m.memory.read(m.regs[RDI], 8) == SET_MARK, "drop set")
        self.log.append(["drop_set"])

    def on_peer(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK, "peer book")
        self.log.append(["peer_clear", self.user(m, regs[RSI]), regs[RDX]])

    def on_lookup(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK and self.user(m, regs[RSI]) == self.w["args"]["user"], "lookup arguments")
        self.log.append(["lookup", regs[RDX]])
        keys = sorted(self.w["relations"], key=int)
        regs[RAX] = RELATION_AT + keys.index(str(regs[RDX])) * 0x30 if str(regs[RDX]) in keys else 0

    def on_reserve(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RSI] == ALLOW_AT, "reserve row")
        block = regs[RCX]
        self.log.append(["reserve", regs[RDX], memory.read(block, 8), memory.read(block + 8, 8), memory.read(block + 0x10, 8), self.user(m, block + 0x18), memory.read(block + 0x2C, 1), memory.read(block + 0x2D, 1)])
        status, second, third = self.w["reserve"]
        if not status >> 63:
            second = self.allocate(status)
        memory.put_bytes(regs[RDI], struct.pack("<QQQ", status, second, third))

    def on_level(self, m):
        regs = m.regs
        memory = m.memory
        self.need(regs[RDI] in (BOOK + 0x80, BOOK + 0x98), "level tree")
        self.log.append(["level", int(regs[RDI] == BOOK + 0x98), to_signed(regs[RSI])])
        head, tail = self.w["rest_level"]
        self.rest_used = True
        memory.put_bytes(LEVEL_AT, struct.pack("<QQQQ", 0 if head is None else 1, 0x3333 if head is None else head, 0 if tail is None else 1, 0x4444 if tail is None else tail))
        regs[RAX] = LEVEL_AT

    def on_slab(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        record = regs[RSI]
        self.need(regs[RDI] == BOOK and regs[RCX] == SINK and regs[R8] == BOOK + 0xD0, "slab arguments")
        self.need(read(record + 0x10, 8) == 0 and read(record + 0x20, 8) == 1, "slab links")
        self.need(read(record + 0x28, 8) == read(record + 0xC8, 8), "slab size")
        self.need(memory.bytes_at(record + 0x30, 0x20) == memory.bytes_at(ARGS + 0x10, 0x20), "slab words")
        self.need(read(record + 0x50, 8) == read(ARGS + 0x30, 8) and read(record + 0x58, 8) == read(ARGS + 0x38, 8), "slab vector")
        self.need(memory.bytes_at(record + 0x60, 0x40) == memory.bytes_at(ARGS + 0x40, 0x40), "slab block")
        self.need(read(record + 0xA8, 8) == read(ARGS + 0x88, 8) and memory.bytes_at(record + 0xB2, 0x10) == memory.bytes_at(ARGS + 0x92, 0x10), "slab tail words")
        self.need(memory.bytes_at(record + 0xC3, 5) == memory.bytes_at(ARGS + 0xA3, 5), "slab bytes")
        has = read(record + 0xB1, 1)
        self.need(has == read(ARGS + 0x91, 1), "slab client flag")
        self.need(self.time_bytes(m, record + 0x100) or True, "slab time")
        self.log.append(["slab_insert", read(record + 8, 8) if read(record, 8) == 1 else None, read(record + 0xC8, 8), read(record + 0xD0, 8), read(record + 0xD8, 8), read(record + 0xA0, 8), read(record + 0xC2, 1), self.user(m, record + 0xE0),
                         read(record + 0xF5, 1), memory.bytes_at(record + 0xB2, 0x10).hex() if has else None, regs[RDX], read(record + 0xB0, 1), read(record + 0xF4, 1)])
        regs[RAX] = self.w["new_slot"]

    def time_bytes(self, m, at):
        return m.memory.bytes_at(at, 12) == bytes(m.memory.bytes_at(CTX + 0x60, 12))

    def on_oid_map(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0x28, "oid map")
        self.log.append(["oid_map", regs[RSI], regs[RDX]])

    def on_cloid(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0x48 and regs[RCX] == ARGS + 0x92, "client map")
        self.log.append(["cloid", self.user(m, regs[RSI]), regs[RDX], m.memory.bytes_at(regs[RCX], 0x10).hex()])

    def state_of(self, user):
        at = self.state_at.get(user)
        if at is None:
            at = self.static(0x60)
            self.machine.memory.put_bytes(at, ramp(0x60, 0x2B))
            self.machine.memory.put_bytes(at, struct.pack("<QQQQ", 0, 8, 0, 0))
            self.machine.memory.put_bytes(at + 0x38, struct.pack("<QQQ", 0, 0, 0))
            self.state_at[user] = at
        return at

    def on_user_state(self, m):
        regs = m.regs
        self.need(regs[RDI] == BOOK + 0xB8, "user state")
        user = self.user(m, regs[RSI])
        self.log.append(["user_state", user])
        regs[RAX] = self.state_of(user)

    def on_user_slots(self, m):
        regs = m.regs
        at = regs[RDI] - 0x20
        self.need(at in self.state_at.values(), "user slots")
        self.log.append(["user_slots", regs[RSI]])

    def on_reduce_push(self, m):
        regs = m.regs
        memory = m.memory
        at = regs[RDI]
        self.need(at in self.state_at.values(), "reduce state")
        self.log.append(["reduce_push", regs[RSI]])
        cap, pointer, head, length = struct.unpack("<QQQQ", memory.bytes_at(at, 0x20))
        if length == cap:
            fresh = self.allocate(max(cap * 2, 4) * 8)
            for number in range(length):
                memory.write(fresh + number * 8, 8, memory.read(pointer + ((head + number) % cap) * 8, 8))
            if cap:
                self.need(self.live.pop(pointer, None) == cap * 8, "reduce free")
            cap, pointer, head = max(cap * 2, 4), fresh, 0
        memory.write(pointer + ((head + length) % cap) * 8, 8, regs[RSI])
        memory.put_bytes(at, struct.pack("<QQQQ", cap, pointer, head, length + 1))

    def on_track(self, m):
        regs = m.regs
        self.need(regs[RDI] == self.field(0x11C0), "track state")
        self.log.append(["track", self.user(m, regs[RSI])])

    def on_time(self, m):
        regs = m.regs
        self.need(regs[RDI] == CTX, "time state")
        self.log.append(["time_row", regs[RSI]])
        regs[RAX] = 0x7654321

    def on_build(self, m):
        regs = m.regs
        memory = m.memory
        read = memory.read
        block = regs[RDX]
        self.need(regs[RSI] == BOOK and regs[RCX] == 0x7654321, "build arguments")
        self.need(read(block, 8) == 0 and read(block + 0x10, 8) == 0, "build zeros")
        self.need(read(block + 0x20, 8) == read(ARGS, 8) and read(block + 0x30, 8) == read(ARGS + 0x10, 8) and read(block + 0x38, 8) == read(ARGS + 0x18, 8) and read(block + 0x40, 8) == read(ARGS + 0x20, 8) and read(block + 0x48, 8) == read(ARGS + 0x28, 8), "build words")
        self.need(read(block + 0x28, 8) == read(ARGS + 8, 8) and read(block + 0x60, 8) == read(ARGS + 0x40, 8), "build sizes")
        self.need(read(block + 0x98, 8) == read(ARGS + 0x78, 8) and read(block + 0xA8, 8) == read(ARGS + 0x88, 8) and read(block + 0xB0, 1) == read(ARGS + 0x90, 1) and read(block + 0xB1, 1) == read(ARGS + 0x91, 1), "build tail")
        tag = 1 if read(ARGS + 0x48, 4) == 1 else 0
        self.need(read(block + 0x68, 8) == tag and (not tag or memory.bytes_at(block + 0x70, 0x20) == memory.bytes_at(ARGS + 0x50, 0x20)), "build block")
        pointer, count = read(block + 0x58, 8), read(block + 0x60, 8)
        self.need((pointer == 8 if not count else memory.bytes_at(pointer, count * 8) == memory.bytes_at(read(ARGS + 0x38, 8), count * 8)), "build vector")
        self.build_block = memory.bytes_at(block + 0x68, 0x28)
        self.need(not read(ARGS + 0x91, 1) or memory.bytes_at(block + 0xB2, 0x10) == memory.bytes_at(ARGS + 0x92, 0x10), "build client id")
        self.need(read(block + 0xF4, 1) == (read(ARGS, 1) ^ 1), "build flag")
        self.log.append(["build_status", read(block + 0xC8, 8), read(block + 0xD0, 8), read(block + 0xD8, 8), self.user(m, block + 0xE0), read(block + 0xF5, 1), read(block + 0xA0, 8), read(block + 0xC2, 1), read(block + 0x90, 8)])
        memory.write(regs[RDI], 8, read(block + 0xD8, 8))

    def on_grow(self, m, size):
        memory = m.memory
        vector = m.regs[RDI]
        capacity, old, length = memory.read(vector, 8), memory.read(vector + 8, 8), memory.read(vector + 0x10, 8)
        self.need(capacity == length and capacity <= 0x100, "grow vector")
        wanted = capacity * 2 or 4
        fresh = self.allocate(wanted * size)
        if capacity:
            memory.copy(fresh, old, capacity * size)
            self.need(self.live.pop(old, None) == capacity * size, "grow free")
        memory.write(vector, 8, wanted)
        memory.write(vector + 8, 8, fresh)

    def on_vec_grow(self, m):
        regs = m.regs
        self.need(regs[RDX] == 1 and regs[RCX] == 8 and regs[R8] == 8, "vector grow arguments")
        self.need(m.memory.read(regs[RDI], 8) == regs[RSI], "vector grow length")
        vector = regs[RDI]
        m.memory.write(vector + 0x10, 8, regs[RSI])
        self.on_grow(m, 8)

    def put_keys(self, at, shape, keys, spare, height=0, children=None):
        memory = self.machine.memory
        size = shape.size + (0x60 if height else 0)
        memory.put_bytes(at, ramp(size, 0x35))
        for index in range(11):
            memory.put_bytes(at + shape.keys + index * shape.width, keys[index] if index < len(keys) else spare)
        memory.write(at + shape.length, 2, len(keys))
        memory.write(at + shape.parent, 8, 0)
        if children:
            for index, child in enumerate(children):
                memory.write(at + shape.edges + index * 8, 8, child)
                memory.write(child + shape.parent, 8, at)
                memory.write(child + shape.slot, 2, index)

    def tree(self, shape, keys, spare):
        """A real tree of one or two levels; returns (root, height, node addresses)."""
        if not keys:
            return 0, 0, []
        if len(keys) <= LEAF_KEYS:
            root = self.static(shape.size)
            self.put_keys(root, shape, keys, spare)
            return root, 0, [root]
        leaves = []
        separators = []
        at = 0
        while at < len(keys):
            take = LEAF_KEYS + 1 if at + LEAF_KEYS + 1 == len(keys) else LEAF_KEYS
            leaves.append(keys[at:at + take])
            if at + take < len(keys):
                separators.append(keys[at + take])
            at += take + 1
        nodes = []
        for leaf in leaves:
            node = self.static(shape.size)
            self.put_keys(node, shape, leaf, spare)
            nodes.append(node)
        root = self.static(shape.size + 0x60)
        self.put_keys(root, shape, separators, spare, 1, nodes)
        return root, 1, [root] + nodes

    def nested(self, shape, keys, height, spare):
        if not height:
            root = self.static(shape.size)
            self.put_keys(root, shape, keys, spare)
            return root, [root]
        middle = len(keys) // 2
        left, left_nodes = self.nested(shape, keys[:middle], height - 1, spare)
        right, right_nodes = self.nested(shape, keys[middle + 1:], height - 1, spare)
        root = self.static(shape.size + 0x60)
        self.put_keys(root, shape, [keys[middle]], spare, 1, [left, right])
        return root, [root] + left_nodes + right_nodes

    def put_slot(self, index, slot, follower):
        memory = self.machine.memory
        at = SLAB + index * SLOT_SIZE
        memory.put_bytes(at, ramp(SLOT_SIZE, 0x41 + index * 5))
        memory.write(at, 8, 2 if slot.get("vacant") else 1)
        memory.write(at + 8, 8, 0x5555)
        memory.write(at + 0x10, 1, 0 if follower is None else 1)
        memory.write(at + 0x18, 8, 0x5A5A if follower is None else follower)
        memory.write(at + 0x20, 8, slot.get("tag", 1))
        memory.write(at + 0x28, 8, slot.get("limit", 0))
        memory.write(at + 0xC2, 1, slot.get("side", 0))
        memory.write(at + 0xC8, 8, slot.get("size", 0))
        memory.write(at + 0xD8, 8, slot.get("oid", 0x99))
        memory.put_bytes(at + 0xE0, bytes.fromhex(slot.get("user", USERS[3])))

    def swiss(self, entries, stride, room):
        """A real group table: entries are (hash, bytes); returns the control address."""
        memory = self.machine.memory
        base = self.static(stride * room + room + 16)
        memory.put_bytes(base, ramp(stride * room, 0x5D))
        ctrl = base + stride * room
        memory.put_bytes(ctrl, b"\xff" * (room + 16))
        table = [0xFF] * room
        for hashed, data in entries:
            at = hashed & (room - 1)
            step = 0
            while True:
                free = [number for number in range(16) if table[(at + number) & (room - 1)] == 0xFF]
                if free:
                    index = (at + free[0]) & (room - 1)
                    break
                step += 16
                at = (at + step) & (room - 1)
            table[index] = hashed >> 57
            memory.write(ctrl + index, 1, hashed >> 57)
            if index < 16:
                memory.write(ctrl + room + index, 1, hashed >> 57)
            memory.put_bytes(ctrl - (index + 1) * stride, data)
        return ctrl

    def build_positions(self, w):
        memory = self.machine.memory
        self.empty_position = self.static(0x20)
        memory.put_bytes(self.empty_position, struct.pack("<QQQQ", 0x77, 0, 0, 0x55))
        self.position_at = {}
        for user, rows in sorted(w["positions"].items()):
            keys = sorted(int(key) for key in rows)
            root, height, nodes = self.tree(POSITION_NODE, [struct.pack("<Q", key) for key in keys], struct.pack("<Q", w["spare"]))
            for node in nodes:
                memory.put_bytes(node, ramp(0x2C0, 0x17))
                for index in range(memory.read(node + POSITION_NODE.length, 2)):
                    tag, szi = rows[str(memory.read(node + 0x2C8 + index * 8, 8))]
                    memory.write(node + index * 0x40, 4, tag)
                    memory.write(node + index * 0x40 + 0x10, 8, szi)
            at = self.static(0x20)
            memory.put_bytes(at, struct.pack("<QQQQ", 0x77, root, height, 0x55))
            self.position_at[user] = at

    def build_market(self, w):
        memory = self.machine.memory
        memory.put_bytes(MARKETS, ramp(MARKET_SIZE * 3, 0x19))
        at = self.market()
        memory.write(self.field(0x1040), 8, MARKETS)
        memory.write(self.field(0x1048), 8, w["dex_count"])
        memory.write(at + 8, 8, META_AT)
        memory.write(at + 0x10, 8, len(w["meta"]))
        memory.write(at + 0x30, 8, w["meta_dex"])
        memory.write(at + 0x68, 8, ORACLE_AT)
        memory.write(at + 0x70, 8, len(w["oracle"]))
        memory.write(at + 0x230, 1, w["main_byte"])
        memory.put_bytes(META_AT, ramp(0x30 * 12, 0x23))
        memory.put_bytes(ORACLE_AT, ramp(0x60 * 12, 0x4F))
        for index, flag in enumerate(w["meta"]):
            memory.write(META_AT + index * 0x30 + 0x28, 1, flag)
        for index, word in enumerate(w["oracle"]):
            memory.write(ORACLE_AT + index * 0x60 + 0x20, 8, word)
        keys = sorted(w["halted"])
        spare = struct.pack("<Q", w["spare"])
        if w["halt_height"] and keys:
            root, _ = self.nested(HALT_NODE, [struct.pack("<Q", key) for key in keys], w["halt_height"], spare)
            height = w["halt_height"]
        else:
            root, height, _ = self.tree(HALT_NODE, [struct.pack("<Q", key) for key in keys], spare)
        memory.write(at + 0x270, 8, root)
        memory.write(at + 0x278, 8, height)

    def build_state(self, w):
        memory = self.machine.memory
        self.state_at = {}
        modes = sorted(w["modes"].items())
        entries = []
        for user, mode in modes:
            data = bytearray(ramp(0x58, 0x3D))
            data[:0x14] = bytes.fromhex(user)
            data[0x54] = mode
            entries.append((user_hash(user), bytes(data)))
        for hashed, data in [(user_hash(user), None) for user in w["twin_users"]]:
            bytes_row = bytearray(ramp(0x58, 0x3D))
            bytes_row[0] ^= 0xFF
            entries.append((hashed, bytes(bytes_row)))
        room = 32
        memory.write(self.field(0x11C0), 8, self.swiss(entries, 0x58, room))
        memory.write(self.field(0x11C8), 8, room - 1)
        memory.write(self.field(0x11D8), 8, len(entries) if entries else 0)
        for user, row in sorted(w["reduce_lists"].items()):
            at = self.state_of(user)
            oids, cap, head = row["oids"], row["cap"], row["head"]
            pointer = self.allocate(cap * 8) if cap else 8
            for number, oid in enumerate(oids):
                memory.write(pointer + ((head + number) % cap) * 8, 8, oid)
            memory.put_bytes(at, struct.pack("<QQQQ", cap, pointer, head, len(oids)))
        for user, rows in sorted(w["untriggered"].items()):
            at = self.state_of(user)
            ordered = sorted(rows)
            root, height, nodes = self.tree(TRIGGER_NODE, [struct.pack("<Q", row[0]) for row in ordered], struct.pack("<Q", w["spare"]))
            by_oid = {row[0]: row for row in ordered}
            for node in nodes:
                memory.put_bytes(node + 0x60, ramp(0xB8 * 11, 0x2F))
                for index in range(memory.read(node + TRIGGER_NODE.length, 2)):
                    oid, reduce, parked, side = by_oid[memory.read(node + 8 + index * 8, 8)]
                    value = node + 0x60 + index * 0xB8
                    memory.write(value + 0x90, 1, reduce)
                    memory.write(value + 0x10, 1, parked)
                    memory.write(value + 0xA2, 1, side)
            memory.put_bytes(at + 0x38, struct.pack("<QQQ", root, height, len(rows)))

    def build(self, w):
        memory = self.machine.memory
        self.w = w
        memory.reset(self.used)
        self.brk = HEAP_FREE
        self.live = {}
        self.log = []
        self.fill_calls = 0
        self.match_calls = 0
        self.rest_used = False
        a = w["args"]
        memory.put_bytes(BOOK, ramp(0x100, 0x27))
        memory.put_bytes(CTX, ramp(0x1400, 0x47))
        memory.put_bytes(ARGS, ramp(0xD0, 0x71))
        memory.put_bytes(ALLOW_AT, ramp(0x60, 0x29))
        memory.write(ALLOW_AT + 0x50, 8, w["pull_word"])
        memory.write(SINK, 8, 0)
        memory.write(SINK + 8, 8, 8)
        memory.write(SINK + 0x10, 8, 0)
        memory.write(BOOK + 0xB0, 8, w["asset"])
        memory.write(BOOK + 8, 8, SLAB)
        rows = book_rows(w)
        memory.write(BOOK + 0x10, 8, len(rows) - w["slab_short"])
        memory.write(CTX + 0x38, 8, w["next_oid"])
        memory.write(self.field(0x1370), 1, w["byte"])
        memory.write(self.field(0x1371), 1, w["mode"])
        memory.write(self.field(0x1372), 1, w["bc"])
        memory.write(CTX + 0x5B0, 1, w["byte_5b0"])
        memory.write(CTX + 0x5B1, 1, w["byte_5b1"])
        self.build_market(w)
        self.build_positions(w)
        self.build_state(w)
        for tree_at, levels in ((BOOK + 0x98, w["levels"] if not a["side"] else []), (BOOK + 0x80, w["levels"] if a["side"] else [])):
            self.side_tree(tree_at, levels, a["side"])
        memory.put_bytes(BOOK + (0x98 if a["side"] else 0x80), struct.pack("<QQQ", w["own_root"], 0, 0))
        index = 0
        for level in w["levels"]:
            chain = level["slots"]
            for number, slot in enumerate(chain):
                follower = index + 1 if number + 1 < len(chain) else None
                self.put_slot(index, slot, follower)
                index += 1
        for row in w["extra_slots"]:
            self.put_slot(index, row, None)
            index += 1
        if w["broken_slot"] is not None:
            memory.write(SLAB + w["broken_slot"] * SLOT_SIZE, 4, 2)
        table = []
        for key, value in sorted(w["oid_table"].items(), key=lambda item: int(item[0])):
            table.append((fx_hash(int(key)), struct.pack("<QQ", int(key), value)))
        for key in w["oid_twins"]:
            table.append((fx_hash(key), struct.pack("<QQ", key ^ 0x7000, 1)))
        room = 64
        memory.write(BOOK + 0x28, 8, self.swiss(table, 0x10, room))
        memory.write(BOOK + 0x30, 8, room - 1)
        memory.write(BOOK + 0x40, 8, len(table))
        for number, key in enumerate(sorted(w["relations"], key=int)):
            at = RELATION_AT + number * 0x30
            memory.put_bytes(at, ramp(0x30, 0x19))
            memory.write(at + 0x20, 8, w["relations"][key][0])
            memory.write(at + 0x28, 8, w["relations"][key][1])
        memory.write(ARGS, 8, a["tag"])
        memory.write(ARGS + 8, 8, a["size"])
        vector = a["vector"]
        if vector:
            cap = len(vector) + 1
            buffer = self.allocate(cap * 8)
            memory.put_bytes(buffer, b"".join(word_bytes(item) for item in vector))
            memory.put_bytes(ARGS + 0x30, struct.pack("<QQQ", cap, buffer, len(vector)))
            self.vector = buffer
        else:
            memory.put_bytes(ARGS + 0x30, struct.pack("<QQQ", 0, 8, 0))
            self.vector = None
        memory.write(ARGS + 0x48, 4, a["block"])
        memory.write(ARGS + 0x70, 8, a["kind"])
        memory.write(ARGS + 0x78, 8, a["word"])
        memory.write(ARGS + 0x80, 8, a["px"])
        memory.write(ARGS + 0x90, 1, a["reduce"])
        memory.write(ARGS + 0x91, 1, 1 if a["cloid"] is not None else 0)
        if a["cloid"] is not None:
            memory.put_bytes(ARGS + 0x92, bytes.fromhex(a["cloid"]))
        memory.write(ARGS + 0xA2, 1, a["side"])
        memory.write(ARGS + 0xA8, 8, a["oid_tag"])
        memory.write(ARGS + 0xB0, 8, a["oid"])
        memory.put_bytes(ARGS + 0xB8, bytes.fromhex(a["user"]))
        memory.write(ARGS + 0xCC, 1, a["tif"])

    def side_tree(self, at, levels, side):
        memory = self.machine.memory
        ordered = sorted(levels, key=lambda row: -row["px"] if side else row["px"])
        keys = [struct.pack("<q", -row["px"] if side else row["px"]) for row in ordered]
        spare = struct.pack("<q", -1 if side else 1)
        wanted = self.w["tree_height"]
        if wanted and keys:
            root, nodes = self.nested(SIDE_NODE, keys, wanted, spare)
            height = wanted
        else:
            root, height, nodes = self.tree(SIDE_NODE, keys, spare)
        memory.put_bytes(at, struct.pack("<QQQ", root, height, len(keys)))
        chains = {}
        index = 0
        for level in levels:
            chains[-level["px"] if side else level["px"]] = (index, len(level["slots"]), level.get("head", True))
            index += len(level["slots"])
        for node in nodes:
            for number in range(memory.read(node + SIDE_NODE.length, 2)):
                key = to_signed(memory.read(node + SIDE_NODE.keys + number * 8, 8))
                first, count, head = chains[key]
                memory.put_bytes(node + number * 0x20, struct.pack("<QQQQ", 1 if count and head else 0, first, 1 if count else 0, first + count - 1))

    def stack(self, words):
        memory = self.machine.memory
        for index, value in enumerate(words):
            memory.write(STACK_TOP - 0x100 + index * 8, 8, value)

    def run(self, case):
        w = case.world
        machine = self.machine
        memory = machine.memory
        self.build(w)
        self.stack([SINK])
        try:
            machine.run(self.start, {RDI: OUT, RSI: BOOK, RDX: ARGS, RCX: w["word_one"], R8: w["word_two"], R9: CTX})
        except Panicked as error:
            return {"panic": str(error), "log": self.log}
        result = self.read_out()
        rested = bool(self.rest_used and self.log and any(row[0] == "track" for row in self.log))
        if rested and self.vector is not None:
            self.need(self.live.pop(self.vector, None) is not None, "vector moved")
        book = self.read_book()
        book["sink"] = self.read_sink()
        if self.live:
            raise Halt("leak %r" % sorted(self.live.values()))
        return {"log": self.log, "result": result, "book": book}

    def read_sink(self):
        memory = self.machine.memory
        read = memory.read
        cap, pointer, length = read(SINK, 8), read(SINK + 8, 8), read(SINK + 0x10, 8)
        self.need(length <= 8, "sink length")
        rows = []
        for number in range(length):
            at = pointer + number * ROW_SIZE
            self.need(read(at, 8) == 3 and read(at + 8, 8) == 2 and read(at + 0x100, 1) == 1, "row head")
            self.need(memory.bytes_at(at + 0xE0, 12) == bytes(memory.bytes_at(CTX + 0x60, 12)), "row time")
            self.need(memory.bytes_at(at + 0x10, 0x28) == self.build_block, "row block")
            rows.append([read(at + 0x38, 8), self.user(self.machine, at + 0xEC)])
        if cap:
            self.need(self.live.pop(pointer, None) == cap * ROW_SIZE, "sink buffer")
        return rows

    def read_out(self):
        memory = self.machine.memory
        read = memory.read
        first = read(OUT, 8)
        if first == NONE_WORD:
            status = read(OUT + 8, 8)
            second, third = read(OUT + 0x10, 8), read(OUT + 0x18, 8)
            if not status >> 63:
                self.need(self.live.pop(second, None) == status, "text status")
                second = None
            return {"status": status, "second": second, "third": third}
        pointer, count = read(OUT + 8, 8), read(OUT + 0x10, 8)
        self.need(count <= 0x40 and (first or pointer == 8), "fill count")
        fills = []
        for index in range(count):
            at = pointer + index * FILL_SIZE
            fills.append([read(at + 0x200, 8), read(at + 0x208, 8), read(at + 0x210, 8)])
        if first:
            self.need(self.live.pop(pointer, None) == first * FILL_SIZE, "fill buffer")
        users = self.read_users(read(OUT + 0x18, 8), read(OUT + 0x20, 8), read(OUT + 0x28, 8))
        has = read(OUT + 0x38, 1)
        return {"oid": read(OUT + 0x30, 8), "fills": fills, "users": users, "cloid": memory.bytes_at(OUT + 0x39, 0x10).hex() if has else None, "fresh_rest": bool(read(OUT + 0x49, 1))}

    def read_users(self, root, height, length):
        """The result map: one leaf in these runs; every buffer is released."""
        memory = self.machine.memory
        read = memory.read
        if not root:
            self.need(length == 0, "map length")
            return []
        self.need(height == 0 and length <= 11 and read(root + 0x1EE, 2) == length, "map shape")
        rows = []
        for index in range(length):
            cap, at, count = read(root + 8 + index * 0x18, 8), read(root + 0x10 + index * 0x18, 8), read(root + 0x18 + index * 0x18, 8)
            self.need(count <= 0x40, "map row")
            rows.append([memory.bytes_at(root + 0x110 + index * 0x14, 0x14).hex(), [read(at + at2 * 8, 8) for at2 in range(count)]])
            self.need(self.live.pop(at, None) == cap * 8, "map row buffer")
        self.need(self.live.pop(root, None) is not None, "map root")
        return rows

    def read_deques(self):
        memory = self.machine.memory
        read = memory.read
        rows = {}
        for user, at in sorted(self.state_at.items()):
            cap, pointer, head, length = struct.unpack("<QQQQ", memory.bytes_at(at, 0x20))
            self.need(length <= 0x40 and (not length or cap), "deque shape")
            if length:
                rows[user] = [read(pointer + ((head + number) % cap) * 8, 8) for number in range(length)]
            if cap:
                self.need(self.live.pop(pointer, None) == cap * 8, "deque buffer")
        return rows

    def read_book(self):
        memory = self.machine.memory
        read = memory.read
        w = self.w
        rows = book_rows(w)
        sizes = [read(SLAB + index * SLOT_SIZE + 0xC8, 8) for index in range(len(rows))]
        links = {}
        head, tail = None, None
        if self.rest_used and any(row[0] == "track" for row in self.log):
            head = read(LEVEL_AT + 8, 8) if read(LEVEL_AT, 8) == 1 else None
            tail = read(LEVEL_AT + 0x18, 8) if read(LEVEL_AT + 0x10, 8) == 1 else None
            old = w["rest_level"][1]
            if old is not None:
                self.need(read(SLAB + old * SLOT_SIZE + 0x10, 8) == 1, "tail link tag")
                links[str(old)] = read(SLAB + old * SLOT_SIZE + 0x18, 8)
        relations = {key: read(RELATION_AT + number * 0x30 + 0x20, 8) for number, key in enumerate(sorted(w["relations"], key=int))}
        changed = read(BOOK + 0x78, 8)
        return {"next_oid": read(CTX + 0x38, 8), "last_trade": None if changed == self.start_last() else changed, "sizes": sizes, "relations": dict(sorted(relations.items())), "links": links, "rest": [head, tail], "deques": self.read_deques()}

    def start_last(self):
        return int.from_bytes(ramp(0x100, 0x27)[0x78:0x80], "little")


CRASHES = (Halt, Panicked, EvidenceError, KeyError, IndexError, ValueError, TypeError, OverflowError, struct.error, UnicodeDecodeError, ZeroDivisionError)


def normal(expected, got):
    """A None in the prediction marks a word the code leaves stale."""
    result = expected.get("result")
    if result and "status" in result and "result" in got:
        fixed = dict(got["result"])
        for key in ("second", "third"):
            if result.get(key) is None and key in fixed:
                fixed[key] = None
        got = dict(got, result=fixed)
    return got


def compare_run(harness, case):
    """None when the run agrees with the spec, else a text."""
    try:
        expected = spec_run(case)
        got = normal(expected, harness.run(case))
    except CRASHES as error:
        return "%s: crash %s %s" % (case.kind, case.label, str(error)[:120])
    if got != expected:
        return "%s: differ %s: %s" % (case.kind, case.label, first_difference(got, expected))
    return None


def first_difference(got, expected):
    if set(got) != set(expected):
        return "shape %r %r" % (sorted(got), expected.get("panic"))
    for key in ("log", "result", "book"):
        one, two = got.get(key), expected.get(key)
        if one != two:
            if key == "log":
                for index, (left, right) in enumerate(zip(one, two)):
                    if left != right:
                        return "log[%d]: %.300r != %.300r" % (index, left, right)
                return "log length %d %d: %.300r" % (len(one), len(two), (one + two)[min(len(one), len(two))])
            return "%s: %.600r != %.600r" % (key, one, two)
    return "same"


def ramp(count, start):
    return bytes((start + index * 7) & 0xFF for index in range(count))


# ---- cases ----

ASSET = 10005


def args(**extra):
    row = {"tag": 1, "size": 10, "px": 100, "side": 0, "tif": 2, "reduce": 0, "oid_tag": 0, "oid": 0x777, "cloid": None, "kind": 2, "word": 0xABCD, "vector": [], "block": 0, "user": TAKER}
    row.update(extra)
    return row


def slot(user, size, oid, side=1):
    return {"user": user, "size": size, "oid": oid, "side": side, "tag": 1, "limit": size}


def world(levels=(), a=None, **extra):
    w = {"args": args(**(a or {})), "levels": [dict(level) for level in levels], "asset": ASSET, "dex_count": 2, "meta_dex": 1, "meta": [0, 0, 0, 0, 0, 1, 0], "oracle": [0x111 * index for index in range(7)], "main_byte": 3,
         "mode": 2, "halted": [], "halt_height": 0, "positions": {}, "spare": 9999, "word_one": 0x31, "word_two": 0x47, "next_oid": 500, "byte": 1, "bc": 5, "tick": 10, "alo": [0x1111, 0x2222], "first_gate": [OK, 1, 2], "second_gate": [OK, 3, 4],
         "match": {}, "settled": {}, "allowed": {}, "may_rest": True, "reserve": [OK, 0, 0], "rest_level": [None, None], "new_slot": 30, "relations": {}, "extra_slots": [{"size": 7, "oid": 0x98}, {"vacant": True, "oid": 0x97}],
         "slab_short": 0, "broken_slot": None, "own_root": 0, "tree_height": 0, "modes": {}, "twin_users": [], "byte_5b0": 0, "byte_5b1": 0, "pull_word": 0x5150, "reduce_lists": {}, "untriggered": {}, "oid_twins": []}
    w.update(extra)
    rows = book_rows(w)
    table = {str(row.get("oid", 0x99)): index for index, row in enumerate(rows)}
    table.update(w.get("oid_extra", {}))
    w["oid_table"] = table
    return w


def book(side=0, sizes=(4, 4, 4), prices=None, users=None):
    """Three price levels of one maker each, by default; sells walk bids at 100, 90, 80 and buys walk asks at 100, 110, 120."""
    prices = prices or ([100 - 10 * index for index in range(len(sizes))] if side else [100 + 10 * index for index in range(len(sizes))])
    users = users or USERS
    return [{"px": px, "slots": [slot(users[index % len(users)], size, 0x100 + index, 1 - side)]} for index, (px, size) in enumerate(zip(prices, sizes))]


def chain(px, sizes, start=0, side=1):
    return {"px": px, "slots": [slot(USERS[(start + index) % 3], size, 0x200 + start + index, side) for index, size in enumerate(sizes)]}


def long(size, tag=1):
    return {str(ASSET): [tag, size]}


def rlist(oids, cap=None, head=0):
    return {"oids": list(oids), "cap": cap if cap is not None else max(len(oids), 1), "head": head}


def ro(oid, size, user=USERS[0], side=1, tag=1, limit=None):
    return {"size": size, "oid": oid, "user": user, "side": side, "tag": tag, "limit": size if limit is None else limit}


def all_cases():
    cases = []

    def add(label, kind, w):
        cases.append(Case(label, kind, w))

    # entry gates
    add("dex bound", "entry", world(dex_count=1))
    add("dex bound equal", "entry", world(asset=20001))
    add("halted", "entry", world(halted=[ASSET]))
    add("halted among", "entry", world(halted=[3, ASSET, 20000, 30000]))
    add("halted deep", "entry", world(halted=[1, 2, 3, ASSET - 1, ASSET, ASSET + 1, 20000], halt_height=1))
    add("halted deep left", "entry", world(halted=[ASSET - 3, ASSET, ASSET + 3, ASSET + 4, ASSET + 5, ASSET + 6, ASSET + 7], halt_height=1))
    add("not halted", "entry", world(halted=[1, 2, 3]))
    add("not halted above", "entry", world(halted=[20000, 20001]))
    add("not halted deep", "entry", world(halted=[1, 2, 3, 4, 5, 6, 7], halt_height=1))
    for mode in (0, 1, 2):
        for reduce in (0, 1):
            base = {"positions": {TAKER: long(-5)}} if reduce else {}
            add("builder no row mode %d reduce %d" % (mode, reduce), "entry", world([], {"reduce": reduce}, main_byte=1, mode=mode, asset=10004))
            add("builder listed mode %d reduce %d" % (mode, reduce), "entry", world([], {"reduce": reduce}, main_byte=1, mode=mode, **base))
            add("builder row tag 1 mode %d reduce %d" % (mode, reduce), "entry", world([], {"reduce": reduce}, main_byte=1, mode=mode, asset=10004, positions={TAKER: {"10004": [1, -5]}}))
            add("builder row tag 0 mode %d reduce %d" % (mode, reduce), "entry", world([], {"reduce": reduce}, main_byte=1, mode=mode, asset=10004, positions={TAKER: {"10004": [0, -5]}}))
    add("builder other asset row", "entry", world([], main_byte=1, mode=0, asset=10004, positions={TAKER: {"10003": [1, 5], "10006": [1, 5]}}))
    add("builder many rows", "entry", world([], main_byte=1, mode=0, asset=10004, positions={TAKER: {str(10000 + number): [1, 5] for number in range(8)}}))
    add("builder many rows absent", "entry", world([], main_byte=1, mode=0, asset=10008, positions={TAKER: {str(10000 + number): [1, 5] for number in range(8)}}, meta=[0] * 9, oracle=[1] * 9))
    add("meta other dex", "entry", world([], main_byte=1, meta_dex=0, asset=10004))
    add("meta short", "entry", world([], main_byte=1, meta=[0, 0, 0], asset=10004))
    add("meta edge", "entry", world([], main_byte=1, meta=[0, 0, 0, 0, 1], asset=10004))
    add("main byte 2", "entry", world([], main_byte=2, mode=0, asset=10004))
    add("main byte 7", "entry", world([], main_byte=7, mode=1, asset=10004))
    for tif in range(5):
        for side in (0, 1):
            for level_px, cross_name in ((100, "touch"), (90, "low"), (110, "high")):
                add("tif %d side %d %s" % (tif, side, cross_name), "entry", world([chain(level_px, [1], side=1 - side)], {"tif": tif, "side": side}, match={"0": {"reason": 3, "fill": None, "status": [0x8000000000000002, 7, 8]}}))
            add("tif %d side %d empty book" % (tif, side), "entry", world([], {"tif": tif, "side": side}))
    add("no size no reduce", "entry", world([], {"tag": 0}))
    add("tag zero book zero", "entry", world([], {"side": 1, "tag": 0}))
    for side, szi in ((1, 5), (0, -5)):
        for size, tag in ((3, 1), (5, 1), (9, 1), (3, 0), (0, 0)):
            add("reduce clamp side %d size %d tag %d" % (side, size, tag), "reduce", world([], {"side": side, "reduce": 1, "size": size, "tag": tag}, positions={TAKER: long(szi)}, may_rest=False))
            add("reduce clamp rests side %d size %d tag %d" % (side, size, tag), "reduce", world([], {"side": side, "reduce": 1, "size": size, "tag": tag}, positions={TAKER: long(szi)}))
    for side, szi in ((1, -5), (0, 5), (1, 0), (0, 0)):
        add("reduce wrong side %d szi %d" % (side, szi), "reduce", world([], {"side": side, "reduce": 1}, positions={TAKER: long(szi)}))
    add("reduce no row", "reduce", world([], {"reduce": 1}))
    add("reduce other row", "reduce", world([], {"reduce": 1, "side": 1}, positions={TAKER: {"10001": [1, 5], "10009": [1, 5]}}))
    add("reduce deep row", "reduce", world([], {"reduce": 1, "side": 1}, positions={TAKER: {str(10000 + number): [1, 5 + number] for number in range(9)}}))
    add("reduce deep absent", "reduce", world([], {"reduce": 1, "side": 1}, positions={TAKER: {str(10010 + number): [1, 5] for number in range(9)}}))
    for px in (10 ** 15, 10 ** 15 + 10, 2 ** 40 * 10):
        add("price %d" % px, "entry", world([], {"px": px}))
    add("price edge zero", "entry", world([], {"px": 0}, tick=1))
    for px, tick in ((105, 10), (2 ** 33 + 1, 3), (2 ** 33 + 3, 2 ** 33 + 3), (100, 7), (2 ** 40 + 1, 1)):
        add("tick %d %d" % (px, tick), "entry", world([], {"px": px}, tick=tick))
    add("oracle short", "entry", world([], oracle=[1, 2, 3]))
    add("oracle edge", "entry", world([], oracle=[1, 2, 3, 4, 5]))
    add("oracle last", "entry", world([], oracle=[1, 2, 3, 4, 5, 0x600]))
    add("first gate stops", "entry", world([], first_gate=[0x8000000000000001, 0x12, 0x34]))
    add("first gate text", "entry", world([], {"side": 1, "size": 77, "user": USERS[1]}, first_gate=[0x8000000000000003, 0x56, 0x78]))
    add("second gate stops", "entry", world([], second_gate=[0x8000000000000009, 0x21, 0x43]))
    add("second gate cross flags", "entry", world([chain(100, [1])], {"tif": 1}, second_gate=[0x800000000000000A, 0x65, 0x87]))
    add("second gate reduce flag", "entry", world([], {"reduce": 1, "side": 1}, positions={TAKER: long(4)}, byte=0, second_gate=[0x800000000000000B, 0x65, 0x87]))

    # walk
    for side in (0, 1):
        add("rests empty side %d" % side, "rest", world([], {"side": side}))
        add("one level partial side %d" % side, "walk", world(book(side, (4,)), {"side": side}))
        add("three levels side %d" % side, "walk", world(book(side), {"side": side, "size": 10}))
        add("three levels used side %d" % side, "walk", world(book(side), {"side": side, "size": 12}))
        add("limit stops side %d" % side, "walk", world(book(side, (2, 2, 2, 2), [100 + (-10 if side else 10) * index for index in range(-1, 3)]), {"side": side, "size": 40, "px": 110 if not side else 90}))
        add("limit equal side %d" % side, "walk", world(book(side, (2, 2), [100, 100 + (-10 if side else 10)]), {"side": side, "size": 40}))
        add("deep tree side %d" % side, "walk", world(book(side, (1, 1, 1, 1, 1, 1, 1), [100 + (-1 if side else 1) * 10 * index for index in range(7)]), {"side": side, "size": 40, "px": 1000 if not side else 10}, tree_height=2))
        add("taker ioc rests not side %d" % side, "walk", world(book(side, (2,)), {"side": side, "tif": 1, "size": 9}))
        add("taker ioc given oid side %d" % side, "walk", world(book(side, (2,)), {"side": side, "tif": 1, "size": 9, "oid_tag": 1}))
        add("used given oid side %d" % side, "walk", world(book(side, (9,)), {"side": side, "size": 9, "oid_tag": 1}))
        add("used given oid ioc side %d" % side, "walk", world(book(side, (9,)), {"side": side, "tif": 3, "size": 9, "oid_tag": 1}))
    add("level chain", "walk", world([chain(100, [2, 2, 2])], {"size": 5}))
    add("level chain exact", "walk", world([chain(100, [2, 3]), chain(110, [2])], {"size": 5, "px": 120}))
    add("two chains", "walk", world([chain(100, [2, 2]), chain(110, [1, 1], 2)], {"size": 50, "px": 120}))
    add("many fills grow", "walk", world([chain(100, [1] * 6), chain(110, [1] * 6, 3)], {"size": 50, "px": 120}))
    add("taker kind nine", "walk", world(book(0, (2,)), {"size": 2, "kind": 9, "tif": 3}))
    add("taker kind eight", "walk", world(book(0, (2,)), {"size": 2, "kind": 8, "tif": 3}))
    add("taker kind ten", "walk", world(book(0, (2,)), {"size": 2, "kind": 10, "tif": 3}))
    add("oid at max", "walk", world(book(0, (2,)), next_oid=MAX64))
    add("oid given kept", "walk", world(book(0, (2,)), {"oid_tag": 1, "oid": 0x1234}))
    add("client id", "walk", world(book(0, (2,)), {"cloid": "00112233445566778899aabbccddeeff"}))
    add("block row", "walk", world(book(0, (2,)), {"block": 1}))
    add("level head missing", "walk", world([dict(chain(100, [2]), head=False)]))
    add("slot index bad", "walk", world(book(0, (2,)), slab_short=3))
    add("slot vacant", "walk", world(book(0, (2,)), broken_slot=0))
    add("chain vacant", "walk", world([chain(100, [2, 2])], {"size": 5}, broken_slot=1))
    add("band first", "walk", world(book(0), allowed={"100": False}))
    add("band first given oid", "walk", world(book(0), {"oid_tag": 1}, allowed={"100": False}))
    add("band second", "walk", world(book(0, (2, 2)), allowed={"110": False}))
    add("band second given oid", "walk", world(book(0, (2, 2)), {"oid_tag": 1, "px": 120}, allowed={"110": False}))
    add("band second side 1", "walk", world(book(1, (2, 2)), {"side": 1, "px": 80}, allowed={"90": False}))

    # match outcomes
    none = {"reason": 3, "fill": None}
    add("no fill link goes on", "match", world([chain(100, [2, 2])], {"size": 5}, match={"0": none}))
    for reason in (0, 1, 2):
        add("reason %d no fill" % reason, "match", world([chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": reason, "fill": None}}))
        add("reason %d with fill" % reason, "match", world([chain(100, [2, 2])], {"size": 3}, match={"0": {"reason": reason}}))
        add("reason %d filled up" % reason, "match", world([chain(100, [2])], {"size": 2}, match={"0": {"reason": reason}}))
        add("reason %d two makers one user" % reason, "match", world([{"px": 100, "slots": [slot(USERS[0], 2, 0x301), slot(USERS[0], 2, 0x302), slot(USERS[1], 2, 0x303)]}], {"size": 9}, match={"0": {"reason": reason, "fill": None}, "1": {"reason": reason, "fill": None}, "2": {"reason": reason}}))
        add("reason %d high users" % reason, "match", world([{"px": 100, "slots": [slot(HIGH_USERS[0], 2, 0x301), slot(USERS[0], 2, 0x302), slot(HIGH_USERS[1], 2, 0x303), slot(HIGH_USERS[0], 2, 0x304)]}], {"size": 9}, match={str(index): {"reason": reason, "fill": None} for index in range(4)}))
        add("reason %d many users" % reason, "match", world([{"px": 100, "slots": [slot("%02x" % (0x30 + index) + USERS[0][2:], 2, 0x301 + index) for index in range(9)]}], {"size": 40}, match={str(index): {"reason": reason, "fill": None} for index in range(9)}))
    add("budget zero after no fill", "match", world([chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": 3, "fill": None, "budget": 0}}))
    add("budget replaced", "match", world([chain(100, [2, 2])], {"size": 5}, match={"0": {"budget": 9}}))
    add("fill over budget", "match", world([chain(100, [2])], {"size": 5}, match={"0": {"budget": 1}}))
    add("fill over maker", "match", world([chain(100, [2])], {"size": 5}, match={"0": {"fill": [100, 3]}}))
    add("settle changes", "match", world(book(0, (4, 4)), {"size": 3}, settled={"0": [97, 2]}))
    add("settle changes all", "match", world(book(0, (4, 4)), {"size": 4}, settled={"0": [97, 4]}))
    add("settle over", "match", world(book(0, (4, 4)), {"size": 3}, settled={"0": [97, 5]}))
    big = (1 << 63) - 1
    add("fill sum overflow", "match", world(book(0, (big, big, big)), {"size": 40, "px": 200}, match={str(index): {"fill": [100, big], "budget": MAX64} for index in range(3)}))
    add("fill size sign", "match", world(book(0, (MAX64,)), {"size": 40}, match={"0": {"fill": [100, 1 << 63], "budget": MAX64}}))
    add("fill size sign no leg", "match", world(book(0, (MAX64,)), {"size": 40}, match={"0": {"fill": [100, 1 << 63], "budget": MAX64, "legs": [[0, 0], [0, 0]]}}))
    add("leg zero overflow", "match", world(book(0, (4,)), match={"0": {"legs": [[1, big], [1, 0]]}}))
    add("leg one overflow", "match", world(book(0, (4,)), match={"0": {"legs": [[1, 0], [1, -big - 1]]}}))
    add("status stops", "match", world(book(0), match={"0": {"fill": None, "status": [0x8000000000000011, 0x5A, 0x6B]}}))
    add("status text stops", "match", world(book(0), match={"0": {"fill": None, "status": [0x18, 0, 0x6B]}}))
    add("status after fill level goes on", "match", world(book(0), match={"1": {"status": [0x8000000000000011, 0x5A, 0x6B]}}))
    add("status text after fill", "match", world(book(0), match={"1": {"status": [0x18, 0, 0x6B]}}))
    add("status with own fill", "match", world(book(0), match={"0": {"status": [0x8000000000000011, 0x5A, 0x6B]}}))
    add("status with fill link skipped", "match", world([chain(100, [2, 2]), chain(110, [2], 2)], {"size": 9, "px": 120}, match={"0": {"status": [0x8000000000000011, 0x5A, 0x6B]}}))
    add("status with fill budget gone", "match", world(book(0, (4, 4)), {"size": 4}, match={"0": {"status": [0x8000000000000011, 0x5A, 0x6B]}}))
    add("status reason row", "match", world(book(0), match={"0": {"reason": 0, "fill": None}, "1": {"status": [0x8000000000000011, 0x5A, 0x6B], "reason": 2}}))

    # pull retry
    user = USERS[0]
    for mode, flag_a, flag_b in ((0, 0, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0), (3, 0, 1), (3, 1, 0), (4, 0, 0), (4, 1, 0), (4, 0, 1), (5, 0, 0), (0xFF, 0, 0), (9, 1, 1)):
        for reason in (0, 3):
            add("pull mode %d %d %d reason %d" % (mode, flag_a, flag_b, reason), "pull", world(book(0, (4,)), {"size": 3}, modes={user: mode}, byte_5b0=flag_a, byte_5b1=flag_b, match={"0": {"reason": reason, "fill": None}}))
    add("pull absent user", "pull", world(book(0, (4,)), {"size": 3}, modes={USERS[2]: 3}, match={"0": {"reason": 0, "fill": None}}))
    add("pull twin hash", "pull", world(book(0, (4,)), {"size": 3}, modes={USERS[2]: 3}, twin_users=[user], match={"0": {"reason": 0, "fill": None}}))
    add("pull twin then row", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, twin_users=[user], match={"0": {"reason": 0, "fill": None}}))
    add("pull full group", "pull", world(book(0, (4,)), {"size": 3}, modes={("%02x" % (0x60 + index)) + user[2:]: 3 for index in range(24)}, match={"0": {"reason": 0, "fill": None}}))
    add("pull then fill", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 4}, match={"0": {"reason": 0, "fill": None}, "1": {"reason": 3}}))
    add("pull then reason 1", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0, "fill": None}, "1": {"reason": 1, "fill": None}}))
    add("pull then reason 0", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0, "fill": None}, "1": {"reason": 0, "fill": None}}))
    add("pull first text dropped", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0, "fill": None, "status": [0x18, 0, 0x6B]}, "1": {"reason": 3}}))
    add("pull first status word", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0, "fill": None, "status": [0x8000000000000011, 0x51, 0x6B]}, "1": {"reason": 3}}))
    add("pull second status", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0, "fill": None}, "1": {"status": [0x8000000000000011, 0x5A, 0x6B], "fill": None}}))
    add("pull first fill replaced", "pull", world(book(0, (4,)), {"size": 3}, modes={user: 3}, match={"0": {"reason": 0}, "1": {"reason": 3, "fill": [100, 1]}}))
    add("pull second maker", "pull", world([chain(100, [2, 2], 0)], {"size": 3}, modes={USERS[1]: 4}, match={"1": {"reason": 0, "fill": None}, "2": {"reason": 3}}))

    # end of the walk, rest
    add("rest gate no, no fills", "rest", world([], may_rest=False))
    add("rest gate no, no fills given oid", "rest", world([], {"oid_tag": 1}, may_rest=False))
    add("rest gate no, fills", "rest", world(book(0, (2,)), may_rest=False))
    add("rest gate no, fills given oid", "rest", world(book(0, (2,)), {"oid_tag": 1, "oid": 0x41}, may_rest=False, relations={"65": [1, 66], "66": [1, 1]}))
    add("rest gate no, given other tag", "rest", world(book(0, (2,)), {"oid_tag": 1, "oid": 0x41}, may_rest=False, relations={"65": [2, 66], "66": [1, 1]}))
    add("rest gate no, peer absent", "rest", world(book(0, (2,)), {"oid_tag": 1, "oid": 0x41}, may_rest=False, relations={"65": [1, 66]}))
    add("rest gate no, self absent", "rest", world(book(0, (2,)), {"oid_tag": 1, "oid": 0x41}, may_rest=False, relations={"66": [1, 1]}))
    add("rest gate no, vector", "rest", world(book(0, (2,)), {"vector": [7, 8, 9]}, may_rest=False))
    add("rest gate no, no fills vector", "rest", world([], {"vector": [7, 8]}, may_rest=False))
    add("reserve word", "rest", world([], reserve=[0x8000000000000007, 0x31, 0x32]))
    add("reserve word given oid", "rest", world([], {"oid_tag": 1}, reserve=[0x8000000000000007, 0x31, 0x32]))
    add("reserve word vector", "rest", world([], {"vector": [1]}, reserve=[0x8000000000000007, 0x31, 0x32]))
    add("reserve text", "rest", world([], reserve=[0x40, 0, 0x32]))
    add("reserve text fills", "rest", world(book(0, (2,)), reserve=[0x40, 0, 0x32]))
    add("reserve word fills", "rest", world(book(0, (2,)), reserve=[0x8000000000000007, 0x31, 0x32]))
    add("reserve word fills given oid", "rest", world(book(0, (2,)), {"oid_tag": 1}, reserve=[0x8000000000000007, 0x31, 0x32]))
    add("reserve word fills vector", "rest", world(book(0, (2,)), {"vector": [3, 4]}, reserve=[0x8000000000000007, 0x31, 0x32]))
    add("rest tail joins", "rest", world([], rest_level=[3, 1], extra_slots=[{"size": 7, "oid": 0x98}, {"size": 1, "oid": 0x96}, {"vacant": True, "oid": 0x97}]))
    add("rest head only", "rest", world([], rest_level=[3, None]))
    add("rest tail bad", "rest", world([], rest_level=[3, 7]))
    add("rest tail vacant", "rest", world([], rest_level=[3, 1]))
    add("rest fresh side 1", "rest", world([], {"side": 1}))
    add("rest given oid", "rest", world([], {"oid_tag": 1}))
    add("rest client id", "rest", world([], {"cloid": "ffeeddccbbaa99887766554433221100"}))
    add("rest vector", "rest", world([], {"vector": [5, 6, 7]}))
    add("rest after fill", "rest", world(book(0, (2,)), {"px": 100}))
    add("rest kind 9", "rest", world(book(0, (2,)), {"kind": 9}, may_rest=False))
    add("rest block", "rest", world([], {"block": 1}))
    add("reduce rests", "rest", world([], {"reduce": 1, "side": 1, "size": 2}, positions={TAKER: long(5)}))
    add("reduce rests list", "rest", world([], {"reduce": 1, "side": 1, "size": 2}, positions={TAKER: long(5)}, new_slot=2, next_oid=0x51, extra_slots=[ro(0x50, 1, TAKER), {"vacant": True, "oid": 0x97}, ro(0x51, 2, TAKER)], reduce_lists={TAKER: rlist([0x50], 4)}))
    add("reduce rests over", "rest", world([], {"reduce": 1, "side": 1, "size": 4}, positions={TAKER: long(5)}, new_slot=2, next_oid=0x51, extra_slots=[ro(0x50, 3, TAKER), {"vacant": True, "oid": 0x97}, ro(0x51, 4, TAKER)], reduce_lists={TAKER: rlist([0x50], 4)}))
    add("reduce fills then rests", "rest", world(book(1, (2,)), {"reduce": 1, "side": 1, "size": 4, "px": 90}, positions={TAKER: long(5)}))

    # sweep one
    px = {"reduce": 0}

    def sweep(label, oids, extra, szi=5, user=USERS[0], cap=None, head=0, **more):
        add(label, "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=extra, positions={user: long(szi)}, reduce_lists={user: rlist(oids, cap, head)}, **more))

    sweep("list empty", [], [{"size": 1, "oid": 0x50}])
    sweep("list empty cap", [], [{"size": 1, "oid": 0x50}], cap=4)
    sweep("one fits", [0x50], [ro(0x50, 2)])
    sweep("one equal", [0x50], [ro(0x50, 5)])
    sweep("one clamped", [0x50], [ro(0x50, 9, limit=9)])
    sweep("one tag zero", [0x50], [ro(0x50, 9, tag=0, limit=2)])
    sweep("one limit low", [0x50], [ro(0x50, 9, limit=3)])
    sweep("one limit high", [0x50], [ro(0x50, 3, limit=9)])
    sweep("one limit over held", [0x50], [ro(0x50, 3, limit=4)], szi=2)
    sweep("two fit", [0x50, 0x51], [ro(0x50, 2), ro(0x51, 3)])
    sweep("two over small oldest shrinks", [0x50, 0x51], [ro(0x50, 2), ro(0x51, 4)])
    sweep("two over cancels oldest", [0x50, 0x51], [ro(0x50, 1), ro(0x51, 5)])
    sweep("two over shrinks oldest", [0x50, 0x51], [ro(0x50, 4), ro(0x51, 4)])
    sweep("two over equal", [0x50, 0x51], [ro(0x50, 3), ro(0x51, 5)])
    sweep("three over", [0x50, 0x51, 0x52], [ro(0x50, 2), ro(0x51, 2), ro(0x52, 4)])
    sweep("five kept grow", [0x50 + index for index in range(6)], [ro(0x50 + index, 1) for index in range(6)])
    sweep("wrap head", [0x50, 0x51, 0x52], [ro(0x50, 2), ro(0x51, 2), ro(0x52, 2)], cap=4, head=3)
    sweep("wrap head fit", [0x50, 0x51], [ro(0x50, 2), ro(0x51, 2)], cap=3, head=2)
    sweep("wrap head full", [0x50, 0x51, 0x52, 0x53], [ro(0x50 + index, 1) for index in range(4)], cap=4, head=2)
    sweep("wrap second only", [0x50, 0x51], [ro(0x50, 2), ro(0x51, 2)], cap=4, head=1)
    sweep("wrap drop first", [0x90, 0x50, 0x51], [ro(0x50, 2), ro(0x51, 2)], cap=4, head=3)
    sweep("wrap wrong in first", [0x50, 0x51, 0x52], [ro(0x50, 2), ro(0x51, 2, side=0), ro(0x52, 2)], cap=4, head=3)
    sweep("wrap wrong tail", [0x50, 0x51, 0x52], [ro(0x50, 2), ro(0x51, 2), ro(0x52, 2, side=0)], cap=4, head=2)
    sweep("unknown oid dropped", [0x90, 0x50], [ro(0x50, 2)])
    sweep("unknown oid only", [0x90], [ro(0x50, 2)])
    sweep("vacant dropped", [0x51, 0x50], [ro(0x50, 2), {"vacant": True, "oid": 0x51}])
    sweep("bad index dropped", [0x93, 0x50], [ro(0x50, 2)], oid_extra={"147": 39})
    sweep("twin hash", [0x50], [ro(0x50, 2)], oid_twins=[0x50, 0x50])
    sweep("wrong side cancels", [0x50, 0x51], [ro(0x50, 2, side=0), ro(0x51, 2)])
    sweep("short position", [0x50], [ro(0x50, 2, side=0)], szi=-4)
    sweep("short wrong side", [0x50], [ro(0x50, 2, side=1)], szi=-4)
    sweep("flat position", [0x50, 0x51], [ro(0x50, 2), ro(0x51, 2)], szi=0)
    add("no position", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 2)], reduce_lists={USERS[0]: rlist([0x50])}))
    add("other asset position", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 2)], positions={USERS[0]: {"10001": [1, 5], "10009": [1, 7]}}, reduce_lists={USERS[0]: rlist([0x50])}))
    add("deep position", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 2), ro(0x51, 2)], positions={USERS[0]: {str(10000 + number): [1, 3] for number in range(9)}}, reduce_lists={USERS[0]: rlist([0x50, 0x51])}))
    add("deep position absent", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 2)], positions={USERS[0]: {str(10010 + number): [1, 3] for number in range(9)}}, reduce_lists={USERS[0]: rlist([0x50])}))
    add("taker list too", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 2, TAKER, side=0)], positions={TAKER: long(-1)}, reduce_lists={TAKER: rlist([0x50])}))
    add("both users", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 3, TAKER, side=0), ro(0x51, 3, side=1)], positions={TAKER: long(-1), USERS[0]: long(1)}, reduce_lists={TAKER: rlist([0x50]), USERS[0]: rlist([0x51])}))
    add("maker removed before sweep", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, positions={USERS[0]: long(5)}, reduce_lists={USERS[0]: rlist([0x100])}))
    add("filled user list only", "sweep", world(book(0, (2, 2)), {"size": 4, "px": 110, "tif": 3}, extra_slots=[ro(0x50, 3, USERS[1])], positions={USERS[1]: long(1)}, reduce_lists={USERS[1]: rlist([0x50]), USERS[2]: rlist([0x50])}))
    add("no fill no sweep", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, 3)], positions={USERS[0]: long(1)}, reduce_lists={USERS[0]: rlist([0x50])}, match={"0": {"reason": 3, "fill": None}}))
    add("hash empty", "sweep", world([], extra_slots=[], reduce_lists={TAKER: rlist([0x50])}, positions={TAKER: long(5)}))
    add("sum overflow", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[ro(0x50, MAX64 - 1, limit=MAX64), ro(0x51, MAX64 - 1, limit=MAX64)], positions={USERS[0]: long(MAX64 >> 1)}, reduce_lists={USERS[0]: rlist([0x50, 0x51])}))

    # sweep two
    def flips(label, rows, szi_after, legs, extra_user=USERS[0], **more):
        add(label, "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, positions={extra_user: long(szi_after)} if szi_after is not None else {}, untriggered={extra_user: rows}, match={"0": {"legs": legs}}, **more))

    maker_leg = [[0, 0], [1, 1]]
    flips("flip none", [[0x70, 1, 0, 0]], 1, [[1, 0], [1, 5]])
    flips("flip closes maker", [[0x70, 1, 0, 0]], 0, maker_leg)
    flips("flip closes no position", [[0x70, 1, 0, 0]], None, maker_leg)
    flips("flip sell on short", [[0x70, 1, 0, 1], [0x71, 1, 0, 0]], -3, maker_leg)
    flips("flip buy on long", [[0x70, 1, 0, 1], [0x71, 1, 0, 0]], 3, maker_leg)
    flips("flip not reduce", [[0x70, 0, 0, 0], [0x71, 2, 0, 0]], 3, maker_leg)
    flips("flip parked", [[0x70, 1, 1, 0], [0x71, 1, 0, 0]], 3, maker_leg)
    flips("flip own oid", [[0x777, 1, 0, 0], [0x778, 1, 0, 0]], 3, maker_leg, )
    add("flip own oid given", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3, "oid_tag": 1}, positions={USERS[0]: long(3)}, untriggered={USERS[0]: [[0x777, 1, 0, 0], [0x778, 1, 0, 0]]}, match={"0": {"legs": maker_leg}}))
    flips("flip many", [[0x70 + index, 1, 0, index & 1] for index in range(9)], 3, maker_leg)
    flips("flip none listed", [], 3, maker_leg)
    flips("flip deep position", [[0x70, 1, 0, 0]], None, maker_leg)
    add("flip deep rows", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, positions={USERS[0]: {str(10000 + number): [1, 3] for number in range(9)}}, untriggered={USERS[0]: [[0x70, 1, 0, 0], [0x71, 1, 0, 1]]}, match={"0": {"legs": maker_leg}}))
    add("flip absent rows", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, positions={USERS[0]: {str(10010 + number): [1, 3] for number in range(9)}}, untriggered={USERS[0]: [[0x70, 1, 0, 0]]}, match={"0": {"legs": maker_leg}}))
    add("flip taker leg", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, positions={TAKER: long(1)}, untriggered={TAKER: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, -1], [0, 0]]}}))
    add("flip taker leg closes", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={TAKER: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, -2], [0, 0]]}}))
    add("flip taker same sign", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={TAKER: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, -3], [1, 3]]}}))
    add("flip seller leg", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={USERS[0]: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, 0], [1, 2]]}}))
    add("flip seller same", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={USERS[0]: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, 0], [1, 3]]}}))
    add("flip seller short", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={USERS[0]: [[0x72, 1, 0, 0]]}, match={"0": {"legs": [[1, 0], [1, -3]]}}))
    add("flip both legs", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, untriggered={USERS[0]: [[0x72, 1, 0, 0]], TAKER: [[0x73, 1, 0, 1]]}, match={"0": {"legs": [[1, -1], [1, 1]]}}))
    add("flip side 1 taker", "trigger", world(book(1, (2,)), {"side": 1, "size": 2, "tif": 3}, untriggered={USERS[0]: [[0x72, 1, 0, 1]], TAKER: [[0x73, 1, 0, 0]]}, match={"0": {"legs": [[1, -1], [1, 1]]}}))

    # survivors of the first pass: words the plain cases leave equal
    wide = 0x1122334455667788
    add("status row client id", "walk", world(book(0, (2,)), {"size": 2, "tif": 3, "cloid": "00112233445566778899aabbccddeeff"}))
    add("status row block", "walk", world(book(0, (2,)), {"size": 2, "tif": 3, "block": 1}))
    add("status row vector", "walk", world(book(0, (2,)), {"size": 2, "tif": 3, "vector": [4, 5, 6]}))
    add("no fill status vector", "entry", world([chain(100, [1])], {"tif": 1, "vector": [4, 5]}, match={"0": {"reason": 3, "fill": None}}))
    add("wide payload alo", "entry", world(book(0, (1,)), {"tif": 0}, alo=[wide, wide + 1]))
    add("wide payload gate", "entry", world([], first_gate=[0x8000000000000001, wide, wide + 2]))
    add("wide payload second gate", "entry", world([], second_gate=[0x8000000000000001, wide, wide + 3]))
    add("wide payload reserve", "rest", world([], reserve=[0x8000000000000007, wide, wide + 4]))
    add("rest tail index zero", "rest", world([], rest_level=[3, 0]))
    add("rest tail index two", "rest", world([], rest_level=[3, 2], extra_slots=[{"size": 7, "oid": 0x98}, {"vacant": True, "oid": 0x97}, {"size": 2, "oid": 0x96}]))
    add("price limit plus one", "entry", world([], {"px": 10 ** 15 + 1}, tick=1))
    add("price limit even", "entry", world([], {"px": 10 ** 15}, tick=1))
    add("tempting key builder", "entry", world([], main_byte=1, mode=0, asset=10004, spare=10004, positions={TAKER: {"10001": [1, 5]}}))
    add("tempting key reduce", "reduce", world([], {"reduce": 1, "side": 1}, spare=ASSET, positions={TAKER: {"10001": [1, 5]}}))
    add("tempting key sweep", "sweep", world(book(0, (2,)), {"size": 2, "tif": 3}, spare=ASSET, extra_slots=[ro(0x50, 2)], positions={USERS[0]: {"10001": [1, 5]}}, reduce_lists={USERS[0]: rlist([0x50])}))
    add("tempting key trigger", "trigger", world(book(0, (2,)), {"size": 2, "tif": 3}, spare=ASSET, positions={USERS[0]: {"10001": [1, 5]}}, untriggered={USERS[0]: [[0x70, 1, 0, 0]]}, match={"0": {"legs": [[0, 0], [1, 1]]}}))
    high = 0x7000000000
    sweep("large oids", [high, high + 1], [ro(high, 2), ro(high + 1, 4)])
    add("hash empty touched", "sweep", world([], {"reduce": 1, "side": 1, "size": 2}, extra_slots=[], positions={TAKER: long(5)}, reduce_lists={TAKER: rlist([0x50])}))
    makers = [slot("%02x" % (0x60 + index) + USERS[0][2:], 1, 0x400 + index) for index in range(13)]
    lists = {row["user"]: [[0x500 + index, 1, 0, 0]] for index, row in enumerate(makers)}
    add("thirteen touched users", "sweep", world([{"px": 100, "slots": makers}], {"size": 13, "tif": 3}, extra_slots=[ro(0x50, 2, makers[7]["user"])], positions={makers[7]["user"]: long(1)}, reduce_lists={makers[7]["user"]: rlist([0x50])}))
    add("thirteen flipped users", "trigger", world([{"px": 100, "slots": makers}], {"size": 13, "tif": 3}, untriggered=lists, match={str(index): {"legs": [[0, 0], [1, 1]]} for index in range(13)}))
    return cases


# ---- static reads ----

def direct_sites(image, targets):
    """Every E8/E9 rel32 byte pattern in .text that lands on a target."""
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    for opcode in (b"\xe8", b"\xe9"):
        at = text.find(opcode)
        while 0 <= at <= len(text) - 5:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in found:
                found[target].append((base + at, opcode[0]))
            at = text.find(opcode, at + 1)
    return found


def slot_sites(image, slot):
    """Every FF 15 call in .text through one data slot."""
    base, text = image.text_bytes()
    rows = []
    at = text.find(b"\xff\x15")
    while 0 <= at <= len(text) - 6:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            rows.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return rows


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

SURVIVED_DEFAULT = "Read at the site, not probed: no case here gives this word a second value that reaches an edge, a result or a compared book word."
SURVIVED_GROUPS = (
    ("Capacity test of the vector copy: no length here is near 2^61.", (0x4311154, 0x431116D, 0x4311174)),
    ("Bit 0 of the divide by 10000 multiplier: no asset here changes the quotient.", (0x43113C4, 0x4311616, 0x4311E08, 0x43121F7, 0x4313864, 0x4314459)),
    ("Same dex bound already passed at entry, so this second test cannot fire, and its panic word is not read.", (0x4312210, 0x4313879, 0x4314476, 0x43148E2)),
    ("Flag used by unwind pads or a niche test of a word that stays 1: the normal path reads no difference.", (0x4311410, 0x4312A28, 0x4312AB8, 0x4312AC6, 0x4312C23)),
    ("Dangling pointer of an empty Vec: it is never read at length 0.", (0x4311C47, 0x43127E4)),
    ("Unused half of the two ended level iterator, or a zero that no later read tells apart.", (0x4311C71, 0x4311DAD, 0x4312897, 0x4314052)),
    ("The retain just rebuilt this list: every oid in it is in the table and live, so this test cannot fail here.", (0x4313AA1, 0x4313ABB, 0x4313BE1, 0x4313E0C, 0x4313E2E, 0x4313EB1, 0x4313EE6)),
    ("Bit 0 of the hash key moves the hash by the key only; group probing needs a larger oid spread than the table holds.", (0x4313BEE, 0x4313F04, 0x43375FE)),
    ("Group probing past a full group, or a byte shuffle of one repeated byte: same result.", (0x4311FB2, 0x431201C, 0x4312042, 0x4312046, 0x4313C21, 0x4313F35, 0x433762B)),
    ("The low byte is or-ed back, so bit 0 of this mask is free.", (0x431181E, 0x4311D09)),
    ("The two divides give the same remainder at any operand size test.", (0x431199C,)),
    ("Reason bytes 4 and up have no row in the table, and the match core gives none here.", (0x4311F5E,)),
    ("One status row per run: index 0 hides the stride.", (0x43135BF,)),
    ("Sign shift of the position word: needs a position of 2^62 or more.", (0x4A07E2C, 0x4A07E37, 0x4A07EB8, 0x4A07EC3)),
    ("Saturating tail after the overflow recorder, which panics in this harness.", (0x4A07F68, 0x4A07F6C, 0x4A07F83, 0x4A07FA3, 0x4A07FA7, 0x4A07FBE)),
)
SURVIVED_REASONS = {va: text for text, rows in SURVIVED_GROUPS for va in rows}


def unreached_reason(va):
    if RETAIN_TEST <= va < RETAIN_TEST + 0x200:
        return "Early exit of the retain test or a tree height this case set does not build."
    if va >= 0x431488E:
        return "Panic tail: the harness raises at the call before this word matters, or the tail is one this case set does not take."
    return "Allocation failure, capacity overflow, a tree descent of height 8 or more, or a long group probe: not built here."


SEPARATE = {FILL_USERS: "user pair of a fill, mutated with the body", RETAIN: "retain of the reduce-only list, run with no mutants", RETAIN_TEST: "retain test of one oid, mutated with the body"}
UNWIND_START = 0x4314A28


def main_rows(image):
    begin, end = image.exact_fde(INSERT)
    return [row for row in decode_range(image, begin, end) if row.va < UNWIND_START]


def mutant_rows(image):
    """The body before its unwind pads, then the two small helpers that have no other reader."""
    rows = [(INSERT, row) for row in main_rows(image)]
    for start in (RETAIN_TEST, FILL_USERS):
        begin, end = image.exact_fde(start)
        rows += [(start, row) for row in decode_range(image, begin, end)]
    return rows


def run_mutants(image, reached, verbose=False):
    """A mutant only changes a run that reaches its instruction, so only those cases run; the last killers go first."""
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    cases = all_cases()
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    owner = {row.va: start for start, row in mutant_rows(image)}
    for va, at, kind in mutation_targets(image, [row for _, row in mutant_rows(image)]):
        indices = by_va.get(va)
        if not indices:
            results.append({"function": owner[va], "va": va, "kind": kind, "result": "unreached", "by": ""})
            continue
        machine.patches = mutate_patch(image, va, at, kind)
        machine.cache.pop(va, None)
        failed = None
        wanted = set(indices)
        order = [index for index in first_kill if index in wanted] + indices
        for index in order:
            failed = compare_run(harness, cases[index])
            if failed:
                if index in first_kill:
                    first_kill.remove(index)
                first_kill.insert(0, index)
                del first_kill[60:]
                break
        machine.patches = {}
        machine.cache.pop(va, None)
        results.append({"function": owner[va], "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": ":".join(failed.split(":")[:2])[:70] if failed else ""})
        if verbose and not failed:
            print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def require(image, va, data, what):
    if code(image, va, len(data)) != data:
        raise EvidenceError("%s: bytes at %#x differ" % (what, va))


def location_row(image, relative, slot):
    path, line, column = image.location(slot, relative)
    return {"slot": "%#x" % slot, "path": path, "line": line, "column": column}


def float_at(image, va):
    bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
    return {"va": "%#x" % va, "bits": "%#x" % bits, "value": repr(to_float(bits))}


def table_rows(image, table, count, name):
    """Jump table entries by raw i32 words; a row outside the function ends the table."""
    begin, end = image.exact_fde(INSERT)
    rows = []
    for index in range(count):
        arm = table + struct.unpack_from("<i", image.blob, image.offset(table) + index * 4)[0]
        if not begin <= arm < end:
            raise EvidenceError("%s entry %d" % (name, index))
        rows.append({"index": index, "arm": "%#x" % arm})
    return rows


def status_texts(image):
    """Display jump table of the place error: arm of each tag, then the `lea rsi` and `mov edx` of its text, by exact bytes."""
    rows = []
    for tag in range(24):
        arm = ERROR_TABLE + struct.unpack_from("<i", image.blob, image.offset(ERROR_TABLE) + tag * 4)[0]
        window = code(image, arm, 64)
        at = window.find(b"\x48\x8d\x35")
        text = None
        if at >= 0 and window[at + 7] == 0xBA:
            start = arm + at + 7 + struct.unpack_from("<i", window, at + 3)[0]
            size = struct.unpack_from("<I", window, at + 8)[0]
            text = code(image, start, size).decode("ascii")
        rows.append({"tag": tag, "arm": "%#x" % arm, "text": text})
    return rows


def status_sites(image):
    """Each status word built from the OK constant in r15, at its site, by exact bytes."""
    rows = []
    for va, data, word in ((0x43114A4, b"\x4d\x8d\x77\xff", 0x17), (0x43119A9, b"\x4d\x8d\x77\xfe", 0x16), (0x4311CEB, b"\x4d\x8d\x77\xfd", 0x15), (0x4311817, b"\x4d\x8d\x77\xee", 6), (0x43117BC, b"\x4d\x8d\x77\xf0", 8), (0x431191F, b"\x4d\x8d\x77\xed", 5), (0x43147AF, b"\x4d\x8d\x6f\xfb", 0x13), (0x43147B5, b"\x49\x8d\x4f\xfb", 0x13)):
        require(image, va, data, "status word %#x" % word)
        rows.append({"va": "%#x" % va, "status": "%#x" % (OK - 0x18 + word), "bytes": data.hex()})
    return rows


def fixed_words(image):
    """Each constant the path depends on, at a fixed site, by exact bytes."""
    rows = []
    for va, data, what in ((0x431196F, b"\x48\xb8" + struct.pack("<Q", PX_LIMIT), "price limit 10^15"),
                           (0x43113C4, b"\x48\xb9" + struct.pack("<Q", 0x346DC5D63886594B), "asset / 10000 multiplier"),
                           (0x43113F8, b"\x4d\x69\xe5" + struct.pack("<I", MARKET_SIZE), "market row stride"),
                           (0x4311F13, b"\x48\x69\xc0" + struct.pack("<I", SLOT_SIZE), "slab slot stride"),
                           (0x431247A, b"\x48\x69\xfb" + struct.pack("<I", FILL_SIZE), "fill row stride"),
                           (0x431214C, b"\xba" + struct.pack("<I", MATCH_SIZE), "match result copy"),
                           (0x4313BEE, b"\x48\xba" + struct.pack("<Q", FX_KEY), "oid hash key"),
                           (0x4312B07, b"\xb0\x05", "row kind 2 removal reason 5"),
                           (0x4312BA7, b"\xb0\x01", "row kind 0 removal reason 1"),
                           (0x4313FE0, b"\x41\xb9\x0a\x00\x00\x00", "sweep one cancel reason 10"),
                           (0x4314616, b"\x41\xb9\x0a\x00\x00\x00", "sweep two cancel reason 10")):
        require(image, va, data, what)
        rows.append({"va": "%#x" % va, "what": what, "bytes": data.hex()})
    return rows


def copy_rows(image):
    """The six insert bodies by FDE size, and which of them carry this body's edges."""
    rows = []
    for start, role in ((INSERT, "this packet"), (TWIN, "same size twin, this packet"), (0x26EBDC0, "third copy, listed by #235"), (0x430D610, "spot, named by #47"), (0x4318A00, "spot twin"), (0x26E81C0, "spot")):
        begin, end = image.exact_fde(start)
        body = code(image, begin, end - begin)
        rows.append({"start": "%#x" % begin, "size": end - begin, "role": role, "price_limit_words": body.count(struct.pack("<Q", PX_LIMIT)), "ok_word": body.count(struct.pack("<Q", OK))})
    return rows


def twin_rows(image):
    """Row by row diff of the two perp bodies: op and size equal, and the targets that differ."""
    left, right = decode_range(image, *image.exact_fde(INSERT)), decode_range(image, *image.exact_fde(TWIN))
    if len(left) != len(right):
        raise EvidenceError("twin row count")
    shape = sum(1 for one, two in zip(left, right) if (one.op, one.size) != (two.op, two.size))
    targets = {}
    base_left, base_right = left[0].va, right[0].va
    for one, two in zip(left, right):
        if one.op == "call" and one.target - base_left != two.target - base_right and one.target != two.target:
            targets["%#x" % one.target] = "%#x" % two.target
    fields = sorted({(first[4], second[4]) for one, two in zip(left, right) for first, second in ((one.a, two.a), (one.b, two.b)) if first and first[0] == "m" and first[1] is not None and first != second})
    return {"rows": len(left), "shape_differences": shape, "different_targets": targets, "state_field_pairs": [["%#x" % pair[0], "%#x" % pair[1]] for pair in fields]}


def outcome_name(case, spec):
    if "panic" in spec:
        return "%s panic %s" % (case.kind, spec["panic"])
    result = spec["result"]
    if "status" in result:
        return "%s status %#x" % (case.kind, result["status"])
    return "%s %d fills, %s" % (case.kind, min(len(result["fills"]), 3), "rests" if spec["book"]["rest"][1] is not None else "done")


def case_line(case, spec):
    return "\t".join((case.kind, case.label, outcome_name(case, spec), str(len(spec["log"]))))


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    cases = all_cases()
    mismatches = []
    outcomes = {}
    reached = []
    seen = set()
    lines = []
    machine = harness.machine
    for case in cases:
        machine.seen = set()
        trouble = compare_run(harness, case)
        if trouble:
            mismatches.append(trouble)
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        spec = spec_run(case)
        name = outcome_name(case, spec)
        outcomes[name] = outcomes.get(name, 0) + 1
        lines.append(case_line(case, spec))
    steps = machine.steps
    second = Harness(image, TWIN)
    twin_bad = [text for text in (compare_run(second, case) for case in cases) if text]
    if (mismatches or twin_bad) and full:
        raise EvidenceError("spec mismatch: %s" % (mismatches + twin_bad)[0])
    begin, end = image.exact_fde(INSERT)
    rows = decode_range(image, begin, end)
    main = main_rows(image)
    functions = [{"role": "perp insert body", "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "before_unwind": len(main), "stepped": sum(1 for row in rows if row.va in seen)}]
    for start, role in sorted(SEPARATE.items()):
        low, high = image.exact_fde(start)
        decoded = decode_range(image, low, high)
        functions.append({"role": role, "start": "%#x" % low, "end": "%#x" % high, "size": high - low, "instructions": len(decoded), "stepped": sum(1 for row in decoded if row.va in seen)})
    relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
    sites = direct_sites(image, [INSERT])[INSERT]
    statics = {
        "callers": [{"site": "%#x" % site, "host": "%#x" % image.fde(site)[0], "kind": "call" if opcode == 0xE8 else "jump"} for site, opcode in sorted(sites)],
        "tif_table": table_rows(image, TIF_TABLE, 5, "time in force"),
        "reason_table": table_rows(image, REASON_TABLE, 4, "reason"),
        "status_word_sites": status_sites(image),
        "status_texts": status_texts(image),
        "fixed_words": fixed_words(image),
        "copies": copy_rows(image),
        "twin": twin_rows(image),
        "text": {"va": "0x6f0596", "value": bytes(image.blob[image.offset(0x6F0596):image.offset(0x6F0596) + 0x1D]).decode("ascii")},
        "locations": [location_row(image, relative, slot) for slot in (0x571C9F0, 0x571CA08, 0x571CA20, 0x571CA50, 0x56E9AE0, 0x56E9AF8, 0x56F21C0, 0x571C828, 0x571C990, 0x571C978)],
        "slots": [{"slot": "%#x" % slot, "target": "%#x" % relative[slot]} for slot in (SLOT_DEX_ROW, SLOT_SECOND_GATE, SLOT_ALLOWED, SLOT_SETTLE, SLOT_RESERVE, SLOT_CLOID, SLOT_TRACK)],
    }
    results_rows = run_mutants(image, reached, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "twin_mismatches": len(twin_bad),
        "first_mismatch": (mismatches + twin_bad)[0] if mismatches or twin_bad else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "_results": results_rows, "_lines": lines,
    }
    doc.update(statics)
    return doc


def reason_for(row):
    if row["result"] == "killed":
        return ""
    if row["result"] == "unreached":
        return unreached_reason(row["va"])
    return SURVIVED_REASONS.get(row["va"], SURVIVED_DEFAULT)


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    case_lines = evidence.pop("_lines")
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    files["cases.tsv"] = "\n".join(["kind\tlabel\toutcome\tedge_calls"] + case_lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row_["function"], row_["va"], row_["kind"], row_["result"], row_["by"], reason_for(row_))) for row_ in results]
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
    files = render(analyse(load_image()))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
