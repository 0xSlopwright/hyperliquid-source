#!/usr/bin/env python3
"""Evaluate the node #94 withdrawal route and fee split from ELF bytes: withdraw3 class router, fee debit, stake sum, f64 pro rata credit to hot users.

The route in front of the core gates, the debit with a fixed fee in dex record +0x250, the transfer sibling with a caller fee, the withdrawable word and the split of the fee over
the active epoch validators run as real bytes in a Python evaluator. A separately written rule list predicts every outcome, event and row word, and conditions, immediates and
offsets of the reached rows are flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

SLOT_MALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_BCMP = 0x576E378
SLOT_MEMCMP = 0x576E488
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMSET = 0x576E1C0
SLOT_REALLOC = 0x576E030
SLOT_PANIC = (0x576E470, 0x576E128, 0x576E048, 0x576DFB8, 0x576E108, 0x576E020, 0x576E118, 0x576E1B0)
SLOT_RECOVER = 0x576FE58

DEBIT = 0x370DA60
SEND = 0x370D980
SPLIT = 0x370DB70
AVAILABLE = 0x36F7560
DEBIT_ROW = 0x370A3D0
CREDIT_ROW = 0x36FF4F0
STAKE_MAP = 0x3364ED0
STAKE_FOLD = 0x3BE39B0
ROUTE = 0x2732530
WRAPPER = 0x1F67810
ROUTE_COPIES = (0x4D3D7E0, 0x4D3FC00)
ROUTES = (ROUTE,) + ROUTE_COPIES
WRAPPERS = (WRAPPER, 0x47B8810, 0x47B8760)
ROUTE_LIFT = (0, 0, 0xA80)
CORE = 0x2734200
CLASS_ROW = 0x2755400
AMOUNT_HELPER = 0x272D000
PREPARE = 0x272FE00
FINISH = 0x272F880
LIMIT_ROW = 0x1F84640
ERROR_DROP = 0x277EBA0
PANIC_DROP = 0x3379490
STATUS_DROP = 0x3762510
ROW_GET = 0x3596940
SET_INSERT = 0x339B590
SET_REMOVE = 0x33ACFE0
USER_LOOKUP = 0x36F57F0
HASH = 0x399C7A0
SLOT_RECORDER = 0x5773190
SLOT_COLLECT = 0x5774918
SLOT_MARGIN = 0x5773178
SLOT_EXEMPT = 0x5773228
SLOT_DEX_AT = 0x5774740
SLOT_LIMITER = 0x5774748
SLOT_AVAILABLE = 0x5774660
SLOT_DEBIT_ROW = 0x57749D8
SLOT_DEBIT = 0x5774B20
SLOT_SEND = 0x57749E8
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (0x5B, 0x5C, 0x33, 0x97, 0x170, 0x141, 0x168, 0x186)
FLOAT_LOW = 0x20ACB8
FLOAT_HIGH = 0x20A7F0
FLOAT_TOP = 0x20A2C8
RECORD_ROW_ADD = 0x56F1C50
RECORD_ROW_SUB = 0x56F1CF8
RECORD_NET = 0x5714C28
RECORD_REST = 0x56F1F60
RECORD_AVAILABLE = 0x56F3A78
TRANSFER = 0x270F6F0
BALANCE_OP = 0x2764A00
ROLLBACK = 0x2710110
ERROR_MAP = 0x272D970
PLAN = 0x272DE40
TAIL = 0x272D9F0
SLOT_SPOT_ROW = 0x5773170
SLOT_DEX_ROOM = 0x57738B8
SLOT_FORMAT = 0x576E040
RECORD_ROOM = 0x56BD1D8
RECORD_ROOM_COPY = 0x572E4E0
REAL_PAIRS = (ERROR_MAP,)
RECORD_HOLD = 0x56DFD90
SLOT_UNWRAP = 0x576E048
MUTANT_STEP_LIMIT = 1500000
MUTANT_CASES = 18
WORKERS = 4

RANDOM_SPLITS = 300
RANDOM_DEBITS = 300
RANDOM_AMOUNTS = 150
MUTATED = ((WRAPPER, "withdraw3 wrapper"), (ROUTE, "class route"), (DEBIT, "withdraw fee debit"), (SEND, "transfer with a caller fee"), (SPLIT, "fee split"), (AVAILABLE, "withdrawable word"),
           (DEBIT_ROW, "row debit"), (CREDIT_ROW, "row credit"), (STAKE_MAP, "stake map"), (STAKE_FOLD, "stake sum fold"), (AMOUNT_HELPER, "dex transfer helper"), (PREPARE, "routed prepare"), (ERROR_MAP, "error text map"), (FINISH, "class 4 finish"), (TAIL, "class 4 prepare tail"))
NEIGHBOURS = tuple((start, "route copy") for start in ROUTE_COPIES) + tuple((start, "wrapper copy") for start in WRAPPERS[1:])

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
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000

HEAP_FREE = HEAP_BASE + 0x40000
DEX_AT = HEAP_BASE + 0x1000
STATE_AT = HEAP_BASE + 0x2000
STAKING_AT = HEAP_BASE + 0x8000
TRACKER_AT = HEAP_BASE + 0x8100
USER_AT = HEAP_BASE + 0x8200
DEST_AT = HEAP_BASE + 0x8220
OUT_AT = HEAP_BASE + 0x8300
ACTION_AT = HEAP_BASE + 0x8400
TABLE_AT = HEAP_BASE + 0x9000
ROW_AT = HEAP_BASE + 0xC000
BOOK_AT = HEAP_BASE + 0xC800
LIMIT_AT = HEAP_BASE + 0xC900
OTHER_DEX_AT = HEAP_BASE + 0xCA00
ROUTE_KEY_AT = HEAP_BASE + 0xCD00
COUNT_AT = HEAP_BASE + 0xCD40
SPOT_ROW_AT = HEAP_BASE + 0xCD80

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


# ---- harness: real bytes through .text; allocator, maps of user rows and shared neighbours are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Layout:
    """Offsets of one B-tree node shape."""

    def __init__(self, key_at, key_size, val_at, val_size, parent, index, count, child, cap=11):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent, self.index, self.count, self.child, self.cap = parent, index, count, child, cap
        self.leaf = child
        self.inner = child + 8 * (cap + 1)


EPOCHS = Layout(8, 8, 0x60, 0x28, 0, 0x218, 0x21A, 0x220)
VALIDATORS = Layout(0x2C0, 0x20, 0, 0x40, 0x420, 0x428, 0x42A, 0x430)
DELEGATIONS = Layout(0x60, 0x14, 8, 8, 0, 0x13C, 0x13E, 0x140)
SKIP_SET = Layout(0x798, 0x14, 0, 0xB0, 0x790, 0x874, 0x876, 0x878)
SPOT_TOKENS = Layout(8, 8, 0x60, 0x18, 0, 0x168, 0x16A, 0x170)
TOKEN_SET = Layout(0x798, 8, 0, 0xB0, 0x790, 0x7F0, 0x7F2, 0x7F8)


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


def call_row(image, relative, start):
    """(site, target) of each direct or rip slot call of a body before its first panic tail, in address order."""
    begin, end = image.exact_fde(start)
    out = []
    for row in body_rows(image, begin, end):
        if row.op == "ud2":
            break
        if row.op == "call":
            out.append((row.va, row.target))
        elif row.op == "calli" and row.a[0] == "m" and row.a[1] is None:
            out.append((row.va, relative.get(row.a[4], row.a[4])))
    return out


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_BCMP: self.on_bcmp, SLOT_MEMCMP: self.on_memcmp, SLOT_REALLOC: self.on_realloc, SLOT_MEMMOVE: self.on_copy,
                 SLOT_RECORDER: self.on_recorder, SLOT_COLLECT: self.on_collect, SLOT_MARGIN: self.on_margin, SLOT_EXEMPT: self.on_exempt, SLOT_DEX_AT: self.on_dex_at, SLOT_LIMITER: self.on_limiter,
                 SLOT_SPOT_ROW: self.on_spot_row, SLOT_DEX_ROOM: self.on_dex_room, SLOT_FORMAT: self.on_format}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {ROW_GET: self.on_row, SET_INSERT: self.on_insert, SET_REMOVE: self.on_remove, USER_LOOKUP: self.on_user_lookup, HASH: self.on_hash, STATUS_DROP: self.on_status,
                         CLASS_ROW: self.on_class_row, CORE: self.on_core, AMOUNT_HELPER: self.on_amount, PREPARE: self.on_prepare, FINISH: self.on_finish, LIMIT_ROW: self.on_limit_row,
                         ERROR_DROP: self.on_error_drop, PANIC_DROP: self.on_panic_drop, TRANSFER: self.on_transfer, BALANCE_OP: self.on_balance_op, ROLLBACK: self.on_rollback, PLAN: self.on_plan, TAIL: self.on_tail}
        self.copy_calls = {}
        self.amounts = [AMOUNT_HELPER]
        self.prepares = [PREPARE]
        self.finishes = [FINISH]
        self.tails_real = [TAIL]

        def link(main_start, start):
            pairs = list(zip(call_row(image, self.relative, main_start), call_row(image, self.relative, start)))
            self.copy_calls[start] = pairs
            for (_, main), (_, other) in pairs:
                if main != other:
                    if main == AMOUNT_HELPER and main_start == ROUTE:
                        if other not in self.amounts:
                            self.amounts.append(other)
                    if main == PREPARE and main_start == ROUTE:
                        if other not in self.prepares:
                            self.prepares.append(other)
                    if main == FINISH and main_start == ROUTE:
                        if other not in self.finishes:
                            self.finishes.append(other)
                    if main == TAIL and main_start == PREPARE:
                        if other not in self.tails_real:
                            self.tails_real.append(other)
                    if main in machine.calls:
                        machine.calls[other] = machine.calls[main]
                    elif main in machine.slots:
                        machine.slots[other] = machine.slots[main]
                    elif main not in REAL_PAIRS:
                        raise EvidenceError("copy call %#x has no stub" % other)

        for start in ROUTE_COPIES:
            link(ROUTE, start)
        for start in self.amounts[1:]:
            link(AMOUNT_HELPER, start)
        for start in self.prepares[1:]:
            link(PREPARE, start)
        for start in self.finishes[1:]:
            link(FINISH, start)
        for start in self.tails_real[1:]:
            link(TAIL, start)
        machine.tails = machine.calls
        self.real.stubs = frozenset(machine.slots) | frozenset(machine.calls)
        machine.watch = {}
        self.reset()

    def reset(self):
        self.machine.memory.reset()
        self.brk = HEAP_FREE
        self.live = {}
        self.fixture = set()
        self.events = []
        self.rows = {}
        self.next_row = ROW_AT
        self.value = 0
        self.used = 0
        self.exempt = False
        self.hash_word = 0
        self.tear = None
        self.user_class = 0
        self.core_status = 0x186
        self.amount_status = []
        self.limits = (1, 1)
        self.transfers = []
        self.room = 0
        self.plan_cap = 0
        self.amount_wide = False
        self.amount_any = False
        self.operations = []
        self.panic_word = None

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def on_malloc(self, m):
        size = m.regs[RDI]
        if size > 0x40000:
            raise Halt("allocation size %#x" % size)
        m.regs[RAX] = self.allocate(size)

    def on_free(self, m):
        at, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(at, None) != size:
            raise Halt("free %#x size %#x" % (at, size))

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
        if regs[RDX] > 0x8000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_bcmp(self, m):
        regs = m.regs
        left, right = m.memory.bytes_at(regs[RDI], regs[RDX]), m.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcmp(self, m):
        regs = m.regs
        left, right = m.memory.bytes_at(regs[RDI], regs[RDX]), m.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_panic(self, m, slot):
        if slot == SLOT_UNWRAP:
            if m.regs[RSI] != 0x2B:
                raise Halt("unwrap text length")
            self.panic_word = m.memory.read(m.regs[RDX], 2)
        raise Panicked("%#x" % slot)

    def on_recorder(self, m):
        self.events.append(("record", m.regs[RSI]))

    def on_collect(self, m):
        self.events.append(("collect", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def on_row(self, m):
        key = m.memory.bytes_at(m.regs[RSI], 20)
        if m.regs[RDI] != DEX_AT + 0xF8:
            raise Halt("row map %#x" % m.regs[RDI])
        at = self.rows.get(key)
        if at is None:
            at = self.next_row
            self.next_row += 0x40
            self.rows[key] = at
            m.memory.put_bytes(at, bytes(0x40))
        m.regs[RAX] = at

    def on_insert(self, m):
        key = m.memory.bytes_at(m.regs[RSI], 20)
        self.events.append(("insert", m.regs[RDI] - DEX_AT, key.hex()))
        if self.tear is not None and m.regs[RDI] == DEX_AT + 0x188:
            m.memory.write(self.rows[key] + 0x20, 8, self.tear)

    def on_remove(self, m):
        self.events.append(("remove", m.regs[RDI] - DEX_AT, m.memory.bytes_at(m.regs[RSI], 20).hex()))

    def on_user_lookup(self, m):
        self.events.append(("lookup", m.regs[RDI] - DEX_AT, m.regs[RSI]))
        m.regs[RAX] = BOOK_AT

    def on_margin(self, m):
        stack = m.regs[RSP]
        self.events.append(("margin", m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8], m.regs[R9] - DEX_AT, m.memory.read(stack, 8) - DEX_AT))
        m.memory.write(m.regs[RDI], 8, self.value)
        m.memory.write(m.regs[RDI] + 8, 8, self.used)

    def on_exempt(self, m):
        m.regs[RAX] = int(self.exempt)

    def on_hash(self, m):
        m.regs[RAX] = self.hash_word

    def on_status(self, m):
        self.events.append(("status", m.memory.read(m.regs[RDI], 2)))

    def stack_words(self, m, count, skip=1):
        return tuple(m.memory.read(m.regs[RSP] + 8 * (skip + at), 8) for at in range(count))

    def on_class_row(self, m):
        self.events.append(("class", m.regs[RDI] - STATE_AT, m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.memory.write(LIMIT_AT + 0x80 + 0x3C, 1, self.user_class)
        m.regs[RAX] = LIMIT_AT + 0x80

    def on_dex_at(self, m):
        self.events.append(("dex_at", m.regs[RDI] - STATE_AT, m.regs[RSI]))
        m.regs[RAX] = OTHER_DEX_AT

    def on_core(self, m):
        self.events.append(("core", "out" if m.regs[RDI] == OUT_AT else "tmp", m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[RCX] - STATE_AT))
        out = m.regs[RDI]
        m.memory.put_bytes(out, bytes(range(0x20, 0x80)))
        m.memory.write(out, 2, self.core_status)

    def amount_args(self, m, name):
        user = m.memory.bytes_at(m.regs[RDX], 20).hex()
        words = self.stack_words(m, 3)
        tail = (words[1],) if self.amount_wide else ()
        self.events.append((name, m.regs[RSI] - STATE_AT, user, m.regs[RCX], m.regs[R8], "any" if self.amount_any else m.regs[R9], words[0], words[2]) + tail)

    def on_amount(self, m):
        self.amount_args(m, "amount")
        status = self.amount_status.pop(0)
        out = m.regs[RDI]
        m.memory.put_bytes(out, bytes(range(0x90, 0xF0)))
        m.memory.write(out, 2, status)

    def on_prepare(self, m):
        user = m.memory.bytes_at(m.regs[RSI], 20).hex()
        self.events.append(("prepare", m.regs[RDI] - STATE_AT, user, m.regs[RDX], m.regs[RCX], m.regs[R8], m.memory.read(m.regs[R9], 8), m.memory.read(m.regs[RSP] + 8, 4)))

    def on_finish(self, m):
        self.events.append(("finish", m.regs[RDI] - STATE_AT, m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[RCX], m.regs[R8]))

    def on_limit_row(self, m):
        self.events.append(("limit_row", m.regs[RDI] - STATE_AT, m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.regs[RAX] = LIMIT_AT

    def on_limiter(self, m):
        now = m.memory.read(m.regs[RSI], 8), m.memory.read(m.regs[RSI] + 8, 4)
        self.events.append(("limiter", m.regs[RDI] - LIMIT_AT, now, m.regs[RDX], m.regs[RCX]))
        m.regs[RAX] = self.limits[0 if m.regs[RDI] == LIMIT_AT else 1]

    def on_error_drop(self, m):
        status = m.memory.read(m.regs[RDI], 2)
        self.events.append(("drop", status, m.memory.read(m.regs[RDI] + 2, 2)))
        if status == 0x168:
            size, at, length = m.memory.read(m.regs[RDI] + 8, 8), m.memory.read(m.regs[RDI] + 0x10, 8), m.memory.read(m.regs[RDI] + 0x18, 8)
            if (size, length) != (14, 14) or m.memory.bytes_at(at, 14) != b"token mismatch":
                raise Halt("dropped text")

    def on_panic_drop(self, m):
        self.events.append(("panic_drop", m.memory.read(m.regs[RDI], 2)))

    def on_spot_row(self, m):
        self.events.append(("spot_row", m.regs[RDI] - STATE_AT, m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.regs[RAX] = SPOT_ROW_AT

    def on_dex_room(self, m):
        self.events.append(("dex_room", m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[RCX]))
        m.regs[RAX] = self.room

    def on_format(self, m):
        self.events.append(("format",))
        for at, word in enumerate((0x1111, 0x2222, 0x3333)):
            m.memory.write(m.regs[RDI] + 8 * at, 8, word)

    def on_transfer(self, m):
        self.events.append(("transfer", m.regs[RSI] - STATE_AT, m.regs[RDX], m.memory.bytes_at(m.regs[RCX], 20).hex(), m.regs[R8], m.regs[R9]))
        out = m.regs[RDI]
        m.memory.put_bytes(out, bytes(range(0x40, 0xA0)))
        m.memory.write(out, 2, self.transfers.pop(0))

    def on_balance_op(self, m):
        words = self.stack_words(m, 2)
        mode, extra = m.regs[R8], m.regs[R9]
        self.events.append(("op", m.regs[RSI] - STATE_AT, m.memory.bytes_at(m.regs[RDX], 20).hex(), m.regs[RCX], mode, extra, words[1] & MASK[4]) + ((words[0],) if extra else ()))
        out = m.regs[RDI]
        m.memory.put_bytes(out, bytes(range(0x60, 0xC0)))
        m.memory.write(out, 2, self.operations.pop(0))

    def on_rollback(self, m):
        self.events.append(("rollback", m.regs[RDI] - STATE_AT, m.regs[RSI], m.regs[RDX], m.memory.bytes_at(m.regs[RCX], 20).hex(), m.regs[R8]))

    def on_plan(self, m):
        self.events.append(("plan", m.regs[RSI] - STATE_AT, m.memory.bytes_at(m.regs[RDX], 20).hex(), m.regs[RCX], m.regs[R8], m.regs[R9]))
        at = self.allocate(max(1, self.plan_cap * 8) if self.plan_cap & MASK[8] >> 1 else 8)
        m.memory.write(m.regs[RDI], 8, self.plan_cap)
        m.memory.write(m.regs[RDI] + 8, 8, at)

    def on_tail(self, m):
        words = self.stack_words(m, 1)
        self.events.append(("tail", m.regs[RDI] - STATE_AT, m.memory.bytes_at(m.regs[RSI], 20).hex(), m.regs[RDX], m.regs[RCX], m.regs[R8], m.regs[R9], words[0]))

    def tree(self, items, layout, fan):
        """Build a B-tree of (key bytes, value bytes) with `fan` keys in each node; return root and height."""
        memory = self.machine.memory

        def capacity(height):
            return fan if height == 0 else fan + (fan + 1) * capacity(height - 1)

        def least(height):
            return 1 if height == 0 else 1 + 2 * least(height - 1)

        def build(part, height):
            if height == 0:
                node = self.allocate(layout.leaf)
                memory.put_bytes(node, bytes([0x5A]) * layout.leaf)
                memory.write(node + layout.parent, 8, 0)
                memory.write(node + layout.count, 2, len(part))
                for at, (key, value) in enumerate(part):
                    memory.put_bytes(node + layout.key_at + at * layout.key_size, key)
                    memory.put_bytes(node + layout.val_at + at * layout.val_size, value)
                return node
            for count in range(1, fan + 1):
                rest = len(part) - count
                if (count + 1) * least(height - 1) <= rest <= (count + 1) * capacity(height - 1):
                    break
            else:
                raise EvidenceError("fixture tree does not fit")
            sizes = [rest // (count + 1) + (1 if at < rest % (count + 1) else 0) for at in range(count + 1)]
            at = 0
            built = []
            middle = []
            for index, size in enumerate(sizes):
                built.append(build(part[at:at + size], height - 1))
                at += size
                if index < count:
                    middle.append(part[at])
                    at += 1
            node = self.allocate(layout.inner)
            memory.put_bytes(node, bytes([0x5A]) * layout.inner)
            memory.write(node + layout.parent, 8, 0)
            memory.write(node + layout.count, 2, len(middle))
            for index, (key, value) in enumerate(middle):
                memory.put_bytes(node + layout.key_at + index * layout.key_size, key)
                memory.put_bytes(node + layout.val_at + index * layout.val_size, value)
            for index, child in enumerate(built):
                memory.write(node + layout.child + 8 * index, 8, child)
                memory.write(child + layout.parent, 8, node)
                memory.write(child + layout.index, 2, index)
            return node

        if not items:
            return 0, 0
        height = 0
        while len(items) > capacity(height):
            height += 1
        return build(items, height), height

    def staking(self, epochs, active, fan):
        """epochs: {epoch: [(key32, hot, cold, [(user, amount)])]}"""
        memory = self.machine.memory
        memory.put_bytes(STAKING_AT, bytes([0x77]) * 0x58)
        rows = []
        for epoch in sorted(epochs):
            members = []
            for key, hot, cold, delegations in sorted(epochs[epoch]):
                root, height = self.tree([(user, amount.to_bytes(8, "little")) for user, amount in sorted(delegations)], DELEGATIONS, fan)
                value = root.to_bytes(8, "little") + height.to_bytes(8, "little") + len(delegations).to_bytes(8, "little") + hot + cold + bytes([0x66]) * 0x40
                members.append((key, value[:0x40]))
            root, height = self.tree(members, VALIDATORS, fan)
            value = root.to_bytes(8, "little") + height.to_bytes(8, "little") + len(members).to_bytes(8, "little") + bytes([0x66]) * 0x10
            rows.append((epoch.to_bytes(8, "little"), value))
        root, height = self.tree(rows, EPOCHS, fan)
        memory.write(STAKING_AT + 0x30, 8, root)
        memory.write(STAKING_AT + 0x38, 8, height)
        memory.write(STAKING_AT + 0x40, 8, len(rows))
        memory.write(STAKING_AT + 0x48, 8, active)
        self.fixture = set(self.live)

    def margin_table(self, rows):
        """rows: [(slot, tag, key, word)] in a 32 slot control table at TABLE_AT; dex +0x128 pointer, +0x130 mask, +0x140 items."""
        memory = self.machine.memory
        control = TABLE_AT + 0x1000
        memory.put_bytes(control, bytes([0xFF]) * 48)
        for slot, tag, key, word in rows:
            memory.write(control + slot, 1, tag)
            if slot < 16:
                memory.write(control + 32 + slot, 1, tag)
            entry = control - (slot + 1) * 0x50
            memory.put_bytes(entry, key)
            memory.write(entry + 0x48, 8, word)
        memory.write(DEX_AT + 0x128, 8, control)
        memory.write(DEX_AT + 0x130, 8, 31)
        memory.write(DEX_AT + 0x140, 8, len(rows))

    def user_row(self, key, word, watch=0):
        at = self.next_row
        self.next_row += 0x40
        self.rows[key] = at
        self.machine.memory.put_bytes(at, bytes(0x40))
        self.machine.memory.write(at, 8, word)
        self.machine.memory.write(at + 0x20, 8, watch)


# ---- rule list, written apart from the bytes ----

I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)
U64 = (1 << 64) - 1
USER = bytes(range(0xA0, 0xB4))
DEST = bytes(range(0xC0, 0xD4))


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def saturate(value):
    return max(I64_MIN, min(I64_MAX, value))


def share_of(stake, total, fee, low, high, top):
    """stake / total * fee in f64, clamp, then truncate; a value that is not finite gives 0."""
    value = float(stake) / float(total) * float(fee)
    if not math.isfinite(value):
        return 0
    value = min(high, max(low, value))
    return I64_MAX if value > top else int(value)


class Spec:
    """Predicts the event list, row words and result of one run."""

    def __init__(self, floats):
        self.low, self.high, self.top = floats

    def row_change(self, world, key, change, record):
        old = world["rows"].get(key, (0, 0))
        world["events"].append(("insert", 0x188, key.hex()))
        watch = old[1]
        after = world["tear"] if world["tear"] is not None else watch
        total = old[0] + change
        if total != saturate(total):
            world["events"].append(("record", record))
        word = saturate(total)
        if watch:
            if not after:
                world["events"].append(("remove", 0x158, key.hex()))
        elif after:
            world["events"].append(("insert", 0x158, key.hex()))
        world["rows"][key] = (word, after)

    def split(self, world, fee, tracker):
        if fee >> 63:
            return "panic 0x576e048"
        members = None
        tree = world["epochs"]
        if world["active"] in tree:
            members = tree[world["active"]]
        rest = fee
        if members is None:
            world["events"].append(("status", 0x97))
        else:
            stakes = []
            for key, hot, _, delegations in sorted(members):
                total = 0
                for _, amount in sorted(delegations):
                    total += amount
                    if total > U64:
                        return "panic stake sum"
                stakes.append((key, hot, total))
            total = 0
            for _, _, stake in stakes:
                total += stake
                if total > U64:
                    return "panic 0x576e118"
            if total:
                for key, hot, stake in stakes:
                    if not stake:
                        continue
                    part = share_of(stake, total, signed(fee), self.low, self.high, self.top)
                    left = rest - part
                    if left != saturate(left):
                        world["events"].append(("record", RECORD_REST))
                    rest = saturate(left)
                    self.row_change(world, hot, part, RECORD_ROW_ADD)
        if rest:
            world["events"].append(("collect", DEX_AT, 0, rest & U64, tracker))
        return None

    def available(self, world):
        world["events"].append(("lookup", 0xF8, USER_AT))
        world["events"].append(("margin", BOOK_AT, 0, 4, world["byte_2ed"], 0x60, 0))
        value, used = signed(world["value"]), world["used"]
        if used >> 63:
            return None, "panic 0x576e048"
        left = value - used
        if left != saturate(left):
            world["events"].append(("record", RECORD_AVAILABLE))
        left = saturate(left)
        word = 0
        if not world["exempt"] and world["table"]:
            word = dict(world["table"]).get(USER, 0)
        if left <= 0:
            left = 0
        return (left - word) if left >= word else 0, None

    def debit(self, world, x, tracker):
        fee = world["fee"]
        if x <= fee:
            return {"status": 0x5C}
        net = x - fee
        room, stop = self.available(world)
        if stop:
            return {"stop": stop}
        if x >> 63:
            return {"stop": "panic 0x576e048"}
        if room < x:
            return {"status": 0x33}
        self.row_change(world, USER, -x, RECORD_ROW_SUB)
        stop = self.split(world, fee, tracker)
        if stop:
            return {"stop": stop}
        word = signed(world["deposit"]) - net
        if word != saturate(word):
            world["events"].append(("record", RECORD_NET))
        world["deposit"] = saturate(word) & U64
        return {"status": 0x186, "net": net}

    def send(self, world, x, fee, tracker):
        if x <= fee:
            return {"status": 0x5B}
        room, stop = self.available(world)
        if stop:
            return {"stop": stop}
        if x >> 63:
            return {"stop": "panic 0x576e048"}
        if room < x:
            return {"status": 0x33}
        self.row_change(world, USER, -x, RECORD_ROW_SUB)
        self.row_change(world, DEST, x - fee, RECORD_ROW_ADD)
        if fee:
            stop = self.split(world, fee, tracker)
            if stop:
                return {"stop": stop}
        return {"status": 0x186}

    def route(self, world, flag, key, count_word, user_two):
        events = world["events"]
        user = USER.hex()
        kind = world["class"]
        lift = world["lift"]
        place = lambda offset: offset + lift if offset >= 0x5B8 else offset
        events.append(("class", 0, user))
        one = world["byte_3acb"]
        path = "direct"
        if kind >= 4:
            if not world["byte_5b0"] & 1:
                path = "routed"
        elif not world["byte_5b1"] & 1 and kind >= 2:
            if kind == 3:
                path = "routed"
            elif count_word & MASK[4] >= 2 and (one ^ 1 | flag) & 1 == 0 and key:
                path = "mirror"
        core = ("core", "tmp", user_two, ACTION_AT, 0)
        if path == "direct":
            events.append(("core", "out", user_two, ACTION_AT, 0))
            return {"result": "core", "path": path}
        if path == "mirror":
            width = world["dex_50"]
            zero = int(width == 0)
            events.append(("dex_at", place(0x5B8), key))
            events.append(("amount", 0, user, width, zero, 0, 1, 0))
            self.amount_tail(world)
            events.append(core)
            if one == 1:
                events.append(("dex_at", place(0x5B8), key))
                events.append(("amount", 0, user, width, 1, key, zero, 0))
                self.amount_tail(world)
            return {"result": "core", "path": path}
        events.append(("limit_row", place(0x770), user))
        now = (world["now"][0], world["now"][1])
        events.append(("limiter", 0, now, world["windows"][0], world["windows"][1]))
        events.append(("limiter", 0x18, now, world["windows"][2], world["windows"][3]))
        if not world["limits"][0] and not world["limits"][1]:
            return {"result": "limit", "path": path}
        world["row_30"] = min(U64, world["row_30"] + 1)
        world["word_7d0"] = min(U64, world["word_7d0"] + 1)
        width = key
        if not flag & 1:
            if key >= world["vec_len"]:
                return {"stop": "panic 0x576e048", "path": path, "word": 0x141}
            events.append(("panic_drop", 0x141))
            width = world["vec_words"][key]
        events.append(("prepare", 0, user, width, flag ^ 1, key, count_word, int(kind == 4)))
        events.append(core)
        if kind == 4:
            events.append(("finish", 0, user, width, flag ^ 1, key))
        else:
            events.append(("amount", 0, user, width, flag ^ 1, key, 0, 0))
            self.amount_tail(world)
        return {"result": "core", "path": path}

    def amount_tail(self, world):
        status = world["amounts"].pop(0)
        if status != 0x186:
            world["events"].append(("drop", status, 0x9392))

    def amount(self, world, token, flag_src, index_src, flag_dst, index_dst, limit_flag, limit):
        """Move up to the room of the source to the other side, one step out and one step in."""
        events = world["events"]
        user = USER.hex()
        lift = world["lift"]
        place = lambda offset: offset + lift if offset >= 0x5B8 else offset
        world["word_7d8"] = min(U64, world["word_7d8"] + 1)
        events.append(("limit_row", place(0x770), user))
        world["row_38"] = min(U64, world["row_38"] + 1)
        done = {"status": 0x186, "moved": 0}
        if flag_src == flag_dst and (flag_src == 0 or index_src == index_dst):
            return done
        if USER in world["skip"]:
            return done
        books = world["books"]
        cap = None
        if flag_dst & 1:
            if index_dst >= len(books):
                return {"stop": "panic 0x576e048", "word": 0x141}
            events.append(("panic_drop", 0x141))
            book = books[index_dst]
            if book["mode"] != 3:
                if book["w1c0"] >> 63:
                    return {"stop": "panic 0x576e048"}
                left = book["w1c0"] - signed(book["w238"])
                if left != saturate(left):
                    events.append(("record", world["record_room"]))
                cap = max(saturate(left), 0)
        if flag_src & 1:
            if index_src >= len(books):
                return {"stop": "panic 0x576e048", "word": 0x141}
            events.append(("panic_drop", 0x141))
            book = books[index_src]
            if book["token"] != token:
                events.append(("drop", 0x168, 0xA3A2))
                return done
            events.append(("panic_drop", 0x141))
            events.append(("dex_room", HEAP_BASE + 0x30000 + index_src * 0x2F0, user, 4, book["byte_2ed"]))
            room = max(signed(world["room"]), 0)
        else:
            events.append(("spot_row", 0x80, user))
            total, hold = world["spot"].get(token, (0, 0))
            if total < hold:
                events.append(("record", RECORD_HOLD))
                room = 0
            else:
                room = (total - hold) // 100
        moved = room if cap is None else min(room, cap)
        if limit_flag & 1:
            moved = min(limit, moved)
        if not moved:
            return done
        statuses = list(world["transfers"])
        if flag_src & 1:
            events.append(("panic_drop", 0x141))
            events.append(("transfer", 0, index_src, user, 1, moved))
            status = statuses.pop(0)
            if status != 0x186:
                events.append(("format",))
                events.append(("drop", status, 0x4342))
                return {"status": 0x168, "string": (0x1111, 0x2222, 0x3333)}
        if flag_dst & 1:
            if index_dst >= len(books):
                return {"stop": "panic 0x576e048"}
            events.append(("panic_drop", 0x141))
            if books[index_dst]["token"] != token:
                return {"status": 0x168, "text": b"token mismatch"}
            events.append(("transfer", 0, index_dst, user, 0, moved))
            status = statuses.pop(0)
            if status != 0x186:
                events.append(("rollback", 0, flag_src, index_src, user, moved))
                events.append(("format",))
                events.append(("drop", status, 0x4342))
                return {"status": 0x168, "string": (0x1111, 0x2222, 0x3333)}
        return {"status": 0x186, "moved": moved}

    def prepare(self, world, token, second, third, count, special):
        events = world["events"]
        user = USER.hex()
        found = int(bool(special) and token in world["tokens"])
        cap = world["plan_cap"]
        events.append(("plan", 0, user, 0, found, token))
        if special:
            events.append(("tail", 0, user, token, second, third, count, 0))
        else:
            events.append(("amount", 0, user, token, 0, POISON, second, 0, third))
            self.amount_tail(world)

    def operation(self, world, token, mode, flag, extra=None):
        """One balance step; returns False when it failed."""
        events = world["events"]
        events.append(("op", 0, USER.hex(), token, mode, 0 if extra is None else 1, flag) + (() if extra is None else (extra,)))
        status = world["operations"].pop(0)
        if status != 0x186:
            events.append(("drop", status, 0x6362))
            return False
        return True

    def finish(self, world, token, flag, index):
        world["events"].append(("amount", 0, USER.hex(), token, flag, index, 0, 0))
        self.amount_tail(world)
        if token in world["tokens"]:
            self.operation(world, token, 2, 0)
            self.operation(world, token, 1, 0)

    def tail(self, world, token, second, third, record, flag):
        tag, key, word = record
        step = tag - 2 if tag >= 2 else 1
        listed = token in world["tokens"]
        if step == 0:
            if listed:
                self.operation(world, token, 3, flag)
                self.operation(world, token, 0, flag)
        else:
            if step == 1 and tag & 1 and key in world["tokens"]:
                if not self.operation(world, key, 3, flag, word):
                    return
            if listed:
                self.operation(world, token, 3, flag)
        world["events"].append(("amount", 0, USER.hex(), token, 0, "any", second, 0, third))
        self.amount_tail(world)



# ---- cases ----

class Case:
    def __init__(self, label, kind, **fields):
        self.label, self.kind, self.fields = label, kind, fields


def tag_bytes(text, size):
    return hashlib.sha256(text.encode()).digest()[:size]


def validators(name, stakes):
    """One validator per stake list; hot and cold users come from the name."""
    rows = []
    for index, amounts in enumerate(stakes):
        key = tag_bytes("key %s %d" % (name, index), 32)
        hot = tag_bytes("hot %s %d" % (name, index), 20)
        cold = tag_bytes("cold %s %d" % (name, index), 20)
        rows.append((key, hot, cold, [(tag_bytes("user %s %d %d" % (name, index, at), 20), amount) for at, amount in enumerate(amounts)]))
    return rows


def base_world():
    return dict(epochs={}, active=7, fan=3, rows={}, tear=None, value=1 << 40, used=0, exempt=False, table=[], fee=1000000, deposit=1 << 50, byte_2ed=9, hash_word=0x1200000000000005,
                table_rows=[], events=[], collect=None)


def world(**change):
    out = base_world()
    out.update(change)
    return out


def route_world(**change):
    out = dict(events=[], rows={}, tear=None, epochs={}, active=0, fan=3, value=0, used=0, exempt=False, table=[], fee=0, deposit=0, byte_2ed=0, hash_word=0, table_rows=[])
    out.update({"class": 0, "byte_5b0": 0, "byte_5b1": 0, "byte_3acb": 0, "dex_50": 0x5151, "now": (0x1122334455667788, 0x99AABBCC), "windows": (0xE8, 0xF0, 0xF8, 0x500), "limits": (1, 1),
                "row_30": 3, "word_7d0": 9, "vec_len": 4, "vec_words": [0x6100, 0x6101, 0x6102, 0x6103], "amounts": [0x186, 0x186], "core": 0x186, "lift": 0})
    out.update(change)
    return out


def split_cases():
    three = validators("three", [[100], [200], [700]])
    out = []
    add = lambda label, fee, **change: out.append(Case("split/" + label, "split", amount=fee, world=world(**change)))
    add("no_epochs", 1000000, epochs={})
    add("epoch_absent", 1000000, epochs={6: three, 8: three})
    add("epoch_found_three", 1000000, epochs={7: three})
    add("epoch_first", 1000000, epochs={1: three, 2: [], 3: []}, active=1)
    add("epoch_last", 999999, epochs={1: [], 2: [], 3: three}, active=3)
    add("epoch_absent_large", 5, epochs={value: three for value in range(40)}, active=99)
    add("epoch_found_large", 12345, epochs={value: three for value in range(40)}, active=23, fan=2)
    add("fee_zero", 0, epochs={7: three})
    add("fee_one", 1, epochs={7: three})
    add("fee_two", 2, epochs={7: three})
    add("fee_top_bit_panics", 1 << 63, epochs={7: three})
    add("fee_max_word_panics", U64, epochs={7: three})
    add("fee_i64_max", I64_MAX, epochs={7: three})
    add("fee_2_53", 1 << 53, epochs={7: three})
    add("fee_2_53_plus_one", (1 << 53) + 1, epochs={7: three})
    add("fee_2_62_rounds", (1 << 62) + 1, epochs={7: validators("thirds", [[1], [1], [1]])})
    add("no_validators", 1000, epochs={7: []})
    add("all_zero", 1000, epochs={7: validators("zero", [[0], [0, 0], []])})
    add("zero_among", 1000, epochs={7: validators("mix", [[0], [50], [], [150]])})
    add("sum_of_delegations", 1000, epochs={7: validators("sum", [[1, 2, 3], [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], [100]])}, fan=2)
    add("one_validator", 1000, epochs={7: validators("one", [[5]])})
    add("stake_at_max", 1000, epochs={7: validators("max", [[U64], [0]])})
    add("stake_top_half", 1000, epochs={7: validators("half", [[1 << 63], [(1 << 63) - 1]])})
    add("delegation_sum_overflow", 1000, epochs={7: validators("over", [[U64, 1]])})
    add("total_overflow", 1000, epochs={7: validators("tover", [[U64], [1]])})
    add("tiny_share_truncates", 3, epochs={7: validators("tiny", [[1], [1000000]])})
    for count in (2, 5, 11, 12, 20, 21, 22, 40, 64):
        add("size_%d" % count, 10000019, epochs={7: validators("size%d" % count, [[index * 977 + 1] for index in range(count)])}, fan=11 if count % 2 else 2)
    for fan in (2, 3, 5, 11):
        add("fan_%d" % fan, 7654321, epochs={3: three, 7: validators("fan%d" % fan, [[index + 1, index + 2] for index in range(14)]), 9: three}, fan=fan)
    shared = validators("share", [[10], [20], [30]])
    shared = [(row[0], shared[0][1], row[2], row[3]) for row in shared]
    add("same_hot_twice", 600, epochs={7: shared})
    add("hot_row_near_top", 1000, epochs={7: three}, rows={three[0][1]: (I64_MAX - 10, 0)})
    add("hot_row_negative", 1000, epochs={7: three}, rows={three[1][1]: (-500, 3)})
    add("hot_row_watch_set", 1000, epochs={7: three}, rows={three[2][1]: (1, 5)})
    add("tear_to_set", 1000, epochs={7: three}, tear=1)
    add("tear_to_clear", 1000, epochs={7: three}, tear=0, rows={three[0][1]: (0, 9), three[1][1]: (0, 9), three[2][1]: (0, 9)})
    rng = random.Random(9401)
    for index in range(RANDOM_SPLITS):
        count = rng.randint(1, 26)
        bits = rng.choice((8, 20, 40, 60))
        stakes = [[rng.getrandbits(bits) for _ in range(rng.randint(0, 3))] for _ in range(count)]
        fee = rng.getrandbits(rng.choice((1, 10, 20, 40, 52, 56, 62)))
        add("random_%03d" % index, fee, epochs={7: validators("r%d" % index, stakes)}, fan=rng.choice((2, 3, 6, 11)))
    return out


def debit_cases():
    three = validators("three", [[100], [200], [700]])
    out = []
    for kind, label_x in (("debit", "debit"), ("send", "send")):
        def add(label, x, **change):
            fields = dict(amount=x, world=world(epochs={7: three}, **change))
            fields["fee_arg"] = fields["world"]["fee"]
            out.append(Case("%s/%s" % (label_x, label), kind, **fields))
        fee = 1000000
        add("x_zero", 0)
        add("x_below_fee", fee - 1)
        add("x_at_fee", fee)
        add("x_above_fee_by_one", fee + 1)
        add("x_ok", 5000000)
        add("x_equals_room", 5000000, value=5000000)
        add("x_one_over_room", 5000001, value=5000000)
        add("x_top_bit_panics", 1 << 63)
        add("x_top_bit_no_margin_panics", (1 << 63) + 5, value=0)
        add("x_i64_max", I64_MAX, value=I64_MAX)
        add("value_negative", 5000000, value=U64)
        add("value_min_used_one", 5000000, value=1 << 63, used=1)
        add("value_max_used_zero", 5000000, value=I64_MAX)
        add("used_top_bit_panics", 5000000, used=1 << 63)
        add("used_eats_room", 5000000, value=6000000, used=1000001)
        add("used_leaves_room", 5000000, value=6000000, used=1000000)
        add("table_word_eats", 5000000, value=6000000, table=[(USER, 1000001)], table_rows=[(5, 0x09, USER, 1000001)])
        add("table_word_leaves", 5000000, value=6000000, table=[(USER, 1000000)], table_rows=[(5, 0x09, USER, 1000000)])
        add("table_word_over_value", 5000000, value=6000000, table=[(USER, 7000000)], table_rows=[(5, 0x09, USER, 7000000)])
        add("table_exempt", 5000000, value=6000000, exempt=True, table=[(USER, 7000000)], table_rows=[(5, 0x09, USER, 7000000)])
        other = bytes(20)
        add("table_other_user", 5000000, value=6000000, table=[(other, 7000000)], table_rows=[(5, 0x09, other, 7000000)])
        add("table_near_key", 5000000, value=6000000, table=[(USER[:19] + b"\0", 7000000)], table_rows=[(5, 0x09, USER[:19] + b"\0", 7000000)])
        add("table_tail_key", 5000000, value=6000000, table=[(b"\0" + USER[1:], 7000000)], table_rows=[(5, 0x09, b"\0" + USER[1:], 7000000)])
        tags = [(slot, 0x09, tag_bytes("wall %d" % slot, 20), 77) for slot in range(5, 21)]
        add("table_second_group", 5000000, value=6000000, table=[(USER, 500)] + [(row[2], 77) for row in tags], table_rows=tags + [(21, 0x09, USER, 500)])
        add("table_second_group_miss", 5000000, value=6000000, table=[(row[2], 77) for row in tags], table_rows=tags)
        add("row_saturates_low", 5000000, rows={USER: (I64_MIN + 3, 0)})
        add("row_exact", 5000000, rows={USER: (5000000, 2)})
        add("tear_to_set", 5000000, tear=1)
        add("tear_to_clear", 5000000, tear=0, rows={USER: (9, 4)})
        add("byte_2ed", 5000000, byte_2ed=0x77)
        if kind == "debit":
            add("fee_zero_word", 5000000, fee=0)
            add("fee_at_i64_max", 1 << 63, fee=I64_MAX)
            add("fee_top_bit_panics", (1 << 63) + 2, fee=1 << 63, value=U64 >> 1)
            add("net_saturates_low", 5000000, deposit=1 << 63)
            add("net_near_low", 5000000, deposit=(1 << 63) + 4000000)
            add("net_large", I64_MAX, fee=1, deposit=(1 << 64) - 1, value=I64_MAX)
            add("epoch_missing", 5000000, active=8)
        else:
            add("caller_fee_zero", 5, fee=0)
            add("caller_fee_zero_at_zero", 0, fee=0)
            add("caller_fee_top_bit_panics", (1 << 63) + 9, fee=1 << 63, value=I64_MAX)
            add("dest_near_top", 5000000, rows={DEST: (I64_MAX - 5, 1)})
            add("epoch_missing", 5000000, active=8)
    rng = random.Random(9402)
    for index in range(RANDOM_DEBITS):
        kind = rng.choice(("debit", "send"))
        fee = rng.choice((0, 1, 1000000, 2000000, rng.getrandbits(30)))
        x = rng.choice((fee, fee + 1, fee + rng.getrandbits(32), rng.getrandbits(50)))
        value = rng.getrandbits(rng.choice((10, 33, 51))) * rng.choice((1, 1, -1)) & U64
        used = rng.getrandbits(rng.choice((1, 30, 50)))
        slot_word = rng.getrandbits(32)
        change = dict(fee=fee, value=value, used=used, deposit=rng.getrandbits(62), rows={USER: (rng.getrandbits(40), rng.randint(0, 1))})
        if rng.random() < 0.5:
            change.update(table=[(USER, slot_word)], table_rows=[(rng.randint(5, 20), 0x09, USER, slot_word)])
        fields = dict(amount=x, world=world(epochs={7: validators("d%d" % index, [[rng.getrandbits(30)] for _ in range(rng.randint(1, 8))])}, **change))
        fields["fee_arg"] = fee
        out.append(Case("%s/random_%03d" % (kind, index), kind, **fields))
    return out


def route_cases():
    out = []
    def add(label, entry="route", **fields):
        flag, key, count = fields.pop("flag", 0), fields.pop("key", 0), fields.pop("count", 0)
        for copy, lift in enumerate(ROUTE_LIFT):
            out.append(Case("%s%d/%s" % (entry, copy, label), entry, flag=flag, key=key, count=count, copy=copy, world=route_world(lift=lift, **fields)))

    for kind in range(0, 7):
        for b0 in (0, 1):
            for b1 in (0, 1):
                add("class_%d_%d%d" % (kind, b0, b1), **{"class": kind, "byte_5b0": b0, "byte_5b1": b1})
                add("class_%d_%d%d_failing_core" % (kind, b0, b1), core=0x27, **{"class": kind, "byte_5b0": b0 | 2, "byte_5b1": b1 | 2})
                add("class_%d_%d%d" % (kind, b0, b1), entry="wrap", core=0x27 if kind & 1 else 0x186, **{"class": kind, "byte_5b0": b0, "byte_5b1": b1})
    two = {"class": 2}
    add("mirror_on", key=2, count=2, byte_3acb=1, **two)
    add("mirror_count_big", key=2, count=(1 << 32) + 1, byte_3acb=1, **two)
    add("mirror_count_low_word", key=2, count=0xFFFFFFFF, byte_3acb=1, **two)
    add("mirror_count_one", key=2, count=1, byte_3acb=1, **two)
    add("mirror_flag", key=2, count=2, byte_3acb=1, flag=1, **two)
    add("mirror_flag_even", key=2, count=2, byte_3acb=1, flag=2, **two)
    add("mirror_key_zero", key=0, count=2, byte_3acb=1, **two)
    add("mirror_byte_off", key=2, count=2, byte_3acb=0, **two)
    add("mirror_byte_three", key=2, count=2, byte_3acb=3, **two)
    add("mirror_dex_word_zero", key=2, count=2, byte_3acb=1, dex_50=0, **two)
    add("mirror_first_fails", key=2, count=2, byte_3acb=1, amounts=[0x31, 0x186], **two)
    add("mirror_second_fails", key=2, count=2, byte_3acb=1, amounts=[0x186, 0x32], **two)
    add("mirror_both_fail_core_fails", key=2, count=2, byte_3acb=1, amounts=[0x31, 0x32], core=0x27, **two)
    three = {"class": 3}
    add("limit_first_only", limits=(1, 0), **three)
    add("limit_second_only", limits=(0, 1), **three)
    add("limit_both_fail", limits=(0, 0), **three)
    add("limit_both_fail_class_four", limits=(0, 0), **{"class": 4})
    add("count_at_max", row_30=U64, word_7d0=U64, **three)
    add("count_one_under", row_30=U64 - 1, word_7d0=U64 - 1, **three)
    add("routed_key_two", key=2, **three)
    add("routed_key_last", key=3, **three)
    add("routed_key_past_end_panics", key=4, **three)
    add("routed_key_far_panics", key=1 << 40, **three)
    add("routed_flag_skips_vector", key=9, flag=1, **three)
    add("routed_flag_even_word", key=2, flag=2, **three)
    add("routed_flag_odd_word", key=9, flag=3, **three)
    add("routed_post_fails", amounts=[0x32], **three)
    add("routed_post_fails_core_fails", amounts=[0x32], core=0x28, **three)
    add("routed_class_four", key=1, **{"class": 4})
    add("routed_class_four_flag", key=9, flag=1, **{"class": 4})
    add("routed_class_five", key=1, **{"class": 5})
    add("routed_class_255", key=1, **{"class": 255})
    add("wrap_routed_post_fails", entry="wrap", amounts=[0x32], **three)
    add("wrap_limit_both_fail", entry="wrap", limits=(0, 0), **three)
    add("wrap_status_other", entry="wrap", core=0x187)
    return out


def book(token=5, mode=0, w1c0=1 << 40, w238=0, byte_2ed=7):
    return dict(token=token, mode=mode, w1c0=w1c0, w238=w238, byte_2ed=byte_2ed)


def amount_world(**change):
    out = dict(events=[], rows={}, tear=None, epochs={}, active=0, fan=3, value=0, used=0, exempt=False, table=[], fee=0, deposit=0, byte_2ed=0, hash_word=0, table_rows=[], lift=0)
    out.update(word_7d8=11, row_38=4, skip=[], books=[book(), book(token=6), book(mode=3)], room=5000, spot={5: (1000000, 0), 6: (250, 40)}, transfers=[0x186, 0x186], fan_spot=3)
    out.update(change)
    return out


def amount_cases():
    out = []

    def add(label, token=5, source=(0, 0), target=(1, 0), limit=(0, 0), **fields):
        for copy, lift in enumerate(ROUTE_LIFT):
            out.append(Case("amount%d/%s" % (copy, label), "amount", copy=copy, token=token, source=source, target=target, limit=limit, world=amount_world(lift=lift, record_room=RECORD_ROOM_COPY if copy else RECORD_ROOM, **fields)))

    add("spot_to_dex")
    add("same_spot", source=(0, 3), target=(0, 9))
    add("same_dex", source=(1, 1), target=(1, 1))
    add("same_flag_other_dex", source=(1, 0), target=(1, 1), token=5)
    add("flag_words_differ", source=(2, 0), target=(0, 0))
    add("flag_word_three", source=(3, 0), target=(1, 0))
    add("flag_word_even_target", source=(1, 0), target=(2, 1))
    add("counters_at_top", word_7d8=U64, row_38=U64)
    add("counters_one_under", word_7d8=U64 - 1, row_38=U64 - 1)
    add("skip_user", skip=[USER])
    add("skip_many_not_user", skip=[tag_bytes("skip %d" % at, 20) for at in range(30)])
    add("skip_many_with_user", skip=[tag_bytes("skip %d" % at, 20) for at in range(30)] + [USER])
    add("skip_user_same_side", skip=[USER], source=(0, 0), target=(0, 0))
    add("skip_near", skip=[USER[:19] + b"\xff", b"\0" + USER[1:]])
    add("target_past_end_panics", target=(1, 3))
    add("target_far_panics", target=(1, 1 << 40))
    add("target_last", target=(1, 2))
    add("target_mode_three_no_cap", target=(1, 2), books=[book(), book(), book(token=5, mode=3, w1c0=1)])
    add("target_cap_small", books=[book(w1c0=100, w238=0)])
    add("target_cap_negative", books=[book(w1c0=100, w238=200)])
    add("target_cap_with_negative_word", books=[book(w1c0=100, w238=(1 << 64) - 50)])
    add("target_cap_saturates", books=[book(w1c0=I64_MAX, w238=1 << 63)])
    add("target_word_top_bit_panics", books=[book(w1c0=1 << 63)])
    add("spot_token_absent", token=6, target=(0, 0), source=(1, 1), spot={})
    add("spot_row_empty", spot={})
    add("spot_token_other", token=5, spot={6: (1000000, 0)})
    add("spot_hold_exact", spot={5: (1000, 1000)})
    add("spot_hold_above", spot={5: (1000, 1001)})
    add("spot_below_hundred", spot={5: (99, 0)})
    add("spot_hundred", spot={5: (100, 0)})
    add("spot_rounds_down", spot={5: (199, 0)})
    add("spot_top_word", spot={5: (U64, 0)}, books=[book(w1c0=I64_MAX)])
    add("spot_many_tokens", spot={value: (value * 1000, value) for value in range(1, 40)})
    add("spot_many_tokens_absent", token=99, spot={value: (value * 1000, value) for value in range(1, 40)}, books=[book(token=99)])
    add("dex_source_to_spot", source=(1, 0), target=(0, 0))
    add("dex_source_to_dex", source=(1, 0), target=(1, 1), token=5, books=[book(), book()])
    add("dex_source_past_end_panics", source=(1, 3), target=(0, 0))
    add("dex_source_token_mismatch", source=(1, 1), target=(0, 0))
    add("dex_source_room_negative", source=(1, 0), target=(0, 0), room=U64)
    add("dex_source_room_zero", source=(1, 0), target=(0, 0), room=0)
    add("target_token_mismatch", token=9, spot={9: (1000000, 0)})
    add("dex_to_dex_target_mismatch", source=(1, 0), target=(1, 1), books=[book(), book(token=6)])
    add("limit_off", limit=(0, 7))
    add("limit_lower", limit=(1, 7))
    add("limit_equal", limit=(1, 5000))
    add("limit_higher", limit=(1, 1 << 40))
    add("limit_zero", limit=(1, 0))
    add("limit_even_flag", limit=(2, 7))
    add("limit_odd_flag", limit=(3, 7))
    add("out_step_fails", source=(1, 0), target=(0, 0), transfers=[0x31, 0x186])
    add("out_step_fails_dex_dex", source=(1, 0), target=(1, 1), books=[book(), book()], transfers=[0x31, 0x186])
    add("in_step_fails_from_spot", transfers=[0x32, 0x186])
    add("in_step_fails_rolls_back", source=(1, 0), target=(1, 1), books=[book(), book()], transfers=[0x186, 0x32])
    rng = random.Random(9403)
    for index in range(RANDOM_AMOUNTS):
        source = (rng.getrandbits(1), rng.randint(0, 2))
        target = (rng.getrandbits(1), rng.randint(0, 2))
        books = [book(token=rng.choice((5, 5, 6)), mode=rng.choice((0, 0, 3)), w1c0=rng.getrandbits(34), w238=rng.getrandbits(33), byte_2ed=index & 7) for _ in range(3)]
        add("random_%03d" % index, source=source, target=target, limit=(rng.getrandbits(1), rng.getrandbits(32)), books=books, room=rng.getrandbits(34), spot={5: (rng.getrandbits(40), rng.getrandbits(34)), 6: (rng.getrandbits(40), 0)}, transfers=[rng.choice((0x186, 0x186, 0x31)), rng.choice((0x186, 0x186, 0x32))])
    return out


def prepare_cases():
    out = []

    def add(label, token=5, second=0x71, third=2, count=0x99, special=0, **fields):
        for copy, lift in enumerate(ROUTE_LIFT):
            state = amount_world(lift=lift, tokens=[], plan_cap=0, amounts=[0x186], record_room=0)
            state.update(fields)
            out.append(Case("prepare%d/%s" % (copy, label), "prepare", copy=copy, token=token, second=second, third=third, count=count, special=special, world=state))

    add("plain")
    add("plain_capacity", plan_cap=3)
    add("plain_niche_word", plan_cap=1 << 63)
    add("plain_amount_fails", amounts=[0x31])
    add("plain_token_listed", tokens=[5])
    add("special_empty_tree", special=1)
    add("special_found", special=1, tokens=[5])
    add("special_absent", special=1, tokens=[4, 6])
    add("special_many_found", special=1, tokens=list(range(0, 60)), token=33)
    add("special_many_absent", special=1, tokens=list(range(0, 60, 2)), token=33)
    add("special_many_past_end", special=1, tokens=list(range(0, 60, 2)), token=99)
    add("special_capacity", special=1, plan_cap=2)
    add("special_byte_two", special=2, tokens=[5])
    return out


def closing_cases():
    out = []

    def add(kind, label, token=5, second=1, third=2, record=(0, 0, 0), flag=0, **fields):
        for copy, lift in enumerate(ROUTE_LIFT):
            state = amount_world(lift=lift, tokens=[], plan_cap=0, amounts=[0x186], operations=[0x186, 0x186], record_room=0)
            state.update(fields)
            out.append(Case("%s%d/%s" % (kind, copy, label), kind, copy=copy, token=token, second=second, third=third, record=record, flag=flag, world=state))

    add("finish", "not_listed")
    add("finish", "listed", tokens=[5])
    add("finish", "listed_among_many", tokens=list(range(60)), token=33)
    add("finish", "absent_among_many", tokens=list(range(0, 60, 2)), token=33)
    add("finish", "past_end", tokens=list(range(0, 60, 2)), token=99)
    add("finish", "amount_fails_goes_on", tokens=[5], amounts=[0x31])
    add("finish", "first_op_fails_goes_on", tokens=[5], operations=[0x41, 0x186])
    add("finish", "second_op_fails", tokens=[5], operations=[0x186, 0x42])
    add("finish", "other_flag_and_index", second=0, third=9, tokens=[5])
    for tag in range(0, 6):
        add("tail", "tag_%d_plain" % tag, record=(tag, 7, 0x1234))
        add("tail", "tag_%d_token_listed" % tag, record=(tag, 7, 0x1234), tokens=[5])
        add("tail", "tag_%d_key_listed" % tag, record=(tag, 7, 0x1234), tokens=[7])
        add("tail", "tag_%d_both_listed" % tag, record=(tag, 7, 0x1234), tokens=[5, 7], flag=1)
    add("tail", "tag_two_first_op_fails", record=(2, 7, 1), tokens=[5], operations=[0x41, 0x186])
    add("tail", "tag_two_second_op_fails", record=(2, 7, 1), tokens=[5], operations=[0x186, 0x42])
    add("tail", "tag_one_key_op_fails_stops", record=(1, 7, 1), tokens=[5, 7], operations=[0x41, 0x186])
    add("tail", "tag_three_key_op_fails_stops", record=(3, 7, 1), tokens=[5, 7], operations=[0x41, 0x186])
    add("tail", "token_op_fails_goes_on", record=(0, 7, 1), tokens=[5], operations=[0x41, 0x186])
    add("tail", "amount_fails", amounts=[0x31])
    add("tail", "many_keys_found", record=(1, 33, 5), tokens=list(range(60)), token=99)
    add("tail", "many_keys_absent", record=(1, 33, 5), tokens=list(range(0, 60, 2)), token=99)
    add("tail", "many_token_found_tag_two", record=(2, 0, 0), tokens=list(range(60)), token=33)
    add("tail", "many_token_absent_tag_two", record=(2, 0, 0), tokens=list(range(0, 60, 2)), token=33)
    add("tail", "many_token_found_tag_zero", record=(0, 0, 0), tokens=list(range(60)), token=33)
    add("tail", "many_token_absent_tag_zero", record=(0, 0, 0), tokens=list(range(0, 60, 2)), token=33)
    add("tail", "flag_byte_three", record=(0, 0, 0), tokens=[5], flag=3)
    return out


def all_cases():
    return split_cases() + debit_cases() + route_cases() + amount_cases() + prepare_cases() + closing_cases()


def prepare(harness, case):
    harness.reset()
    state = case.fields["world"]
    memory = harness.machine.memory
    memory.put_bytes(USER_AT, USER)
    memory.put_bytes(DEST_AT, DEST)
    memory.put_bytes(DEX_AT, bytes([0x33]) * 0x2F0)
    memory.write(DEX_AT + 0x250, 8, state["fee"])
    memory.write(DEX_AT + 0x238, 8, state["deposit"])
    memory.write(DEX_AT + 0x2ED, 1, state["byte_2ed"])
    memory.write(DEX_AT + 0x140, 8, 0)
    harness.value, harness.used, harness.exempt, harness.hash_word = state["value"], state["used"], state["exempt"], state["hash_word"]
    harness.tear = state["tear"]
    for key, (word, watch) in sorted(state["rows"].items()):
        harness.user_row(key, word & U64, watch)
    if state["table_rows"]:
        harness.margin_table(state["table_rows"])
    harness.staking(state["epochs"], state["active"], state["fan"])
    if case.kind in ("amount", "prepare", "finish", "tail"):
        prepare_amount(harness, case)


def prepare_amount(harness, case):
    state = case.fields["world"]
    memory = harness.machine.memory
    memory.put_bytes(STATE_AT, bytes([0x44]) * 0x5000)
    lift = state["lift"]
    place = lambda offset: STATE_AT + (offset + lift if offset >= 0x5B8 else offset)
    harness.room = state["room"]
    harness.transfers = list(state["transfers"])
    memory.write(place(0x7D8), 8, state["word_7d8"])
    memory.write(LIMIT_AT + 0x38, 8, state["row_38"])
    memory.write(place(0x5C0), 8, HEAP_BASE + 0x30000)
    memory.write(place(0x5C8), 8, len(state["books"]))
    for index, row in enumerate(state["books"]):
        at = HEAP_BASE + 0x30000 + index * 0x2F0
        memory.put_bytes(at, bytes([0x22]) * 0x2F0)
        memory.write(at + 0x50, 8, row["token"])
        memory.write(at + 0x230, 1, row["mode"])
        memory.write(at + 0x1C0, 8, row["w1c0"])
        memory.write(at + 0x238, 8, row["w238"])
        memory.write(at + 0x2ED, 1, row["byte_2ed"])
    root, height = harness.tree([(key, bytes(0xB0)) for key in sorted(state["skip"])], SKIP_SET, 3)
    memory.write(place(0x8D0), 8, root)
    memory.write(place(0x8D8), 8, height)
    root, height = harness.tree([(token.to_bytes(8, "little"), word_pair(state["spot"][token]) + bytes(8)) for token in sorted(state["spot"])], SPOT_TOKENS, state["fan_spot"])
    memory.put_bytes(SPOT_ROW_AT, bytes([0x55]) * 0x40)
    memory.write(SPOT_ROW_AT + 0x10, 8, root)
    memory.write(SPOT_ROW_AT + 0x18, 8, height)
    if case.kind != "amount":
        tokens = sorted(state["tokens"])
        root, height = harness.tree([(token.to_bytes(8, "little"), bytes(0xB0)) for token in tokens], TOKEN_SET, 3)
        memory.write(STATE_AT + 0x568, 8, root)
        memory.write(STATE_AT + 0x570, 8, height)
        harness.plan_cap = state["plan_cap"]
        harness.amount_status = list(state["amounts"])
        harness.amount_wide = case.kind != "finish"
        harness.amount_any = case.kind == "tail"
        harness.operations = list(state.get("operations", []))
    harness.fixture = set(harness.live)


def word_pair(pair):
    return pair[0].to_bytes(8, "little") + pair[1].to_bytes(8, "little")


def prepare_route(harness, case):
    state = case.fields["world"]
    memory = harness.machine.memory
    memory.put_bytes(STATE_AT, bytes([0x44]) * 0x5000)
    harness.user_class = state["class"]
    harness.core_status = state["core"]
    harness.amount_status = list(state["amounts"])
    harness.limits = state["limits"]
    lift = state["lift"]
    place = lambda offset: STATE_AT + (offset + lift if offset >= 0x5B8 else offset)
    memory.write(place(0x5B0), 1, state["byte_5b0"])
    memory.write(place(0x5B1), 1, state["byte_5b1"])
    memory.write(place(0x3ACB), 1, state["byte_3acb"])
    memory.write(place(0x60), 8, state["now"][0])
    memory.write(place(0x68), 4, state["now"][1])
    for at, word in zip((0x4E8, 0x4F0, 0x4F8, 0x500), state["windows"]):
        memory.write(place(at), 8, word)
    memory.write(place(0x7D0), 8, state["word_7d0"])
    memory.write(place(0x5C8), 8, state["vec_len"])
    memory.write(place(0x5C0), 8, HEAP_BASE + 0x30000)
    for index, word in enumerate(state["vec_words"]):
        memory.write(HEAP_BASE + 0x30000 + index * 0x2F0 + 0x50, 8, word)
    memory.write(LIMIT_AT + 0x30, 8, state["row_30"])
    memory.write(OTHER_DEX_AT + 0x50, 8, state["dex_50"])
    memory.write(COUNT_AT, 8, case.fields["count"])


def compare(harness, spec, case):
    """Run one case; return None on a full match or the first difference."""
    prepare(harness, case)
    machine = harness.machine
    memory = machine.memory
    state = case.fields["world"]
    want = {key: value for key, value in state.items()}
    want["rows"] = dict(state["rows"])
    want["events"] = []
    want["amounts"] = list(state.get("amounts", []))
    kind = case.kind
    amount = case.fields.get("amount", 0)
    stop = None
    got_stop = None
    if kind == "split":
        stop = spec.split(want, amount, TRACKER_AT)
        verdict = {"stop": stop} if stop else {}
        args = {RDI: DEX_AT, RSI: amount, RDX: STAKING_AT, RCX: TRACKER_AT}
        entry = SPLIT
    elif kind == "debit":
        verdict = spec.debit(want, amount, TRACKER_AT)
        args = {RDI: OUT_AT, RSI: DEX_AT, RDX: USER_AT, RCX: amount, R8: STAKING_AT, R9: TRACKER_AT}
        entry = DEBIT
    elif kind == "send":
        verdict = spec.send(want, amount, case.fields["fee_arg"], TRACKER_AT)
        memory.write(STACK_TOP - 0x100, 8, STAKING_AT)
        memory.write(STACK_TOP - 0xF8, 8, TRACKER_AT)
        args = {RDI: OUT_AT, RSI: DEX_AT, RDX: USER_AT, RCX: DEST_AT, R8: amount, R9: case.fields["fee_arg"]}
        entry = SEND
    elif kind == "amount":
        return compare_amount(harness, spec, case, want)
    elif kind == "prepare":
        return compare_prepare(harness, spec, case, want)
    elif kind in ("finish", "tail"):
        return compare_closing(harness, spec, case, want)
    else:
        prepare_route(harness, case)
        wrapped = kind == "wrap"
        copy = case.fields["copy"]
        if wrapped:
            verdict = spec.route(want, 0, 0, 0, USER.hex())
            want["events"] = [("core", "tmp") + row[2:] if row[0] == "core" else row for row in want["events"]]
            args = {RDI: OUT_AT, RSI: ACTION_AT, RDX: USER_AT, RCX: STATE_AT}
            entry = WRAPPERS[copy]
        else:
            verdict = spec.route(want, case.fields["flag"], case.fields["key"], case.fields["count"], DEST.hex())
            memory.write(STACK_TOP - 0x100, 8, DEST_AT)
            memory.write(STACK_TOP - 0xF8, 8, ACTION_AT)
            memory.write(STACK_TOP - 0xF0, 8, 0x56914D8)
            args = {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: case.fields["flag"], R8: case.fields["key"], R9: COUNT_AT}
            entry = ROUTES[copy]
    try:
        machine.run(entry, args)
    except Panicked as error:
        got_stop = "panic %s" % error
    want_stop = verdict.get("stop")
    if want_stop != got_stop:
        if not (want_stop == "panic stake sum" and got_stop):
            return "stop %s vs %s" % (want_stop, got_stop)
    if kind in ("route", "wrap"):
        if harness.events != want["events"]:
            return "events %s vs %s" % (harness.events, want["events"])
        if want_stop:
            return None if verdict.get("word", harness.panic_word) == harness.panic_word else "panic word"
        return route_result(harness, want, verdict, kind)
    if harness.events != want["events"]:
        return "events %s vs %s" % (harness.events, want["events"])
    if want_stop:
        return None
    if kind != "split":
        if memory.read(OUT_AT, 2) != verdict["status"]:
            return "status %#x vs %#x" % (memory.read(OUT_AT, 2), verdict["status"])
        if "net" in verdict and memory.read(OUT_AT + 8, 8) != verdict["net"]:
            return "net"
        if "net" not in verdict and memory.read(OUT_AT + 8, 8) != STACK_WORD and memory.bytes_at(OUT_AT + 8, 1) != b"\xa5":
            return "out word written"
    if memory.read(DEX_AT + 0x238, 8) != want["deposit"]:
        return "deposit word %#x vs %#x" % (memory.read(DEX_AT + 0x238, 8), want["deposit"])
    for key, (word, watch) in want["rows"].items():
        at = harness.rows.get(key)
        got = (memory.read(at, 8), memory.read(at + 0x20, 8)) if at else (0, 0)
        if got != (word & U64, watch):
            return "row %s %s vs %s" % (key.hex()[:8], got, (word & U64, watch))
    if sorted(harness.live) != sorted(harness.fixture):
        return "leak %d" % (len(harness.live) - len(harness.fixture))
    return None


STACK_WORD = 0xA5A5A5A5A5A5A5A5


def compare_amount(harness, spec, case, want):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    place = lambda offset: STATE_AT + offset + want["lift"]
    source, target, limit = fields["source"], fields["target"], fields["limit"]
    verdict = spec.amount(want, fields["token"], source[0], source[1], target[0], target[1], limit[0], limit[1])
    for at, word in enumerate((target[0], target[1], limit[0], limit[1])):
        memory.write(STACK_TOP - 0x100 + 8 * at, 8, word)
    stop = None
    try:
        machine.run(harness.amounts[fields["copy"]], {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: fields["token"], R8: source[0], R9: source[1]})
    except Panicked as error:
        stop = "panic %s" % error
    if stop != verdict.get("stop"):
        return "stop %s vs %s" % (verdict.get("stop"), stop)
    if harness.events != want["events"]:
        return "events %s vs %s" % (harness.events, want["events"])
    if memory.read(place(0x7D8), 8) != want["word_7d8"] or memory.read(LIMIT_AT + 0x38, 8) != want["row_38"]:
        return "counters"
    if stop:
        return None if verdict.get("word", harness.panic_word) == harness.panic_word else "panic word"
    if memory.read(OUT_AT, 2) != verdict["status"]:
        return "status %#x vs %#x" % (memory.read(OUT_AT, 2), verdict["status"])
    if "moved" in verdict and memory.read(OUT_AT + 8, 8) != verdict["moved"]:
        return "moved %d vs %d" % (memory.read(OUT_AT + 8, 8), verdict["moved"])
    if "text" in verdict:
        size, at, length = memory.read(OUT_AT + 8, 8), memory.read(OUT_AT + 0x10, 8), memory.read(OUT_AT + 0x18, 8)
        if (size, length) != (14, 14) or memory.bytes_at(at, 14) != verdict["text"]:
            return "text"
    if "string" in verdict:
        got = tuple(memory.read(OUT_AT + 8 + 8 * at, 8) for at in range(3))
        if got != verdict["string"]:
            return "string %s" % (got,)
    return None


def compare_closing(harness, spec, case, want):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    want["operations"] = list(want["operations"])
    if case.kind == "finish":
        spec.finish(want, fields["token"], fields["second"], fields["third"])
        machine.run(harness.finishes[fields["copy"]], {RDI: STATE_AT, RSI: USER_AT, RDX: fields["token"], RCX: fields["second"], R8: fields["third"]})
    else:
        spec.tail(want, fields["token"], fields["second"], fields["third"], fields["record"], fields["flag"])
        for at, word in enumerate(fields["record"]):
            memory.write(COUNT_AT + 8 * at, 8, word)
        memory.write(STACK_TOP - 0x100, 8, fields["flag"])
        machine.run(harness.tails_real[fields["copy"]], {RDI: STATE_AT, RSI: USER_AT, RDX: fields["token"], RCX: fields["second"], R8: fields["third"], R9: COUNT_AT})
    if harness.events != want["events"]:
        return "events %s vs %s" % (harness.events, want["events"])
    return None


def compare_prepare(harness, spec, case, want):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    spec.prepare(want, fields["token"], fields["second"], fields["third"], fields["count"], fields["special"])
    memory.write(STACK_TOP - 0x100, 8, fields["special"])
    machine.run(harness.prepares[fields["copy"]], {RDI: STATE_AT, RSI: USER_AT, RDX: fields["token"], RCX: fields["second"], R8: fields["third"], R9: fields["count"]})
    if harness.events != want["events"]:
        return "events %s vs %s" % (harness.events, want["events"])
    extra = set(harness.live) - harness.fixture
    if want["plan_cap"] & (U64 >> 1) and extra:
        return "plan block kept"
    return None


def route_result(harness, want, verdict, kind):
    memory = harness.machine.memory
    block = bytes(range(0x20, 0x80))
    status = want["core"]
    if verdict["result"] == "limit":
        status = 0x170
    if kind == "route":
        if memory.read(OUT_AT, 2) != status:
            return "route status %#x vs %#x" % (memory.read(OUT_AT, 2), status)
        if verdict["result"] == "core" and memory.bytes_at(OUT_AT + 2, 0x5E) != block[2:]:
            return "route block"
    else:
        tag = memory.read(OUT_AT, 1)
        if tag != (0xD if status == 0x186 else 0xE):
            return "wrap tag %#x" % tag
        if status != 0x186:
            if memory.read(OUT_AT + 8, 2) != status:
                return "wrap status"
            if verdict["result"] == "core" and memory.bytes_at(OUT_AT + 0xA, 0x5E) != block[2:]:
                return "wrap block"
        elif memory.bytes_at(OUT_AT + 8, 8) != b"\xa5" * 8:
            return "wrap wrote a payload"
    if verdict["path"] == "routed" and verdict["result"] != "limit":
        if memory.read(LIMIT_AT + 0x30, 8) != want["row_30"] or memory.read(STATE_AT + 0x7D0 + want["lift"], 8) != want["word_7d0"]:
            return "counters"
    return None


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def float_constants(image):
    return tuple(struct.unpack("<d", code(image, at, 8))[0] for at in (FLOAT_LOW, FLOAT_HIGH, FLOAT_TOP))


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


def location_rows(harness):
    rows = []
    for name, slot in (("row add", RECORD_ROW_ADD), ("row sub", RECORD_ROW_SUB), ("dex +0x238 sub", RECORD_NET), ("fee rest sub", RECORD_REST), ("margin sub", RECORD_AVAILABLE), ("target room sub", RECORD_ROOM), ("spot hold sub", RECORD_HOLD)):
        path, line, column = harness.image.location(slot, harness.relative)
        rows.append((name, slot, path, line, column))
    return rows


def slot_sites(harness, slot):
    """FF 15 sites through one slot, by byte scan of .text."""
    base, text = harness.image.text_bytes()
    out = []
    at = text.find(b"\xff\x15")
    while at >= 0:
        if base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            out.append(base + at)
        at = text.find(b"\xff\x15", at + 1)
    return out


def direct_sites(harness, target):
    base, text = harness.image.text_bytes()
    out = []
    at = text.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(text) and base + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            out.append(base + at)
        at = text.find(b"\xe8", at + 1)
    return out


def send_site_row(harness, site):
    """Read the fixed setup of one transfer site: the fee register source and an all ones destination, by bytes in front of the two pushes."""
    data = code(harness.image, site - 0x60, 0x60)
    host = harness.image.fde(site)[0]
    fee = "stack word" if b"\x4c\x8b\x4c\x24" in data[-0x20:] else "zero" if b"\x45\x31\xc9" in data[-0x20:] else "other"
    ones = b"\xc7\x84\x24" in data and b"\xff\xff\xff\xff" in data
    return site, host, fee, "all ones" if ones else "caller value"


def host_table(harness):
    rows = []
    for name, slot in (("debit", SLOT_DEBIT), ("send", SLOT_SEND)):
        for site in slot_sites(harness, slot):
            rows.append((name, site, harness.image.fde(site)[0]) + send_site_row(harness, site)[2:] if name == "send" else (name, site, harness.image.fde(site)[0], "dex +0x250", "action text"))
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


MUTANT_STATE = {}


def worker_start():
    image = load_image()
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    MUTANT_STATE.update(harness=harness, cases=all_cases(), spec=Spec(float_constants(image)))


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
            trouble = compare(harness, MUTANT_STATE["spec"], cases[index])
        except (Halt, Panicked, EvidenceError, KeyError, ValueError, IndexError, OverflowError, TypeError) as error:
            trouble = "%s" % type(error).__name__
        if trouble:
            failed = cases[index].label + ": " + trouble
            break
    machine.patches = {}
    machine.cache.pop(va, None)
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:60].replace("\t", " ") if failed else ""}


def run_mutants(image, reached):
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    tasks = []
    results = []
    cases = all_cases()
    named = frozenset(index for index, case in enumerate(cases) if "random" not in case.label and not case.label.split("/")[0].endswith(("1", "2")))
    for start, _ in MUTATED:
        begin, end = image.exact_fde(start)
        for va, at, kind in mutation_targets(image, body_rows(image, begin, end)):
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            step = max(1, len(indices) // MUTANT_CASES)
            chosen = indices[::step][:MUTANT_CASES]
            chosen = sorted(set(chosen + indices[:4] + indices[-4:] + [index for index in indices if index in named]))
            tasks.append((start, va, at, kind, chosen))
    with multiprocessing.Pool(WORKERS, worker_start) as pool:
        results += pool.map(run_one, tasks, 4)
    return sorted(results, key=lambda row: (row["function"], row["va"], row["kind"]))


# ---- evidence ----

def outcome_of(harness, case, spec):
    """A short outcome label of one case, from the rule list alone."""
    state = dict(case.fields["world"])
    state["rows"] = dict(state["rows"])
    state["events"] = []
    state["amounts"] = list(state.get("amounts", []))
    kind = case.kind
    if kind == "split":
        stop = spec.split(state, case.fields["amount"], TRACKER_AT)
        if stop:
            return stop.split()[0]
        credits = sum(1 for row in state["events"] if row[:2] == ("insert", 0x188))
        rest = [row for row in state["events"] if row[0] == "collect"]
        missing = any(row[0] == "status" for row in state["events"])
        return "split %s credits %s" % ("no epoch" if missing else "epoch", "with rest" if rest else "no rest") if credits or missing else "split no credit %s" % ("with rest" if rest else "no rest")
    if kind in ("debit", "send"):
        verdict = spec.debit(state, case.fields["amount"], TRACKER_AT) if kind == "debit" else spec.send(state, case.fields["amount"], case.fields["fee_arg"], TRACKER_AT)
        return "%s %s" % (kind, verdict["stop"].split()[0] if "stop" in verdict else "status %#x" % verdict["status"])
    if kind == "amount":
        fields = case.fields
        state.update(word_7d8=state["word_7d8"], row_38=state["row_38"], transfers=list(state["transfers"]))
        verdict = spec.amount(state, fields["token"], fields["source"][0], fields["source"][1], fields["target"][0], fields["target"][1], fields["limit"][0], fields["limit"][1])
        if "stop" in verdict:
            return "amount panic"
        return "amount status %#x%s" % (verdict["status"], " moved" if verdict.get("moved") else "")
    if kind == "prepare":
        return "prepare %s" % ("special" if case.fields["special"] else "plain")
    if kind in ("finish", "tail"):
        return "%s %s" % (kind, "tag %d" % case.fields["record"][0] if kind == "tail" else "listed" if case.fields["token"] in state["tokens"] else "not listed")
    verdict = spec.route(state, 0 if kind == "wrap" else case.fields["flag"], 0 if kind == "wrap" else case.fields["key"], 0 if kind == "wrap" else case.fields["count"], "")
    return "%s %s %s" % (kind, verdict["path"], "panic" if "stop" in verdict else verdict["result"])


def share_vector(case, spec):
    state = dict(case.fields["world"])
    state["rows"] = {}
    state["events"] = []
    stop = spec.split(state, case.fields["amount"], TRACKER_AT)
    members = state["epochs"].get(state["active"], [])
    stakes = [sum(amount for _, amount in row[3]) for row in members]
    credited = sum(word for word, _ in state["rows"].values())
    rest = [row[3] for row in state["events"] if row[0] == "collect"]
    return "\t".join((case.label, str(case.fields["amount"]), str(len(members)), str(sum(stakes)), "panic" if stop else str(credited), "panic" if stop else str(rest[0] if rest else 0)))


def analyse(image, full=True):
    harness = Harness(image)
    spec = Spec(float_constants(image))
    cases = all_cases()
    machine = harness.machine
    mismatches = []
    outcomes = collections.Counter()
    reached = []
    seen = set()
    lines = []
    vectors = ["label\tfee\tvalidators\ttotal_stake\tcredited\trest"]
    for case in cases:
        machine.seen = set()
        try:
            trouble = compare(harness, spec, case)
        except (Halt, Panicked) as error:
            trouble = "%s %s" % (type(error).__name__, error)
        if trouble:
            mismatches.append("%s: %s" % (case.label, trouble))
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        outcome = outcome_of(harness, case, spec)
        outcomes[outcome] += 1
        lines.append("\t".join((case.kind, case.label, outcome, "fail" if trouble else "match")))
        if case.kind == "split":
            vectors.append(share_vector(case, spec))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    copies = tuple((start, "transfer helper copy") for start in harness.amounts[1:]) + tuple((start, "prepare copy") for start in harness.prepares[1:]) + tuple((start, "finish copy") for start in harness.finishes[1:]) + tuple((start, "tail copy") for start in harness.tails_real[1:])
    for start, role in MUTATED + NEIGHBOURS + copies:
        begin, end = image.exact_fde(start)
        rows = body_rows(image, begin, end)
        hit = sum(1 for row in rows if row.va in seen)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "instructions": len(rows), "stepped": hit})
        function_lines.append("%#x\t%#x\t%d\t%d\t%d\t%s" % (begin, end, end - begin, len(rows), hit, role))
    results_rows = run_mutants(image, reached) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    route_lines = ["class\tbyte_5b0\tbyte_5b1\tpath"]
    for kind in range(0, 6):
        for b0 in (0, 1):
            for b1 in (0, 1):
                world = route_world(**{"class": kind, "byte_5b0": b0, "byte_5b1": b1})
                route_lines.append("%d\t%d\t%d\t%s" % (kind, b0, b1, spec.route(world, 0, 0, 0, "")["path"]))
    copy_lines = ["copy\tsite\ttarget\tmain_site\tmain_target"]
    for start, pairs in sorted(harness.copy_calls.items()):
        for (main_site, main), (site, other) in pairs:
            copy_lines.append("%#x\t%#x\t%#x\t%#x\t%#x" % (start, site, other, main_site, main))
    status_lines = ["tag\tarm\tform\ttext"]
    for tag, arm, form, text in (status_row(image, tag) for tag in STATUS_TAGS):
        status_lines.append("%#x\t%#x\t%s\t%s" % (tag, arm, form, text))
    location_lines = ["where\tslot\tpath\tline\tcolumn"]
    for name, slot, path, line, column in location_rows(harness):
        location_lines.append("%s\t%#x\t%s\t%d\t%d" % (name, slot, path, line, column))
    site_lines = ["caller_of\tsite\thost\tfee_source\tdestination"]
    for row in host_table(harness):
        site_lines.append("%s\t%#x\t%#x\t%s\t%s" % row)
    low, high, top = float_constants(image)
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0][:200] if mismatches else "",
        "instructions_stepped": steps,
        "functions": functions,
        "mutations": tally,
        "float_clamp": {"low": low.hex(), "high": high.hex(), "top": top.hex()},
        "split_callers": ["%#x" % site for site in direct_sites(harness, SPLIT)],
        "route_callers": ["%#x" % site for site in direct_sites(harness, ROUTE)],
        "transfer_helper_sites": len(direct_sites(harness, AMOUNT_HELPER)),
        "_results": results_rows, "_lines": lines, "_vectors": vectors, "_functions": function_lines, "_route": route_lines, "_copies": copy_lines, "_status": status_lines, "_locations": location_lines, "_sites": site_lines,
    }
    return doc


SURVIVOR_GROUPS = (
    ("vector or iterator word", (0x3364F18, 0x3364F3C, 0x3364F77, 0x3364F8D, 0x3365027, 0x370DE67, 0x272D3DA, 0x272D5DF)),
    ("text byte a later store overwrites", (0x272D3EE, 0x272D5F3)),
    ("float clamp that gives the same value on every finite input", (0x370DF72, 0x370DF8D, 0x370DF97, 0x370DFCC, 0x370DEE2)),
    ("tree walk bound or height word that ends at the same key on these fixtures", (0x272D24C, 0x272FE46, 0x272FE4F, 0x272FE78, 0x272DA66, 0x272DA98, 0x272DADF, 0x272DAE8, 0x272DB18, 0x272DC92, 0x272DC9B, 0x272DCC8, 0x272F951, 0x272F95A, 0x272F988, 0x370DBAC, 0x370DCF5, 0x370DD54, 0x370DD8E, 0x370DDC4, 0x370DDD9, 0x370E005, 0x370E093, 0x3BE3A85, 0x3BE3B68, 0x3BE3C95, 0x3BE3CF4, 0x3BE3D79)),
    ("repeat of a bounds test that already passed", (0x272D30D, 0x272D4A1, 0x272D536)),
    ("sort size choice with the same sorted result", (0x33650AE, 0x33650B2)),
    ("table probe word behind a stubbed hash", (0x36F75E6, 0x36F7617, 0x36F7689, 0x36F76A7, 0x36F76AB)),
    ("saturation arm whose word another minimum hides", (0x272D790, 0x370A492)),
)
SURVIVOR_CLASS = {va: name for name, group in SURVIVOR_GROUPS for va in group}
UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, or a B-tree parent walk no fixture needs"


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toutcome\tresult"] + evidence.pop("_lines"), "share-vectors.tsv": evidence.pop("_vectors"), "functions.tsv": evidence.pop("_functions"), "route-table.tsv": evidence.pop("_route"),
              "copy-calls.tsv": evidence.pop("_copies"), "status-text.tsv": evidence.pop("_status"), "locations.tsv": evidence.pop("_locations"), "call-sites.tsv": evidence.pop("_sites")}
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    for name, lines in tables.items():
        files[name] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else (UNREACHED_REASON if row["result"] == "unreached" else SURVIVOR_CLASS.get(row["va"], "unclassified")))) for row in results]
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
