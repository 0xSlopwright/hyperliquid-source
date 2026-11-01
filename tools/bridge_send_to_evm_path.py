#!/usr/bin/env python3
"""Evaluate the node #94 send asset family from ELF bytes: sendToEvmWithData, sendAsset, agentSendAsset and SystemSendAsset, the shared route, the dex move, and the system send that fills both L1 to EVM queues.

The arms, the text parser, the recipient parser, the route, the move and the system send run as real bytes in a Python evaluator.
A separately written rule list predicts each status, stub event and queue row, and conditions, immediates and offsets of the reached rows are flipped to show the run can tell.
Tables are read from section bytes. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

SEND_ASSET = 0x1F678C0
AGENT_SEND = 0x27288C0
SYSTEM_SEND_ASSET = 0x2728E10
SEND_EVM = 0x2729060
PARSE = 0x272B950
RECIPIENT = 0x3988B80
ROUTE = 0x2729C30
MOVE = 0x272BD60
SYSTEM = 0x2715320
FEE_ERROR = 0x2715130
CLONE = 0x27B5760
DROP_RECORD = 0x2784560
DROP_STRINGS = 0x27822A0
QUEUE_PUSH = 0x27A0450
U256_MUL = 0x27A1150
ADDRESS_TEXT = 0x1444A00
DEX_ROW = 0x3332600
SYSTEM_RANGE = 0x37E5110
HASHER = 0x399C7A0
BS58 = 0x3BC5960

USER_ROW = 0x2755400
PRECHECK = 0x28CC390
BEFORE = 0x272FE00
AFTER_FLAG = 0x272F880
AFTER = 0x272D000
COUNTERS = 0x1F84640
MARGIN_ROW = 0x36F57F0
MARGIN_SUM = 0x37D7F10
TOKEN_FIND = 0x3C0DE00
TOKEN_NAME = 0x3C0D6E0
AMOUNT_TEXT = 0x37601E0
DEX_FIND = 0x3331FD0
BALANCE_ROW = 0x371B3A0
SHIFT = 0x270F6F0
CORE = 0x2712CE0
PRICE = 0x371CF40
TO_USD = 0x32815F0
TRADABLE = 0x3760360
ONE_WHOLE = 0x375FB50
HAS_ROW = 0x371B8A0
BASE_FEE = 0x342A1B0
GAS_FEE = 0x37325D0
QUOTE = 0x27101A0
SCALE = 0x333E310
RECIPIENT_STEP = 0x2711440
GAS_STEP = 0x2711A80
STAMP = 0x3987CB0
SINK = 0x3576710
GROW_USERS = 0x32D64A0
GROW_QUEUE = 0x32D59B0
GROW_LIST = 0x32D5A20
STATUS_DROP = 0x277EBA0
DEX_NAME_DROP = 0x3379490
STATUS_DROP_B = 0x3999770
TEXT_FORMAT = 0x1344760
HEX_DECODE = 0x156E650
RECIPIENT_TEMPLATE = 0x5A8445
ALPHABET_AT = 0x5A8450
BASE58_TEXT = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

EMPTY_TEXT = ""
ACK = 0xD
FAIL = 0xE
MAX_TEXT = 100
MAX_GAS = 1000000
MAX_DATA = 0x400
MAX_NUMBER = 0xCCCCCCCCCCCCCCC
SINGLE_LIMIT = 0x38D7EA4C68000
FEE_CAP = 0x2540BE400
QUEUE_NATIVE = 0xBB7
QUEUE_ERC20 = 9
GAS_FLOOR = 0x5F5E100
USD_CAP = 0x2386F26FC10000
STATUS_TAGS = (0x15, 0x28, 0x7C, 0xB6, 0xBA, 0xDC, 0xEA, 0xF6, 0xF8, 0xF9, 0xFB, 0x13F, 0x141, 0x142, 0x143, 0x148, 0x149, 0x14A, 0x14C, 0x14D, 0x14E, 0x15B, 0x15F, 0x160, 0x169, 0x16E, 0x17E, 0x183, 0x186)
MUTANT_STEP_LIMIT = 60000
MUTANT_CASES = 36
MUTANT_CASE_COST = 8000
WORKERS = 4

STATUS_OK = 0x186
STATUS_TABLE = 0x59A8D0

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

HEAP_FREE = HEAP_BASE + 0x60000
OUT_AT = HEAP_BASE + 0x1000
KEY_AT = HEAP_BASE + 0x2140
ACTION_AT = HEAP_BASE + 0x2200
USER_AT = HEAP_BASE + 0x3000
LIST_AT = HEAP_BASE + 0x3100
RECORD_AT = HEAP_BASE + 0x3400
VTABLE_AT = HEAP_BASE + 0x3800
ERROR_AT = HEAP_BASE + 0x3880
BYTES_AT = HEAP_BASE + 0x3900
STATE_AT = HEAP_BASE + 0x10000
DEXES_AT = HEAP_BASE + 0x20000
TOKENS_AT = HEAP_BASE + 0x22000
ROWS_AT = HEAP_BASE + 0x24000
COUNTER_AT = HEAP_BASE + 0x25000
BOOK_AT = HEAP_BASE + 0x26000
BALANCE_AT = HEAP_BASE + 0x27000
QUEUE_AT = HEAP_BASE + 0x28000
STATE_SIZE = 0x3B00
DEX_SIZE = 0x2F0
TOKEN_SIZE = 0xE8
FAKE_CLONE = 0x7E0000010
FAKE_NOOP = 0x7E0000020
FAKE_DROP = 0x7E0000030

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
        if rela["size"] % 24 or rela["offset"] + rela["size"] > len(self.blob):
            raise EvidenceError("truncated .rela.dyn")
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
        if two == 0x12 and opsize:
            reg, rm = modrm(True)
            return finish("movsd", ("x", reg), rm, 8, cc=1)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movsd", rm, ("x", reg), 8)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            return finish("psrlq", rm, w=16, target=value)
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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0xFB, True): "psubq", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd", (0xEB, False): "orpd"}
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
        elif op in ("shl", "shr", "sar", "rol", "ror"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "rol":
                result = (value << count | value >> (8 * width - count)) & MASK[width]
            elif op == "ror":
                result = (value >> count | value << (8 * width - count)) & MASK[width]
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
                elif row.cc == 1:
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
        elif op in ("subpd", "addpd", "divpd"):
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            pairs = ((to_float(left & MASK[8]), to_float(right & MASK[8])), (to_float(left >> 64), to_float(right >> 64)))
            if op == "subpd":
                low, high = [a - b for a, b in pairs]
            elif op == "addpd":
                low, high = [a + b for a, b in pairs]
            else:
                low, high = [a / b if b else math.nan for a, b in pairs]
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "psrlq":
            source = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((source & MASK[8]) >> row.target) | (((source >> 64) >> row.target) << 64)
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



# ---- harness: real bytes through .text; the allocator and memory slots are hooked, callees owned by merged packets are stubs that log their arguments ----

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

    def __init__(self, name, key_at, key_size, value_at, value_size, count_at, leaf, parent_at, index_at):
        self.name = name
        self.parent_at = parent_at
        self.index_at = index_at
        self.key_at = key_at
        self.key_size = key_size
        self.value_at = value_at
        self.value_size = value_size
        self.count_at = count_at
        self.leaf = leaf


MULTI_NODE = Layout("multi sig user map", 0x168, 20, 0, 0x20, 0x246, 0x248, 0x160, 0x244)
VAULT_NODE = Layout("vault map", 0x798, 20, 0, 0xB0, 0x876, 0x878, 0x790, 0x874)
LAYOUTS = (MULTI_NODE, VAULT_NODE)


FILLED = {}


def filled(name, size):
    data = FILLED.get(name, b"")
    if len(data) < size:
        data = hashlib.sha256(name.encode()).digest()
        while len(data) < size:
            data += hashlib.sha256(data).digest()
        FILLED[name] = data
    return data[:size]


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
        self.base_statics = dict(machine.memory.statics)
        self.base_hooks = {relative[slot]: hook for slot, hook in table.items()}
        self.base_hooks.update({FAKE_CLONE: self.on_bytes_clone, FAKE_NOOP: self.on_nothing, FAKE_DROP: self.on_bytes_drop})
        self.stub_hooks = {USER_ROW: self.on_user_row, PRECHECK: self.on_precheck, BEFORE: self.on_before, AFTER_FLAG: self.on_after_flag, AFTER: self.on_after, COUNTERS: self.on_counters, MARGIN_ROW: self.on_margin_row,
                           MARGIN_SUM: self.on_margin_sum, TOKEN_FIND: self.on_token_find, TOKEN_NAME: self.on_token_name, AMOUNT_TEXT: self.on_amount_text, DEX_FIND: self.on_dex_find, BALANCE_ROW: self.on_balance_row,
                           SHIFT: self.on_shift, CORE: self.on_core, PRICE: self.on_price, TO_USD: self.on_to_usd, TRADABLE: self.on_tradable, ONE_WHOLE: self.on_one_whole, HAS_ROW: self.on_has_row, BASE_FEE: self.on_base_fee,
                           GAS_FEE: self.on_gas_fee, QUOTE: self.on_quote, SCALE: self.on_scale, RECIPIENT_STEP: self.on_recipient_step, GAS_STEP: self.on_gas_step, STAMP: self.on_stamp, SINK: self.on_sink, GROW_USERS: self.on_grow_users,
                           GROW_QUEUE: self.on_grow_queue, GROW_LIST: self.on_grow_list, BS58: self.on_base58, TEXT_FORMAT: self.on_format, HEX_DECODE: self.on_hex, ADDRESS_TEXT: self.on_address_text, STATUS_DROP: self.on_status_drop, DEX_NAME_DROP: self.on_nothing, STATUS_DROP_B: self.on_nothing}
        self.switch = {ROUTE: self.on_route, MOVE: self.on_move}
        self.real = RealExcept()
        machine.real = self.real
        machine.watch = {}
        self.use(())
        self.tally = collections.Counter()
        self.case = None
        self.reset()

    def use(self, stubbed):
        """Stub set of one case kind: the fixed list plus the path functions the kind does not run."""
        hooks = dict(self.base_hooks)
        hooks.update(self.stub_hooks)
        for target in stubbed:
            hooks[target] = self.switch[target]
        machine = self.machine
        machine.slots = hooks
        machine.calls = hooks
        machine.tails = hooks
        self.real.stubs = frozenset(hooks)

    def reset(self):
        self.machine.memory.reset(USED)
        self.machine.memory.statics.clear()
        self.machine.memory.statics.update(self.base_statics)
        self.brk = HEAP_FREE
        self.live = {}
        self.events = []
        self.pending = []

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

    def on_nothing(self, m):
        pass

    def on_panic(self, m, slot):
        raise Panicked("%#x" % slot)

    def address(self, at):
        return self.machine.memory.bytes_at(at, 20).hex()

    def stack_arg(self, m, index):
        return m.memory.read(m.regs[RSP] + 8 + 8 * index, 8)

    def status_out(self, m, out, status, name):
        m.memory.put_bytes(out, filled(name, 0x60))
        m.memory.write(out, 2, status)

    # stubs

    def on_bytes_clone(self, m):
        out, at, ptr, size = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]
        self.events.append(("data clone", size))
        m.memory.write(out, 8, VTABLE_AT)
        m.memory.write(out + 8, 8, ptr)
        m.memory.write(out + 0x10, 8, size)
        m.memory.write(out + 0x18, 8, m.memory.read(at, 8))

    def on_bytes_drop(self, m):
        self.events.append(("data drop",))

    def on_address_text(self, m):
        out = m.regs[RDI]
        text = m.memory.bytes_at(m.regs[RSI], m.regs[RDX]).decode()
        address = parse_address(text)
        if address is None:
            m.memory.write(out, 1, 1)
            m.memory.write(out + 8, 8, ERROR_AT)
            m.memory.write(ERROR_AT, 8, ERROR_AT + 8)
            m.memory.write(ERROR_AT + 8, 8, FAKE_NOOP)
            return
        m.memory.write(out, 1, 0)
        m.memory.put_bytes(out + 1, address)

    def on_format(self, m):
        memory = m.memory
        pair = memory.read(m.regs[RDX], 8)
        text = memory.bytes_at(memory.read(pair, 8), memory.read(pair + 8, 8)).decode()
        if m.regs[RSI] == RECIPIENT_TEMPLATE:
            text = text.rjust(64, "0")
        self.write_string(m.regs[RDI], text)

    def on_hex(self, m):
        out, at, size, target = m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]
        text = m.memory.bytes_at(at, size).decode()
        try:
            m.memory.put_bytes(target, bytes.fromhex(text))
            m.memory.write(out, 4, 3)
        except ValueError:
            m.memory.write(out, 4, 0)

    def on_base58(self, m):
        memory = m.memory
        spec = m.regs[RCX]
        at, size = memory.read(spec, 8), memory.read(spec + 8, 8)
        text = memory.bytes_at(at, size).decode() if size else ""
        self.events.append(("base58", memory.read(spec + 0x10, 8), memory.read(spec + 0x18, 1)))
        status, raw = base58_rule(text)
        vector = memory.read(m.regs[RSI], 8)
        memory.write(m.regs[RDI] + 8, 4, 0x110006 if status == STATUS_OK else 1)
        if status == STATUS_OK:
            ptr = self.allocate(max(len(raw), 1))
            memory.put_bytes(ptr, raw)
            memory.write(vector, 8, max(len(raw), 1))
            memory.write(vector + 8, 8, ptr)
            memory.write(vector + 0x10, 8, len(raw))

    def on_user_row(self, m):
        address = m.memory.bytes_at(m.regs[RSI], 20)
        self.events.append(("user row", address.hex()))
        at = ROWS_AT + 0x40 * len(self.events)
        m.memory.write(at + 0x3C, 1, self.fix.modes.get(address, 0))
        m.regs[RAX] = at

    def on_precheck(self, m):
        self.events.append(("precheck", self.address(m.regs[RSI])))
        self.status_out(m, m.regs[RDI], self.fix.precheck, "precheck")

    def on_before(self, m):
        self.events.append(("before", self.address(m.regs[RSI]), m.regs[RDX], m.regs[RCX], m.regs[R8], m.memory.read(m.regs[R9], 8), m.memory.read(m.regs[R9] + 8, 8) if m.memory.read(m.regs[R9], 8) == 1 else 0, self.stack_arg(m, 0) & 0xFF))

    def on_after_flag(self, m):
        self.events.append(("after flag", self.address(m.regs[RSI]), m.regs[RDX], m.regs[RCX], m.regs[R8]))

    def on_after(self, m):
        self.events.append(("after", self.address(m.regs[RDX]), m.regs[RCX], m.regs[R8], m.regs[R9]))
        self.status_out(m, m.regs[RDI], self.fix.after, "after")

    def on_counters(self, m):
        self.events.append(("counters", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI])))
        m.regs[RAX] = COUNTER_AT

    def on_margin_row(self, m):
        self.events.append(("margin row", m.regs[RDI] - DEXES_AT, self.address(m.regs[RSI])))
        m.regs[RAX] = COUNTER_AT + 0x100

    def on_margin_sum(self, m):
        self.events.append(("margin sum", m.regs[RSI] - DEXES_AT, m.regs[RDX] - DEXES_AT))
        m.regs[RAX] = self.fix.margin

    def on_token_find(self, m):
        name = m.memory.bytes_at(m.regs[RDI], m.regs[RSI]).decode() if m.regs[RSI] else ""
        self.events.append(("token", name, m.regs[RDX] - STATE_AT))
        found = self.fix.names.get(name)
        m.keep_rdx = True
        m.regs[RAX] = 0 if found is None else 1
        m.regs[RDX] = found or 0

    def on_token_name(self, m):
        out, token = m.regs[RDI], m.regs[RSI]
        self.events.append(("token name", token, m.regs[RDX] - STATE_AT))
        self.write_string(out, "T%d" % token)

    def on_amount_text(self, m):
        text = self.text_at(m.regs[RCX])
        self.events.append(("amount", m.regs[RSI] - STATE_AT, m.regs[RDX], text))
        out = m.regs[RDI]
        m.memory.put_bytes(out, filled("amount", 0x60))
        if self.fix.amount_status != STATUS_OK:
            m.memory.write(out, 2, self.fix.amount_status)
            return
        m.memory.write(out, 2, STATUS_OK)
        m.memory.write(out + 8, 8, int(text))

    def on_dex_find(self, m):
        name = m.memory.bytes_at(m.regs[RDX], m.regs[RCX]).decode() if m.regs[RCX] else ""
        self.events.append(("dex", m.regs[RSI] - STATE_AT, name))
        out = m.regs[RDI]
        m.memory.put_bytes(out, filled("dex", 0x60))
        found = self.fix.dex_names.get(name)
        if found is None:
            m.memory.write(out, 2, 0x141)
            return
        m.memory.write(out, 2, STATUS_OK)
        m.memory.write(out + 8, 8, found[0])
        m.memory.write(out + 0x10, 8, found[1])

    def on_balance_row(self, m):
        self.events.append(("balance row", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI])))
        m.regs[RAX] = BOOK_AT

    def on_shift(self, m):
        self.events.append(("shift", m.regs[RDX], self.address(m.regs[RCX]), m.regs[R8] & 0xFF, m.regs[R9]))
        status = self.pending_shift()
        self.status_out(m, m.regs[RDI], status, "shift")

    def pending_shift(self):
        statuses = self.fix.shifts
        return statuses.pop(0) if statuses else STATUS_OK

    def on_core(self, m):
        frame = m.regs[RDX]
        memory = m.memory
        self.events.append(("core", memory.read(frame, 8), memory.read(frame + 0x10, 8), memory.read(frame + 0x20, 8), memory.read(frame + 0x28, 8), memory.read(frame + 0x30, 8) != 0, self.address(frame + 0x88), self.address(frame + 0x9C), memory.read(frame + 0xB0, 1)))
        out = m.regs[RDI]
        self.status_out(m, out, self.fix.core, "core")
        if self.fix.core == STATUS_OK:
            memory.write(out + 8, 8, 0)
            memory.write(out + 0x10, 8, 1)
            memory.write(out + 0x18, 8, 0)
            memory.put_bytes(out + 0x20, b"fee word sixteen")
        if self.fix.touch:
            self.touch_balance()

    def touch_balance(self):
        memory = self.machine.memory
        memory.write(BOOK_AT + 0x100 + 0x60, 8, memory.read(BOOK_AT + 0x100 + 0x60, 8) + 1)

    def on_price(self, m):
        self.events.append(("price", m.regs[RDI] - STATE_AT, m.regs[RSI], m.regs[RDX] - STATE_AT))
        m.regs[RAX] = self.fix.price

    def on_to_usd(self, m):
        self.events.append(("to usd", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8] - STATE_AT))
        result = self.fix.to_usd
        m.keep_rdx = True
        m.regs[RAX] = 0 if result is None else 1
        m.regs[RDX] = result or 0

    def on_tradable(self, m):
        self.events.append(("tradable", m.regs[RDI] - STATE_AT, m.regs[RSI]))
        m.regs[RAX] = int(self.fix.tradable)

    def on_one_whole(self, m):
        self.events.append(("one whole", m.regs[RDI] - STATE_AT, m.regs[RSI]))
        m.regs[RAX] = self.fix.whole

    def on_has_row(self, m):
        self.events.append(("has row", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI]), m.regs[RDX]))
        m.regs[RAX] = int(self.fix.has_row)

    def on_base_fee(self, m):
        self.events.append(("base fee", m.regs[RDI] - STATE_AT))
        m.regs[RAX] = self.fix.base_fee

    def on_gas_fee(self, m):
        self.events.append(("gas fee", m.regs[RSI], m.regs[RDX], m.regs[RCX] & 0xFF, m.regs[R8]))
        out = m.regs[RDI]
        self.status_out(m, out, self.fix.gas_status, "gas fee")
        if self.fix.gas_status == STATUS_OK:
            m.memory.write(out + 8, 8, self.fix.gas)

    def on_quote(self, m):
        self.events.append(("quote", self.address(m.regs[RSI]), self.address(m.regs[RDX])))
        m.keep_rdx = True
        m.regs[RAX] = self.fix.quote
        m.regs[RDX] = self.fix.quote_flag

    def on_scale(self, m):
        self.events.append(("scale", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX], m.regs[R8] - STATE_AT))
        result = self.fix.scale
        m.keep_rdx = True
        m.regs[RAX] = 0 if result is None else 1
        m.regs[RDX] = result or 0

    def on_recipient_step(self, m):
        frame = m.regs[R8]
        memory = m.memory
        words = (memory.read(frame, 1), memory.read(frame + 8, 8), memory.read(frame + 0x10, 8), memory.read(frame + 0x18, 8))
        self.events.append(("recipient step", self.address(m.regs[RDX]), self.address(m.regs[RCX]), m.regs[R9] & 0xFF) + (words if self.fix.log_frame else ()))
        self.status_out(m, m.regs[RDI], self.fix.step, "recipient step")

    def on_gas_step(self, m):
        out = m.regs[RDI]
        self.events.append(("gas step", self.address(m.regs[RDX]), m.regs[RCX], m.regs[R8] & 0xFF, m.regs[R9], self.stack_arg(m, 0)))
        self.status_out(m, out, self.fix.gas_step[0], "gas step")
        memory = m.memory
        if self.fix.gas_step[0] == STATUS_OK:
            kind, flag, token, amount, extra, last = self.fix.gas_step[1:]
            memory.write(out + 8, 1, kind)
            memory.write(out + 9, 1, flag)
            memory.write(out + 0x10, 8, token)
            memory.write(out + 0x18, 8, amount)
            memory.write(out + 0x20, 8, extra)
            memory.write(out + 0x28, 1, last)
        elif self.fix.gas_step[0] == 0xF6:
            at = self.allocate(0x40)
            memory.write(at, 8, 7)
            memory.write(at + 8, 8, 8)
            memory.write(out + 8, 8, 0)
            memory.write(out + 0x10, 8, 1)
            memory.write(out + 0x18, 8, 0)
            memory.write(out + 0x20, 8, 4)
            memory.write(out + 0x28, 8, at)
            memory.write(out + 0x30, 8, 1)

    def on_stamp(self, m):
        self.events.append(("stamp", m.regs[RSI] & 0xFF, m.regs[RDX], m.regs[RCX], m.regs[R8]))
        m.memory.put_bytes(m.regs[RDI], filled("stamp", 32))

    def on_sink(self, m):
        memory = m.memory
        users, frame = m.regs[RSI], m.regs[R8]
        count = memory.read(users + 0x10, 8)
        at = memory.read(users + 8, 8)
        self.events.append(("sink", m.regs[RDI] - STATE_AT, tuple(memory.bytes_at(at + 20 * index, 20).hex() for index in range(count)), memory.read(m.regs[RDX], 8), memory.read(m.regs[RDX] + 8, 4),
                            memory.bytes_at(m.regs[RCX], 32) == filled("stamp", 32), self.text_at(frame), self.text_at(frame + 0x18), self.text_at(frame + 0x30), memory.read(frame + 0x60, 8), memory.read(frame + 0x68, 8),
                            memory.read(frame + 0x70, 8), memory.read(frame + 0x78, 8), memory.read(frame + 0x80, 8), memory.read(frame + 0x48, 8), memory.read(frame + 0x50, 8), memory.read(frame + 0x58, 8)))

    def on_grow_users(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        old = memory.read(vector + 8, 8)
        at = self.allocate(0x50)
        m.memory.copy(at, old, 20)
        memory.write(vector, 8, 4)
        memory.write(vector + 8, 8, at)

    def on_grow_queue(self, m):
        raise Halt("native queue grow")

    def on_grow_list(self, m):
        memory = m.memory
        vector = m.regs[RDI]
        at = self.allocate(0x40)
        memory.write(vector, 8, 4)
        memory.write(vector + 8, 8, at)

    def on_status_drop(self, m):
        self.events.append(("status drop", m.memory.read(m.regs[RDI], 2)))

    def text_at(self, at):
        memory = self.machine.memory
        size = memory.read(at + 0x10, 8)
        return memory.bytes_at(memory.read(at + 8, 8), size).decode() if size else ""

    def on_route(self, m):
        memory = m.memory
        frame = m.regs[RCX]
        self.events.append(("route", self.address(m.regs[RDX]), m.regs[R8] & 0xFF, m.regs[R9] if m.regs[R8] & 0xFF else 0) + self.read_record(frame))
        self.status_out(m, m.regs[RDI], self.fix.result, "route")

    def read_record(self, frame):
        memory = self.machine.memory
        has_sub = memory.read(frame + 0x9C, 1)
        vtable = memory.read(frame + 0x30, 8)
        source = memory.read(frame, 8)
        target = memory.read(frame + 0x10, 8)
        words = (source, memory.read(frame + 8, 8) if source else 0, target, memory.read(frame + 0x18, 8) if target else 0, memory.read(frame + 0x20, 8), memory.read(frame + 0x28, 8), self.address(frame + 0x88), has_sub, self.address(frame + 0x9D) if has_sub else "")
        if vtable:
            ptr, size = memory.read(frame + 0x38, 8), memory.read(frame + 0x40, 8)
            words += (memory.bytes_at(ptr, size).hex(), memory.bytes_at(frame + 0x50, 32).hex(), memory.read(frame + 0x70, 8), memory.read(frame + 0x78, 8), memory.read(frame + 0x80, 4))
        return words

    def on_move(self, m):
        memory = m.memory
        frame = m.regs[RDX]
        self.events.append(("move", memory.read(frame, 8), memory.read(frame + 8, 8) if memory.read(frame, 8) else 0, memory.read(frame + 0x10, 8), memory.read(frame + 0x18, 8) if memory.read(frame + 0x10, 8) else 0, self.text_at(frame + 0x20), self.text_at(frame + 0x38), self.text_at(frame + 0x50),
                            memory.read(frame + 0x68, 8), memory.read(frame + 0x70, 8), memory.read(frame + 0x78, 8), memory.read(frame + 0x80, 8) != 0, self.address(frame + 0xD8), self.address(frame + 0xEC), memory.read(frame + 0x100, 1), m.regs[RCX] & 0xFF, m.regs[R8], memory.read(STATE_AT + 0x58, 8)))
        out = m.regs[RDI]
        status = self.fix.moves.pop(0) if self.fix.moves else STATUS_OK
        self.status_out(m, out, status, "move")
        if status == 0xF6 and self.fix.retry:
            at = self.allocate(16 * len(self.fix.retry))
            for index, (token, amount) in enumerate(self.fix.retry):
                memory.write(at + 16 * index, 8, token)
                memory.write(at + 16 * index + 8, 8, amount)
            memory.write(out + 0x20, 8, len(self.fix.retry))
            memory.write(out + 0x28, 8, at)
            memory.write(out + 0x30, 8, len(self.fix.retry))
        elif status == 0xF6:
            memory.write(out + 0x30, 8, 0)

    # fixtures

    def write_string(self, at, text):
        memory = self.machine.memory
        data = text.encode()
        ptr = self.allocate(max(len(data), 1))
        memory.put_bytes(ptr, data)
        memory.write(at, 8, len(data))
        memory.write(at + 8, 8, ptr)
        memory.write(at + 0x10, 8, len(data))

    def tree(self, layout, rows):
        """One leaf over sorted (key, value) rows. Returns root, height."""
        memory = self.machine.memory
        at = self.allocate(layout.leaf)
        memory.put_bytes(at, filled("node", layout.leaf))
        memory.write(at + layout.parent_at, 8, 0)
        for index, (key, value) in enumerate(rows):
            memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
            if layout.value_size:
                memory.put_bytes(at + layout.value_at + layout.value_size * index, value)
        memory.write(at + layout.count_at, 2, len(rows))
        return at, 0

    def table_hash(self, keys_at, key):
        memory = self.machine.memory
        memory.put_bytes(KEY_AT, key)
        return self.machine.run(HASHER, {RDI: keys_at, RSI: KEY_AT})

    def build_table(self, at, size, rows, keys_at, seed):
        """A 32 bucket table written byte by byte at the hash the real hasher gives; rows are (key, bytes after the key)."""
        memory = self.machine.memory
        buckets = 32
        block = self.allocate(buckets * size + buckets + 16)
        ctrl = block + buckets * size
        memory.put_bytes(block, bytes(buckets * size))
        memory.put_bytes(ctrl, b"\xff" * (buckets + 16))
        memory.write(at, 8, ctrl)
        memory.write(at + 8, 8, buckets - 1)
        memory.write(at + 0x10, 8, 28 - len(rows))
        memory.write(at + 0x18, 8, len(rows))
        memory.write(keys_at, 8, seed[0])
        memory.write(keys_at + 8, 8, seed[1])
        for key, value in rows:
            digest = self.table_hash(keys_at, key)
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
            end = ctrl - index * size
            memory.put_bytes(end - size, key + value)

    def run_at(self, entry, args):
        return self.machine.run(entry, args)


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def status_row(image, tag):
    """Display arm of a status tag: a direct text, a format piece, or a shape this reader leaves unnamed."""
    arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE) + 4 * tag)[0]
    data = code(image, arm, 80)
    at = data.find(b"\x48\x8d\x35", 0, 64)
    if at >= 0 and data[at + 7] == 0xBA:
        text = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        size = struct.unpack_from("<I", data, at + 8)[0]
        return tag, arm, "text", code(image, text, size).decode("ascii")
    at = data.find(b"\x48\x8d\x15", 0, 64)
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


# ---- cases ----

SIZE_TABLE = 0x584B08
SCALE_PAIR = 0x204900


def rodata_table(image, base, count):
    return [struct.unpack_from("<Q", image.blob, image.offset(base) + 8 * index)[0] for index in range(count)]


def hexed(address):
    return "0x" + address.hex()


def recipient_cases():
    rows = []
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def enc(raw):
        value = int.from_bytes(raw, "big")
        text = ""
        while value:
            value, rest = divmod(value, 58)
            text = b58[rest] + text
        return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + text
    items = [("0x", 0), ("0", 0), ("", 0), ("xx", 0), ("0X" + "ab" * 32, 0), ("0x" + "ab" * 32, 0), ("0x" + "AB" * 32, 0), ("0x" + "1" * 63, 0), ("0x1", 0), ("0xdead", 0), ("0x" + "1" * 64 + "1", 0), ("0xzz", 0), ("0x" + "g" * 64, 0), ("0x" + "0" * 64, 0), ("00" + "ab" * 31, 0)]
    for raw in (bytes(range(32)), b"\xff" * 32, bytes(32), bytes(31) + b"\x01", b"\x01" + bytes(31), bytes(range(31)), bytes(range(33)), b"", b"\x00", b"\x7f" * 20):
        items.append((enc(raw), 1))
    items += [("0OIl", 1), ("1" * 32, 1), ("1" * 31, 1), ("1" * 33, 1), ("abc!", 1), ("3yZe7d", 1), ("0x" + "ab" * 32, 1)]
    for index, (text, encoding) in enumerate(items):
        rows.append(Case("recipient", "recipient_%d" % index, Fix(), text=text, encoding=encoding))
    return rows


def wire(label, fix=None, **items):
    base = dict(token="PURR", amount="12300", source="", recipient="0x" + "ab" * 32, data=b"\x01\x02\x03", gas=21000, nonce=0x1234, chain=8453, encoding=0)
    base.update(items)
    return Case("send to evm", label, fix or Fix(), **base)


def wire_cases():
    return [
        wire("wire_plain"), wire("wire_usdc", token="USDC"), wire("wire_native_address", token="HYPE"), wire("wire_native_off_is_plain_address", Fix(native=0), token="HYPE"), wire("wire_from_dex", source="xyz"),
        wire("wire_empty_data", data=b""), wire("wire_data_limit", data=b"\x07" * MAX_DATA), wire("wire_data_over", data=b"\x07" * (MAX_DATA + 1)),
        wire("wire_gas_zero", gas=0), wire("wire_gas_limit", gas=MAX_GAS), wire("wire_gas_over", gas=MAX_GAS + 1), wire("wire_gas_number_edge", gas=MAX_NUMBER - 1), wire("wire_gas_number", gas=MAX_NUMBER), wire("wire_gas_top", gas=MASK[8]),
        wire("wire_token_limit", token="T" * MAX_TEXT), wire("wire_token_over", token="T" * (MAX_TEXT + 1)), wire("wire_unknown_token", token="ZZZ"), wire("wire_spot_off", Fix(spot_off=1)),
        wire("wire_recipient_limit", recipient="0x" + "1" * (MAX_TEXT - 2)), wire("wire_recipient_over", recipient="0x" + "1" * (MAX_TEXT - 1)), wire("wire_recipient_bad", recipient="abc"), wire("wire_recipient_short", recipient="0x12"),
        wire("wire_base58", recipient="1" * 32, encoding=1), wire("wire_base58_bad", recipient="1" * 31, encoding=1), wire("wire_amount_limit", amount="1" * MAX_TEXT, fix=Fix(amount_status=0x13F)), wire("wire_amount_over", amount="1" * (MAX_TEXT + 1)), wire("wire_amount_bad", Fix(amount_status=0x13F)),
        wire("wire_source_over", source="x" * (MAX_TEXT + 1)), wire("wire_source_unknown", source="nope"), wire("wire_route_fails", Fix(result=0x15B)), wire("wire_route_fails_b", Fix(result=0xF6)),
    ]


def asset(kind, label, fix=None, **items):
    base = dict(destination=hexed(OTHER), source="", target="spot", token="PURR", amount="4200", sub="", nonce=0x9876)
    base.update(items)
    return Case(kind, label, fix or Fix(), **base)


def asset_cases():
    rows = []
    for kind, prefix in (("send asset", "asset"), ("agent send", "agent")):
        same = Fix(subs={OTHER: USER})
        rows += [asset(kind, prefix + "_plain", Fix(subs={OTHER: USER})), asset(kind, prefix + "_dex_to_dex", same, source="xyz", target="abc"), asset(kind, prefix + "_with_sub", Fix(subs={SUB: USER, OTHER: USER}), sub=hexed(SUB)),
                 asset(kind, prefix + "_dest_over", same, destination="0x" + "1" * 100), asset(kind, prefix + "_dest_bad", same, destination="0x12"), asset(kind, prefix + "_sub_over", same, sub="0x" + "1" * 100), asset(kind, prefix + "_sub_bad", same, sub="0x12"),
                 asset(kind, prefix + "_token_over", same, token="T" * 101), asset(kind, prefix + "_spot_off", Fix(spot_off=1, subs={OTHER: USER})), asset(kind, prefix + "_unknown_token", same, token="ZZZ"), asset(kind, prefix + "_amount_over", same, amount="1" * 101),
                 asset(kind, prefix + "_amount_bad", Fix(amount_status=0x13F, subs={OTHER: USER})), asset(kind, prefix + "_source_over", same, source="s" * 101), asset(kind, prefix + "_source_unknown", same, source="nope"), asset(kind, prefix + "_target_over", same, target="t" * 101), asset(kind, prefix + "_target_unknown", same, target="nope"),
                 asset(kind, prefix + "_route_fails", Fix(result=0x15B, subs={OTHER: USER}))]
    rows += [asset("send asset", "asset_no_tables"), asset("agent send", "agent_stranger"), asset("agent send", "agent_self", destination=hexed(USER)), asset("agent send", "agent_sibling_sub", Fix(subs={OTHER: PARENT, USER: PARENT})), asset("agent send", "agent_sub_to_stranger", Fix(subs={SUB: USER}), sub=hexed(SUB)),
             asset("agent send", "agent_master_from_sub", Fix(subs={USER: PARENT}), destination=hexed(PARENT)), asset("agent send", "agent_other_master", Fix(subs={OTHER: PARENT}))]
    return rows


def system_asset_cases():
    rows = []
    for label, items, fix in (("plain", {}, None), ("token_edge", dict(token=max(Fix().tokens)), None), ("token_over", dict(token=max(Fix().tokens) + 1), None), ("amount_edge", dict(amount=MAX_NUMBER - 1), None), ("amount_over", dict(amount=MAX_NUMBER), None), ("source_dex", dict(source=(1, 3)), None), ("source_over", dict(source=(1, 4)), None), ("target_dex", dict(target=(1, 3)), None), ("target_over", dict(target=(1, 4)), None), ("both", dict(source=(1, 1), target=(1, 2)), None), ("fails", {}, Fix(result=0xF6))):
        base = dict(source=(0, 0), target=(0, 0), token=1, amount=500, destination=OTHER)
        base.update(items)
        rows.append(Case("system send asset", "system_asset_" + label, fix or Fix(), **base))
    return rows


def route(label, fix=None, **items):
    base = dict(source=(0, 0), target=(0, 0), token=1, amount=5000, destination=OTHER, flag=1, nonce=0x4444)
    base.update(items)
    return Case("route", label, fix or Fix(), **base)


def open_dex(index, **items):
    rows = [dict(state=3, coll=0, lim1=10 ** 12, lim2=2 * 10 ** 12, total=10 ** 9) for _ in range(4)]
    rows[index] = dict(rows[index], **items)
    return rows


def route_cases():
    rows = [route("route_spot"), route("route_no_flag", flag=0), route("route_no_data_amount_zero", amount=0), route("route_self", destination=USER), route("route_self_to_dex", destination=USER, target=(1, 1), token=0), route("route_dex_self_same", destination=USER, source=(1, 1), target=(1, 1), token=0), route("route_dex_self_other", destination=USER, source=(1, 1), target=(1, 2), token=0),
            route("route_source_over", source=(1, 4)), route("route_target_over", target=(1, 4)), route("route_source_edge", source=(1, 3), token=0), route("route_target_edge", target=(1, 3), token=0), route("route_dex_index_zero", source=(1, 0), token=0)]
    vaults = {VAULT: (USER, 1), PARENT: (USER, 0), SUB: (PARENT, 1), THIRD: (OTHER, 1), ALT: (ALT[::-1], 0)}
    rows += [route("route_vault_to_self", Fix(vaults=vaults), sub=VAULT, destination=VAULT, token=0), route("route_vault_other_dest", Fix(vaults=vaults), sub=VAULT, token=0), route("route_vault_token", Fix(vaults=vaults), sub=VAULT, destination=VAULT, token=1), route("route_vault_flag_off", Fix(vaults=vaults), sub=PARENT, destination=PARENT, token=0),
             route("route_vault_chain", Fix(vaults=vaults), sub=SUB, destination=SUB, token=0), route("route_vault_wrong_owner", Fix(vaults=vaults), sub=THIRD, destination=THIRD, token=0), route("route_vault_dead_chain", Fix(vaults=vaults), sub=ALT, destination=ALT, token=0),
             route("route_sub_ok", Fix(subs={SUB: USER}), sub=SUB), route("route_sub_wrong_master", Fix(subs={SUB: OTHER}), sub=SUB), route("route_sub_none", sub=SUB), route("route_sub_miss", Fix(subs={OTHER: USER}), sub=SUB), route("route_sub_self", Fix(subs={SUB: USER}), sub=SUB, destination=SUB)]
    for mode in range(0, 7):
        for b in (0, 1):
            modes = {USER: mode}
            rows += [route("route_mode%d_b%d_spot" % (mode, b), Fix(modes=dict(modes), b5b0=b, b5b1=0), amount=5001), route("route_mode%d_c%d_spot" % (mode, b), Fix(modes=dict(modes), b5b1=b), moves=None),
                     route("route_mode%d_c%d_dex0" % (mode, b), Fix(modes=dict(modes), b5b1=b), source=(1, 0), token=0), route("route_mode%d_c%d_dex1" % (mode, b), Fix(modes=dict(modes), b5b1=b), source=(1, 1), token=0)]
    for mode in range(0, 6):
        rows += [route("route_dest_mode%d_dex1" % mode, Fix(modes={OTHER: mode}), target=(1, 1), token=0), route("route_dest_mode%d_dex0" % mode, Fix(modes={OTHER: mode}), target=(1, 0), token=0), route("route_dest_mode%d_gate" % mode, Fix(modes={OTHER: mode}, b5b1=1), target=(1, 1), token=0)]
    rows += [route("route_odd_spot", amount=5001), route("route_odd_source_coll", source=(1, 1), amount=5001, token=0), route("route_odd_source_other", source=(1, 1), amount=5001, token=1), route("route_odd_target_coll", target=(1, 1), amount=5001, token=0), route("route_odd_target_other", target=(1, 1), amount=5001, token=1),
             route("route_odd_flag_live", Fix(b8f0=1, dexes=open_dex(1, state=1)), source=(1, 1), amount=5001, token=0), route("route_odd_flag_dead", Fix(b8f0=1), source=(1, 1), amount=5001, token=0), route("route_source_coll_miss", source=(1, 1), token=1), route("route_target_coll_miss", target=(1, 1), token=1),
             route("route_flag_live_source", Fix(b8f0=1, dexes=open_dex(1, state=1)), source=(1, 1), token=0), route("route_flag_dead_source", Fix(b8f0=1), source=(1, 1), token=0), route("route_flag_live_target", Fix(b8f0=1, dexes=open_dex(1, state=1)), target=(1, 1), token=0), route("route_flag_dead_target", Fix(b8f0=1), target=(1, 1), token=0),
             route("route_to_system_dex", target=(1, 1), token=0, destination=b"\x20" + bytes(17) + b"\x00\x05"), route("route_to_system_edge", target=(1, 1), token=0, destination=b"\x20" + bytes(17) + b"\x27\x0f"), route("route_past_system", target=(1, 1), token=0, destination=b"\x20" + bytes(17) + b"\x27\x10"), route("route_to_native_system", target=(1, 1), token=0, destination=b"\x22" * 20)]
    limit = open_dex(1, state=1)
    rows += [route("route_cap_under", Fix(dexes=limit), target=(1, 1), token=0, amount=100000), route("route_cap_edge", Fix(dexes=limit), target=(1, 1), token=0, amount=(10 ** 12 - 10 ** 9) * 100), route("route_cap_over_no_margin", Fix(dexes=limit), target=(1, 1), token=0, amount=(10 ** 12 - 10 ** 9 + 1) * 100),
             route("route_cap_margin_passes", Fix(dexes=limit, margin=10 ** 12), target=(1, 1), token=0, amount=(10 ** 12) * 100), route("route_cap_margin_edge", Fix(dexes=limit, margin=10 ** 12), target=(1, 1), token=0, amount=(10 ** 12 + 1) * 100), route("route_cap_second_edge", Fix(dexes=limit, margin=3 * 10 ** 12), target=(1, 1), token=0, amount=(2 * 10 ** 12 - 10 ** 9) * 100),
             route("route_cap_second_over", Fix(dexes=limit, margin=3 * 10 ** 12), target=(1, 1), token=0, amount=(2 * 10 ** 12 - 10 ** 9 + 1) * 100), route("route_cap_total_over", Fix(dexes=open_dex(1, state=1, total=3 * 10 ** 12)), target=(1, 1), token=0, amount=100), route("route_cap_total_over_margin", Fix(dexes=open_dex(1, state=1, total=3 * 10 ** 12), margin=1000), target=(1, 1), token=0, amount=100),
             route("route_cap_negative_total", Fix(dexes=open_dex(1, state=1, total=-5 & MASK[8])), target=(1, 1), token=0, amount=100), route("route_cap_same_dex_skips", Fix(dexes=open_dex(1, state=1, lim1=0)), source=(1, 1), target=(1, 1), token=0), route("route_cap_other_dex", Fix(dexes=open_dex(1, state=1, lim1=0)), source=(1, 2), target=(1, 1), token=0), route("route_cap_dead_skips", Fix(dexes=open_dex(1, state=3, lim1=0)), target=(1, 1), token=0)]
    for mode, name in ((3, "unified"), (4, "portfolio"), (5, "five"), (6, "six")):
        modes = {USER: mode}
        rows += [route("route_%s_move" % name, Fix(modes=dict(modes))), route("route_%s_fail" % name, Fix(modes=dict(modes), moves=[0x15B])), route("route_%s_gate_a" % name, Fix(modes=dict(modes), b5b0=1)), route("route_%s_precheck" % name, Fix(modes=dict(modes), precheck=0xDB)), route("route_%s_after_fails" % name, Fix(modes=dict(modes), after=0x15B)),
                 route("route_%s_insufficient" % name, Fix(modes=dict(modes), moves=[0xF6, 0x186], retry=[(9, 8), (7, 6)])), route("route_%s_retry_two" % name, Fix(modes=dict(modes), moves=[0xF6, 0xF6, 0x186], retry=[(9, 8), (7, 6)])), route("route_%s_retry_fails" % name, Fix(modes=dict(modes), moves=[0xF6, 0xF6, 0xF6], retry=[(9, 8), (7, 6)])),
                 route("route_%s_retry_mutated" % name, Fix(modes=dict(modes), moves=[0xF6, 0x17E], retry=[(9, 8), (7, 6)])), route("route_%s_empty_list" % name, Fix(modes=dict(modes), moves=[0xF6])), route("route_%s_zero_amount" % name, Fix(modes=dict(modes), moves=[0xF6], retry=[(9, 8)]), amount=0), route("route_%s_with_data" % name, Fix(modes=dict(modes)), data=b""), route("route_%s_retry_data" % name, Fix(modes=dict(modes), moves=[0xF6, 0x186], retry=[(9, 8)]), data=b"")]
    return [case for case in rows if not case.items.pop("moves", 1) is None or True]


def move(label, fix=None, **items):
    base = dict(source=(0, 0), target=(0, 0), token=0, amount=5000, hundredth=50, names=("spot", "spot", "T0"), acting=USER, destination=OTHER, flag=1, nonce=0x5555)
    base.update(items)
    return Case("move", label, fix or Fix(), **base)


def move_cases():
    rows = [move("move_spot"), move("move_no_flag", flag=0), move("move_override", Fix(override=1)), move("move_not_stamped", Fix(stamped=0)), move("move_with_data", data=b""), move("move_core_fails", Fix(core=0x15B)), move("move_core_fails_data", Fix(core=0x15B), data=b""), move("move_core_touches", Fix(core=0x15B, touch=True)), move("move_ok_touches", Fix(touch=True)),
            move("move_from_dex", source=(1, 1)), move("move_from_dex_fails", Fix(shifts=[0xF6]), source=(1, 1)), move("move_from_dex_fails_data", Fix(shifts=[0xF6]), source=(1, 1), data=b""), move("move_from_dex_core_fails", Fix(core=0x15B), source=(1, 1)), move("move_from_dex_refund_fails", Fix(core=0x15B, shifts=[STATUS_OK, 0xF6]), source=(1, 1)),
            move("move_to_dex", target=(1, 2)), move("move_to_dex_fails_dropped", Fix(shifts=[0x15F]), target=(1, 2)), move("move_self_to_dex", target=(1, 2), destination=USER), move("move_self_to_dex_fails", Fix(shifts=[0x15F]), target=(1, 2), destination=USER), move("move_self_to_dex_fails_data", Fix(shifts=[0x15F]), target=(1, 2), destination=USER, data=b""),
            move("move_self_dex_to_dex", source=(1, 1), target=(1, 2), destination=USER), move("move_self_dex_refund", Fix(shifts=[STATUS_OK, 0x15F]), source=(1, 1), target=(1, 2), destination=USER), move("move_self_dex_refund_fails", Fix(shifts=[STATUS_OK, 0x15F, 0xF6]), source=(1, 1), target=(1, 2), destination=USER), move("move_self_spot", destination=USER), move("move_self_spot_data", destination=USER, data=b""),
            move("move_token_one", token=1), move("move_token_one_big", Fix(to_usd=USD_CAP + 5), token=1), move("move_token_capped", Fix(to_usd=USD_CAP + 5), token=3), move("move_token_cap_edge", Fix(to_usd=USD_CAP - 1), token=3), move("move_token_native_name", Fix(to_usd=USD_CAP + 5), token=2), move("move_price_zero", Fix(price=0), token=3), move("move_scale_fails", Fix(to_usd=None), token=3), move("move_size_0", Fix(tokens={**Fix().tokens, 3: dict(name="UBTC", sz=0, evm=None)}), token=3), move("move_size_7", Fix(tokens={**Fix().tokens, 3: dict(name="UBTC", sz=7, evm=None)}), token=3)]
    return rows


def sys_case(label, fix=None, **items):
    base = dict(token=3, amount=5000, source=USER, target=OTHER, third=THIRD, gas=21000)
    base.update(items)
    return Case("system", label, fix or Fix(), **base)


def system_cases():
    rows = [sys_case("system_erc20"), sys_case("system_erc20_data", data=b""), sys_case("system_evm_off", Fix(evm_on=0)), sys_case("system_evm_off_data", Fix(evm_on=0), data=b""), sys_case("system_evm_flag_two", Fix(evm_on=2)), sys_case("system_multi_user", Fix(multi=[USER])), sys_case("system_multi_other", Fix(multi=[OTHER, THIRD])), sys_case("system_multi_bigger", Fix(multi=[PARENT])), sys_case("system_multi_data", Fix(multi=[USER]), data=b""),
            sys_case("system_usdc_limit", token=0, amount=SINGLE_LIMIT), sys_case("system_usdc_over", token=0, amount=SINGLE_LIMIT + 1), sys_case("system_erc20_over_is_fine", amount=SINGLE_LIMIT + 1), sys_case("system_token_no_evm", token=8), sys_case("system_token_no_evm_data", token=8, data=b""),
            sys_case("system_native", token=NATIVE_ID), sys_case("system_native_data", token=NATIVE_ID, data=b""), sys_case("system_native_off", Fix(native=0), token=NATIVE_ID), sys_case("system_native_off_erc20", Fix(native=0)), sys_case("system_native_off_erc20_data", Fix(native=0), data=b""),
            sys_case("system_native_queue_edge", Fix(native_len=QUEUE_NATIVE), token=NATIVE_ID), sys_case("system_native_queue_full", Fix(native_len=QUEUE_NATIVE + 1), token=NATIVE_ID), sys_case("system_erc20_queue_edge", Fix(erc20_len=QUEUE_ERC20)), sys_case("system_erc20_queue_full", Fix(erc20_len=QUEUE_ERC20 + 1)), sys_case("system_erc20_queue_full_data", Fix(erc20_len=QUEUE_ERC20 + 1), data=b""),
            sys_case("system_negative_exact", token=4, amount=5000), sys_case("system_negative_rest", token=4, amount=5001), sys_case("system_negative_rest_data", token=4, amount=5001, data=b""), sys_case("system_power_zero", token=5), sys_case("system_power_wide", token=6, amount=10 ** 19), sys_case("system_power_overflow", Fix(tokens={**Fix().tokens, 6: dict(name="WIDE", sz=4, evm=(CONTRACT, 78))}), token=6), sys_case("system_negative_wide", token=7, amount=10 ** 19),
            sys_case("system_gas_state", Fix(gas_state=1)), sys_case("system_gas_fails", Fix(gas_status=0x14D)), sys_case("system_gas_fails_data", Fix(gas_status=0x14D), data=b""), sys_case("system_gas_data_flag", gas=500000, data=b"\x01"), sys_case("system_fee_edge", Fix(gas=FEE_CAP)), sys_case("system_fee_over", Fix(gas=FEE_CAP + 1)), sys_case("system_fee_over_data", Fix(gas=FEE_CAP + 1), data=b""),
            sys_case("system_quote", Fix(quote=4)), sys_case("system_quote_flag", Fix(quote=4, quote_flag=1)), sys_case("system_quote_flag_no_value", Fix(quote_flag=1)), sys_case("system_quote_not_tradable", Fix(quote=4, tradable=False)), sys_case("system_quote_no_price", Fix(quote=4, tradable=False, price=0)), sys_case("system_quote_scale_fails", Fix(quote=4, scale=None)), sys_case("system_quote_sum_over", Fix(quote=4, gas=FEE_CAP - 3, scale=33)),
            sys_case("system_alt_payer", alt=ALT), sys_case("system_no_row", Fix(has_row=False)), sys_case("system_no_row_alt", Fix(has_row=False), alt=ALT), sys_case("system_no_row_not_tradable", Fix(has_row=False, tradable=False)), sys_case("system_no_row_no_price", Fix(has_row=False, price=0)), sys_case("system_no_row_usd_fails", Fix(has_row=False, to_usd=None)), sys_case("system_no_row_shift_fails", Fix(has_row=False, shifts=[0xF6])), sys_case("system_no_row_step_kind_1", Fix(has_row=False, gas_step=(STATUS_OK, 1, 0, 5, 66, 0x77, 0))), sys_case("system_no_row_step_fails", Fix(has_row=False, gas_step=(0x15B,))), sys_case("system_no_row_step_insufficient", Fix(has_row=False, gas_step=(0xF6,))),
            sys_case("system_step_fails", Fix(step=0x1C)), sys_case("system_step_fails_data", Fix(step=0x1C), data=b""), sys_case("system_step_frame", Fix(log_frame=True, quote=4, quote_flag=1)), sys_case("system_native_step_fails", Fix(step=0x1C), token=NATIVE_ID)]
    return rows


SENTINELS = frozenset(("wire_plain", "wire_gas_limit", "wire_gas_over", "wire_data_limit", "wire_data_over", "system_erc20", "system_native", "system_usdc_limit", "system_usdc_over", "route_cap_edge", "route_cap_over_no_margin", "route_cap_second_over", "route_unified_move", "route_portfolio_move", "route_five_retry_two", "move_spot", "move_core_touches", "move_token_capped", "recipient_5", "recipient_15"))


def all_cases():
    return recipient_cases() + wire_cases() + asset_cases() + system_asset_cases() + route_cases() + move_cases() + system_cases()


# ---- rule list: written from the reading, checked against the real run ----

USER = bytes(range(0x10, 0x24))
OTHER = bytes(range(0x40, 0x54))
VAULT = bytes(range(0x60, 0x74))
SUB = bytes(range(0x80, 0x94))
PARENT = bytes(range(0xA0, 0xB4))
THIRD = bytes(range(0xC0, 0xD4))
ALT = bytes(range(0xE0, 0xF4))
CONTRACT = bytes(range(0x20, 0x34))
NATIVE_ID = 0x96
SEED = (0x0706050403020100, 0x0F0E0D0C0B0A0908)
ROW_NAMES = ("", "xyz", "abc", "flx")
TIME_WORD = 0x1122334455667788
TIME_NANOS = 0x0ABCDEF1
DEPTH = 5


class Fix:
    def __init__(self, **items):
        self.user = USER
        self.names = {"USDC": 0, "HYPE": NATIVE_ID, "PURR": 1, "UBTC": 3, "NOPE": 700}
        self.dex_names = {"": (0, 0), "spot": (0, 0), "xyz": (1, 1), "abc": (1, 2), "flx": (1, 3)}
        self.amount_status = STATUS_OK
        self.spot_off = 0
        self.native = 1
        self.modes = {}
        self.vaults = {}
        self.subs = {}
        self.multi = []
        self.b5b0 = 0
        self.b5b1 = 0
        self.b8f0 = 0
        self.dexes = [dict(state=3, coll=0, lim1=10 ** 12, lim2=2 * 10 ** 12, total=10 ** 9) for _ in range(4)]
        self.precheck = STATUS_OK
        self.after = STATUS_OK
        self.margin = 0
        self.moves = []
        self.retry = []
        self.result = STATUS_OK
        self.core = STATUS_OK
        self.touch = False
        self.shifts = []
        self.price = 7
        self.to_usd = 5000
        self.tradable = True
        self.whole = 9
        self.has_row = True
        self.base_fee = 1234
        self.gas_status = STATUS_OK
        self.gas = 77
        self.quote = 0
        self.quote_flag = 0
        self.scale = 33
        self.step = STATUS_OK
        self.gas_step = (STATUS_OK, 2, 1, 5, 66, 0x77, 1)
        self.log_frame = False
        self.evm_on = 1
        self.stamped = 1
        self.override = 0
        self.gas_state = 2
        self.native_len = 0
        self.erc20_len = 0
        self.tokens = {0: dict(name="USDC", sz=2, evm=None), 1: dict(name="PURR", sz=2, evm=None), 2: dict(name="HYPE", sz=3, evm=None), 3: dict(name="UBTC", sz=4, evm=(CONTRACT, 2)), 4: dict(name="NEGA", sz=4, evm=(CONTRACT, -2)), 5: dict(name="ZERO", sz=4, evm=(CONTRACT, 0)), 6: dict(name="WIDE", sz=4, evm=(CONTRACT, 70)), 7: dict(name="BADD", sz=4, evm=(CONTRACT, -40)), 8: dict(name="NONE", sz=4, evm=None), NATIVE_ID: dict(name="HYPE", sz=3, evm=None)}
        self.__dict__.update(items)


class Case:
    def __init__(self, kind, label, fix, **items):
        self.kind, self.label, self.fix = kind, label, fix
        self.items = items
        self.copy = 0


def state_of(harness, fix):
    memory = harness.machine.memory
    memory.put_bytes(STATE_AT, filled("state", STATE_SIZE))
    write = lambda offset, size, word: memory.write(STATE_AT + offset, size, word)
    write(0, 4, fix.stamped)
    write(8, 8, 0x8888)
    write(0x28, 8, 0x2828)
    write(0x50, 8, 0x5050)
    write(0x58, 8, DEPTH)
    write(0x60, 8, TIME_WORD)
    write(0x68, 4, TIME_NANOS)
    write(0x78, 1, fix.override)
    write(0x80, 4, fix.native)
    write(0x88, 8, NATIVE_ID)
    count = max(fix.tokens) + 1
    write(0x210, 8, TOKENS_AT)
    write(0x218, 8, count)
    memory.put_bytes(TOKENS_AT, filled("tokens", min(count, 0x100) * TOKEN_SIZE))
    for token, row in fix.tokens.items():
        at = TOKENS_AT + token * TOKEN_SIZE
        harness.write_string(at + 0x30, row["name"])
        memory.write(at + 0x49, 1, row["sz"])
        memory.write(at + 0xBC, 1, 1 if row["evm"] else 0)
        if row["evm"]:
            memory.put_bytes(at + 0xBD, row["evm"][0])
            memory.write(at + 0xD1, 1, row["evm"][1] & 0xFF)
    write(0x5B0, 1, fix.b5b0)
    write(0x5B1, 1, fix.b5b1)
    write(0x5C0, 8, DEXES_AT)
    write(0x5C8, 8, len(fix.dexes))
    memory.put_bytes(DEXES_AT, filled("dexes", DEX_SIZE * len(fix.dexes)))
    for index, row in enumerate(fix.dexes):
        at = DEXES_AT + DEX_SIZE * index
        name = harness.allocate(0x18)
        harness.write_string(name, ROW_NAMES[index])
        memory.write(at + 0x208, 8, name)
        memory.write(at + 0x230, 1, row["state"])
        memory.write(at + 0x50, 8, row["coll"])
        memory.write(at + 0x1C0, 8, row["lim1"])
        memory.write(at + 0x1C8, 8, row["lim2"])
        memory.write(at + 0x238, 8, row["total"])
    write(0x7D0, 8, 0x700)
    write(0x7D8, 8, 0x800)
    memory.put_bytes(COUNTER_AT, bytes(0x80))
    root, height = harness.tree(VAULT_NODE, [(key, vault_value(*value)) for key, value in sorted(fix.vaults.items())]) if fix.vaults else (0, 0)
    write(0x8D0, 8, root)
    write(0x8D8, 8, height)
    write(0x8F0, 1, fix.b8f0)
    write(0x8F2, 1, 3)
    write(0x2A30, 4, fix.gas_state)
    write(0x3100, 8, 8)
    write(0x3108, 8, QUEUE_AT)
    write(0x3110, 8, fix.native_len)
    write(0x3118, 8, fix.erc20_len + 2)
    write(0x3120, 8, QUEUE_AT + 0x400)
    write(0x3128, 8, fix.erc20_len)
    write(0x3828, 8, 0)
    if fix.subs:
        harness.build_table(STATE_AT + 0x3810, 0x28, sorted(fix.subs.items()), STATE_AT + 0x3830, SEED)
    root, height = harness.tree(MULTI_NODE, [(key, bytes(0x20)) for key in sorted(fix.multi)]) if fix.multi else (0, 0)
    write(0x39E8, 8, root)
    write(0x39F0, 8, height)
    write(0x3AC8, 1, fix.spot_off)
    write(0x3AC9, 1, fix.evm_on)
    memory.write(VTABLE_AT, 8, FAKE_CLONE)
    memory.write(VTABLE_AT + 0x20, 8, FAKE_DROP)
    memory.put_bytes(USER_AT, fix.user)


def vault_value(parent, flag):
    value = bytearray(filled("vault value", 0xB0))
    value[0x98:0xAC] = parent
    value[0xAF] = flag
    return bytes(value)


def system_address(fix, token):
    if fix.native == 1 and token == NATIVE_ID:
        return b"\x22" * 20
    return b"\x20" + bytes(11) + struct.pack(">Q", token)


def system_range(address):
    return address == b"\x22" * 20 or (address[0] == 0x20 and address[1:18] == bytes(17) and int.from_bytes(address[18:], "big") < 0x2710)


def recipient_rule(text, encoding):
    """Status and the 32 bytes."""
    if encoding == 0:
        if len(text) < 2 or text[:2] != "0x" or len(text) - 2 > 64:
            return 0xB6, None
        body = text[2:].rjust(64, "0")
        try:
            return STATUS_OK, bytes.fromhex(body)
        except ValueError:
            return 0xB6, None
    status, raw = base58_rule(text)
    if status != STATUS_OK or len(raw) != 32:
        return 0xB6, None
    return STATUS_OK, raw


def base58_rule(text):
    value = 0
    for char in text:
        if char not in BASE58_TEXT:
            return 0xB6, None
        value = value * 58 + BASE58_TEXT.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return STATUS_OK, bytes(len(text) - len(text.lstrip("1"))) + raw


def parse_address(text):
    if len(text) != 42 or text[:2] != "0x":
        return None
    try:
        return bytes.fromhex(text[2:])
    except ValueError:
        return None


def parse_rule(fix, events, destination, source, target, token, amount, sub):
    """The six text fields of 0x272b950. Returns status, source, target, token id, amount."""
    if len(sub) > MAX_TEXT:
        return (0x143,)
    if sub and parse_address(sub) is None:
        return (0xB6,)
    if len(destination) > MAX_TEXT:
        return (0x143,)
    if parse_address(destination) is None:
        return (0xB6,)
    if len(token) > MAX_TEXT:
        return (0x143,)
    if fix.spot_off:
        return (0xF9,)
    events.append(("token", token, 0x90))
    if token not in fix.names:
        return (0xF8,)
    if len(amount) > MAX_TEXT:
        return (0x143,)
    found = fix.names[token]
    events.append(("amount", 0x90, found, amount))
    if fix.amount_status != STATUS_OK:
        return (fix.amount_status,)
    if len(source) > MAX_TEXT:
        return (0x143,)
    events.append(("dex", 0x5B8, source))
    if source not in fix.dex_names:
        return (0x141,)
    if len(target) > MAX_TEXT:
        return (0x143,)
    events.append(("dex", 0x5B8, target))
    if target not in fix.dex_names:
        return (0x141,)
    return (STATUS_OK, fix.dex_names[source], fix.dex_names[target], found, int(amount))


def record_words(parsed, destination, sub, data=()):
    source, target, token, amount = parsed[1:]
    words = (source[0], source[1] if source[0] else 0, target[0], target[1] if target[0] else 0, token, amount, destination.hex(), 1 if sub else 0, sub.hex() if sub else "")
    return words + data


def wire_rule(fix, item):
    events = [("data clone", len(item["data"]))]
    finish = lambda status: (status, events + [("data drop",)])
    if len(item["token"]) > MAX_TEXT:
        return finish(0x143)
    if fix.spot_off:
        return finish(0xF9)
    events.append(("token", item["token"], 0x90))
    if item["token"] not in fix.names:
        return finish(0xF8)
    token = fix.names[item["token"]]
    if len(item["recipient"]) > MAX_TEXT:
        return finish(0x143)
    status, recipient = recipient_rule(item["recipient"], item["encoding"])
    if item["encoding"]:
        events.append(("base58", ALPHABET_AT, 2))
    if status != STATUS_OK:
        return finish(status)
    if item["gas"] >= MAX_NUMBER:
        return finish(0x13F)
    if item["gas"] > MAX_GAS:
        return finish(0x149)
    if len(item["data"]) > MAX_DATA:
        return finish(0x142)
    events.append(("data clone", len(item["data"])))
    destination = system_address(fix, token)
    parsed = parse_rule(fix, events, "0x" + destination.hex(), item["source"], "spot", item["token"], item["amount"], "")
    if parsed[0] != STATUS_OK:
        events.append(("data drop",))
        return finish(parsed[0])
    data = (item["data"].hex(), recipient.hex(), item["gas"], item["nonce"], item["chain"])
    events.append(("route", fix.user.hex(), 1, item["nonce"]) + record_words(parsed, destination, b"", data))
    return finish(fix.result)


def asset_rule(fix, item, agent):
    events = []
    parsed = parse_rule(fix, events, item["destination"], item["source"], item["target"], item["token"], item["amount"], item["sub"])
    if parsed[0] != STATUS_OK:
        return parsed[0], events
    destination = parse_address(item["destination"])
    sub = parse_address(item["sub"]) if item["sub"] else b""
    if agent:
        left = sub or fix.user
        if fix.subs.get(left, left) != fix.subs.get(destination, destination):
            return 0x183, events
    events.append(("route", fix.user.hex(), 1, item["nonce"]) + record_words(parsed, destination, sub))
    return fix.result, events


def system_asset_rule(fix, item):
    if item["token"] >= max(fix.tokens) + 1:
        return 0xEA, []
    if item["amount"] > MAX_NUMBER - 1:
        return 0x13F, []
    for klass, index in (item["source"], item["target"]):
        if klass and index >= len(fix.dexes):
            return 0x141, []
    parsed = (0, item["source"], item["target"], item["token"], item["amount"])
    return fix.result, [("route", fix.user.hex(), 0, 0) + record_words(parsed, item["destination"], b"")]


def route_rule(fix, item):
    """Status, payload, events of 0x2729c30 with the move stubbed."""
    events = []
    user, destination = fix.user, item["destination"]
    source, target = item["source"], item["target"]
    token, amount = item["token"], item["amount"]
    acting = user
    sub = item.get("sub")
    if sub:
        if sub in fix.vaults:
            key = sub
            seen = 0
            while True:
                if key not in fix.vaults:
                    return 0x7C, None, events
                parent, flag = fix.vaults[key]
                if key == sub:
                    own = flag
                if parent == user:
                    break
                key = parent
                seen += 1
                if seen > 8:
                    raise EvidenceError("vault chain")
            if destination != sub or token != 0 or not own:
                return 0x15, None, events
        elif fix.subs.get(sub) != user:
            return 0xDC, None, events
        acting = sub
    mode = fix.modes.get(destination, 0)
    events.append(("user row", destination.hex()))
    if mode <= 3 and not fix.b5b1 and target[0] & 1 and mode == 2 and target[1] != 0:
        return 0x169, None, events
    acting_mode = fix.modes.get(acting, 0)
    events.append(("user row", acting.hex()))
    gate = fix.b5b0 if acting_mode >= 4 else fix.b5b1
    if gate:
        route = 1
    elif source[0] == 0 or acting_mode < 2:
        route = acting_mode
    elif acting_mode in (3, 4):
        return 0x16E, None, events
    elif source[1] == 0:
        route = 2
    else:
        return 0x169, None, events
    if (source[0] & MASK[4]) == (target[0] & MASK[4]) and destination == acting and (source[0] == 0 or source[1] == target[1]):
        return 0x15B, None, events
    for klass, index in (source, target):
        if klass and index >= len(fix.dexes):
            return 0x141, None, events
    events.append(("token name", token, 0x90))
    hundredth = amount // 100
    def row_gate(index):
        row = fix.dexes[index]
        if fix.b8f0 and row["state"] != 3:
            return 0x15B
        return None
    if amount % 100:
        if source[0] or target[0]:
            index = source[1] if source[0] & 0xFF else target[1]
            row = fix.dexes[index]
            if fix.b8f0 and row["state"] != 3:
                return 0x15B, None, events
            return (0x15B if row["coll"] == token else 0xEA), None, events
    else:
        if source[0] & 0xFF:
            if row_gate(source[1]):
                return 0x15B, None, events
            if fix.dexes[source[1]]["coll"] != token:
                return 0xEA, None, events
        if target[0] & 0xFF:
            if row_gate(target[1]):
                return 0x15B, None, events
            if fix.dexes[target[1]]["coll"] != token:
                return 0xEA, None, events
            if system_range(destination):
                return 0x15B, None, events
            if not (source[0] and source[1] == target[1]) and fix.dexes[target[1]]["state"] != 3:
                row = fix.dexes[target[1]]
                base = DEX_SIZE * target[1]
                events.append(("margin row", base + 0xF8, destination.hex()))
                events.append(("margin sum", base + 0x60, base))
                margin = fix.margin
                total = row["total"] - (1 << 64) if row["total"] >> 63 else row["total"]
                total = max(total, 0)
                reached = hundredth + total
                if reached > row["lim1"]:
                    first = (row["lim1"] - total) / 1e6 if row["lim1"] > total else 0.0
                    if margin == 0:
                        return 0x15F, first, events
                    if not (hundredth <= margin and reached <= row["lim2"]):
                        second = (row["lim2"] - total) / 1e6 if row["lim2"] > total else 0.0
                        third = margin / 1e6
                        return 0x15F, max(first, min(second, third)), events
    names = (ROW_NAMES[source[1]] if source[0] and fix.dexes[source[1]]["state"] != 3 else ("" if source[0] else "spot"), ROW_NAMES[target[1]] if target[0] and fix.dexes[target[1]]["state"] != 3 else ("" if target[0] else "spot"), "T%d" % token)
    flag, nonce = item["flag"], item["nonce"]
    has_data = item.get("data") is not None

    def move(depth, keep_flag=flag, keep_nonce=nonce):
        events.append(("move", source[0], source[1] if source[0] else 0, target[0], target[1] if target[0] else 0) + names + (token, amount, hundredth, has_data, acting.hex(), destination.hex(), route, keep_flag & 0xFF, keep_nonce, depth))
        return fix.moves.pop(0) if fix.moves else STATUS_OK

    def active(mode_byte):
        if mode_byte > 3:
            return not fix.b5b0 & 1
        return mode_byte == 3 and not fix.b5b1 & 1

    bookkeeping = lambda: None
    moves_left = fix.moves
    if route < 3:
        status = move(DEPTH)
        return status, None, events
    events.append(("user row", acting.hex()))
    mode_byte = fix.modes.get(acting, 0)
    if route == 3:
        if not active(mode_byte):
            status = move(DEPTH + 1)
            return status, None, events
        events.append(("precheck", acting.hex()))
        if fix.precheck != STATUS_OK:
            return fix.precheck, None, events
        events.append(("before", acting.hex(), token, 0, token, 4, 0, int(mode_byte == 4)))
        status = move(DEPTH + 1)
        if mode_byte == 4:
            events.append(("after flag", acting.hex(), token, 0, token))
        else:
            events.append(("after", acting.hex(), token, 0, token))
            if fix.after != STATUS_OK:
                events.append(("status drop", fix.after))
        return status, None, events
    if not active(mode_byte):
        if has_data:
            events.append(("data clone", 0))
        status = move(DEPTH + 1)
    else:
        events.append(("precheck", acting.hex()))
        if fix.precheck != STATUS_OK:
            status = fix.precheck
        else:
            events.append(("before", acting.hex(), token, 0, token, 0, 0, int(mode_byte == 4)))
            if has_data:
                events.append(("data clone", 0))
            status = move(DEPTH + 1)
            if mode_byte == 4:
                events.append(("after flag", acting.hex(), token, 0, token))
            else:
                events.append(("after", acting.hex(), token, 0, token))
                if fix.after != STATUS_OK:
                    events.append(("status drop", fix.after))
    first = status
    if amount and status == 0xF6:
        for entry in fix.retry:
            mode_byte = fix.modes.get(acting, 0)
            events.append(("user row", acting.hex()))
            on = (mode_byte > 3 and not fix.b5b0 & 1) or (mode_byte == 3 and not fix.b5b1 & 1)
            if on:
                events.append(("counters", 0x770, acting.hex()))
                events.append(("before", acting.hex(), token, 0, token, 1, entry[0], int(mode_byte >= 4)))
            if has_data:
                events.append(("data clone", 0))
            again = move(DEPTH + 1)
            if on:
                if mode_byte >= 4:
                    events.append(("after flag", acting.hex(), token, 0, token))
                else:
                    events.append(("counters", 0x770, acting.hex()))
            if again == 0x17E:
                events.append(("status drop", again))
                break
            if again == STATUS_OK:
                events.append(("status drop", first))
                first = STATUS_OK
                break
            events.append(("status drop", again))
    if has_data:
        events.append(("data drop",))
    return first, None, events


def move_rule(fix, item):
    """Status and events of 0x272bd60 with the shift and the core stubbed."""
    acting, destination = item["acting"], item["destination"]
    source, target = item["source"], item["target"]
    token, amount, hundredth = item["token"], item["amount"], item["hundredth"]
    has_data = item.get("data") is not None
    events = [("balance row", 0x80, acting.hex())]
    if has_data:
        events.append(("data clone", 0))
    status = STATUS_OK
    differ = acting != destination
    shifts = list(fix.shifts)
    held = False
    done = None

    def shift(index, address, sign):
        events.append(("shift", index, address.hex(), sign, hundredth))
        return shifts.pop(0) if shifts else STATUS_OK
    first = shift(source[1], acting, 1) if source[0] == 1 else STATUS_OK
    fee = (0, 1, 0, bytes(16))
    if first != STATUS_OK:
        status = first
        if has_data:
            events.append(("data drop",))
        done = True
    if not done and differ:
        events.append(("core", 0, 4, token, amount, has_data, acting.hex(), destination.hex(), 0))
        if fix.core != STATUS_OK:
            status = fix.core
            if source[0]:
                back = shift(source[1], acting, 0)
                if back != STATUS_OK:
                    events.append(("status drop", back))
            done = True
        else:
            fee = (0, 1, 0, b"fee word sixteen")
    elif not done:
        held = True
    if not done and target[0]:
        put = shift(target[1], destination, 0)
        if put != STATUS_OK:
            if differ:
                events.append(("status drop", put))
            else:
                if source[0]:
                    back = shift(source[1], acting, 0)
                    if back != STATUS_OK:
                        events.append(("status drop", back))
                status = put
                if held and has_data:
                    events.append(("data drop",))
                done = True
    if not done:
        if token == 0:
            usd = amount // 100
        else:
            events.append(("price", 0x80, token, 0x3380))
            usd = 0
            if fix.price:
                events.append(("to usd", amount, token, fix.price, 0, 0x90))
                usd = fix.to_usd or 0
                if token != 1 and fix.tokens[token]["name"] != "HYPE":
                    usd = min(usd, USD_CAP)
        size = fix.tokens[token]["sz"]
        scale = item["scales"]
        word = item["nonce"] if item["flag"] & 1 else 0
        if fix.override:
            word = 0x5050
        if fix.stamped == 1:
            events.append(("stamp", 3, 0x2828, 0x8888, 0))
        users = (acting.hex(), destination.hex()) if differ else (acting.hex(),)
        pair = (float(amount) / scale[size], float(usd) / scale["high"])
        events.append(("sink", 0x8F3, users, TIME_WORD, TIME_NANOS, fix.stamped == 1, item["names"][0], item["names"][1], item["names"][2], to_bits(pair[0]), to_bits(pair[1]),
                       struct.unpack("<Q", fee[3][:8])[0], struct.unpack("<Q", fee[3][8:])[0], word, fee[0], fee[1], fee[2]))
        status = STATUS_OK
        if held and has_data:
            events.append(("data drop",))
    events.append(("balance row", 0x80, acting.hex()))
    if fix.touch and status != STATUS_OK:
        events.append(("status drop", status))
        status = 0x17E
    if has_data:
        events.append(("data drop",))
    return status, events


def system_rule(fix, item):
    """Status, payload and events of 0x2715320."""
    events = []
    token, amount = item["token"], item["amount"]
    data = item.get("data")
    drop = [("data drop",)] if data is not None else []
    if not fix.evm_on == 1:
        return 0x14A, drop
    if item["source"] in fix.multi:
        return 0x14E, drop
    if token == 0 and amount > SINGLE_LIMIT:
        return 0x28, drop
    native = fix.native & 0xFF and token == NATIVE_ID
    if native:
        if data is not None:
            return 0x148, drop
        power = 10
    else:
        row = fix.tokens[token]
        if not row["evm"]:
            return 0x14A, drop
        events.append(("status drop", 0x14A))
        power = row["evm"][1]
    if power < 0:
        divisor = 10 ** -power
        if -power >= 32 or amount % divisor:
            return 0xBA, events + drop
        wei = amount // divisor
    else:
        if power >= 78 or amount * 10 ** power >= 1 << 256 or 10 ** power >= 1 << 256:
            return 0xBA, events + drop
        wei = amount * 10 ** power
    source, target = item["source"], item["target"]
    tag = 0 if native else 1
    if not fix.native & 0xFF:
        return 0xFB, events + drop
    events.append(("status drop", 0xFB))
    native_id = NATIVE_ID
    if tag == 0 and fix.native_len > QUEUE_NATIVE:
        return 0x14C, events
    if tag == 1 and fix.erc20_len > QUEUE_ERC20:
        return 0x14C, events + drop
    has = int(data is not None)
    use_alt = item.get("alt")
    debit = None
    late_flag = 0
    if tag == 1:
        price = GAS_FLOOR
        if fix.gas_state != 2:
            events.append(("base fee", 0x2A30))
            price = fix.base_fee
        events.append(("gas fee", price, native_id, has, item.get("gas", 0)))
        if fix.gas_status != STATUS_OK:
            return fix.gas_status, events + drop
        fee = fix.gas
        events.append(("quote", source.hex(), item["third"].hex()))
        quote, flag = fix.quote, fix.quote_flag & 1
        if quote:
            events.append(("price", 0x80, native_id, 0x3380))
            events.append(("tradable", 0x90, native_id))
            if fix.tradable:
                events.append(("one whole", 0x90, native_id))
                value = fix.whole
            else:
                if not fix.price:
                    return 0x160, events + drop
                value = fix.price
            events.append(("scale", quote * 100, native_id, value, 0, 0x90))
            if fix.scale is None:
                return 0x13F, events + drop
            fee += fix.scale
        if fee > FEE_CAP:
            return 0x14D, events + drop
        payer = use_alt if use_alt else source
        events.append(("has row", 0x80, payer.hex(), native_id))
        if fix.has_row:
            debit = (1, native_id, fee, quote, flag)
        else:
            events.append(("tradable", 0x90, token))
            if not fix.tradable:
                return 0xF6, events + drop
            events.append(("price", 0x80, native_id, 0x3380))
            if not fix.price:
                return 0x160, events + drop
            events.append(("to usd", fee, native_id, fix.price, 0, 0x90))
            if fix.to_usd is None:
                return 0x13F, events + drop
            events.append(("gas step", payer.hex(), fix.to_usd, flag, amount if payer == source else 0, token))
            if fix.gas_step[0] != STATUS_OK:
                return fix.gas_step[0], events + drop
            kind, _, step_token, step_amount, extra, last = fix.gas_step[1:]
            debit = (kind, step_token, step_amount, extra, last)
    if debit and debit[0] >= 2:
        events.append(("shift", debit[1], source.hex(), 1, debit[2]))
        status = fix.shifts[0] if fix.shifts else STATUS_OK
        if status != STATUS_OK:
            return status, events + drop
    last = debit[4] & 1 if debit else 0
    step = ("recipient step", (use_alt or source).hex(), target.hex(), last)
    if fix.log_frame and debit:
        step += (debit[0], debit[1], debit[2], debit[3])
    events.append(step)
    if fix.step != STATUS_OK:
        return fix.step, events + drop
    return STATUS_OK, events


def setup(harness, case):
    if not hasattr(case, "plan"):
        case.plan = (list(case.fix.moves), list(case.fix.shifts))
    case.fix.moves, case.fix.shifts = list(case.plan[0]), list(case.plan[1])
    harness.reset()
    harness.fix = case.fix
    harness.use(KIND_STUBS[case.kind])
    state_of(harness, case.fix)


KIND_STUBS = {"recipient": (ROUTE, MOVE), "send to evm": (ROUTE, MOVE), "send asset": (ROUTE, MOVE), "agent send": (ROUTE, MOVE), "system send asset": (ROUTE, MOVE), "route": (MOVE,), "move": (ROUTE,), "system": (ROUTE, MOVE)}


def tell(harness, expected, status):
    got = harness.events
    if status[0] != status[1]:
        return "status %#x, rule %#x; events %r" % (status[0], status[1], got[-3:])
    if got != expected:
        for index, (left, right) in enumerate(zip(got, expected)):
            if left != right:
                return "event %d: %r, rule %r" % (index, left, right)
        return "event count %d, rule %d: %r / %r" % (len(got), len(expected), got[-2:], expected[-2:])
    return ""


def compare_recipient(harness, case):
    item = case.items
    memory = harness.machine.memory
    data = item["text"].encode()
    at = harness.allocate(max(len(data), 1))
    memory.put_bytes(at, data)
    harness.machine.run(RECIPIENT, {RDI: OUT_AT, RSI: at, RDX: len(data), RCX: item["encoding"]})
    status, raw = recipient_rule(item["text"], item["encoding"])
    got = memory.read(OUT_AT, 2)
    if item["encoding"] and harness.events != [("base58", ALPHABET_AT, 2)]:
        return "base58 arguments %r" % harness.events
    if got != status:
        return "status %#x, rule %#x" % (got, status)
    if raw is not None and memory.bytes_at(OUT_AT + 2, 32) != raw:
        return "bytes differ"
    harness.tally["recipient ok" if raw is not None else "recipient refused"] += 1
    return ""


def compare_wire(harness, case):
    item = case.items
    memory = harness.machine.memory
    fix = case.fix
    for offset, key in ((0, "token"), (0x18, "amount"), (0x30, "source"), (0x48, "recipient")):
        harness.write_string(ACTION_AT + offset, item[key])
    memory.put_bytes(BYTES_AT, item["data"])
    memory.write(ACTION_AT + 0x60, 8, VTABLE_AT)
    memory.write(ACTION_AT + 0x68, 8, BYTES_AT)
    memory.write(ACTION_AT + 0x70, 8, len(item["data"]))
    memory.write(ACTION_AT + 0x78, 8, 0x77)
    memory.put_bytes(ACTION_AT + 0x80, filled("wire word", 32))
    memory.write(ACTION_AT + 0xA0, 8, item["gas"])
    memory.write(ACTION_AT + 0xA8, 8, item["nonce"])
    memory.write(ACTION_AT + 0xB0, 4, item["chain"])
    memory.write(ACTION_AT + 0xB4, 1, item["encoding"])
    memory.write(ACTION_AT + 0xB5, 1, 1)
    harness.machine.run(SEND_EVM, {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: ACTION_AT})
    status, events = wire_rule(fix, item)
    got = memory.read(OUT_AT, 2)
    harness.tally["status %#x" % status] += 1
    return tell(harness, events, (got, status))


def compare_asset(harness, case):
    item = case.items
    memory = harness.machine.memory
    fix = case.fix
    for offset, key in ((0, "destination"), (0x18, "source"), (0x30, "target"), (0x48, "token"), (0x60, "amount"), (0x78, "sub")):
        harness.write_string(ACTION_AT + offset, item[key])
    agent = case.kind == "agent send"
    memory.write(ACTION_AT + (0x90 if agent else 0xB0), 8, item["nonce"])
    if agent:
        harness.machine.run(AGENT_SEND, {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: ACTION_AT})
        got = memory.read(OUT_AT, 2)
    else:
        harness.machine.run(SEND_ASSET, {RDI: OUT_AT, RSI: ACTION_AT, RDX: USER_AT, RCX: STATE_AT})
        tag = memory.read(OUT_AT, 1)
        got = STATUS_OK if tag == ACK else memory.read(OUT_AT + 8, 2)
    status, events = asset_rule(fix, item, agent)
    harness.tally["status %#x" % status] += 1
    if not agent and status == fix.result and status != STATUS_OK and got == status and memory.bytes_at(OUT_AT + 10, 0x5E) != filled("route", 0x60)[2:]:
        return "carried words differ"
    return tell(harness, events, (got, status))


def compare_system_asset(harness, case):
    item = case.items
    memory = harness.machine.memory
    fix = case.fix
    memory.put_bytes(RECORD_AT, filled("system asset", 0xB8))
    for offset, word in ((0, item["source"][0]), (8, item["source"][1]), (0x10, item["target"][0]), (0x18, item["target"][1]), (0x20, item["token"]), (0x28, item["amount"]), (0x30, 0)):
        memory.write(RECORD_AT + offset, 8, word)
    memory.put_bytes(RECORD_AT + 0x30, item["destination"])
    memory.write(RECORD_AT + 0x44, 1, 0)
    harness.machine.run(SYSTEM_SEND_ASSET, {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: RECORD_AT})
    status, events = system_asset_rule(fix, item)
    got = memory.read(OUT_AT, 2)
    harness.tally["status %#x" % status] += 1
    return tell(harness, events, (got, status))


def write_route(harness, item):
    memory = harness.machine.memory
    memory.put_bytes(RECORD_AT, filled("route record", 0xB8))
    for offset, word in ((0, item["source"][0]), (8, item["source"][1]), (0x10, item["target"][0]), (0x18, item["target"][1]), (0x20, item["token"]), (0x28, item["amount"])):
        memory.write(RECORD_AT + offset, 8, word)
    if item.get("data") is None:
        memory.write(RECORD_AT + 0x30, 8, 0)
    else:
        memory.write(RECORD_AT + 0x30, 8, VTABLE_AT)
        memory.write(RECORD_AT + 0x38, 8, BYTES_AT)
        memory.write(RECORD_AT + 0x40, 8, 0)
    memory.put_bytes(RECORD_AT + 0x88, item["destination"])
    memory.write(RECORD_AT + 0x9C, 1, 1 if item.get("sub") else 0)
    if item.get("sub"):
        memory.put_bytes(RECORD_AT + 0x9D, item["sub"])


def compare_route(harness, case):
    item = case.items
    memory = harness.machine.memory
    fix = case.fix
    write_route(harness, item)
    plan = list(fix.moves)
    harness.machine.run(ROUTE, {RDI: OUT_AT, RSI: STATE_AT, RDX: USER_AT, RCX: RECORD_AT, R8: item["flag"], R9: item["nonce"]})
    fix.moves = plan
    status, payload, events = route_rule(fix, item)
    fix.moves = list(plan)
    got = memory.read(OUT_AT, 2)
    harness.tally["status %#x" % status] += 1
    if payload is not None and got == status:
        word = memory.read(OUT_AT + 8, 8)
        if word != to_bits(payload):
            return "payload %#x, rule %r" % (word, payload)
    if memory.read(STATE_AT + 0x58, 8) != DEPTH:
        return "depth word changed"
    if status not in (STATUS_OK, 0xF6) and got == status and events and events[-1][0] == "move" and memory.bytes_at(OUT_AT + 2, 0x5E) != filled("move", 0x60)[2:]:
        return "carried words differ"
    return tell(harness, events, (got, status))


def compare_move(harness, case):
    item = dict(case.items)
    memory = harness.machine.memory
    fix = case.fix
    memory.put_bytes(BOOK_AT, filled("book", 0x400))
    node = BOOK_AT + 0x100
    memory.put_bytes(node, filled("balance node", 0x1C0))
    memory.write(node + 8, 8, item["token"])
    memory.write(node + 0x60, 8, 0x1000)
    memory.write(node + 0x16A, 2, 1)
    memory.write(BOOK_AT + 0x10, 8, node)
    memory.write(BOOK_AT + 0x18, 8, 0)
    frame = RECORD_AT
    memory.put_bytes(frame, filled("move record", 0x108))
    for offset, word in ((0, item["source"][0]), (8, item["source"][1]), (0x10, item["target"][0]), (0x18, item["target"][1]), (0x68, item["token"]), (0x70, item["amount"]), (0x78, item["hundredth"])):
        memory.write(frame + offset, 8, word)
    for offset, text in zip((0x20, 0x38, 0x50), item["names"]):
        harness.write_string(frame + offset, text)
    if item.get("data") is None:
        memory.write(frame + 0x80, 8, 0)
    else:
        memory.write(frame + 0x80, 8, VTABLE_AT)
        memory.write(frame + 0x88, 8, BYTES_AT)
        memory.write(frame + 0x90, 8, 0)
    memory.put_bytes(frame + 0xD8, item["acting"])
    memory.put_bytes(frame + 0xEC, item["destination"])
    memory.write(frame + 0x100, 1, 1)
    table = rodata_table(harness.image, SIZE_TABLE, 8)
    scales = {index: to_float(word) for index, word in enumerate(table)}
    scales["high"] = to_float(struct.unpack_from("<Q", harness.image.blob, harness.image.offset(SCALE_PAIR) + 8)[0])
    item["scales"] = scales
    plan = list(fix.shifts)
    harness.machine.run(MOVE, {RDI: OUT_AT, RSI: STATE_AT, RDX: frame, RCX: item["flag"], R8: item["nonce"]})
    fix.shifts = plan
    status, events = move_rule(fix, item)
    fix.shifts = list(plan)
    got = memory.read(OUT_AT, 2)
    harness.tally["status %#x" % status] += 1
    if got == status and status == fix.core and status != STATUS_OK and memory.bytes_at(OUT_AT + 2, 0x5E) != filled("core", 0x60)[2:]:
        return "carried words differ"
    if got == status and status != STATUS_OK and status != fix.core and status != 0x17E and memory.bytes_at(OUT_AT + 2, 0x5E) != filled("shift", 0x60)[2:]:
        return "carried words differ"
    return tell(harness, events, (got, status))


def compare_system(harness, case):
    item = case.items
    memory = harness.machine.memory
    fix = case.fix
    frame = RECORD_AT
    memory.put_bytes(frame, filled("system record", 0xC0))
    memory.write(frame, 8, item["token"])
    memory.write(frame + 8, 8, item["amount"])
    memory.write(frame + 0x50, 8, item.get("gas", 0))
    if item.get("data") is None:
        memory.write(frame + 0x10, 8, 0)
    else:
        memory.write(frame + 0x10, 8, VTABLE_AT)
        memory.write(frame + 0x18, 8, BYTES_AT)
        memory.write(frame + 0x20, 8, len(item["data"]))
    memory.put_bytes(frame + 0x68, item["source"])
    memory.put_bytes(frame + 0x7C, item["target"])
    memory.put_bytes(frame + 0x90, item["third"])
    memory.write(frame + 0xA4, 1, 1 if item.get("alt") else 0)
    memory.put_bytes(frame + 0xA5, item.get("alt") or ALT)
    plan = list(fix.shifts)
    harness.machine.run(SYSTEM, {RDI: OUT_AT, RSI: STATE_AT, RDX: frame})
    fix.shifts = plan
    status, events = system_rule(fix, item)
    fix.shifts = list(plan)
    got = memory.read(OUT_AT, 2)
    harness.tally["status %#x" % status] += 1
    trouble = tell(harness, events, (got, status))
    if not trouble and status != STATUS_OK and status == fix.gas_status and memory.bytes_at(OUT_AT + 2, 0x5E) != filled("gas fee", 0x60)[2:]:
        return "carried words differ"
    if not trouble and status != STATUS_OK and status == fix.step and fix.gas_status == STATUS_OK and memory.bytes_at(OUT_AT + 2, 0x5E) != filled("recipient step", 0x60)[2:]:
        return "carried words differ"
    if trouble or status != STATUS_OK:
        return trouble
    native = fix.native & 0xFF and item["token"] == NATIVE_ID
    wei = (item["amount"] * 10 ** 10) if native else None
    if native:
        count = memory.read(STATE_AT + 0x3110, 8)
        row = QUEUE_AT + 0x38 * fix.native_len
        if count != fix.native_len + 1:
            return "native queue length"
        if int.from_bytes(memory.bytes_at(row, 32), "little") != wei or memory.bytes_at(row + 32, 20) != item["source"]:
            return "native row"
        harness.tally["native row"] += 1
        return ""
    count = memory.read(STATE_AT + 0x3128, 8)
    row = QUEUE_AT + 0x400 + 0xC0 * fix.erc20_len
    if count != fix.erc20_len + 1:
        return "erc20 queue length"
    power = fix.tokens[item["token"]]["evm"][1]
    wei = item["amount"] * 10 ** power if power >= 0 else item["amount"] // 10 ** -power
    if int.from_bytes(memory.bytes_at(row, 32), "little") != wei:
        return "erc20 wei"
    if memory.read(row + 0x20, 8) != item["token"] or memory.bytes_at(row + 0x80, 20) != item["third"] or memory.bytes_at(row + 0x94, 20) != CONTRACT or memory.bytes_at(row + 0xA8, 20) != item["source"]:
        return "erc20 row"
    if (memory.read(row + 0x28, 8) != 0) != (item.get("data") is not None):
        return "erc20 data"
    harness.tally["erc20 row"] += 1
    return ""


COMPARES = {"recipient": compare_recipient, "send to evm": compare_wire, "send asset": compare_asset, "agent send": compare_asset, "system send asset": compare_system_asset, "route": compare_route, "move": compare_move, "system": compare_system}


def compare(harness, _, case):
    setup(harness, case)
    return COMPARES[case.kind](harness, case)


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
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(": ")[0] if failed else ""}


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



KEY_ROW_TEXT = (
    (0x272924d, "4983fc64761c4c8b7424", "token text length against 0x64"),
    (0x2729277, "4180bfc83a000000", "spot disabled byte, state +0x3ac8"),
    (0x2729562, "483d40420f00", "gas limit against 1000000"),
    (0x272956e, "6641c70649", "status 0x149, gas_limit too large"),
    (0x27296b5, "4881f900040000", "data length against 0x400"),
    (0x27296be, "6641c70642", "status 0x142, Invalid bytes"),
    (0x27292c3, "c78424b000000022", "the literal row of the native system address, twenty 0x22"),
    (0x27293b8, "c70073706f74", "literal text spot as the target dex"),
    (0x2729c65, "f6819c00000001", "sub-account byte of the record"),
    (0x272a227, "6641bf5b", "status 0x15b, Invalid send"),
    (0x272a048, "6641bf6e", "status 0x16e, sender in mode 3 or 4 from a dex"),
    (0x272a6d0, "6641bf69", "status 0x169"),
    (0x272a3c3, "48b8295c8fc2f5285c8f", "multiplicative inverse of 25 for the multiple of 100 test"),
    (0x272b725, "6641bf5f", "status 0x15f, Transfer limit is"),
    (0x272abc5, "48c78424d000000004000000", "word 4 in the before step of route 3"),
    (0x272c3b0, "48b80000c16ff2862300", "usd cap 10^16"),
    (0x272c3a4, "3b056adaadfd", "compare of the first four name bytes with the literal at 0x209e14"),
    (0x272cad6, "6641c7067e", "status 0x17e, Unexpected mutation"),
    (0x27153fd, "66b84a01", "status 0x14a, EVM transfer not configured"),
    (0x2715401, "80bec93a000001", "state +0x3ac9 against 1"),
    (0x271550a, "66b84e01", "status 0x14e, multi sig user"),
    (0x27155ca, "48b90080c6a47e8d0300", "token 0 limit 10^15"),
    (0x27155e0, "66bb2800", "status 0x28"),
    (0x271561d, "66bb4801", "status 0x148, data on the native token"),
    (0x2715641, "4280bc33bc000000", "EVM row byte of the token at row +0xbc"),
    (0x271568d, "0fb693d1000000", "extra decimals i8 at row +0xd1"),
    (0x2715e6e, "4883b92831000009", "erc20 queue length against 9"),
    (0x27160ad, "4881b910310000b70b0000", "native queue length against 0xbb7"),
    (0x2715e7c, "be00e1f505", "gas price floor 10^8"),
    (0x27166a1, "48b800e40b5402000000", "fee cap 10^10"),
    (0x27166b0, "66b84d01", "status 0x14d, unable to compute fee"),
    (0x27168f6, "c70048595045", "literal text HYPE of the Insufficient row"),
    (0x2716218, "4881c718310000", "erc20 queue at state +0x3118"),
    (0x27165d0, "498b9f10310000", "native queue length at state +0x3110"),
    (0x3988c5a, "4883c2fe", "cut of the 0x prefix"),
    (0x3988c89, "4983fe41", "hex text length against 0x41"),
    (0x3988c1a, "48837c241020", "base58 length against 0x20"),
    (0x2728d4c, "66c7038301", "status 0x183, agent target"),
)

# ---- evidence ----

def core_functions():
    return [(SEND_EVM, "sendToEvmWithData arm 76 body", True), (SEND_ASSET, "sendAsset arm 69 body", True), (AGENT_SEND, "agentSendAsset arm 82 body", True), (SYSTEM_SEND_ASSET, "SystemSendAsset arm 71 body", True), (PARSE, "six text fields to the send record", True),
            (RECIPIENT, "recipient text to 32 bytes", True), (ROUTE, "gates and route of a send record", True), (MOVE, "move and event of a send", True), (SYSTEM, "system send, both L1 to EVM queues", True), (FEE_ERROR, "gas step error to Insufficient token", True),
            (CLONE, "send record clone", True), (DROP_RECORD, "send record drop", True), (DROP_STRINGS, "arm text fields drop", True), (QUEUE_PUSH, "erc20 queue push", True), (U256_MUL, "checked U256 product, shared", False), (DEX_ROW, "dex row by index, shared", False), (SYSTEM_RANGE, "system address range test, shared", False)]


GATES = (
    ("0x2729060", 1, "token text over 100 bytes", "0x143"), ("0x2729060", 2, "state +0x3ac8 set", "0xf9"), ("0x2729060", 3, "token name not in the spot table", "0xf8"), ("0x2729060", 4, "recipient text over 100 bytes", "0x143"), ("0x2729060", 5, "recipient parse fails", "0xb6"),
    ("0x2729060", 6, "gas limit >= 0xccccccccccccccc", "0x13f"), ("0x2729060", 7, "gas limit > 1000000", "0x149"), ("0x2729060", 8, "data over 0x400 bytes", "0x142"), ("0x2729060", 9, "system address of the token as destination, spot as target dex, then the parser", "carried"),
    ("0x272b950", 1, "sub-account text over 100 bytes, then parse", "0x143, 0xb6"), ("0x272b950", 2, "destination text over 100 bytes, then parse", "0x143, 0xb6"), ("0x272b950", 3, "token text over 100 bytes", "0x143"), ("0x272b950", 4, "state +0x3ac8 set", "0xf9"), ("0x272b950", 5, "token name unknown", "0xf8"), ("0x272b950", 6, "amount text over 100 bytes, then decimal parse", "0x143, carried"), ("0x272b950", 7, "source dex text over 100 bytes, then lookup", "0x143, carried"), ("0x272b950", 8, "target dex text over 100 bytes, then lookup", "0x143, carried"),
    ("0x27288c0", 1, "master of the sender differs from the master of the destination, a miss being the address itself", "0x183"),
    ("0x2728e10", 1, "token >= token count", "0xea"), ("0x2728e10", 2, "amount above 0xccccccccccccccb", "0x13f"), ("0x2728e10", 3, "either dex index >= dex count", "0x141"),
    ("0x2729c30", 1, "sub-account: vault chain does not reach the signer", "0x7c"), ("0x2729c30", 2, "vault: destination is not the vault, token not 0, or vault byte +0xaf clear", "0x15"), ("0x2729c30", 3, "sub-account: no row or another master", "0xdc"), ("0x2729c30", 4, "destination mode 2 into a dex other than 0, byte +0x5b1 clear", "0x169"), ("0x2729c30", 5, "sender mode 3 or 4 from a perp dex", "0x16e"), ("0x2729c30", 6, "sender mode 2 or 5 up from a dex other than 0", "0x169"), ("0x2729c30", 7, "same class, same dex or spot, destination is the sender", "0x15b"), ("0x2729c30", 8, "dex index >= dex count, source then target", "0x141"),
    ("0x2729c30", 9, "amount not a multiple of 100 with a dex side: byte +0x8f0 with a live dex, or collateral token", "0x15b"), ("0x2729c30", 10, "amount not a multiple of 100, token is not the collateral", "0xea"), ("0x2729c30", 11, "byte +0x8f0 with a live dex", "0x15b"), ("0x2729c30", 12, "token is not the collateral of a dex side", "0xea"), ("0x2729c30", 13, "dex target with a destination in the system range", "0x15b"), ("0x2729c30", 14, "other dex or spot into a live dex over its transfer limits", "0x15f"),
    ("0x2715320", 1, "state +0x3ac9 not 1", "0x14a"), ("0x2715320", 2, "sender is a multi sig user", "0x14e"), ("0x2715320", 3, "token 0 above 10^15", "0x28"), ("0x2715320", 4, "native token with data", "0x148"), ("0x2715320", 5, "other token with no EVM contract row", "0x14a"), ("0x2715320", 6, "wei scale refuses the amount", "0xba"), ("0x2715320", 7, "state +0x80 clear", "0xfb"), ("0x2715320", 8, "native queue above 3000 rows, erc20 queue above 10 rows", "0x14c"), ("0x2715320", 9, "gas fee step", "carried"), ("0x2715320", 10, "quote price missing, or scale fails", "0x160, 0x13f"), ("0x2715320", 11, "fee above 10^10", "0x14d"), ("0x2715320", 12, "payer has no native row: not tradable, no price, gas step", "0xf6, 0x160, 0x13f, carried"), ("0x2715320", 13, "debit and recipient step", "carried"),
)
RECORD_ROWS = (
    ("send record", "+0x00", "source class, 0 spot, 1 perp dex"), ("send record", "+0x08", "source dex index"), ("send record", "+0x10", "target class"), ("send record", "+0x18", "target dex index"), ("send record", "+0x20", "token"), ("send record", "+0x28", "amount"), ("send record", "+0x30", "bytes::Bytes data, vtable word 0 means none"), ("send record", "+0x50", "32 byte recipient"), ("send record", "+0x70", "gas limit"), ("send record", "+0x78", "nonce"), ("send record", "+0x80", "u32 destination chain id"), ("send record", "+0x88", "destination, 20 bytes"), ("send record", "+0x9c", "sub-account byte"), ("send record", "+0x9d", "sub-account, 20 bytes"),
    ("move record", "+0x00..+0x18", "classes and indexes"), ("move record", "+0x20, +0x38, +0x50", "source name, target name, token name"), ("move record", "+0x68", "token"), ("move record", "+0x70", "amount"), ("move record", "+0x78", "amount / 100"), ("move record", "+0x80", "the 0x58 byte EVM data block"), ("move record", "+0xd8", "acting address"), ("move record", "+0xec", "destination"), ("move record", "+0x100", "route byte"),
    ("system record", "+0x00", "token"), ("system record", "+0x08", "amount"), ("system record", "+0x10", "the 0x58 byte EVM data block, gas limit at +0x50"), ("system record", "+0x68", "sender"), ("system record", "+0x7c", "system address"), ("system record", "+0x90", "third address, reaches the quote and erc20 row +0x80"), ("system record", "+0xa4", "alternate payer byte"), ("system record", "+0xa5", "alternate payer"),
    ("native queue row, state +0x3100, 0x38 bytes", "+0x00", "wei, U256 little endian"), ("native queue row, state +0x3100, 0x38 bytes", "+0x20", "sender, 20 bytes"),
    ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0x00", "wei, U256 little endian"), ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0x20", "token"), ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0x28", "the 0x58 byte EVM data block"), ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0x80", "third address"), ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0x94", "EVM contract of the token"), ("erc20 queue row, state +0x3118, 0xc0 bytes", "+0xa8", "sender"),
)
KEY_ROWS = KEY_ROW_TEXT


def base58_alphabet(image):
    """The alphabet the 128 byte decode table at ALPHABET_AT stands for."""
    at = image.offset(ALPHABET_AT)
    found = {}
    for code_point, value in enumerate(bytes(image.blob[at:at + 128])):
        if value != 0xFF:
            if value in found:
                raise EvidenceError("base58 table repeats %d" % value)
            found[value] = code_point
    if sorted(found) != list(range(58)):
        raise EvidenceError("base58 table is not 58 rows")
    return "".join(chr(found[index]) for index in range(58))


def key_row_lines(image):
    lines = ["address\tbytes\tmeaning"]
    for va, hexed, meaning in KEY_ROWS:
        found = code(image, va, len(hexed) // 2).hex()
        if found != hexed:
            raise EvidenceError("row moved at %#x: %s" % (va, found))
        lines.append("%#x\t%s\t%s" % (va, hexed, meaning))
    return lines


def site_lines(image):
    """Sites by one pass over .text: rel32 calls for the direct targets, FF 15 for the slots."""
    base, text = image.text_bytes()
    direct = {SEND_EVM: "sendToEvmWithData body", SEND_ASSET: "sendAsset body", AGENT_SEND: "agentSendAsset body", SYSTEM_SEND_ASSET: "SystemSendAsset body", PARSE: "text parser", ROUTE: "route", MOVE: "move", SYSTEM: "system send", CORE: "transfer core", FEE_ERROR: "gas step error map", QUEUE_PUSH: "erc20 queue push"}
    slots = {0x5774AE8: "recipient parse through slot", 0x5774A38: "gas fee through slot", 0x5774A18: "native row test through slot"}
    found = []
    for match in re.finditer(b"[\xe8\xe9]", text):
        at = match.start()
        if at + 5 <= len(text):
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in direct:
                found.append((direct[target], target, base + at))
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text):
            target = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            if target in slots:
                found.append((slots[target], target, base + at))
    lines = ["relation\ttarget\tsite\thost"]
    for name, target, site in sorted(found):
        try:
            host = "%#x" % image.fde(site)[0]
        except EvidenceError:
            continue
        lines.append("%s\t%#x\t%#x\t%s" % (name, target, site, host))
    return lines


def analyse(image, full=True):
    harness = Harness(image)
    if base58_alphabet(image) != BASE58_TEXT:
        raise EvidenceError("base58 alphabet differs from the rule list")
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
        lines.append("\t".join((case.kind, case.label, " ".join("%s=%d" % item for item in sorted(harness.tally.items())) or "-", "fail" if trouble else "match")))
        for key, value in harness.tally.items():
            OUTCOMES[key] += value
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    for start, role, _ in core_functions():
        begin, end = image.exact_fde(start)
        rows = body_rows(image, begin, end)
        hit = sum(1 for row in rows if row.va in seen)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "instructions": len(rows), "stepped": hit})
        function_lines.append("%#x\t%#x\t%d\t%d\t%d\t%s" % (begin, end, end - begin, len(rows), hit, role))
    targets = [(start, role) for start, role, claimed in core_functions() if claimed]
    results_rows = run_mutants(image, targets, reached, costs, [case.label for case in cases]) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    status_lines = ["tag\tarm\tform\ttext"]
    for tag, status_arm, form, text in (status_row(image, tag) for tag in STATUS_TAGS):
        status_lines.append("%#x\t%#x\t%s\t%s" % (tag, status_arm, form, text))
    layout_lines = ["tree\tkey_at\tkey_size\tvalue_at\tvalue_size\tcount_at\tleaf_size"]
    for item in LAYOUTS:
        layout_lines.append("%s\t%#x\t%#x\t%#x\t%#x\t%#x\t%#x" % (item.name, item.key_at, item.key_size, item.value_at, item.value_size, item.count_at, item.leaf))
    gate_lines = ["function\torder\ttest\tstatus"] + ["%s\t%d\t%s\t%s" % row for row in GATES]
    record_lines = ["record\toffset\tfield"] + ["%s\t%s\t%s" % row for row in RECORD_ROWS]
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
        "constants": {"max_text": MAX_TEXT, "max_gas_limit": MAX_GAS, "max_data_bytes": MAX_DATA, "single_limit": SINGLE_LIMIT, "fee_cap": FEE_CAP, "native_queue_rows": QUEUE_NATIVE + 1, "erc20_queue_rows": QUEUE_ERC20 + 1, "gas_floor": GAS_FLOOR, "usd_cap": USD_CAP, "base58_decode_table": "%#x" % ALPHABET_AT, "base58_alphabet": base58_alphabet(image)},
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_sites": site_lines(image), "_status": status_lines, "_layouts": layout_lines, "_keys": key_row_lines(image), "_gates": gate_lines, "_records": record_lines,
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, or an arm behind a stub"
SURVIVOR_REASON = "not hand checked row by row: copy size, stack base, error payload words no rule reads, or a value only a stub reads"
OUTCOMES = collections.Counter()


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toutcomes\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "call-sites.tsv": evidence.pop("_sites"), "status-text.tsv": evidence.pop("_status"),
              "node-layouts.tsv": evidence.pop("_layouts"), "key-rows.tsv": evidence.pop("_keys"), "gates.tsv": evidence.pop("_gates"), "record-fields.tsv": evidence.pop("_records")}
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
    files = render(analyse(image))
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
