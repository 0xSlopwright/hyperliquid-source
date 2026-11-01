#!/usr/bin/env python3
"""Evaluate the node #94 EVM block step from ELF bytes: queue drain, system transactions, EVM logs back to L1 rows, the supply check, the automatic halt byte, held rows and the retry and release votes.

The drain, the transaction builder, the log classifier and its decoders, the supply check, the step body, the hold pass, the keep list and the two vote arms run as real bytes in a Python evaluator.
A separately written rule list predicts each transaction, row, event and state word, and conditions, immediates and offsets of the reached rows are flipped to show the run can tell.
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
ONCE_WORD = 0x577AB98

STEP = 0x2760A70
RECONCILE = 0x2760040
CHECKED_SUB = 0x2760A10
DRAIN = 0x3270830
TX_OF_ROW = 0x3730D70
TRANSFER_DATA = 0x324D680
KEEP_EXTEND = 0x24F4FD0
CLASSIFY = 0x34273D0
RECEIVED_DECODE = 0x37A3850
ERC20_DECODE = 0x37A2990
WORD_READ = 0x37A4230
ERROR_DROP = 0x34353C0
HOLD = 0x2517D60
REQUEUE = 0x239F460
PAIR_TIMES_100 = 0x28F4830
TREE_SUM = 0x28C3000
TREE_NEXT = 0x2869350
GAS_ENTRY = 0x2878340
HELD_ENTRY = 0x28784E0
SCALE = 0x3281770
ABI_ENCODE = 0x3303050
U256_MUL = 0x1498BC0
ROW_ITER_DROP = 0x330BE30

VOTE_GLOBAL = 0x2355F40
VOTE_GLOBAL_END = 0x235C713
RETRY_ARM = 0x2356007
RETRY_END = 0x23560AD
RETRY_B = 0x235A6CA
RETRY_B_END = 0x235A730
RELEASE_ARM = 0x235B3C4
SELECTOR_GAUGE = 0x235B2B4
SELECTOR_GAUGE_END = 0x235B2CF
RELEASE_END = 0x235B43A
RELEASE_B = 0x235D00F
RELEASE_B_END = 0x235D255
EVM_RUN = 0x2448500
LOG_LOOP = 0x244A0EC
LOG_LOOP_END = 0x244A298

SYS_CODE = 0x3271680
PENDING_ROWS = 0x3BAE680
REBALANCE_ROW = 0x3299180
REBALANCE_NEXT = 0x330FB70
U256_DIV = 0x32D6AD0
U256_SUB = 0x32D8310
REBALANCE_DIVISOR = 100
REBALANCE_SHARE = 90
EXEC = 0x326D500
BALANCE_OF = 0x326E540
ONE_READ = 0x244BC40
TWO_READ = 0x244BEA0
BALANCE_ROW = 0x371B3A0
SIGN_BYTE = 0x335EC90
APPLY = 0x2759240
APPLY_SIGNED = 0x27584A0
STAMP = 0x3987CB0
ERR_TEXT = 0x1F99480
ERR_DROP = 0x1EAD7F0
OK_VALUE = 0x2780900
RESPONSE = 0x334CC40
DROP_ROWS = 0x255C550
LOG = 0x358DCD0
CORE = 0x2712CE0
CORE_ERR_DROP = 0x239CB60
CORE_OK_DROP = 0x239C230
CORE_WRITER = 0x333B2A0
HASH_ONCE = 0x4E560D7

LINK = 0x274B7E0
LINK_ROW = 0x1F849B0
CREDIT = 0x371D120
ENV_BUILD = 0x37DC090
HEAD_END = 0x2448888
SELECTOR_TABLE = 0x3DD380
VOTE_TABLE = 0x3DD1B8
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (0x26, 0x27, 0xDF, 0x13F, 0x186)
LINK_MAX = 0x7FFFFFFFFFFFFFFF
LINK_USED_TEXT = "Address is already used as EVM contract"
LINK_FIRST_TEXT = "must unset usdc evm contract first"
LINK_UNSET_TEXT = "unable to unset usdc evm contract"
STEP_COPIES = (0x4D8DB10, 0x4D8EBC0)
ALIAS = {0x4464DC0: EVM_RUN, 0x4D8C610: RECONCILE, 0x4D84170: APPLY, 0x4D81660: APPLY_SIGNED, 0x4B011C0: ERR_TEXT, 0x472F840: ERR_DROP, 0x4DB1B80: OK_VALUE, 0x44C88E0: DROP_ROWS, 0x446BBE0: ONE_READ, 0x446BE20: TWO_READ}
RECONCILE_COPY = 0x4D8C610
EVM_RUN_COPIES = (0x4464DC0, 0x44684D0)
VOTE_GLOBAL_COPY = 0x4CAA870
HOLD_SITES = ()

EVENT_DATA_TEXT = "Received(address,uint256)"
TRANSFER_TEXT = "Transfer(address,address,uint256)"
APPROVAL_TEXT = "Approval(address,address,uint256)"
TOPIC_LOW = (0x2094E0, 0x207ED0)
SIGNATURE_AT = 0x59B811
SYSTEM_TEXT = ((0x584A00, "33" * 20), (0x5849E4, "22" * 20), (0x584A14, "55" * 20))
ERC20_TEXT_AT = 0x59B1C8

GAS_NATIVE = 0x7530
GAS_ERC20 = 0x30D40
ACTION_TAG = 0xAD
ROW_END_TAG = 0xCC
KEEP_FLOOR = 0x3B9ACA00
MAX_NUMBER = 0xCCCCCCCCCCCCCCC
SELECTOR_TRANSFER = "a9059cbb"
SELECTOR_DATA = "6ddde35e"
USD_DECIMALS_BYTE = 0xFE
NATIVE_DECIMALS = 10

MUTANT_STEP_LIMIT = 60000
MUTANT_CASES = 36
MUTANT_CASE_COST = 40000
WORKERS = 4

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
VTABLE_AT = HEAP_BASE + 0x3800
BYTES_AT = HEAP_BASE + 0x3900
STATE_AT = HEAP_BASE + 0x10000
EVM_AT = STATE_AT + 0xBC0
SPOT_AT = STATE_AT + 0x80
TOKENS_AT = HEAP_BASE + 0x22000
BOOK_AT = HEAP_BASE + 0x26000
CONTEXT_AT = HEAP_BASE + 0x27000
LOG_AT = HEAP_BASE + 0x28000
STATE_SIZE = 0x3B00
TOKEN_SIZE = 0xE8
FAKE_CLONE = 0x7E0000010
FAKE_NOOP = 0x7E0000020
FAKE_DROP = 0x7E0000030
NONE_WORD = 0x8000000000000000

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
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x6C, True): "unpcklpd", (0x60, True): "punpcklbw", (0x68, True): "punpckhbw", (0x61, True): "punpcklwd", (0x6D, True): "punpckhqdq", (0x67, True): "packuswb", (0xFB, True): "psubq", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd", (0xEB, False): "orpd"}
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
        if two == 0x70 and (opsize or repne or rep):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else ("pshuflw" if repne else "pshufhw"), ("x", reg), rm, 16, target=value)
        if two == 0x71 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            if reg & 7 != 6:
                raise EvidenceError("unsupported word shift at %#x" % va)
            return finish("psllw", rm, None, 16, target=value)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd_out", rm, ("x", reg), 4)
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

    def run_fragment(self, entry, args, stops, top):
        """Run from a row inside a body with rsp at top until a stop row."""
        self.regs = [POISON] * 16
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = top
        pc = entry
        limit = self.step_limit
        cache = self.cache
        while pc not in stops:
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
        return pc

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
        elif op == "movss":
            if row.a[0] == "x":
                if row.b[0] == "x":
                    self.xmm[row.a[1]] = (self.xmm[row.a[1]] >> 32) << 32 | (self.xmm[row.b[1]] & MASK[4])
                else:
                    self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "movd_out":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpckhbw":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (8 * (at + 8))) & 0xFF) | ((right >> (8 * (at + 8))) & 0xFF) << 8) << (16 * at) for at in range(8))
        elif op == "punpcklwd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = sum((((left >> (16 * at)) & 0xFFFF) | ((right >> (16 * at)) & 0xFFFF) << 16) << (32 * at) for at in range(4))
        elif op == "punpckhqdq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left >> 64) | (right >> 64) << 64
        elif op == "packuswb":
            left, right = self.xmm[row.a[1]], self.vector(row.b)

            def clamp(word):
                value = word - 0x10000 if word & 0x8000 else word
                return max(0, min(value, 255))
            self.xmm[row.a[1]] = sum(clamp((left >> (16 * at)) & 0xFFFF) << (8 * at) for at in range(8)) | sum(clamp((right >> (16 * at)) & 0xFFFF) << (8 * (at + 8)) for at in range(8))
        elif op == "pshufhw":
            source = self.vector(row.b)
            words = sum(((source >> (64 + 16 * ((row.target >> (2 * at)) & 3))) & 0xFFFF) << (16 * at) for at in range(4))
            self.xmm[row.a[1]] = (source & MASK[8]) | words << 64
        elif op == "psllw":
            source = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum((((source >> (16 * at)) & 0xFFFF) << row.target & 0xFFFF) << (16 * at) for at in range(8))
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



# ---- harness: real bytes through .text; the allocator and memory slots are hooked, callees outside the path are stubs that log their arguments ----

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


ADDRESS_NODE = Layout("EVM contract address to token and decimals", 0xB8, 20, 0, 0x10, 0x196, 0x198, 0xB0, 0x194)
PENDING_NODE = Layout("token to the two addresses, spot +0x278", 8, 8, 0x60, 0x68, 0x4DA, 0x4E0, 0, 0x4D8)
BALANCE_NODE = Layout("token balance row", 8, 8, 0x60, 0x18, 0x16A, 0x170, 0, 0x168)
HELD_NODE = Layout("user to u64, state +0x3168 and the block output map", 0x60, 20, 8, 8, 0x13E, 0x140, 0, 0x13C)
GAS_NODE = Layout("user to 32 byte row, state +0x39d0", 0x168, 20, 0, 0x20, 0x246, 0x248, 0x160, 0x244)
LAYOUTS = (ADDRESS_NODE, PENDING_NODE, BALANCE_NODE, HELD_NODE, GAS_NODE)
FILLED = {}


def filled(name, size):
    data = FILLED.get(name, b"")
    if len(data) < size:
        data = hashlib.sha256(name.encode()).digest()
        while len(data) < size:
            data += hashlib.sha256(data).digest()
        FILLED[name] = data
    return data[:size]


def le32(value):
    return value.to_bytes(32, "little")


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
        machine.memory.statics[ONCE_WORD] = 0
        self.base_statics = dict(machine.memory.statics)
        self.base_hooks = {relative[slot]: hook for slot, hook in table.items()}
        self.base_hooks.update({FAKE_CLONE: self.on_bytes_clone, FAKE_NOOP: self.on_nothing, FAKE_DROP: self.on_bytes_drop})
        self.stub_hooks = {SYS_CODE: self.on_sys_code, EXEC: self.on_exec, BALANCE_OF: self.on_balance_of, ONE_READ: self.on_one_read, TWO_READ: self.on_two_read, BALANCE_ROW: self.on_balance_row,
                           SIGN_BYTE: self.on_sign_byte, APPLY: self.on_apply, APPLY_SIGNED: self.on_apply_signed, STAMP: self.on_stamp, ERR_TEXT: self.on_err_text, ERR_DROP: self.on_nothing, OK_VALUE: self.on_nothing, RESPONSE: self.on_response,
                           LINK_ROW: self.on_link_row, CREDIT: self.on_credit, ENV_BUILD: self.on_env, DROP_ROWS: self.on_drop_rows, LOG: self.on_log, CORE: self.on_core, CORE_ERR_DROP: self.on_core_err, CORE_OK_DROP: self.on_nothing, CORE_WRITER: self.on_core_writer, HASH_ONCE: self.on_hash_once, EVM_RUN: self.on_evm_run}
        self.switch = {RECONCILE: self.on_reconcile, CLASSIFY: self.on_classify, DRAIN: self.on_drain}
        self.real = RealExcept()
        machine.real = self.real
        machine.watch = {}
        self.use(())
        self.tally = collections.Counter()
        self.case = None
        self.fix = {}
        self.reset()

    def use(self, stubbed):
        hooks = dict(self.base_hooks)
        hooks.update(self.stub_hooks)
        for target in stubbed:
            hooks[target] = self.switch[target]
        for target, origin in ALIAS.items():
            if origin in hooks:
                hooks[target] = hooks[origin]
        machine = self.machine
        machine.slots = hooks
        machine.calls = hooks
        machine.tails = hooks
        self.real.stubs = frozenset(hooks)

    def reset(self):
        memory = self.machine.memory
        memory.reset(USED)
        memory.statics.clear()
        memory.statics.update(self.base_statics)
        self.brk = HEAP_FREE
        self.live = {}
        self.events = []
        memory.write(VTABLE_AT, 8, FAKE_CLONE)
        memory.write(VTABLE_AT + 8, 8, FAKE_NOOP)
        memory.write(VTABLE_AT + 0x10, 8, FAKE_NOOP)
        memory.write(VTABLE_AT + 0x18, 8, FAKE_NOOP)
        memory.write(VTABLE_AT + 0x20, 8, FAKE_DROP)

    def allocate(self, size):
        at = (self.brk + 15) & ~15
        self.brk = at + size
        if self.brk > HEAP_BASE + USED:
            raise Halt("heap full")
        self.live[at] = size
        return at

    def block(self, data):
        at = self.allocate(max(len(data), 1))
        self.machine.memory.put_bytes(at, data)
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
        if self.live[at] != size:
            raise Halt("free %#x size %#x, block %#x" % (at, size, self.live[at]))
        del self.live[at]

    def on_realloc(self, m):
        regs = m.regs
        old, new = regs[RDI], regs[RCX] if regs[RCX] != POISON and regs[RCX] < 0x100000 else regs[RSI]
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

    def stack_word(self, m, index):
        return m.memory.read(m.regs[RSP] + 8 * index, 8)

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

    def on_sys_code(self, m):
        self.events.append(("system code", m.regs[RDI] - EVM_AT, self.address(m.regs[RSI]), m.regs[RDX]))

    def on_exec(self, m):
        memory = m.memory
        tx, out = m.regs[RSI], m.regs[RDI]
        size = memory.read(tx + 0x10, 8)
        data = memory.bytes_at(memory.read(tx + 8, 8), size).hex() if size else ""
        value = int.from_bytes(memory.bytes_at(tx + 0x20, 32), "little")
        self.events.append(("exec", self.stack_word(m, 1) & MASK[4], memory.read(tx + 0x18, 8), value, self.address(tx + 0x40), self.address(tx + 0x54), memory.read(tx + 0x68, 1), data, m.regs[RDX], m.regs[R8] - EVM_AT))
        cap = memory.read(tx, 8)
        if cap and memory.read(tx + 8, 8) in self.live and cap != NONE_WORD:
            del self.live[memory.read(tx + 8, 8)]
        memory.put_bytes(out, filled("exec", 0x110))
        results = self.fix.setdefault("receipts", [])
        result = results.pop(0) if results else "ok"
        memory.write(out + 0xE0, 8, NONE_WORD if result == "none" else 1)
        memory.write(out + 0x100, 8, 0 if result == "fail" else 1)

    def on_balance_of(self, m):
        memory = m.memory
        frame = m.regs[RSI]
        self.events.append(("balance of", memory.read(frame, 8) - EVM_AT, self.address(frame + 8), self.address(frame + 0x1C)))
        out = m.regs[RDI]
        answer = self.fix.get("balances", {}).get(memory.bytes_at(frame + 0x1C, 20))
        memory.write(out, 8, 0 if answer is None else 1)
        if answer is not None:
            memory.put_bytes(out + 8, le32(answer))

    def on_one_read(self, m):
        memory = m.memory
        self.events.append(("one read", m.regs[RSI] - EVM_AT, m.regs[RDX] & 0xFF, self.address(m.regs[RCX]), self.address(m.regs[R8])))
        out = m.regs[RDI]
        answer = self.fix.get("read")
        memory.write(out, 4, 0 if answer is None else 1)
        if answer is not None:
            memory.put_bytes(out + 8, le32(answer[0]))

    def on_two_read(self, m):
        memory = m.memory
        self.events.append(("two read", m.regs[RSI] - EVM_AT, m.regs[RDX] & 0xFF, self.address(m.regs[RCX]), self.address(m.regs[R8]), self.address(m.regs[R8] + 20)))
        out = m.regs[RDI]
        answer = self.fix.get("read")
        memory.write(out, 8, 0 if answer is None else 1)
        if answer is not None:
            memory.put_bytes(out + 8, le32(answer[0]) + le32(answer[1]))

    def on_balance_row(self, m):
        self.events.append(("balance row", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI])))
        m.regs[RAX] = BOOK_AT

    def on_sign_byte(self, m):
        m.regs[RAX] = self.fix.get("sign_byte", 3)

    def on_apply(self, m):
        memory = m.memory
        action = m.regs[R8]
        self.events.append(("apply", m.regs[RDX] & 0xFF, m.regs[RCX] & 0xFF, memory.read(action, 8), memory.read(action + 8, 8), memory.read(action + 0x10, 8), self.address(action + 0x18), self.address(m.regs[R9]), memory.read(STATE_AT + 0x50, 8), memory.read(STATE_AT + 0x78, 1)))
        self.apply_out(m.regs[RDI])

    def apply_out(self, out):
        memory = self.machine.memory
        results = self.fix.setdefault("apply", [])
        result = results.pop(0) if results else "ok"
        memory.put_bytes(out, filled("apply", 0x68))
        memory.write(out, 1, 0xE if result == "err" else 3)

    def on_apply_signed(self, m):
        memory = m.memory
        action, frame = m.regs[RCX], self.stack_word(m, 2)
        self.events.append(("apply signed", self.address(m.regs[RDX]), memory.read(action, 8), m.regs[R8], m.regs[R9], memory.read(frame, 1), memory.bytes_at(frame + 1, 32).hex()))
        self.apply_out(m.regs[RDI])

    def on_stamp(self, m):
        self.events.append(("stamp", m.regs[RSI] & 0xFF, m.regs[RDX], m.regs[RCX], m.regs[R8]))
        m.memory.put_bytes(m.regs[RDI], filled("stamp", 32))

    def on_err_text(self, m):
        memory = m.memory
        out = m.regs[RDI]
        memory.write(out, 8, 11)
        memory.write(out + 8, 8, 12)
        memory.write(out + 0x10, 8, 13)

    def on_response(self, m):
        memory = m.memory
        out = m.regs[RDI]
        memory.put_bytes(out, filled("response", 0x28))
        memory.write(out, 1, memory.read(m.regs[RSI], 1))

    def on_drop_rows(self, m):
        self.events.append(("rows dropped",))

    def on_log(self, m):
        self.events.append(("log", m.regs[RDI] & 0xFF, m.regs[RSI]))

    def on_link_row(self, m):
        self.events.append(("user row", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI])))

    def on_credit(self, m):
        self.events.append(("credit", m.regs[RDI] - STATE_AT, self.address(m.regs[RSI]), m.regs[RDX] & MASK[4], m.regs[RCX] & 0xFF, m.regs[R8], m.regs[R9] & MASK[4]))

    def on_env(self, m):
        memory = m.memory
        out = m.regs[RDI]
        self.events.append(("env", m.regs[RSI] & 0xFF, m.regs[RDX] - CONTEXT_AT, m.regs[RCX] - EVM_AT))
        memory.put_bytes(out, bytes(0x100))
        memory.write(out + 0x90, 8, 1)
        memory.write(out + 0x70, 8, 2)

    def on_drain(self, m):
        memory = m.memory
        out = m.regs[RDI]
        self.events.append(("drain", m.regs[RSI] - EVM_AT, m.regs[RCX] - CONTEXT_AT))
        rows = self.fix.get("keep", ())
        at = self.allocate(0xC0 * max(len(rows), 1))
        for index, row in enumerate(rows):
            memory.put_bytes(at + 0xC0 * index, row)
        memory.put_bytes(out, bytes(0x48))
        memory.write(out + 8, 8, 0x10)
        memory.write(out + 0x18, 8, max(len(rows), 1))
        memory.write(out + 0x20, 8, at)
        memory.write(out + 0x28, 8, len(rows))
        memory.write(out + 0x38, 8, 8)

    def on_core(self, m):
        frame = m.regs[RDX]
        memory = m.memory
        self.events.append(("core", memory.read(frame, 8), memory.read(frame + 0x10, 8), memory.read(frame + 0x20, 8), memory.read(frame + 0x28, 8), memory.read(frame + 0x30, 8), self.address(frame + 0x88), self.address(frame + 0x9C), memory.read(frame + 0xB0, 1)))
        results = self.fix.setdefault("core", [])
        status = results.pop(0) if results else 0x186
        memory.put_bytes(m.regs[RDI], filled("core", 0x60))
        memory.write(m.regs[RDI], 2, status)

    def on_core_err(self, m):
        self.events.append(("core error dropped",))

    def on_core_writer(self, m):
        self.events.append(("core writer", self.address(m.regs[RDI] + 0x38)))

    def on_hash_once(self, m):
        self.events.append(("hash once",))
        m.memory.write(self.frame + 0xF58, 4, 0)

    def on_evm_run(self, m):
        memory = m.memory
        context = m.regs[RCX]
        words = tuple(memory.read(context + 8 * index, 8) - STATE_AT for index in range(11))
        self.events.append(("evm run", m.regs[RSI] - STATE_AT, m.regs[RDX] & 0xFF, words, memory.read(context + 0x58, 1), m.regs[R8] - STATE_AT))
        out = m.regs[RDI]
        fix = self.fix
        rows = fix.get("rows", ())
        at = self.allocate(0x48 * max(len(rows), 1))
        for index, row in enumerate(rows):
            memory.put_bytes(at + 0x48 * index, row)
        memory.write(out, 8, max(len(rows), 1))
        memory.write(out + 8, 8, at)
        memory.write(out + 0x10, 8, len(rows))
        signed = fix.get("signed", ())
        at = self.allocate(0x128 * max(len(signed), 1))
        for index, row in enumerate(signed):
            memory.put_bytes(at + 0x128 * index, row)
        memory.write(out + 0x18, 8, max(len(signed), 1))
        memory.write(out + 0x20, 8, at)
        memory.write(out + 0x28, 8, len(signed))
        gas = fix.get("gas", ())
        if gas:
            root, height = self.tree(HELD_NODE, gas)
            memory.write(out + 0x30, 8, root)
            memory.write(out + 0x38, 8, height)
            memory.write(out + 0x40, 8, len(gas))
        else:
            memory.write(out + 0x30, 8, 0)
            memory.write(out + 0x38, 8, 0)
            memory.write(out + 0x40, 8, 0)

    def on_reconcile(self, m):
        memory = m.memory
        self.events.append(("reconcile", m.regs[RDX]))
        out = m.regs[RDI]
        tag, value = self.fix.get("reconcile", (2, 0))
        memory.write(out, 8, tag)
        memory.put_bytes(out + 8, le32(value))
        m.regs[RAX] = out

    def on_classify(self, m):
        memory = m.memory
        log, out = m.regs[RSI], m.regs[RDI]
        self.events.append(("classify", self.address(log + 0x38), m.regs[RCX] - SPOT_AT, memory.bytes_at(m.regs[R8], 32).hex()))
        row = self.fix.setdefault("classified", {}).get(bytes(memory.bytes_at(log + 0x38, 20)))
        if row is None:
            memory.write(out, 8, 0)
            return
        memory.write(out, 8, 1)
        memory.put_bytes(out + 8, row)

    # fixtures

    def tree(self, layout, rows):
        """One leaf over sorted (key, value) rows. Returns root, height."""
        memory = self.machine.memory
        at = self.allocate(layout.leaf)
        memory.put_bytes(at, filled("node", layout.leaf))
        memory.write(at + layout.parent_at, 8, 0)
        for index, (key, value) in enumerate(rows):
            memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
            memory.put_bytes(at + layout.value_at + layout.value_size * index, value)
        memory.write(at + layout.count_at, 2, len(rows))
        return at, 0

    def tree_two(self, layout, rows):
        """Height one tree: rows split at the middle key, for lookups that must walk down."""
        memory = self.machine.memory
        middle = len(rows) // 2
        left, _ = self.tree(layout, rows[:middle])
        right, _ = self.tree(layout, rows[middle + 1:])
        at = self.allocate(layout.leaf + 12 * 8)
        memory.put_bytes(at, filled("inner", layout.leaf))
        key, value = rows[middle]
        memory.put_bytes(at + layout.key_at, key)
        memory.put_bytes(at + layout.value_at, value)
        memory.write(at + layout.count_at, 2, 1)
        memory.write(at + layout.leaf, 8, left)
        memory.write(at + layout.leaf + 8, 8, right)
        return at, 1

    def tree_rows(self, layout, root, height):
        """Rows of a tree in key order."""
        memory = self.machine.memory
        if not root:
            return []
        rows = []
        count = memory.read(root + layout.count_at, 2)
        for index in range(count + 1):
            if height:
                rows += self.tree_rows(layout, memory.read(root + layout.leaf + 8 * index, 8), height - 1)
            if index < count:
                rows.append((memory.bytes_at(root + layout.key_at + layout.key_size * index, layout.key_size), memory.bytes_at(root + layout.value_at + layout.value_size * index, layout.value_size)))
        return rows

    def run_at(self, entry, args):
        return self.machine.run(entry, args)

    def state(self):
        memory = self.machine.memory
        memory.put_bytes(STATE_AT, filled("state", STATE_SIZE))
        memory.write(STATE_AT, 8, 0)
        memory.write(STATE_AT + 8, 8, 0)
        for at in (0x3168, 0x3178, 0x39D0, 0x39E0):
            memory.write(STATE_AT + at, 8, 0)
        memory.write(STATE_AT + 0x2F8, 8, 0)
        memory.write(STATE_AT + 0x300, 8, 0)
        for at in (0x3180, 0x3188, 0x3190, 0x3198):
            memory.write(STATE_AT + at, 8, 0)
        memory.write(STATE_AT + 0x31A2, 1, 0)
        memory.write(STATE_AT + 0x50, 8, 40)
        memory.write(STATE_AT + 0x78, 1, 0)
        memory.write(STATE_AT + 0x8F2, 1, 7)


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


# ---- rule list, written from the reading of the rows, separate from the run ----

USER = bytes(range(0x10, 0x24))
OTHER = bytes(range(0x40, 0x54))
THIRD = bytes(range(0xC0, 0xD4))
CONTRACT = bytes(range(0x20, 0x34))
CONTRACT_B = bytes(range(0x60, 0x74))
ADDRESS_ONE = bytes(range(0x80, 0x94))
ADDRESS_TWO = bytes(range(0xA0, 0xB4))
NATIVE_ID = 0x96
HASH = bytes(range(0x90, 0xB0))
ENV = HEAP_BASE + 0x12345
SYS_NATIVE = b"\x22" * 20
SYS_ZERO = b"\x20" + bytes(19)
TOP = (1 << 256) - 1
WORD = MASK[8]
ROUNDS = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
          0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)


def keccak256(data):
    """Keccak-256 with the original padding byte, standard library only."""
    state = [0] * 25
    rate = 136
    message = bytearray(data)
    message.append(1)
    message += bytes(-len(message) % rate)
    message[-1] |= 0x80
    for start in range(0, len(message), rate):
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(message[start + 8 * index:start + 8 * index + 8], "little")
        for constant in ROUNDS:
            columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            for x in range(5):
                mixed = columns[(x + 4) % 5] ^ (((columns[(x + 1) % 5] << 1) | (columns[(x + 1) % 5] >> 63)) & WORD)
                for y in range(0, 25, 5):
                    state[x + y] ^= mixed
            turned = [0] * 25
            x, y = 1, 0
            current = state[1]
            for step in range(24):
                x, y = y, (2 * x + 3 * y) % 5
                shift = ((step + 1) * (step + 2) // 2) % 64
                current, state[x + 5 * y] = state[x + 5 * y], ((current << shift) | (current >> (64 - shift))) & WORD if shift else current
            for y in range(0, 25, 5):
                row = state[y:y + 5]
                for x in range(5):
                    state[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5] & WORD)
            state[0] ^= constant
            del turned
    return b"".join(value.to_bytes(8, "little") for value in state[:4])


RECEIVED = keccak256(EVENT_DATA_TEXT.encode())
TRANSFER = keccak256(TRANSFER_TEXT.encode())
APPROVAL = keccak256(APPROVAL_TEXT.encode())


def scale_rule(value, exponent):
    """Merged rule of RE-004-evm-amount-scale-94."""
    size = abs(exponent)
    if size >= 20:
        return None
    power = 10 ** size
    if exponent >= 0:
        result = value // power
    else:
        result = value * power
        if result > TOP:
            return None
    return result if result < MAX_NUMBER else None


def token_address(native, token):
    if native[0] == 1 and native[1] == token:
        return SYS_NATIVE
    return b"\x20" + bytes(11) + token.to_bytes(8, "big")


def received_rule(item):
    topics, data = item["topics"], item["data"]
    if not topics or topics[0] != RECEIVED or len(topics) == 1 or len(data) != 32:
        return None
    return int.from_bytes(data, "big"), topics[1][12:]


def transfer_rule(item):
    topics, data = item["topics"], item["data"]
    if not topics or topics[0] != TRANSFER or len(topics) < 3 or len(data) != 32:
        return None
    return topics[1][12:], topics[2][12:], int.from_bytes(data, "big")


def classify_rule(item):
    native = item["native"]
    if item["address"] == SYS_NATIVE:
        found = received_rule(item)
        if found and found[0] and native[0]:
            amount = scale_rule(found[0], NATIVE_DECIMALS)
            return None if amount is None else (native[1], amount, found[1])
    row = dict(item["map"]).get(item["address"])
    if row is None:
        return None
    token, exponent = row
    found = transfer_rule(item)
    if found is None or found[1] != token_address(native, token):
        return None
    amount = scale_rule(found[2], exponent)
    return None if amount is None else (token, amount, found[0])


def compare_classify(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    topics = b"".join(item["topics"])
    memory.write(LOG_AT, 8, len(item["topics"]))
    memory.write(LOG_AT + 8, 8, harness.block(topics))
    memory.write(LOG_AT + 0x10, 8, len(item["topics"]))
    memory.write(LOG_AT + 0x18, 8, VTABLE_AT)
    memory.write(LOG_AT + 0x20, 8, harness.block(item["data"]))
    memory.write(LOG_AT + 0x28, 8, len(item["data"]))
    memory.write(LOG_AT + 0x30, 8, 0)
    memory.put_bytes(LOG_AT + 0x38, item["address"])
    memory.write(SPOT_AT, 8, item["native"][0])
    memory.write(SPOT_AT + 8, 8, item["native"][1])
    memory.put_bytes(KEY_AT, HASH)
    rows = sorted((key, value[0].to_bytes(8, "little") + bytes([value[1] & 0xFF]) + bytes(7)) for key, value in item["map"])
    build = harness.tree_two if item.get("deep") else harness.tree
    root, height = build(ADDRESS_NODE, rows) if rows else (0, 0)
    memory.write(CONTEXT_AT, 8, root)
    memory.write(CONTEXT_AT + 8, 8, height)
    harness.run_at(CLASSIFY, {RDI: OUT_AT, RSI: LOG_AT, RDX: CONTEXT_AT, RCX: SPOT_AT, R8: KEY_AT})
    expected = classify_rule(item)
    tag = memory.read(OUT_AT, 8)
    if expected is None:
        harness.tally["no row"] += 1
        return "" if tag == 0 else "row, rule none"
    if tag != 1:
        return "no row, rule %r" % (expected,)
    got = (memory.read(OUT_AT + 0x28, 8), memory.read(OUT_AT + 0x30, 8), memory.bytes_at(OUT_AT + 0x38, 20))
    harness.tally["row"] += 1
    if got != expected or memory.bytes_at(OUT_AT + 8, 32) != HASH:
        return "row %r, rule %r" % (got, expected)
    return ""


def native_row(wei, user):
    return le32(wei) + user + filled("pad", 4)


def erc20_row(wei, token, third, contract, sender, data=None, gas=0, nonce=0, chain=0, recipient=bytes(32)):
    if data is None:
        block = bytes(0x20) + recipient + gas.to_bytes(8, "little") + nonce.to_bytes(8, "little") + chain.to_bytes(4, "little") + bytes(4)
    else:
        block = VTABLE_AT.to_bytes(8, "little") + data[0].to_bytes(8, "little") + data[1].to_bytes(8, "little") + filled("word", 8) + recipient + gas.to_bytes(8, "little") + nonce.to_bytes(8, "little") + chain.to_bytes(4, "little") + bytes(4)
    return le32(wei) + token.to_bytes(8, "little") + block + third + contract + sender + filled("pad", 4)


def pad32(data):
    return data + bytes(-len(data) % 32)


def data_call(row, data):
    sender = row[0xA8:0xBC]
    recipient = row[0x48:0x68]
    chain = int.from_bytes(row[0x78:0x7C], "little")
    wei = int.from_bytes(row[:32], "little")
    nonce = int.from_bytes(row[0x70:0x78], "little")
    return (bytes.fromhex(SELECTOR_DATA) + bytes(12) + sender + recipient + chain.to_bytes(32, "big") + wei.to_bytes(32, "big") + nonce.to_bytes(32, "big") + (0xC0).to_bytes(32, "big") + len(data).to_bytes(32, "big") + pad32(data)).hex()


def transfer_call(to, amount):
    return (bytes.fromhex(SELECTOR_TRANSFER) + bytes(12) + to + amount.to_bytes(32, "big")).hex()


def drain_rule(item, data_at):
    events = [("system code", 0, "33" * 20, 0x57863D0), ("system code", 0, "22" * 20, 0x57863F0), ("system code", 0, "55" * 20, 0x5786410)]
    tails = []
    keep = []
    receipts = list(item.get("receipts", ()))

    def run(flag, gas, value, source, target, kind, data):
        events.append(("exec", flag, gas, value, source.hex(), target.hex(), kind, data, ENV, 0))
        tails.append(receipts.pop(0) if receipts else "ok")

    balances = item.get("balances", {})
    tokens = item.get("tokens", ())
    later = []
    for token, (one, two) in sorted(item.get("links", ())):
        flag, contract = tokens[token] if token < len(tokens) else (0, bytes(20))
        if not flag & 1:
            continue
        events.append(("balance of", 0, two.hex(), contract.hex()))
        first = balances.get(contract)
        if first is None:
            continue
        events.append(("balance of", 0, two.hex(), one.hex()))
        second = balances.get(one)
        if second is None or first + second > TOP:
            continue
        goal = (first + second) // REBALANCE_DIVISOR * REBALANCE_SHARE
        if goal > second:
            later.append((1, GAS_ERC20, 0, contract, two, 3, transfer_call(one, goal - second)))
        elif goal < second:
            later.append((1, GAS_ERC20, 0, one, two, 3, transfer_call(contract, second - goal)))
    for row in later:
        run(*row)
    for wei, user in item.get("native", ()):
        run(0, GAS_NATIVE, wei, SYS_NATIVE, user, 0, "")
    links = dict(item.get("links", ()))
    for row, data in item.get("erc20", ()):
        wei = int.from_bytes(row[:32], "little")
        token = int.from_bytes(row[0x20:0x28], "little")
        third, contract, sender = row[0x80:0x94], row[0x94:0xA8], row[0xA8:0xBC]
        link = links.get(token)
        if link:
            events.append(("balance of", 0, link[1].hex(), link[0].hex()))
            balance = balances.get(link[0])
            if balance is not None and min(balance, wei):
                run(1, GAS_ERC20, 0, link[0], link[1], 4, transfer_call(contract, min(balance, wei)))
        if data is None:
            run(0, GAS_ERC20, 0, third, contract, 1, transfer_call(sender, wei))
        else:
            events.append(("data clone", len(data)))
            events.append(("data drop",))
            gas = int.from_bytes(row[0x68:0x70], "little")
            run(0, gas, 0, third, contract, 2, data_call(row, data))
        last = tails[-1]
        if third == SYS_ZERO and last != "ok" and wei >= KEEP_FLOOR:
            keep.append(row)
        elif data is not None:
            events.append(("data drop",))
    return events, tails, keep


def compare_drain(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    fix = harness.fix
    fix["receipts"] = list(item.get("receipts", ()))
    fix["balances"] = item.get("balances", {})
    data_at = {}
    tokens = item.get("tokens") or tuple((0, bytes(20)) for _ in range(10))
    item = dict(item, tokens=tokens)
    for index, (flag, contract) in enumerate(tokens):
        at = TOKENS_AT + TOKEN_SIZE * index
        memory.put_bytes(at, filled("token", TOKEN_SIZE))
        memory.write(at + 0xBC, 1, flag)
        memory.put_bytes(at + 0xBD, contract)
    memory.write(STATE_AT + 0x210, 8, TOKENS_AT)
    memory.write(STATE_AT + 0x218, 8, len(tokens))
    native = item.get("native", ())
    at = harness.allocate(0x38 * len(native)) if native else 8
    for index, (wei, user) in enumerate(native):
        memory.put_bytes(at + 0x38 * index, native_row(wei, user))
    memory.write(EVM_AT + 0x2540, 8, len(native))
    memory.write(EVM_AT + 0x2548, 8, at)
    memory.write(EVM_AT + 0x2550, 8, len(native))
    erc20 = []
    for spec in item.get("erc20", ()):
        data = spec.get("data")
        pair = (harness.block(data), len(data)) if data is not None else None
        erc20.append((erc20_row(spec["wei"], spec.get("token", 3), spec.get("third", THIRD), spec.get("contract", CONTRACT), spec.get("sender", USER), pair, spec.get("gas", 0), spec.get("nonce", 0), spec.get("chain", 0), spec.get("recipient", bytes(32))), data))
    at = harness.allocate(0xC0 * len(erc20)) if erc20 else 8
    for index, (row, _) in enumerate(erc20):
        memory.put_bytes(at + 0xC0 * index, row)
    memory.write(EVM_AT + 0x2558, 8, len(erc20))
    memory.write(EVM_AT + 0x2560, 8, at)
    memory.write(EVM_AT + 0x2568, 8, len(erc20))
    links = item.get("links", ())
    rows = sorted((key.to_bytes(8, "little"), filled("link", 0x40) + one + two + filled("end", 0x68 - 0x68)) for key, (one, two) in links)
    rows = [(key, value + bytes(0x68 - len(value))) for key, value in rows]
    root, height = harness.tree(PENDING_NODE, rows) if rows else (0, 0)
    memory.write(SPOT_AT + 0x278, 8, root)
    memory.write(SPOT_AT + 0x280, 8, height)
    memory.write(SPOT_AT + 0x288, 8, len(rows))
    memory.write(CONTEXT_AT + 0x18, 8, SPOT_AT)
    harness.run_at(DRAIN, {RDI: OUT_AT, RSI: EVM_AT, RDX: ENV, RCX: CONTEXT_AT})
    expected = dict(item)
    expected["erc20"] = erc20
    events, tails, keep = drain_rule(expected, data_at)
    trouble = tell(harness, events)
    if trouble:
        return trouble
    if memory.read(OUT_AT + 0x10, 8) != len(tails):
        return "result rows %d, rule %d" % (memory.read(OUT_AT + 0x10, 8), len(tails))
    ptr = memory.read(OUT_AT + 8, 8)
    for index, result in enumerate(tails):
        words = memory.read(ptr + 0x110 * index + 0xE0, 8), memory.read(ptr + 0x110 * index + 0x100, 8)
        if words != ((NONE_WORD if result == "none" else 1), (0 if result == "fail" else 1)):
            return "result row %d: %r" % (index, words)
    if memory.read(OUT_AT + 0x28, 8) != len(keep):
        return "kept rows %d, rule %d" % (memory.read(OUT_AT + 0x28, 8), len(keep))
    ptr = memory.read(OUT_AT + 0x20, 8)
    for index, row in enumerate(keep):
        if memory.bytes_at(ptr + 0xC0 * index, 0xC0) != row:
            return "kept row %d differs" % index
    words = tuple(memory.read(EVM_AT + at, 8) for at in (0x2540, 0x2548, 0x2550, 0x2558, 0x2560, 0x2568))
    if words != (0, 8, 0, 0, 8, 0):
        return "queues not emptied: %r" % (words,)
    harness.tally["kept"] += len(keep)
    harness.tally["transactions"] += len(tails)
    return ""


def plain_logs(harness, item, events):
    """Log rows carry a Location that differs in a copy, so a copy compares level only."""
    if not item.get("copy"):
        return events
    harness.events = [row[:2] if row[0] == "log" else row for row in harness.events]
    return [row[:2] if row[0] == "log" else row for row in events]


def tell(harness, expected):
    got = harness.events
    if got != expected:
        for index, (left, right) in enumerate(zip(got, expected)):
            if left != right:
                return "event %d: %r, rule %r" % (index, left, right)
        return "event count %d, rule %d: %r / %r" % (len(got), len(expected), got[-2:], expected[-2:])
    return ""


def deque_rows(harness, at):
    memory = harness.machine.memory
    cap, ptr, head, size = [memory.read(at + 8 * index, 8) for index in range(4)]
    return [memory.bytes_at(ptr + 0xC0 * ((head + index) % cap), 0xC0) for index in range(size)]


def plain_row(index):
    return erc20_row(1000 + index, index, SYS_ZERO, CONTRACT, USER)


def deque_put(harness, at, cap, head, rows):
    memory = harness.machine.memory
    ptr = harness.allocate(0xC0 * cap) if cap else 8
    for index, row in enumerate(rows):
        memory.put_bytes(ptr + 0xC0 * ((head + index) % cap), row)
    memory.write(at, 8, cap)
    memory.write(at + 8, 8, ptr)
    memory.write(at + 0x10, 8, head)
    memory.write(at + 0x18, 8, len(rows))


def compare_keep(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    old = [plain_row(index) for index in range(item["old"])]
    new = [plain_row(100 + index) for index in range(item["new"])]
    deque = EVM_AT + 0x2570
    deque_put(harness, deque, item["cap"], item["head"], old)
    ptr = harness.allocate(0xC0 * max(len(new), 1))
    for index, row in enumerate(new):
        memory.put_bytes(ptr + 0xC0 * index, row)
    memory.write(CONTEXT_AT, 8, ptr)
    memory.write(CONTEXT_AT + 8, 8, ptr)
    memory.write(CONTEXT_AT + 0x10, 8, max(len(new), 1))
    memory.write(CONTEXT_AT + 0x18, 8, ptr + 0xC0 * len(new))
    harness.run_at(KEEP_EXTEND, {RDI: deque, RSI: CONTEXT_AT})
    harness.tally["rows"] += len(new)
    got = deque_rows(harness, deque)
    return "" if got == old + new else "deque rows %d, rule %d" % (len(got), len(old + new))


def retry_rule(item, rows):
    """Rows left in the deque, the row put back in the erc20 queue, and data drops."""
    if not rows:
        return rows, None, []
    head, rest = rows[0], rows[1:]
    drops = [("data drop",)] if head[0x28:0x30] != bytes(8) else []
    if item["flag"]:
        return rest, None, drops
    return rest, head[:0x28] + bytes(8) + head[0x30:], drops


def compare_retry(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    rows = [plain_row(index) for index in range(item["rows"])]
    if item.get("data") and rows:
        rows[0] = rows[0][:0x28] + VTABLE_AT.to_bytes(8, "little") + BYTES_AT.to_bytes(8, "little") + (8).to_bytes(8, "little") + rows[0][0x40:]
    deque = STATE_AT + 0x3130
    deque_put(harness, deque, item.get("cap", 4), item.get("head", 0), rows)
    queue = [plain_row(50 + index) for index in range(item.get("queue", 0))]
    cap = max(item.get("queue_cap", len(queue)), len(queue))
    at = harness.allocate(0xC0 * cap) if cap else 8
    for index, row in enumerate(queue):
        memory.put_bytes(at + 0xC0 * index, row)
    memory.write(STATE_AT + 0x3118, 8, cap)
    memory.write(STATE_AT + 0x3120, 8, at)
    memory.write(STATE_AT + 0x3128, 8, len(queue))
    action = CONTEXT_AT
    memory.write(action + 8, 1, item["flag"])
    top = STACK_TOP - 0x4000
    harness.machine.run_fragment(RETRY_ARM, {R13: STATE_AT, R15: action}, {VOTE_GLOBAL_END}, top)
    rest, back, drops = retry_rule(item, rows)
    trouble = tell(harness, drops)
    if trouble:
        return trouble
    if deque_rows(harness, deque) != rest:
        return "deque after the arm differs"
    size = memory.read(STATE_AT + 0x3128, 8)
    want = queue + ([back] if back else [])
    if size != len(want):
        return "queue rows %d, rule %d" % (size, len(want))
    ptr = memory.read(STATE_AT + 0x3120, 8)
    for index, row in enumerate(want):
        if memory.bytes_at(ptr + 0xC0 * index, 0xC0) != row:
            return "queue row %d differs" % index
    harness.tally["requeued" if back else "dropped"] += 1
    return ""


def set_held(harness, rows):
    memory = harness.machine.memory
    root, height = harness.tree(HELD_NODE, [(key, value.to_bytes(8, "little")) for key, value in sorted(rows)]) if rows else (0, 0)
    memory.write(STATE_AT + 0x3168, 8, root)
    memory.write(STATE_AT + 0x3170, 8, height)
    memory.write(STATE_AT + 0x3178, 8, len(rows))


def compare_release(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    harness.use((RECONCILE,))
    native = item.get("native", (1, NATIVE_ID))
    memory.write(SPOT_AT, 8, native[0])
    memory.write(SPOT_AT + 8, 8, native[1])
    memory.write(STATE_AT + 0x31A2, 1, item.get("flag", 0))
    held = item.get("held", ())
    set_held(harness, held)
    harness.fix["reconcile"] = (item.get("tag", 1), 5)
    harness.fix["core"] = list(item.get("core", ()))
    harness.machine.run_fragment(RELEASE_ARM, {R13: STATE_AT}, {VOTE_GLOBAL_END}, STACK_TOP - 0x4000)
    events = []
    if item.get("flag", 0):
        return tell(harness, events)
    events.append(("reconcile", 0))
    if item.get("tag", 1) != 1:
        return tell(harness, events) or ("" if memory.read(STATE_AT + 0x3178, 8) == len(held) else "held rows changed")
    source = SYS_NATIVE if native == (1, 0) else SYS_ZERO
    statuses = list(item.get("core", ()))
    for key, value in sorted(held):
        events.append(("core", 0, 3, 0, value, 0, source.hex(), key.hex(), 0))
        if (statuses.pop(0) if statuses else 0x186) != 0x186:
            events.append(("core error dropped",))
    harness.tally["paid"] += len(held)
    trouble = tell(harness, events)
    if trouble:
        return trouble
    return "" if (memory.read(STATE_AT + 0x3168, 8), memory.read(STATE_AT + 0x3178, 8)) == (0, 0) else "held tree not taken"


def evm_row(token, amount, user, hashed=HASH):
    return hashed + token.to_bytes(8, "little") + amount.to_bytes(8, "little") + user + filled("pad", 4)


def hold_rule(rows, held):
    """Rows of token 0 leave the list and add to the held map, saturating."""
    held = dict(held)
    kept = []
    logs = 0
    for token, amount, user in rows:
        if token:
            kept.append((token, amount, user))
            continue
        total = held.get(user, 0) + amount
        if total > WORD:
            logs += 1
            total = WORD
        held[user] = total
    return kept, held, logs


def compare_hold(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    rows = item["rows"]
    at = harness.allocate(0x48 * max(len(rows), 1))
    for index, row in enumerate(rows):
        memory.put_bytes(at + 0x48 * index, evm_row(*row))
    memory.write(CONTEXT_AT, 8, max(len(rows), 1))
    memory.write(CONTEXT_AT + 8, 8, at)
    memory.write(CONTEXT_AT + 0x10, 8, len(rows))
    set_held(harness, item.get("held", ()))
    harness.run_at(HOLD, {RDI: CONTEXT_AT, RSI: STATE_AT + 0x3168})
    kept, held, logs = hold_rule(rows, item.get("held", ()))
    return check_hold(harness, kept, held, logs, CONTEXT_AT)


def check_hold(harness, kept, held, logs, vector):
    memory = harness.machine.memory
    if len([row for row in harness.events if row[0] == "log"]) != logs:
        return "log count %r, rule %d" % (harness.events, logs)
    if memory.read(vector + 0x10, 8) != len(kept):
        return "kept %d, rule %d" % (memory.read(vector + 0x10, 8), len(kept))
    at = memory.read(vector + 8, 8)
    for index, row in enumerate(kept):
        if memory.bytes_at(at + 0x48 * index, 0x44) != evm_row(*row)[:0x44]:
            return "kept row %d differs" % index
    got = dict((key, int.from_bytes(value, "little")) for key, value in harness.tree_rows(HELD_NODE, memory.read(STATE_AT + 0x3168, 8), memory.read(STATE_AT + 0x3170, 8)))
    harness.tally["held rows"] += len(held)
    if got != held or memory.read(STATE_AT + 0x3178, 8) != len(held):
        return "held %r, rule %r" % (got, held)
    return ""


def reconcile_rule(item):
    tokens = item.get("tokens", ((1, USD_DECIMALS_BYTE, CONTRACT),))
    source = SYS_NATIVE if item.get("native", (1, NATIVE_ID)) == (1, 0) else SYS_ZERO
    events = [("balance row", 0x80, source.hex())]
    balance = dict(item.get("book", ())).get(0, 0)
    if not tokens or not tokens[0][0]:
        return 2, None, events
    if tokens[0][1] != USD_DECIMALS_BYTE:
        return 3, None, events
    contract = tokens[0][2]
    link = dict(item.get("links", ())).get(0)
    if link:
        events.append(("two read", 0, 7, contract.hex(), contract.hex(), link[0].hex()))
    else:
        events.append(("one read", 0, 7, contract.hex(), contract.hex()))
    read = item.get("read")
    if read is None:
        return 3, None, events
    first, second = read[0], read[1] if link else 0
    extra = item.get("extra", 0)
    held = 0
    for _, value in item.get("held", ()):
        held = min(held + value, WORD)
    total = held + extra
    if total > WORD:
        events.append(("log", 0, 0x56DFD90))
        total = WORD
    queued = 0
    for spec in item.get("erc20", ()):
        if spec.get("contract", CONTRACT) == contract:
            queued = min(queued + spec["wei"], TOP)
    p0, p1, q = min(first * 100, TOP), min(second * 100, TOP), min(queued * 100, TOP)
    z0 = item.get("minted", 0)
    words = {"balance": balance, "z0": z0, "p0": p0, "p1": p1, "z1": total, "q": q}
    left = p0 + balance
    if left > TOP or left + p1 > TOP:
        return 0, words, events
    left = left + p1
    for part in (z0, total, q):
        if left < part:
            return 0, words, events
        left -= part
    return 1, dict(words, value=left), events


def set_reconcile(harness, item):
    memory = harness.machine.memory
    native = item.get("native", (1, NATIVE_ID))
    memory.write(SPOT_AT, 8, native[0])
    memory.write(SPOT_AT + 8, 8, native[1])
    tokens = item.get("tokens", ((1, USD_DECIMALS_BYTE, CONTRACT),))
    for index, (flag, decimals, contract) in enumerate(tokens):
        at = TOKENS_AT + TOKEN_SIZE * index
        memory.put_bytes(at, filled("token", TOKEN_SIZE))
        memory.write(at + 0xBC, 1, flag)
        memory.put_bytes(at + 0xBD, contract)
        memory.write(at + 0xD1, 1, decimals)
    memory.write(STATE_AT + 0x210, 8, TOKENS_AT)
    memory.write(STATE_AT + 0x218, 8, len(tokens))
    book = sorted((key.to_bytes(8, "little"), value.to_bytes(8, "little") + bytes(0x10)) for key, value in item.get("book", ()))
    root, height = harness.tree(BALANCE_NODE, book) if book else (0, 0)
    memory.write(BOOK_AT + 0x10, 8, root)
    memory.write(BOOK_AT + 0x18, 8, height)
    links = item.get("links", ())
    rows = sorted((key.to_bytes(8, "little"), filled("link", 0x40) + one + two + bytes(0x18 - 0x18)) for key, (one, two) in links)
    rows = [(key, value + bytes(0x68 - len(value))) for key, value in rows]
    root, height = harness.tree(PENDING_NODE, rows) if rows else (0, 0)
    memory.write(STATE_AT + 0x2F8, 8, root)
    memory.write(STATE_AT + 0x300, 8, height)
    memory.write(STATE_AT + 0x3A48, 8, item.get("minted", 0))
    set_held(harness, item.get("held", ()))
    erc20 = [erc20_row(spec["wei"], 3, THIRD, spec.get("contract", CONTRACT), USER) for spec in item.get("erc20", ())]
    at = harness.allocate(0xC0 * max(len(erc20), 1))
    for index, row in enumerate(erc20):
        memory.put_bytes(at + 0xC0 * index, row)
    memory.write(STATE_AT + 0x3120, 8, at)
    memory.write(STATE_AT + 0x3128, 8, len(erc20))
    harness.fix["read"] = item.get("read")


def compare_reconcile(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    set_reconcile(harness, item)
    harness.run_at(RECONCILE_COPY if item.get("copy") else RECONCILE, {RDI: OUT_AT, RSI: STATE_AT, RDX: item.get("extra", 0)})
    tag, words, events = reconcile_rule(item)
    harness.tally["tag %d" % tag] += 1
    trouble = tell(harness, plain_logs(harness, item, events))
    if trouble:
        return trouble
    got = memory.read(OUT_AT, 8)
    if got != tag:
        return "tag %d, rule %d" % (got, tag)
    if words is None:
        return ""
    fields = ((0x48, "z0"), (0x68, "p0"), (0x88, "p1"), (0xA8, "z1"), (0xC8, "q"))
    if memory.read(OUT_AT + 0x28, 8) != words["balance"]:
        return "balance word"
    for at, name in fields:
        if int.from_bytes(memory.bytes_at(OUT_AT + at, 32), "little") != words[name]:
            return "field %s: %#x, rule %#x" % (name, int.from_bytes(memory.bytes_at(OUT_AT + at, 32), "little"), words[name])
    if tag == 1 and int.from_bytes(memory.bytes_at(OUT_AT + 8, 32), "little") != words["value"]:
        return "value %#x, rule %#x" % (int.from_bytes(memory.bytes_at(OUT_AT + 8, 32), "little"), words["value"])
    return ""


CONTEXT_WORDS = (0, 0x3368, 0x5B8, 0x80, 0x3380, 0x8D0, 0x8F8, 0x740, 0x39E8, 0x3A30, 0x498)


def signed_row(index, tag=7):
    body = bytearray(filled("signed%d" % index, 0x128))
    body[:8] = tag.to_bytes(8, "little")
    body[0xF0:0x104] = OTHER[:19] + bytes([index])
    body[0x104:0x124] = HASH[::-1]
    return bytes(body)


def step_rule(item, memory):
    rows = item.get("rows", ())
    events = [("evm run", 0xBC0, item["mode"], CONTEXT_WORDS, 7, 0x8F3)]
    total = 0
    for token, amount, _ in rows:
        if not token:
            if total + amount > WORD:
                events.append(("log", 0, 0x56C4ED8))
            total = min(total + amount, WORD)
    if item.get("real"):
        pass
    else:
        events.append(("reconcile", total))
    tag, value = item.get("reconcile", (2, 0))
    gauge = item.get("gauge", 0)
    flag = item.get("flag", 0)
    if tag == 1 and value > gauge:
        gauge = value
    if tag in (0, 3):
        if not flag:
            flag = 1
            events.append(("log", 3, 0x56BDF88))
    held = dict(item.get("held", ()))
    kept = list(rows)
    if flag:
        kept, held, logs = hold_rule(rows, held)
        events += [("log", 0, 0x56DFD78)] * logs
    return events, total, kept, held, gauge, flag


def compare_step(harness, case):
    item = case.items
    machine = harness.machine
    memory = machine.memory
    harness.state()
    harness.use(() if item.get("real") else (RECONCILE,))
    native = item.get("native", (1, NATIVE_ID))
    if item.get("real"):
        set_reconcile(harness, item)
    memory.write(SPOT_AT, 8, native[0])
    memory.write(SPOT_AT + 8, 8, native[1])
    memory.put_bytes(STATE_AT + 0x3180, le32(item.get("gauge", 0)))
    memory.write(STATE_AT + 0x31A2, 1, item.get("flag", 0))
    memory.write(STATE_AT, 8, item.get("stamp", (0, 0))[0])
    memory.write(STATE_AT + 8, 8, item.get("stamp", (0, 0))[1])
    nonce = item.get("nonce", 40)
    memory.write(STATE_AT + 0x50, 8, nonce)
    if not item.get("real"):
        set_held(harness, item.get("held", ()))
    fix = harness.fix
    fix["rows"] = [evm_row(*row) for row in item.get("rows", ())]
    signed = [signed_row(index) for index in range(item.get("signed", 0))]
    if item.get("stop"):
        signed.append(signed_row(9, ROW_END_TAG))
    fix["signed"] = signed
    fix["gas"] = [(key, value.to_bytes(8, "little")) for key, value in sorted(item.get("gas", ()))]
    fix["reconcile"] = item.get("reconcile", (2, 0))
    fix["apply"] = list(item.get("apply", ()))
    fix["sign_byte"] = item.get("sign_byte", 3)
    existing = item.get("gas_old", ())
    root, height = harness.tree(GAS_NODE, [(key, value.to_bytes(8, "little") + filled("gas", 0x18)) for key, value in sorted(existing)]) if existing else (0, 0)
    memory.write(STATE_AT + 0x39D0, 8, root)
    memory.write(STATE_AT + 0x39D8, 8, height)
    memory.write(STATE_AT + 0x39E0, 8, len(existing))
    word_28 = memory.read(STATE_AT + 0x28, 8)
    harness.run_at(STEP_COPIES[0] if item.get("copy") else STEP, {RDI: OUT_AT, RSI: STATE_AT, RDX: item["mode"]})
    events, total, kept, held, gauge, flag = step_rule(item, memory)
    if item.get("real"):
        tag, words, real_events = reconcile_rule(dict(item, extra=total))
        events = events[:1] + real_events + events[1:]
    counter = item.get("stamp", (0, 0))
    count = counter[1] if counter[0] == 1 else 0
    tagged = counter[0] == 1
    results = []
    plan = list(item.get("apply", ()))
    for index, (token, amount, user) in enumerate(kept):
        nonce = min(nonce + 1, WORD)
        source = token_address(native, token)
        events.append(("apply", 0, item.get("sign_byte", 3), ACTION_TAG, token, amount, user.hex(), source.hex(), nonce, 1))
        count = min(count + 1, WORD)
        tagged = True
        results.append((ACTION_TAG, plan.pop(0) if plan else "ok", source, (token, amount, user)))
    for index in range(item.get("signed", 0)):
        if tagged:
            events.append(("stamp", 7, word_28, count, 0))
        events.append(("apply signed", (OTHER[:19] + bytes([index])).hex(), 7, 0, 0, 0, HASH[::-1].hex()))
        count = min(count + 1, WORD)
        tagged = True
        results.append((7, plan.pop(0) if plan else "ok", OTHER[:19] + bytes([index]), None))
    events.append(("rows dropped",))
    trouble = tell(harness, plain_logs(harness, item, events))
    if trouble:
        return trouble
    if int.from_bytes(memory.bytes_at(STATE_AT + 0x3180, 32), "little") != gauge:
        return "gauge %#x, rule %#x" % (int.from_bytes(memory.bytes_at(STATE_AT + 0x3180, 32), "little"), gauge)
    if memory.read(STATE_AT + 0x31A2, 1) != flag:
        return "flag byte"
    if memory.read(STATE_AT + 0x50, 8) != nonce:
        return "nonce word"
    if tagged and (memory.read(STATE_AT, 4), memory.read(STATE_AT + 8, 8)) != (1, count):
        return "counter %r" % memory.read(STATE_AT + 8, 8)
    if memory.read(OUT_AT + 0x10, 8) != len(results):
        return "result rows %d, rule %d" % (memory.read(OUT_AT + 0x10, 8), len(results))
    ptr = memory.read(OUT_AT + 8, 8)
    for index, (tag, result, source, fields) in enumerate(results):
        row = ptr + 0x130 * index
        if memory.read(row, 8) != tag:
            return "result %d tag" % index
        if fields and (memory.read(row + 8, 8), memory.read(row + 0x10, 8), memory.bytes_at(row + 0x18, 20)) != fields:
            return "result %d fields" % index
        if memory.bytes_at(row + 0x118, 20) != source:
            return "result %d address" % index
        byte = memory.read(row + 0xF0, 1)
        if result == "err":
            if byte != 0xE or [memory.read(row + 0xF8 + 8 * at, 8) for at in range(3)] != [11, 12, 13]:
                return "result %d error words" % index
        elif byte != (0xD if tag == ACTION_TAG else 3) or memory.bytes_at(row + 0xF1, 0x27) != filled("response", 0x28)[1:]:
            return "result %d response" % index
    if not item.get("real"):
        got = dict((key, int.from_bytes(value, "little")) for key, value in harness.tree_rows(HELD_NODE, memory.read(STATE_AT + 0x3168, 8), memory.read(STATE_AT + 0x3170, 8)))
        if got != held:
            return "held %r, rule %r" % (got, held)
    want = dict(existing)
    for key, value in item.get("gas", ()):
        want[key] = min(want.get(key, 0) + value, WORD)
    rows = harness.tree_rows(GAS_NODE, memory.read(STATE_AT + 0x39D0, 8), memory.read(STATE_AT + 0x39D8, 8))
    got = dict((key, int.from_bytes(value[:8], "little")) for key, value in rows)
    if got != want:
        return "gas rows %r, rule %r" % (got, want)
    harness.tally["applied"] += len(results)
    return ""


def link_rule(item):
    """Status text or None, the events, the cap after, and whether token 0 took the address."""
    address = item["address"]
    source = SYS_NATIVE if item.get("native", (1, NATIVE_ID)) == (1, 0) else SYS_ZERO
    cap = item.get("cap", 0)
    book = dict((key, value) for key, value in item.get("book", ()))
    total, hold = book.get(0, (0, 0))
    events = []
    if address == bytes(20):
        events.append(("balance row", 0x80, source.hex()))
        need = (cap + hold) & WORD
        if need < hold or need > total:
            return LINK_UNSET_TEXT, events, cap, False
        events.append(("user row", 0x740, source.hex()))
        events.append(("credit", 0x80, source.hex(), 0, 1, cap, 0))
        return None, events, 0, False
    tokens = item.get("tokens", ((0, 0, CONTRACT_B),))
    if not tokens:
        return "panic", events, cap, False
    if any(flag & 1 and contract == address for flag, _, contract in tokens):
        return LINK_USED_TEXT, events, cap, False
    if cap:
        return LINK_FIRST_TEXT, events, cap, False
    events.append(("balance row", 0x80, source.hex()))
    events.append(("user row", 0x740, source.hex()))
    events.append(("credit", 0x80, source.hex(), 0, 1, total, 0))
    events.append(("credit", 0x80, "00" * 20, 0, 0, total, 0))
    events.append(("credit", 0x80, source.hex(), 0, 0, LINK_MAX, 0))
    return None, events, LINK_MAX, True


def compare_link(harness, case):
    item = case.items
    memory = harness.machine.memory
    harness.state()
    native = item.get("native", (1, NATIVE_ID))
    memory.write(SPOT_AT, 8, native[0])
    memory.write(SPOT_AT + 8, 8, native[1])
    tokens = item.get("tokens", ((0, 0, CONTRACT_B),))
    for index, (flag, decimals, contract) in enumerate(tokens):
        at = TOKENS_AT + TOKEN_SIZE * index
        memory.put_bytes(at, filled("token", TOKEN_SIZE))
        memory.write(at + 0xBC, 1, flag)
        memory.put_bytes(at + 0xBD, contract)
        memory.write(at + 0xD1, 1, decimals)
    memory.write(STATE_AT + 0x210, 8, TOKENS_AT)
    memory.write(STATE_AT + 0x218, 8, len(tokens))
    memory.write(STATE_AT + 0x3A48, 8, item.get("cap", 0))
    book = sorted((key.to_bytes(8, "little"), value[0].to_bytes(8, "little") + value[1].to_bytes(8, "little") + bytes(8)) for key, value in item.get("book", ()))
    root, height = harness.tree(BALANCE_NODE, book) if book else (0, 0)
    memory.write(BOOK_AT + 0x10, 8, root)
    memory.write(BOOK_AT + 0x18, 8, height)
    memory.put_bytes(KEY_AT, item["address"])
    text, events, cap, linked = link_rule(item)
    try:
        harness.run_at(LINK, {RDI: OUT_AT, RSI: STATE_AT, RDX: KEY_AT})
    except Panicked:
        return "" if text == "panic" else "panic, rule %r" % text
    harness.tally["refused" if text else "done"] += 1
    trouble = tell(harness, events)
    if trouble:
        return trouble
    status = memory.read(OUT_AT, 2)
    if text:
        got = memory.bytes_at(memory.read(OUT_AT + 8, 8), memory.read(OUT_AT + 0x10, 8)).decode()
        if status != 0xDF or got != text:
            return "status %#x %r, rule %r" % (status, got, text)
    elif status != 0x186:
        return "status %#x" % status
    if memory.read(STATE_AT + 0x3A48, 8) != cap:
        return "cap word %#x, rule %#x" % (memory.read(STATE_AT + 0x3A48, 8), cap)
    row = (memory.read(TOKENS_AT + 0xBC, 1), memory.read(TOKENS_AT + 0xD1, 1), memory.bytes_at(TOKENS_AT + 0xBD, 20)) if tokens else None
    if linked and row != (1, USD_DECIMALS_BYTE, item["address"]):
        return "token row %r" % (row,)
    if not linked and tokens and row != tokens[0]:
        return "token row changed"
    return ""


def compare_head(harness, case):
    item = case.items
    machine = harness.machine
    memory = machine.memory
    harness.state()
    harness.use((DRAIN,))
    deque = EVM_AT + 0x2570
    old = [plain_row(index) for index in range(item.get("old", 0))]
    new = [plain_row(100 + index) for index in range(item.get("new", 0))]
    deque_put(harness, deque, 8, 0, old)
    harness.fix["keep"] = new
    mode = item["mode"]
    picked = EVM_AT + (0x2520 if mode else 0x21B8)
    other = EVM_AT + (0x21B8 if mode else 0x2520)
    memory.put_bytes(picked, filled("slot picked", 0x20))
    memory.put_bytes(other, filled("slot other", 0x20))
    top = STACK_TOP - 0x4000
    machine.run_fragment(EVM_RUN, {RDI: OUT_AT, RSI: EVM_AT, RDX: mode, RCX: CONTEXT_AT, R8: STATE_AT + 0x8F3}, {HEAD_END}, top)
    frame = machine.regs[RSP]
    trouble = tell(harness, [("env", mode, 0, 0), ("drain", 0, 0)])
    if trouble:
        return trouble
    if deque_rows(harness, deque) != old + new:
        return "keep rows differ"
    if memory.bytes_at(frame + 0x40, 0x20) != filled("slot picked", 0x20):
        return "taken words differ"
    if memory.read(picked, 8) != 0 or memory.bytes_at(other, 0x20) != filled("slot other", 0x20):
        return "slot after the take"
    if memory.read(frame + 0x6C8, 8) != picked:
        return "slot pointer"
    harness.tally["kept rows"] += len(new)
    return ""


def compare_gauge(harness, case):
    memory = harness.machine.memory
    harness.state()
    memory.put_bytes(STATE_AT + 0x3180, le32(case.items["gauge"]))
    harness.machine.run_fragment(SELECTOR_GAUGE, {R13: STATE_AT}, {VOTE_GLOBAL_END}, STACK_TOP - 0x4000)
    return "" if memory.bytes_at(STATE_AT + 0x3180, 32) == bytes(32) else "gauge not cleared"


def compare_loop(harness, case):
    item = case.items
    machine = harness.machine
    memory = machine.memory
    harness.state()
    harness.use((CLASSIFY,))
    top = STACK_TOP - 0x4000
    harness.frame = top
    logs = item.get("logs", ())
    harness.fix["classified"] = {address: HASH + token.to_bytes(8, "little") + amount.to_bytes(8, "little") + address + filled("pad", 4) for address, token, amount in logs if token is not None}
    at = harness.allocate(0x50 * max(len(logs), 1))
    for index, (address, _, _) in enumerate(logs):
        memory.write(at + 0x50 * index, 8, 0)
        memory.write(at + 0x50 * index + 8, 8, 1)
        memory.write(at + 0x50 * index + 0x10, 8, 0)
        memory.write(at + 0x50 * index + 0x18, 8, VTABLE_AT)
        memory.put_bytes(at + 0x50 * index + 0x38, address)
    memory.write(top + 8, 8, NONE_WORD if item.get("failed") else 7)
    memory.write(top + 0xB8, 8, at)
    memory.write(top + 0xC0, 8, len(logs))
    memory.write(top + 0x698, 8, SPOT_AT)
    memory.put_bytes(top + 0xF38, HASH)
    memory.write(top + 0xF58, 4, item.get("once", 0))
    memory.write(top + 0x1A8, 8, 0)
    memory.write(top + 0x1B0, 8, 8)
    memory.write(top + 0x1B8, 8, 0)
    machine.run_fragment(LOG_LOOP, {R15: 0x1234}, {LOG_LOOP_END}, top)
    events = []
    rows = []
    if not item.get("failed"):
        for address, token, amount in logs:
            if item.get("once", 0):
                events.append(("hash once",))
            memory.write(top + 0xF58, 4, 0) if False else None
            item_once = 0
            events.append(("classify", address.hex(), 0, HASH.hex()))
            if token is None:
                events.append(("core writer", address.hex()))
            else:
                rows.append(harness.fix["classified"][address][:0x48])
            if item.get("once", 0):
                break
    trouble = tell(harness, events)
    if trouble:
        return trouble
    size = memory.read(top + 0x1B8, 8)
    if size != len(rows):
        return "rows %d, rule %d" % (size, len(rows))
    ptr = memory.read(top + 0x1B0, 8)
    for index, row in enumerate(rows):
        if memory.bytes_at(ptr + 0x48 * index, 0x48) != row:
            return "row %d differs" % index
    harness.tally["evm rows"] += len(rows)
    return ""


COMPARES = {"classify": compare_classify, "drain": compare_drain, "keep": compare_keep, "retry": compare_retry, "release": compare_release, "hold": compare_hold, "reconcile": compare_reconcile, "step": compare_step, "loop": compare_loop, "link": compare_link, "head": compare_head, "gauge": compare_gauge}


def compare(harness, _, case):
    harness.reset()
    harness.fix = {}
    harness.use(())
    harness.tally = harness.tally if harness.tally is not None else collections.Counter()
    return COMPARES[case.kind](harness, case)


# ---- cases ----

class Case:
    def __init__(self, kind, label, **items):
        self.kind = kind
        self.label = label
        self.items = items


def topic_of(address):
    return bytes(12) + address


def amount_word(value):
    return value.to_bytes(32, "big")


def classify_cases():
    out = []
    base = {"native": (1, NATIVE_ID), "map": ((CONTRACT, (3, 2)), (CONTRACT_B, (NATIVE_ID, 0)), (ADDRESS_ONE, (5, -2)))}

    def add(label, **items):
        out.append(Case("classify", "classify_" + label, **dict(base, **items)))

    wei = 5 * 10 ** 18
    good = {"address": SYS_NATIVE, "topics": (RECEIVED, topic_of(USER)), "data": amount_word(wei)}
    add("received", **good)
    add("received_dust", **dict(good, data=amount_word(10 ** 10 - 1)))
    add("received_one_unit", **dict(good, data=amount_word(10 ** 10)))
    add("received_zero", **dict(good, data=amount_word(0)))
    add("received_at_cap", **dict(good, data=amount_word((MAX_NUMBER - 1) * 10 ** 10)))
    add("received_over_cap", **dict(good, data=amount_word(MAX_NUMBER * 10 ** 10)))
    add("received_top", **dict(good, data=amount_word(TOP)))
    add("received_short_data", **dict(good, data=b"\x01" * 31))
    add("received_long_data", **dict(good, data=amount_word(wei) + bytes(32)))
    add("received_no_data", **dict(good, data=b""))
    add("received_one_topic", **dict(good, topics=(RECEIVED,)))
    add("received_no_topic", **dict(good, topics=()))
    add("received_three_topics", **dict(good, topics=(RECEIVED, topic_of(USER), topic_of(OTHER))))
    add("received_dirty_topic", **dict(good, topics=(RECEIVED, b"\xff" * 12 + USER)))
    add("received_wrong_topic", **dict(good, topics=(TRANSFER, topic_of(USER))))
    add("received_last_byte", **dict(good, topics=(RECEIVED[:31] + bytes([RECEIVED[31] ^ 1]), topic_of(USER))))
    add("received_native_off", **dict(good, native=(0, NATIVE_ID)))
    add("received_native_two", **dict(good, native=(2, NATIVE_ID)))
    add("received_other_address", **dict(good, address=OTHER))
    add("received_in_map", **dict(good, map=((SYS_NATIVE, (9, 0)),)))
    transfer = {"topics": (TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x03")), "data": amount_word(12345678)}
    add("erc20", address=CONTRACT, **transfer)
    add("erc20_deep", address=CONTRACT, deep=True, **transfer)
    add("erc20_exact_decimals", address=CONTRACT, **dict(transfer, data=amount_word(100)))
    add("erc20_floor", address=CONTRACT, **dict(transfer, data=amount_word(199)))
    add("erc20_under_unit", address=CONTRACT, **dict(transfer, data=amount_word(99)))
    add("erc20_zero", address=CONTRACT, **dict(transfer, data=amount_word(0)))
    add("erc20_negative_exponent", address=ADDRESS_ONE, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x05"))))
    add("erc20_exponent_over", address=ADDRESS_ONE, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x05")), data=amount_word(TOP)))
    add("erc20_to_user", address=CONTRACT, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(OTHER))))
    add("erc20_to_other_token", address=CONTRACT, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x04"))))
    add("erc20_to_native_system", address=CONTRACT_B, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(SYS_NATIVE))))
    add("erc20_native_token_zero_style", address=CONTRACT_B, **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(11) + NATIVE_ID.to_bytes(8, "big")))))
    add("erc20_native_off_style", address=CONTRACT_B, native=(0, NATIVE_ID), **dict(transfer, topics=(TRANSFER, topic_of(USER), topic_of(b"\x20" + bytes(11) + NATIVE_ID.to_bytes(8, "big")))))
    add("erc20_unknown_contract", address=OTHER, **transfer)
    add("erc20_empty_map", address=CONTRACT, map=(), **transfer)
    add("erc20_approval", address=CONTRACT, **dict(transfer, topics=(APPROVAL, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x03"))))
    add("erc20_approval_short", address=CONTRACT, **dict(transfer, topics=(APPROVAL, topic_of(USER))))
    add("erc20_other_event", address=CONTRACT, **dict(transfer, topics=(RECEIVED, topic_of(USER), topic_of(b"\x20" + bytes(18) + b"\x03"))))
    add("erc20_no_topics", address=CONTRACT, **dict(transfer, topics=()))
    add("erc20_two_topics", address=CONTRACT, **dict(transfer, topics=(TRANSFER, topic_of(USER))))
    add("erc20_four_topics", address=CONTRACT, **dict(transfer, topics=transfer["topics"] + (topic_of(OTHER),)))
    add("erc20_short_data", address=CONTRACT, **dict(transfer, data=b"\x01" * 16))
    add("erc20_long_data", address=CONTRACT, **dict(transfer, data=amount_word(100) + bytes(1)))
    add("erc20_dirty_to", address=CONTRACT, **dict(transfer, topics=(TRANSFER, topic_of(USER), b"\xff" * 12 + b"\x20" + bytes(18) + b"\x03")))
    rng = random.Random(9401)
    for index in range(30):
        add("grid_%d" % index, address=rng.choice((CONTRACT, CONTRACT_B, ADDRESS_ONE, OTHER, SYS_NATIVE)), topics=rng.choice(((RECEIVED, topic_of(USER)), (TRANSFER, topic_of(OTHER), topic_of(b"\x20" + bytes(18) + b"\x03")), (TRANSFER, topic_of(OTHER), topic_of(b"\x20" + bytes(18) + b"\x05")), (APPROVAL, topic_of(USER), topic_of(OTHER)))),
            data=amount_word(rng.choice((0, 1, 99, 100, 10 ** 10, 10 ** 12, 10 ** 22, 2 ** 200, TOP))), native=rng.choice(((1, NATIVE_ID), (0, 0), (1, 3))))
    return out


def drain_cases():
    out = []

    def add(label, **items):
        out.append(Case("drain", "drain_" + label, **items))

    add("empty")
    add("native_one", native=((10 ** 18, USER),))
    add("native_two", native=((1, USER), (TOP, OTHER)))
    add("native_receipt_failed", native=((7, USER),), receipts=("fail",))
    contract_rows = ((0, bytes(20)),) * 3 + ((1, CONTRACT),) + ((0, bytes(20)),) * 4 + ((3, CONTRACT_B),) + ((2, OTHER),)
    linked = ((3, (ADDRESS_ONE, ADDRESS_TWO)),)
    base = dict(links=linked, tokens=contract_rows)
    add("rebalance_up", balances={CONTRACT: 1000, ADDRESS_ONE: 100}, **base)
    add("rebalance_down", balances={CONTRACT: 10, ADDRESS_ONE: 990}, **base)
    add("rebalance_exact", balances={CONTRACT: 100, ADDRESS_ONE: 900}, **base)
    add("rebalance_floor", balances={CONTRACT: 199, ADDRESS_ONE: 900}, **base)
    add("rebalance_floor_up", balances={CONTRACT: 200, ADDRESS_ONE: 899}, **base)
    add("rebalance_all_zero", balances={CONTRACT: 0, ADDRESS_ONE: 0}, **base)
    add("rebalance_under_100", balances={CONTRACT: 99, ADDRESS_ONE: 0}, **base)
    add("rebalance_first_none", balances={ADDRESS_ONE: 5}, **base)
    add("rebalance_second_none", balances={CONTRACT: 5}, **base)
    add("rebalance_sum_carries", balances={CONTRACT: TOP, ADDRESS_ONE: 1}, **base)
    add("rebalance_top", balances={CONTRACT: TOP - 1, ADDRESS_ONE: 1}, **base)
    add("rebalance_high_limb", balances={CONTRACT: 1 << 200, ADDRESS_ONE: 1 << 130}, **base)
    add("rebalance_limb_two", balances={CONTRACT: 1 << 140, ADDRESS_ONE: 0}, **base)
    add("rebalance_limb_one", balances={CONTRACT: 1 << 70, ADDRESS_ONE: 0}, **base)
    add("rebalance_flag_clear", links=((2, (ADDRESS_ONE, ADDRESS_TWO)),), tokens=contract_rows, balances={CONTRACT: 5, ADDRESS_ONE: 1})
    add("rebalance_flag_bit_one", links=((9, (ADDRESS_ONE, ADDRESS_TWO)),), tokens=contract_rows, balances={OTHER: 5000, ADDRESS_ONE: 1})
    add("rebalance_flag_three", links=((8, (ADDRESS_ONE, ADDRESS_TWO)),), tokens=contract_rows, balances={CONTRACT_B: 5000, ADDRESS_ONE: 1})
    add("rebalance_two_rows", links=((3, (ADDRESS_ONE, ADDRESS_TWO)), (8, (ADDRESS_TWO, ADDRESS_ONE))), tokens=contract_rows, balances={CONTRACT: 1000, CONTRACT_B: 10, ADDRESS_ONE: 100, ADDRESS_TWO: 990})
    add("rebalance_three_rows_order", links=((1, (ADDRESS_ONE, ADDRESS_TWO)), (3, (ADDRESS_ONE, ADDRESS_TWO)), (8, (ADDRESS_TWO, ADDRESS_ONE))), tokens=contract_rows, balances={CONTRACT: 1000, CONTRACT_B: 10, ADDRESS_ONE: 100, ADDRESS_TWO: 990})
    add("rebalance_receipts_tail", receipts=("fail", "ok"), native=((5, USER),), balances={CONTRACT: 1000, ADDRESS_ONE: 100}, **base)
    add("rebalance_then_queues", native=((5, USER),), erc20=({"wei": 6},), balances={CONTRACT: 1000, ADDRESS_ONE: 100}, **base)
    add("erc20_plain", erc20=({"wei": 500000},))
    add("erc20_plain_top", erc20=({"wei": TOP},))
    add("erc20_two", erc20=({"wei": 1}, {"wei": 2, "sender": OTHER, "contract": CONTRACT_B, "third": ADDRESS_ONE}))
    add("erc20_data", erc20=({"wei": 500000, "data": b"\x11" * 5, "gas": 90000, "nonce": 12, "chain": 1399811149, "recipient": bytes(range(32))},))
    add("erc20_data_word", erc20=({"wei": 500000, "data": b"\x22" * 32, "gas": 1000000, "nonce": 1, "chain": 2, "recipient": b"\x07" * 32},))
    add("erc20_data_33", erc20=({"wei": 9, "data": b"\x23" * 33, "gas": 5, "nonce": 2 ** 63, "chain": 0xFFFFFFFF},))
    add("erc20_data_empty", erc20=({"wei": 9, "data": b"", "gas": 5},))
    add("order_native_before_erc20", native=((5, USER), (6, OTHER)), erc20=({"wei": 7}, {"wei": 8}))
    add("linked_balance_above", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 10 ** 9}, erc20=({"wei": 5000},))
    add("linked_balance_equal", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 5000}, erc20=({"wei": 5000},))
    add("linked_balance_below", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 4999}, erc20=({"wei": 5000},))
    add("linked_balance_zero", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 0}, erc20=({"wei": 5000},))
    add("linked_balance_none", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), erc20=({"wei": 5000},))
    add("linked_high_limb", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 1 << 200}, erc20=({"wei": (1 << 200) + 1},))
    add("linked_other_token", links=((4, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 9}, erc20=({"wei": 5000},))
    add("linked_three_rows", links=((1, (ADDRESS_TWO, ADDRESS_ONE)), (3, (ADDRESS_ONE, ADDRESS_TWO)), (8, (USER, OTHER))), balances={ADDRESS_ONE: 9}, erc20=({"wei": 5000}, {"wei": 6, "token": 8}, {"wei": 7, "token": 9}))
    add("linked_data", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 9}, erc20=({"wei": 5000, "data": b"\x31" * 4, "gas": 3},))
    add("keep_failed", erc20=({"wei": 10 ** 9, "third": SYS_ZERO},), receipts=("fail",))
    add("keep_no_receipt", erc20=({"wei": 10 ** 9, "third": SYS_ZERO},), receipts=("none",))
    add("keep_ok_no_keep", erc20=({"wei": 10 ** 9, "third": SYS_ZERO},), receipts=("ok",))
    add("keep_under_floor", erc20=({"wei": 10 ** 9 - 1, "third": SYS_ZERO},), receipts=("fail",))
    add("keep_high_limb", erc20=({"wei": 1 << 64, "third": SYS_ZERO},), receipts=("fail",))
    add("keep_limb_two", erc20=({"wei": 1 << 128, "third": SYS_ZERO},), receipts=("fail",))
    add("keep_limb_three", erc20=({"wei": 1 << 192, "third": SYS_ZERO},), receipts=("fail",))
    add("keep_other_third", erc20=({"wei": 10 ** 12, "third": THIRD},), receipts=("fail",))
    add("keep_third_last_byte", erc20=({"wei": 10 ** 12, "third": SYS_ZERO[:19] + b"\x01"},), receipts=("fail",))
    add("keep_third_first_byte", erc20=({"wei": 10 ** 12, "third": b"\x21" + SYS_ZERO[1:]},), receipts=("fail",))
    add("keep_with_data", erc20=({"wei": 10 ** 12, "third": SYS_ZERO, "data": b"\x41" * 3, "gas": 8},), receipts=("fail",))
    add("drop_with_data_under_floor", erc20=({"wei": 5, "third": SYS_ZERO, "data": b"\x41" * 3, "gas": 8},), receipts=("fail",))
    add("drop_with_data_ok", erc20=({"wei": 10 ** 12, "third": SYS_ZERO, "data": b"\x41" * 3, "gas": 8},), receipts=("ok",))
    add("keep_two_of_three", erc20=({"wei": 10 ** 12, "third": SYS_ZERO}, {"wei": 10 ** 12, "third": SYS_ZERO}, {"wei": 10 ** 13, "third": SYS_ZERO}), receipts=("fail", "ok", "none"))
    add("keep_after_escrow_ok", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 7}, erc20=({"wei": 10 ** 12, "third": SYS_ZERO},), receipts=("ok", "fail"))
    add("no_keep_escrow_failed", links=((3, (ADDRESS_ONE, ADDRESS_TWO)),), balances={ADDRESS_ONE: 7}, erc20=({"wei": 10 ** 12, "third": SYS_ZERO},), receipts=("fail", "ok"))
    return out


def keep_cases():
    out = []
    for label, cap, head, old, new in (("empty_nothing", 0, 0, 0, 0), ("empty_one", 0, 0, 0, 1), ("empty_three", 0, 0, 0, 3), ("room", 8, 0, 2, 2), ("room_exact", 4, 0, 2, 2), ("wraps", 4, 3, 2, 1), ("wraps_new", 8, 6, 2, 3), ("full_grows", 4, 0, 4, 1), ("full_wrapped_grows", 4, 2, 4, 3), ("wrapped_short_tail", 8, 7, 8, 1), ("wrapped_long_tail", 8, 2, 8, 5), ("nothing_added", 4, 1, 2, 0)):
        out.append(Case("keep", "keep_" + label, cap=cap, head=head, old=old, new=new))
    return out


def retry_cases():
    out = []
    for label, items in (("empty", dict(flag=0, rows=0)), ("empty_flag", dict(flag=1, rows=0)), ("requeue", dict(flag=0, rows=1)), ("drop", dict(flag=1, rows=1)), ("requeue_two_keeps_tail", dict(flag=0, rows=2)), ("drop_two_keeps_tail", dict(flag=1, rows=2)), ("flag_two_drops", dict(flag=2, rows=1)), ("wrap_head", dict(flag=0, rows=2, head=3)), ("head_last", dict(flag=1, rows=1, head=3)),
                        ("requeue_data_dropped", dict(flag=0, rows=1, data=True)), ("drop_data", dict(flag=1, rows=1, data=True)), ("queue_room", dict(flag=0, rows=1, queue=2, queue_cap=4)), ("queue_full_grows", dict(flag=0, rows=1, queue=2)), ("queue_above_ten", dict(flag=0, rows=1, queue=12)), ("queue_empty_grows", dict(flag=0, rows=3, cap=8, head=6))):
        out.append(Case("retry", "retry_" + label, **items))
    return out


def release_cases():
    out = []
    two = ((USER, 100), (OTHER, 200))
    for label, items in (("flag_set", dict(flag=1, held=two)), ("flag_two", dict(flag=2, held=two)), ("tag_0", dict(tag=0, held=two)), ("tag_2", dict(tag=2, held=two)), ("tag_3", dict(tag=3, held=two)), ("nothing_held", dict()), ("one", dict(held=((USER, 7),))), ("two", dict(held=two)), ("sorted", dict(held=((OTHER, 2), (USER, 1), (CONTRACT, 3)))),
                        ("native_token_zero", dict(held=two, native=(1, 0))), ("native_tag_off", dict(held=two, native=(0, 0))), ("native_other_id", dict(held=two, native=(1, 5))), ("core_fails_first", dict(held=two, core=(0x28,))), ("core_fails_last", dict(held=two, core=(0x186, 0xF6))), ("core_fails_all", dict(held=two, core=(0x28, 0x28)))):
        out.append(Case("release", "release_" + label, **items))
    return out


def hold_cases():
    out = []
    for label, items in (("empty", dict(rows=())), ("no_token_zero", dict(rows=((3, 5, USER), (4, 6, OTHER)))), ("one", dict(rows=((0, 5, USER),))), ("mix_keeps_order", dict(rows=((3, 5, USER), (0, 6, OTHER), (4, 7, USER), (0, 8, USER), (5, 9, OTHER)))), ("same_user_adds", dict(rows=((0, 5, USER), (0, 6, USER)))), ("existing_adds", dict(rows=((0, 5, USER),), held=((USER, 10), (OTHER, 1)))), ("new_key_beside_rows", dict(rows=((0, 5, CONTRACT),), held=((USER, 10), (OTHER, 1)))),
                        ("first_token_then_zero", dict(rows=((3, 5, USER), (0, 6, USER)))), ("zero_then_token", dict(rows=((0, 6, USER), (3, 5, USER)))), ("saturates", dict(rows=((0, 5, USER),), held=((USER, WORD - 1),))), ("saturates_exact", dict(rows=((0, 1, USER),), held=((USER, WORD - 1),))), ("saturates_later_row", dict(rows=((3, 1, USER), (0, 5, USER), (0, 5, USER)), held=((USER, WORD - 6),))), ("all_zero_token", dict(rows=((0, 1, USER), (0, 2, OTHER), (0, 3, CONTRACT))))):
        out.append(Case("hold", "hold_" + label, **items))
    return out


def reconcile_cases():
    out = []
    ok = dict(book=((0, 500),), read=(100, 0))

    def add(label, **items):
        out.append(Case("reconcile", "reconcile_" + label, **dict(ok, **items)))

    add("plain")
    add("no_tokens", tokens=())
    add("no_contract", tokens=((0, USD_DECIMALS_BYTE, CONTRACT),))
    add("other_decimals", tokens=((1, 0xFF, CONTRACT),))
    add("decimals_zero", tokens=((1, 0, CONTRACT),))
    add("read_none", read=None)
    add("native_is_zero", native=(1, 0))
    add("native_off", native=(0, 0))
    add("no_book", book=())
    add("book_other_key", book=((5, 77),))
    add("book_after_other", book=((0, 9), (1, 77)))
    add("two_reads", links=((0, (ADDRESS_ONE, ADDRESS_TWO)),), read=(100, 40))
    add("two_reads_none", links=((0, (ADDRESS_ONE, ADDRESS_TWO)),), read=None)
    add("other_link_ignored", links=((1, (ADDRESS_ONE, ADDRESS_TWO)),))
    add("minted", minted=1000)
    add("minted_exact", minted=10500)
    add("minted_over", minted=10501)
    add("extra", extra=7)
    add("held", held=((USER, 30), (OTHER, 40)))
    add("held_and_extra_over", held=((USER, 10400),), extra=101)
    add("held_and_extra_exact", held=((USER, 10400),), extra=100)
    add("extra_saturates", held=((USER, 2),), extra=WORD)
    add("queue_counts", erc20=({"wei": 3},))
    add("queue_exact", erc20=({"wei": 105},))
    add("queue_over", erc20=({"wei": 106},))
    add("queue_other_contract", erc20=({"wei": 3, "contract": CONTRACT_B},))
    add("queue_two_of_three", erc20=({"wei": 3}, {"wei": 9, "contract": CONTRACT_B}, {"wei": 4}))
    add("queue_saturates", erc20=({"wei": TOP}, {"wei": 2}))
    add("queue_product_saturates", erc20=({"wei": 1 << 250},), read=(1 << 240, 0))
    add("read_product_saturates", read=(1 << 250, 0))
    add("read_top", read=(TOP, 0))
    add("sum_carry", read=(TOP // 100, 0), book=((0, WORD),))
    add("second_product", links=((0, (ADDRESS_ONE, ADDRESS_TWO)),), read=(0, 1 << 250))
    add("two_sum_carry", links=((0, (ADDRESS_ONE, ADDRESS_TWO)),), read=(TOP // 100, TOP // 100))
    add("all_parts", links=((0, (ADDRESS_ONE, ADDRESS_TWO)),), read=(1000, 2000), minted=11, held=((USER, 22),), extra=33, erc20=({"wei": 44},), book=((0, 55),))
    rng = random.Random(9402)
    for index in range(16):
        add("grid_%d" % index, read=(rng.choice((0, 1, 10 ** 6, 10 ** 15, 1 << 100)), rng.choice((0, 5, 10 ** 9))), links=rng.choice(((), ((0, (ADDRESS_ONE, ADDRESS_TWO)),))), minted=rng.choice((0, 3, 10 ** 8, 10 ** 17)), extra=rng.choice((0, 9, 10 ** 12)), erc20=rng.choice(((), ({"wei": 7},), ({"wei": 10 ** 13},))), book=((0, rng.choice((0, 8, 10 ** 10))),))
    return out


def step_cases():
    out = []

    def add(label, **items):
        items.setdefault("mode", 1)
        out.append(Case("step", "step_" + label, **items))

    rows = ((3, 50, USER), (0, 60, OTHER))
    add("empty")
    add("mode_zero", mode=0)
    add("one_token_row", rows=((3, 50, USER),))
    add("one_usdc_row", rows=((0, 60, OTHER),))
    add("native_row", rows=((NATIVE_ID, 50, USER),))
    add("native_off", rows=((NATIVE_ID, 50, USER),), native=(0, 0))
    add("native_is_token_zero", rows=((0, 50, USER),), native=(1, 0))
    add("two_rows", rows=rows)
    add("sign_byte", rows=rows, sign_byte=1)
    add("apply_error", rows=rows, apply=("err", "ok"))
    add("nonce_saturates", rows=rows, nonce=WORD - 1)
    add("counter_continues", rows=rows, stamp=(1, 9))
    add("counter_restarts", rows=rows, stamp=(0, 9))
    add("counter_saturates", rows=rows, stamp=(1, WORD))
    add("sum_two_usdc", rows=((0, 5, USER), (3, 100, USER), (0, 6, OTHER)))
    add("sum_saturates", rows=((0, WORD, USER), (0, 6, OTHER)))
    add("gauge_rises", reconcile=(1, 500))
    add("gauge_equal", reconcile=(1, 500), gauge=500)
    add("gauge_falls_stays", reconcile=(1, 400), gauge=500)
    add("gauge_top_limb", reconcile=(1, 1 << 200), gauge=(1 << 200) - 1)
    add("gauge_low_limb_only", reconcile=(1, (1 << 200) + 1), gauge=1 << 200)
    add("gauge_keeps_high", reconcile=(1, 1 << 64), gauge=(1 << 64) + 5)
    add("gauge_limb_two", reconcile=(1, (1 << 128) + 7), gauge=(1 << 128) + 3 + (1 << 64))
    add("gauge_limb_three", reconcile=(1, (1 << 192) + 7), gauge=(1 << 192) + (1 << 130))
    add("no_contract", reconcile=(2, 0), rows=rows)
    add("bad_setup_flags", reconcile=(3, 0), rows=rows)
    add("underflow_flags", reconcile=(0, 0), rows=rows)
    add("already_flagged_tag_0", reconcile=(0, 0), rows=rows, flag=1)
    add("already_flagged_tag_1", reconcile=(1, 9), rows=rows, flag=1)
    add("already_flagged_tag_2", reconcile=(2, 0), rows=rows, flag=1)
    add("already_flagged_tag_3", reconcile=(3, 0), rows=rows, flag=1)
    add("flagged_keeps_token_rows", reconcile=(0, 0), rows=((3, 1, USER), (4, 2, OTHER)))
    add("flagged_all_held", reconcile=(0, 0), rows=((0, 1, USER), (0, 2, OTHER)))
    add("flagged_adds_to_held", reconcile=(0, 0), rows=((0, 1, USER),), held=((USER, 5),))
    add("flag_two_counts", reconcile=(2, 0), rows=rows, flag=2)
    add("signed_one", signed=1)
    add("signed_two", signed=2)
    add("signed_after_rows", rows=rows, signed=2)
    add("signed_stamped", signed=2, stamp=(1, 4))
    add("signed_error", signed=2, apply=("ok", "err"))
    add("signed_stop", signed=1, stop=True)
    add("stop_first", stop=True)
    add("gas_new", gas=((USER, 5),))
    add("gas_two", gas=((USER, 5), (OTHER, 6)))
    add("gas_adds", gas=((USER, 5),), gas_old=((USER, 7),))
    add("gas_beside", gas=((CONTRACT, 5),), gas_old=((USER, 7), (OTHER, 8)))
    add("gas_saturates", gas=((USER, 5),), gas_old=((USER, WORD - 1),))
    add("real_check", real=True, book=((0, 500),), read=(100, 0), tokens=((1, USD_DECIMALS_BYTE, CONTRACT),), reconcile=(1, 10493), rows=((0, 7, USER), (3, 1, USER)))
    add("real_check_fails", real=True, book=((0, 500),), read=(100, 0), minted=10501, reconcile=(0, 0), rows=((3, 1, USER),))
    add("real_check_no_contract", real=True, tokens=((0, USD_DECIMALS_BYTE, CONTRACT),), reconcile=(2, 0), rows=((3, 1, USER),))
    return out


def loop_cases():
    out = []
    for label, items in (("no_logs", dict()), ("failed_tx", dict(failed=True, logs=((CONTRACT, 3, 5),))), ("one_row", dict(logs=((CONTRACT, 3, 5),))), ("one_writer", dict(logs=((OTHER, None, 0),))), ("mix", dict(logs=((CONTRACT, 3, 5), (OTHER, None, 0), (CONTRACT_B, 4, 6), (USER, None, 0)))), ("five_rows", dict(logs=((CONTRACT, 3, 1), (CONTRACT_B, 3, 2), (USER, 3, 3), (OTHER, 3, 4), (THIRD, 3, 5)))), ("hash_once", dict(once=1, logs=((CONTRACT, 3, 5),))), ("hash_once_writer", dict(once=1, logs=((OTHER, None, 0),)))):
        out.append(Case("loop", "loop_" + label, **items))
    return out


def link_cases():
    out = []
    low = dict(address=CONTRACT, book=((0, (900, 0)),))
    for label, items in (("set", low), ("set_no_book", dict(address=CONTRACT)), ("set_book_other_key", dict(address=CONTRACT, book=((4, (9, 0)),))), ("set_native_zero", dict(low, native=(1, 0))), ("set_native_off", dict(low, native=(0, 0))), ("set_again", dict(low, cap=LINK_MAX)), ("set_cap_one", dict(low, cap=1)), ("used_token_zero", dict(low, tokens=((1, 0xFE, CONTRACT),))), ("used_later_token", dict(low, tokens=((0, 0, OTHER), (1, 2, CONTRACT)))), ("unused_flag_clear", dict(low, tokens=((0, 0, CONTRACT), (2, 2, CONTRACT)))),
                        ("used_last_byte", dict(low, tokens=((1, 0, CONTRACT[:19] + b"\x00"), (1, 2, OTHER)))), ("same_as_used_before_cap", dict(low, cap=5, tokens=((1, 0, CONTRACT),))), ("no_tokens", dict(address=CONTRACT, tokens=())),
                        ("unset", dict(address=bytes(20), cap=900, book=((0, (900, 0)),))), ("unset_above", dict(address=bytes(20), cap=900, book=((0, (1000, 0)),))), ("unset_short", dict(address=bytes(20), cap=901, book=((0, (900, 0)),))), ("unset_hold", dict(address=bytes(20), cap=900, book=((0, (1000, 100)),))), ("unset_hold_short", dict(address=bytes(20), cap=901, book=((0, (1000, 100)),))), ("unset_hold_wraps", dict(address=bytes(20), cap=WORD, book=((0, (WORD, 2)),))), ("unset_no_cap", dict(address=bytes(20), book=((0, (5, 0)),))), ("unset_no_cap_hold", dict(address=bytes(20), book=((0, (5, 6)),))), ("unset_no_row", dict(address=bytes(20), cap=1)), ("unset_no_row_no_cap", dict(address=bytes(20))), ("unset_native_zero", dict(address=bytes(20), cap=900, native=(1, 0), book=((0, (900, 0)),)))):
        out.append(Case("link", "link_" + label, **items))
    return out


def head_cases():
    out = []
    for label, items in (("mode_zero", dict(mode=0)), ("mode_one", dict(mode=1)), ("mode_two", dict(mode=2)), ("keeps_rows", dict(mode=1, new=2)), ("keeps_after_old", dict(mode=0, old=3, new=2))):
        out.append(Case("head", "head_" + label, **items))
    return out


def copy_cases():
    out = []
    for case in step_cases() + reconcile_cases():
        out.append(Case(case.kind, "copy_" + case.label, **dict(case.items, copy=True)))
    return out


def all_cases():
    return classify_cases() + drain_cases() + keep_cases() + retry_cases() + release_cases() + hold_cases() + reconcile_cases() + step_cases() + loop_cases() + link_cases() + head_cases() + [Case("gauge", "gauge_clears", gauge=(1 << 200) + 5)] + copy_cases()


SENTINELS = frozenset(("drain_keep_failed", "drain_keep_under_floor", "drain_linked_balance_below", "drain_rebalance_up", "drain_rebalance_down", "drain_erc20_data", "step_underflow_flags", "step_two_rows", "reconcile_all_parts", "classify_received", "classify_erc20"))


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
        begin, end = body_range(image, start)
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
    (0x2760b60, "e89b79ceff", "call of the block run in the step"),
    (0x2760bc4, "4983bc241031000000", "native queue length read at state +0x3110, result unused"),
    (0x2760c51, "e8eaf3ffff", "call of the supply check"),
    (0x2760c5e, "4883f802", "supply check tag against 2"),
    (0x2760c68, "83f803", "supply check tag against 3"),
    (0x2760c9e, "488b8098310000", "gauge top limb at state +0x3198"),
    (0x2760d4d, "c680a231000001", "halt byte set to 1 in the step"),
    (0x2760d7d, "e8de6fdbff", "call of the hold pass"),
    (0x2760df7, "4c8b742410", "state pointer before the map at +0x39d0"),
    (0x2760dfc, "4d8dbed0390000", "map at state +0x39d0"),
    (0x27611ea, "48c78424c0050000ad000000", "action tag 0xad"),
    (0x27611f6, "498b4650", "nonce word state +0x50 read"),
    (0x276120c, "41c6467801", "byte state +0x78 set around the apply"),
    (0x276125b, "e8e07fffff", "apply of the action"),
    (0x2761600, "4981fecc000000", "signed row tag against 0xcc"),
    (0x27616f2, "e8a96dffff", "apply of a signed row"),
    (0x276017c, "80b8d1000000fe", "token 0 byte +0xd1 against 0xfe"),
    (0x2760189, "8b88cd000000", "contract read from token row +0xcd"),
    (0x276039a, "e8a1b8ceff", "one EVM read"),
    (0x276042e, "e86dbaceff", "two EVM reads"),
    (0x27604da, "498b86483a0000", "cap word state +0x3a48"),
    (0x2760502, "498b8668310000", "held map root at state +0x3168"),
    (0x27605a1, "498b8628310000", "erc20 queue length state +0x3128"),
    (0x27605b8, "4881c194000000", "contract at row +0x94"),
    (0x276068c, "48c744244064000000", "constant 100"),
    (0x3270854, "488b153d4d5002", "code blob pointer of the first system contract"),
    (0x3270c15, "488bb240250000", "native queue capacity evm +0x2540"),
    (0x3270c23, "48c7824025000000000000", "capacity cleared"),
    (0x3270c57, "488b9a60250000", "erc20 queue pointer evm +0x2560"),
    (0x3270f4b, "0f10443038", "from of the linked transfer at value +0x40"),
    (0x3270f58, "0f1044304c", "target of the linked transfer at value +0x54"),
    (0x327110e, "48c7842458040000400d0300", "gas 200000 of the linked transfer"),
    (0x3271128, "c68424a804000004", "kind byte 4"),
    (0x3271148, "c7042401000000", "flag 1 on the stack"),
    (0x3271255, "c7042400000000", "flag 0 on the stack"),
    (0x327138a, "4881bc248003000000ca9a3b", "wei against 10^9"),
    (0x329941a, "48c74424705a000000", "90 of 100, the rebalance share"),
    (0x3299369, "48c7042464000000", "100, the rebalance divisor"),
    (0x329965e, "48c74318400d0300", "gas 200000 of the rebalance transfer"),
    (0x3299687, "c6436803", "kind byte 3"),
    (0x3730f45, "48c7431830750000", "gas 30000 of the native call"),
    (0x3730f4d, "c6436800", "kind byte 0"),
    (0x3730f9e, "c700a9059cbb", "selector a9059cbb, little endian immediate"),
    (0x37310f3, "ba400d0300", "gas 200000 of the transfer"),
    (0x3731125, "c7006ddde35e", "selector 6ddde35e, little endian immediate"),
    (0x373142b, "b002", "kind byte 2 in al"),
    (0x3427441, "41b901000000", "r9 = 1, validate flag of the Received decoder"),
    (0x3427535, "be0a000000", "decimals 10 of the native token"),
    (0x3427692, "41b622", "first byte 0x22 of the native system address"),
    (0x34276ad, "41b620", "first byte 0x20 of a token system address"),
    (0x3427521, "803900", "byte test of the native record"),
    (0x34277d0, "660f74442430", "to address compare"),
    (0x2517da4, "49837df000", "token word test of a row"),
    (0x2356007, "498b8548310000", "list length state +0x3148"),
    (0x235603c, "410fb65f08", "byte +8 of the action"),
    (0x2356017, "498b8d30310000", "list capacity state +0x3130"),
    (0x235a6fe, "4981c518310000", "erc20 queue at state +0x3118 in the retry"),
    (0x235b3c4, "4180bda231000000", "halt byte test of selector 3"),
    (0x235d02b, "498b8568310000", "held map root read"),
    (0x235b2b8, "66410f118590310000", "gauge clear"),
    (0x274b98f, "66c703df00", "status 0xdf"),
    (0x274bb0e, "c681bc00000001", "token 0 flag set"),
    (0x274bb28, "c681d1000000fe", "token 0 decimals byte 0xfe"),
    (0x274bbaa, "49bcffffffffffffff7f", "cap 2^63-1"),
    (0x274ba47, "49c786483a000000000000", "cap cleared"),
    (0x274bbc6, "4d89a6483a0000", "cap stored"),
    (0x271338c, "66b82600", "status 0x26 of the transfer core"),
    (0x271339b, "493b8c24483a0000", "cap compare in the transfer core"),
    (0x27133a9, "4180bc24a231000000", "halt byte test in the transfer core"),
    (0x27342ea, "80b9a231000001", "halt byte read in the withdraw core"),
    (0x4d8ebdc, "0fb68672130000", "shifted layout copy: byte +0x1372 for +0x8f2"),
    (0x4d8ec90, "498db42440160000", "shifted layout copy: EVM state at +0x1640"),
    (0x4d8ed1c, "4983bc24903b000000", "shifted layout copy: native queue length at +0x3b90"),
)

# ---- evidence ----

FRAGMENTS = {EVM_RUN: HEAD_END, LOG_LOOP: LOG_LOOP_END, RETRY_ARM: RETRY_END, RETRY_B: RETRY_B_END, RELEASE_ARM: RELEASE_END, RELEASE_B: RELEASE_B_END, SELECTOR_GAUGE: SELECTOR_GAUGE_END}


def body_range(image, start):
    if start in FRAGMENTS:
        return start, FRAGMENTS[start]
    return image.exact_fde(start)


def core_functions():
    return [(STEP, "EVM block step", True), (EVM_RUN, "head of the block run: environment, drain, keep list, slot take", True), (DRAIN, "queue drain to system transactions", True), (TX_OF_ROW, "queue row to system transaction", True), (TRANSFER_DATA, "transfer(address,uint256) calldata", True), (KEEP_EXTEND, "keep list append", True), (PENDING_ROWS, "rebalance row collect", True), (REBALANCE_ROW, "rebalance row of one linked token", True),
            (LOG_LOOP, "log loop of one transaction", True), (CLASSIFY, "log to L1 row", True), (RECEIVED_DECODE, "Received decoder", True), (ERC20_DECODE, "ERC20 event decoder", True), (WORD_READ, "32 byte word read", True), (RECONCILE, "supply check", True), (CHECKED_SUB, "U256 checked subtract, merged", False), (HOLD, "token 0 rows into the held map", True), (REQUEUE, "erc20 queue push of the retry arm", True),
            (RETRY_ARM, "raw 0x61 arm, pop and drop branch", True), (RETRY_B, "raw 0x61 arm, requeue branch", True), (RELEASE_ARM, "raw 0x5e selector 3, gate", True), (RELEASE_B, "raw 0x5e selector 3, pay held rows", True), (SELECTOR_GAUGE, "raw 0x5e selector 4, gauge clear", True), (LINK, "raw 0x5e selector 0, set or unset the token 0 contract", True),
            (STEP_COPIES[0], "EVM block step, copy with the same layout", False), (RECONCILE_COPY, "supply check, copy with the same layout", False), (SCALE, "wei scale, merged", False), (ERROR_DROP, "decoder error drop, shared", False), (REBALANCE_NEXT, "linked token map next, shared", False), (U256_DIV, "U256 division, merged", False), (U256_SUB, "U256 subtract, shared", False), (ABI_ENCODE, "ABI encoder, shared", False), (ROW_ITER_DROP, "queue iterator drop, shared", False), (PAIR_TIMES_100, "pair times 100, shared", False), (U256_MUL, "U256 product, shared", False), (TREE_SUM, "map value sum, shared", False), (TREE_NEXT, "map take next, shared", False), (GAS_ENTRY, "map entry, shared", False), (HELD_ENTRY, "map entry, shared", False)]


GATES = (
    ("0x2760a70", 1, "run the block with mode dl, take rows, signed rows and the user map", "-"), ("0x2760a70", 2, "sum amount of rows with token 0, saturating", "-"), ("0x2760a70", 3, "supply check with that sum", "-"), ("0x2760a70", 4, "check tag 2: nothing", "-"), ("0x2760a70", 5, "check tag 1: value above the U256 at +0x3180 replaces it", "-"), ("0x2760a70", 6, "check tag 0 or 3 with +0x31a2 clear: set +0x31a2, recorder 3", "-"), ("0x2760a70", 7, "+0x31a2 set after that: token 0 rows leave the list for the map at +0x3168", "-"), ("0x2760a70", 8, "user map adds to the row at +0x39d0, saturating", "-"), ("0x2760a70", 9, "each row left: nonce +0x50 up, +0x78 set, action 0xad applied from the token system address, +0x78 clear, counter up", "-"), ("0x2760a70", 10, "each signed row until tag 0xcc: applied with a stamp when the counter tag is 1", "-"),
    ("0x3270830", 1, "code of 0x3333.., 0x2222.., 0x5555..", "-"), ("0x3270830", 2, "each row of spot +0x278 in token order, as flag 1 transactions: token +0xbc bit 0 clear skips, balance of token contract and of value +0x40 at target value +0x54, none or a carry skips, goal = total / 100 * 90, goal above the second balance: transfer of the gap from the token contract to value +0x40, below: from value +0x40 to the token contract, gas 200000, kind 3", "-"), ("0x3270830", 3, "take both queues", "-"), ("0x3270830", 4, "native rows: value call, gas 30000, kind 0", "-"), ("0x3270830", 5, "erc20 row with a token row in spot +0x278: balance read, min of balance and wei, non zero: transfer call, gas 200000, kind 4, flag 1", "-"), ("0x3270830", 6, "erc20 row: transfer call, gas 200000, kind 1, or data call, row gas, kind 2", "-"), ("0x3270830", 7, "third address 0x20.. with no receipt or a failed one and wei at or above 10^9: row kept", "-"),
    ("0x34273d0", 1, "log address 0x22..: Received decoder with validation", "-"), ("0x34273d0", 2, "decoded, amount not 0, spot +0x80 low byte not 0: scale by 10, a scale refusal ends with no row", "-"), ("0x34273d0", 3, "address in the contract map, else no row", "-"), ("0x34273d0", 4, "system address of the mapped token", "-"), ("0x34273d0", 5, "ERC20 decoder with validation: only Transfer goes on", "-"), ("0x34273d0", 6, "to equals the system address, else no row", "-"), ("0x34273d0", 7, "scale by the map byte, a refusal ends with no row", "-"),
    ("0x2760040", 1, "balance of token 0 at its system address", "-"), ("0x2760040", 2, "token 0 row missing or +0xbc clear", "tag 2"), ("0x2760040", 3, "+0xd1 not 0xfe", "tag 3"), ("0x2760040", 4, "one or two EVM reads, none", "tag 3"), ("0x2760040", 5, "both reads times 100, saturating", "-"), ("0x2760040", 6, "balance + read 0 + read 1 carries", "tag 0"), ("0x2760040", 7, "less the word +0x3a48, the held sum + argument, 100 times the erc20 queue wei for that contract, any step under zero", "tag 0"), ("0x2760040", 8, "value left", "tag 1"),
    ("0x235b3c4", 1, "+0x31a2 set: nothing", "-"), ("0x235b3c4", 2, "supply check with argument 0, tag not 1: nothing", "-"), ("0x235d00f", 3, "take the map at +0x3168, each row through the transfer core from the token 0 system address", "failure dropped"),
    ("0x2356007", 1, "empty list: nothing", "-"), ("0x2356007", 2, "pop front of the list at +0x3130", "-"), ("0x2356007", 3, "byte +8 not 0: drop the row", "-"), ("0x235a6ca", 4, "byte +8 is 0: drop the data, push to +0x3118 with no length test", "-"),
    ("0x274b7e0", 1, "address not zero, tokens empty", "panic"), ("0x274b7e0", 2, "address is a contract of a token with +0xbc bit 0", "0xdf " + LINK_USED_TEXT), ("0x274b7e0", 3, "cap +0x3a48 not 0", "0xdf " + LINK_FIRST_TEXT), ("0x274b7e0", 4, "set: token 0 row takes the address and 0xfe, balance moves from the system address to address zero, the system address takes 2^63-1, cap takes 2^63-1", "0x186"), ("0x274b7e0", 5, "zero address: cap + word 1 wraps or passes word 0", "0xdf " + LINK_UNSET_TEXT), ("0x274b7e0", 6, "unset: cap debited, cap 0", "0x186"),
)
RECORD_ROWS = (
    ("L1 to EVM system transaction, 0x70 bytes", "+0x00", "calldata Vec capacity, pointer, length"), ("L1 to EVM system transaction, 0x70 bytes", "+0x18", "gas limit"), ("L1 to EVM system transaction, 0x70 bytes", "+0x20", "value, U256 little endian"), ("L1 to EVM system transaction, 0x70 bytes", "+0x40", "from, 20 bytes"), ("L1 to EVM system transaction, 0x70 bytes", "+0x54", "to, 20 bytes"), ("L1 to EVM system transaction, 0x70 bytes", "+0x68", "kind byte: 0 native, 1 transfer, 2 data call, 3 rebalance, 4 linked transfer"),
    ("drain output", "+0x00", "Vec of 0x110 byte results, tail at +0xe0 with word 0 = 1 shl 63 for none and bit 0 of +0x100 for success"), ("drain output", "+0x18", "Vec of kept 0xc0 byte rows, appended to the list at state +0x3130"), ("drain output", "+0x30", "the 3 words the caller passes to every execution"),
    ("log, 0x50 bytes", "+0x00", "topics Vec capacity, pointer, length, 32 byte rows"), ("log, 0x50 bytes", "+0x18", "bytes::Bytes data"), ("log, 0x50 bytes", "+0x38", "address, 20 bytes"),
    ("EVM to L1 row, 0x48 bytes", "+0x00", "transaction hash"), ("EVM to L1 row, 0x48 bytes", "+0x20", "token"), ("EVM to L1 row, 0x48 bytes", "+0x28", "amount"), ("EVM to L1 row, 0x48 bytes", "+0x30", "user, 20 bytes"),
    ("action 0xad", "+0x00", "tag 0xad, SystemSpotSendAction in RE-010"), ("action 0xad", "+0x08", "token"), ("action 0xad", "+0x10", "amount"), ("action 0xad", "+0x18", "user"),
    ("step result, 0x130 bytes", "+0x00", "action, 0xf0 bytes"), ("step result, 0x130 bytes", "+0xf0", "response, byte 0xe with a text, else the response record"), ("step result, 0x130 bytes", "+0x118", "acting address"),
    ("signed row, 0x128 bytes", "+0x00", "action tag, 0xcc ends the list"), ("signed row, 0x128 bytes", "+0xf0", "sender"), ("signed row, 0x128 bytes", "+0x104", "32 bytes passed to the apply function"),
    ("state", "+0x3100", "native queue, Vec, evm +0x2540"), ("state", "+0x3118", "erc20 queue, Vec, evm +0x2558"), ("state", "+0x3130", "kept rows, VecDeque capacity, pointer, head, length, evm +0x2570"), ("state", "+0x3168", "map user to u64, held token 0 rows"), ("state", "+0x3180", "U256 gauge, highest supply check value"), ("state", "+0x31a2", "halt byte"), ("state", "+0x39d0", "map user to 32 byte row, word 0 takes the block user map"), ("state", "+0x3a48", "token 0 cap, 2^63-1 while linked"), ("state", "+0xbc0", "EVM state, argument of the block run"),
    ("spot +0x278 value, 0x68 bytes", "+0x40", "from of the linked transfer, holder that gets 90 of 100"), ("spot +0x278 value, 0x68 bytes", "+0x54", "target of the linked transfer, the rebalance transfer and each balance read"),
)
TEXTS = ("l1_to_evm_native_token_queue", "l1_to_evm_erc20_queue", "l1_transfers_enabled", "disabled_core_writer_actions", "user_to_evm_to_l1_wei_remaining", "evm_transfer_escrows", "token_to_pending_evm_contract", "struct L1ToEvmErc20Transfer with 6 elements", "struct L1ToEvmNativeTokenTransfer", "SetUsdcEvmContract", "initial_usdc_evm_system_balance", "evm_minted_supply", "IERC20Events", "EvmTransferEvents", EVENT_DATA_TEXT, TRANSFER_TEXT, APPROVAL_TEXT, "SystemSpotSendAction", "CoreWriterEvents")
FIELDS = (0x31A2, 0x3180, 0x3168, 0x3A48, 0x3148, 0x2540, 0x2558, 0x2570)
KEY_ROWS = KEY_ROW_TEXT


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
    direct = {STEP: "block step", STEP_COPIES[0]: "block step copy", STEP_COPIES[1]: "block step, shifted layout", EVM_RUN: "block run", EVM_RUN_COPIES[0]: "block run copy", EVM_RUN_COPIES[1]: "block run copy", RECONCILE: "supply check", RECONCILE_COPY: "supply check copy", HOLD: "hold pass", KEEP_EXTEND: "keep list append", REQUEUE: "retry push", LINK: "contract set or unset", TX_OF_ROW: "row to transaction", TRANSFER_DATA: "transfer calldata", PENDING_ROWS: "rebalance row collect", REBALANCE_ROW: "rebalance row"}
    slots = {0x5774008: "drain through slot", 0x5774038: "classifier through slot", 0x5774048: "core writer decoder through slot", 0x5775D38: "Received decoder through slot", 0x5775D40: "ERC20 decoder through slot"}
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


FIELD_OPCODES = frozenset((0x89, 0x8B, 0x8D, 0x39, 0x3B, 0x01, 0x03, 0xC7, 0x83, 0x81, 0x6F, 0x7F, 0x10, 0x11, 0x28, 0x29, 0x80, 0xFF, 0xF7, 0x85, 0xB6, 0xB7, 0x88, 0x8A, 0xC6, 0x63))


def field_lines(image):
    """Displacement census by byte pattern: a mod 10 ModRM byte and an opcode byte in front of the 32 bit offset. Unrelated structs can share an offset."""
    base, text = image.text_bytes()
    lines = ["offset\thost\tsites"]
    for value in FIELDS:
        hosts = collections.Counter()
        for match in re.finditer(re.escape(struct.pack("<I", value)), text):
            at = match.start()
            for back in (1, 2):
                modrm = text[at - back]
                if modrm >> 6 == 2 and ((modrm & 7) == 4) == (back == 2) and text[at - back - 1] in FIELD_OPCODES:
                    try:
                        hosts[image.fde(base + at)[0]] += 1
                    except EvidenceError:
                        pass
                    break
        for host, count in sorted(hosts.items()):
            lines.append("%#x\t%#x\t%d" % (value, host, count))
    return lines


def text_lines(image):
    start, data = image.rodata_bytes()
    lines = ["text\tfirst_address\tcount"]
    for text in TEXTS:
        raw = text.encode("ascii")
        at = data.find(raw)
        if at < 0:
            raise EvidenceError("text moved: " + text)
        lines.append("%s\t%#x\t%d" % (text, start + at, data.count(raw)))
    return lines


def signature_lines(image):
    """Keccak of the three event texts against the 32 bytes the decoders compare."""
    low = code(image, TOPIC_LOW[0], 16) + code(image, TOPIC_LOW[1], 16)
    if low != RECEIVED:
        raise EvidenceError("Received topic differs")
    if code(image, SIGNATURE_AT, len(EVENT_DATA_TEXT)).decode() != EVENT_DATA_TEXT:
        raise EvidenceError("Received text differs")
    lines = ["text\tkeccak256\trodata"]
    lines.append("%s\t%s\t%#x + %#x" % (EVENT_DATA_TEXT, RECEIVED.hex(), TOPIC_LOW[0], TOPIC_LOW[1]))
    for text, digest, at in ((TRANSFER_TEXT, TRANSFER, 0x20C6C0), (APPROVAL_TEXT, APPROVAL, 0x20BCE0)):
        if code(image, at, 32) != digest:
            raise EvidenceError("topic differs: " + text)
        lines.append("%s\t%s\t%#x" % (text, digest.hex(), at))
    for at, hexed in SYSTEM_TEXT:
        if code(image, at, 20).hex() != hexed:
            raise EvidenceError("system address differs at %#x" % at)
        lines.append("system address\t%s\t%#x" % (hexed, at))
    return lines


def table_lines(image):
    lines = ["table\trow\ttarget"]
    for index in range(8):
        lines.append("raw 0x5e selector\t%d\t%#x" % (index, SELECTOR_TABLE + struct.unpack_from("<i", image.blob, image.offset(SELECTOR_TABLE) + 4 * index)[0]))
    for row in (0x5E, 0x61):
        lines.append("VoteGlobal raw tag\t%#x\t%#x" % (row, VOTE_TABLE + struct.unpack_from("<i", image.blob, image.offset(VOTE_TABLE) + 4 * (row - 0x12))[0]))
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
        lines.append("\t".join((case.kind, case.label, " ".join("%s=%d" % item for item in sorted(harness.tally.items())) or "-", "fail" if trouble else "match")))
        for key, value in harness.tally.items():
            OUTCOMES[key] += value
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    for start, role, _ in core_functions():
        begin, end = body_range(image, start)
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
        "constants": {"gas_native": GAS_NATIVE, "gas_erc20": GAS_ERC20, "action_tag": ACTION_TAG, "row_end_tag": ROW_END_TAG, "keep_floor_wei": KEEP_FLOOR, "native_decimals": NATIVE_DECIMALS, "usd_decimals_byte": USD_DECIMALS_BYTE, "link_cap": LINK_MAX, "selector_transfer": SELECTOR_TRANSFER, "selector_data": SELECTOR_DATA},
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_sites": site_lines(image), "_status": status_lines, "_layouts": layout_lines, "_keys": key_row_lines(image), "_gates": gate_lines, "_records": record_lines, "_fields": field_lines(image), "_texts": text_lines(image), "_signatures": signature_lines(image), "_tables": table_lines(image),
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, or an arm behind a stub"
SURVIVOR_REASON = "not hand checked row by row: copy size, stack base, error payload words no rule reads, or a value only a stub reads"
OUTCOMES = collections.Counter()


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toutcomes\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "call-sites.tsv": evidence.pop("_sites"), "status-text.tsv": evidence.pop("_status"), "node-layouts.tsv": evidence.pop("_layouts"), "key-rows.tsv": evidence.pop("_keys"), "gates.tsv": evidence.pop("_gates"), "record-fields.tsv": evidence.pop("_records"),
              "field-sites.tsv": evidence.pop("_fields"), "rodata-texts.tsv": evidence.pop("_texts"), "signatures.tsv": evidence.pop("_signatures"), "jump-rows.tsv": evidence.pop("_tables")}
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
