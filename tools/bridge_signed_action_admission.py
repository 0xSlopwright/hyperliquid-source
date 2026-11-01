#!/usr/bin/env python3
"""Evaluate the node #94 signed action admission from ELF bytes: signer to acting address, multi sig threshold, vault and sub-account arms, the record words and the class order of a bundle.

The record writers, their map loops, the signer resolvers, the agent lookups, the multi sig bodies, the asset gates and the class partition run as real bytes in a Python evaluator.
A separately written rule list predicts each record, status and stub event, and conditions, immediates and offsets of the reached rows are flipped to show the run can tell.
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
SLOT_ONCE = 0x576E8B8
SLOT_RECOVER = 0x57731F8
SLOT_SIGNATURE = 0x5773210
SLOT_VALIDATOR = 0x5773148
SLOT_IS_SUB = 0x5773218
SLOT_MASTER = 0x5773220
SLOT_LIST_A = 0x5773228
SLOT_LIST_B = 0x5773230
SLOT_DEX_META = 0x5773950
SLOT_ORDERS_TEST = 0x5775C50
SLOT_CLASS = 0x5773200
SLOT_TOUCH = 0x5773208
SLOT_SORT_A = 0x5773A00
SLOT_SORT_B = 0x5773A10
EMPTY_TABLE = 0x5732CE8

RECOVER = 0x333FC80
PARSES = (0X43A31B0, 0X43A31B0, 0X1B2C1C0)
CONVERTS = (0x46BCB90, 0x46BCD60, 0x1E64010)
CONVERT_CORES = (0x4D9E4B0, 0x4D9F0D0, 0x27693D0)
STORE = 0x3426290
STORE_INSERT = 0x339CAB0
MAP_REMOVE = 0x33AA550
LINKS = 0x3810
MAX_JSON = 0x3E9
MAX_SIGNERS = 10
SIGNATURE = 0x3360B40
VALIDATOR = 0x33690C0
HASHER = 0x399C7A0
CLASS_FN = 0x335ECB0
TOUCH_FN = 0x335ECD0
SORT_A = 0x3363370
SORT_B = 0x3362F30
SORTER = 0x446FAB0
CHAIN = 0x4873270
LIST_SCAN = 0x3C1D690
VAULT_FIND = (0x45A3F20, 0x45A3F20, 0x25A7BF0)
SET_REMOVE = (0x4945FB0, 0x4945FB0, 0x2867580)
SET_ADD = (0x4932AD0, 0x4932AD0, 0x4932AD0)
ASSET_ERROR_DROP = (0x472F840, 0x472F840, 0x1EAD7F0)
VALIDATOR_DROP = 0x3379490
LAZY = (0x577AE70, 0x577AEA0)
LAZY_INIT = (0x1451FB0, 0x14520E0)
MAGIC_USER = bytes(19) + b"\x07"
CLASS_TABLE = 0x58C1D8
TOUCH_TABLE = 0x588A7C
SORT_A_TABLE = 0x58983C
SORT_B_TABLE = 0x58941C
RESOLVE_TABLE = 0x6FFED4
ASSET_TABLE = 0x6FFEE4
ROWS = 86
MULTI_MASK = 0x80000006408
MULTI_TAG = 0xA8
NOOP_TAG = 0x74
ROW_BASE = 0x74
LOW_ROW = 0x14
MULTI_ROW = 52
MAX_SIGS = 0x2710
STATUS_TAGS = (0x7, 0x15, 0x58, 0x7B, 0x7C, 0x7D, 0xBD, 0xDB, 0xDC, 0x112, 0x113, 0x114, 0x115, 0x116, 0x117, 0x118, 0x119, 0x11A, 0x11B, 0x11C, 0x11D, 0x11E, 0x143, 0x15E, 0x186)
MUTANT_STEP_LIMIT = 60000
MUTANT_CASES = 8
MUTANT_CASE_COST = 9000
WORKERS = 4

STATUS_OK = 0x186
STATUS_END = 0x187
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

HEAP_FREE = HEAP_BASE + 0x40000
OUT_AT = HEAP_BASE + 0x1000
KEY_AT = HEAP_BASE + 0x2140
ARG_AT = HEAP_BASE + 0x2200
ENV_AT = HEAP_BASE + 0x3000
INNER_AT = HEAP_BASE + 0x9000
SIGS_AT = HEAP_BASE + 0xA000
STATE_AT = HEAP_BASE + 0x10000
ROWLIST_AT = HEAP_BASE + 0x20000

# offsets of the state fields in the second layout; the first layout adds 0xa80, except USERS
CHAIN_BYTE = 0x8F2
MULTI_MAP = 0x39E8
AGENTS = 0x3730
VAULTS = 0x8D0
SUBS = 0x37E0
VALIDATORS = 0x3840
VALIDATOR_WORD = 0x3888
DEX_ROWS = 0x5C0
USERS = 0x318
COPY_SHIFT = 0xA80

COPIES = (
    {"core": 0x46D49B0, "wrap": 0x4550650, "multi": 0x4C5CA60, "resolve": 0x48F5570, "agent": 0x4D8B030, "assets": 0x48F58A0, "shift": 0, "name": "second layout"},
    {"core": 0x46D54D0, "wrap": 0x45524A0, "multi": 0x4C5C2D0, "resolve": 0x48F52E0, "agent": 0x4D8B3B0, "assets": 0x48F5A30, "shift": COPY_SHIFT, "name": "first layout"},
    {"core": 0x1E8DB10, "wrap": 0x2584BB0, "multi": None, "resolve": 0x282EC60, "agent": 0x275EA20, "assets": 0x282EEA0, "shift": 0, "name": "third copy, multi sig inlined"},
)

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



# ---- harness: real bytes through .text; the allocator and memory slots are hooked, every signature, the validator row and the sub-account rows are fed in ----

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
SIGNER_NODE = Layout("authorized signer set", 8, 20, 0, 0, 0xE6, 0xE8, 0, 0xE4)
VAULT_NODE = Layout("vault map", 0x798, 20, 0, 0xB0, 0x876, 0x878, 0x790, 0x874)
LAYOUTS = (MULTI_NODE, SIGNER_NODE, VAULT_NODE)


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
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {}
        machine.tails = machine.calls
        machine.watch = {}
        hooks = {RECOVER: self.on_recover, SIGNATURE: self.on_signature, VALIDATOR: self.on_validator, relative[SLOT_IS_SUB]: self.on_is_sub, relative[SLOT_MASTER]: self.on_master, relative[SLOT_LIST_A]: self.on_list_a, relative[SLOT_LIST_B]: self.on_list_b,
                 relative[SLOT_DEX_META]: self.on_meta, relative[SLOT_ONCE]: self.on_once, PARSES[0]: self.on_parse, PARSES[1]: self.on_parse, PARSES[2]: self.on_parse, VALIDATOR_DROP: self.on_nothing, 0x3C1ADA0: self.on_nothing, 0x447CB60: self.on_nothing}
        for drop in ASSET_ERROR_DROP:
            hooks[drop] = self.on_asset_drop
        for item in COPIES:
            for target in leaf_targets(image, item["assets"]):
                hooks[target] = self.on_leaf
        machine.slots.update(hooks)
        machine.calls.update(hooks)
        harness_stubs = frozenset(machine.slots) | frozenset(machine.calls)
        self.real.stubs = harness_stubs
        self.tables = Tables(image)
        self.lazy = self.tables.lazy
        self.tally = collections.Counter()
        self.panic_text = ""
        self.case = None
        self.reset()

    def reset(self):
        self.machine.memory.reset(USED)
        self.machine.memory.statics.clear()
        self.machine.memory.statics.update(self.base_statics)
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

    def on_nothing(self, m):
        pass

    def on_panic(self, m, slot):
        if slot == SLOT_PANIC_TEXT:
            self.panic_text = m.memory.bytes_at(m.regs[RDI], m.regs[RSI]).decode("ascii")
        raise Panicked("%#x" % slot)

    # stubs fed from the case

    def on_recover(self, m):
        self.index = (m.regs[RSI] - ENV_AT) // ENV_STEP
        case = self.case = self.current[self.index]
        self.events.append(("recover", m.regs[RSI] - ENV_AT, m.regs[RDX] & 0xFF))
        out = m.regs[RDI]
        m.memory.put_bytes(out, filled("recover error", 0x60))
        m.memory.write(out, 2, case.recover)
        m.memory.put_bytes(out + 2, case.signer)

    def on_signature(self, m):
        out = m.regs[RDI]
        row = m.memory.read(m.regs[RSP], 8)
        context = m.regs[R9]
        self.events.append(("signature", (row - SIGS_AT) // 0x48, m.regs[RDX] & 0xFF, m.memory.bytes_at(m.regs[RCX], 20).hex(), m.memory.bytes_at(m.regs[R8], 20).hex(), m.regs[RSI] - INNER_AT,
                            m.memory.read(context, 8), m.memory.read(context + 8, 8), m.memory.read(context + 0x10, 8), m.memory.bytes_at(context + 0x18, 21).hex()))
        m.memory.put_bytes(out, filled("signature error", 0x60))
        m.memory.write(out, 2, m.memory.read(row, 2))
        m.memory.put_bytes(out + 2, m.memory.bytes_at(row + 2, 20))

    def on_validator(self, m):
        address = m.memory.bytes_at(m.regs[RDX], 20)
        self.events.append(("validator", address.hex(), m.regs[RSI] - STATE_AT, m.regs[RCX]))
        m.memory.put_bytes(m.regs[RDI], filled("validator error", 0x60))
        m.memory.write(m.regs[RDI], 2, STATUS_OK if address in self.case.validators else 0x97)

    def on_is_sub(self, m):
        address = m.memory.bytes_at(m.regs[RSI], 20)
        self.events.append(("is sub", address.hex(), m.regs[RDI] - STATE_AT))
        m.regs[RAX] = int(address in self.case.subs)

    def on_master(self, m):
        address = m.memory.bytes_at(m.regs[RDX], 20)
        self.events.append(("master", address.hex(), m.regs[RSI] - STATE_AT))
        master = self.case.subs.get(address)
        out = m.regs[RDI]
        m.memory.put_bytes(out, filled("master", 21))
        if master is None:
            m.memory.write(out, 1, 0)
        else:
            m.memory.write(out, 1, 1)
            m.memory.put_bytes(out + 1, master)

    def on_list_a(self, m):
        address = m.memory.bytes_at(m.regs[RDI], 20)
        self.events.append(("list a", address.hex()))
        m.regs[RAX] = int(address in self.case.list_a)

    def on_list_b(self, m):
        address = m.memory.bytes_at(m.regs[RDI], 20)
        self.events.append(("list b", address.hex()))
        m.regs[RAX] = int(address in self.case.list_b)

    def on_meta(self, m):
        self.events.append(("dex meta", m.regs[RSI] & MASK[4]))
        out = m.regs[RDI]
        meta = self.case.meta
        m.memory.put_bytes(out, filled("meta", 0x60))
        if meta[0] == "error":
            m.memory.write(out, 2, meta[1])
            return
        m.memory.write(out, 2, STATUS_OK)
        m.memory.write(out + 8, 4, 1 if meta[0] == "absent" else 0)
        if meta[0] == "value":
            m.memory.write(out + 0x10, 8, meta[1])

    def on_once(self, m):
        at = m.regs[RDI] - 0x28
        which = LAZY.index(at)
        self.events.append(("once", which))
        keys = sorted(self.lazy[which])
        node = self.tree(SIGNER_NODE, [(key, b"") for key in keys])
        statics = m.memory.statics
        statics[at], statics[at + 8] = node

    def on_leaf(self, m):
        out = m.regs[RDI]
        self.events.append(("leaf",))
        leaf = self.case.leaf
        if leaf[0] == "error":
            m.memory.put_bytes(out, filled("leaf error", 0x60))
            m.memory.write(out, 2, leaf[1])
        elif leaf[0] == "none":
            m.memory.write(out, 2, STATUS_OK)
            m.memory.write(out + 8, 8, 0)
        else:
            m.memory.write(out, 2, STATUS_OK)
            m.memory.write(out + 8, 8, 1)
            m.memory.put_bytes(out + 0x10, m.memory.bytes_at(DEXES_AT + 0x18 * self.dex_used, 0x18))
            self.dex_used += 1

    def on_parse(self, m):
        fix = self.case
        out = m.regs[RDI]
        self.events.append(("parse", m.memory.read(m.regs[RSI], 8), m.memory.read(m.regs[RSI] + 8, 8)))
        if fix.parse_error:
            m.memory.write(out, 8, 2)
            m.memory.write(out + 8, 8, 0x77)
            return
        self.parsed(out)

    def parsed(self, out):
        memory = self.machine.memory
        fix = self.case
        if fix.signers is None:
            memory.put_bytes(out, bytes(0x28))
            return
        rows = [(key, b"") for key in sorted(fix.signers)]
        root, height = self.tree(SIGNER_NODE, rows) if rows else (0, 0)
        for offset, word in ((0, 1), (8, root), (0x10, height), (0x18, len(rows)), (0x20, fix.threshold)):
            memory.write(out + offset, 8, word)

    def on_asset_drop(self, m):
        self.events.append(("asset error dropped",))

    # fixtures

    def run_at(self, entry, args):
        return self.machine.run(entry, args)

    def tree(self, layout, rows):
        """Balanced tree over sorted (key, value) rows, height 0 or 1. Returns root, height."""
        memory = self.machine.memory

        def leaf(chunk):
            at = self.allocate(layout.leaf)
            memory.put_bytes(at, filled("node", layout.leaf))
            memory.write(at + layout.parent_at, 8, 0)
            for index, (key, value) in enumerate(chunk):
                memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
                if layout.value_size:
                    memory.put_bytes(at + layout.value_at + layout.value_size * index, value)
            memory.write(at + layout.count_at, 2, len(chunk))
            return at
        if len(rows) <= 11:
            return leaf(rows), 0
        parts = [rows[index:index + 6] for index in range(0, len(rows), 7)]
        separators = [rows[index] for index in range(6, len(rows) - 1, 7)]
        parts = parts[:len(separators) + 1]
        at = self.allocate(layout.leaf + 0x60)
        memory.put_bytes(at, filled("inner node", layout.leaf + 0x60))
        memory.write(at + layout.parent_at, 8, 0)
        for index, (key, value) in enumerate(separators):
            memory.put_bytes(at + layout.key_at + layout.key_size * index, key)
            if layout.value_size:
                memory.put_bytes(at + layout.value_at + layout.value_size * index, value)
        memory.write(at + layout.count_at, 2, len(separators))
        for index, chunk in enumerate(parts):
            child = leaf(chunk)
            memory.write(at + layout.leaf + 8 * index, 8, child)
            memory.write(child + layout.parent_at, 8, at)
            memory.write(child + layout.index_at, 2, index)
        return at, 1

    def empty_table(self, at, seed=(0x0706050403020100, 0x0F0E0D0C0B0A0908)):
        memory = self.machine.memory
        for offset, word in ((0, self.relative[EMPTY_TABLE]), (8, 0), (0x10, 0), (0x18, 0), (0x20, seed[0]), (0x28, seed[1])):
            memory.write(at + offset, 8, word)

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


# ---- static tables read from .rodata and the arm bytes ----

def rodata_table(image, base, count):
    return struct.unpack_from("<%di" % count, image.blob, image.offset(base))


def table_targets(image, base, count=ROWS):
    return [base + value for value in rodata_table(image, base, count)]


ASSET_BUILDERS = (0x4A00BC0, 0x4A00AA0, 0x28E3FA0)
ASSET_TABLES = (ASSET_TABLE, 0x700044, 0x3F2C78)
RESOLVE_TABLES = (RESOLVE_TABLE, 0x6FFEC4, 0x3F2C68)


def leaf_targets(image, assets):
    """Direct call targets of an asset gate, the shared dex builder left out."""
    begin, end = image.exact_fde(assets)
    return sorted({row.target for row in body_rows(image, begin, end) if row.op == "call" and row.target and row.target not in ASSET_BUILDERS})


def asset_arm(image, target):
    """Shape of one arm of the asset gate, from fixed byte patterns."""
    data = code(image, target, 16)
    if data[:5] == b"\x48\xc7\x47\x08\x00":
        return ("none",)
    if data[:5] == b"\x48\xc7\x47\x08\x01":
        return ("empty",)
    if data[:4] == b"\x48\x8b\x76\x20":
        return ("multi",)
    if data[:2] == b"\x8b\x76":
        return ("field", data[2])
    if data[:4] == b"\x48\x8d\x46\x08" and data[4:8] == b"\x48\x81\x7e\x18":
        return ("list", 0x18)
    if data[:4] == b"\x48\x8d\x46\x20" and data[4:8] == b"\x48\x81\x7e\x30":
        return ("list", 0x30)
    if data[:2] == b"\x48\x83" or data[:3] == b"\x48\x89\xfb":
        return ("leaf",)
    raise EvidenceError("asset arm shape at %#x: %s" % (target, data.hex()))


class Tables:
    """Row tables of the action tag, read once."""

    def __init__(self, image):
        self.klass = list(code(image, CLASS_TABLE, ROWS))
        self.touch = []
        for target in table_targets(image, TOUCH_TABLE):
            self.touch.append({0x335ED1C: 0, 0x335ECF6: 2, 0x335ED1F: 1, 0x335ED00: "inner"}[target])
        self.sort_a = []
        for target in table_targets(image, SORT_A_TABLE):
            self.sort_a.append({0x3363396: 0, 0x33633BE: 1, 0x33633A0: "inner"}[target])
        self.sort_b = []
        for target in table_targets(image, SORT_B_TABLE):
            self.sort_b.append({0x3362F5A: 0, 0x3362F7E: "orders", 0x3362F8C: "modify", 0x3362F9D: "bulk", 0x3362F60: "inner"}[target])
        self.assets = [[asset_arm(image, target) for target in table_targets(image, base)] for base in ASSET_TABLES]
        self.resolve = [table_targets(image, base, 4) for base in RESOLVE_TABLES]
        self.lazy = [lazy_list(image, init) for init in LAZY_INIT]


def lazy_list(image, init):
    """Three addresses: a movups of 16 rodata bytes followed by a movl of the last four, read by fixed pattern."""
    begin, end = image.exact_fde(init)
    data = code(image, begin, end - begin)
    found = []
    at = data.find(b"\x0f\x10\x05")
    while at >= 0 and len(found) < 3:
        source = begin + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
        tail = data[at + 7:at + 25]
        move = tail.find(b"\xc7\x44\x24\x10")
        if move < 0:
            raise EvidenceError("lazy list row moved")
        found.append(code(image, source, 16) + tail[move + 4:move + 8])
        at = data.find(b"\x0f\x10\x05", at + 8)
    if len(found) != 3:
        raise EvidenceError("lazy list is not three rows")
    return found


def filled(name, size):
    """Distinct bytes for a field no rule reads, so a wrong offset shows."""
    seed = hashlib.sha256(name.encode()).digest()
    return (seed * (size // 32 + 1))[:size]


# ---- rule list: written from the reading, checked against the real run ----

ADDRESSES = tuple(bytes([0x20 + index * 3]) * 18 + bytes([0x40 + index, index]) for index in range(24))
SIGNER, USER, AGENT, OTHER, VAULT, LEADER, MULTI, COSIGNER, THIRD, MASTER, SUB, TOP = ADDRESSES[:12]
ENV_STEP = 0x168
INNER_STEP = 0x100
ORDERS_AT = HEAP_BASE + 0xE000
DEXES_AT = HEAP_BASE + 0x2300
DEX_SETS = 8


def row_of(tag):
    return tag - ROW_BASE if tag >= ROW_BASE else LOW_ROW


class Fix:
    """One signed action and the state it meets."""

    defaults = {"recover": STATUS_OK, "signer": SIGNER, "tag": 0x75, "inner": 0x75, "vault": None, "multi_user": MULTI, "outer": SIGNER, "sigs": (), "sig_count": None, "chain": 1, "validators": frozenset(), "agents": (), "dex_rows": (), "users": frozenset(),
                "multi": (), "vaults": (), "subs": (), "list_a": frozenset(), "list_b": frozenset(), "leaf": ("set", ()), "meta": ("value", 0), "list_len": 1, "orders": (), "tif": 0, "trigger": 0, "parse_error": False, "signers": None, "threshold": 0, "json_len": 0x40, "links": frozenset(), "convert_user": USER}

    def __init__(self, **values):
        for key, value in self.defaults.items():
            setattr(self, key, value)
        for key, value in values.items():
            if key not in self.defaults:
                raise EvidenceError("unknown field " + key)
            setattr(self, key, value)
        self.agents = dict(self.agents)
        self.multi = dict(self.multi)
        self.vaults = dict(self.vaults)
        self.subs = dict(self.subs)


class Case:
    __slots__ = ("kind", "label", "copy", "fixes", "state", "end")

    def __init__(self, kind, label, copy, fixes, end=None):
        self.kind, self.label, self.copy, self.fixes = kind, label, copy, fixes
        self.end = end


def state_of(harness, fix, shift):
    """Writes every state field the path reads."""
    memory = harness.machine.memory
    memory.put_bytes(STATE_AT, filled("state", 0x5000))
    memory.write(STATE_AT + CHAIN_BYTE + shift, 1, fix.chain)
    rows = []
    for user in sorted(fix.multi):
        signers, threshold = fix.multi[user]
        root, height = harness.tree(SIGNER_NODE, [(key, b"") for key in sorted(signers)]) if signers else (0, 0)
        rows.append((user, struct.pack("<QQQQ", root, height, len(signers), threshold)))
    root, height = harness.tree(MULTI_NODE, rows) if rows else (0, 0)
    for offset, word in ((0, root), (8, height), (0x10, len(rows))):
        memory.write(STATE_AT + MULTI_MAP + shift + offset, 8, word)
    rows = []
    for vault in sorted(fix.vaults):
        value = filled("vault value", 0xB0)
        rows.append((vault, value[:0x98] + fix.vaults[vault] + value[0x98 + 20:]))
    root, height = harness.tree(VAULT_NODE, rows) if rows else (0, 0)
    for offset, word in ((0, root), (8, height), (0x10, len(rows))):
        memory.write(STATE_AT + VAULTS + shift + offset, 8, word)
    agents_at = STATE_AT + AGENTS + shift
    harness.empty_table(agents_at)
    if fix.agents:
        harness.build_table(agents_at, 0x28, [(key, value) for key, value in sorted(fix.agents.items())], agents_at + 0x20, (11, 12))
    users_at = STATE_AT + USERS
    harness.empty_table(users_at)
    if fix.users:
        harness.build_table(users_at, 0x58, [(key, filled("user row", 0x44)) for key in sorted(fix.users)], users_at + 0x20, (21, 22))
    links_at = STATE_AT + LINKS + shift
    harness.empty_table(links_at)
    if fix.links:
        harness.build_table(links_at, 0x28, [(key, filled("link", 20)) for key in sorted(fix.links)], links_at + 0x20, (41, 42))
    memory.write(STATE_AT + DEX_ROWS + shift, 8, ROWLIST_AT)
    memory.write(STATE_AT + DEX_ROWS + shift + 8, 8, len(fix.dex_rows))
    for index, keys in enumerate(fix.dex_rows):
        row = ROWLIST_AT + index * 0x2F0
        memory.put_bytes(row, filled("dex row", 0x2F0))
        harness.empty_table(row + 0xF8)
        if keys:
            harness.build_table(row + 0xF8, 0x78, [(key, filled("dex user", 0x64)) for key in sorted(keys)], row + 0x118, (31 + index, 32))


def write_action(harness, at, tag, fix, orders_at):
    memory = harness.machine.memory
    memory.write(at, 8, tag)
    row = row_of(tag)
    for offset in (0x10, 0x20, 0x40, 0xC):
        memory.write(at + offset, 4, 0x1200 + offset)
    if harness.tables.assets[0][row][0] == "field":
        memory.write(at + harness.tables.assets[0][row][1], 4, 0x2000 + row)
    memory.write(at + 0x18, 8, fix.list_len)
    memory.write(at + 0x30, 8, fix.list_len)
    if row == 2 or row == 14:
        step, tif, trigger = (0x50, 0x21, 0x18) if row == 2 else (0x38, 9, 0)
        memory.put_bytes(orders_at, filled("orders", 0x600))
        for index, (kind, flag) in enumerate(fix.orders):
            memory.write(orders_at + step * index + tif, 1, kind)
            memory.write(orders_at + step * index + trigger, 1, flag)
        if row == 2:
            memory.write(at + 0x10, 8, orders_at)
            memory.write(at + 0x18, 8, fix.list_len if fix.list_len > 1 else len(fix.orders))
        else:
            memory.write(at + 0x38, 8, orders_at)
            memory.write(at + 0x40, 8, len(fix.orders))
    if row == 12:
        memory.write(at + 0x29, 1, fix.tif)
        memory.write(at + 0x20, 1, fix.trigger)


def write_env(harness, index, fix):
    memory = harness.machine.memory
    at = ENV_AT + index * ENV_STEP
    memory.put_bytes(at, filled("envelope %d" % index, ENV_STEP))
    write_action(harness, at + 0x10, fix.tag, fix, ORDERS_AT + index * 0x800)
    if fix.tag == MULTI_TAG:
        inner = INNER_AT + index * INNER_STEP
        memory.put_bytes(inner, filled("inner %d" % index, INNER_STEP))
        write_action(harness, inner, fix.inner, fix, ORDERS_AT + index * 0x800)
        rows = SIGS_AT + index * 0x48 * 0x20
        count = len(fix.sigs) if fix.sig_count is None else fix.sig_count
        memory.write(at + 0x20, 8, rows)
        memory.write(at + 0x28, 8, count)
        memory.write(at + 0x30, 8, inner)
        memory.put_bytes(at + 0x38, fix.multi_user)
        memory.put_bytes(at + 0x4C, fix.outer)
        for sig, (status, address) in enumerate(fix.sigs):
            memory.put_bytes(rows + sig * 0x48, filled("sig row", 0x48))
            memory.write(rows + sig * 0x48, 2, status)
            memory.put_bytes(rows + sig * 0x48 + 2, address)
    if fix.vault is None:
        memory.write(at + 0x150, 1, 0)
    else:
        memory.write(at + 0x150, 1, 1)
        memory.put_bytes(at + 0x151, fix.vault)
    return at


def prepare_dexes(harness, fix):
    memory = harness.machine.memory
    harness.dex_used = 0
    memory.put_bytes(DEXES_AT, bytes(0x18 * DEX_SETS))
    if fix.leaf[0] == "set":
        for index in range(DEX_SETS):
            for dex in fix.leaf[1]:
                harness.run_at(SET_ADD[0], {RDI: DEXES_AT + 0x18 * index, RSI: dex})


def resolve_rule(harness, fix, events, tag, address, shift):
    """Signer word to acting address, by the class byte of the action row."""
    tables = harness.tables
    klass = tables.klass[row_of(tag)]
    if klass in (0, 1):
        events.append(("validator", address.hex(), VALIDATORS + shift, harness.machine.memory.read(STATE_AT + VALIDATOR_WORD + shift, 8)))
        if address in fix.validators:
            return STATUS_OK, address
        if klass == 1:
            which = 0 if fix.chain == 3 else 1
            events.append(("once", which))
            if address in tables.lazy[which]:
                return STATUS_OK, address
        return 0x7B, None
    if klass == 2:
        return STATUS_OK, address
    if klass == 4:
        return 0x7D, None
    if address in fix.agents:
        return STATUS_OK, fix.agents[address]
    if any(address in keys for keys in fix.dex_rows) or address in fix.users:
        return STATUS_OK, address
    return 0x58, address


def touch_rule(harness, tag, inner):
    value = harness.tables.touch[row_of(tag)]
    if value == "inner":
        value = harness.tables.touch[row_of(inner)]
    return value


def assets_rule(harness, fix, events, tag, inner, env_at, depth=0):
    arm = harness.tables.assets[0][row_of(tag)]
    if arm[0] == "multi":
        return assets_rule(harness, fix, events, inner, inner, env_at, 1)
    if arm[0] == "none":
        return ("none",)
    if arm[0] == "empty":
        return ("set", ())
    if arm[0] == "field":
        events.append(("dex meta", harness.machine.memory.read((INNER_AT + harness.index * INNER_STEP if depth else env_at + 0x10) + arm[1], 4)))
        if fix.meta[0] == "error":
            return ("error", fix.meta[1])
        if fix.meta[0] == "absent":
            return ("error", 0x15E)
        return ("set", (fix.meta[1] // 10000,))
    if arm[0] == "list" and fix.list_len >= MAX_SIGS + 1:
        return ("error", 0x143)
    events.append(("leaf",))
    return fix.leaf


def multi_rule(harness, fix, events, shift, index):
    """The signed multi sig wrapper: returns status and the multi sig user."""
    if fix.outer != fix.signer:
        return 0x11D, None
    user = fix.multi_user
    row = row_of(fix.inner)
    if user == MAGIC_USER and (row > 0x2B or not MULTI_MASK >> row & 1):
        return 0x112, None
    if harness.tables.klass[row] & 6 != 2:
        return 0x112, None
    if user not in fix.multi:
        return 0x114, None
    status, address = resolve_rule(harness, fix, events, fix.inner, fix.outer, shift)
    if status != STATUS_OK:
        return status, address
    signers, threshold = fix.multi[user]
    if address not in signers:
        return 0x11D, None
    count = len(fix.sigs) if fix.sig_count is None else fix.sig_count
    if count > MAX_SIGS:
        return 0x143, None
    seen = set()
    memory = harness.machine.memory
    env = ENV_AT + index * ENV_STEP
    tail = memory.bytes_at(env + 0x150, 21).hex()
    for sig, (state, recovered) in enumerate(fix.sigs):
        events.append(("signature", sig + index * 0x20, fix.chain, user.hex(), fix.outer.hex(), index * INNER_STEP, memory.read(env, 8), memory.read(env + 8, 8), memory.read(env + 0x148, 8), tail))
        if state != STATUS_OK:
            return state, recovered
        if recovered not in signers:
            return 0x11E, None
        seen.add(recovered)
    if len(seen) < threshold:
        return 0x116, None
    return STATUS_OK, user


def expect_core(harness, fix, copy, index=0):
    """Status and record words of one action, with the stub events in order."""
    shift = COPIES[copy]["shift"]
    env = ENV_AT + index * ENV_STEP
    events = [("recover", index * ENV_STEP, fix.chain)]
    if fix.recover != STATUS_OK:
        return ("error", fix.recover, fix.signer), events
    signer = fix.signer
    tag = fix.tag
    if tag == MULTI_TAG:
        if fix.inner == MULTI_TAG:
            return ("error", 0x112, None), events
        status, user = multi_rule(harness, fix, events, shift, index)
        if status != STATUS_OK:
            return ("error", status, user), events
    else:
        status, user = resolve_rule(harness, fix, events, tag, signer, shift)
        if status != STATUS_OK:
            return ("error", status, user), events
        if user in fix.multi and signer not in fix.agents:
            return ("error", 0x115, None), events
    if fix.chain != 3:
        answer = assets_rule(harness, fix, events, tag, fix.inner, env)
        if answer[0] == "error":
            events.append(("asset error dropped",))
    vault = fix.vault
    if vault is None:
        return ("record", 0, user, user, signer), events
    if touch_rule(harness, tag, fix.inner) >= 2:
        return ("error", 0x15, None), events
    if vault in fix.vaults:
        answer = assets_rule(harness, fix, events, tag, fix.inner, env)
        if answer[0] == "error":
            return ("error", answer[1], None), events
        if answer[0] == "none":
            return ("error", 0x15, None), events
        if set(answer[1]) - {0}:
            return ("error", 0x15, None), events
        leader = fix.vaults[vault]
        leader = fix.vaults.get(leader, leader)
        if user == MAGIC_USER:
            events.append(("list a", vault.hex()))
            if vault not in fix.list_a:
                events.append(("list b", vault.hex()))
                if vault not in fix.list_b:
                    return ("error", 0x119, None), events
        elif user != leader:
            return ("pair", 0x7C, user, vault), events
        return ("record", 1, vault, user, signer), events
    subs = SUBS + shift
    events.append(("is sub", vault.hex(), subs))
    if vault not in fix.subs:
        return ("one", 7, vault), events
    events.append(("master", vault.hex(), subs))
    if fix.subs[vault] != user:
        return ("pair", 0xDC, user, vault), events
    if touch_rule(harness, tag, fix.inner) != 0:
        return ("error", 0xDB, None), events
    return ("record", 0, vault, user, signer), events


def read_core(memory, out, want):
    status = memory.read(out, 2)
    if want[0] == "record":
        return ("record", memory.read(out + 2, 1), memory.bytes_at(out + 3, 20), memory.bytes_at(out + 0x17, 20), memory.bytes_at(out + 0x2B, 20)) if status == STATUS_OK else ("status", status)
    if want[0] == "one":
        return ("one", status, memory.bytes_at(out + 2, 20))
    if want[0] == "pair":
        return ("pair", status, memory.bytes_at(out + 2, 20), memory.bytes_at(out + 0x16, 20))
    return ("error", status, memory.bytes_at(out + 2, 20) if want[2] else None)


def read_keys(memory, root, height):
    """Sorted keys of an authorized signer set."""
    out = []

    def visit(node, level):
        count = memory.read(node + SIGNER_NODE.count_at, 2)
        for index in range(count):
            if level:
                visit(memory.read(node + SIGNER_NODE.leaf + 8 * index, 8), level - 1)
            out.append(memory.bytes_at(node + SIGNER_NODE.key_at + 20 * index, 20))
        if level:
            visit(memory.read(node + SIGNER_NODE.leaf + 8 * count, 8), level - 1)
    if root:
        visit(root, height)
    return out


def read_multi(harness, at):
    """The multi sig map as user: (signers, threshold), from the tree the real code left."""
    memory = harness.machine.memory
    root, height, length = memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 0x10, 8)
    out = {}

    def visit(node, level):
        count = memory.read(node + MULTI_NODE.count_at, 2)
        for index in range(count):
            if level:
                visit(memory.read(node + MULTI_NODE.leaf + 8 * index, 8), level - 1)
            value = node + MULTI_NODE.value_size * index
            out[memory.bytes_at(node + MULTI_NODE.key_at + 20 * index, 20)] = (frozenset(read_keys(memory, memory.read(value, 8), memory.read(value + 8, 8))), memory.read(value + 0x18, 8))
        if level:
            visit(memory.read(node + MULTI_NODE.leaf + 8 * count, 8), level - 1)
    if root:
        visit(root, height)
    if len(out) != length:
        raise Halt("map length differs from its walk")
    return out


def known_user(fix, address):
    return any(address in keys for keys in fix.dex_rows) or address in fix.users


def expect_convert(fix):
    """Status of convertToMultiSigUser and the map after it."""
    after = dict(fix.multi)
    user = fix.convert_user
    if fix.json_len >= MAX_JSON:
        return 0x143, after
    if fix.parse_error:
        return 0xBD, after
    if user == MAGIC_USER:
        return 0x118, after
    if not known_user(fix, user):
        return 0x118, after
    if fix.signers is None:
        if user not in after:
            return 0x118, after
        del after[user]
        return STATUS_OK, after
    for signer in sorted(fix.signers):
        if not known_user(fix, signer):
            return 0x11A, after
        if signer in fix.vaults or signer in fix.links:
            return 0x11B, after
        if signer == user:
            return 0x11C, after
    count = len(fix.signers)
    if (fix.threshold - 1) & MASK[8] >= count:
        return 0x113, after
    if count > MAX_SIGNERS:
        return 0x117, after
    after[user] = (frozenset(fix.signers), fix.threshold)
    return STATUS_OK, after


def compare_convert(harness, case):
    machine = harness.machine
    memory = machine.memory
    setup(harness, case)
    fix = case.fixes[0]
    shift = COPIES[case.copy]["shift"]
    memory.write(ARG_AT, 8, 0x4000)
    memory.write(ARG_AT + 8, 8, 0x5000)
    memory.write(ARG_AT + 0x10, 8, fix.json_len)
    memory.put_bytes(KEY_AT, fix.convert_user)
    memory.put_bytes(OUT_AT, filled("out", 0x60))
    status, after = expect_convert(fix)
    machine.run(CONVERTS[case.copy], {RDI: OUT_AT, RSI: ARG_AT, RDX: KEY_AT, RCX: STATE_AT})
    tag = memory.read(OUT_AT, 1)
    got = STATUS_OK if tag == 0xD else (memory.read(OUT_AT + 8, 2) if tag == 0xE else -tag)
    harness.tally["convert %#x" % status] += 1
    if got != status:
        return "status %#x want %#x" % (got, status)
    final = read_multi(harness, STATE_AT + MULTI_MAP + shift)
    if final != after:
        return "map differs: %d rows want %d" % (len(final), len(after))
    return None


def setup(harness, case):
    harness.reset()
    fix = case.fixes[0]
    harness.case = fix
    harness.current = case.fixes
    harness.index = 0
    harness.env_at = ENV_AT
    state_of(harness, fix, COPIES[case.copy]["shift"])
    prepare_dexes(harness, fix)
    harness.events = []


def compare_core(harness, case):
    machine = harness.machine
    memory = machine.memory
    setup(harness, case)
    fix = case.fixes[0]
    env = write_env(harness, 0, fix)
    memory.put_bytes(OUT_AT, filled("out", 0x60))
    want, events = expect_core(harness, fix, case.copy)
    machine.run(COPIES[case.copy]["core"], {RDI: OUT_AT, RSI: env, RDX: STATE_AT})
    harness.tally[want[0] if want[0] == "record" else "status %#x" % want[1]] += 1
    if read_core(memory, OUT_AT, want) != want:
        return "got %r want %r" % (read_core(memory, OUT_AT, want), want)
    if harness.events != events:
        return "events %r want %r" % (harness.events, events)
    return None


def compare_wrap(harness, case):
    """The map loop: envelope pointer, index, record, until a record reads 0x187."""
    machine = harness.machine
    memory = machine.memory
    setup(harness, case)
    envs = [write_env(harness, index, fix) for index, fix in enumerate(case.fixes)]
    rows_at = HEAP_BASE + 0x30000
    memory.put_bytes(ARG_AT, bytes(0x40))
    third = case.copy == 2
    memory.write(ARG_AT, 8, ARG_AT + 0x40 if third else rows_at)
    memory.write(ARG_AT + 8, 8, rows_at if third else 0x10)
    memory.write(ARG_AT + 0x10, 8, 0x10 if third else 2)
    memory.write(ARG_AT + 0x18, 8, 2)
    memory.write(ARG_AT + 0x40, 8, STATE_AT)
    producer = ARG_AT + 0x60
    memory.write(producer, 8, ENV_AT)
    memory.write(producer + 0x10, 8, 0x700)
    memory.write(producer + 0x20, 8, 0)
    memory.write(producer + 0x28, 8, len(envs))
    memory.write(producer + 0x30, 8, ARG_AT + 0x40)
    want = []
    events = []
    for index, fix in enumerate(case.fixes):
        if fix.recover == STATUS_END:
            events.append(("recover", index * ENV_STEP, fix.chain))
            break
        harness.index = index
        answer, more = expect_core(harness, fix, case.copy, index)
        events.extend(more)
        want.append((index, answer))
    harness.index = 0
    machine.run(COPIES[case.copy]["wrap"], {RDI: OUT_AT, RSI: ARG_AT, RDX: producer})
    length = memory.read(OUT_AT + (0x18 if third else 0x10), 8)
    if memory.read(OUT_AT + (8 if third else 0), 8) != rows_at or length != 2 + len(want):
        return "output length %d" % length
    for position, (index, answer) in enumerate(want):
        at = rows_at + (2 + position) * 0x70
        if memory.read(at, 8) != ENV_AT + index * ENV_STEP:
            return "pointer of row %d" % position
        if memory.read(at + 8, 8) != 0x700 + index:
            return "index of row %d" % position
        if read_core(memory, at + 0x10, answer) != answer:
            return "row %d got %r want %r" % (position, read_core(memory, at + 0x10, answer), answer)
    if harness.events != events:
        return "events %r want %r" % (harness.events, events)
    harness.tally["rows"] += len(want)
    return None


def alo(harness, row, fix):
    kind = harness.tables.sort_b[row]
    if kind == "modify":
        return fix.tif == 2 and fix.trigger == 0
    if kind in ("orders", "bulk"):
        if kind == "orders" and fix.list_len > MAX_SIGS:
            return False
        return bool(fix.orders) and all(tif == 2 and flag == 0 for tif, flag in fix.orders)
    return False


def sort_class(harness, fix):
    """Class of one record: 0 noop, 1 post only, 2 cancel, 3 the rest. A multi sig wrapper takes the class of its inner action, a noop tag is only seen at top level."""
    if fix.tag == NOOP_TAG:
        return 0
    row = row_of(fix.tag)
    if row == MULTI_ROW:
        row = row_of(fix.inner)
    if harness.tables.sort_a[row] == 1:
        return 2
    if alo(harness, row, fix):
        return 1
    return 3


def compare_sort(harness, case):
    """The partition 0x446fab0: one list per class, joined noop, post only, cancel, rest; a record with status 0x187 ends the input."""
    machine = harness.machine
    memory = machine.memory
    harness.reset()
    harness.current = case.fixes
    harness.case = case.fixes[0]
    harness.index = 0
    block = harness.allocate(0x70 * len(case.fixes))
    for index, fix in enumerate(case.fixes):
        write_env(harness, index, fix)
        at = block + index * 0x70
        memory.put_bytes(at, filled("record", 0x70))
        memory.write(at, 8, ENV_AT + index * ENV_STEP)
        memory.write(at + 8, 8, 0x700 + index)
        memory.write(at + 0x10, 2, fix.recover)
    memory.write(ARG_AT, 8, len(case.fixes))
    memory.write(ARG_AT + 8, 8, block)
    memory.write(ARG_AT + 0x10, 8, len(case.fixes))
    machine.run(SORTER, {RDI: OUT_AT, RSI: ARG_AT})
    lists = ([], [], [], [])
    for index, fix in enumerate(case.fixes):
        if fix.recover == STATUS_END:
            break
        lists[sort_class(harness, fix)].append(index)
    want = lists[0] + lists[1] + lists[2] + lists[3]
    rows = memory.read(OUT_AT + 8, 8)
    count = memory.read(OUT_AT + 0x10, 8)
    got = [memory.read(rows + index * 0x70 + 8, 8) - 0x700 for index in range(count)]
    for position, index in enumerate(want):
        if position < count and memory.bytes_at(rows + position * 0x70 + 0x12, 0x5E) != filled("record", 0x70)[0x12:]:
            return "record body of %d changed" % index
    harness.tally["sorted"] += count
    return None if got == want else "order %r want %r" % (got, want)


def compare(harness, _, case):
    if case.kind == "core":
        return compare_core(harness, case)
    if case.kind == "wrap":
        return compare_wrap(harness, case)
    if case.kind == "convert":
        return compare_convert(harness, case)
    return compare_sort(harness, case)


def convert_cases(copy):
    known = frozenset((USER, COSIGNER, THIRD, OTHER, SIGNER))
    pair = frozenset((COSIGNER, THIRD))
    base = dict(convert_user=USER, users=known, signers=pair, threshold=2)
    prior = {USER: (frozenset((OTHER,)), 1)}
    wide = frozenset(ADDRESSES[12:23])
    rows = []

    def add(label, **values):
        data = dict(base)
        data.update(values)
        rows.append(Case("convert", "convert_%s_%d" % (label, copy), copy, (Fix(**data),)))
    add("new_two_of_two")
    add("new_one_of_two", threshold=1)
    add("threshold_zero", threshold=0)
    add("threshold_above_count", threshold=3)
    add("threshold_huge", threshold=1 << 63)
    add("replace_rows", multi=prior)
    add("second_user_row", convert_user=OTHER, multi={USER: (pair, 2)})
    add("user_unknown", users=frozenset((COSIGNER, THIRD)))
    add("user_in_dex_row", users=frozenset((COSIGNER, THIRD)), dex_rows=(frozenset((USER,)),))
    add("signer_in_dex_row", users=frozenset((USER, THIRD)), dex_rows=(frozenset((OTHER,)), frozenset((COSIGNER,))))
    add("signer_unknown", signers=frozenset((COSIGNER, TOP)))
    add("signer_is_vault", vaults={COSIGNER: LEADER})
    add("signer_is_linked", links=frozenset((COSIGNER,)))
    add("signer_is_user", signers=frozenset((USER, COSIGNER)))
    add("failure_in_key_order", signers=frozenset((SIGNER, USER, TOP)))
    add("empty_signers", signers=frozenset(), threshold=1)
    add("empty_signers_zero", signers=frozenset(), threshold=0)
    add("remove_row", signers=None, multi=prior)
    add("remove_absent", signers=None)
    add("remove_keeps_other", signers=None, multi={USER: (pair, 2), OTHER: (pair, 1)})
    add("ten_signers", users=known | frozenset(ADDRESSES[12:22]), signers=frozenset(ADDRESSES[12:22]), threshold=10)
    add("eleven_signers", users=known | wide, signers=wide, threshold=4)
    add("eleven_threshold_first", users=known | wide, signers=wide, threshold=12)
    add("twelve_signers", users=known | frozenset(ADDRESSES[12:24]), signers=frozenset(ADDRESSES[12:24]), threshold=2)
    add("json_at_limit", json_len=MAX_JSON - 1)
    add("json_over_limit", json_len=MAX_JSON)
    add("parse_error", parse_error=True)
    add("magic_user", convert_user=MAGIC_USER, users=known | frozenset((MAGIC_USER,)))
    add("magic_user_no_signers", convert_user=MAGIC_USER, signers=None)
    return rows


SENTINELS = frozenset(["sort_all_classes", "sort_multi", "sort_orders", "sort_batch"] + ["%s_%d" % (name, copy) for copy in range(3) for name in (
    "multi_threshold_met", "multi_below_threshold", "multi_duplicate_not_counted", "multi_outsider_after_quorum", "multi_big_signer_set", "multi_magic_allowed_row", "multi_vault_pass", "multi_sub_pass", "multi_outer_agent_resolved", "agent_found", "known_in_dex_row_two", "known_in_user_table", "unknown_with_all_tables",
    "vault_leader_pass", "vault_leader_is_vault", "vault_many_rows", "sub_master_pass", "plain_record", "user_is_multi_agent_passes", "user_is_multi_direct_refused", "magic_list_b", "field_row_dex_one", "convert_new_two_of_two", "convert_replace_rows", "convert_remove_keeps_other", "convert_signer_is_vault", "convert_signer_is_linked", "convert_twelve_signers", "convert_signer_in_dex_row")])


def named_core(copy):
    """Every branch outcome by name, for one copy."""
    C = "%d" % copy
    agents = {AGENT: USER}
    sign = {SIGNER: USER}
    cases = []

    def add(label, **values):
        cases.append(Case("core", label, copy, (Fix(**values),)))
    add("plain_record", tag=0x75)
    add("recover_fails", recover=0x31, tag=0x75)
    add("recover_fails_multi", recover=0x31, tag=MULTI_TAG)
    add("chain_three_plain", chain=3)
    add("agent_found", tag=0x76, agents=sign)
    add("agent_unknown", tag=0x76)
    add("agent_table_miss_with_rows", tag=0x76, agents=agents)
    add("agent_many_rows", tag=0x76, agents={ADDRESSES[12 + index]: USER for index in range(10)} | sign)
    add("known_in_dex_row_one", tag=0x76, dex_rows=(frozenset((SIGNER,)),))
    add("known_in_dex_row_two", tag=0x76, dex_rows=(frozenset((OTHER,)), frozenset((SIGNER,))))
    add("empty_dex_row_then_user", tag=0x76, dex_rows=(frozenset(),), users=frozenset((SIGNER,)))
    add("known_in_user_table", tag=0x76, users=frozenset((SIGNER,)))
    add("unknown_with_all_tables", tag=0x76, dex_rows=(frozenset((OTHER,)),), users=frozenset((OTHER,)), agents=agents)
    add("agent_beats_user_row", tag=0x76, agents=sign, users=frozenset((SIGNER,)))
    add("class_zero_validator", tag=0x74 + 24, validators=frozenset((SIGNER,)))
    add("class_zero_refused", tag=0x74 + 24)
    add("class_one_low_tag_validator", tag=0x10, validators=frozenset((SIGNER,)))
    add("class_one_refused", tag=0x10)
    add("class_one_list_chain_three", tag=0x10, chain=3, signer=bytes(19) + b"\x02")
    add("class_one_chain_three_other", tag=0x10, chain=3, signer=SIGNER)
    add("class_four_refused", tag=0x74 + 56)
    add("user_is_multi_direct_refused", tag=0x76, agents=sign, multi={USER: (frozenset((SIGNER,)), 1)}, signer=USER, outer=USER, users=frozenset((USER,)))
    add("user_is_multi_agent_passes", tag=0x76, agents=sign, multi={USER: (frozenset((SIGNER,)), 1)})
    add("signer_is_multi_itself", tag=0x75, multi={SIGNER: (frozenset((OTHER,)), 1)})
    add("signer_is_multi_empty_agents", tag=0x75, multi={SIGNER: (frozenset((OTHER,)), 1)}, chain=3)
    add("signer_is_multi_with_agent_row", tag=0x75, multi={SIGNER: (frozenset((OTHER,)), 1)}, agents={SIGNER: USER})
    add("multi_map_many_rows_miss", tag=0x75, multi={ADDRESSES[12 + index]: (frozenset((OTHER,)), 1) for index in range(12)})
    add("multi_map_many_rows_hit", tag=0x75, signer=ADDRESSES[20], outer=ADDRESSES[20], multi={ADDRESSES[12 + index]: (frozenset((OTHER,)), 1) for index in range(12)})
    # the wrapper
    base = dict(tag=MULTI_TAG, multi_user=MULTI, outer=SIGNER, inner=0x75, multi={MULTI: (frozenset((SIGNER, COSIGNER, THIRD)), 2)})
    good = ((STATUS_OK, COSIGNER), (STATUS_OK, THIRD))

    def many(label, **values):
        data = dict(base)
        data.update(values)
        add(label, **data)
    many("multi_threshold_met", sigs=good)
    many("multi_nested_refused", inner=MULTI_TAG, sigs=good)
    many("multi_outer_mismatch", outer=OTHER, sigs=good)
    many("multi_user_unknown", multi_user=OTHER, sigs=good)
    many("multi_map_empty", multi={}, sigs=good)
    many("multi_class_four_inner", inner=0x74 + 56, sigs=good)
    many("multi_class_zero_inner", inner=0x74 + 24, sigs=good)
    many("multi_class_one_inner", inner=0x10, sigs=good)
    many("multi_outer_not_listed", outer=OTHER, signer=OTHER, sigs=good)
    many("multi_outer_agent_resolved", inner=0x76, signer=AGENT, outer=AGENT, agents={AGENT: THIRD}, sigs=good)
    many("multi_outer_agent_unlisted", inner=0x76, signer=AGENT, outer=AGENT, agents={AGENT: OTHER}, sigs=good)
    many("multi_outer_agent_unknown", inner=0x76, signer=AGENT, outer=AGENT, sigs=good)
    many("multi_no_signatures", sigs=())
    many("multi_threshold_zero_no_signatures", multi={MULTI: (frozenset((SIGNER,)), 0)}, sigs=())
    many("multi_below_threshold", sigs=good[:1])
    many("multi_duplicate_not_counted", sigs=(good[0], good[0]))
    many("multi_above_threshold", sigs=good + ((STATUS_OK, SIGNER),))
    many("multi_signature_fails", sigs=(good[0], (0x33, OTHER)))
    many("multi_signature_outsider", sigs=(good[0], (STATUS_OK, OTHER)))
    many("multi_outsider_after_quorum", sigs=good + ((STATUS_OK, OTHER),))
    many("multi_too_many_signatures", sig_count=MAX_SIGS + 1)
    many("multi_big_signer_set", multi={MULTI: (frozenset(ADDRESSES[10:24]) | frozenset((SIGNER,)), 3)}, sigs=tuple((STATUS_OK, ADDRESSES[12 + index]) for index in range(3)))
    many("multi_big_set_outsider", multi={MULTI: (frozenset(ADDRESSES[10:24]) | frozenset((SIGNER,)), 3)}, sigs=((STATUS_OK, OTHER),))
    many("multi_chain_three", chain=3, sigs=good)
    many("multi_magic_allowed_row", multi_user=MAGIC_USER, inner=0x74 + 3, multi={MAGIC_USER: (frozenset((SIGNER, COSIGNER, THIRD)), 2)}, sigs=good, agents={SIGNER: SIGNER})
    many("multi_magic_refused_row", multi_user=MAGIC_USER, inner=0x75, multi={MAGIC_USER: (frozenset((SIGNER, COSIGNER, THIRD)), 2)}, sigs=good)
    many("multi_magic_low_tag", multi_user=MAGIC_USER, inner=0x10, multi={MAGIC_USER: (frozenset((SIGNER, COSIGNER, THIRD)), 2)}, sigs=good)
    many("multi_vault_pass", vault=VAULT, vaults={VAULT: MULTI}, sigs=good)
    many("multi_vault_touch", vault=VAULT, vaults={VAULT: MULTI}, inner=0x74 + 9, sigs=good, chain=3)
    many("multi_sub_pass", vault=SUB, subs={SUB: MULTI}, inner=0x74 + 1, sigs=good)
    # vault and sub-account arms, action row 3 takes a list, row 1 none
    row_set = 0x74 + 3
    left = dict(tag=row_set, signer=SIGNER, agents=sign, leaf=("set", (0,)))

    def vault(label, **values):
        data = dict(left)
        data.update(values)
        add(label, **data)
    vault("vault_leader_pass", vault=VAULT, vaults={VAULT: USER})
    vault("vault_leader_differs", vault=VAULT, vaults={VAULT: OTHER})
    vault("vault_leader_is_vault", vault=VAULT, vaults={VAULT: LEADER, LEADER: USER})
    vault("vault_leader_is_vault_differs", vault=VAULT, vaults={VAULT: LEADER, LEADER: OTHER})
    vault("vault_leader_is_vault_self", vault=VAULT, vaults={VAULT: USER, USER: USER})
    vault("vault_two_levels_only", vault=VAULT, vaults={VAULT: LEADER, LEADER: TOP, TOP: USER})
    vault("vault_many_rows", vault=VAULT, vaults={**{ADDRESSES[12 + index]: USER for index in range(12)}, VAULT: USER})
    vault("vault_many_rows_miss", vault=ADDRESSES[23], vaults={ADDRESSES[12 + index]: USER for index in range(11)})
    vault("vault_empty_set", vault=VAULT, vaults={VAULT: USER}, leaf=("set", ()))
    vault("vault_dex_one", vault=VAULT, vaults={VAULT: USER}, leaf=("set", (1,)))
    vault("vault_dex_zero_and_one", vault=VAULT, vaults={VAULT: USER}, leaf=("set", (0, 1)))
    vault("vault_leaf_none", vault=VAULT, vaults={VAULT: USER}, leaf=("none",))
    vault("vault_leaf_error", vault=VAULT, vaults={VAULT: USER}, leaf=("error", 0x44))
    vault("plain_leaf_error_dropped", leaf=("error", 0x44))
    vault("plain_list_too_long", list_len=MAX_SIGS + 1)
    vault("vault_list_too_long", vault=VAULT, vaults={VAULT: USER}, list_len=MAX_SIGS + 1)
    vault("vault_list_at_limit", vault=VAULT, vaults={VAULT: USER}, list_len=MAX_SIGS)
    vault("vault_chain_three", chain=3, vault=VAULT, vaults={VAULT: USER})
    vault("not_sub_refused", vault=OTHER)
    vault("sub_master_pass", vault=SUB, subs={SUB: USER}, tag=0x75 + 0x20 - 0x20 + 1 - 1)
    vault("sub_master_pass_touch_one", vault=SUB, subs={SUB: USER}, tag=0x74 + 7)
    vault("sub_master_other", vault=SUB, subs={SUB: OTHER})
    vault("sub_touch_two", vault=SUB, subs={SUB: USER}, tag=0x74 + 9)
    magic = dict(left, agents={SIGNER: MAGIC_USER}, vault=VAULT, vaults={VAULT: LEADER})
    add("magic_list_a", **dict(magic, list_a=frozenset((VAULT,))))
    add("magic_list_b", **dict(magic, list_b=frozenset((VAULT,))))
    add("magic_neither_list", **magic)
    add("field_row_dex_zero", tag=0x74 + 34, vault=VAULT, vaults={VAULT: SIGNER}, meta=("value", 9999))
    add("field_row_dex_one", tag=0x74 + 34, vault=VAULT, vaults={VAULT: SIGNER}, meta=("value", 10000))
    add("field_row_asset_absent", tag=0x74 + 34, vault=VAULT, vaults={VAULT: SIGNER}, meta=("absent",))
    add("field_row_meta_error", tag=0x74 + 34, vault=VAULT, vaults={VAULT: SIGNER}, meta=("error", 0x41))
    add("field_row_plain", tag=0x74 + 34, meta=("value", 123456))
    return [Case(item.kind, item.label + "_" + C, item.copy, item.fixes) for item in cases]


def row_cases(copy):
    cases = []
    rows = list(range(ROWS)) + [None]
    for row in rows:
        tag = 0x10 if row is None else row + ROW_BASE
        if tag == MULTI_TAG:
            continue
        name = "low" if row is None else "%d" % row
        leaf = ("set", (0,))
        cases.append(Case("core", "row_%s_stranger_%d" % (name, copy), copy, (Fix(tag=tag, leaf=leaf),)))
        cases.append(Case("core", "row_%s_validator_%d" % (name, copy), copy, (Fix(tag=tag, leaf=leaf, validators=frozenset((SIGNER,))),)))
        cases.append(Case("core", "row_%s_agent_%d" % (name, copy), copy, (Fix(tag=tag, leaf=leaf, agents={SIGNER: USER}),)))
        cases.append(Case("core", "row_%s_vault_%d" % (name, copy), copy, (Fix(tag=tag, leaf=leaf, agents={SIGNER: USER}, validators=frozenset((SIGNER,)), vault=VAULT, vaults={VAULT: SIGNER}),)))
        cases.append(Case("core", "row_%s_sub_%d" % (name, copy), copy, (Fix(tag=tag, leaf=leaf, agents={SIGNER: USER}, validators=frozenset((SIGNER,)), vault=SUB, subs={SUB: SIGNER}),)))
        if copy == 0 or row in (3, 10, 13, 14, 43, 1, 2, None):
            signers = frozenset((SIGNER, COSIGNER))
            cases.append(Case("core", "row_%s_multi_%d" % (name, copy), copy, (Fix(tag=MULTI_TAG, inner=tag, leaf=leaf, agents={SIGNER: SIGNER}, multi={MULTI: (signers, 1)}, sigs=((STATUS_OK, COSIGNER),)),)))
            cases.append(Case("core", "row_%s_magic_%d" % (name, copy), copy, (Fix(tag=MULTI_TAG, inner=tag, leaf=leaf, multi_user=MAGIC_USER, agents={SIGNER: SIGNER}, multi={MAGIC_USER: (signers, 1)}, sigs=((STATUS_OK, COSIGNER),)),)))
    return cases


def lazy_cases(copy, tables):
    cases = []
    for which, chain in ((0, 3), (1, 1), (1, 0), (1, 2)):
        for index, address in enumerate(tables.lazy[which]):
            cases.append(Case("core", "lazy_%d_%d_chain_%d_%d" % (which, index, chain, copy), copy, (Fix(tag=0x10, chain=chain, signer=address),)))
        cases.append(Case("core", "lazy_miss_%d_%d_%d" % (which, chain, copy), copy, (Fix(tag=0x10, chain=chain, signer=tables.lazy[1 - which][0]),)))
    return cases


def wrap_cases(copy):
    state = dict(agents={AGENT: USER}, multi={MULTI: (frozenset((AGENT, COSIGNER)), 1)}, vaults={VAULT: USER})
    plain = Fix(tag=0x76, signer=AGENT, **state)
    vaulted = Fix(tag=0x76, signer=AGENT, vault=VAULT, leaf=("set", (0,)), **state)
    refused = Fix(tag=0x76, signer=OTHER, **state)
    wrapped = Fix(tag=MULTI_TAG, inner=0x76, signer=AGENT, outer=AGENT, sigs=((STATUS_OK, COSIGNER),), **state)
    end = Fix(recover=STATUS_END, **state)
    rows = []
    for label, fixes in (("three", (plain, vaulted, refused)), ("wrapped", (wrapped, plain)), ("stop_first", (end, plain)), ("stop_middle", (plain, end, refused)), ("one", (refused,)), ("four", (refused, wrapped, vaulted, plain))):
        rows.append(Case("wrap", "wrap_%s_%d" % (label, copy), copy, fixes))
    return rows


def sort_cases():
    noop = Fix(tag=NOOP_TAG)
    cancel = Fix(tag=0x74 + 3)
    cancel_cloid = Fix(tag=0x74 + 4)
    plain = Fix(tag=0x75)
    gtc = Fix(tag=0x74 + 14, orders=((1, 0),))
    alo_order = Fix(tag=0x74 + 14, orders=((2, 0), (2, 0)))
    mixed = Fix(tag=0x74 + 14, orders=((2, 0), (1, 0)))
    trigger = Fix(tag=0x74 + 14, orders=((2, 1),))
    tail_trigger = Fix(tag=0x74 + 14, orders=((2, 0), (2, 1)))
    empty = Fix(tag=0x74 + 14)
    modify = Fix(tag=0x74 + 12, tif=2)
    modify_gtc = Fix(tag=0x74 + 12, tif=1)
    modify_trigger = Fix(tag=0x74 + 12, tif=2, trigger=1)
    batch = Fix(tag=0x74 + 2, orders=((2, 0), (2, 0), (2, 0)))
    batch_one = Fix(tag=0x74 + 2, orders=((2, 0),))
    batch_last = Fix(tag=0x74 + 2, orders=((2, 0), (0, 0)))
    batch_trigger = Fix(tag=0x74 + 2, orders=((2, 0), (2, 3)))
    batch_first = Fix(tag=0x74 + 2, orders=((3, 0), (2, 0)))
    batch_empty = Fix(tag=0x74 + 2)
    batch_long = Fix(tag=0x74 + 2, orders=((2, 0),), list_len=MAX_SIGS + 1)
    multi_cancel = Fix(tag=MULTI_TAG, inner=0x74 + 3)
    multi_alo = Fix(tag=MULTI_TAG, inner=0x74 + 14, orders=((2, 0),))
    multi_noop = Fix(tag=MULTI_TAG, inner=NOOP_TAG)
    multi_plain = Fix(tag=MULTI_TAG, inner=0x75)
    failed = Fix(tag=0x74 + 3, recover=0x31)
    end = Fix(recover=STATUS_END, tag=0x75)
    shapes = (("empty_input", ()), ("sort_all_classes", (plain, gtc, cancel, alo_order, noop, modify, cancel_cloid, batch, plain, noop)), ("sort_stable", (cancel_cloid, cancel, alo_order, modify, gtc, plain)), ("sort_multi", (multi_plain, multi_cancel, multi_alo, multi_noop, noop)),
              ("sort_orders", (gtc, mixed, trigger, tail_trigger, empty, alo_order)), ("sort_modify", (modify_gtc, modify_trigger, modify)), ("sort_batch", (batch_last, batch_trigger, batch_first, batch_empty, batch_long, batch_one, batch)), ("sort_failed_rows", (failed, plain, noop)),
              ("sort_end_first", (end, plain)), ("sort_end_middle", (plain, cancel, end, noop, alo_order)), ("sort_end_last", (noop, end)), ("sort_grow", tuple((noop, cancel, plain, alo_order)[index % 4] for index in range(24))))
    return [Case("sort", label, 0, fixes) for label, fixes in shapes if fixes]


def all_cases(tables=None):
    tables = tables or TABLES[0]
    cases = []
    for copy in range(3):
        cases += named_core(copy) + row_cases(copy) + lazy_cases(copy, tables) + wrap_cases(copy) + convert_cases(copy)
    return cases + sort_cases()


TABLES = []


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
    TABLES.append(harness.tables)
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



# ---- evidence ----

def core_functions():
    rows = []
    for index, item in enumerate(COPIES):
        name = item["name"]
        rows.append((item["core"], "record writer, " + name, True))
        rows.append((item["wrap"], "map loop over envelopes, " + name, True))
        rows.append((item["resolve"], "signer to acting address, " + name, True))
        rows.append((item["agent"], "agent lookup, " + name, True))
        rows.append((item["assets"], "dex set of an action, " + name, True))
        if item["multi"]:
            rows.append((item["multi"], "multi sig body, " + name, True))
    for index in range(3):
        rows.append((CONVERTS[index], "convertToMultiSigUser entry, " + COPIES[index]["name"], True))
        rows.append((CONVERT_CORES[index], "signer checks and clear, " + COPIES[index]["name"], True))
    rows += [(STORE, "threshold test and store", True), (STORE_INSERT, "multi sig map insert, shared", False), (MAP_REMOVE, "multi sig map remove, shared", False)]
    rows += [(CLASS_FN, "resolve class of a row", True), (TOUCH_FN, "touch class of a row", True), (SORT_A, "cancel row test", True), (SORT_B, "post only row test", True), (SORTER, "class partition", True), (CHAIN, "join of the four lists", True),
             (0x3BDE170, "post only test of a batch", True), (LIST_SCAN, "post only test of an order list", True), (VAULT_FIND[0], "vault lookup", True), (VAULT_FIND[2], "vault lookup copy", True),
             (HASHER, "SipHash 1-3 of twenty bytes, shared", False), (SET_REMOVE[0], "dex set remove, shared", False), (SET_REMOVE[2], "dex set remove copy, shared", False), (SET_ADD[0], "dex set insert, shared", False), (0x4941FE0, "seen set insert, shared", False), (0x284F810, "seen set insert copy, shared", False), (0x284BB50, "signer set lookup copy, shared", False)]
    return rows


KEY_ROWS = ((0x46D4A1C, "41817c2410a8000000", "envelope action tag against 0xa8, the multi sig wrapper"), (0x46D4A30, "8138a8000000", "inner tag against 0xa8"), (0x46D4A3C, "66c7031201", "status 0x112, nested multi sig"), (0x46D4B46, "498b8fe8390000", "multi sig user map root at state +0x39e8"),
            (0x46D4E02, "4983bf4837000000", "agent_to_user item count, state +0x3748"), (0x46D4CD4, "4180bff208000003", "chain byte 3 skips the asset gate"), (0x46D4F90, "418b842461010000", "vault address at envelope +0x151"), (0x46D50D6, "66c7031501", "status 0x115, direct use of a multi sig user"),
            (0x46D5283, "66c703dc00", "status 0xdc, not the master"), (0x46D5326, "66c7030700", "status 7, no vault and no sub-account"), (0x46D53A6, "483500000007", "magic user test, last word 0x07000000"), (0x46D5413, "66c703db00", "status 0xdb, sub-account action refused"),
            (0x46D549D, "66c7031901", "status 0x119, neither list"), (0x46D545D, "c6430201", "record byte +2 = 1 on a vault"), (0x4C5CB0D, "48ba0864000000080000", "row mask of the magic user 0x80000006408"), (0x4C5CE18, "4881fe10270000", "signature count against 0x2710"),
            (0x4C5D073, "493b4618", "seen set length against the threshold at value +0x18"), (0x4C5D079, "66c7031601", "status 0x116, below threshold"), (0x4C5D088, "66c7031e01", "status 0x11e, signature from outside the set"), (0x4C5CD9F, "66c7031401", "status 0x114, not a multi sig user"),
            (0x4C5CABF, "66c7031d01", "status 0x11d, outer signer"), (0x48F560F, "4c8b3d4aa1e700", "lazy list slot of chain byte 3"), (0x48F57DD, "66c7037b00", "status 0x7b, not allowed for the class"), (0x48F5673, "66c7037d00", "status 0x7d, refused class"),
            (0x4D8B39C, "66b85800", "status 0x58, unknown signer"), (0x446FC76, "41837d1074", "tag 0x74 at the record envelope"),
            (0x1E64023, "483de9030000", "action text length against 0x3e9"), (0x34262A7, "66bf1301", "status 0x113, threshold outside 1..=count"), (0x34262B0, "66bf1701", "status 0x117"), (0x34262B4, "4883f80a", "more than ten signers"),
            (0x2769D89, "66b81b01", "status 0x11b, signer is a vault or linked"), (0x2769CF7, "66b81c01", "status 0x11c, signer is the user"), (0x2769E4A, "66b81a01", "status 0x11a, signer unknown"), (0x2769DEF, "66b81801", "status 0x118 on a clear with no row"))


def key_row_lines(image):
    lines = ["address\tbytes\tmeaning"]
    for va, hexed, meaning in KEY_ROWS:
        found = code(image, va, len(hexed) // 2).hex()
        if found != hexed:
            raise EvidenceError("row moved at %#x: %s" % (va, found))
        lines.append("%#x\t%s\t%s" % (va, hexed, meaning))
    return lines


def handler_names():
    """Wire names of the merged dispatch evidence, by row."""
    doc = json.loads(HANDLERS.read_text(encoding="utf-8"))
    return {row["index"]: row.get("reconstruction", {}).get("wire_type") or "-" for row in doc["cases"]}


def row_lines(tables):
    names = handler_names()
    lines = ["row\ttag\twire_type_from_RE_010\tresolve_class\ttouch\tsort_class\tasset_arm\tmagic_user_mask"]
    for row in range(ROWS):
        tag = row + ROW_BASE
        if tag == NOOP_TAG:
            order = "noop"
        elif tables.sort_a[row] == 1:
            order = "cancel"
        elif tables.sort_a[row] == "inner":
            order = "inner"
        elif tables.sort_b[row]:
            order = "post only if " + tables.sort_b[row]
        else:
            order = "rest"
        arm = " ".join(str(part) for part in tables.assets[0][row])
        lines.append("%d\t%#x\t%s\t%d\t%s\t%s\t%s\t%d" % (row, tag, names.get(row, "-"), tables.klass[row], tables.touch[row], order, arm, 1 if row <= 0x2B and MULTI_MASK >> row & 1 else 0))
    return lines


def lazy_lines(tables):
    lines = ["list\tinit\tchain_byte\tposition\taddress"]
    for index, init in enumerate(LAZY_INIT):
        for position, address in enumerate(tables.lazy[index]):
            lines.append("%#x\t%#x\t%s\t%d\t0x%s" % (LAZY[index], init, "3" if index == 0 else "not 3", position, address.hex()))
    return lines


def site_lines(image):
    """Sites by one pass over .text: rel32 calls for the direct targets, FF 15 for the slots."""
    base, text = image.text_bytes()
    direct = {}
    for item in COPIES:
        for key in ("core", "wrap", "resolve", "agent", "assets", "multi"):
            if item[key]:
                direct[item[key]] = "%s call" % key
    direct.update({SORTER: "partition call", CHAIN: "join call"})
    for index in range(3):
        direct[CONVERTS[index]] = "convert call"
        direct[CONVERT_CORES[index]] = "convert core call"
    slots = {0x5774960: "threshold store through slot", SLOT_SIGNATURE: "multi sig row recovery through slot", SLOT_RECOVER: "signer recovery through slot", SLOT_CLASS: "class through slot", SLOT_SORT_A: "cancel test through slot", SLOT_SORT_B: "post only test through slot"}
    found = []
    for match in re.finditer(b"\xe8", text):
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
        lines.append("%s\t%#x\t%#x\t%#x" % (name, target, site, image.fde(site)[0]))
    return lines


def analyse(image, full=True):
    harness = Harness(image)
    TABLES.append(harness.tables)
    tables = harness.tables
    if tables.assets[0] != tables.assets[1] or tables.assets[0] != tables.assets[2]:
        raise EvidenceError("asset rows differ between copies")
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
        "constants": {"multi_tag": "0xa8", "max_signatures": MAX_SIGS, "magic_user_mask": "%#x" % MULTI_MASK, "envelope_size": "0x168", "record_size": "0x70", "agent_bucket": "0x28", "copy_shift": "0xa80", "dex_divisor": 10000, "max_signers": MAX_SIGNERS, "max_action_text": MAX_JSON - 1},
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_sites": site_lines(image), "_status": status_lines, "_layouts": layout_lines, "_keys": key_row_lines(image), "_rows": row_lines(tables), "_lazy": lazy_lines(tables),
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, the wide join shapes, a tree edge step with no fixture, or an asset arm whose leaf is a stub"
SURVIVOR_REASON = "not hand checked row by row: copy size, stack base, error payload words no rule reads, tree edge test, or a value only a stub reads"
OUTCOMES = collections.Counter()


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\tcopy\toutcomes\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "call-sites.tsv": evidence.pop("_sites"), "status-text.tsv": evidence.pop("_status"),
              "node-layouts.tsv": evidence.pop("_layouts"), "key-rows.tsv": evidence.pop("_keys"), "action-rows.tsv": evidence.pop("_rows"), "lazy-lists.tsv": evidence.pop("_lazy")}
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
