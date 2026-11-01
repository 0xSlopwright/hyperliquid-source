#!/usr/bin/env python3
"""Evaluate the node #94 signing of its own actions from ELF bytes: request record, 30 s expiry rows, multi sig wrap, sign tables, gates, the fall back to the agent form and the compact bundle.

The builder that turns a node action into a signed record, its three wrappers, the signer map, the two sign tables, 41 small gate hosts, the agent sign tail, the queue push and the
compact bundle writer and reader run as real bytes in a Python evaluator. A separately written rule list predicts each output record and event, and conditions, immediates and offsets of the reached rows are flipped to show the run can
tell. The tables and call sites are read from section bytes. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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
HANDLERS = ROOT / "research" / "work-items" / "RE-010-exchange-handlers" / "exchange-dispatch.json"

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
SLOT_UNWRAP = 0x576E048
SLOT_NOW_MS = 0x576E9F8
SLOT_UTC_NOW = 0x576E8A0
SLOT_WALLETS = 0x576EA00
SLOT_ALIGNED = 0x576E298
SLOT_ABSORB = 0x576E1D8
SLOT_SQUEEZE = 0x576E1E0
SLOT_ENCODE = 0x57739E0
SLOT_READER = 0x5775D60
SLOT_BUILD = 0x5773C88
SLOT_PLAIN = 0x5775A50

BUILD = 0x3341AF0
SIGNER_MAP = 0x3BAD290
MULTI = 0x335EDB0
MULTI_TAIL = 0x33609F0
PLAIN = 0x3362B30
AGENT_SIGN = 0x333F7B0
SIGN_DIGEST = 0x359EE60
AGENT_VERIFY = 0x333F690
ERROR_CONVERT = 0x365EB00
SIGNER_SAMPLE = 0x13CD040
SIGNER_COLLECT = 0x14B14C0
QUEUE_PUSH = 0x44ADBF0
BUNDLE_ENCODE = 0x3340100
RECORD_ENCODE = 0x3340A40
BUNDLE_DECODE = 0x342E4B0
RECORD_DECODE = 0x333F820
ACTION_ENCODE = 0x3362FD0
ACTION_DECODE = 0x3340E90
RECORDS_DROP = 0x3437C90
SEND_ERROR = 0x447CB60
SEND_CDEPOSIT = 0x4A10F80
SEND_CWITHDRAW = 0x4A11020
SEND_DELEGATE = 0x4A110C0
PAYLOAD = 0x333F240
MULTI_PAYLOAD = 0x37EB2D0
DIGEST = 0x37F2940
SECP = 0x14A2710
ENVELOPE = 0x3984FE0
DROP_A = 0x3999770
DROP_B = 0x3379490
EXPIRY_TABLE = 0x587BD0
PLAIN_TABLE = 0x58915C
MULTI_TABLE = 0x588D3C
EXPIRY_ARM = 0x3341EE3
NO_EXPIRY_ARM = 0x3341FB5
PLAIN_DEFAULT_ARM = 0x3362B63
ROWS = 88
TAG_BASE = 0x74
LOW_TAG_ROW = 0x14
MULTI_SIG_ROW = 52
MULTI_SIG_TAG = 0xA8
EXPIRY_ADD_MS = 30000
MULTI_USER = bytes(19) + b"\x07"
MAINNET_CHAIN_ID = 0xA4B1
TESTNET_CHAIN_ID = 0x66EEE
REQUEST_SITES = ((0x22AF2BF, 0x21C0), (0x22AF83F, 0x21C0), (0x22B01B9, 0x21C0), (0x44AEB59, 0x620), (0x47C0CCC, 0x70), (0x4A11006, 8), (0x4A110A6, 8), (0x4A11169, 8))
BYTES_CLONE = 0xDEAD1000
BYTES_DROP = 0xDEAD1020
STATUS_TABLE = 0x59A8D0
STATUS_TAGS = (0x15, 0x5D, 0x7A, 0x8C, 0x8F, 0x186)
PANIC_TEXTS = (0x595171, 0x216F9D)
MUTANT_STEP_LIMIT = 30000
MUTANT_CASES = 36
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
HEAP_SIZE = 0x100000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 4000000

HEAP_FREE = HEAP_BASE + 0x40000
OUT_AT = HEAP_BASE + 0x1000
ACTION_AT = HEAP_BASE + 0x2000
CONTEXT_AT = HEAP_BASE + 0x2200
USER_AT = HEAP_BASE + 0x2300
OUTER_AT = HEAP_BASE + 0x2320
VALIDATOR_AT = HEAP_BASE + 0x2340
WALLET_AT = HEAP_BASE + 0x3000
REQUEST_AT = HEAP_BASE + 0x4000
TEXT_AT = HEAP_BASE + 0x5000
STATE_AT = HEAP_BASE + 0x10000
BROADCASTER_AT = STATE_AT + 0x9D0
WIRE_AT = HEAP_BASE + 0x20000
QUEUE_AT = HEAP_BASE + 0x30000
RECORDS_AT = HEAP_BASE + 0x34000

RANDOM_DATES = 300

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
        if rela["size"] % 24:
            raise EvidenceError("truncated RELA section")
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



# ---- harness: real bytes through .text; allocator, clock, wallet list, payload hashes and secp256k1 are stubbed ----

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


def relative_table(image, table, count):
    base = image.offset(table)
    return [table + struct.unpack_from("<i", image.blob, base + 4 * row)[0] for row in range(count)]


def slot_of_arm(image, arm):
    """The rip slot of the first FF 15 in an arm of a sign table."""
    data = bytes(image.blob[image.offset(arm):image.offset(arm) + 48])
    at = data.find(b"\xff\x15")
    if at < 0:
        raise EvidenceError("arm %#x has no slot call" % arm)
    return arm + at + 6 + struct.unpack_from("<i", data, at + 2)[0]


def gate_offsets(image, host):
    """(chain offset, time offset, signer target) of one plain gate host, from its rows; rsi is the action word 1 address."""
    begin, end = image.exact_fde(host)
    chain = time = None
    signer = None
    for row in body_rows(image, begin, end):
        if row.op == "call" and row.target not in (DROP_A, DROP_B, ENVELOPE):
            signer = row.target
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] == RSI:
                if row.op == "cmp" and row.width == 1 and chain is None:
                    chain = operand[4]
                elif (row.op == "mov" and row.width == 8 and row.a == ("r", RDX)) or (row.op == "cmp" and row.width == 8):
                    time = operand[4]
    return chain, time, signer


class SignTable:
    """Rows of the three action tables, read from their relative offsets and arm bytes."""

    def __init__(self, image, relative):
        self.expiry = relative_table(image, EXPIRY_TABLE, ROWS)
        self.plain = relative_table(image, PLAIN_TABLE, ROWS)
        self.multi = relative_table(image, MULTI_TABLE, ROWS)
        self.plain_host = {}
        self.multi_host = {}
        self.plain_signer = {}
        self.multi_signer = {}
        self.chain_at = {}
        self.time_at = {}
        for row in range(ROWS):
            if self.plain[row] != PLAIN_DEFAULT_ARM:
                host = relative[slot_of_arm(image, self.plain[row])]
                self.plain_host[row] = host
                self.chain_at[row], self.time_at[row], self.plain_signer[row] = gate_offsets(image, host)
            arm = self.multi[row]
            if bytes(image.blob[image.offset(arm):image.offset(arm) + 4]) == b"\x48\x83\xc6\x08":
                host = relative[slot_of_arm(image, arm)]
                self.multi_host[row] = host
                begin, end = image.exact_fde(host)
                self.multi_signer[row] = [item.target for item in body_rows(image, begin, end) if item.op == "call" and item.target not in (DROP_A, DROP_B, 0x5660110) and not 0x399A000 <= item.target < 0x399C000][0]

    def row_of(self, tag):
        return tag - TAG_BASE if tag >= TAG_BASE else LOW_TAG_ROW

    def has_expiry(self, row):
        return self.expiry[row] == EXPIRY_ARM


def signature_of(digest, wallet):
    data = hashlib.sha256(digest + wallet).digest() + hashlib.sha256(wallet + digest).digest()
    return data + bytes([27 + (digest[0] & 1)])


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        self.table = SignTable(image, relative)
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_NOW_MS: self.on_now_ms, SLOT_UTC_NOW: self.on_utc_now, SLOT_WALLETS: self.on_wallets, SLOT_RECOVER: self.on_recover,
                 SLOT_REALLOC: self.on_realloc, SLOT_ALIGNED: self.on_aligned, SLOT_ABSORB: self.on_absorb, SLOT_SQUEEZE: self.on_squeeze}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        machine.slots[BYTES_CLONE] = self.on_bytes_clone
        machine.slots[BYTES_DROP] = self.on_bytes_drop
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {PAYLOAD: self.on_payload, MULTI_PAYLOAD: self.on_multi_payload, DIGEST: self.on_digest, SECP: self.on_secp, ENVELOPE: self.on_envelope, ERROR_CONVERT: self.on_convert, ACTION_ENCODE: self.on_action_encode, ACTION_DECODE: self.on_action_decode, RECORDS_DROP: self.on_records_drop, SEND_ERROR: self.on_send_error, DROP_A: self.on_drop, DROP_B: self.on_drop}
        for row, target in self.table.plain_signer.items():
            machine.calls[target] = lambda m, row=row: self.on_user_sign(m, row, False)
        for row, target in self.table.multi_signer.items():
            machine.calls[target] = lambda m, row=row: self.on_user_sign(m, row, True)
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
        self.now_ms = 0
        self.utc = (0, 0, 0)
        self.wallets = []
        self.digest_error = False
        self.secp_error = False
        self.envelope = (0, 0)
        self.panic_word = None
        self.pair = b""
        self.recover_error = False
        self.quiet = False
        self.absorbed = b""
        self.bad_encode = None
        self.panicked = False

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

    def on_copy(self, m):
        regs = m.regs
        if regs[RDX] > 0x8000:
            raise Halt("copy size")
        if regs[RDX]:
            m.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_panic(self, m, slot):
        if slot == SLOT_UNWRAP:
            if m.regs[RSI] != 0x2B:
                raise Halt("unwrap text length")
            self.panic_word = m.memory.read(m.regs[RDX], 8)
        raise Panicked("%#x" % slot)

    def on_now_ms(self, m):
        m.regs[RAX] = self.now_ms

    def on_utc_now(self, m):
        out = m.regs[RDI]
        for at, word in enumerate(self.utc):
            m.memory.write(out + 4 * at, 4, word)

    def on_wallets(self, m):
        out = m.regs[RDI]
        count = len(self.wallets)
        at = self.allocate(count * 8) if count else 8
        for index, wallet in enumerate(self.wallets):
            m.memory.write(at + 8 * index, 8, wallet)
        m.memory.write(out, 8, count)
        m.memory.write(out + 8, 8, at)
        m.memory.write(out + 0x10, 8, count)

    def context_words(self, m, at):
        memory = m.memory
        tag = memory.read(at, 8)
        return tag, memory.read(at + 8, 8) if tag else None, memory.read(at + 0x10, 8), memory.read(at + 0x18, 1), memory.bytes_at(at + 0x19, 20).hex()

    def wallet_index(self, at):
        return (at - WALLET_AT) // 0x100

    def payload_buffer(self, m, out, marker):
        at = self.allocate(1)
        m.memory.write(out, 8, 1)
        m.memory.write(out + 8, 8, at)
        m.memory.put_bytes(out + 0x18, marker)

    def on_payload(self, m):
        memory = m.memory
        words = self.context_words(m, m.regs[RCX])
        row = ("payload", memory.read(m.regs[RSI], 8), m.regs[RDX] & 0xFF) + words
        self.events.append(row)
        self.payload_buffer(m, m.regs[RDI], hashlib.sha256(repr(row).encode()).digest())

    def on_multi_payload(self, m):
        memory = m.memory
        words = self.context_words(m, m.regs[RCX])
        wrapper = m.regs[RSI]
        action = memory.read(wrapper + 0x28, 8)
        row = ("multi_payload", memory.bytes_at(wrapper, 20).hex(), memory.bytes_at(wrapper + 0x14, 20).hex(), memory.read(action, 8), m.regs[RDX] & 0xFF) + words
        self.events.append(row)
        self.payload_buffer(m, m.regs[RDI], hashlib.sha256(repr(row).encode()).digest())

    def on_digest(self, m):
        marker = m.memory.bytes_at(m.regs[RSI] + 0x18, 32)
        out = m.regs[RDI]
        self.events.append(("digest", marker.hex()))
        if self.digest_error:
            m.memory.write(out, 1, 1)
            m.memory.put_bytes(out + 8, bytes(range(0x30, 0x48)))
            return
        m.memory.write(out, 1, 0)
        m.memory.put_bytes(out + 1, hashlib.sha256(marker).digest())

    def on_secp(self, m):
        digest = m.memory.bytes_at(m.regs[RDX], 32)
        wallet = m.regs[RSI]
        out = m.regs[RDI]
        self.events.append(("secp", self.wallet_index(wallet), digest.hex()))
        if self.secp_error:
            m.memory.write(out, 4, 1)
            m.memory.put_bytes(out + 8, bytes(range(0x50, 0x78)))
            return
        m.memory.write(out, 4, 0)
        m.memory.put_bytes(out + 8, signature_of(digest, m.memory.bytes_at(wallet + 0x80, 20)))

    def on_drop(self, m):
        if not self.quiet:
            self.events.append(("drop", m.memory.read(m.regs[RDI], 2)))

    def on_realloc(self, m):
        regs = m.regs
        old, new = regs[RDI], regs[RSI]
        if old not in self.live:
            raise Halt("realloc %#x" % old)
        size = self.live.pop(old)
        at = self.allocate(new)
        m.memory.copy(at, old, min(size, new))
        regs[RAX] = at

    def on_aligned(self, m):
        m.regs[RAX] = self.allocate(m.regs[RSI])

    def on_absorb(self, m):
        self.absorbed = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])

    def on_squeeze(self, m):
        if m.regs[RDX] != 32:
            raise Halt("squeeze size")
        m.memory.put_bytes(m.regs[RSI], hashlib.sha256(self.absorbed).digest())

    def on_action_encode(self, m):
        action = m.regs[RSI]
        out = m.regs[RDI]
        if m.memory.read(action, 8) == self.bad_encode:
            m.memory.put_bytes(out, bytes(range(0x10, 0x70)))
            m.memory.write(out, 2, 0x55)
            return
        size = m.memory.read(action + 0xE8, 1)
        at = self.allocate(size)
        m.memory.copy(at, action, size)
        m.memory.write(out, 2, 0x186)
        m.memory.write(out + 8, 8, size)
        m.memory.write(out + 0x10, 8, at)
        m.memory.write(out + 0x18, 8, size)

    def on_action_decode(self, m):
        out = m.regs[RDI]
        data = m.memory.bytes_at(m.regs[RSI], m.regs[RDX])
        if not data:
            m.memory.put_bytes(out, bytes(range(0x20, 0x80)))
            m.memory.write(out, 8, 0xCC)
            m.memory.write(out + 8, 2, 0x87)
            return
        if data[:1] == b"\xee":
            m.memory.put_bytes(out, bytes(range(0x20, 0x90)))
            m.memory.write(out, 8, 0xCC)
            m.memory.write(out + 8, 2, 0x55)
            return
        m.memory.put_bytes(out, data.ljust(0xF0, b"\0")[:0xF0])

    def on_records_drop(self, m):
        at = m.regs[RDI]
        cap = m.memory.read(at, 8)
        self.events.append(("records_drop", m.memory.read(at + 0x10, 8)))
        if cap:
            self.live.pop(m.memory.read(at + 8, 8), None)

    def on_send_error(self, m):
        self.events.append(("send_error", m.memory.bytes_at(m.regs[RDI], 0x60).hex()))

    def on_envelope(self, m):
        out = m.regs[RDI]
        self.events.append(("envelope", m.memory.read(m.regs[RSI] - 8, 8)))
        nonce, chain = self.envelope
        m.memory.put_bytes(out, bytes([0x3C]) * 0x50)
        m.memory.write(out + 0x40, 8, nonce)
        m.memory.write(out + 0x48, 1, chain)

    def on_recover(self, m):
        out = m.regs[RDI]
        self.events.append(("recover", m.memory.bytes_at(m.regs[RSI], 0x41).hex(), m.memory.bytes_at(m.regs[RDX], 32).hex()))
        if self.recover_error:
            m.memory.write(out, 1, 1)
            m.memory.write(out + 8, 8, 0x7A7A7A7A)
            return
        m.memory.write(out, 1, 0)
        m.memory.put_bytes(out + 1, wallet_address(1))

    def on_convert(self, m):
        self.events.append(("convert", m.memory.read(m.regs[RDI], 8)))
        m.regs[RAX] = 0x7B7B7B7B

    def on_bytes_clone(self, m):
        out = m.regs[RDI]
        for at, word in enumerate((m.memory.read(m.regs[RSI] - 0x18, 8), m.regs[RDX], m.regs[RCX], 0)):
            m.memory.write(out + 8 * at, 8, word)

    def on_bytes_drop(self, m):
        pass

    def on_user_sign(self, m, row, multi):
        wallet = m.regs[RSI]
        memory = m.memory
        where = -1
        if multi:
            block = memory.bytes_at(m.regs[RDX], 0x100)
            where = block.find(self.pair)
        self.events.append(("user", row, multi, self.wallet_index(wallet), where >= 0 if multi else True))
        digest = hashlib.sha256(b"user" + bytes([row, multi])).digest()
        memory.put_bytes(m.regs[RDI], signature_of(digest, memory.bytes_at(wallet + 0x80, 20)))


# ---- rule list, written from the reading notes and not from the evaluator ----

USER_SIGNED_ROWS = (1, 11, 28, 33, 39, 47, 49, 50, 51, 53, 54, 61, 62, 63, 69, 74, 76, 77, 78, 86)


def row_of(tag):
    return tag - 0x74 if tag >= 0x74 else 20


def unix_ms(utc):
    """Unix milliseconds of a chrono date record: packed year and ordinal, seconds of day, nanoseconds."""
    packed, seconds, nanos = utc
    if packed & 0x80000000:
        packed -= 1 << 32
    year = packed >> 13
    ordinal = (packed & 0x1FFF) >> 4
    before = year - 1
    days = ordinal + before * 365 + before // 4 - before // 100 + before // 400 - 719163
    return (days * 86400 + seconds) * 1000 + nanos // 1000000


def expiry_after(utc):
    return max(unix_ms(utc), 0) + 30000


def marker_of(row):
    return hashlib.sha256(repr(row).encode()).digest()


class Spec:
    def __init__(self, chain_at, time_at):
        self.chain_at = chain_at
        self.time_at = time_at

    def gate(self, row, action, chain, context):
        """Status of the sign side gates of a user signed row, or None."""
        expiry_tag, _, nonce, vault_flag, _ = context
        if action[8 + self.chain_at[row]] != chain:
            return 0x8F
        if vault_flag & 1:
            return 0x15
        if int.from_bytes(action[8 + self.time_at[row]:16 + self.time_at[row]], "little") != nonce:
            return 0x5D
        if expiry_tag:
            return 0x8C
        return None

    def finish_digest(self, state, row, wallet):
        marker = marker_of(row)
        state["events"].append(row)
        state["events"].append(("digest", marker.hex()))
        if state.get("digest_error"):
            return "panic digest"
        digest = hashlib.sha256(marker).digest()
        state["events"].append(("secp", wallet[0], digest.hex()))
        if state.get("secp_error"):
            return "panic secp"
        return signature_of(digest, wallet[1])

    def plain_sign(self, state, action, chain, context, wallet):
        """Signature bytes, or a panic text, of one action with the plain table."""
        tag = int.from_bytes(action[:8], "little")
        row = row_of(tag)
        if row == 52:
            state["events"].append(("envelope", tag))
            nonce, signed_chain = state["envelope"]
            status = 0x8F if signed_chain != chain else 0x5D if nonce != context[2] else None
            if status is None:
                state["events"].append(("user", 52, False, wallet[0], True))
                return signature_of(hashlib.sha256(b"user" + bytes([52, 0])).digest(), wallet[1])
            state["events"].append(("drop", status))
        elif row in USER_SIGNED_ROWS:
            status = self.gate(row, action, chain, context)
            if status is None:
                state["events"].append(("user", row, False, wallet[0], True))
                return signature_of(hashlib.sha256(b"user" + bytes([row, 0])).digest(), wallet[1])
            state["events"].append(("drop", status))
        return self.finish_digest(state, ("payload", tag, chain) + context, wallet)

    def multi_sign(self, state, action, chain, user, outer, context, wallet):
        tag = int.from_bytes(action[:8], "little")
        row = row_of(tag)
        if row in USER_SIGNED_ROWS:
            status = self.gate(row, action, chain, context)
            if status is None:
                state["events"].append(("user", row, True, wallet[0], True))
                return signature_of(hashlib.sha256(b"user" + bytes([row, 1])).digest(), wallet[1])
            state["events"].append(("drop", status))
        return self.finish_digest(state, ("multi_payload", user.hex(), outer.hex(), tag, chain) + context, wallet)

    def verify(self, state, action, chain, context, signature):
        """(status, word or address) of the agent form verifier."""
        tag = int.from_bytes(action[:8], "little")
        row = ("payload", tag, chain) + context
        marker = marker_of(row)
        state["events"] += [row, ("digest", marker.hex())]
        if state.get("digest_error"):
            state["events"].append(("convert", 0x3736353433323130))
            return 0x7A, 0x7B7B7B7B
        digest = hashlib.sha256(marker).digest()
        state["events"].append(("recover", signature.hex(), digest.hex()))
        if state.get("recover_error"):
            return 0x7A, 0x7A7A7A7A
        return 0x186, wallet_address(1)

    def build(self, state, request):
        """Predict the 0x168 byte record: a dict of ranges, or a panic text."""
        action = request["action"]
        chain = request["chain"]
        nonce = request["nonce"] if request["has_nonce"] == 1 else state["now_ms"]
        vault = request["vault"]
        wallet = request["wallet"]
        vault_flag, vault_address = vault[0], vault[1:].hex()
        if request["multi"]:
            context = (0, None, nonce, vault_flag, vault_address)
            signatures = []
            for item in state["wallets"]:
                signature = self.multi_sign(state, action, chain, MULTI_USER, wallet[1], context, item)
                if isinstance(signature, str):
                    return signature
                signatures.append(signature)
            wrapped = bytearray(action)
            wrapped[:8] = MULTI_SIG_TAG.to_bytes(8, "little")
            signature = self.plain_sign(state, bytes(wrapped), chain, context, wallet)
            if isinstance(signature, str):
                return signature
            return {"expiry": None, "nonce": nonce, "signature": signature, "vault": vault, "signers": signatures, "chain_id": 0xA4B1 if chain == 3 else 0x66EEE}
        row = row_of(int.from_bytes(action[:8], "little"))
        if row in USER_SIGNED_ROWS:
            context = (0, None, nonce, vault_flag, vault_address)
            expiry = None
        else:
            expiry = expiry_after(state["utc"])
            context = (1, expiry, nonce, vault_flag, vault_address)
        signature = self.plain_sign(state, action, chain, context, wallet)
        if isinstance(signature, str):
            return signature
        return {"expiry": expiry, "nonce": nonce, "signature": signature, "vault": vault, "action": action}


def msgpack_sizes(sizes):
    """Array header and compact unsigned integers."""
    count = len(sizes)
    if count < 16:
        out = bytes([0x90 | count])
    elif count < 0x10000:
        out = b"\xdc" + struct.pack(">H", count)
    else:
        out = b"\xdd" + struct.pack(">I", count)
    for size in sizes:
        if size < 0x80:
            out += bytes([size])
        elif size < 0x100:
            out += bytes([0xCC, size])
        elif size < 0x10000:
            out += b"\xcd" + struct.pack(">H", size)
        else:
            out += b"\xce" + struct.pack(">I", size)
    return out


def wire_record(record):
    """Compact bytes of one 0x168 byte signed record."""
    out = record[0x100:0x120][::-1] + record[0x120:0x140][::-1] + record[0x140:0x141] + record[0x148:0x150][::-1]
    out += b"\x01" + record[0x151:0x165] if record[0x150] == 1 else b"\x00"
    out += record[0x165:0x166]
    out += b"\x01" + record[8:16][::-1] if int.from_bytes(record[:4], "little") == 1 else b"\x00"
    return out + record[0x10:0x10 + record[0xF8]]


def wire_bundle(blobs, now, wallet):
    """(wire bytes, digest) of a compact bundle signed by one wallet address."""
    sizes = msgpack_sizes([len(blob) for blob in blobs])
    data = struct.pack(">I", len(sizes)) + sizes + b"".join(blobs) + struct.pack(">Q", now)
    digest = hashlib.sha256(data).digest()
    signature = signature_of(digest, wallet)
    return data + signature[:32][::-1] + signature[32:64][::-1] + signature[64:], digest, signature


def decode_record(blob):
    """Fields of one compact record, or (status, byte)."""
    size = len(blob)
    if size <= 0x4B:
        return 0x86, None
    vault_tag = blob[0x49]
    at, rest = 0x4A, size - 0x4A
    address = None
    if vault_tag == 1:
        if rest < 0x14:
            return 0x87, None
        address = blob[at:at + 20]
        at, rest = at + 20, rest - 20
        if rest == 0:
            return 0x87, None
    elif vault_tag:
        return 0x89, vault_tag
    flag = blob[at]
    if flag >= 2:
        return 0x8A, flag
    if rest == 1:
        return 0x87, None
    tag = blob[at + 1]
    at, rest = at + 2, rest - 2
    expiry = None
    if tag == 1:
        if rest <= 7:
            return 0x87, None
        expiry = int.from_bytes(blob[at:at + 8], "big")
        at, rest = at + 8, rest - 8
    elif tag:
        return 0x8B, tag
    if rest == 0:
        return 0x87, None
    if blob[at] == 0xEE:
        return 0x55, None
    return {"signature": blob[:0x20][::-1] + blob[0x20:0x40][::-1] + blob[0x40:0x41], "nonce": int.from_bytes(blob[0x41:0x49], "big"), "vault": address, "flag": flag, "expiry": expiry, "action": blob[at:].ljust(0xF0, b"\0")[:0xF0]}


def read_msgpack_sizes(data):
    """Size list of a msgpack array of unsigned integers, or None."""
    if not data:
        return None
    first = data[0]
    if first & 0xF0 == 0x90:
        count, at = first & 15, 1
    elif first == 0xDC:
        count, at = int.from_bytes(data[1:3], "big"), 3
    else:
        return None
    out = []
    for _ in range(count):
        if at >= len(data):
            return None
        head = data[at]
        if head < 0x80:
            out.append(head)
            at += 1
        elif head == 0xCC:
            out.append(data[at + 1])
            at += 2
        elif head == 0xCD:
            out.append(int.from_bytes(data[at + 1:at + 3], "big"))
            at += 3
        else:
            return None
    return out


def decode_bundle(state, wire):
    """(status, value) of the bundle reader; appends the recovery event."""
    size = len(wire)
    if size <= 0x86:
        return 0x86, None
    signed = wire[:-0x41]
    digest = hashlib.sha256(signed).digest()
    signature = wire[-0x41:-0x21][::-1] + wire[-0x21:-1][::-1] + wire[-1:]
    state["events"].append(("recover", signature.hex(), digest.hex()))
    if state.get("recover_error"):
        return 0x7A, 0x7A7A7A7A
    time = int.from_bytes(wire[-0x49:-0x41], "big")
    left = size - 0x4D
    head = int.from_bytes(wire[:4], "big")
    if head > left:
        return 0x87, None
    left -= head
    sizes = read_msgpack_sizes(wire[4:4 + head])
    if sizes is None:
        return 0xBB, None
    if sum(sizes) != left:
        return 0x88, None
    at = 4 + head
    records = []
    for item in sizes:
        fields = decode_record(wire[at:at + item])
        if isinstance(fields, tuple):
            state["events"].append(("records_drop", len(records)))
            return fields
        records.append(fields)
        at += item
    return 0x186, {"records": records, "time": time, "signer": wallet_address(1)}


# ---- cases ----

class Case:
    def __init__(self, label, kind, **fields):
        self.label, self.kind, self.fields = label, kind, fields


def filled(text, size):
    out = b""
    round_number = 0
    while len(out) < size:
        out += hashlib.sha256(("%s/%d" % (text, round_number)).encode()).digest()
        round_number += 1
    return out[:size]


USER = filled("multi sig user", 20)
OUTER = filled("outer signer", 20)


def wallet_address(index):
    return filled("wallet %d" % index, 20)


def wallet_row(index):
    return index, wallet_address(index)


def action_bytes(tag, chain_at=None, time_at=None, chain=0, time=0, label="action"):
    """One action record with a text triple in each leading slot, so that cloned fields hold live pointers."""
    data = bytearray(filled("%s %#x" % (label, tag), 0xF0))
    data[:8] = tag.to_bytes(8, "little")
    if chain_at is not None:
        first = min(chain_at, time_at, 0x60 if tag == 0xC0 else 0x10000)
        at = 0
        count = 0
        while at + 0x18 <= first:
            size = 8 + count
            data[8 + at:8 + at + 0x18] = struct.pack("<QQQ", size, TEXT_AT + 0x40 * count, size)
            at += 0x18
            count += 1
        if tag == 0xC0:
            data[8 + 0x60:8 + 0x80] = struct.pack("<QQQQ", TEXT_AT + 0x400, TEXT_AT, 16, 0)
        data[8 + chain_at] = chain
        data[8 + time_at:16 + time_at] = time.to_bytes(8, "little")
    return bytes(data)


def date_word(year, ordinal, flags=0):
    return (year << 13 | ordinal << 4 | flags) & MASK[4]


def table_offsets():
    """Gate offsets of the 21 action shapes, as read in the reading notes."""
    chain = {1: 84, 11: 60, 28: 112, 33: 68, 39: 88, 47: 88, 49: 88, 50: 72, 51: 65, 53: 64, 54: 84, 61: 48, 62: 48, 63: 40, 69: 184, 74: 60, 76: 181, 77: 60, 78: 61, 86: 60}
    return chain


def all_cases(chain_at, time_at):
    cases = []
    scenarios = ("ok", "chain", "flag", "nonce", "expiry")

    def context_for(scenario, time):
        tag, value, nonce, flag = 0, None, time, 0
        if scenario == "flag":
            flag = 3
        elif scenario == "nonce":
            nonce = time + 1
        elif scenario == "expiry":
            tag, value = 1, 0x1234
        return tag, value, nonce, flag, filled("vault", 20).hex()

    for row in sorted(chain_at):
        tag = row + TAG_BASE
        for chain in (3, 1):
            time = 1760000000000 + row
            action = action_bytes(tag, chain_at[row], time_at[row], chain, time)
            for scenario in scenarios:
                wanted = chain ^ 1 if scenario == "chain" else chain
                cases.append(Case("plain/%d/%s/%d" % (row, scenario, chain), "plain", action=action, chain=wanted, context=context_for(scenario, time), wallet=wallet_row(1)))
                cases.append(Case("multi/%d/%s/%d" % (row, scenario, chain), "multi", action=action, chain=wanted, context=context_for(scenario, time), wallet=wallet_row(2)))
    for row in range(ROWS):
        if row in chain_at or row == 52:
            continue
        tag = row + TAG_BASE
        action = action_bytes(tag)
        cases.append(Case("plain/%d/agent" % row, "plain", action=action, chain=row & 3, context=(row & 1, row if row & 1 else None, 5000 + row, row >> 1 & 1, filled("vault", 20).hex()), wallet=wallet_row(0)))
        cases.append(Case("multi/%d/agent" % row, "multi", action=action, chain=row & 3, context=(0, None, 5000 + row, row >> 1 & 1, filled("vault", 20).hex()), wallet=wallet_row(0)))
    cases.append(Case("multi/52/agent", "multi", action=action_bytes(0xA8), chain=2, context=(0, None, 77, 0, filled("vault", 20).hex()), wallet=wallet_row(3)))
    for tag in (0, 1, 0x38, 0x73):
        cases.append(Case("plain/low/%#x" % tag, "plain", action=action_bytes(tag), chain=3, context=(1, 9, 8, 0, filled("vault", 20).hex()), wallet=wallet_row(0)))
        cases.append(Case("multi/low/%#x" % tag, "multi", action=action_bytes(tag), chain=3, context=(0, None, 8, 0, filled("vault", 20).hex()), wallet=wallet_row(0)))
    for tag in (0x74, 0xA3, 0xA8, 0xCB):
        for name, fields in (("ok", {}), ("digest", {"digest_error": True}), ("recover", {"recover_error": True})):
            for chain in (0, 3):
                cases.append(Case("verify/%#x/%s/%d" % (tag, name, chain), "verify", action=action_bytes(tag), chain=chain, context=(1, 0xBEEF, 91, 1, filled("vault", 20).hex()), wallet=wallet_row(0), signature=filled("signature", 0x41), **fields))
    def record(index, tag=0x80, size=0x40, expiry=None, vault=None, flag=0):
        data = bytearray(filled("record %d" % index, 0x168))
        data[0:8] = (1 if expiry is not None else 0).to_bytes(8, "little")
        if expiry is not None:
            data[8:16] = expiry.to_bytes(8, "little")
        data[0x10:0x18] = tag.to_bytes(8, "little")
        data[0xF8] = size
        data[0x10 + size:0x100] = bytes(0xF0 - size)
        data[0xF8] = size
        data[0x150] = 1 if vault else 0
        if vault:
            data[0x151:0x165] = vault
        data[0x165] = flag
        return bytes(data)

    samples = {"one": [record(0, expiry=1761900030000)], "two": [record(1), record(2, 0xA3, expiry=7, vault=filled("vault", 20))], "flag": [record(3, flag=1), record(4, flag=1, expiry=1)],
               "sizes": [record(5, size=0x10), record(6, size=0x60), record(7, size=0xE8)], "many": [record(8 + index, size=0x20 + index) for index in range(16)], "empty": []}
    for name, records in samples.items():
        for now in (1761900000123, MASK[8]):
            cases.append(Case("bundle/%s/%#x" % (name, now), "bundle", records=records, now_ms=now, wallet=wallet_row(0), queue=(4, 1)))
    cases.append(Case("bundle/grow", "bundle", records=samples["two"], now_ms=9, wallet=wallet_row(0), queue=(1, 1)))
    cases.append(Case("bundle/bad action", "bundle", records=samples["two"], now_ms=9, wallet=wallet_row(0), queue=(4, 1), bad_encode=0xA3))
    base = samples["two"]
    good = wire_bundle([wire_record(item) for item in base], 11, bytes(20))[0]

    def wire_of(blobs, head=None, now=11):
        return wire_bundle(blobs, now, bytes(20))[0] if head is None else head

    blob = wire_record(base[0])
    with_vault = wire_record(base[1])
    no_expiry_head = blob[:0x4A]
    decoded = {"good": wire_of([blob, with_vault]), "one": wire_of([blob]), "flag": wire_of([wire_record(samples["flag"][1])]), "sizes": wire_of([wire_record(item) for item in samples["sizes"]]),
               "short": good[:0x86], "at edge": bytes(0x87), "head long": b"\xff\xff\xff\xff" + good[4:], "bad msgpack": b"\x00\x00\x00\x01\xc1" + bytes(0x90), "sum off": wire_of([blob]).replace(b"\x91\xcc", b"\x91\xcc", 1)[:6] + b"\x7f" + wire_of([blob])[7:],
               "record short": wire_of([blob[:0x4B] + bytes(0x40)[:0], bytes(0x50)[:0x40], with_vault]),
               "vault tag": wire_of([no_expiry_head[:0x49] + b"\x02" + bytes(0x20)]), "vault cut": wire_of([no_expiry_head[:0x49] + b"\x01" + bytes(0x13)]), "vault end": wire_of([no_expiry_head[:0x49] + b"\x01" + bytes(0x14)]),
               "flag byte": wire_of([no_expiry_head + b"\x02" + bytes(0x20)]), "flag end": wire_of([no_expiry_head + b"\x00"]), "expiry tag": wire_of([no_expiry_head + b"\x00\x03" + bytes(0x20)]), "expiry cut": wire_of([no_expiry_head + b"\x00\x01" + bytes(7)]),
               "no action": wire_of([no_expiry_head + b"\x00\x00"]), "action bad": wire_of([blob, no_expiry_head + b"\x00\x00\xee\x00"]), "second bad": wire_of([blob, with_vault, no_expiry_head[:0x49] + b"\x05" + bytes(0x20)])}
    for name, wire in decoded.items():
        cases.append(Case("decode/%s" % name, "decode", wire=wire, wallet=wallet_row(0)))
    cases.append(Case("decode/recover", "decode", wire=decoded["good"], wallet=wallet_row(0), recover_error=True))
    for name, fields in (("digest", {"digest_error": True}), ("secp", {"secp_error": True})):
        cases.append(Case("plain/%s/agent" % name, "plain", action=action_bytes(0x74), chain=3, context=(1, 9, 8, 0, filled("vault", 20).hex()), wallet=wallet_row(0), **fields))
        cases.append(Case("multi/%s/agent" % name, "multi", action=action_bytes(0x74), chain=3, context=(0, None, 8, 0, filled("vault", 20).hex()), wallet=wallet_row(0), **fields))
        cases.append(Case("plain/%s/fallback" % name, "plain", action=action_bytes(0xA3, chain_at[47], time_at[47], 3, 5), chain=2, context=(0, None, 5, 0, filled("vault", 20).hex()), wallet=wallet_row(0), **fields))

    base_utc = (date_word(2026, 305, 5), 22000, 123456789)
    vault_none = bytes([0]) + filled("vault", 20)
    vault_some = bytes([1]) + filled("vault two", 20)
    for tag in list(range(0x74, 0x74 + ROWS)) + [0, 0x73]:
        row = row_of(tag)
        time = 1761900000000 + row
        action = action_bytes(tag, chain_at.get(row), time_at.get(row), 3, time)
        if row == 52:
            continue
        cases.append(Case("build/%#x/given" % tag, "build", action=action, chain=3, has_nonce=1, nonce=time, vault=vault_none, multi=0, utc=base_utc, now_ms=4, wallet=wallet_row(1)))
        cases.append(Case("build/%#x/clock" % tag, "build", action=action, chain=3, has_nonce=0, nonce=9, vault=vault_none, multi=0, utc=base_utc, now_ms=time, wallet=wallet_row(1)))
        cases.append(Case("build/%#x/gate" % tag, "build", action=action, chain=1, has_nonce=7, nonce=9, vault=vault_some, multi=0, utc=base_utc, now_ms=time + 1, wallet=wallet_row(1)))
        if row in chain_at:
            cases.append(Case("build/%#x/multi1" % tag, "build", action=action, chain=3, has_nonce=1, nonce=time, vault=vault_none, multi=1, utc=base_utc, now_ms=4, wallet=wallet_row(1), wallets=(wallet_row(1), wallet_row(2)), envelope=(time, 3)))
    plain_action = action_bytes(0x80)
    user_action = action_bytes(0xA3, chain_at[47], time_at[47], 3, 777)
    for count in range(0, 5):
        wallets = tuple(wallet_row(index) for index in range(1, count + 1))
        cases.append(Case("build/multi/agent/%d" % count, "build", action=plain_action, chain=3, has_nonce=1, nonce=777, vault=vault_none, multi=1, utc=base_utc, now_ms=4, wallet=wallet_row(0), wallets=wallets, envelope=(777, 3)))
        cases.append(Case("build/multi/user/%d" % count, "build", action=user_action, chain=2, has_nonce=0, nonce=1, vault=vault_some, multi=1, utc=base_utc, now_ms=777, wallet=wallet_row(0), wallets=wallets, envelope=(777, 2)))
    for name, envelope in (("chain", (777, 2)), ("nonce", (778, 3))):
        cases.append(Case("build/multi/envelope/%s" % name, "build", action=plain_action, chain=3, has_nonce=1, nonce=777, vault=vault_none, multi=1, utc=base_utc, now_ms=4, wallet=wallet_row(0), wallets=(wallet_row(1),), envelope=envelope))
    cases.append(Case("build/multi/secp", "build", action=plain_action, chain=3, has_nonce=1, nonce=777, vault=vault_none, multi=1, utc=base_utc, now_ms=4, wallet=wallet_row(0), wallets=(wallet_row(1),), envelope=(777, 3), secp_error=True))
    for chain in range(0, 4):
        cases.append(Case("build/multi/chain/%d" % chain, "build", action=plain_action, chain=chain, has_nonce=1, nonce=777, vault=vault_none, multi=1, utc=base_utc, now_ms=4, wallet=wallet_row(0), wallets=(wallet_row(1),), envelope=(777, chain)))
    dates = [("epoch", (date_word(1970, 1, 1), 0, 0)), ("before", (date_word(1969, 365, 1), 86399, 999000000)), ("old", (date_word(1000, 60), 5, 1)), ("year one", (date_word(1, 1), 0, 0)), ("year zero", (date_word(0, 60), 0, 0)),
             ("negative", (date_word(-1, 1), 7, 0)), ("minus 400", (date_word(-400, 366), 9, 0)), ("minus 401", (date_word(-401, 365), 9, 0)), ("far past", (date_word(-262000, 1), 0, 0)), ("far future", (date_word(262000, 365), 86399, 999999999)),
             ("leap second", (date_word(2016, 366), 86399, 1999999999)), ("after epoch", (date_word(1970, 1), 0, 999999)), ("one ms", (date_word(1970, 1), 0, 1000000))]
    for name, utc in dates:
        cases.append(Case("build/date/%s" % name, "build", action=action_bytes(0x80), chain=0, has_nonce=1, nonce=1, vault=vault_none, multi=0, utc=utc, now_ms=4, wallet=wallet_row(0)))
    source = random.Random(94)
    for index in range(RANDOM_DATES):
        utc = (date_word(source.randrange(-3000, 9000), source.randrange(1, 367), source.randrange(16)), source.randrange(86400), source.randrange(2000000000))
        cases.append(Case("build/random/%d" % index, "build", action=action_bytes(0x80), chain=source.randrange(4), has_nonce=source.randrange(3), nonce=source.getrandbits(64), vault=vault_some if index & 1 else vault_none, multi=0, utc=utc, now_ms=source.getrandbits(44), wallet=wallet_row(index % 4)))
    for chain in range(0, 4):
        for now in (1, 1761900000000, MASK[8]):
            cases.append(Case("send/cdeposit/%d/%#x" % (chain, now), "send", which="cdeposit", chain=chain, now_ms=now, amount=now ^ 0x1234, wallet=wallet_row(1)))
            cases.append(Case("send/cwithdraw/%d/%#x" % (chain, now), "send", which="cwithdraw", chain=chain, now_ms=now, amount=now ^ 0x4321, wallet=wallet_row(1)))
            for flag in (0, 1):
                cases.append(Case("send/delegate/%d/%#x/%d" % (chain, now, flag), "send", which="delegate", chain=chain, now_ms=now, amount=now ^ 0x777, wallet=wallet_row(1), validator=filled("validator", 20), flag=flag))
    return cases


def prepare(harness, case):
    harness.reset()
    fields = case.fields
    memory = harness.machine.memory
    for index in range(0, 5):
        memory.put_bytes(WALLET_AT + 0x100 * index, bytes([0x31 + index]) * 0x100)
        memory.put_bytes(WALLET_AT + 0x100 * index + 0x80, wallet_address(index))
    memory.put_bytes(USER_AT, USER)
    memory.put_bytes(OUTER_AT, OUTER)
    memory.put_bytes(VALIDATOR_AT, fields.get("validator", bytes(20)))
    for index in range(0, 12):
        memory.put_bytes(TEXT_AT + 0x40 * index, filled("text %d" % index, 0x20))
    harness.digest_error = fields.get("digest_error", False)
    harness.secp_error = fields.get("secp_error", False)
    harness.recover_error = fields.get("recover_error", False)
    harness.now_ms = fields.get("now_ms", 0)
    harness.utc = fields.get("utc", (0, 0, 0))
    harness.wallets = [WALLET_AT + 0x100 * index for index, _ in fields.get("wallets", ())]
    harness.envelope = fields.get("envelope", (0, 0))
    harness.bad_encode = fields.get("bad_encode")
    harness.quiet = case.kind == "decode"
    memory.put_bytes(BROADCASTER_AT, bytes([0x39]) * 0x100)
    memory.put_bytes(BROADCASTER_AT + 0x80, wallet_address(9))
    harness.pair = MULTI_USER + wallet_address(fields["wallet"][0]) if case.kind == "build" else USER + OUTER
    memory.write(TEXT_AT + 0x400, 8, BYTES_CLONE)
    memory.write(TEXT_AT + 0x420, 8, BYTES_DROP)


def put_context(memory, context):
    memory.put_bytes(CONTEXT_AT, bytes([0x5B]) * 0x40)
    memory.write(CONTEXT_AT, 8, context[0])
    if context[1] is not None:
        memory.write(CONTEXT_AT + 8, 8, context[1])
    memory.write(CONTEXT_AT + 0x10, 8, context[2])
    memory.write(CONTEXT_AT + 0x18, 1, context[3])
    memory.put_bytes(CONTEXT_AT + 0x19, bytes.fromhex(context[4]))


def compare(harness, spec, case):
    """Run one case; return None on a full match or the first difference."""
    prepare(harness, case)
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    kind = case.kind
    state = {"events": [], "wallets": [wallet_row(index) for index, _ in fields.get("wallets", ())], "now_ms": fields.get("now_ms", 0), "utc": fields.get("utc"), "envelope": fields.get("envelope", (0, 0)),
             "digest_error": fields.get("digest_error"), "secp_error": fields.get("secp_error"), "recover_error": fields.get("recover_error")}
    wallet = fields["wallet"]
    wallet_at = WALLET_AT + 0x100 * wallet[0]
    stack_words = {}
    if kind == "plain":
        memory.put_bytes(ACTION_AT, fields["action"])
        put_context(memory, fields["context"])
        want = spec.plain_sign(state, fields["action"], fields["chain"], fields["context"], wallet)
        entry = PLAIN
        args = {RDI: OUT_AT, RSI: ACTION_AT, RDX: fields["chain"], RCX: CONTEXT_AT, R8: wallet_at}
    elif kind == "multi":
        memory.put_bytes(ACTION_AT, fields["action"])
        put_context(memory, fields["context"])
        want = spec.multi_sign(state, fields["action"], fields["chain"], USER, OUTER, fields["context"], wallet)
        memory.write(STACK_TOP - 0x100, 8, wallet_at)
        entry = MULTI
        args = {RDI: OUT_AT, RSI: ACTION_AT, RDX: fields["chain"], RCX: USER_AT, R8: OUTER_AT, R9: CONTEXT_AT}
    elif kind == "bundle":
        records = fields["records"]
        cap, used = fields["queue"]
        queue = harness.allocate(0x168 * cap)
        harness.fixture.add(queue)
        memory.write(STATE_AT + 0x4D0, 8, cap)
        memory.write(STATE_AT + 0x4D8, 8, queue)
        memory.write(STATE_AT + 0x4E0, 8, used)
        memory.put_bytes(queue, bytes([0x4A]) * 0x168)
        for index, item in enumerate(records):
            memory.put_bytes(RECORDS_AT + 0x168 * index, item)
        bad = fields.get("bad_encode")
        blobs = []
        for item in records:
            if bad is not None and int.from_bytes(item[0x10:0x18], "little") == bad:
                break
            blobs.append(wire_record(item))
        if len(blobs) < len(records):
            state["events"].append(("send_error", (b"\x55\x00" + bytes(range(0x12, 0x70))).hex()))
            want = None
        else:
            wire, digest, _ = wire_bundle(blobs, fields["now_ms"], wallet_address(9))
            state["events"].append(("secp", (BROADCASTER_AT - WALLET_AT) // 0x100, digest.hex()))
            want = wire
        entry = QUEUE_PUSH
        args = {RDI: STATE_AT, RSI: RECORDS_AT, RDX: len(records)}
    elif kind == "decode":
        wire = fields["wire"]
        memory.put_bytes(WIRE_AT, wire)
        want = decode_bundle(state, wire)
        entry = BUNDLE_DECODE
        args = {RDI: OUT_AT, RSI: WIRE_AT, RDX: len(wire)}
    elif kind == "verify":
        memory.put_bytes(ACTION_AT, fields["action"])
        put_context(memory, fields["context"])
        memory.put_bytes(USER_AT + 0x80, fields["signature"])
        want = spec.verify(state, fields["action"], fields["chain"], fields["context"], fields["signature"])
        entry = AGENT_VERIFY
        args = {RDI: OUT_AT, RSI: ACTION_AT, RDX: fields["chain"], RCX: CONTEXT_AT, R8: USER_AT + 0x80}
    elif kind == "build":
        memory.put_bytes(REQUEST_AT, bytes([0x6E]) * 0x128)
        memory.write(REQUEST_AT, 4, fields["has_nonce"])
        memory.write(REQUEST_AT + 8, 8, fields["nonce"])
        memory.put_bytes(REQUEST_AT + 0x10, fields["action"])
        memory.write(REQUEST_AT + 0x100, 8, wallet_at)
        memory.put_bytes(REQUEST_AT + 0x108, fields["vault"])
        memory.write(REQUEST_AT + 0x11D, 1, fields["multi"])
        memory.write(REQUEST_AT + 0x11E, 1, fields["chain"])
        want = spec.build(state, {"action": fields["action"], "chain": fields["chain"], "has_nonce": fields["has_nonce"], "nonce": fields["nonce"], "vault": fields["vault"], "wallet": wallet, "multi": fields["multi"]})
        entry = BUILD
        args = {RDI: OUT_AT, RSI: REQUEST_AT}
    else:
        which = fields["which"]
        row = {"cdeposit": 62, "cwithdraw": 61, "delegate": 33}[which]
        want = {"nonce": fields["now_ms"], "signature": signature_of(hashlib.sha256(b"user" + bytes([row, 0])).digest(), wallet[1])}
        state["events"].append(("user", row, False, wallet[0], True))
        if which == "delegate":
            entry = SEND_DELEGATE
            args = {RDI: OUT_AT, RSI: fields["chain"], RDX: VALIDATOR_AT, RCX: fields["amount"], R8: fields["flag"], R9: wallet_at}
        else:
            entry = SEND_CDEPOSIT if which == "cdeposit" else SEND_CWITHDRAW
            args = {RDI: OUT_AT, RSI: fields["chain"], RDX: fields["amount"], RCX: wallet_at}
    got_stop = None
    try:
        machine.run(entry, args)
    except Panicked as error:
        got_stop = "%s" % error
        harness.panicked = True
    if isinstance(want, str):
        if got_stop is None:
            return "no panic: %s" % want
    elif got_stop is not None:
        return "panic %s" % got_stop
    if harness.events != state["events"]:
        return "events %s vs %s" % (harness.events[:3], state["events"][:3])
    if isinstance(want, str):
        return None
    if kind == "bundle":
        return compare_bundle(harness, case, want)
    if kind == "decode":
        return compare_decode(harness, want)
    if kind == "verify":
        status, word = want
        if memory.read(OUT_AT, 2) != status:
            return "verify status"
        if status == 0x186:
            if memory.bytes_at(OUT_AT + 2, 20) != word:
                return "verify address"
        elif memory.read(OUT_AT + 8, 8) != word:
            return "verify word"
        return None if not harness.live else "leak"
    if kind in ("plain", "multi"):
        if memory.bytes_at(OUT_AT, 0x41) != want:
            return "signature"
        return None if not harness.live else "leak"
    return compare_record(harness, case, want, wallet_at)


def compare_bundle(harness, case, want):
    memory = harness.machine.memory
    cap, used = case.fields["queue"]
    count = memory.read(STATE_AT + 0x4E0, 8)
    if want is None:
        return None if count == used else "pushed on error"
    if count != used + 1:
        return "queue count"
    queue = memory.read(STATE_AT + 0x4D8, 8)
    item = queue + 0x168 * used
    if memory.read(item, 8) != 9:
        return "queue tag"
    arc = memory.read(item + 8, 8)
    if (memory.read(arc, 8), memory.read(arc + 8, 8)) != (1, 1):
        return "arc counts"
    if memory.read(arc + 0x20, 8) != len(want) or memory.bytes_at(memory.read(arc + 0x18, 8), len(want)) != want:
        return "wire bytes"
    if used and memory.read(queue, 8) != 0x4A4A4A4A4A4A4A4A:
        return "queue head"
    return None


def compare_decode(harness, want):
    memory = harness.machine.memory
    status, value = want
    if memory.read(OUT_AT, 2) != status:
        return "decode status %#x want %#x" % (memory.read(OUT_AT, 2), status)
    if status in (0x89, 0x8A, 0x8B) and memory.read(OUT_AT + 2, 1) != value:
        return "decode byte"
    if status == 0x7A and memory.read(OUT_AT + 8, 8) != value:
        return "decode word"
    if status == 0x55 and memory.bytes_at(OUT_AT + 2, 0x5E) != bytes(range(0x2A, 0x88)):
        return "decode error bytes"
    if status != 0x186:
        return None
    records = value["records"]
    if memory.read(OUT_AT + 0x18, 8) != len(records) or memory.read(OUT_AT + 0x20, 8) != value["time"] or memory.bytes_at(OUT_AT + 0x28, 20) != value["signer"]:
        return "decode head"
    at = memory.read(OUT_AT + 0x10, 8)
    for index, fields in enumerate(records):
        item = memory.bytes_at(at + 0x168 * index, 0x168)
        if item[0x100:0x141] != fields["signature"] or int.from_bytes(item[0x148:0x150], "little") != fields["nonce"] or item[0x10:0x100] != fields["action"] or item[0x165] != fields["flag"]:
            return "decode record %d" % index
        if (item[0x150] == 1) != (fields["vault"] is not None) or (fields["vault"] is not None and item[0x151:0x165] != fields["vault"]):
            return "decode vault %d" % index
        if int.from_bytes(item[:8], "little") != (0 if fields["expiry"] is None else 1) or (fields["expiry"] is not None and int.from_bytes(item[8:16], "little") != fields["expiry"]):
            return "decode expiry %d" % index
    return None


def compare_record(harness, case, want, wallet_at):
    memory = harness.machine.memory
    fields = case.fields
    out = memory.bytes_at(OUT_AT, 0x168)
    if out[0x100:0x141] != want["signature"]:
        return "record signature"
    if int.from_bytes(out[0x148:0x150], "little") != want["nonce"]:
        return "record nonce"
    if out[0x165] != 0:
        return "record byte 0x165"
    if case.kind == "send":
        action = out[0x10:0x100]
        which = fields["which"]
        tag = {"cdeposit": 0xB2, "cwithdraw": 0xB1, "delegate": 0x95}[which]
        head = struct.pack("<QQQQQQQ", tag, 1, 0, 0, 0, fields["amount"], fields["now_ms"])
        if action[:0x38] != head or out[:8] != bytes(8) or out[8:16] != wallet_at.to_bytes(8, "little") or out[0x150] != 0:
            return "send head"
        if which == "delegate":
            if action[0x38:0x4C] != fields["validator"] or action[0x4C] != fields["chain"] or action[0x4D] != fields["flag"]:
                return "delegate body"
        elif action[0x38] != fields["chain"]:
            return "send chain"
        return None if not harness.live else "leak"
    if out[0x150:0x165] != want["vault"]:
        return "record vault"
    if want["expiry"] is None:
        if out[:8] != bytes(8):
            return "record no expiry"
    elif int.from_bytes(out[:8], "little") != 1 or int.from_bytes(out[8:16], "little") != want["expiry"]:
        return "record expiry"
    if "action" in want:
        if out[0x10:0x100] != want["action"]:
            return "record action"
        if want["expiry"] is None and out[8:16] != wallet_at.to_bytes(8, "little"):
            return "stale word"
        return None if not harness.live else "leak"
    if out[8:16] != bytes([STACK_MARK]) * 8:
        return "multi word 1"
    action = fields["action"]
    wrapped = out[0x10:0x100]
    signers = want["signers"]
    cap, at, count = struct.unpack("<QQQ", wrapped[8:0x20])
    box = int.from_bytes(wrapped[0x20:0x28], "little")
    if wrapped[:8] != MULTI_SIG_TAG.to_bytes(8, "little") or cap != len(signers) or count != len(signers):
        return "wrap head"
    if wrapped[0x28:0x3C] != MULTI_USER or wrapped[0x3C:0x50] != wallet_address(fields["wallet"][0]):
        return "wrap addresses"
    if int.from_bytes(wrapped[0x50:0x58], "little") != want["chain_id"] or wrapped[0x58:0x70] != bytes(0x18):
        return "wrap chain id"
    if wrapped[0x70:] != action[0x70:]:
        return "wrap tail"
    if memory.bytes_at(box, 0xF0) != action:
        return "wrap box"
    for index, signature in enumerate(signers):
        if memory.bytes_at(at + 0x48 * index, 0x41) != signature:
            return "signer %d" % index
    sizes = sorted(harness.live.values())
    if sizes != sorted([0xF0] + ([0x48 * len(signers)] if signers else [])):
        return "live %s" % sizes
    return None


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


def stack_store(window, disp, width):
    """Last immediate stored at [rsp+disp] in a byte window, by the three fixed store forms, or None."""
    forms = {8: (b"\x48\xc7\x84\x24", b"\x48\xc7\x44\x24", 4), 4: (b"\xc7\x84\x24", b"\xc7\x44\x24", 4), 1: (b"\xc6\x84\x24", b"\xc6\x44\x24", 1)}
    long_form, short_form, size = forms[width]
    needles = [long_form + struct.pack("<I", disp)]
    if disp < 0x80:
        needles.append(short_form + bytes([disp]))
    best = None
    for needle in needles:
        at = window.rfind(needle)
        if at >= 0 and (best is None or at > best[0]):
            best = (at, int.from_bytes(window[at + len(needle):at + len(needle) + size], "little"))
    return None if best is None else best[1]


def site_rows(image):
    """One row per call of the builder: host, request base, tag, nonce form, vault byte, multi byte."""
    rows = []
    for site, base in REQUEST_SITES:
        window = code(image, site - 0x1C0, 0x1C0)
        nonce = stack_store(window, base, 8)
        if nonce is None:
            nonce = stack_store(window, base, 4)
        tag = stack_store(window, base + 0x10, 8)
        rows.append({"site": site, "host": image.fde(site)[0], "base": base, "tag": tag, "nonce_form": nonce, "vault_byte": stack_store(window, base + 0x108, 1), "multi_byte": stack_store(window, base + 0x11D, 1)})
    return rows


def sample_facts(image):
    """Fixed bytes of the signer sample and its collector."""
    take = code(image, 0x13CD1DE, 5)
    stride = code(image, 0x14B1544, 7)
    if take[:1] != b"\xb8" or stride[:3] != b"\x48\x69\xc5":
        raise EvidenceError("signer sample bytes moved")
    return {"take_limit": int.from_bytes(take[1:], "little"), "wallet_stride": int.from_bytes(stride[3:], "little"), "cmp_two": code(image, 0x13CD1DA, 4).hex()}


def handler_names():
    data = json.loads(HANDLERS.read_text())
    names = {}
    for case in data["cases"]:
        recon = case.get("reconstruction") or {}
        names[case["index"]] = recon.get("wire_type") or "-"
    return names


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


def build_spec(table):
    chain_at = {row: value for row, value in table.chain_at.items() if row != MULTI_SIG_ROW}
    time_at = {row: value for row, value in table.time_at.items() if row != MULTI_SIG_ROW}
    return Spec(chain_at, time_at), chain_at, time_at


def worker_start():
    image = load_image()
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    spec, chain_at, time_at = build_spec(harness.table)
    MUTANT_STATE.update(harness=harness, cases=all_cases(chain_at, time_at), spec=spec)


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
        except (Halt, Panicked, EvidenceError, KeyError, ValueError, IndexError, OverflowError, TypeError, struct.error) as error:
            trouble = "%s" % type(error).__name__
        if trouble:
            failed = cases[index].label + ": " + trouble
            break
    machine.patches = {}
    machine.cache.pop(va, None)
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:60].replace("\t", " ") if failed else ""}


def run_mutants(image, targets, reached, labels, always):
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
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
            groups = {}
            for index in indices:
                groups.setdefault(labels[index], []).append(index)
            chosen = []
            for name in sorted(groups):
                chosen += groups[name][:2]
            if len(chosen) > MUTANT_CASES:
                step = len(chosen) / MUTANT_CASES
                chosen = [chosen[int(step * item)] for item in range(MUTANT_CASES)]
            tasks.append((start, va, at, kind, sorted(set(chosen + indices[:2] + indices[-2:] + [index for index in indices if index in always]))))
    with multiprocessing.Pool(WORKERS, worker_start) as pool:
        results += pool.map(run_one, tasks, 8)
    return sorted(results, key=lambda row: (row["function"], row["va"], row["kind"]))


# ---- evidence ----

def outcome_of(harness, case):
    """A short outcome label from the recorded events."""
    events = harness.events
    parts = [case.kind]
    drops = [row[1] for row in events if row[0] == "drop"]
    if drops:
        parts.append("status %#x" % drops[0])
    if harness.panicked:
        parts.append("panic")
    elif any(row[0] == "user" for row in events):
        parts.append("user %d" % sum(1 for row in events if row[0] == "user"))
    if any(row[0] == "payload" for row in events):
        parts.append("agent")
    if any(row[0] == "multi_payload" for row in events):
        parts.append("multi agent")
    if case.kind == "verify":
        parts.append("%#x" % harness.machine.memory.read(OUT_AT, 2))
    if case.kind == "build":
        parts.append("multi wrap" if case.fields["multi"] else "single")
    return " ".join(parts)


def row_lines(table, names):
    lines = ["row\ttag\tname\texpiry\tplain_form\tplain_host\tplain_signer\tmulti_form\tmulti_host\tmulti_signer\tchain_at\ttime_at"]
    for row in range(ROWS):
        plain_host = table.plain_host.get(row)
        multi_host = table.multi_host.get(row)
        chain, time = table.chain_at.get(row), table.time_at.get(row)
        lines.append("%d\t%#x\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (
            row, row + TAG_BASE, names.get(row, "-"), "now+30s" if table.has_expiry(row) else "none", "user" if plain_host else "agent", "%#x" % plain_host if plain_host else "-",
            "%#x" % table.plain_signer[row] if plain_host else "-", "user" if multi_host else "agent", "%#x" % multi_host if multi_host else "-", "%#x" % table.multi_signer[row] if multi_host else "-",
            "%#x" % chain if chain is not None else "-", "%#x" % time if time is not None else "-"))
    return lines


def date_lines(cases, spec):
    lines = ["label\tpacked\tseconds\tnanos\tunix_ms\texpiry"]
    for case in cases:
        if case.label.startswith("build/date/"):
            utc = case.fields["utc"]
            lines.append("%s\t%#x\t%d\t%d\t%d\t%d" % (case.label[11:], utc[0], utc[1], utc[2], unix_ms(utc), expiry_after(utc)))
    return lines


def analyse(image, full=True):
    harness = Harness(image)
    table = harness.table
    spec, chain_at, time_at = build_spec(table)
    cases = all_cases(chain_at, time_at)
    machine = harness.machine
    mismatches = []
    outcomes = collections.Counter()
    reached = []
    labels = []
    seen = set()
    lines = []
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
        outcome = outcome_of(harness, case)
        outcomes[outcome] += 1
        labels.append(outcome)
        lines.append("\t".join((case.kind, case.label, outcome, "fail" if trouble else "match")))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    core = ((BUILD, "builder"), (SIGNER_MAP, "signer map"), (MULTI, "multi sign table"), (MULTI_TAIL, "multi agent tail"), (PLAIN, "plain sign table"), (AGENT_SIGN, "agent sign"), (AGENT_VERIFY, "agent verify"), (SIGN_DIGEST, "digest then secp"),
            (QUEUE_PUSH, "queue push"), (BUNDLE_ENCODE, "bundle encoder"), (RECORD_ENCODE, "record encoder"), (BUNDLE_DECODE, "bundle reader"), (RECORD_DECODE, "record reader"),
            (SEND_CDEPOSIT, "cDeposit sender"), (SEND_CWITHDRAW, "cWithdraw sender"), (SEND_DELEGATE, "tokenDelegate sender"))
    targets = core + tuple((host, "plain gate row %d" % row) for row, host in sorted(table.plain_host.items())) + tuple((host, "multi gate row %d" % row) for row, host in sorted(table.multi_host.items()))
    functions = []
    function_lines = ["start\tend\tbytes\tinstructions\tstepped\trole"]
    for start, role in targets:
        begin, end = image.exact_fde(start)
        rows = body_rows(image, begin, end)
        hit = sum(1 for row in rows if row.va in seen)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "instructions": len(rows), "stepped": hit})
        function_lines.append("%#x\t%#x\t%d\t%d\t%d\t%s" % (begin, end, end - begin, len(rows), hit, role))
    always = frozenset(index for index, case in enumerate(cases) if case.label.startswith(("build/date/", "build/multi/", "bundle/", "decode/")))
    results_rows = run_mutants(image, targets, reached, labels, always) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    names = handler_names()
    sites = site_rows(image)
    site_lines = ["site\thost\trequest_base\ttag\tname\tnonce_form\tvault_byte\tmulti_byte"]
    for row in sites:
        tag = row["tag"]
        site_lines.append("%#x\t%#x\t%#x\t%s\t%s\t%s\t%s\t%s" % (row["site"], row["host"], row["base"], "%#x" % tag if tag is not None else "parsed", names.get(tag - TAG_BASE, "-") if tag is not None else "-", row["nonce_form"], row["vault_byte"], row["multi_byte"]))
    status_lines = ["tag\tarm\tform\ttext"]
    for tag, arm, form, text in (status_row(image, tag) for tag in STATUS_TAGS):
        status_lines.append("%#x\t%#x\t%s\t%s" % (tag, arm, form, text))
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0][:200] if mismatches else "",
        "instructions_stepped": steps,
        "functions": functions,
        "mutations": tally,
        "rows": {"total": ROWS, "no_expiry": sum(1 for row in range(ROWS) if not table.has_expiry(row)), "plain_user": len(table.plain_host), "multi_user": len(table.multi_host)},
        "builder_sites": ["%#x" % site for site in slot_sites(image, SLOT_BUILD)],
        "sign_table_sites": ["%#x" % site for site in slot_sites(image, SLOT_PLAIN)],
        "signer_map_sites": ["%#x" % site for site in direct_sites(image, SIGNER_MAP)],
        "signer_sample_sites": ["%#x" % site for site in slot_sites(image, SLOT_WALLETS)],
        "signer_sample": sample_facts(image),
        "record_encoder_sites": ["%#x" % site for site in slot_sites(image, SLOT_ENCODE)],
        "bundle_reader_sites": ["%#x" % site for site in slot_sites(image, SLOT_READER)],
        "record_reader_sites": ["%#x" % site for site in direct_sites(image, RECORD_DECODE)],
        "multi_user": MULTI_USER.hex(),
        "constants": {"multi_user_head": code(image, 0x58B94D, 16).hex(), "chain_ids": [MAINNET_CHAIN_ID, TESTNET_CHAIN_ID], "expiry_add_ms": EXPIRY_ADD_MS},
        "panic_texts": [code(image, at, 0x2B).decode("ascii", "replace") for at in PANIC_TEXTS],
        "_results": results_rows, "_lines": lines, "_functions": function_lines, "_rows": row_lines(table, names), "_sites": site_lines, "_status": status_lines, "_dates": date_lines(cases, spec),
    }
    return doc


UNREACHED_REASON = "no case reaches it: a panic arm, an unwind pad, an allocator failure, or a table arm with no fixture"


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toutcome\tresult"] + evidence.pop("_lines"), "functions.tsv": evidence.pop("_functions"), "action-rows.tsv": evidence.pop("_rows"), "builder-sites.tsv": evidence.pop("_sites"),
              "status-text.tsv": evidence.pop("_status"), "date-vectors.tsv": evidence.pop("_dates")}
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    for name, lines in tables.items():
        files[name] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else (UNREACHED_REASON if row["result"] == "unreached" else survivor_reason(row["function"], row["va"], row["kind"])))) for row in results]
    files["mutations.tsv"] = "\n".join(lines) + "\n"
    return files


WIRE_REASON = "wire code class, not hand checked row by row: buffer capacity test, start capacity, alignment, copy size, a status built only for a dropped ok_or value, or a free guard"
MULTI_FIELD_REASON = "action field copied into the struct of the stubbed signer, or the dangling pointer of an empty text; the stub reads only the user and outer pair"
SURVIVOR_GROUPS = (
    ("copy size one byte larger or a stack base that a later store overwrites", (0x3341B73, 0x3341C94, 0x3341CD4, 0x3341DEA, 0x3341FC0, 0x334202E)),
    ("tag bound or low tag row that lands on an arm of the same class", (0x3341EBC, 0x3341EC0, 0x335EDE2, 0x335EDE6, 0x3362B43, 0x3362B47)),
    ("stack probe word", (0x335EDC0,)),
    ("a year of 0 or below gives a negative time and the floor at 0 hides the whole cycle shift", (0x3341F18, 0x3341F20, 0x3341F27, 0x3341F2D, 0x3341F37)),
    ("rounding of the divide by 100 that gives the same quotient on these years, or a sign fix on a value that is never negative here", (0x3341F54, 0x3341F5E)),
    ("the sender puts the same clock word in the nonce and the action, so a None nonce gives the same record", (0x4A10FAF, 0x4A1104F, 0x4A1110D)),
    ("capacity bit below the 8 byte alignment of a pointer list, or the dangling pointer of an empty list", (0x3BAD2B1, 0x3BAD2B9, 0x3BAD43E)),
)
SURVIVOR_CLASS = {va: name for name, group in SURVIVOR_GROUPS for va in group}


def survivor_reason(function, va, kind):
    if function in SURVIVOR_CLASS or va in SURVIVOR_CLASS:
        return SURVIVOR_CLASS.get(va, SURVIVOR_CLASS.get(function))
    if function in (QUEUE_PUSH, BUNDLE_ENCODE, RECORD_ENCODE, BUNDLE_DECODE, RECORD_DECODE):
        return WIRE_REASON
    if function not in (BUILD, SIGNER_MAP, MULTI, PLAIN, MULTI_TAIL, SEND_CDEPOSIT, SEND_CWITHDRAW, SEND_DELEGATE):
        return MULTI_FIELD_REASON
    return "unclassified"


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
