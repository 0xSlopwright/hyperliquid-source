#!/usr/bin/env python3
"""Evaluate the node #94 user signed action family from ELF bytes: 41 EIP-712 type texts, struct hashes, digests, signer gates and both dispatch tables.

Every user signed action (withdraw3 and 20 others, plain and in a multi sig wrapper) runs through the same five function tiers: type hash, struct hash, digest, error mapping
and verifier. The real bytes of all of them run in a Python evaluator with the allocator and the secp256k1 recover slot stubbed. A separately written table predicts each type
text, struct hash, digest and gate status, and conditions, immediates and offsets of a sample of the functions are flipped to show the run can tell. No objdump or readelf output
is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import collections
import hashlib
import json
import math
import multiprocessing
import pathlib
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

KECCAK_F = 0x4F59480
TYPE_HASH = 0x1594E50
CAMEL = 0x37EAF70
ERROR_BOX = 0x365EB00
SIGN_DIGEST = 0x14A2710
ACTION_HASH = 0x3984FE0
ERROR_DROP = 0x37F9400
DISPATCH = 0x333FC80
DISPATCH_TABLE = 0x587A3C
DISPATCH_REST = 0x333F690
DISPATCH_ROWS = 88
MULTI_DISPATCH = 0x3360B40
MULTI_TABLE = 0x588FFC
MULTI_ROWS = 88
TAG_BASE = 0x74
TIER4_TABLE = 0x599F30
TIER4_TEXTS = ((0x2602C0, 0x25), (0x2602E5, 0x1A), (0x2602FF, 0x26), (0x260325, 0x27), (0x26034C, 0x36))
CHAIN_POINTERS = 0x57100C0
CHAIN_LENGTHS = 0x20CBE0
ENUM_TABLES = {"vote": (0x56EAA98, 0x58C2D8, 3), "cat": (0x5710088, 0x20C6E0, 4), "abs": (0x5710060, 0x5A8CF0, 5)}
ENCODING_TEXT = ((0x5A74CD, 3), (0x5A74D0, 6))
PREFIX_1901 = 0x5A6048
NAME_TEXT = 0x5A83E6
TYPE_PREFIX = 0x5A5E9C
STATUS_TEXTS = ((0x15, 0x59C539, 0x22), (0x5D, None, 0), (0x7A, None, 0), (0x8C, None, 0), (0x8F, None, 0))
SEND_MULTI_SIG = "SendMultiSig"
MUTANT_STEP_LIMIT = 400000
MUTANT_CASES = 14
SAMPLE_EVERY = 5
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
FAKE_CLONE = 0x7000
FAKE_DROP = 0x7008

OUT = HEAP_BASE + 0x400
ACTION_AT = HEAP_BASE + 0x500
ENVELOPE_AT = HEAP_BASE + 0x800
TEXT_AT = HEAP_BASE + 0x1000
SIGNATURE_AT = HEAP_BASE + 0x4000
USER_AT = HEAP_BASE + 0x4080
OUTER_AT = HEAP_BASE + 0x40A0
CTX_AT = HEAP_BASE + 0x40C0
VTABLE_AT = HEAP_BASE + 0x4100
WALLET_AT = HEAP_BASE + 0x4200
HEAP_FREE = HEAP_BASE + 0x8000

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
        if rela["size"] % 24 != 0:
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


# ---- specification: written from the reading notes, it never looks at the evaluator ----

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
ROTATIONS = (1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44)
LANES = (10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1)
MASK64 = (1 << 64) - 1


def keccak_f(state):
    for constant in ROUND_CONSTANTS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        for x in range(5):
            right = columns[(x + 1) % 5]
            mixed = columns[(x + 4) % 5] ^ ((right << 1 | right >> 63) & MASK64)
            for y in range(0, 25, 5):
                state[y + x] ^= mixed
        last = state[1]
        for lane, turn in zip(LANES, ROTATIONS):
            state[lane], last = (last << turn | last >> (64 - turn)) & MASK64, state[lane]
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5] & MASK64)
        state[0] ^= constant


def keccak(data):
    rate = 136
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    padded[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(padded), rate):
        for at in range(rate // 8):
            state[at] ^= int.from_bytes(padded[start + 8 * at:start + 8 * at + 8], "little")
        keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def word(value):
    return value.to_bytes(32, "big")


TYPES = (
    ("GovVote", 0, (0x330cc00, 0x330c570, 0x3312000, 0x37f2b80, 0x33e0300, 0x359e730), 0x48, 0x0, (("id", "bytes32", 0x20), ("choice", "vote", 0x49), ("nonce", "uint64", 0x40),)),
    ("ApproveAgent", 1, (0x330d540, 0x330cf10, 0x3313b10, 0x37ecf40, 0x330dcd0, 0x35a03f0), 0x7c, 0x18, (("payloadMultiSigUser", "address", 0x40), ("outerSigner", "address", 0x54), ("agentAddress", "address", 0x68), ("agentName", "opt", 0x0), ("nonce", "uint64", 0x38),)),
    ("CDeposit", 0, (0x330e480, 0x330df90, 0x3312a30, 0x37ef580, 0x33e0770, 0x35a0c90), 0x30, 0x0, (("wei", "uint64", 0x20), ("nonce", "uint64", 0x28),)),
    ("UserSetAbstraction", 1, (0x3310b40, 0x3310510, 0x3313e80, 0x37f1980, 0x3311e30, 0x359dbb0), 0x65, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("user", "address", 0x50), ("abstraction", "abs", 0x64), ("nonce", "uint64", 0x20),)),
    ("ApproveAgent", 0, (0x33118a0, 0x3311350, 0x3312360, 0x37edf00, 0x330d9b0, 0x359ffa0), 0x54, 0x18, (("agentAddress", "address", 0x40), ("agentName", "opt", 0x0), ("nonce", "uint64", 0x38),)),
    ("StakingLinkDisableTradingUser", 1, (0x33147b0, 0x33141e0, 0x3312d90, 0x37f1bc0, 0x3317230, 0x359f420), 0x64, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("tradingUser", "address", 0x50), ("nonce", "uint64", 0x20),)),
    ("UserSetAbstraction", 0, (0x3315760, 0x3315210, 0x33126d0, 0x37efc40, 0x3311c10, 0x359f9e0), 0x3d, 0x0, (("user", "address", 0x28), ("abstraction", "abs", 0x3c), ("nonce", "uint64", 0x20),)),
    ("StakingLinkDisableTradingUser", 0, (0x3317c50, 0x3317760, 0x33137b0, 0x37ef7c0, 0x3317020, 0x35a0b20), 0x3c, 0x0, (("tradingUser", "address", 0x28), ("nonce", "uint64", 0x20),)),
    ("GovVote", 1, (0x33f0990, 0x33f0210, 0x33130f0, 0x37f0c00, 0x33e0530, 0x359f870), 0x70, 0x0, (("payloadMultiSigUser", "address", 0x48), ("outerSigner", "address", 0x5c), ("id", "bytes32", 0x20), ("choice", "vote", 0x71), ("nonce", "uint64", 0x40),)),
    ("CDeposit", 1, (0x3403730, 0x3403150, 0x3313450, 0x37ee5c0, 0x33e0980, 0x359f2b0), 0x58, 0x0, (("payloadMultiSigUser", "address", 0x30), ("outerSigner", "address", 0x44), ("wei", "uint64", 0x20), ("nonce", "uint64", 0x28),)),
    ("CWithdraw", 1, (0x38dde30, 0x38dd850, 0x38ef4f0, 0x37ed840, 0x3a1c950, 0x35a0560), 0x58, 0x0, (("payloadMultiSigUser", "address", 0x30), ("outerSigner", "address", 0x44), ("wei", "uint64", 0x20), ("nonce", "uint64", 0x28),)),
    ("SendAsset", 1, (0x38deb30, 0x38de1c0, 0x38efbc0, 0x37eeec0, 0x3a1d160, 0x359d8d0), 0xe0, 0x90, (("payloadMultiSigUser", "address", 0xb8), ("outerSigner", "address", 0xcc), ("destination", "string", 0x8), ("sourceDex", "string", 0x20), ("destinationDex", "string", 0x38), ("token", "string", 0x50), ("amount", "string", 0x68), ("fromSubAccount", "string", 0x80), ("nonce", "uint64", 0xb0),)),
    ("GovPropose", 1, (0x38df930, 0x38df140, 0x38f5130, 0x37ef340, 0x3a1e8d0, 0x359da40), 0x80, 0x30, (("payloadMultiSigUser", "address", 0x58), ("outerSigner", "address", 0x6c), ("title", "string", 0x8), ("description", "string", 0x20), ("category", "cat", 0x81), ("nonce", "uint64", 0x50),)),
    ("CUserModify", 1, (0x38e0840, 0x38e0280, 0x38f2b70, 0x37ed180, 0x38e0030, 0x359ecf0), 0x50, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("extendLongTermStaking", "bool", 0x51), ("nonce", "uint64", 0x20),)),
    ("UsdSend", 0, (0x38e11b0, 0x38e0bc0, 0x38f3260, 0x37eda80, 0x3a11520, 0x359e000), 0x58, 0x30, (("destination", "string", 0x8), ("amount", "string", 0x20), ("time", "uint64", 0x50),)),
    ("TokenDelegate", 1, (0x38e1b60, 0x38e14b0, 0x38f2150, 0x37eea40, 0x38e2cb0, 0x359ea10), 0x6c, 0x0, (("payloadMultiSigUser", "address", 0x30), ("outerSigner", "address", 0x44), ("validator", "address", 0x58), ("wei", "uint64", 0x20), ("isUndelegate", "bool", 0x6d), ("nonce", "uint64", 0x28),)),
    ("SpotSend", 0, (0x38e26a0, 0x38e1ff0, 0x38f1de0, 0x37edcc0, 0x3a1b760, 0x35a0e00), 0x70, 0x48, (("destination", "string", 0x8), ("token", "string", 0x20), ("amount", "string", 0x38), ("time", "uint64", 0x68),)),
    ("Withdraw", 0, (0x38e36b0, 0x38e30c0, 0x38ef850, 0x37f0780, 0x3a1bff0, 0x359fb50), 0x58, 0x30, (("destination", "string", 0x8), ("amount", "string", 0x20), ("time", "uint64", 0x50),)),
    ("CWithdraw", 0, (0x38e3f90, 0x38e3aa0, 0x38f5810, 0x37ee800, 0x3a1c740, 0x359f590), 0x30, 0x0, (("wei", "uint64", 0x20), ("nonce", "uint64", 0x28),)),
    ("LinkStakingUser", 1, (0x38e4840, 0x38e4210, 0x38f1720, 0x37f1740, 0x38e8710, 0x359f140), 0x64, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("user", "address", 0x50), ("isFinalize", "bool", 0x65), ("nonce", "uint64", 0x20),)),
    ("SendAsset", 0, (0x38e54b0, 0x38e4c40, 0x38f4a50, 0x37f1080, 0x3a1cb80, 0x359eb80), 0xb8, 0x90, (("destination", "string", 0x8), ("sourceDex", "string", 0x20), ("destinationDex", "string", 0x38), ("token", "string", 0x50), ("amount", "string", 0x68), ("fromSubAccount", "string", 0x80), ("nonce", "uint64", 0xb0),)),
    ("UsdClassTransfer", 1, (0x38e6040, 0x38e59c0, 0x38f54a0, 0x37f09c0, 0x38ebac0, 0x359e5c0), 0x69, 0x18, (("payloadMultiSigUser", "address", 0x40), ("outerSigner", "address", 0x54), ("amount", "string", 0x8), ("toPerp", "bool", 0x68), ("nonce", "uint64", 0x38),)),
    ("ApproveBuilderFee", 1, (0x38e6ae0, 0x38e6450, 0x38f4000, 0x37f0540, 0x38ec860, 0x359f700), 0x7c, 0x18, (("payloadMultiSigUser", "address", 0x40), ("outerSigner", "address", 0x54), ("maxFeeRate", "string", 0x8), ("builder", "address", 0x68), ("nonce", "uint64", 0x38),)),
    ("GovPropose", 0, (0x38e7640, 0x38e6ee0, 0x38f3c90, 0x37eec80, 0x3a1e530, 0x359e170), 0x58, 0x30, (("title", "string", 0x8), ("description", "string", 0x20), ("category", "cat", 0x59), ("nonce", "uint64", 0x50),)),
    ("UserDexAbstraction", 1, (0x38e8f10, 0x38e88e0, 0x38f3930, 0x37f0e40, 0x38eeb50, 0x359d5f0), 0x64, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("user", "address", 0x50), ("enabled", "bool", 0x65), ("nonce", "uint64", 0x20),)),
    ("SendToEvmWithData", 1, (0x38e9ea0, 0x38e9310, 0x38f2ed0, 0x37f2700, 0x38ee3d0, 0x35a0280), 0xdd, 0x80, (("payloadMultiSigUser", "address", 0xb0), ("outerSigner", "address", 0xc4), ("token", "string", 0x8), ("amount", "string", 0x20), ("sourceDex", "string", 0x38), ("destinationRecipient", "string", 0x50), ("addressEncoding", "enc", 0xdc), ("destinationChainId", "uint32", 0xd8), ("gasLimit", "uint64", 0xa0), ("data", "bytes", 0x60), ("nonce", "uint64", 0xa8),)),
    ("UserPortfolioMargin", 1, (0x38eac00, 0x38ea5d0, 0x38f0290, 0x37f24c0, 0x38eefb0, 0x35a0f70), 0x64, 0x0, (("payloadMultiSigUser", "address", 0x28), ("outerSigner", "address", 0x3c), ("user", "address", 0x50), ("enabled", "bool", 0x65), ("nonce", "uint64", 0x20),)),
    ("CUserModify", 0, (0x38eb4e0, 0x38eb000, 0x38f1a80, 0x37efe80, 0x38dfe20, 0x35a0840), 0x28, 0x0, (("extendLongTermStaking", "bool", 0x29), ("nonce", "uint64", 0x20),)),
    ("SendMultiSig", 0, (0x38ec270, 0x38ebd50, 0x38f35d0, 0x37f12c0, 0x3a1b570, 0x35a06d0), 0x48, 0x0, (("multiSigActionHash", "bytes32", 0x20), ("nonce", "uint64", 0x40),)),
    ("ConvertToMultiSigUser", 1, (0x38ed120, 0x38ecb00, 0x38f4370, 0x37f0300, 0x38f7bd0, 0x35a09b0), 0x68, 0x18, (("payloadMultiSigUser", "address", 0x40), ("outerSigner", "address", 0x54), ("signers", "string", 0x8), ("nonce", "uint64", 0x38),)),
    ("TokenDelegate", 0, (0x38eda70, 0x38ed4a0, 0x38f05f0, 0x37f1e00, 0x38e2a90, 0x359e2e0), 0x44, 0x0, (("validator", "address", 0x30), ("wei", "uint64", 0x20), ("isUndelegate", "bool", 0x45), ("nonce", "uint64", 0x28),)),
    ("LinkStakingUser", 0, (0x38f6430, 0x38f5ee0, 0x38f2810, 0x37ef100, 0x38e84f0, 0x359e450), 0x3c, 0x0, (("user", "address", 0x28), ("isFinalize", "bool", 0x3d), ("nonce", "uint64", 0x20),)),
    ("UsdClassTransfer", 0, (0x38f6cd0, 0x38f6730, 0x38ef180, 0x37f2040, 0x38eb7d0, 0x359dd20), 0x41, 0x18, (("amount", "string", 0x8), ("toPerp", "bool", 0x40), ("nonce", "uint64", 0x38),)),
    ("ApproveBuilderFee", 0, (0x38f7570, 0x38f6fd0, 0x38f46e0, 0x37ee380, 0x38ec560, 0x359e8a0), 0x54, 0x18, (("maxFeeRate", "string", 0x8), ("builder", "address", 0x40), ("nonce", "uint64", 0x38),)),
    ("SendToEvmWithData", 0, (0x38f8900, 0x38f7e50, 0x38f0950, 0x37f1500, 0x38ede80, 0x359efd0), 0xb5, 0x80, (("token", "string", 0x8), ("amount", "string", 0x20), ("sourceDex", "string", 0x38), ("destinationRecipient", "string", 0x50), ("addressEncoding", "enc", 0xb4), ("destinationChainId", "uint32", 0xb0), ("gasLimit", "uint64", 0xa0), ("data", "bytes", 0x60), ("nonce", "uint64", 0xa8),)),
    ("UserDexAbstraction", 0, (0x38f9470, 0x38f8f20, 0x38f24b0, 0x37efa00, 0x38ee930, 0x35a10e0), 0x3c, 0x0, (("user", "address", 0x28), ("enabled", "bool", 0x3d), ("nonce", "uint64", 0x20),)),
    ("UserPortfolioMargin", 0, (0x38f9e30, 0x38f98e0, 0x38f1050, 0x37ed600, 0x38eed90, 0x359fcc0), 0x3c, 0x0, (("user", "address", 0x28), ("enabled", "bool", 0x3d), ("nonce", "uint64", 0x20),)),
    ("ConvertToMultiSigUser", 0, (0x38fa660, 0x38fa130, 0x38f4dc0, 0x37f00c0, 0x38f78e0, 0x359fe30), 0x40, 0x18, (("signers", "string", 0x8), ("nonce", "uint64", 0x38),)),
    ("UsdSend", 1, (0x3a1e0c0, 0x3a1d9f0, 0x38f5b70, 0x37f2280, 0x3a118b0, 0x359d760), 0x80, 0x30, (("payloadMultiSigUser", "address", 0x58), ("outerSigner", "address", 0x6c), ("destination", "string", 0x8), ("amount", "string", 0x20), ("time", "uint64", 0x50),)),
    ("SpotSend", 1, (0x3a1f3e0, 0x3a1ec30, 0x38f13b0, 0x37ee140, 0x3a1bb90, 0x359de90), 0x98, 0x48, (("payloadMultiSigUser", "address", 0x70), ("outerSigner", "address", 0x84), ("destination", "string", 0x8), ("token", "string", 0x20), ("amount", "string", 0x38), ("time", "uint64", 0x68),)),
    ("Withdraw", 1, (0x3a1ff30, 0x3a1f860, 0x38f0ce0, 0x37ed3c0, 0x3a1c380, 0x35a0110), 0x80, 0x30, (("payloadMultiSigUser", "address", 0x58), ("outerSigner", "address", 0x6c), ("destination", "string", 0x8), ("amount", "string", 0x20), ("time", "uint64", 0x50),)),
)


# ---- specification: EIP-712 words from the table above, written apart from the machine ----

SOLIDITY = {"opt": "string", "abs": "string", "vote": "string", "cat": "string", "enc": "string", "string": "string", "address": "address", "uint64": "uint64", "uint32": "uint32", "bool": "bool", "bytes32": "bytes32", "bytes": "bytes"}
ENUM_NAMES = {"vote": ("yes", "no", "abstain"), "cat": ("accelerated", "constitutional", "ecosystem", "electoral"), "abs": ("default", "disabled", "dexAbstraction", "unifiedAccount", "portfolioMargin"), "enc": ("hex", "base58")}
CHAIN_NAMES = ("Local", "Sandbox", "Testnet", "Mainnet")
DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
PREFIX = b"HyperliquidTransaction:"


def type_text(row):
    return (PREFIX + row[0].encode("ascii") + b"(string hyperliquidChain," + ",".join("%s %s" % (SOLIDITY[kind], name) for name, kind, _ in row[5]).encode("ascii") + b")")


def field_word(kind, value):
    if kind in ("string", "bytes"):
        return keccak(value)
    if kind == "opt":
        return keccak(value or b"")
    if kind in ENUM_NAMES:
        return keccak(ENUM_NAMES[kind][value].encode("ascii"))
    if kind == "address":
        return bytes(12) + value
    if kind == "bytes32":
        return value
    if kind == "bool":
        return word(1 if value else 0)
    return word(value)


def struct_hash(row, chain, values):
    data = keccak(type_text(row)) + keccak(CHAIN_NAMES[chain].encode("ascii"))
    for name, kind, _ in row[5]:
        data += field_word(kind, values[name])
    return keccak(data)


def domain_hash(signature_chain):
    return keccak(keccak(DOMAIN_TYPE) + keccak(b"HyperliquidSignTransaction") + keccak(b"1") + word(signature_chain) + bytes(32))


def digest_of(row, chain, signature_chain, values):
    return keccak(b"\x19\x01" + domain_hash(signature_chain) + struct_hash(row, chain, values))


def filler(label, count):
    out = b""
    at = 0
    while len(out) < count:
        out += keccak(("%s/%d" % (label, at)).encode("ascii"))
        at += 1
    return out[:count]


TEXT_SIZES = (42, 0, 101, 33)
VARIANT_CHAINS = (3, 2, 1, 0)
VARIANT_IDS = (0xA4B1, 0x66EEE, 0x1122334455667788_99AABBCCDDEEFF00_0102030405060708_1112131415161718, 1)
NUMBERS = (1700000123456, 0, (1 << 64) - 1, 1 << 63)
SHORT = (70000, 0, 0xFFFFFFFF, 0x80000000)


def values_for(row, variant):
    """Field values of one variant, the same for the plain and the multi sig row of an action except the two wrapper addresses."""
    out = {}
    for name, kind, _ in row[5]:
        label = "%s/%s/%d" % (row[0], name, variant)
        if kind == "string":
            out[name] = filler(label, TEXT_SIZES[variant]).hex().encode("ascii")[:TEXT_SIZES[variant]]
        elif kind == "bytes":
            out[name] = filler(label, (5, 0, 70, 32)[variant])
        elif kind == "opt":
            out[name] = (b"worker", None, filler(label, 40).hex().encode("ascii"), b"")[variant]
        elif kind in ENUM_NAMES:
            out[name] = (0, 1, len(ENUM_NAMES[kind]) - 1, 1)[variant]
        elif kind == "address":
            out[name] = bytes(20) if variant == 1 else filler(label, 20)
        elif kind == "bytes32":
            out[name] = bytes(32) if variant == 1 else filler(label, 32)
        elif kind == "bool":
            out[name] = bool((1, 0, 1, 0)[variant])
        elif kind == "uint32":
            out[name] = SHORT[variant]
        else:
            out[name] = NUMBERS[variant]
    return out


def plain_of(row):
    return PLAIN[row[0]]


def time_field(row):
    return next(value for value in row[5] if value[0] in ("time", "nonce"))[0]


PLAIN = {row[0]: row for row in TYPES if not row[1]}


# ---- harness: real bytes through .text; allocator, memory calls and the recover slot are stubbed ----

class RealExcept:
    """Every call target runs its real bytes unless the harness stubs it."""

    def __init__(self):
        self.stubs = frozenset()

    def __contains__(self, target):
        return target not in self.stubs


class Harness:
    def __init__(self, image):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        table = {SLOT_MALLOC: self.on_malloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_BCMP: self.on_bcmp, SLOT_MEMCMP: self.on_bcmp, SLOT_REALLOC: self.on_realloc, SLOT_MEMMOVE: self.on_copy, SLOT_RECOVER: self.on_recover}
        for slot in SLOT_PANIC:
            table[slot] = lambda m, which=slot: self.on_panic(m, which)
        for slot in table:
            relative.setdefault(slot, slot)
        machine.memory.statics.update(relative)
        machine.slots = {relative[slot]: hook for slot, hook in table.items()}
        machine.slots[FAKE_CLONE] = self.on_bytes_clone
        machine.slots[FAKE_DROP] = self.on_bytes_drop
        machine.slots[KECCAK_F] = self.on_keccak_f
        self.real = RealExcept()
        machine.real = self.real
        machine.calls = {SIGN_DIGEST: self.on_sign, ACTION_HASH: self.on_action_hash, DISPATCH_REST: self.on_rest, ERROR_DROP: self.on_error_drop}
        machine.tails = machine.calls
        self.real.stubs = frozenset(machine.slots) | frozenset(machine.calls)
        machine.watch = {}
        self.brk = HEAP_FREE
        self.live = {}
        self.recover_result = None
        self.seen_digest = None
        self.sign_fails = False
        self.action_block = b""
        self.bytes_value = (0, 0)

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
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[8])

    def on_panic(self, m, slot):
        raise Panicked("slot %#x" % slot)

    def on_keccak_f(self, m):
        at = m.regs[RDI]
        state = [m.memory.read(at + 8 * index, 8) for index in range(25)]
        keccak_f(state)
        m.memory.put_bytes(at, b"".join(lane.to_bytes(8, "little") for lane in state))

    def on_bytes_clone(self, m):
        """Clone of a bytes::Bytes: the words come back unchanged, in vtable, pointer, length, data order."""
        out = m.regs[RDI]
        m.memory.write(out, 8, VTABLE_AT)
        m.memory.write(out + 8, 8, m.regs[RDX])
        m.memory.write(out + 0x10, 8, m.regs[RCX])
        m.memory.write(out + 0x18, 8, 0)

    def on_bytes_drop(self, m):
        pass

    def on_error_box(self, m):
        m.regs[RAX] = 0x5555

    def on_tier3_error(self, m):
        out = m.regs[RDI]
        m.memory.put_bytes(out, bytes(0x20))
        m.memory.write(out, 1, 1)
        m.memory.write(out + 8, 8, (1 << 63) | self.tier3_error)

    def on_recover(self, m):
        self.seen_digest = (m.regs[RSI], m.memory.bytes_at(m.regs[RDX], 32))
        out = m.regs[RDI]
        if self.recover_result is None:
            m.memory.write(out, 1, 1)
            m.memory.write(out + 8, 8, 0x4444)
        else:
            m.memory.write(out, 1, 0)
            m.memory.put_bytes(out + 1, self.recover_result)

    def on_sign(self, m):
        self.seen_digest = (m.regs[RSI], m.memory.bytes_at(m.regs[RDX], 32))
        out = m.regs[RDI]
        if self.sign_fails:
            m.memory.write(out, 4, 1)
            m.memory.put_bytes(out + 8, bytes(0x28))
            return
        m.memory.write(out, 4, 0)
        m.memory.put_bytes(out + 8, SIGNED_WORDS)

    def on_action_hash(self, m):
        m.memory.put_bytes(m.regs[RDI], self.action_block)

    def on_error_drop(self, m):
        pass

    def on_rest(self, m):
        self.rest_seen = m.regs[RSI]
        m.memory.write(m.regs[RDI], 2, REST_STATUS)

    def reset(self):
        self.machine.memory.reset()
        self.brk = HEAP_FREE
        self.live = {}
        self.seen_digest = None
        self.recover_result = None
        self.sign_fails = False
        self.rest_seen = None


SIGNED_WORDS = bytes(range(0x41))
REST_STATUS = 0x1234
RECOVERED = bytes(range(0x60, 0x74))


# ---- driving one case ----

def put_text(harness, data):
    at = harness.text_next
    harness.machine.memory.put_bytes(at, data)
    harness.text_next = (at + len(data) + 15) & ~15
    return at if data else 1


def put_action(harness, row, at, chain, signature_chain, values):
    """Lay one action out with the field offsets of the table; bytes no field names keep a distinct filler."""
    memory = harness.machine.memory
    memory.put_bytes(at, bytes((0xC0 + index) & 0xFF for index in range(0xE8)))
    memory.write(at + row[3], 1, chain)
    memory.put_bytes(at + row[4], signature_chain.to_bytes(32, "little"))
    for name, kind, offset in row[5]:
        value = values[name]
        if kind == "string":
            memory.write(at + offset - 8, 8, len(value) | 0x100)
            memory.write(at + offset, 8, put_text(harness, value))
            memory.write(at + offset + 8, 8, len(value))
        elif kind == "bytes":
            memory.write(at + offset, 8, VTABLE_AT)
            memory.write(at + offset + 8, 8, put_text(harness, value))
            memory.write(at + offset + 0x10, 8, len(value))
            memory.write(at + offset + 0x18, 8, 0)
        elif kind == "opt":
            if value is None:
                memory.write(at + offset, 8, 1 << 63)
            else:
                memory.write(at + offset, 8, len(value))
                memory.write(at + offset + 8, 8, put_text(harness, value))
                memory.write(at + offset + 0x10, 8, len(value))
        elif kind in ENUM_NAMES:
            memory.write(at + offset, 1, value)
        elif kind == "bool":
            memory.write(at + offset, 1, 1 if value else 0)
        elif kind == "uint32":
            memory.write(at + offset, 4, value)
        elif kind == "uint64":
            memory.write(at + offset, 8, value)
        else:
            memory.put_bytes(at + offset, value)


class Case:
    __slots__ = ("label", "kind", "row", "fields", "focus")

    def __init__(self, label, kind, row, focus=(), **fields):
        self.label, self.kind, self.row, self.fields, self.focus = label, kind, row, fields, focus


def row_label(row):
    return row[0] + ("/multi" if row[1] else "")


def wrapper_values(row, variant):
    values = values_for(row, variant)
    if row[1]:
        values["payloadMultiSigUser"] = bytes(20) if variant == 1 else filler("user/%d" % variant, 20)
        values["outerSigner"] = bytes(20) if variant == 1 else filler("outer/%d" % variant, 20)
    return values


GATES = (("chain", {"wrong_chain": True}, 0x8F), ("vault", {"vault": True}, 0x15), ("nonce", {"wrong_nonce": True}, 0x5D), ("expires", {"expires": True}, 0x8C),
         ("recover", {"bad_signature": True}, 0x7A), ("all", {"wrong_chain": True, "vault": True, "wrong_nonce": True, "expires": True}, 0x8F),
         ("vault-first", {"vault": True, "wrong_nonce": True, "expires": True}, 0x15), ("nonce-first", {"wrong_nonce": True, "expires": True}, 0x5D))
MULTI_SIG_GATES = (("chain", {"wrong_chain": True}, 0x8F), ("nonce", {"wrong_nonce": True}, 0x5D), ("recover", {"bad_signature": True}, 0x7A), ("no-vault-gate", {"vault": True}, 0x186), ("no-expires-gate", {"expires": True}, 0x186))


def all_cases():
    rows = []
    for row in TYPES:
        label = row_label(row)
        rows.append(Case("type/%s" % label, "type", row))
        rows.append(Case("struct/%s/0" % label, "struct", row, variant=0))
        rows.append(Case("digest/%s/0" % label, "digest", row, variant=0))
        rows.append(Case("wrap/%s/0" % label, "wrap", row, variant=0))
        rows.append(Case("sign/%s/0" % label, "sign", row, variant=0))
        for variant in range(4):
            rows.append(Case("verify/%s/%d" % (label, variant), "verify", row, variant=variant, want=0x186))
        for name, flags, status in (MULTI_SIG_GATES if row[0] == SEND_MULTI_SIG else GATES):
            rows.append(Case("gate/%s/%s" % (label, name), "verify", row, variant=0, want=status, **flags))
    withdraw = next(row for row in TYPES if row[0] == "Withdraw" and not row[1])
    for row in TYPES:
        for index, (at, size) in enumerate(TIER4_TEXTS):
            rows.append(Case("tier4/%s/%d" % (row_label(row), index), "tier4", row, index=index, at=at, size=size))
        rows.append(Case("sign-panic/%s" % row_label(row), "sign", row, variant=0, fails=True))
        rows.append(Case("gate/%s/type-error" % row_label(row), "verify", row, variant=0, want=0x7A, tier3_error=True))
    for index, name in DISPATCH_ROW_NAMES:
        row = PLAIN[name]
        rows.append(Case("dispatch/%d/%s" % (index + TAG_BASE, name), "dispatch", row, index=index, want=0x186, variant=0))
        if name != SEND_MULTI_SIG:
            rows.append(Case("dispatch/%d/%s/nonce" % (index + TAG_BASE, name), "dispatch", row, index=index, want=0x5D, variant=0, wrong_nonce=True))
        rows.append(Case("dispatch/%d/%s/recover" % (index + TAG_BASE, name), "dispatch", row, index=index, want=0x7A, variant=0, bad_signature=True))
    rows.append(Case("dispatch/%d/rest" % (2 + TAG_BASE), "dispatch", withdraw, index=2, want=REST_STATUS, variant=0, rest=True))
    rows.append(Case("dispatch/low-tag/rest", "dispatch", withdraw, index=-1, want=REST_STATUS, variant=0, rest=True))
    rows.append(Case("dispatch/%d/inner-nonce-equal" % (82 + TAG_BASE), "dispatch", withdraw, index=82, want=REST_STATUS, variant=0, rest=True, inner=True))
    rows.append(Case("dispatch/%d/inner-nonce-differs" % (82 + TAG_BASE), "dispatch", withdraw, index=82, want=0x5D, variant=0, rest=True, inner=False))
    return rows


DISPATCH_ROW_NAMES = ((1, "ApproveAgent"), (11, "LinkStakingUser"), (28, "SpotSend"), (33, "TokenDelegate"), (39, "UsdSend"), (47, "Withdraw"), (49, "GovPropose"), (50, "GovVote"), (51, "UsdClassTransfer"),
                      (52, "SendMultiSig"), (53, "ConvertToMultiSigUser"), (54, "ApproveBuilderFee"), (61, "CWithdraw"), (62, "CDeposit"), (63, "CUserModify"), (69, "SendAsset"), (74, "UserDexAbstraction"),
                      (76, "SendToEvmWithData"), (77, "UserPortfolioMargin"), (78, "UserSetAbstraction"), (86, "StakingLinkDisableTradingUser"))


def tier_of(row, index):
    return row[2][index]


def expected_type(row):
    return keccak(type_text(row))


def run_case(harness, case):
    """Run one case; a text describing the first difference, or None."""
    machine = harness.machine
    memory = machine.memory
    harness.reset()
    harness.text_next = TEXT_AT
    memory.put_bytes(VTABLE_AT, b"".join(value.to_bytes(8, "little") for value in (FAKE_CLONE, FAKE_DROP, FAKE_DROP, FAKE_DROP, FAKE_DROP, FAKE_DROP)))
    memory.put_bytes(OUT, bytes(0x100))
    row = case.row
    fields = case.fields
    if case.kind == "type":
        machine.run(tier_of(row, 0), {RDI: OUT})
        if memory.read(OUT, 1) != 0 or memory.bytes_at(OUT + 1, 32) != expected_type(row):
            return "type hash"
        return None
    if case.kind == "tier4":
        return run_tier4(harness, case)
    variant = fields["variant"]
    chain, signature_chain = VARIANT_CHAINS[variant], VARIANT_IDS[variant]
    if case.kind == "dispatch":
        return run_dispatch(harness, case)
    values = wrapper_values(row, variant)
    if case.kind in ("struct", "digest", "wrap", "sign"):
        put_action(harness, row, ACTION_AT, chain, signature_chain, values)
        digest = digest_of(row, chain, signature_chain, values)
        if case.kind == "struct":
            machine.run(tier_of(row, 1), {RDI: OUT, RSI: ACTION_AT})
            return None if memory.read(OUT, 1) == 0 and memory.bytes_at(OUT + 1, 32) == struct_hash(row, chain, values) else "struct hash"
        if case.kind == "digest":
            machine.run(tier_of(row, 2), {RDI: OUT, RSI: ACTION_AT})
            return None if memory.read(OUT, 1) == 0 and memory.bytes_at(OUT + 1, 32) == digest else "digest"
        if case.kind == "wrap":
            machine.run(tier_of(row, 3), {RDI: OUT, RSI: ACTION_AT})
            return None if memory.read(OUT, 1) == 0 and memory.bytes_at(OUT + 1, 32) == digest else "wrapped digest"
        harness.sign_fails = fields.get("fails", False)
        try:
            machine.run(tier_of(row, 5), {RDI: OUT, RSI: WALLET_AT, RDX: ACTION_AT})
        except Panicked:
            return None if harness.sign_fails else "sign panic"
        if harness.sign_fails or harness.seen_digest != (WALLET_AT, digest) or memory.bytes_at(OUT, 0x41) != SIGNED_WORDS:
            return "signed output"
        return None
    return run_verify(harness, case, row, chain, signature_chain, variant, values)


def nonce_of(row, values):
    return values[time_field(row)]


def put_ctx(harness, fields, nonce):
    memory = harness.machine.memory
    memory.put_bytes(CTX_AT, bytes(0x30))
    memory.write(CTX_AT, 8, 1 if fields.get("expires") else 0)
    memory.write(CTX_AT + 0x10, 8, (nonce ^ 1) if fields.get("wrong_nonce") else nonce)
    memory.write(CTX_AT + 0x18, 1, 1 if fields.get("vault") else 0)


def check_status(harness, case, want, digest):
    memory = harness.machine.memory
    status = memory.read(OUT, 2)
    if status != want:
        return "status %#x" % status
    if want == 0x186:
        if harness.seen_digest != (SIGNATURE_AT, digest):
            return "digest at the recover call"
        if memory.read(OUT + 2, 1) != 1 or memory.bytes_at(OUT + 3, 20) != RECOVERED:
            return "recovered address"
    elif want == 0x7A:
        if harness.seen_digest != (SIGNATURE_AT, digest) or memory.read(OUT + 8, 8) != 0x4444:
            return "recover error word"
    elif harness.seen_digest is not None:
        return "a refused action reached the recover call"
    return None


def run_verify(harness, case, row, chain, signature_chain, variant, values):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    nonce = nonce_of(row, values)
    put_ctx(harness, fields, nonce)
    digest = digest_of(row, chain, signature_chain, values)
    harness.recover_result = None if fields.get("bad_signature") else RECOVERED
    passed = chain ^ 1 if fields.get("wrong_chain") else chain
    verifier = tier_of(row, 4)
    if fields.get("tier3_error"):
        harness.tier3_error = 1
        machine.calls[row[2][2]] = harness.on_tier3_error
        machine.calls[ERROR_BOX] = harness.on_error_box
        machine.real.stubs = machine.real.stubs | {row[2][2], ERROR_BOX}
        try:
            return run_verify_body(harness, case, row, chain, signature_chain, values, passed, verifier, digest, True)
        finally:
            del machine.calls[row[2][2]], machine.calls[ERROR_BOX]
            machine.real.stubs = machine.real.stubs - {row[2][2], ERROR_BOX}
    return run_verify_body(harness, case, row, chain, signature_chain, values, passed, verifier, digest, False)


def run_verify_body(harness, case, row, chain, signature_chain, values, passed, verifier, digest, boxed):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    if row[0] == SEND_MULTI_SIG:
        put_action(harness, row, ACTION_AT, chain, signature_chain, values)
        harness.action_block = memory.bytes_at(ACTION_AT, 0x50)
        machine.run(verifier, {RDI: OUT, RSI: WALLET_AT, RDX: passed, RCX: CTX_AT, R8: SIGNATURE_AT})
    elif row[1]:
        plain = plain_of(row)
        put_action(harness, plain, ACTION_AT, chain, signature_chain, values)
        memory.put_bytes(USER_AT, values["payloadMultiSigUser"])
        memory.put_bytes(OUTER_AT, values["outerSigner"])
        memory.write(STACK_TOP - 0x100, 8, SIGNATURE_AT)
        machine.run(verifier, {RDI: OUT, RSI: ACTION_AT, RDX: passed, RCX: USER_AT, R8: OUTER_AT, R9: CTX_AT})
    else:
        put_action(harness, row, ACTION_AT, chain, signature_chain, values)
        machine.run(verifier, {RDI: OUT, RSI: ACTION_AT, RDX: passed, RCX: CTX_AT, R8: SIGNATURE_AT})
    if boxed:
        return None if memory.read(OUT, 2) == 0x7A and memory.read(OUT + 8, 8) == 0x5555 and harness.seen_digest is None else "boxed error"
    return check_status(harness, case, fields["want"], digest)


def run_tier4(harness, case):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    harness.tier3_error = fields["index"]
    machine.calls[case.row[2][2]] = harness.on_tier3_error
    machine.real.stubs = machine.real.stubs | {case.row[2][2]}
    try:
        machine.run(tier_of(case.row, 3), {RDI: OUT, RSI: ACTION_AT})
    finally:
        del machine.calls[case.row[2][2]]
        machine.real.stubs = machine.real.stubs - {case.row[2][2]}
    if memory.read(OUT, 1) != 1:
        return "tier 4 tag"
    text = memory.bytes_at(memory.read(OUT + 0x10, 8), memory.read(OUT + 0x18, 8))
    return None if text == code(machine.image, fields["at"], fields["size"]) else "tier 4 text"


def run_dispatch(harness, case):
    machine = harness.machine
    memory = machine.memory
    fields = case.fields
    row = case.row
    variant = fields["variant"]
    chain, signature_chain = VARIANT_CHAINS[variant], VARIANT_IDS[variant]
    values = values_for(row, variant)
    memory.put_bytes(ENVELOPE_AT, bytes(0x170))
    tag = fields["index"] + TAG_BASE if fields["index"] >= 0 else 0x20
    memory.write(ENVELOPE_AT + 0x10, 8, tag)
    if fields.get("rest"):
        nonce = 77
        memory.write(ENVELOPE_AT + 0x148, 8, nonce)
        if "inner" in fields:
            memory.write(ENVELOPE_AT + 0xA8, 8, nonce if fields["inner"] else nonce + 1)
        machine.run(DISPATCH, {RDI: OUT, RSI: ENVELOPE_AT, RDX: chain, RCX: ACTION_AT, R8: ACTION_AT})
        if memory.read(OUT, 2) != fields["want"]:
            return "status %#x" % memory.read(OUT, 2)
        if fields["want"] == REST_STATUS and harness.rest_seen != ENVELOPE_AT + 0x10:
            return "shared path input"
        return None if fields["want"] == REST_STATUS or memory.read(OUT + 2, 1) == 0 else "flag byte"
    put_action(harness, row, ENVELOPE_AT + 0x18, chain, signature_chain, values)
    nonce = nonce_of(row, values)
    memory.write(ENVELOPE_AT + 0x148, 8, (nonce ^ 1) if fields.get("wrong_nonce") else nonce)
    memory.put_bytes(ENVELOPE_AT + 0x150, bytes(0x18))
    harness.recover_result = None if fields.get("bad_signature") else RECOVERED
    if row[0] == SEND_MULTI_SIG:
        put_action(harness, row, ACTION_AT, chain, signature_chain, values)
        harness.action_block = memory.bytes_at(ACTION_AT, 0x50)
    machine.run(DISPATCH, {RDI: OUT, RSI: ENVELOPE_AT, RDX: chain, RCX: ACTION_AT, R8: ACTION_AT})
    status = memory.read(OUT, 2)
    if status != fields["want"]:
        return "status %#x" % status
    if status == 0x186:
        digest = digest_of(row, chain, signature_chain, values)
        if harness.seen_digest != (ENVELOPE_AT + 0x100, digest):
            return "digest at the recover call"
        if memory.bytes_at(OUT + 2, 20) != RECOVERED:
            return "dispatch address"
    if status == 0x7A and memory.read(OUT + 8, 8) != 0x4444:
        return "error word"
    return None


# ---- static reads ----

def code(image, va, count):
    return bytes(image.blob[image.offset(va):image.offset(va) + count])


def slot_target(harness, slot):
    return harness.relative.get(slot)


def body_slot_call(harness, start, target):
    """The first FF 15 call in a body whose slot holds target; every tier hop is one of these or a direct E8."""
    begin, end = harness.image.exact_fde(start)
    data = code(harness.image, begin, end - begin)
    at = data.find(b"\xff\x15")
    while at >= 0:
        slot = begin + at + 6 + struct.unpack_from("<i", data, at + 2)[0]
        if harness.relative.get(slot) == target:
            return {"site": begin + at, "slot": slot}
        at = data.find(b"\xff\x15", at + 1)
    raise EvidenceError("no slot call from %#x to %#x" % (start, target))


def body_direct_call(harness, start, target):
    begin, end = harness.image.exact_fde(start)
    data = code(harness.image, begin, end - begin)
    at = data.find(b"\xe8")
    while at >= 0:
        if at + 5 <= len(data) and begin + at + 5 + struct.unpack_from("<i", data, at + 1)[0] == target:
            return {"site": begin + at, "slot": 0}
        at = data.find(b"\xe8", at + 1)
    raise EvidenceError("no direct call from %#x to %#x" % (start, target))


def hop_rows(harness):
    rows = []
    for row in TYPES:
        one, two, three, four, five, six = row[2]
        hops = (body_slot_call(harness, two, one), body_slot_call(harness, three, two), body_direct_call(harness, four, three), body_direct_call(harness, five, four), body_direct_call(harness, six, four))
        rows.append((row, hops))
    return rows


def arm_row(harness, table, index, begin, end):
    """Walk one table row in byte patterns to its first call or jump; the row names a verifier, a shared path, or a jump inside the host."""
    image = harness.image
    entry = table + struct.unpack_from("<i", image.blob, image.offset(table) + 4 * index)[0]
    if not begin <= entry < end:
        raise EvidenceError("table row %d leaves the host" % index)
    data = code(image, entry, 0x60)

    def read(va, count):
        return data[va - entry:va - entry + count]

    va = entry
    while True:
        insn = decode(read, va)
        raw = read(va, 6)
        if raw[:2] == b"\xff\x15":
            slot = va + 6 + struct.unpack_from("<i", raw, 2)[0]
            return {"index": index, "tag": index + TAG_BASE, "arm": entry, "exit": "slot", "site": va, "slot": slot, "target": harness.relative[slot]}
        if raw[0] == 0xE8:
            return {"index": index, "tag": index + TAG_BASE, "arm": entry, "exit": "call", "site": va, "slot": 0, "target": va + 5 + struct.unpack_from("<i", raw, 1)[0]}
        if insn.op == "jcc" or insn.op == "jmp":
            return {"index": index, "tag": index + TAG_BASE, "arm": entry, "exit": insn.op, "site": va, "slot": 0, "target": insn.target}
        va = insn.next


def dispatch_rows(harness):
    verifiers = {row[2][4]: row for row in TYPES}
    out = {}
    for name, table, host, count in (("plain", DISPATCH_TABLE, DISPATCH, DISPATCH_ROWS), ("multi", MULTI_TABLE, MULTI_DISPATCH, MULTI_ROWS)):
        begin, end = harness.image.exact_fde(host)
        rows = []
        for index in range(count):
            item = arm_row(harness, table, index, begin, end)
            hit = verifiers.get(item["target"])
            item["action"] = row_label(hit) if hit else ""
            rows.append(item)
        out[name] = rows
    wanted_plain = sorted(row_label(row) for row in TYPES if not row[1])
    wanted_multi = sorted(row_label(row) for row in TYPES if row[1])
    if sorted(r["action"] for r in out["plain"] if r["action"]) != wanted_plain or sorted(r["action"] for r in out["multi"] if r["action"]) != wanted_multi:
        raise EvidenceError("dispatch tables do not cover the verifier set")
    return out


def table_names(harness, pointers, lengths, count):
    image = harness.image
    rows = []
    for index in range(count):
        at = harness.relative[pointers + 8 * index]
        size = struct.unpack_from("<Q", image.blob, image.offset(lengths) + 8 * index)[0]
        rows.append(code(image, at, size).decode("ascii"))
    return rows


def static_reads(harness):
    image = harness.image
    return {
        "chain_names": table_names(harness, CHAIN_POINTERS, CHAIN_LENGTHS, 4),
        "enum_names": {key: table_names(harness, pointers, lengths, count) for key, (pointers, lengths, count) in sorted(ENUM_TABLES.items())},
        "address_encodings": [code(image, at, size).decode("ascii") for at, size in ENCODING_TEXT],
        "domain_name": code(image, NAME_TEXT, 26).decode("ascii"),
        "prefix_1901": code(image, PREFIX_1901, 2).hex(),
        "type_prefix": code(image, TYPE_PREFIX, 23).decode("ascii"),
        "tier4_texts": [code(image, at, size).decode("ascii") for at, size in TIER4_TEXTS],
        "tier4_table": ["%#x" % (TIER4_TABLE + struct.unpack_from("<i", image.blob, image.offset(TIER4_TABLE) + 4 * index)[0]) for index in range(6)],
        "status_text_0x15": code(image, STATUS_TEXTS[0][1], STATUS_TEXTS[0][2]).decode("ascii"),
    }


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


def tolerant_rows(image, begin, end):
    """Linear rows of a body; unwind pads past an unknown opcode are skipped to the next FDE end."""
    base = image.offset(begin)
    code_bytes = image.blob[base:base + (end - begin) + 16]

    def read(va, count):
        return code_bytes[va - begin:va - begin + count]

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


def mutated_functions():
    """Every mutant of the two Withdraw rows, the multi sig verifier and the shared helpers; one in SAMPLE_EVERY across the other tiers."""
    out = [(TYPE_HASH, 1, "type text and hash"), (CAMEL, 1, "snake to camel"), (DISPATCH, 1, "plain dispatch"), (0x3B63F50, 1, "agent name word"), (0x38E39B0, 1, "abstraction word"), (0x3A1B570, 1, "SendMultiSig verifier")]
    seen = {item[0] for item in out}
    for row in TYPES:
        every = 1 if row[0] == "Withdraw" else SAMPLE_EVERY
        for tier, start in enumerate(row[2][:5]):
            if start not in seen:
                seen.add(start)
                out.append((start, every, "%s tier %d" % (row_label(row), tier + 1)))
    return out


MUTANT_STATE = {}


def worker_start():
    harness = Harness(load_image())
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    MUTANT_STATE["harness"] = harness
    MUTANT_STATE["cases"] = all_cases()


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
            trouble = run_case(harness, cases[index])
        except (Halt, Panicked, EvidenceError, KeyError, ValueError, IndexError, UnicodeDecodeError, OverflowError) as error:
            trouble = "%s" % type(error).__name__
        if trouble:
            failed = cases[index].label + ": " + trouble
            break
    machine.patches = {}
    machine.cache.pop(va, None)
    return {"function": function, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed[:70] if failed else ""}


def run_mutants(image, reached):
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    tasks = []
    results = []
    counter = 0
    for start, every, _ in mutated_functions():
        begin, end = image.exact_fde(start)
        for va, at, kind in mutation_targets(image, tolerant_rows(image, begin, end)):
            counter += 1
            if counter % every:
                continue
            indices = by_va.get(va)
            if not indices:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            step = max(1, len(indices) // MUTANT_CASES)
            tasks.append((start, va, at, kind, indices[::step][:MUTANT_CASES]))
    with multiprocessing.Pool(WORKERS, worker_start) as pool:
        results += pool.map(run_one, tasks, 8)
    return sorted(results, key=lambda row: (row["function"], row["va"], row["kind"]))


# ---- evidence ----

def analyse(image, full=True):
    harness = Harness(image)
    cases = all_cases()
    machine = harness.machine
    mismatches = []
    outcomes = collections.Counter()
    reached = []
    seen = set()
    lines = []
    vectors = ["label\tchain\tsignature_chain_id\tstruct_hash\tdigest"]
    for case in cases:
        machine.seen = set()
        try:
            trouble = run_case(harness, case)
        except (Halt, Panicked) as error:
            trouble = "%s %s" % (type(error).__name__, error)
        if trouble:
            mismatches.append("%s: %s" % (case.label, trouble))
        reached.append(frozenset(machine.seen))
        seen |= machine.seen
        outcome = case.kind
        if case.kind in ("verify", "dispatch") and not case.fields.get("tier3_error"):
            outcome = "%s status %#x" % (case.kind, case.fields["want"])
        elif case.kind == "verify":
            outcome = "verify error from the digest tier, status 0x7a"
        outcomes[outcome] += 1
        lines.append("\t".join((case.kind, case.label, outcome, "fail" if trouble else "match")))
        if case.kind == "verify" and case.fields["want"] == 0x186 and case.label.startswith("verify/"):
            variant = case.fields["variant"]
            values = wrapper_values(case.row, variant)
            chain, signature_chain = VARIANT_CHAINS[variant], VARIANT_IDS[variant]
            vectors.append("\t".join((case.label, CHAIN_NAMES[chain], "%#x" % signature_chain, struct_hash(case.row, chain, values).hex(), digest_of(case.row, chain, signature_chain, values).hex())))
    steps = machine.steps
    if mismatches and full:
        raise EvidenceError("spec mismatch: %s" % mismatches[0])
    type_lines = ["action\tkind\ttype_text\ttype_hash\ttier1_type\ttier2_struct\ttier3_digest\ttier4_wrap\ttier5_verify\ttier6_sign\tchain_byte\tsignature_chain_id\tverifier_bytes\tinstructions_stepped"]
    field_lines = ["action\tkind\tfield\tsolidity\trust_form\toffset"]
    hops = hop_rows(harness)
    hop_lines = ["action\tkind\thop\tsite\tslot"]
    tiers = [{"instructions": 0, "stepped": 0, "bytes": 0, "functions": 0} for _ in range(6)]
    for row, chain_hops in hops:
        stepped = 0
        for tier, start in enumerate(row[2]):
            begin, end = image.exact_fde(start)
            rows = tolerant_rows(image, begin, end)
            hit = sum(1 for item in rows if item.va in seen)
            tiers[tier]["instructions"] += len(rows)
            tiers[tier]["stepped"] += hit
            tiers[tier]["bytes"] += end - begin
            tiers[tier]["functions"] += 1
            stepped += hit
        kind = "multi" if row[1] else "plain"
        size = image.exact_fde(row[2][4])
        type_lines.append("\t".join((row[0], kind, type_text(row).decode("ascii"), keccak(type_text(row)).hex()) + tuple("%#x" % value for value in row[2]) + ("%#x" % row[3], "%#x" % row[4], str(size[1] - size[0]), str(stepped))))
        for name, form, offset in row[5]:
            field_lines.append("\t".join((row[0], kind, name, SOLIDITY[form], form, "%#x" % offset)))
        for index, hop in enumerate(chain_hops):
            hop_lines.append("\t".join((row[0], kind, "tier %d to %d" % ((index + 2, index + 1) if index < 4 else (6, 4)), "%#x" % hop["site"], "%#x" % hop["slot"])))
    table = dispatch_rows(harness)
    dispatch_lines = ["table\tindex\ttag\tarm\texit\tsite\tslot\ttarget\taction"]
    for name, rows in sorted(table.items()):
        for item in rows:
            dispatch_lines.append("\t".join((name, str(item["index"]), "%#x" % item["tag"], "%#x" % item["arm"], item["exit"], "%#x" % item["site"], "%#x" % item["slot"], "%#x" % item["target"], item["action"])))
    results_rows = run_mutants(image, reached) if full else []
    tally = {key: sum(1 for item in results_rows if item["result"] == key) for key in ("killed", "survived", "unreached")}
    shared = []
    for start, _, role in mutated_functions()[:6]:
        begin, end = image.exact_fde(start)
        rows = tolerant_rows(image, begin, end)
        shared.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows), "instructions_stepped": sum(1 for item in rows if item.va in seen)})
    doc = {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "actions": {"plain": sum(1 for row in TYPES if not row[1]), "multi": sum(1 for row in TYPES if row[1])},
        "tiers": dict(zip(("type", "struct", "digest", "wrap", "verify", "sign"), tiers)),
        "shared_functions": shared,
        "cases": {"total": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "instructions_stepped": steps,
        "mutations": tally,
        "domain": {"type": DOMAIN_TYPE.decode("ascii"), "version": "1", "verifying_contract": "0x" + "00" * 20},
        "gates": {"order": ["0x8f chain", "0x15 flag at ctx+0x18", "0x5d nonce at ctx+0x10", "0x8c word at ctx+0", "0x7a recover"], "success": "0x186"},
        "static": static_reads(harness),
        "_results": results_rows, "_lines": lines, "_vectors": vectors, "_types": type_lines, "_fields": field_lines, "_hops": hop_lines, "_dispatch": dispatch_lines,
    }
    return doc


UNREACHED_REASON = "no case reaches it: an allocator failure arm, a panic arm, an unwind pad, or an error arm of the type tier, which never fails on its literal fields"
SURVIVED_REASON = "class label, not proven row by row: a capacity or spill word, a Vec cap, a drop guard, or a second read of a value the digest already fixed"


def render(evidence):
    evidence = dict(evidence)
    results = evidence.pop("_results")
    tables = {"cases.tsv": ["kind\tlabel\toutcome\tresult"] + evidence.pop("_lines"), "vectors.tsv": evidence.pop("_vectors"), "types.tsv": evidence.pop("_types"), "fields.tsv": evidence.pop("_fields"),
              "hops.tsv": evidence.pop("_hops"), "dispatch.tsv": evidence.pop("_dispatch")}
    files = {"evidence.json": (json.dumps(evidence, indent=2, sort_keys=True) + "\n").replace("\x40", "[at]")}
    for name, lines in tables.items():
        files[name] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += [("%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], "" if row["result"] == "killed" else (UNREACHED_REASON if row["result"] == "unreached" else SURVIVED_REASON))) for row in results]
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
