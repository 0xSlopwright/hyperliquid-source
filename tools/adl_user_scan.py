#!/usr/bin/env python3
"""Pin the node #94 ADL and liquidation user scan: the three address sources of 0x3707910 and the candidate sets of 0x33c58e0, with their sort orders.

Every function of the two paths runs whole in a Python evaluator, rayon bridges included, down to the per-user row builder
0x37d7360 and the per-user score 0x36f5d40, which are stubs. A separately written specification predicts every stub argument,
final set and heap block, and every condition, immediate and field offset of those bodies is flipped to show the run can tell.
No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import copy
import functools
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

SCAN = 0x3707910
RANKS = 0x33C58E0
ROW_BUILDER = 0x37D7360
RANK_BODY = 0x36F5D40
HASH_ADDRESS = 0x399C7A0
WORKER = 0x4E17630
DROP_SET = 0x33F3FC0
RESERVE = 0x32D6A00
GROW_ROW = 0x32D5860
GROW_RANK = 0x32D5B70
GROW_PAIR = 0x32D59B0
PANIC_NONE = 0x157A9F0
PANIC_BOUNDS = 0x157B64F
PANIC_TEXT = 0x157B7F0
PANIC_INDEX = 0x157B520
PANIC_FORMAT = 0x157B810
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
REAL_FUNCTIONS = (0x3707910, 0x33C58E0, 0x3BC3B00, 0x3BC3E00, 0x3BC4080, 0x33C31F0, 0x3BB36E0, 0x3BC9A80, 0x3766090, 0x37664D0, 0x3761320, 0x3766BB0, 0x3767460, 0x33C4530, 0x3BC4300, 0x3BB2FC0, 0x33A3610, 0x33A98E0, 0x3889650, 0x34445B0, 0x388DF00,
                  0x38DBF40, 0x38DC1C0, 0x38DC560, 0x38DC2F0, 0x38DCC10, 0x343D720, 0x343FE10, 0x3440820, 0x3439270, 0x3441590, 0x3309780, 0x3396340, 0x2FDCBD0, 0x3383C10, 0x33864B0, 0x3394240, 0x3394360, 0x33AF160, 0x3BABAA0, 0x3BBACB0, 0x33B5620, 0x3307A60, 0x381A7A0, 0x381ACC0, 0x381ADC0, 0x381AEB0, 0x2F257C0, 0x2F6CD10, 0x2F73C40, 0x2FBC2E0, 0x339A6A0, 0x38035B0, 0x2F6BE10, 0x2FA0DF0, 0x2FB6A20, 0x35831F0, 0x2FA4C50, 0x3BC1AE0, 0x3BC03F0, 0x3878AC0, 0x3877320, 0x3863090, 0x386B6C0, 0x338FCE0, 0x3862970, 0x3384380, 0x338AFB0, 0x3383DA0)
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x8000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 90000
DEX = HEAP_BASE + 0x1000
BUMP = HEAP_BASE + 0x8000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Finished(Exception):
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
        elif byte not in (0x2E, 0xF0):
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
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x60, True): "punpcklbw", (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0xDB, True): "andpd",
                  (0xEB, True): "orpd", (0x6C, True): "unpcklpd", (0x58, True): "addpd", (0x59, True): "mulpd", (0x5E, True): "divpd", (0x5F, True): "maxpd"}
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
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1)
            if value != 2:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmplepd", ("x", reg), rm, 16)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0x70 and (opsize or repne):
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("pshufd" if opsize else "pshuflw", ("x", reg), rm, 16, target=value)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if two == 0xB0:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1)
        if two == 0xBD and not rep:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
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
        if two == 0xBE:
            reg, rm = modrm()
            return finish("movsx8", ("r", reg), rm, width)
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
        self.real = frozenset()
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.watch = {}
        self.steps = 0
        self.keep_rdx = False
        self.keep_float = False
        self.step_limit = STEP_LIMIT
        self.jump_ranges = ()
        self.call_site = 0

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
                row = decode(self.read_code, pc)
                cache[pc] = row
            self.seen.add(pc)
            if pc in self.watch:
                self.watch[pc](self)
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
                self.call_site = row.va
                self.stub(hook)
                return self.pop()
            if not any(low <= target < high for low, high in self.jump_ranges):
                raise Halt("indirect jump out of the function at %#x" % row.va)
            return target
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (self.regs[row.b[1]] & (8 * width - 1)) & 1)
        elif op == "ret":
            return self.pop()
        elif op == "movsx8":
            value = self.get(row.b, 1)
            self.put(row.a, row.width, value - 0x100 if value & 0x80 else value)
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
        elif op in ("addpd", "mulpd", "divpd", "maxpd"):
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            parts = []
            for at in (0, 64):
                x, y = to_float(left >> at & MASK[8]), to_float(right >> at & MASK[8])
                parts.append(x + y if op == "addpd" else x * y if op == "mulpd" else x / y if op == "divpd" else (x if x > y else y))
            self.xmm[row.a[1]] = to_bits(parts[0]) | to_bits(parts[1]) << 64
        elif op == "cmplepd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum((MASK[8] if to_float(left >> at & MASK[8]) <= to_float(right >> at & MASK[8]) else 0) << at for at in (0, 64))
        elif op == "movmskpd":
            source = self.xmm[row.b[1]]
            self.put(row.a, 4, (source >> 63 & 1) | (source >> 127 & 1) << 1)
        elif op == "psrlq":
            source = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum(((source >> at & MASK[8]) >> row.b[1]) << at for at in (0, 64))
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
        elif op == "bsr":
            value = self.get(row.b, row.width)
            self.zf = value == 0
            if value:
                self.put(row.a, row.width, value.bit_length() - 1)
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


# ---- specification ----

ROW_STRIDE = 0x30
CAPACITY = 11
BUCKETS = 256
ENTRY_STRIDE = 0x78
HASH_K0, HASH_K1 = 0x0123456789ABCDEF, 0xFEDCBA9876543210
ROW_SET = dict(leaf=0x220, inner=0x280, parent=0x210, slot=0x218, length=0x21A, keys=0, stride=0x30, edges=0x220, values=0)
ADDRESS_SET = dict(leaf=0xE8, inner=0x148, parent=0, slot=0xE4, length=0xE6, keys=8, stride=20, edges=0xE8, values=0)
KEY_MAP = dict(leaf=0x1C8, inner=0x228, parent=0xB0, slot=0x1C0, length=0x1C2, keys=0, stride=0x10, edges=0x1C8, values=0x18, value_base=0xB8)
RANK_SET = dict(leaf=0x170, inner=0x1D0, parent=0x160, slot=0x168, length=0x16A, keys=0, stride=0x20, edges=0x170, values=0)


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def word_of(value):
    return value & MASK[8]


def rotate(word, count):
    return (word << count | word >> (64 - count)) & MASK[8]


def sip13(k0, k1, data):
    """SipHash 1-3 of the bytes alone, as the inline finish in the body computes it."""
    v0, v1, v2, v3 = k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573

    def round_():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & MASK[8]
        v1 = rotate(v1, 13) ^ v0
        v0 = rotate(v0, 32)
        v2 = (v2 + v3) & MASK[8]
        v3 = rotate(v3, 16) ^ v2
        v0 = (v0 + v3) & MASK[8]
        v3 = rotate(v3, 21) ^ v0
        v2 = (v2 + v1) & MASK[8]
        v1 = rotate(v1, 17) ^ v2
        v2 = rotate(v2, 32)
    blocks = len(data) // 8
    for index in range(blocks):
        word = struct.unpack_from("<Q", data, index * 8)[0]
        v3 ^= word
        round_()
        v0 ^= word
    tail = data[blocks * 8:]
    last = int.from_bytes(tail, "little") | (len(data) & 0xFF) << 56
    v3 ^= last
    round_()
    v0 ^= last
    v2 ^= 0xFF
    round_()
    round_()
    round_()
    return v0 ^ v1 ^ v2 ^ v3


def placements(case):
    """Bucket of each user in the table: the probe start plus the case's crowd, first free bucket after that. Fixture, not a claim."""
    used, where, shadows = set(), {}, []
    crowd = case.get("crowd", 0)
    for key in sorted(case.get("users", {})):
        digest = sip13(HASH_K0, HASH_K1, key)
        start = digest & (BUCKETS - 1)
        top = digest >> 57
        for shift in range(crowd):
            at = (start + shift) % BUCKETS
            if at not in used:
                used.add(at)
                shadows.append((at, top ^ 1))
        at = (start + crowd) % BUCKETS
        while at in used:
            at = (at + 1) % BUCKETS
        used.add(at)
        where[key] = at
    return where, shadows


def rank_word(bits):
    """Order word of the f64 total order: 0x33a3610 and the sort read it as unsigned."""
    return bits ^ MASK[8] if bits >> 63 else bits | SIGN[8]


def search_key(row):
    tag, one, two, name = row
    return (name, signed(tag), one if tag else 0, signed(two))


def sort_order(left, right):
    """Sort compare of the whole account arm: word 1 only when both tags are not 0."""
    if left[3] != right[3]:
        return -1 if left[3] < right[3] else 1
    if left[0] & MASK[4] and right[0] & MASK[4]:
        if left[1] != right[1]:
            return -1 if left[1] < right[1] else 1
    elif left[0] != right[0]:
        return -1 if signed(left[0]) < signed(right[0]) else 1
    if left[2] != right[2]:
        return -1 if signed(left[2]) < signed(right[2]) else 1
    return 0


class Spec:
    def __init__(self, case):
        self.case = case
        self.events = []

    def bucket_order(self):
        where, _ = placements(self.case)
        return sorted(where, key=lambda key: where[key])

    def scan_arm(self):
        case = self.case
        if case.get("given") is not None:
            return "given"
        if case.get("every") or case.get("flag"):
            return "whole"
        return "touched"

    def scan(self):
        case = self.case
        users = case.get("users", {})
        arm = self.scan_arm()
        if arm == "whole":
            names = self.bucket_order()
        else:
            listed = case["given"] if arm == "given" else case.get("touched", ())
            names = [name for name in sorted(listed) if name in users]
        rows = []
        for name in names:
            self.events.append(("row", name, case.get("bytes", (0, 1))))
            rows += [(tag, one, two, name) for tag, one, two in users[name]]
        if arm == "whole":
            return dict(rows=tuple(self.sorted_rows(rows)))
        kept = {search_key(row): row for row in reversed(rows)}
        return dict(rows=tuple(kept[key] for key in sorted(kept)))

    def sorted_rows(self, rows):
        order = sorted(rows, key=functools.cmp_to_key(sort_order))
        kept = []
        for row in order:
            if kept and sort_order(kept[-1], row) == 0:
                kept[-1] = row
            else:
                kept.append(row)
        return kept

    def rank(self):
        case = self.case
        users = case.get("users", {})
        scores = case.get("scores", {})
        sets = []
        for name_id, side in case["keys"]:
            if case.get("flag"):
                names = self.bucket_order()
            else:
                names = [name for name in sorted(case.get("touched", ())) if name in users]
            held = []
            for name in names:
                self.events.append(("rank", name_id, side, name))
                bits = scores.get((name_id, side, name))
                if bits is not None:
                    held.append((bits, name))
            sets.append(((name_id, side), tuple(sorted(held, key=lambda row: (rank_word(row[0]), row[1])))))
        final = {}
        for key, held in sets:
            if key in final:
                self.events.append(("drop", len(final[key])))
            final[key] = held
        return dict(final=final)

    def run(self):
        return self.scan() if self.case["kind"] == "scan" else self.rank()


# ---- evaluator ----

def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items):
    """B-tree over sorted key bytes; returns the root and its height."""
    if not items:
        return 0, 0

    def make(rows, level, parent, slot):
        node = bump(shape["inner"] if level else shape["leaf"])
        memory.write(node + shape["parent"], 8, parent)
        memory.write(node + shape["slot"], 2, slot)
        room = CAPACITY
        for _ in range(level - 1):
            room = room * (CAPACITY + 1) + CAPACITY
        if level == 0:
            entries, children = rows, []
        else:
            parts = 2
            while (len(rows) - (parts - 1)) > parts * room:
                parts += 1
            size = (len(rows) - (parts - 1)) // parts
            extra = (len(rows) - (parts - 1)) - size * parts
            at, entries, children = 0, [], []
            for index in range(parts):
                take = size + (1 if index < extra else 0)
                children.append(rows[at:at + take])
                at += take
                if index + 1 < parts:
                    entries.append(rows[at])
                    at += 1
        memory.write(node + shape["length"], 2, len(entries))
        for index, key in enumerate(entries):
            memory.put_bytes(node + shape["keys"] + shape["stride"] * index, key)
        for index, part in enumerate(children):
            memory.write(node + shape["edges"] + 8 * index, 8, make(part, level - 1, node, index))
        return node

    height = tree_height(len(items))
    return make(items, height, 0, 0), height


def tree_items(memory, shape, node, height, nodes=None):
    """(key bytes, value address) in key order; every node visited joins `nodes`."""
    if not node:
        return []
    if nodes is not None:
        nodes.add(node)
    found = []
    count = memory.read(node + shape["length"], 2)
    if count > CAPACITY:
        raise Halt("node length")
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1, nodes)
        if index < count:
            found.append((memory.bytes_at(node + shape["keys"] + shape["stride"] * index, shape["stride"]), node + shape.get("value_base", 0) + shape["values"] * index))
    return found


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = set(REAL_FUNCTIONS)
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        machine.calls = {ROW_BUILDER: self.on_rows, RANK_BODY: self.on_rank, HASH_ADDRESS: self.on_hash, WORKER: self.on_worker, DROP_SET: self.on_drop, RESERVE: self.on_reserve}
        hooks = {GROW_ROW: self.on_grow(ROW_STRIDE), GROW_RANK: self.on_grow(0x20), GROW_PAIR: self.on_grow(0x38), PANIC_NONE: self.on_panic("none"), PANIC_BOUNDS: self.on_panic("bounds"), PANIC_TEXT: self.on_panic("text"), PANIC_INDEX: self.on_panic("index"), PANIC_FORMAT: self.on_panic("format")}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
            elif target in real:
                machine.memory.statics[slot] = target
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def node(self, size):
        at = self.bump(size)
        self.blocks[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.node(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        if self.blocks.get(at) != size:
            raise Halt("free of %#x with size %#x, held %r" % (at, size, self.blocks.get(at)))
        del self.blocks[at]

    def on_memcmp(self, machine):
        regs, memory = machine.regs, machine.memory
        left = memory.bytes_at(regs[RDI], regs[RDX])
        right = memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_worker(self, machine):
        machine.regs[RAX] = self.worker

    def on_grow(self, size):
        def grow(machine):
            regs, memory = machine.regs, machine.memory
            vector = regs[RDI]
            cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
            wider = max(cap * 2, 4)
            fresh = self.node(wider * size)
            if cap:
                memory.copy(fresh, data, cap * size)
                del self.blocks[data]
            memory.write(vector, 8, wider)
            memory.write(vector + 8, 8, fresh)
        return grow

    def on_reserve(self, machine):
        regs, memory = machine.regs, machine.memory
        vector, stride = regs[RDI], regs[R8]
        if regs[RCX] != 8 or stride not in (0x10, 0x20, 0x28, 0x30, 0x38):
            raise Halt("reserve arguments")
        cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
        wider = max(cap * 2, regs[RSI] + regs[RDX], 4)
        fresh = self.node(wider * stride)
        if cap:
            memory.copy(fresh, data, cap * stride)
            del self.blocks[data]
        memory.write(vector, 8, wider)
        memory.write(vector + 8, 8, fresh)

    def on_hash(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0x118:
            raise Halt("hash table")
        regs[RAX] = sip13(memory.read(regs[RDI], 8), memory.read(regs[RDI] + 8, 8), memory.bytes_at(regs[RSI], 20))

    def on_rows(self, machine):
        regs, memory = machine.regs, machine.memory
        name = memory.bytes_at(regs[RDX], 20)
        if self.table.get(name) != regs[RSI] or regs[R9] != DEX + 0x60 or memory.read(regs[RSP] + 8, 8) != DEX:
            raise Halt("row builder arguments")
        self.events.append(("row", name, (regs[RCX] & 0xFF, regs[R8] & 0xFF)))
        rows = self.case["users"][name]
        data = self.node(len(rows) * ROW_STRIDE) if rows else 8
        for index, (tag, one, two) in enumerate(rows):
            at = data + index * ROW_STRIDE
            memory.write(at, 8, tag)
            memory.write(at + 8, 8, one)
            memory.write(at + 0x10, 8, word_of(two))
            memory.put_bytes(at + 0x18, name)
            self.pad = (self.pad + 0x1357) & MASK[4]
            memory.write(at + 0x2C, 4, self.pad)
        memory.write(regs[RDI], 8, len(rows))
        memory.write(regs[RDI] + 8, 8, data)
        memory.write(regs[RDI] + 0x10, 8, len(rows))

    def on_rank(self, machine):
        regs, memory = machine.regs, machine.memory
        name = memory.bytes_at(regs[R9], 20)
        if regs[RCX] != self.oracle_at or regs[R8] != DEX or memory.read(regs[RSP] + 8, 8) != self.table.get(name):
            raise Halt("rank arguments")
        key = (regs[RSI], regs[RDX] & 0xFF)
        self.events.append(("rank", key[0], key[1], name))
        bits = self.case.get("scores", {}).get(key + (name,))
        out = regs[RDI]
        if bits is None:
            memory.write(out, 8, 0)
        else:
            memory.write(out, 8, 1)
            memory.write(out + 8, 8, bits)
            memory.put_bytes(out + 0x10, name)
            self.pad = (self.pad + 0x1357) & MASK[4]
            memory.write(out + 0x24, 4, self.pad)

    def on_drop(self, machine):
        regs, memory = machine.regs, machine.memory
        at = regs[RDI]
        root, height, count = memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 0x10, 8)
        self.events.append(("drop", count))
        nodes = set()
        tree_items(memory, RANK_SET, root, height, nodes)
        for node in nodes:
            del self.blocks[node]

    def lay_table(self, case):
        memory = self.machine.memory
        users = case.get("users", {})
        area = self.bump(BUCKETS * ENTRY_STRIDE + BUCKETS + 16)
        ctrl = area + BUCKETS * ENTRY_STRIDE
        memory.put_bytes(ctrl, b"\xff" * (BUCKETS + 16))

        def tag(at, value):
            memory.write(ctrl + at, 1, value)
            if at < 16:
                memory.write(ctrl + BUCKETS + at, 1, value)
        where, shadows = placements(case)
        for at, value in shadows:
            tag(at, value)
        self.table = {}
        for key in sorted(users):
            at = where[key]
            tag(at, sip13(HASH_K0, HASH_K1, key) >> 57)
            entry = ctrl - ENTRY_STRIDE * (at + 1)
            memory.put_bytes(entry, key)
            self.table[key] = entry + 0x18
        memory.write(DEX + 0xF8, 8, ctrl)
        memory.write(DEX + 0x100, 8, BUCKETS - 1)
        memory.write(DEX + 0x110, 8, len(users))
        memory.write(DEX + 0x118, 8, HASH_K0)
        memory.write(DEX + 0x120, 8, HASH_K1)

    def put_set(self, at, names):
        memory = self.machine.memory
        names = sorted(names)
        root, height = build_tree(memory, self.bump, ADDRESS_SET, names)
        memory.write(at, 8, root)
        memory.write(at + 8, 8, height)
        memory.write(at + 0x10, 8, len(names))

    def prepare(self, case):
        machine, memory = self.machine, self.machine.memory
        memory.reset(getattr(self, "dirty", HEAP_SIZE))
        self.dirty = HEAP_SIZE
        self.case = case
        self.at = BUMP
        self.events = []
        self.blocks = {}
        self.pad = 0x5A5A5A5A
        self.lay_table(case)
        self.put_set(DEX + 0x158, case.get("touched", ()))
        memory.write(DEX + 0x1A0, 1, case.get("flag", 0))
        self.worker = self.bump(8)
        inner = self.bump(0x118)
        pool = self.bump(0x210)
        memory.write(self.worker, 8, inner)
        memory.write(inner + 0x110, 8, pool)
        memory.write(pool + 0x208, 8, 0)
        self.oracle_at = self.bump(0x18)
        return self.bump(0x40), machine

    def finish(self):
        self.dirty = self.at - HEAP_BASE

    def run_scan(self, case):
        out, machine = self.prepare(case)
        memory = machine.memory
        given = 0
        if case.get("given") is not None:
            given = self.bump(0x18)
            self.put_set(given, case["given"])
        one, two = case.get("bytes", (0, 1))
        try:
            machine.run(SCAN, {RDI: out, RSI: DEX, RDX: 0x5500 | one, RCX: 0x6600 | two, R8: given, R9: 0x7700 | case.get("every", 0)})
        finally:
            self.finish()
        nodes = set()
        rows = tuple((struct.unpack_from("<Q", key)[0], struct.unpack_from("<Q", key, 8)[0], signed(struct.unpack_from("<Q", key, 0x10)[0]), key[0x18:0x2C])
                     for key, _ in tree_items(memory, ROW_SET, memory.read(out, 8), memory.read(out + 8, 8), nodes))
        if len(rows) != memory.read(out + 0x10, 8):
            raise Halt("row set length")
        self.check_blocks(nodes)
        return dict(rows=rows)

    def run_rank(self, case):
        out, machine = self.prepare(case)
        memory = machine.memory
        memory.write(out, 8, 0)
        memory.write(out + 8, 8, 0)
        memory.write(out + 0x10, 8, 0)
        keys = case["keys"]
        table = self.bump(max(len(keys), 1) * 0x10)
        pointers = self.bump(max(len(keys), 1) * 8)
        for index, (name, side) in enumerate(keys):
            memory.write(table + index * 0x10, 8, name)
            memory.write(table + index * 0x10 + 8, 1, side)
            memory.write(pointers + index * 8, 8, table + index * 0x10)
        args = self.bump(0x28)
        for index, word in enumerate((pointers, len(keys), DEX + 0xF8, self.oracle_at, DEX)):
            memory.write(args + index * 8, 8, word)
        try:
            machine.run(RANKS, {RDI: out, RSI: args})
        finally:
            self.finish()
        nodes = set()
        final = {}
        items = tree_items(memory, KEY_MAP, memory.read(out, 8), memory.read(out + 8, 8), nodes)
        if len(items) != memory.read(out + 0x10, 8):
            raise Halt("key map length")
        for key, at in items:
            root, height, count = memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 0x10, 8)
            held = tuple((struct.unpack_from("<Q", row)[0], row[8:28]) for row, _ in tree_items(memory, RANK_SET, root, height, nodes))
            if len(held) != count:
                raise Halt("rank set length")
            final[struct.unpack_from("<Q", key)[0], key[8]] = held
        self.check_blocks(nodes)
        return dict(final=final)

    def check_blocks(self, nodes):
        rest = set(self.blocks) - nodes
        if rest or nodes - set(self.blocks):
            raise Halt("blocks left %r, missing %r" % (sorted(rest)[:3], sorted(nodes - set(self.blocks))[:3]))

    def run_case(self, case):
        return self.run_scan(case) if case["kind"] == "scan" else self.run_rank(case)


def compare_run(harness, case):
    label = case["label"]
    spec = Spec(case)
    want = spec.run()
    try:
        got = harness.run_case(case)
    except Panicked as panic:
        return "%s: panic %s" % (label, panic)
    except Halt as stop:
        return "%s: halt %s after %r" % (label, stop, harness.events[-2:])
    except (EvidenceError, KeyError, IndexError, ValueError, TypeError, struct.error, OverflowError, ZeroDivisionError) as error:
        return "%s: error %r" % (label, error)
    if harness.events != spec.events:
        for at in range(max(len(harness.events), len(spec.events))):
            left = harness.events[at] if at < len(harness.events) else None
            right = spec.events[at] if at < len(spec.events) else None
            if left != right:
                return "%s: event %d got %r want %r" % (label, at, left, right)
    if got != want:
        return "%s: got %r want %r" % (label, got, want)
    return None


# ---- cases ----

ONE = address(0x10)
TWO = address(0x20)
THREE = address(0x30, 0xBB)
LOW = address(0x05, 0x11)
HIGH = address(0xF5, 0xE1)
GONE = address(0x77, 0x33)
JUNK = 0x5DEADBEEF0
PLUS, MINUS = 0x3FF0000000000000, 0xBFF0000000000000
TWO_F, HALF = 0x4000000000000000, 0x3FE0000000000000
NEG_ZERO, INF, NEG_INF, NAN, NEG_NAN, TINY = SIGN[8], 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 0xFFF8000000000000, 1


def many(count, first=0x40):
    return [address(first + index, 0xA0 + index % 7) for index in range(count)]


def cross(value=-5):
    return (0, JUNK, value)


def isolated(asset, value=-3):
    return (1, asset, value)


def scan_case(label, users, **fields):
    return dict(kind="scan", label=label, users=users, **fields)


def arm_cases(prefix, users, **fields):
    """The same users through each of the three address sources."""
    names = sorted(users)
    return [scan_case(prefix + " given", users, given=names, **fields), scan_case(prefix + " touched", users, touched=names, **fields), scan_case(prefix + " every", users, every=1, **fields), scan_case(prefix + " flag", users, flag=1, **fields)]


def scan_cases():
    rows = []
    rows += arm_cases("no users", {})
    rows += arm_cases("user without rows", {ONE: []})
    rows += arm_cases("one cross row", {ONE: [cross()]})
    rows += arm_cases("one isolated row", {ONE: [isolated(4)]})
    rows += arm_cases("cross and isolated", {ONE: [cross(-9), isolated(7, -2), isolated(2, -8)]})
    rows += arm_cases("two users", {TWO: [cross(-1)], ONE: [cross(-2)]})
    rows += arm_cases("three users order", {HIGH: [cross(-1)], LOW: [isolated(1)], THREE: [cross(-3), isolated(9)]})
    rows += arm_cases("isolated sort by asset", {ONE: [isolated(9), isolated(1), isolated(5), isolated(3)]})
    rows += arm_cases("isolated huge asset", {ONE: [isolated(1 << 63), isolated(5)]})
    rows += arm_cases("equal rows differ in word 2", {ONE: [isolated(4, -9), isolated(4, -2), isolated(4, -5)]})
    rows += arm_cases("word 2 is signed", {ONE: [isolated(4, 3), isolated(4, -3)]})
    rows += arm_cases("the same row twice", {ONE: [isolated(4, -2), isolated(4, -2)]})
    rows += arm_cases("positive word 2 kept", {ONE: [cross(7)], TWO: [isolated(3, 0)]})
    rows += arm_cases("two cross rows differ in word 1", {ONE: [(0, 9, -5), (0, 4, -5)]})
    rows += arm_cases("two cross rows differ in word 2", {ONE: [(0, JUNK, -5), (0, JUNK, -7)]})
    rows += arm_cases("many rows of one user", {ONE: [isolated(index) for index in range(14)]})
    for count in (2, 3, 4, 11, 12, 13, 20, 21, 22, 30, 40, 90, 150):
        users = {name: [cross(-index - 1)] for index, name in enumerate(many(count))}
        rows += arm_cases("users %d" % count, users)
    users = {name: [isolated(40 - index), cross(-index)] for index, name in enumerate(many(16))}
    rows += arm_cases("users 16 two rows", users)
    users = {name: [] if index % 3 else [cross(-index)] for index, name in enumerate(many(30))}
    rows += arm_cases("every third has a row", users)
    rows.append(scan_case("given skips absent", {ONE: [cross()]}, given=[ONE, GONE]))
    rows.append(scan_case("touched skips absent", {ONE: [cross()]}, touched=[ONE, GONE]))
    rows.append(scan_case("given of absent only", {ONE: [cross()]}, given=[GONE]))
    rows.append(scan_case("touched of absent only", {ONE: [cross()]}, touched=[GONE]))
    rows.append(scan_case("empty given", {ONE: [cross()]}, given=[]))
    rows.append(scan_case("empty touched", {ONE: [cross()]}, touched=[]))
    rows.append(scan_case("given beats every", {ONE: [cross()], TWO: [cross()]}, given=[TWO], every=1))
    rows.append(scan_case("given beats flag", {ONE: [cross()], TWO: [cross()]}, given=[TWO], flag=1))
    rows.append(scan_case("empty given beats every", {ONE: [cross()], TWO: [cross()]}, given=[], every=1, flag=1))
    rows.append(scan_case("given beats touched", {ONE: [cross()], TWO: [cross()]}, given=[TWO], touched=[ONE]))
    rows.append(scan_case("every beats touched", {ONE: [cross()], TWO: [cross()]}, touched=[ONE], every=1))
    rows.append(scan_case("flag beats touched", {ONE: [cross()], TWO: [cross()]}, touched=[TWO], flag=1))
    rows.append(scan_case("touched only part", {ONE: [cross()], TWO: [cross()], THREE: [cross()]}, touched=[THREE, ONE]))
    rows.append(scan_case("tall given only part", {name: [cross(-1)] for name in many(40)}, given=many(40)[3:30]))
    rows.append(scan_case("tall touched only part", {name: [cross(-1)] for name in many(40)}, touched=many(40)[:27]))
    for pair in ((1, 0), (0, 0), (1, 1), (2, 3), (0xFF, 0x80)):
        rows += [dict(case, label=case["label"] + " bytes %d %d" % pair, bytes=pair) for case in arm_cases("bytes", {ONE: [cross()]})]
    for crowd in (1, 3, 15, 16, 17):
        rows += [dict(case, label=case["label"] + " crowd %d" % crowd, crowd=crowd) for case in arm_cases("crowd", {name: [cross(-1)] for name in many(6)})[:2]]
    return rows


def rank_case(label, users, keys, scores, **fields):
    return dict(kind="rank", label="rank " + label, users=dict.fromkeys(users, ()), keys=keys, scores=scores, **fields)


def rank_arms(prefix, names, keys, scores, **fields):
    names = list(names)
    return [rank_case(prefix + " touched", names, keys, scores, touched=names, **fields), rank_case(prefix + " flag", names, keys, scores, flag=1, **fields)]


def rank_cases():
    rows = []
    key = (5, 1)
    rows += rank_arms("no keys", [ONE], [], {})
    rows += rank_arms("no users", [], [key], {})
    rows += rank_arms("no score", [ONE, TWO], [key], {})
    rows += rank_arms("one score", [ONE, TWO], [key], {key + (TWO,): PLUS})
    rows += rank_arms("order by score", [ONE, TWO, THREE], [key], {key + (ONE,): TWO_F, key + (TWO,): HALF, key + (THREE,): PLUS})
    rows += rank_arms("tie by address", [ONE, TWO, THREE, HIGH, LOW], [key], {key + (name,): PLUS for name in (HIGH, ONE, LOW, THREE, TWO)})
    rows += rank_arms("score beats address", [LOW, HIGH], [key], {key + (LOW,): TWO_F, key + (HIGH,): PLUS})
    rows += rank_arms("zero then tiny", [ONE, TWO, THREE], [key], {key + (ONE,): 0, key + (TWO,): TINY, key + (THREE,): NEG_ZERO})
    rows += rank_arms("negative below zero", [ONE, TWO, THREE], [key], {key + (ONE,): MINUS, key + (TWO,): 0, key + (THREE,): MINUS + 1})
    rows += rank_arms("infinities and nan", many(6), [key], {key + (name,): bits for name, bits in zip(many(6), (INF, NEG_INF, NAN, NEG_NAN, PLUS, MINUS))})
    rows += rank_arms("two keys", [ONE, TWO], [(5, 1), (5, 0)], {(5, 1, ONE): PLUS, (5, 0, TWO): PLUS, (5, 0, ONE): HALF})
    rows += rank_arms("keys out of order", [ONE], [(9, 1), (2, 0), (9, 0), (2, 1)], {(id_, side, ONE): PLUS for id_ in (2, 9) for side in (0, 1)})
    rows += rank_arms("big id", [ONE], [(1 << 63, 1), (3, 1)], {(1 << 63, 1, ONE): PLUS})
    rows += rank_arms("key with no set", [ONE], [(5, 1), (6, 1)], {(6, 1, ONE): PLUS})
    rows += rank_arms("the same key twice", [ONE, TWO], [(5, 1), (5, 1)], {key + (ONE,): PLUS, key + (TWO,): TWO_F})
    rows += rank_arms("the same key three times", [ONE], [(5, 1), (6, 0), (5, 1), (5, 1)], {key + (ONE,): PLUS})
    for count in (2, 3, 4, 5, 11, 12, 13, 20, 21, 22, 30, 40, 60, 100):
        names = many(count)
        rows += rank_arms("users %d" % count, names, [key], {key + (name,): 0x3FF0000000000000 + ((index * 37) % 19 << 44) for index, name in enumerate(names)})
    names = many(24)
    rows += rank_arms("users 24 reversed", names, [key], {key + (name,): 0x4000000000000000 - (index << 40) for index, name in enumerate(names)})
    rows += rank_arms("users 24 sorted", names, [key], {key + (name,): 0x3FF0000000000000 + (index << 40) for index, name in enumerate(names)})
    rows += rank_arms("users 24 one score", names, [key], {key + (name,): PLUS for name in names})
    rows += rank_arms("users 30 half missing", many(30), [key], {key + (name,): PLUS + index for index, name in enumerate(many(30)) if index % 2})
    keys = [(index, index & 1) for index in range(26)]
    rows += rank_arms("keys 26", [ONE, TWO], keys, {(index, side, ONE): PLUS + index for index, side in keys})
    keys = [(100 - index, 1) for index in range(14)]
    rows += rank_arms("keys 14 down", [ONE], keys, {(index, side, ONE): PLUS + index for index, side in keys})
    keys = [(8, 1), (7, 1), (7, 0), (8, 0)]
    rows += rank_arms("side bytes", [ONE], keys, {name + (ONE,): PLUS for name in keys})
    rows.append(rank_case("touched skips absent", [ONE], [key], {key + (ONE,): PLUS}, touched=[ONE, GONE]))
    rows.append(rank_case("touched of absent only", [ONE], [key], {key + (ONE,): PLUS}, touched=[GONE]))
    rows.append(rank_case("empty touched", [ONE], [key], {key + (ONE,): PLUS}, touched=[]))
    rows.append(rank_case("flag beats touched", [ONE, TWO], [key], {key + (ONE,): PLUS, key + (TWO,): PLUS}, touched=[ONE], flag=1))
    rows.append(rank_case("touched only part", [ONE, TWO, THREE], [key], {key + (THREE,): PLUS, key + (TWO,): HALF}, touched=[THREE, ONE]))
    rows.append(rank_case("no touched has no key rows", [ONE], [(1, 1), (2, 0)], {}, touched=[]))
    for crowd in (1, 3, 15, 16, 17):
        names = many(6)
        rows += [dict(case, label=case["label"] + " crowd %d" % crowd, crowd=crowd) for case in rank_arms("crowd", names, [key], {key + (name,): PLUS + index for index, name in enumerate(names)})[:1]]
    return rows


def all_cases():
    return scan_cases() + rank_cases()


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x37d7360", "per-user row builder; user row, address, both mode bytes, dex + 0x60 and dex checked; rows given by the case in a real heap vector. Held by #222, #229"),
    ("0x36f5d40", "per-user score; id, side, oracle pointer, dex, address and user row checked; a miss or a score word given by the case. Held by open #799"),
    ("0x399c7a0", "address hash; hasher pointer checked, SipHash 1-3 of the key so that the inline probe in the folds must agree"),
    ("0x4e17630", "rayon thread-local read; returns a worker whose pool reports 0 threads, so that the real bridges run their leaf arm"),
    ("0x33f3fc0", "drop of a replaced candidate set, reached only by the same key twice; count read and call order recorded, nodes freed. Listed by #875"),
    ("0x32d6a00, 0x32d5860, 0x32d59b0, 0x32d5b70", "vector growth; element size checked, real heap blocks moved"),
)
CLAIMED = (("scan host", 0x3707910), ("address keys", 0x3BC3B00), ("given insert loop", 0x3BC4080), ("touched insert loop", 0x3BC3E00), ("row insert", 0x3396340), ("row search", 0x2FDCBD0), ("whole collect", 0x33C31F0), ("whole collect loop", 0x3307A60), ("whole sort", 0x3BB36E0), ("row order", 0x3383C10),
           ("row fold by address", 0x3766090), ("row fold by pair", 0x37664D0), ("candidate collect", 0x33C58E0), ("set of one key", 0x3761320), ("score fold by address", 0x3766BB0), ("score fold by pair", 0x3767460), ("touched set loop", 0x3BC4300), ("rank insert", 0x33A3610), ("flag address map", 0x33C4530), ("flag sort", 0x3BB2FC0), ("rank order", 0x33864B0), ("key map insert", 0x33A98E0), ("key fold", 0x388DF00))
OTHER_REAL = "the other functions of REAL_FUNCTIONS: rayon bridges and folders, the std sort, B-tree bulk push and node inserts. They run real and are not claimed"
CONSTANT_SITES = (
    ("users object inside the dex", 0x3707924, b"\x4c\x8d\xa6\xf8\x00\x00\x00", 0xF8),
    ("set +0x60 of the dex", 0x370792B, b"\x4c\x8d\x7e\x60", 0x60),
    ("whole account flag, dex", 0x37079D5, b"\x41\x80\xbe\xa0\x01\x00\x00\x00", 0x1A0),
    ("touched address set, dex", 0x37079E3, b"\x49\x8d\xb6\x58\x01\x00\x00", 0x158),
    ("whole account flag, users object", 0x3761348, b"\x41\x80\xbf\xa8\x00\x00\x00\x00", 0xA8),
    ("touched address set, users object", 0x3761486, b"\x49\x8d\x77\x60", 0x60),
    ("bucket stride of the users table", 0x3766C28, b"\x4d\x6b\xc9\x78", 0x78),
    ("side byte that ends the key fold", 0x388DF79, b"\x80\x7c\x24\x28\x02", 2),
    ("row sort: insertion up to 20", 0x3BB39B6, b"\x49\x83\xff\x15", 0x15),
    ("score sort: insertion up to 20", 0x3BB321B, b"\x49\x83\xff\x15", 0x15),
    ("rank row stride in the collect", 0x33C4667, b"\x48\x6b\xcb\x38", 0x38),
    ("row stride times 3 in the given loop", 0x3BC41D3, b"\x4b\x8d\x2c\x76", 3),
)


def groups(image):
    return [(role, *image.exact_fde(start)) for role, start in CLAIMED]


def constants(image):
    rows = []
    for name, va, pattern, value in CONSTANT_SITES:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(pattern)]) != pattern:
            raise EvidenceError("constant moved: " + name)
        rows.append({"name": name, "address": "%#x" % va, "bytes": pattern.hex(), "value": value})
    return rows


def callers(image):
    """Who reaches the two paths: E8 sites and FF 15 sites through RELATIVE slots."""
    base, text = image.text_bytes()
    slots = {}
    for slot, target in relative_slots(image).items():
        if target in (SCAN, RANKS):
            slots.setdefault(target, []).append(slot)
    rows = []
    for at in range(len(text) - 6):
        if text[at] == 0xE8:
            target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
            if target in (SCAN, RANKS):
                rows.append(("%#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0], "direct"))
        elif text[at] == 0xFF and text[at + 1] == 0x15:
            slot = base + at + 6 + struct.unpack_from("<i", text, at + 2)[0]
            for target, held in slots.items():
                if slot in held:
                    rows.append(("%#x" % target, "%#x" % (base + at), "%#x" % image.fde(base + at)[0], "slot %#x" % slot))
    return sorted(rows)


# ---- mutation ----

MUTANT_CASES = 4
MUTANT_EVERY = 3


def displacement_at(image, row):
    for operand in (row.a, row.b):
        if operand and operand[0] == "m" and operand[1] not in (None, RSP) and operand[4]:
            disp = operand[4]
            end = row.size - (row.imm_size or 0)
            base = image.offset(row.va)
            data = bytes(image.blob[base:base + row.size])
            if -128 <= disp <= 127 and data[end - 1:end] == struct.pack("<b", disp):
                return end - 1
            if data[end - 4:end] == struct.pack("<i", disp):
                return end - 4
            raise EvidenceError("displacement not found at %#x" % row.va)
    return None


def mutation_targets(image, rows):
    """Yield (va, byte offset in the instruction, xor mask, kind)."""
    for row in rows:
        at = displacement_at(image, row)
        if at is not None:
            yield row.va, at, 8, "offset"
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), 1, "branch"
        elif row.op in ("set", "cmov"):
            base = image.offset(row.va)
            yield row.va, bytes(image.blob[base:base + 16]).index(b"\x0f") + 1, 1, row.op
        if row.imm_at is not None and row.op not in ("jcc", "call", "jmp"):
            yield row.va, row.imm_at, 1, "immediate"


def pick_cases(indices, steps):
    """The cheapest half of the budget, then the rest spaced evenly over the dearer cases, so a rare state is not left out."""
    ordered = sorted(indices, key=lambda at: (steps[at], at))
    if len(ordered) <= MUTANT_CASES:
        return ordered
    half = MUTANT_CASES // 2
    rest = ordered[half:]
    return ordered[:half] + [rest[at * len(rest) // half] for at in range(half)]


def run_mutants(image, reached, steps, cases):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for role, begin, end in groups(image):
        for number, (va, at, xor, kind) in enumerate(mutation_targets(image, decode_range(image, begin, end))):
            if number % MUTANT_EVERY:
                continue
            indices = by_va.get(va)
            if not indices:
                results.append({"group": role, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            base = image.offset(va)
            machine.patches = {va + at: image.blob[base + at] ^ xor}
            machine.cache.pop(va, None)
            failed = None
            wanted = set(indices)
            chosen = pick_cases(indices, steps)
            seen = set(chosen)
            for index in [item for item in first_kill if item in wanted and item not in seen] + chosen:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    del first_kill[40:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"group": role, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
    return results



def site_rows(image, rows):
    """Arguments at each slot call of the scan, by fixed byte forms in the 40 bytes before the call."""
    found = []
    for target, site, function, kind in rows:
        if target != "%#x" % SCAN:
            continue
        va = int(site, 16)
        at = image.offset(va)
        data = bytes(image.blob[at - 40:at])
        if data[-3:] != b"\x45\x31\xc9":
            raise EvidenceError("argument 6 is not cleared at " + site)
        mode, place = None, -1
        for pattern, value in ((b"\x31\xd2", 0), (b"\xba\x02\x00\x00\x00", 2), (b"\xba\x03\x00\x00\x00", 3)):
            spot = data.rfind(pattern)
            if spot > place:
                mode, place = value, spot
        zero = data.rfind(b"\x45\x31\xc0")
        lea = data.rfind(b"\x4c\x8d\x84\x24")
        found.append((site, function, mode, "none" if zero > lea else "stack set", 0))
    if len(found) != 16:
        raise EvidenceError("scan sites")
    return found


FIELD_SITES = ((0x3B13FC, b"user_to_state"), (0x3B1409, b"users_with_positions"), (0x3B141D, b"check_all_users_for_liquidatables"))


def field_rows(image):
    rows = []
    for va, text in FIELD_SITES:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(text)]) != text:
            raise EvidenceError("field text moved")
        rows.append({"address": "%#x" % va, "text": text.decode()})
    return rows


# ---- evidence ----

def path_rows():
    return [
        ("1", "scan entry", "0x3707910", "arguments out, dex, mode byte, payload byte, optional address set, byte. Users are dex +0xf8 (user_to_state). Set given: that set. Otherwise byte != 0 or dex +0x1a0 != 0: the whole table. Otherwise the set at dex +0x158 (users_with_positions). A given set wins, even an empty one"),
        ("2", "set arms", "0x3bc3b00, 0x3bc3e00, 0x3bc4080", "the set becomes a vector of pointers to its keys, the fold runs, the rows of every list node are inserted one at a time into a B-tree set. The same two functions are what the ADL core 0x36f7c40 calls directly"),
        ("3", "row fold", "0x3766090", "users empty: every address skipped with no hash. Else hash, probe; an address not in the table is skipped; found: 0x37d7360(row, address, mode, payload, dex +0x60, dex) gives a vector of 0x30 rows, joined to the fold's vector"),
        ("4", "whole arm", "0x3bc9a80, 0x37664d0, 0x33c31f0, 0x3307a60, 0x3bb36e0", "bucket order pairs (address, row), the same builder per pair, the (address, rows) items in a B-tree map by address, then all rows flattened, sorted, equal rows dropped and bulk built. 0 rows gives root 0"),
        ("5", "row order", "0x2fdcbd0, 0x3383c10", "address bytes, tag, word 1 only with both tags not 0, word 2 signed. Word 1 of a cross row is never read, and the builder leaves it unset"),
        ("6", "candidate entry", "0x33c58e0, 0x3889650, 0x388df00", "a list of pointers to (id, side) keys, the users object, the oracle table and the dex. One 0x28 row per key is collected first, and only then inserted into the out map, in list order"),
        ("7", "end of fold", "0x388df00", "side byte 2 in a result row ends the fold, and 0x3889650 then panics on the short count. Side is a bool niche, so 2 cannot come from a real key"),
        ("8", "one key", "0x3761320", "byte +0xa8 of the users object (dex +0x1a0) != 0: every pair of the table. Otherwise the keys of the set at +0x60 (dex +0x158). A key always gets a row, empty set included"),
        ("9", "score fold", "0x3766bb0, 0x3767460", "users empty: nothing. Else 0x36f5d40(id, side, oracle, dex, address, row); a result with word 0 != 1 drops the user, a kept one is (score, address), 0x20 bytes. The pair fold also keeps the address as a 0x38 row"),
        ("10", "listed set", "0x3bc4300, 0x33a3610", "rows go one at a time into a set ordered by (score word, address)"),
        ("11", "flag set", "0x33c4530, 0x3bb2fc0", "rows first go to a map by address, then into a vector of its values, sorted by the same order and bulk built"),
        ("12", "score order", "0x33a3610, 0x33864b0", "score bits x: sign clear gives x | 2^63, sign set gives !x, compared unsigned, then address bytes. This is f64 total order: NaN at the two ends, -0 below +0"),
        ("13", "key map", "0x33a98e0, 0x33f3fc0", "out map keyed (id, side). The same key again replaces the set and the old one is dropped. A key with no candidate stays in the map with root 0, and the ADL core panics on it only when size is left"),
    ]


def reference_rows():
    return [
        ("result shape", "Vec<AdlSideCandidates> with Vec<AdlCandidate>", "B-tree map (id, side) to a B-tree set of (score, address)", "the reference has no sort; order is the point of the set"),
        ("order in the all users arm", "BTreeMap by user, into_values, so address order", "values of the address map are sorted by score then address", "the reference order is the intermediate one"),
        ("order in the active arm", "set order, so address order", "(score, address) set", "same point"),
        ("flag at +0xa8", "use_full_user_scan_for_adl, ADL only", "the same byte also selects the whole table in the scan of 0x3707910", "serializer text after users_with_positions is check_all_users_for_liquidatables"),
        ("users set at +0x60", "active_users_with_positions", "rodata text users_with_positions", "name differs"),
        ("collection", "a plain loop over requests", "rayon collect of one set per key, then one insert per key, last one wins", "the loop order is the same"),
    ]


SAMPLES = ("no users given", "one cross row touched", "cross and isolated every", "isolated sort by asset flag", "equal rows differ in word 2 given", "two cross rows differ in word 1 given", "two cross rows differ in word 1 every", "given skips absent", "empty given beats every", "every beats touched", "users 22 every", "rank order by score touched", "rank tie by address flag", "rank zero then tiny touched", "rank infinities and nan flag", "rank keys out of order touched", "rank key with no set flag", "rank the same key twice touched", "rank touched only part", "rank users 30 half missing flag")


def sample_rows(image, cases):
    harness = Harness(image)
    rows = []
    for case in cases:
        if case["label"] not in SAMPLES:
            continue
        if compare_run(harness, case):
            raise EvidenceError("sample mismatch: " + case["label"])
        spec = Spec(case)
        want = spec.run()
        calls = len([event for event in spec.events if event[0] in ("row", "rank")])
        if case["kind"] == "scan":
            shape = "rows " + ", ".join("%02x:%d" % (row[3][19], row[0]) for row in want["rows"][:8])
        else:
            shape = "; ".join("%d/%d: %s" % (key[0], key[1], " ".join("%02x" % row[1][19] for row in want["final"][key][:8])) for key in sorted(want["final"]))
        rows.append((case["label"], case["kind"], calls, shape))
    if len(rows) != len(SAMPLES):
        raise EvidenceError("sample list")
    return rows


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached, steps = [], []
    kinds = {}
    for case in cases:
        machine.seen = set()
        before = machine.steps
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        steps.append(machine.steps - before)
        if failed:
            mismatches += 1
            first = first or failed
        kinds[case["kind"]] = kinds.get(case["kind"], 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    entries = callers(image)
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "real_functions_not_claimed": ["%#x" % start for start in sorted(set(REAL_FUNCTIONS) - {start for _, start in CLAIMED})],
        "callers": [{"target": row[0], "site": row[1], "function": row[2], "kind": row[3]} for row in entries],
        "constants": constants(image),
        "field_texts": field_rows(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "cases": kinds,
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
    }
    results = None
    if full:
        results = run_mutants(image, reached, steps, cases)
        summary_rows = {}
        for row_ in results:
            summary_rows[row_["result"]] = summary_rows.get(row_["result"], 0) + 1
        evidence["mutations"] = {name: summary_rows.get(name, 0) for name in ("killed", "survived", "unreached")}
        evidence["mutations"]["cases_per_mutant_at_most"] = MUTANT_CASES
        evidence["mutations"]["one_site_in"] = MUTANT_EVERY
    return evidence, results


COLD = "not stepped by any case: allocation failure, unwind, a second rayon list node, or the 8 step unrolled part of a tree walk"
UNCLASSIFIED = "no case in the budget tells it apart; see README limits"
REASONS = {}
for _start, _end, _text in ((0x33C590F, 0x33C5D87, "0x3889650 always returns word 0 == 0 on its normal path, so the arm for a rayon list result cannot run here"),):
    for _at in range(_start, _end):
        REASONS[_at] = _text
for _at in (0x3BB375A, 0x3BB377D, 0x3BB37B4, 0x3BB38DB, 0x3BB38FF, 0x3BB3019, 0x3BC3B38, 0x33C4594):
    REASONS[_at] = "changes only a size hint or an allocation overflow guard, and no list here is long enough to tell"
for _at in (0x33963A6, 0x33963DA):
    REASONS[_at] = "the return byte of the row insert for a row with tag 2, which no builder writes"
for _at in (0x33C4750, 0x33A3750, 0x33A36C6):
    REASONS[_at] = "a compare of one byte more; addresses in the cases are unique, so it ends inside the 20 bytes"


def reason_for(row_):
    return REASONS.get(row_["va"], COLD if row_["result"] == "unreached" else UNCLASSIFIED)


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row_) for row_ in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    image = load_image()
    evidence, results = analyse(image)
    if evidence["mismatches"]:
        raise EvidenceError("specification mismatch: %s" % evidence["first_mismatch"])
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), path_rows())
    write_tsv(out / "reference-diffs.tsv", ("point", "reference_text", "node_94_bytes", "note"), reference_rows())
    write_tsv(out / "scan-sites.tsv", ("site", "function", "mode_byte", "address_set", "byte_argument"), site_rows(image, callers(image)))
    write_tsv(out / "samples.tsv", ("label", "kind", "stub_calls", "result"), sample_rows(image, all_cases()))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row_ in results:
        reason = "" if row_["result"] == "killed" else reason_for(row_)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row_["group"], row_["va"], row_["kind"], row_["result"], row_["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %r, mismatches %d, mutants %r" % (evidence["cases"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
