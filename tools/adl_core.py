#!/usr/bin/env python3
"""Pin the node #94 auto-deleverage core 0x36f7c40 from ELF bytes: trigger scan, target rows, candidate walk, margin move, fill rows, equity sweep and round loop.

The core and the tree helpers it owns run whole in a Python evaluator. A separately written specification predicts every stub
argument, text argument, fill row and final account, and every condition, immediate and field offset of those bodies is flipped
to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import copy
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

ADL = 0x36F7C40
USER_READ = 0x36F57F0
USER_ENTRY = 0x3596940
ACCOUNT_VALUE = 0x37D77E0
SUMMARY = 0x37D79E0
CREDIT = 0x37067B0
SET_ADD = 0x339B590
SET_REMOVE = 0x33ACFE0
HASH_ADDRESS = 0x399C7A0
HASH_ID = 0x399C4A0
DECODE = 0x3BFFFD0
MARGIN_TABLE = 0x3398F50
LEVERAGE_NOTE = 0x370E6A0
LEVERAGE_MOVE = 0x370E2A0
PRODUCER = 0x3BC3B00
COLLECT = 0x3BC4080
FLATTEN = 0x3BACA10
RANKS = 0x33C58E0
DROP_RANKS = 0x33F1980
DROP_SET = 0x33F3FC0
DROP_MAP = 0x33FCB30
DROP_MAP_ITER = 0x33AE610
DROP_FINAL = 0x33F3150
RELEASE = 0x37646D0
FILL = 0x36FE830
RESERVE = 0x32D6A00
GROW_TEXT = 0x4F04BB0
GROW_ROW = 0x32D5860
GROW_TARGET = 0x32D5A90
GROW_FILL = 0x32D5EF0
FORMAT = 0x1344760
FINAL_MARK = 0x14385C0
PANIC_NONE = 0x157A9F0
PANIC_UNWRAP = 0x157AA10
PANIC_ADD = 0x157B480
PANIC_NEG = 0x157B4C0
PANIC_BOUNDS = 0x157B64F
PANIC_TEXT = 0x157B7F0
OVERFLOW_LOG = 0x358DCD0
ONCE_CALL = 0x4EE3B20
ONCE_WORD = 0x577AB98
ROW_ONCE = 0x5786300
DEFAULT_ROW = 0x57862A0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
REAL_FUNCTIONS = (0x33100D0, 0x33AE240, 0x33AD470, 0x2FDC550, 0x2FDAD90, 0x33BB3E0, 0x33BB000, 0x33BB960, 0x2FDD500, 0x2F8D190, 0x2F0E3D0, 0x33BC4D0, 0x36F7350, 0x3A00700, 0x2F24930, 0x2F18F20, 0x2FCCFA0, 0x2F53670, 0x33BD420, 0x2FCEFA0, 0x2FA4C50, 0x2FAF3B0, 0x2FAA750)
OK = 0x186
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 90000
DEX = HEAP_BASE + 0x1000
EXCHANGE = HEAP_BASE + 0x2000
ROUND_SET = HEAP_BASE + 0x3000
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

DEX_STEP = 10000
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)
U64_MAX = (1 << 64) - 1
LIST_STRIDE = 0x30
TARGET_STRIDE = 0x28
FILL_STRIDE = 0x248
TEXT_STRIDE = 0x18
ORACLE_STRIDE = 0x60
ROW_END = 2
TAG, LEVERAGE, RAW, SIZE, WORD18, WORD20, WORD28, WORD30, WORD38 = range(9)


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def word_of(value):
    return value & MASK[8]


def position(size=0, tag=0, leverage=5, raw=0, words=(0x18, 0x20, 0x28, 0x30), last=7):
    return [tag, leverage, raw, size] + list(words) + [last]


def account(balance=0, positions=None, count=None, tail=0x51):
    held = positions or {}
    return dict(balance=balance, positions={key: list(value) for key, value in held.items()}, count=sum(1 for value in held.values() if value[SIZE]) if count is None else count, tail=tail)


def dump_view(row):
    return (row["balance"], row["count"], row["tail"], tuple((at, tuple(row["positions"][at])) for at in sorted(row["positions"])))


class Spec:
    """Written from the reading of the body, without running it."""

    def __init__(self, case):
        self.case = case
        self.users = copy.deepcopy(case.get("users", {}))
        self.totals = dict(case.get("totals", {}))
        self.oracles = case.get("oracles", (1000, 1000, 1000, 1000))
        self.events = []
        self.logs = 0
        self.counter = case.get("counter", 100)
        self.values = {key: list(items) for key, items in case.get("values", {}).items()}
        self.fills = 0
        self.held = {}
        self.final = {}
        self.extra = {}

    def holder(self, key):
        if key in self.users:
            return self.users[key]
        return self.extra.setdefault(key, account())

    def plus(self, left, right):
        out = left + right
        if out > I64_MAX or out < I64_MIN:
            self.logs += 1
            return I64_MAX if out > 0 else I64_MIN
        return out

    def size_of(self, value):
        if value == I64_MIN:
            raise Panicked("unwrap")
        return abs(value)

    def value(self, key, first, second, read=False):
        key = key if read or key in self.users else None
        self.events.append(("value", key, first, second))
        items = self.values.get(key)
        if not items:
            return 0
        return items.pop(0) if len(items) > 1 else items[0]

    def read_row(self, key, name):
        return self.users.get(key, dict(positions={}))["positions"].get(name)

    def text(self, kind, *words):
        self.events.append(("text", kind) + words)

    def scan(self, rows):
        total, kept = 0, []
        exempt = self.case.get("exempt", ())
        mode = self.case.get("mode", 0)
        for row in rows:
            first, second, _, key = row
            value = self.value(key, first, second)
            if value == I64_MIN:
                raise Panicked("neg")
            short = max(-value, 0)
            immediate = False
            if first & MASK[4] == 1:
                if second // DEX_STEP != self.case.get("dex_id", 0) or second % DEX_STEP >= len(self.case.get("markets", ())):
                    raise Panicked("none")
                immediate = self.case["markets"][second % DEX_STEP].get("flag", 0) != 0
            if not immediate and key in exempt:
                immediate = True
            if immediate:
                if mode != 2:
                    self.text("immediate", first, second, key)
                kept.append(row)
            else:
                total += short
                if total > U64_MAX:
                    self.logs += 1
                    total = U64_MAX
        return total, kept

    def targets(self, rows):
        found = {}

        def hold(name, key, first, second, size):
            self.held.setdefault(name, []).append(key)
            self.events.append(("held", name, key))
            found.setdefault((name, int(size <= 0)), []).append((first, second, key))
        for first, second, _, key in rows:
            held = self.users.get(key, dict(positions={}))["positions"]
            if first & MASK[4] == 1:
                if second in held:
                    hold(second, key, first, second, held[second][SIZE])
                continue
            for name in sorted(held):
                if held[name][SIZE] and held[name][TAG] == 0:
                    hold(name, key, first, second, held[name][SIZE])
        return found

    def fill(self, name, price, delta, key):
        status = self.case.get("fill_status", {}).get(self.fills, OK)
        self.fills += 1
        self.events.append(("fill", name, price, delta, key, status))
        if status != OK:
            raise Panicked("unwrap")
        row = self.users[key]["positions"][name]
        if not self.case.get("fill_quiet"):
            row[SIZE] = signed(word_of(row[SIZE] + delta))
        pay = self.case.get("pay", {}).get(key)
        if pay:
            if pay[0]:
                row[RAW] = signed(word_of(row[RAW] + pay[1]))
            else:
                self.users[key]["balance"] = signed(word_of(self.users[key]["balance"] + pay[1]))

    def available(self, key, first, second):
        """Margin that leaves the target before its fill, or None."""
        if first == 0:
            return None
        if first & MASK[4] != 1:
            self.events.append(("summary", key))
            words = self.case.get("summary", {}).get(key, (0, 0))
            if words[1] < 0:
                raise Panicked("unwrap")
            return self.plus(words[0], -words[1])
        row = self.read_row(key, second)
        if row is None:
            return None
        if second % DEX_STEP >= len(self.oracles):
            raise Panicked("bounds")
        price = self.oracles[second % DEX_STEP]
        worth = price * row[SIZE]
        if price < 0 or worth > I64_MAX or worth < I64_MIN:
            raise Panicked("none")
        if not row[TAG] & 1:
            raise Panicked("text")
        return self.plus(worth, row[RAW])

    def shift(self, key, name, amount):
        user = self.users[key]
        self.events.append(("entry", key))
        self.events.append(("touch", key))
        row = user["positions"][name]
        if row[TAG] & 0xFF:
            row[RAW] = self.plus(row[RAW], amount)
        else:
            user["balance"] = self.plus(user["balance"], amount)
        size = self.size_of(row[SIZE])
        self.totals[name] = self.plus(self.plus(self.totals.get(name, 0), -size), size)

    def match(self, name, side, price, candidates, present, rows, out):
        for first, second, key in rows:
            if first == ROW_END:
                break
            row = self.read_row(key, name)
            if row is None or row[SIZE] == 0:
                continue
            left = row[SIZE]
            while left:
                if not present or not candidates:
                    raise Panicked("none")
                other = candidates[-1][1]
                theirs = self.read_row(other, name)
                size = theirs[SIZE] if theirs else 0
                if size == 0:
                    candidates.pop()
                    continue
                if abs(size) > abs(left):
                    if left == I64_MIN:
                        raise Panicked("neg")
                    delta = -left
                else:
                    candidates.pop()
                    delta = size
                sequence = self.counter
                self.counter = min(sequence + 1, U64_MAX)
                pair = ((key, left), (other, size)) if side else ((other, size), (key, left))
                if self.case.get("settle", 1) == 1:
                    amount = self.available(key, first, second)
                    moved = amount is not None and amount > 0
                    if moved:
                        self.shift(key, name, -amount)
                    self.fill(name, price, delta, key)
                    if moved:
                        self.shift(key, name, amount)
                    if delta == I64_MIN:
                        raise Panicked("neg")
                    self.fill(name, price, -delta, other)
                size_ = abs(delta)
                worth = (price & U64_MAX) * size_
                if worth > I64_MAX - 1:
                    raise Panicked("none")
                out.append((pair[0][1], sequence, pair[0][0], pair[1][1], pair[1][0], price, name, size_, worth, self.case.get("clock", (0x1122334455667788, 0x99AABBCC)), side, first, second))
                left = self.plus(left, delta)
        self.events.append(("drop set", len(candidates)))

    def sweep(self, rows):
        for first, second, floor, key in rows:
            if first == ROW_END:
                break
            self.events.append(("read", key))
            value = self.value(key, first, second, True)
            if value < floor:
                self.text("balance", key, first, second, value, floor)
            user = self.holder(key)
            held = user["positions"]
            if first & 0xFF:
                if second in held and held[second][SIZE]:
                    self.text("final", key, first, second, held[second][SIZE])
            else:
                for name in sorted(held):
                    if held[name][SIZE] and held[name][TAG] == 0:
                        self.text("final cross", key, first, second, name, held[name][SIZE])
            if value <= 0:
                continue
            self.events.append(("entry", key))
            self.events.append(("touch", key))
            if first & MASK[4] == 1:
                row = held.get(second)
                if row is None:
                    self.events.append(("decode", second))
                    tag, leverage, raw = self.case.get("defaults", {}).get(second, (0, 3, 0))
                    market = self.case["markets"][second % DEX_STEP].get("word", 0x900 + second % DEX_STEP)
                    row = held[second] = [tag, leverage, raw, 0, 0, 0, 0, 0, market]
                if row[TAG] & 0xFF == 0:
                    raise Panicked("text")
                row[RAW] = self.plus(row[RAW], -value)
                size = self.size_of(row[SIZE])
                self.totals[second] = self.plus(self.plus(self.totals.get(second, 0), -size), size)
            else:
                user["balance"] = self.plus(user["balance"], -value)
            self.events.append(("credit", value, self.case.get("credit_word", 0x7777)))

    def run(self):
        case = self.case
        rounds = case.get("rounds", ([],))
        ranks = case.get("ranks", ({},))
        mode = case.get("mode", 0)
        settle = case.get("settle", 1)
        words = case.get("word248", 500)
        turn = 0
        while True:
            turn += 1
            rows = rounds[min(turn - 1, len(rounds) - 1)]
            self.events.append(("collect", turn))
            total, kept = self.scan(rows)
            whole = total >= words
            if whole:
                self.events.append(("flatten", len(rows)))
                kept = rows
            found = self.targets(kept)
            if mode != 2:
                if found:
                    self.text("trigger", total, words)
                elif total:
                    self.text("none", total)
            self.events.append(("ranks", tuple(sorted(found))))
            table = {key: sorted(items) for key, items in ranks[min(turn - 1, len(ranks) - 1)].items()}
            out = {}
            for key in sorted(found):
                name, side = key
                if name % DEX_STEP >= len(self.oracles):
                    raise Panicked("bounds")
                rows_ = []
                present = key in table
                candidates = table.pop(key, [])
                self.match(name, side, self.oracles[name % DEX_STEP], candidates, present, found[key], rows_)
                if rows_:
                    out[key] = rows_
            if settle == 1:
                self.sweep(kept)
            self.events.append(("drop ranks", len(table)))
            if settle != 1 or not out:
                break
            for key in sorted(out):
                for row in out[key]:
                    self.events.append(("round set", row[2]))
                    self.events.append(("round set", row[4]))
                self.final.setdefault(key, []).extend(out[key])
            if not whole:
                self.events.append(("drop map",))
        if self.final:
            self.events.append(("final",))
        if not whole:
            self.events.append(("drop map",))
        self.events.append(("release",))
        return dict(rounds=turn, final={key: tuple(self.final[key]) for key in self.final}, held={key: tuple(self.held[key]) for key in self.held}, counter=self.counter, users={key: dump_view(self.users[key]) for key in self.users}, totals=self.totals, logs=self.logs)


# ---- harness ----

POSITION_MAP = dict(leaf=0x328, inner=0x388, parent=0x2C0, slot=0x320, length=0x322, keys=0x2C8, stride=8, edges=0x328, values=0x40)
TOTAL_MAP = dict(leaf=0xC0, inner=0x120, parent=0, slot=0xB8, length=0xBA, keys=8, stride=8, edges=0xC0, values=8, value_base=0x60)
ROW_SET = dict(leaf=0x220, inner=0x280, parent=0x210, slot=0x218, length=0x21A, keys=0, stride=0x30, edges=0x220, values=0)
EXEMPT_SET = dict(leaf=0xE8, inner=0x148, parent=0, slot=0xE4, length=0xE6, keys=8, stride=20, edges=0xE8, values=0)
KEY_MAP = dict(leaf=0x1C8, inner=0x228, parent=0xB0, slot=0x1C0, length=0x1C2, keys=0, stride=0x10, edges=0x1C8, values=0x18, value_base=0xB8)
RANK_SET = dict(leaf=0x170, inner=0x1D0, parent=0x160, slot=0x168, length=0x16A, keys=0, stride=0x20, edges=0x170, values=0)
HELD_MAP = dict(leaf=0x170, inner=0x1D0, parent=0, slot=0x168, length=0x16A, keys=8, stride=8, edges=0x170, values=0x18, value_base=0x60)
CAPACITY = 11
HASH_K0, HASH_K1 = 0x0123456789ABCDEF, 0xFEDCBA9876543210
BUCKETS = 256
ENTRY_STRIDE = 0x78


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


def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items, put):
    """B-tree over sorted (key bytes, value) items; returns the root and its height."""
    if not items:
        return 0, 0
    base = shape.get("value_base", 0)

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
        for index, (key, value) in enumerate(entries):
            memory.put_bytes(node + shape["keys"] + shape["stride"] * index, key)
            put(node + base + shape["values"] * index, value)
        for index, part in enumerate(children):
            memory.write(node + shape["edges"] + 8 * index, 8, make(part, level - 1, node, index))
        return node

    height = tree_height(len(items))
    return make(items, height, 0, 0), height


def tree_items(memory, shape, node, height):
    """(key bytes, value address) in key order."""
    if not node:
        return []
    found = []
    count = memory.read(node + shape["length"], 2)
    if count > CAPACITY:
        raise Halt("node length")
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            found.append((memory.bytes_at(node + shape["keys"] + shape["stride"] * index, shape["stride"]), node + shape.get("value_base", 0) + shape["values"] * index))
    return found


def word_key(value):
    return struct.pack("<Q", value)


def pair_key(name, side):
    return struct.pack("<QB", name, side) + b"\xbb" * 7


TEXTS = {0x1E77A3: "immediate", 0x1E5653: "trigger", 0x1EACFE: "none", 0x1DEEA6: "balance", 0x1E4080: "final cross", 0x1EE7CC: "final"}


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {ADL} | set(REAL_FUNCTIONS)
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        machine.calls = {USER_READ: self.on_read, USER_ENTRY: self.on_entry, SET_ADD: self.on_add, SET_REMOVE: self.on_remove, HASH_ADDRESS: self.on_hash, HASH_ID: self.on_halt, DECODE: self.on_decode, MARGIN_TABLE: self.on_halt, LEVERAGE_NOTE: self.on_halt, LEVERAGE_MOVE: self.on_halt,
                         PRODUCER: self.on_producer, COLLECT: self.on_collect, FLATTEN: self.on_flatten, RANKS: self.on_ranks, DROP_RANKS: self.on_drop_ranks, DROP_SET: self.on_drop_set, DROP_MAP: self.on_drop_map, DROP_MAP_ITER: self.on_drop_iter, DROP_FINAL: self.on_nothing, RELEASE: self.on_release, FILL: self.on_fill,
                         RESERVE: self.on_reserve}
        hooks = {ACCOUNT_VALUE: self.on_value, SUMMARY: self.on_summary, CREDIT: self.on_credit, OVERFLOW_LOG: self.on_log, ONCE_CALL: self.on_once, FORMAT: self.on_format, FINAL_MARK: self.on_final,
                 GROW_TEXT: self.on_grow(TEXT_STRIDE), GROW_ROW: self.on_grow(LIST_STRIDE), GROW_TARGET: self.on_grow(TARGET_STRIDE), GROW_FILL: self.on_grow(FILL_STRIDE),
                 PANIC_NONE: self.on_panic("none"), PANIC_UNWRAP: self.on_panic("unwrap"), PANIC_ADD: self.on_panic("add"), PANIC_NEG: self.on_panic("neg"), PANIC_BOUNDS: self.on_panic("bounds"), PANIC_TEXT: self.on_panic("text")}
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        for slot, target in relative_slots(image).items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy), (SLOT_MEMMOVE, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        for word in range(0, 0x60, 4):
            machine.memory.statics[DEFAULT_ROW + word] = 0
        machine.memory.statics[ONCE_WORD] = 0
        machine.memory.statics[ROW_ONCE] = 0

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

    def on_log(self, machine):
        self.logs += 1

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_halt(self, machine):
        raise Halt("stub outside the cases at %#x" % machine.regs[RDI])

    def on_decode(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDX] != DEX:
            raise Halt("decode context")
        self.events.append(("decode", regs[RSI]))
        tag, leverage, raw = self.case.get("defaults", {}).get(regs[RSI], (0, 3, 0))
        memory.write(regs[RDI], 4, tag)
        memory.write(regs[RDI] + 4, 4, leverage)
        memory.write(regs[RDI] + 8, 8, word_of(raw))

    def on_nothing(self, machine):
        pass

    def on_once(self, machine):
        raise Halt("once")

    def on_final(self, machine):
        self.events.append(("final",))

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
        if regs[RCX] != 8 or regs[R8] != FILL_STRIDE:
            raise Halt("reserve arguments")
        vector = regs[RDI]
        cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
        wider = max(cap * 2, regs[RSI] + regs[RDX], 4)
        fresh = self.node(wider * FILL_STRIDE)
        if cap:
            memory.copy(fresh, data, cap * FILL_STRIDE)
            del self.blocks[data]
        memory.write(vector, 8, wider)
        memory.write(vector + 8, 8, fresh)

    def key_of(self, row):
        return self.row_keys.get(row)

    def on_read(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0xF8:
            raise Halt("read map")
        key = memory.bytes_at(regs[RSI], 20)
        self.events.append(("read", key))
        regs[RAX] = self.row_at(key)

    def on_entry(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0xF8:
            raise Halt("entry map")
        key = memory.bytes_at(regs[RSI], 20)
        self.events.append(("entry", key))
        regs[RAX] = self.row_at(key)

    def row_at(self, key):
        if key not in self.rows:
            self.rows[key] = self.put_account(self.bump(0x60), account())
            self.row_keys[self.rows[key]] = key
        return self.rows[key]

    def on_add(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RSI], 20)
        if regs[RDI] == DEX + 0x188:
            self.events.append(("touch", key))
        elif regs[RDI] == ROUND_SET:
            self.events.append(("round set", key))
        else:
            place = regs[RDI]
            names = [struct.unpack("<Q", name)[0] for name, at in tree_items(memory, HELD_MAP, memory.read(self.held_at, 8), memory.read(self.held_at + 8, 8)) if at == place]
            if not names:
                raise Halt("set pointer")
            self.events.append(("held", names[0], key))
            self.held.setdefault(names[0], []).append(key)

    def on_remove(self, machine):
        raise Halt("set remove outside the cases")

    def on_hash(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0x118:
            raise Halt("hash table")
        regs[RAX] = sip13(memory.read(regs[RDI], 8), memory.read(regs[RDI] + 8, 8), memory.bytes_at(regs[RSI], 20))

    def on_value(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RCX] & 0xFF or regs[R9] != DEX + 0x60 or memory.read(regs[RSP], 8) != DEX:
            raise Halt("value arguments")
        key = self.key_of(regs[RDI])
        if key is None and regs[RDI] != DEFAULT_ROW:
            raise Halt("value row")
        name = self.row_name.get(regs[RDI], key)
        self.events.append(("value", name, regs[RSI], regs[RDX]))
        items = self.values.get(name)
        regs[RAX] = word_of(0 if not items else items.pop(0) if len(items) > 1 else items[0])

    def on_summary(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDX] or regs[RCX] or regs[R9] != self.oracle_at or memory.read(regs[RSP], 8) != DEX:
            raise Halt("summary arguments")
        key = self.key_of(regs[RSI])
        self.events.append(("summary", key))
        words = self.case.get("summary", {}).get(key, (0, 0))
        memory.write(regs[RDI], 8, word_of(words[0]))
        memory.write(regs[RDI] + 8, 8, word_of(words[1]))

    def on_credit(self, machine):
        regs = machine.regs
        if regs[RDI] != DEX or regs[RSI]:
            raise Halt("credit arguments")
        self.events.append(("credit", signed(regs[RDX]), regs[RCX]))

    def on_format(self, machine):
        regs, memory = machine.regs, machine.memory
        kind = TEXTS.get(regs[RSI])
        if kind is None:
            raise Halt("format text %#x" % regs[RSI])
        args = regs[RDX]

        def at(index):
            return memory.read(args + index * 16, 8)

        def word(index, *hops):
            value = at(index)
            for _ in hops:
                value = memory.read(value, 8)
            return value
        if kind == "immediate":
            row = word(0, 1, 2)
            self.events.append(("text", kind, memory.read(row, 8), memory.read(row + 8, 8), memory.bytes_at(row + 0x18, 20)))
        elif kind == "trigger":
            self.events.append(("text", kind, word(0, 1, 2), word(1, 1, 2)))
            if memory.read(at(2), 8) != self.keys_at:
                raise Halt("trigger map")
        elif kind == "none":
            self.events.append(("text", kind, word(0, 1, 2)))
        else:
            key = memory.bytes_at(word(1, 1), 20)
            head = word(2, 1)
            words = memory.read(head, 8), memory.read(head + 8, 8)
            if kind == "balance":
                self.events.append(("text", kind, key) + words + (signed(word(3, 1, 2)), signed(word(4, 1, 2))))
            elif kind == "final":
                held = word(3, 1, 2)
                self.events.append(("text", kind, key) + words + (signed(memory.read(held + 0x10, 8)),))
            else:
                name, held = word(3, 1, 2), word(4, 1, 2)
                self.events.append(("text", kind, key) + words + (name, signed(memory.read(held + 0x10, 8))))
        data = self.node(1)
        memory.write(regs[RDI], 8, 1)
        memory.write(regs[RDI] + 8, 8, data)
        memory.write(regs[RDI] + 0x10, 8, 1)

    def on_producer(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != ROUND_SET:
            raise Halt("producer set")
        memory.write(regs[RDI], 8, 0x6161)
        memory.write(regs[RDI] + 8, 8, 0x6262)
        memory.write(regs[RDI] + 0x10, 8, 0x6363)

    def on_collect(self, machine):
        regs, memory = machine.regs, machine.memory
        source = regs[RSI]
        if [memory.read(source + index * 8, 8) for index in (0, 1, 2)] != [0x6161, 0x6262, 0x6363] or memory.read(source + 0x18, 8) != DEX + 0xF8 or memory.read(source + 0x28, 8) != DEX + 0x60 or memory.read(source + 0x30, 8) != DEX:
            raise Halt("collect context")
        self.turn += 1
        self.events.append(("collect", self.turn))
        rounds = self.case.get("rounds", ([],))
        rows = rounds[min(self.turn - 1, len(rounds) - 1)]

        def key_of(row):
            first, second, third, key = row
            return struct.pack("<QQQ", first, second, word_of(third)) + key + b"\xcc" * 4
        root, height = build_tree(memory, self.node, ROW_SET, [(key_of(row), None) for row in rows], lambda at, value: None)
        memory.write(regs[RDI], 8, root)
        memory.write(regs[RDI] + 8, 8, height)
        memory.write(regs[RDI] + 0x10, 8, len(rows))

    def on_flatten(self, machine):
        regs, memory = machine.regs, machine.memory
        source = regs[RSI]
        root, height, count = memory.read(source + 0x10, 8), memory.read(source + 0x18, 8), memory.read(source + 0x40, 8)
        items = tree_items(memory, ROW_SET, root, height)
        if len(items) != count or memory.read(source, 8) != int(root != 0):
            raise Halt("flatten iterator")
        self.events.append(("flatten", count))
        data = self.node(max(count, 1) * LIST_STRIDE)
        for index, (key, _) in enumerate(items):
            memory.put_bytes(data + index * LIST_STRIDE, key)
        memory.write(regs[RDI], 8, max(count, 1))
        memory.write(regs[RDI] + 8, 8, data)
        memory.write(regs[RDI] + 0x10, 8, count)
        self.drop_tree(ROW_SET, root, height)

    def drop_tree(self, shape, root, height):
        if not root:
            return
        count = self.machine.memory.read(root + shape["length"], 2)
        if height:
            for index in range(count + 1):
                self.drop_tree(shape, self.machine.memory.read(root + shape["edges"] + 8 * index, 8), height - 1)
        self.blocks.pop(root, None)

    def on_ranks(self, machine):
        regs, memory = machine.regs, machine.memory
        source = regs[RSI]
        data, count = memory.read(source, 8), memory.read(source + 8, 8)
        keys = []
        for index in range(count):
            at = memory.read(data + index * 8, 8)
            keys.append((memory.read(at, 8), memory.read(at + 8, 1)))
        if memory.read(source + 0x10, 8) != DEX + 0xF8 or memory.read(source + 0x18, 8) != DEX + 0x60 or memory.read(source + 0x20, 8) != DEX:
            raise Halt("ranks context")
        self.events.append(("ranks", tuple(keys)))
        ranks = self.case.get("ranks", ({},))
        table = ranks[min(self.turn - 1, len(ranks) - 1)]

        def put(at, items):
            root, height = build_tree(memory, self.node, RANK_SET, [(struct.pack("<Q", rank) + key + b"\xdd" * 4, None) for rank, key in sorted(items)], lambda place, value: None)
            memory.write(at, 8, root)
            memory.write(at + 8, 8, height)
            memory.write(at + 0x10, 8, len(items))
        root, height = build_tree(memory, self.node, KEY_MAP, [(pair_key(*key), table[key]) for key in sorted(table)], put)
        memory.write(regs[RDI], 8, root)
        memory.write(regs[RDI] + 8, 8, height)
        memory.write(regs[RDI] + 0x10, 8, len(table))

    def on_drop_ranks(self, machine):
        self.events.append(("drop ranks", self.machine.memory.read(machine.regs[RDI] + 0x10, 8)))

    def on_drop_set(self, machine):
        self.events.append(("drop set", self.machine.memory.read(machine.regs[RDI] + 0x10, 8)))

    def on_drop_map(self, machine):
        self.events.append(("drop map",))

    def on_drop_iter(self, machine):
        self.events.append(("drop map",))

    def on_release(self, machine):
        if machine.regs[RDI] != self.oracle_at:
            raise Halt("release word")
        self.events.append(("release",))

    def on_fill(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != DEX or memory.read(regs[RSP] + 8, 8):
            raise Halt("fill arguments")
        name, price, delta = regs[RDX], signed(regs[RCX]), signed(regs[R8])
        key = memory.bytes_at(regs[R9], 20)
        status = self.case.get("fill_status", {}).get(self.fills, OK)
        self.fills += 1
        self.events.append(("fill", name, price, delta, key, status))
        memory.write(regs[RDI], 2, status)
        if status != OK:
            return
        row = self.rows[key]
        pay = self.case.get("pay", {}).get(key)
        for place, at in tree_items(memory, POSITION_MAP, memory.read(row + 8, 8), memory.read(row + 0x10, 8)):
            if struct.unpack("<Q", place)[0] == name:
                if not self.case.get("fill_quiet"):
                    memory.write(at + 0x10, 8, word_of(signed(memory.read(at + 0x10, 8)) + delta))
                if pay:
                    where = at + 8 if pay[0] else row
                    memory.write(where, 8, word_of(memory.read(where, 8) + pay[1]))
                return
        raise Halt("fill of a missing row")

    def put_account(self, at, row):
        memory = self.machine.memory
        held = row["positions"]

        def put(place, value):
            memory.write(place, 4, value[TAG])
            memory.write(place + 4, 4, value[LEVERAGE])
            memory.write(place + 8, 8, word_of(value[RAW]))
            memory.write(place + 0x10, 8, word_of(value[SIZE]))
            memory.write(place + 0x18, 8, value[WORD18])
            memory.write(place + 0x20, 8, value[WORD20])
            memory.write(place + 0x28, 8, value[WORD28])
            memory.write(place + 0x30, 8, value[WORD30])
            memory.write(place + 0x38, 4, value[WORD38])
            memory.write(place + 0x3C, 4, 0x3C3C)
        root, height = build_tree(memory, self.node, POSITION_MAP, [(word_key(key), held[key]) for key in sorted(held)], put)
        memory.write(at, 8, word_of(row["balance"]))
        memory.write(at + 8, 8, root)
        memory.write(at + 0x10, 8, height)
        memory.write(at + 0x18, 8, len(held))
        memory.write(at + 0x20, 8, row["count"])
        memory.write(at + 0x50, 4, row["tail"])
        return at

    def lay_table(self, case):
        memory = self.machine.memory
        users = case.get("users", {})
        area = self.bump(BUCKETS * ENTRY_STRIDE + BUCKETS + 16)
        ctrl = area + BUCKETS * ENTRY_STRIDE
        memory.put_bytes(ctrl, b"\xff" * (BUCKETS + 16))
        crowd = case.get("crowd", 0)
        used = set()

        def tag(at, value):
            memory.write(ctrl + at, 1, value)
            if at < 16:
                memory.write(ctrl + BUCKETS + at, 1, value)
        for key in sorted(users):
            digest = sip13(HASH_K0, HASH_K1, key)
            start = digest & (BUCKETS - 1)
            top = digest >> 57
            for shift in range(crowd):
                at = (start + shift) % BUCKETS
                if at not in used:
                    used.add(at)
                    tag(at, top ^ 1 if top ^ 1 != 0xFF else 0)
            at = (start + crowd) % BUCKETS
            while at in used:
                at = (at + 1) % BUCKETS
            used.add(at)
            tag(at, top)
            entry = ctrl - ENTRY_STRIDE * (at + 1)
            memory.put_bytes(entry, key)
            row = self.put_account(entry + 0x18, users[key])
            self.rows[key] = row
            self.row_keys[row] = key
        memory.write(DEX + 0xF8, 8, ctrl)
        memory.write(DEX + 0x100, 8, BUCKETS - 1)
        memory.write(DEX + 0x110, 8, len(users))
        memory.write(DEX + 0x118, 8, HASH_K0)
        memory.write(DEX + 0x120, 8, HASH_K1)

    def run_case(self, case):
        machine, memory = self.machine, self.machine.memory
        memory.reset(getattr(self, "dirty", HEAP_SIZE))
        self.dirty = HEAP_SIZE
        self.case = case
        self.at = BUMP
        self.events = []
        self.logs = 0
        self.blocks = {}
        self.rows, self.row_keys, self.row_name = {}, {}, {DEFAULT_ROW: None}
        self.values = {key: list(items) for key, items in case.get("values", {}).items()}
        self.fills, self.turn = 0, 0
        self.held = {}
        markets = case.get("markets", ())
        table = self.bump(max(len(markets), 1) * 0x30)
        for index, market in enumerate(markets):
            memory.write(table + index * 0x30 + 0x18, 4, market.get("word", 0x900 + index))
            memory.write(table + index * 0x30 + 0x28, 1, market.get("flag", 0))
        memory.write(DEX + 8, 8, table)
        memory.write(DEX + 0x10, 8, len(markets))
        memory.write(DEX + 0x30, 8, case.get("dex_id", 0))
        memory.write(DEX + 0x140, 8, 0)
        totals = case.get("totals", {})

        def put_total(at, value):
            memory.write(at, 8, word_of(value))
        root, height = build_tree(memory, self.node, TOTAL_MAP, [(word_key(key), totals[key]) for key in sorted(totals)], put_total)
        memory.write(DEX + 0x170, 8, root)
        memory.write(DEX + 0x178, 8, height)
        memory.write(DEX + 0x180, 8, len(totals))
        memory.write(DEX + 0x248, 8, case.get("word248", 500))
        memory.write(DEX + 0x2EC, 1, case.get("settle", 1))
        self.lay_table(case)
        memory.write(EXCHANGE + 0x38, 8, case.get("counter", 100))
        clock = case.get("clock", (0x1122334455667788, 0x99AABBCC))
        memory.write(EXCHANGE + 0x60, 8, clock[0])
        memory.write(EXCHANGE + 0x68, 4, clock[1])
        oracles = case.get("oracles", (1000, 1000, 1000, 1000))
        data = self.bump(max(len(oracles), 1) * ORACLE_STRIDE)
        for index, oracle in enumerate(oracles):
            memory.write(data + index * ORACLE_STRIDE + 0x20, 8, word_of(oracle))
        self.oracle_at = self.bump(0x18)
        memory.write(self.oracle_at + 8, 8, data)
        memory.write(self.oracle_at + 0x10, 8, len(oracles))
        exempt = sorted(case.get("exempt", ()))
        root, height = build_tree(memory, self.node, EXEMPT_SET, [(key, None) for key in exempt], lambda at, value: None)
        pair = self.bump(0x10)
        memory.write(pair, 8, root)
        memory.write(pair + 8, 8, height)
        out = self.bump(0x40)
        memory.write(STACK_TOP - 0x100, 8, case.get("credit_word", 0x7777))
        memory.write(STACK_TOP - 0xF8, 8, pair)
        self.watch_frame()
        try:
            machine.run(ADL, {RDI: out, RSI: DEX, RDX: 0x5500 | case.get("mode", 0), RCX: EXCHANGE, R8: self.oracle_at, R9: ROUND_SET})
        finally:
            self.dirty = self.at - HEAP_BASE
        final = {}
        for name, at in tree_items(memory, KEY_MAP, memory.read(out, 8), memory.read(out + 8, 8)):
            data, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8)
            final[struct.unpack_from("<Q", name)[0], name[8]] = tuple(self.fill_row(data + index * FILL_STRIDE) for index in range(count))
        return dict(rounds=memory.read(out + 0x18, 8), final=final, held={key: tuple(self.held[key]) for key in self.held}, counter=memory.read(EXCHANGE + 0x38, 8), users=self.users_view(), totals=self.totals_view(), logs=self.logs)

    def watch_frame(self):
        """The key map pointer of the trigger text sits at this stack offset of the frame."""
        self.keys_at = STACK_TOP - 0x100 - 8 - 0x30 - 0x758 + 0x288
        self.held_at = STACK_TOP - 0x100 - 8 - 0x30 - 0x758 + 0x3C8

    def fill_row(self, at):
        memory = self.machine.memory
        fixed = ((0, 1), (0x10, 0), (0x20, 0), (0x48, 0), (0x58, 2), (0x100, 1), (0x110, 0), (0x120, 0), (0x148, 0), (0x158, 2), (0x220, 0))
        for place, want in fixed:
            if memory.read(at + place, 8) != want:
                raise Halt("fill row word %#x" % place)
        if memory.read(at + 0xEC, 1) or memory.read(at + 0x1EC, 1) or memory.read(at + 0xD0, 8) != memory.read(at + 0x1D0, 8):
            raise Halt("fill row side bytes")
        return (signed(memory.read(at + 8, 8)), memory.read(at + 0xD0, 8), memory.bytes_at(at + 0xD8, 20), signed(memory.read(at + 0x108, 8)), memory.bytes_at(at + 0x1D8, 20), signed(memory.read(at + 0x200, 8)), memory.read(at + 0x208, 8),
                memory.read(at + 0x210, 8), memory.read(at + 0x218, 8), (memory.read(at + 0x228, 8), memory.read(at + 0x230, 4)), memory.read(at + 0x234, 1), memory.read(at + 0x238, 8), memory.read(at + 0x240, 8))

    def users_view(self):
        memory = self.machine.memory
        users = {}
        for key in self.case.get("users", {}):
            at = self.rows[key]
            root, height, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)
            items = tree_items(memory, POSITION_MAP, root, height)
            if len(items) != count:
                raise Halt("tree length word")
            held = []
            for name, place in items:
                held.append((struct.unpack("<Q", name)[0], (memory.read(place, 4), memory.read(place + 4, 4), signed(memory.read(place + 8, 8)), signed(memory.read(place + 0x10, 8)), memory.read(place + 0x18, 8), memory.read(place + 0x20, 8),
                                                            memory.read(place + 0x28, 8), memory.read(place + 0x30, 8), memory.read(place + 0x38, 4))))
            users[key] = (signed(memory.read(at, 8)), memory.read(at + 0x20, 8), memory.read(at + 0x50, 4), tuple(held))
        return users

    def totals_view(self):
        memory = self.machine.memory
        return {struct.unpack("<Q", name)[0]: signed(memory.read(at, 8)) for name, at in tree_items(memory, TOTAL_MAP, memory.read(DEX + 0x170, 8), memory.read(DEX + 0x178, 8))}


def show(left, right):
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right), key=repr):
            if left.get(key) != right.get(key):
                return "%r: got %r want %r" % (key, left.get(key), right.get(key))
    return "got %r want %r" % (left, right)


def compare_run(harness, case):
    label = case["label"]
    spec = Spec(case)
    try:
        want = spec.run()
    except Panicked as panic:
        want = dict(panic=str(panic))
    try:
        got = harness.run_case(case)
    except Panicked as panic:
        got = dict(panic=str(panic))
    except Halt as stop:
        return "%s: halt %s after %r" % (label, stop, harness.events[-3:])
    except (EvidenceError, KeyError, IndexError, ValueError, TypeError, struct.error, OverflowError, ZeroDivisionError) as error:
        return "%s: error %r" % (label, error)
    if harness.events != spec.events:
        for at in range(max(len(harness.events), len(spec.events))):
            left = harness.events[at] if at < len(harness.events) else None
            right = spec.events[at] if at < len(spec.events) else None
            if left != right:
                return "%s: event %d got %r want %r" % (label, at, left, right)
    if "panic" in want or "panic" in got:
        if want.get("panic") != got.get("panic"):
            return "%s: panic %r against %r" % (label, want.get("panic"), got.get("panic"))
        return None
    for name in ("rounds", "final", "held", "counter", "users", "totals", "logs"):
        if got[name] != want[name]:
            return "%s: %s %s" % (label, name, show(got[name], want[name]))
    return None


# ---- cases ----

TARGET = address(0x60)
MAKER = address(0x20)
THIRD = address(0x30)
FOURTH = address(0x40, 0xBB)
LOW = address(0x05, 0x11)
HIGH = address(0xF5, 0xE1)
SIXTH = address(0x77, 0x33)
PLAIN = ({}, {}, {}, {})


def cross_case(label, **fields):
    case = dict(label=label, markets=PLAIN, word248=500, rounds=([(0, 0, -5000, TARGET)],), values={TARGET: [-600, 100]},
                users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(-20)})}, ranks=({(1, 0): [(7, MAKER)]},), totals={1: 30})
    case.update(fields)
    return case


def isolated_case(label, **fields):
    case = dict(label=label, markets=({}, {"flag": 1}, {}, {}), word248=500, rounds=([(1, 1, -5000, TARGET)],), values={TARGET: [-600, 100]},
                users={TARGET: account(50, {1: position(10, tag=1, raw=70)}), MAKER: account(9000, {1: position(-20)})}, ranks=({(1, 0): [(7, MAKER)]},), totals={1: 30})
    case.update(fields)
    return case


def many(count, first=0x10):
    return [address(first + at, 0xC0) for at in range(count)]


def scan_cases():
    rows = [(0, 0, 0, key) for key in many(5)]
    wide = many(13)
    return [
        cross_case("no rows", rounds=([],)),
        cross_case("no rows, word 0 takes the flatten", rounds=([],), word248=0),
        cross_case("no users", users={}, rounds=([(0, 0, 0, TARGET)],), values={None: [-9]}, word248=9000, totals={}),
        cross_case("no users, flag row", users={}, rounds=([(1, 1, 0, TARGET)],), values={None: [-9]}, totals={}),
        cross_case("absent user keeps default row", rounds=([(0, 0, 0, FOURTH)],), values={None: [-600]}),
        cross_case("under the word", word248=601, values={TARGET: [-600]}),
        cross_case("at the word", word248=600),
        cross_case("under by one", word248=601, values={TARGET: [-600]}, rounds=([(0, 0, 0, TARGET), (0, 0, 1, TARGET)],), ),
        cross_case("mode 2 has no text", mode=2),
        cross_case("mode 2 under the word", mode=2, word248=601, values={TARGET: [-600]}),
        cross_case("mode 1 reads as mode 0", mode=1),
        cross_case("mode 3 reads as mode 0", mode=3),
        cross_case("positive value adds nothing", values={TARGET: [600]}),
        cross_case("value 0 adds nothing", values={TARGET: [0]}, word248=1),
        cross_case("value -1", values={TARGET: [-1]}, word248=2),
        cross_case("value i64 min panics", values={TARGET: [I64_MIN]}),
        cross_case("value i64 min + 1", values={TARGET: [I64_MIN + 1, 0]}, word248=U64_MAX),
        cross_case("two rows add", values={TARGET: [-300, -300, 0]}, rounds=([(0, 0, 0, TARGET), (0, 1, 0, TARGET)],), word248=600),
        cross_case("total wraps to the top with a log", word248=U64_MAX, values={TARGET: [-I64_MAX, -I64_MAX, -I64_MAX, -I64_MAX]}, rounds=([(0, at, 0, TARGET) for at in range(4)],)),
        cross_case("total at the top without a log", word248=U64_MAX, values={TARGET: [-I64_MAX, -I64_MAX, -1, 0]}, rounds=([(0, at, 0, TARGET) for at in range(3)],)),
        isolated_case("flag market row is immediate", word248=9000),
        isolated_case("flag market row in mode 2", word248=9000, mode=2),
        isolated_case("flag 0 market row, no text", rounds=([(1, 0, 0, TARGET)],), word248=9000),
        isolated_case("flag byte 2", markets=({}, {"flag": 2}), word248=9000),
        isolated_case("wrong dex panics", rounds=([(1, 10001, 0, TARGET)],)),
        isolated_case("dex 1 row", dex_id=1, rounds=([(1, 10001, 0, TARGET)],), users={TARGET: account(50, {10001: position(10, tag=1, raw=70)}), MAKER: account(9000, {10001: position(-20)})}, ranks=({(10001, 0): [(7, MAKER)]},), totals={10001: 30}),
        isolated_case("dex 1 row wrong id", dex_id=1, rounds=([(1, 1, 0, TARGET)],)),
        isolated_case("market past the table panics", rounds=([(1, 4, 0, TARGET)],)),
        isolated_case("market at the last index", rounds=([(1, 3, 0, TARGET)],), users={TARGET: account(50, {3: position(10, tag=1, raw=70)}), MAKER: account(9000, {3: position(-20)})}, ranks=({(3, 0): [(7, MAKER)]},), word248=9000, markets=({}, {}, {}, {"flag": 1})),
        isolated_case("word 0 with high bits acts as 1", rounds=([(0x100000001, 1, 0, TARGET)],), word248=9000),
        cross_case("exempt user is immediate", exempt=[TARGET], word248=9000),
        cross_case("exempt beside the user", exempt=[address(0x5F), address(0x61)], word248=9000),
        cross_case("exempt below the user", exempt=[address(0x5F)], word248=9000),
        cross_case("exempt above the user", exempt=[address(0x61)], word248=9000),
        cross_case("exempt in mode 2", exempt=[TARGET], word248=9000, mode=2),
        cross_case("exempt tree two levels, hit", exempt=sorted(many(30) + [TARGET]), word248=9000),
        cross_case("exempt tree two levels, hit leaf end", exempt=sorted(many(13) + [TARGET]), word248=9000),
        cross_case("exempt tree two levels, miss", exempt=many(30), word248=9000),
        cross_case("exempt tree three levels, miss", exempt=many(140), word248=9000),
        cross_case("exempt tree 8 keys down", exempt=many(40) + [TARGET], word248=9000),
        cross_case("five rows grow the vector", word248=9000, exempt=sorted(row[3] for row in rows), rounds=(rows,), users={row[3]: account(1) for row in rows}, values={}),
        cross_case("thirteen flag rows grow the text list", word248=9000, exempt=wide, rounds=([(0, 0, 0, key) for key in wide],), users={key: account(1) for key in wide}, values={}),
        cross_case("thirteen flag rows in mode 2", word248=9000, mode=2, exempt=wide, rounds=([(0, 0, 0, key) for key in wide],), users={key: account(1) for key in wide}, values={}),
        cross_case("two level row tree", word248=0, rounds=([(0, 0, 0, key) for key in many(13)],), users={key: account(1) for key in many(13)}, values={}),
        cross_case("three level row tree", word248=0, rounds=([(0, 0, 0, key) for key in many(150)],), users={key: account(1) for key in many(150)}, values={}),
        cross_case("eight rows in a leaf walk", word248=0, rounds=([(0, 0, 0, key) for key in many(9)],), users={key: account(1) for key in many(9)}, values={}),
        cross_case("crowded group", crowd=16),
        cross_case("crowded partly", crowd=7),
    ]


def target_cases():
    set_ = {(at, 0): [(7, MAKER)] for at in range(1, 4)}
    set_.update({(at, 1): [(7, THIRD)] for at in range(1, 4)})
    users = {TARGET: account(50, {1: position(10), 2: position(-3), 3: position(4)}), MAKER: account(9000, {1: position(-20), 3: position(-20)}), THIRD: account(9000, {2: position(20)})}
    ids = {at: position(1) for at in range(1, 15)}
    big = {key: [(7, MAKER)] for key in ((at, 0) for at in range(1, 15))}
    long_users = {TARGET: account(50, ids), MAKER: account(9000, {at: position(-40) for at in range(1, 15)})}
    five = many(5, 0x30)
    return [
        cross_case("three rows in id order", users=users, ranks=(set_,), totals={1: 30, 2: 23, 3: 24}),
        cross_case("isolated row is passed over", users={**users, TARGET: account(50, {1: position(10), 2: position(-3, tag=1, raw=5)})}, ranks=(set_,)),
        cross_case("tag 2 row is passed over", users={**users, TARGET: account(50, {1: position(10), 2: position(-3, tag=2)})}, ranks=(set_,)),
        cross_case("tag 1 byte 0 high word", users={**users, TARGET: account(50, {1: position(10), 2: position(-3, tag=0x100)})}, ranks=(set_,)),
        cross_case("zero size row is passed over", users={**users, TARGET: account(50, {1: position(10), 2: position(0)})}, ranks=(set_,)),
        cross_case("all rows pass, no target", users={**users, TARGET: account(50, {2: position(0)})}, ranks=(set_,)),
        cross_case("no rows on the target", users={**users, TARGET: account(50)}, ranks=(set_,)),
        cross_case("no rows, under word, text none", users={**users, TARGET: account(50)}, ranks=(set_,), word248=601, values={TARGET: [-600]}),
        isolated_case("isolated row missing", rounds=([(1, 2, 0, TARGET)],), word248=9000, markets=({}, {}, {"flag": 1}, {})),
        isolated_case("isolated zero size has side 1", users={TARGET: account(50, {1: position(0, tag=1, raw=70)}), MAKER: account(9000, {1: position(-20)})}, ranks=({(1, 1): [(7, MAKER)]},), word248=9000, values={TARGET: [0]}),
        isolated_case("isolated short row", users={TARGET: account(50, {1: position(-10, tag=1, raw=70)}), MAKER: account(9000, {1: position(20)})}, ranks=({(1, 1): [(7, MAKER)]},), word248=9000, values={TARGET: [-1, 0]}),
        isolated_case("isolated row beside others", users={TARGET: account(50, {0: position(3), 1: position(10, tag=1, raw=70), 2: position(3)}), MAKER: account(9000, {1: position(-20)})}, word248=9000),
        cross_case("fourteen ids split the key map", users=long_users, ranks=(big,), totals={}, values={TARGET: [-600, 0]}),
        cross_case("fourteen ids both sides", users={TARGET: account(50, {at: position(1 if at % 2 else -1) for at in range(1, 15)}), MAKER: account(9000, {at: position(-40 if at % 2 else 40) for at in range(1, 15)})}, ranks=({(at, 0 if at % 2 else 1): [(7, MAKER)] for at in range(1, 15)},), totals={}, values={TARGET: [-600, 0]}),
        cross_case("five users on one key", rounds=([(0, 0, 0, key) for key in five],), word248=0, users={**{key: account(5, {1: position(2)}) for key in five}, MAKER: account(9000, {1: position(-40)})}, values={}, ranks=({(1, 0): [(7, MAKER)]},), totals={1: 50}),
        cross_case("row word 2 ends the list", rounds=([(0, 0, 0, TARGET), (2, 0, 0, THIRD), (0, 0, 0, FOURTH)],), word248=0, users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {1: position(3)}), FOURTH: account(5, {1: position(3)}), MAKER: account(9000, {1: position(-40)})}, values={}, ranks=({(1, 0): [(7, MAKER)]},)),
    ]


def walk_cases():
    two = {TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(-4)}), THIRD: account(9000, {1: position(-20)})}
    short = {TARGET: account(50, {1: position(-10)}), MAKER: account(9000, {1: position(30)})}
    ranks = {(1, 0): [(3, THIRD), (7, MAKER)]}
    thirteen = many(13, 0x50)
    return [
        cross_case("first candidate takes part", users=two, ranks=(ranks,)),
        cross_case("candidate bigger", ),
        cross_case("candidate equal", users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(-10)})}),
        cross_case("rank order, high rank first", users=two, ranks=({(1, 0): [(9, THIRD), (7, MAKER)]},)),
        cross_case("candidate same side grows", users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(4)}), THIRD: account(1, {1: position(-40)})}, ranks=(ranks,)),
        cross_case("short target", users=short, ranks=({(1, 1): [(7, MAKER)]},)),
        cross_case("candidate without the id", users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {2: position(-4)}), THIRD: account(9000, {1: position(-20)})}, ranks=(ranks,)),
        cross_case("candidate with zero size", users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(0)}), THIRD: account(9000, {1: position(-20)})}, ranks=(ranks,)),
        cross_case("candidate absent", users={TARGET: account(50, {1: position(10)}), THIRD: account(9000, {1: position(-20)})}, ranks=(ranks,)),
        cross_case("candidate in a tree with rows, id above", users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {5: position(-4)}), THIRD: account(9000, {1: position(-20), 0: position(5)})}, ranks=(ranks,)),
        cross_case("no key panics", ranks=({},)),
        cross_case("other key only panics", ranks=({(1, 1): [(7, MAKER)]},)),
        cross_case("set runs out panics", ranks=({(1, 0): [(7, THIRD)]},), users={TARGET: account(50, {1: position(10)}), THIRD: account(9000, {1: position(-4)})}),
        cross_case("set of a dead row runs out", ranks=({(1, 0): [(7, THIRD)]},), users={TARGET: account(50, {1: position(10)}), THIRD: account(9000)}),
        cross_case("empty set panics", ranks=({(1, 0): []},)),
        cross_case("spare key is dropped", ranks=({(1, 0): [(7, MAKER)], (2, 1): [(7, MAKER)]},)),
        cross_case("spare key below", ranks=({(1, 0): [(7, MAKER)], (0, 1): [(7, MAKER)]},)),
        cross_case("spare candidates dropped", ranks=({(1, 0): [(2, THIRD), (7, MAKER)]},)),
        cross_case("thirteen candidates walk the tree", users={**{key: account(5, {1: position(-1)}) for key in thirteen}, TARGET: account(50, {1: position(10)})}, ranks=({(1, 0): [(index, key) for index, key in enumerate(thirteen)]},)),
        cross_case("thirteen candidates all taken", users={**{key: account(5, {1: position(-1)}) for key in thirteen}, TARGET: account(50, {1: position(13)})}, ranks=({(1, 0): [(index, key) for index, key in enumerate(thirteen)]},)),
        cross_case("forty candidates walk two levels", users={**{key: account(5, {1: position(-1)}) for key in many(40, 0x60)}, TARGET: account(50, {1: position(39)})}, ranks=({(1, 0): [(index, key) for index, key in enumerate(many(40, 0x60))]},)),
        cross_case("two targets share a candidate", rounds=([(0, 0, 0, TARGET), (0, 0, 0, THIRD)],), word248=0, users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {1: position(5)}), MAKER: account(9000, {1: position(-40)})}, values={}),
        cross_case("oracle past the table panics", oracles=(5,)),
        cross_case("oracle at the last index", oracles=(5, 6)),
        cross_case("settle off: counter runs, no fills", settle=0, users=two, ranks=(ranks,)),
        cross_case("settle 2 reads as off", settle=2),
        cross_case("settle off rows are dropped", settle=0, word248=0),
        cross_case("counter at the top", counter=U64_MAX, ),
        cross_case("counter at the top - 1", counter=U64_MAX - 1, users=two, ranks=(ranks,)),
        cross_case("first fill refused", fill_status={0: 3}),
        cross_case("second fill refused", fill_status={1: 3}),
        cross_case("status 0x186 high byte", fill_status={0: 0x286}),
        cross_case("status 0x186 low byte", fill_status={1: 0x187}),
        cross_case("notional at the top", oracles=(1, (I64_MAX - 1) // 10), users={TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(-20)})}, values={TARGET: [-600, 0]}),
        cross_case("notional over the top", oracles=(1, I64_MAX // 10 + 1), values={TARGET: [-600, 0]}),
        cross_case("notional one over", oracles=(1, I64_MAX), users={TARGET: account(50, {1: position(1)}), MAKER: account(9000, {1: position(-20)})}, values={TARGET: [-600, 0]}),
        cross_case("notional one under", oracles=(1, I64_MAX - 1), users={TARGET: account(50, {1: position(1)}), MAKER: account(9000, {1: position(-20)})}, values={TARGET: [-600, 0]}),
        cross_case("notional mul overflow", oracles=(1, 1 << 62), values={TARGET: [-600, 0]}, users={TARGET: account(50, {1: position(8)}), MAKER: account(9000, {1: position(-20)})}),
        cross_case("negative oracle", oracles=(1, -5)),
        cross_case("target i64 min, bigger candidate cannot be", users={TARGET: account(50, {1: position(I64_MIN)}), MAKER: account(9000, {1: position(I64_MIN)})}, ranks=({(1, 1): [(7, MAKER)]},), totals={}),
        cross_case("candidate i64 min", users={TARGET: account(50, {1: position(5)}), MAKER: account(9000, {1: position(I64_MIN)})}),
        cross_case("target i64 min against small", users={TARGET: account(50, {1: position(I64_MIN)}), MAKER: account(9000, {1: position(5)}), THIRD: account(9000)}, ranks=({(1, 1): [(7, MAKER)]},)),
        cross_case("target max against i64 min", users={TARGET: account(50, {1: position(I64_MAX)}), MAKER: account(9000, {1: position(I64_MIN)})}),
    ]


def margin_cases():
    row = lambda tag=1, raw=70, size=10: account(50, {1: position(size, tag=tag, raw=raw)})
    maker = account(9000, {1: position(-20)})
    tagged = {TARGET: account(50, {1: position(10, tag=1, raw=70)}), MAKER: maker}
    return [
        isolated_case("isolated moves value + margin", word248=9000),
        isolated_case("isolated zero value and margin moves nothing", users={TARGET: row(raw=-10000), MAKER: maker}, word248=9000),
        isolated_case("isolated value + margin -1", users={TARGET: row(raw=-10001), MAKER: maker}, word248=9000),
        isolated_case("isolated value + margin 1", users={TARGET: row(raw=-9999), MAKER: maker}, word248=9000),
        isolated_case("isolated odd tag 3", users={TARGET: row(tag=3), MAKER: maker}, word248=9000),
        isolated_case("isolated even tag panics", users={TARGET: row(tag=2), MAKER: maker}, word248=9000),
        isolated_case("isolated negative oracle panics", oracles=(1, -1), word248=9000),
        isolated_case("isolated oracle product overflows", oracles=(1, 1 << 61), word248=9000),
        isolated_case("isolated product at the edge", oracles=(1, I64_MAX // 10), users={TARGET: row(raw=0), MAKER: maker}, word248=9000),
        isolated_case("isolated short product", users={TARGET: row(size=-10), MAKER: account(9000, {1: position(20)})}, ranks=({(1, 1): [(7, MAKER)]},), word248=9000),
        isolated_case("isolated sum saturates up", oracles=(1, I64_MAX // 10), users={TARGET: row(raw=I64_MAX), MAKER: maker}, word248=9000),
        isolated_case("isolated sum saturates down", oracles=(1, I64_MAX // 10), users={TARGET: row(size=-10, raw=I64_MIN), MAKER: account(9000, {1: position(20)})}, ranks=({(1, 1): [(7, MAKER)]},), word248=9000),
        isolated_case("margin word saturates on the way out", users={TARGET: account(50, {1: position(10, tag=1, raw=-I64_MAX + 1000)}), MAKER: maker}, oracles=(1, I64_MAX // 10), word248=9000),
        isolated_case("id missing from the totals", totals={}, word248=9000),
        isolated_case("id missing from a full total tree", totals={at: 4 for at in range(20, 40)}, word248=9000),
        isolated_case("total below id", totals={0: 4, 2: 5}, word248=9000),
        isolated_case("total saturates low", totals={1: I64_MIN + 3}, word248=9000),
        isolated_case("total saturates high", totals={1: I64_MAX - 3}, word248=9000),
        isolated_case("total tree two levels", totals={at: 4 for at in range(0, 30)}, word248=9000),
        isolated_case("size i64 min panics", users={TARGET: row(size=I64_MIN, raw=-5), MAKER: account(9000, {1: position(I64_MAX)})}, oracles=(1, 0), ranks=({(1, 1): [(7, MAKER)]},), word248=9000),
        cross_case("word 3 row reads the summary", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}),
        cross_case("word 3 row with tag", rounds=([(3, 1, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, users={TARGET: account(50, {1: position(10, tag=1, raw=0)}), MAKER: maker}, oracles=(1, 2)),
        cross_case("summary equal words", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (200, 200)}),
        cross_case("summary one over", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (201, 200)}),
        cross_case("summary below", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (100, 200)}),
        cross_case("summary word 1 negative panics", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (100, -1)}),
        cross_case("summary difference saturates", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (I64_MIN, 5)}),
        cross_case("summary difference saturates high", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (I64_MAX, 0)}),
        cross_case("balance saturates on the way back", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (I64_MAX, 0)}, users={TARGET: account(I64_MAX, {1: position(10)}), MAKER: maker}),
        cross_case("balance saturates on the way out", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (I64_MAX, 0)}, users={TARGET: account(-5, {1: position(10)}), MAKER: maker}),
        cross_case("word 0x100 row", rounds=([(0x100, 0, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, values={TARGET: [-600, 9, 0]}),
        cross_case("word 1 << 32 row", rounds=([(1 << 32, 0, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, values={TARGET: [-600, 9, 0]}),
    ]


def sweep_cases():
    maker = account(9000, {1: position(-20)})
    held = account(50, {1: position(10, tag=1, raw=70), 2: position(4)})
    return [
        cross_case("sweep moves value to fees", values={TARGET: [-600, 40]}),
        cross_case("sweep nothing at value 0", values={TARGET: [-600, 0]}),
        cross_case("sweep at value 1", values={TARGET: [-600, 1]}),
        cross_case("sweep negative value", values={TARGET: [-600, -1]}),
        cross_case("floor keeps the text off", rounds=([(0, 0, 40, TARGET)],), values={TARGET: [-600, 40]}, word248=500),
        cross_case("floor by one", rounds=([(0, 0, 41, TARGET)],), values={TARGET: [-600, 40]}, word248=500),
        cross_case("floor signed", rounds=([(0, 0, -1, TARGET)],), values={TARGET: [-600, -2]}, word248=500),
        cross_case("floor signed equal", rounds=([(0, 0, -1, TARGET)],), values={TARGET: [-600, -1]}, word248=500),
        cross_case("floor signed against positive", rounds=([(0, 0, -1, TARGET)],), values={TARGET: [-600, 1]}, word248=500),
        cross_case("target keeps a row after the walk", ranks=({(1, 0): [(7, MAKER)]},), users={TARGET: account(50, {1: position(10), 2: position(5, tag=1)}), MAKER: maker}),
        cross_case("cross left size in text", settle=1, users={TARGET: account(50, {1: position(10), 2: position(5)}), MAKER: account(1, {1: position(-20), 2: position(-1)})}, ranks=({(1, 0): [(7, MAKER)], (2, 0): [(7, MAKER), (3, THIRD)]},), fill_quiet=True),
        isolated_case("isolated sweep", word248=9000, values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep value 0", word248=9000, values={TARGET: [-600, 0]}),
        isolated_case("isolated sweep beside another row", word248=9000, users={TARGET: held, MAKER: maker}, values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep on the zero row, tag 0 panics", word248=9000, users={TARGET: account(50, {1: position(0)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep on the zero row", word248=9000, users={TARGET: account(50, {1: position(0, tag=1, raw=9)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep tag byte 2", word248=9000, users={TARGET: account(50, {1: position(0, tag=2, raw=9)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep tag high byte", word248=9000, users={TARGET: account(50, {1: position(0, tag=0x100, raw=9)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep saturates", word248=9000, users={TARGET: account(50, {1: position(0, tag=1, raw=I64_MIN)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}),
        isolated_case("isolated sweep totals", word248=9000, users={TARGET: account(50, {1: position(0, tag=1, raw=3)}), MAKER: maker}, ranks=({(1, 1): []},), values={TARGET: [-600, 25]}, totals={}),
        cross_case("cross sweep saturates", values={TARGET: [-600, 25]}, users={TARGET: account(I64_MIN, {1: position(10)}), MAKER: maker}),
        cross_case("word 3 row sweeps the balance", rounds=([(3, 0, 0, TARGET)],), word248=0, values={TARGET: [-600, 25, 0]}),
        cross_case("word 0x100 row reads low byte as cross", rounds=([(0x100, 0, 0, TARGET)],), word248=0, values={TARGET: [-600, 25, 0]}),
        cross_case("word 0x101 low byte, no flag", rounds=([(0x101, 2, 0, TARGET)],), word248=0, values={TARGET: [-600, 25, 0]}),
        cross_case("sweep count zero", values={TARGET: [-600, 25]}, users={TARGET: account(50, {1: position(10)}, count=0), MAKER: maker}),
        cross_case("sweep count two", values={TARGET: [-600, 25]}, users={TARGET: account(50, {1: position(10)}, count=2), MAKER: maker}),
    ]


def round_cases():
    two = {TARGET: account(50, {1: position(10)}), MAKER: account(9000, {1: position(-20)})}
    many_keys = {TARGET: account(50, {at: position(1) for at in range(1, 15)}), MAKER: account(9000, {at: position(-40) for at in range(1, 15)})}
    wide = {(at, 0): [(7, MAKER)] for at in range(1, 15)}
    six = many(6, 0x70)
    return [
        cross_case("second round sees nothing", rounds=([(0, 0, 0, TARGET)], []), ranks=({(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0]}),
        cross_case("second round drops a map", rounds=([(0, 0, 0, TARGET)], []), word248=601, exempt=[TARGET], ranks=({(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0]}),
        cross_case("three rounds", rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, THIRD)], []), users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {1: position(2)}), MAKER: account(9000, {1: position(-20)})}, ranks=({(1, 0): [(7, MAKER)]}, {(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0], THIRD: [-600, 0]}),
        cross_case("rounds on two keys", rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, THIRD)], []), users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {2: position(-2)}), MAKER: account(9000, {1: position(-20), 2: position(20)})}, ranks=({(1, 0): [(7, MAKER)]}, {(2, 1): [(7, MAKER)]}, {}), values={TARGET: [-600, 0], THIRD: [-600, 0]}),
        cross_case("rounds on keys in falling order", rounds=([(0, 0, 0, THIRD)], [(0, 0, 0, TARGET)], []), users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {2: position(-2)}), MAKER: account(9000, {1: position(-20), 2: position(20)})}, ranks=({(2, 1): [(7, MAKER)]}, {(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0], THIRD: [-600, 0]}),
        cross_case("same key, same id, other side", rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, THIRD)], []), users={TARGET: account(50, {1: position(10)}), THIRD: account(5, {1: position(-2)}), MAKER: account(9000, {1: position(-20), 2: position(20)}), FOURTH: account(5, {1: position(30)})}, ranks=({(1, 0): [(7, MAKER)]}, {(1, 1): [(7, FOURTH)]}, {}), values={TARGET: [-600, 0], THIRD: [-600, 0]}),
        cross_case("rows beyond one fill grow the list", users={**{key: account(5, {1: position(-1)}) for key in six}, TARGET: account(50, {1: position(6)})}, ranks=({(1, 0): [(index, key) for index, key in enumerate(six)]},)),
        cross_case("merge grows the final list", rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, THIRD)], [(0, 0, 0, FOURTH)], [(0, 0, 0, LOW)], [(0, 0, 0, HIGH)], [(0, 0, 0, SIXTH)], []), word248=0,
                   users={key: account(5, {1: position(1)}) for key in (TARGET, THIRD, FOURTH, LOW, HIGH, SIXTH)} | {MAKER: account(9000, {1: position(-20)})}, ranks=({(1, 0): [(7, MAKER)]},), values={}),
        cross_case("round after keys split", users=many_keys, ranks=(wide,), rounds=([(0, 0, 0, TARGET)], []), values={TARGET: [-600, 0]}),
        cross_case("settle off exits in one round", settle=0, rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, THIRD)])),
        cross_case("mode 2 rounds", mode=2, rounds=([(0, 0, 0, TARGET)], []), ranks=({(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0]}),
        cross_case("whole map second round under", rounds=([(0, 0, 0, TARGET)], [(0, 0, 0, TARGET)], []), word248=500, values={TARGET: [-600, 0, -100, 0]}, ranks=({(1, 0): [(7, MAKER)]}, {}), users=two),
        cross_case("clock bytes", clock=(0xF0E0D0C0B0A09080, 0x01020304)),
    ]


def tall(count=20, skip=(), **fields):
    return {at: position(**fields) for at in range(40, 40 + count) if at not in skip}


def depth_cases():
    maker = account(9000, {1: position(-20)})
    markets = tuple({"flag": 1} for _ in range(60))
    prices = tuple(10 + at for at in range(60))
    rows = [(1, at, 0, TARGET) for at in range(40, 54)]
    book = {at: position(-30) for at in range(40, 54)}
    keys = {(at, 0): [(7, MAKER)] for at in range(40, 54)}
    tall_target = {**tall(40, size=0), 1: position(10), 90: position(0)}
    dead = many(40, 0x60)
    return [
        cross_case("flag row then whole map frees the first list", exempt=[TARGET], rounds=([(0, 0, 0, TARGET), (0, 1, 0, THIRD)],), users={TARGET: account(50, {1: position(10)}), THIRD: account(1), MAKER: maker}, values={THIRD: [-600, 0], TARGET: [-1, 0]}),
        cross_case("no users, word 0, rows listed", users={}, rounds=([(0, 0, 0, TARGET)],), values={}, word248=0, totals={}),
        cross_case("no users, word 0, flag word row", users={}, rounds=([(1, 1, 0, TARGET)],), values={}, word248=0, totals={}),
        cross_case("target tree three levels", users={TARGET: account(50, tall_target), MAKER: maker}),
        cross_case("target tree two levels, sizes", users={TARGET: account(50, {**tall(14, size=0), 45: position(5)}), MAKER: account(9000, {45: position(-20)})}, ranks=({(45, 0): [(7, MAKER)]},)),
        isolated_case("isolated hit in a tall tree", rounds=([(1, 47, 0, TARGET)],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, tall(30, size=1, tag=1, raw=5)), MAKER: account(9000, tall(30, size=-5))}, ranks=({(47, 0): [(7, MAKER)]},), totals={}),
        isolated_case("isolated miss in a tall tree", rounds=([(1, 39, 0, TARGET)],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, tall(30, size=1, tag=1)), MAKER: maker}),
        isolated_case("isolated miss between keys", rounds=([(1, 47, 0, TARGET)],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, tall(30, skip=(47,), size=1, tag=1)), MAKER: maker}),
        isolated_case("isolated miss above", rounds=([(1, 59, 0, TARGET)],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, tall(12, size=1, tag=1)), MAKER: maker}),
        isolated_case("fourteen isolated rows", rounds=(rows,), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, {at: position(2, tag=1, raw=3) for at in range(40, 54)}), MAKER: account(9000, book)}, ranks=(keys,), totals={}, values={}),
        isolated_case("fourteen isolated rows, falling", rounds=(rows[::-1],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, {at: position(2, tag=1, raw=3) for at in range(40, 54)}), MAKER: account(9000, book)}, ranks=(keys,), totals={}, values={}),
        isolated_case("candidate tree tall", rounds=([(1, 47, 0, TARGET)],), markets=markets, oracles=prices, word248=9000, users={TARGET: account(50, {47: position(1, tag=1, raw=5)}), MAKER: account(9000, tall(30, size=-5))}, ranks=({(47, 0): [(7, MAKER)]},)),
        cross_case("candidate tall, id missing", users={TARGET: account(50, {47: position(5)}), MAKER: account(9000, tall(30, skip=(47,), size=-5)), THIRD: account(9, {47: position(-5)})}, ranks=({(47, 0): [(3, THIRD), (7, MAKER)]},), oracles=prices),
        cross_case("candidate tall, id above", users={TARGET: account(50, {80: position(5)}), MAKER: account(9000, tall(30, size=-5)), THIRD: account(9, {80: position(-5)})}, ranks=({(80, 0): [(3, THIRD), (7, MAKER)]},), oracles=tuple(range(90))),
        cross_case("forty dead candidates", oracles=(1, 2), users={**{key: account(5) for key in dead}, TARGET: account(50, {1: position(1)}), THIRD: account(5, {1: position(-5)})}, ranks=({(1, 0): [(0, THIRD)] + [(index + 1, key) for index, key in enumerate(dead)]},)),
        cross_case("forty zero candidates", users={**{key: account(5, {1: position(0)}) for key in dead}, TARGET: account(50, {1: position(1)}), THIRD: account(5, {1: position(-5)})}, ranks=({(1, 0): [(0, THIRD)] + [(index + 1, key) for index, key in enumerate(dead)]},)),
        cross_case("thirteen dead candidates", users={**{key: account(5) for key in many(13, 0x60)}, TARGET: account(50, {1: position(1)}), THIRD: account(5, {1: position(-5)})}, ranks=({(1, 0): [(0, THIRD)] + [(index + 1, key) for index, key in enumerate(many(13, 0x60))]},)),
        cross_case("hundred fifty candidates all taken", users={**{key: account(5, {1: position(-1)}) for key in many(150, 0x60)}, TARGET: account(50, {1: position(150)})}, ranks=({(1, 0): [(index, key) for index, key in enumerate(many(150, 0x60))]},)),
        cross_case("thirty candidates, ninety ranks", users={**{key: account(5, {1: position(-1)}) for key in many(30, 0x60)}, TARGET: account(50, {1: position(29)})}, ranks=({(1, 0): [(index * 3, key) for index, key in enumerate(many(30, 0x60))]},)),
        cross_case("word 3 row on a tall tree", rounds=([(3, 47, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, users={TARGET: account(50, tall(30, size=2)), MAKER: account(9000, tall(30, size=-5))}, ranks=({(at, 0): [(7, MAKER)] for at in range(40, 70)},), totals={}, values={}, oracles=tuple(range(90))),
        cross_case("final text cross", fill_quiet=True, rounds=([(0, 0, 0, TARGET)], []), users={TARGET: account(50, {1: position(10), 2: position(-4)}), MAKER: account(9000, {1: position(-20), 2: position(20)})}, ranks=({(1, 0): [(7, MAKER)], (2, 1): [(7, MAKER)]}, {}), values={TARGET: [-600, 0]}),
        cross_case("final text cross over tags", fill_quiet=True, rounds=([(0, 0, 0, TARGET)], []), users={TARGET: account(50, {1: position(10), 2: position(-4, tag=1), 3: position(0)}), MAKER: maker}, ranks=({(1, 0): [(7, MAKER)]}, {}), values={TARGET: [-600, 0]}),
        cross_case("final text cross on a tall tree", fill_quiet=True, rounds=([(0, 0, 0, TARGET)], []), users={TARGET: account(50, tall(40, size=1)), MAKER: account(9000, tall(40, size=-5))}, ranks=({(at, 0): [(7, MAKER)] for at in range(40, 80)}, {}), values={TARGET: [-600, 0]}, oracles=tuple(range(100)), totals={}),
        cross_case("final text cross on 8 keys", fill_quiet=True, rounds=([(0, 0, 0, TARGET)], []), users={TARGET: account(50, tall(13, size=1)), MAKER: account(9000, tall(13, size=-5))}, ranks=({(at, 0): [(7, MAKER)] for at in range(40, 53)}, {}), values={TARGET: [-600, 0]}, oracles=tuple(range(100)), totals={}),
        isolated_case("final text isolated", fill_quiet=True, word248=9000, rounds=([(1, 1, 0, TARGET)], []), ranks=({(1, 0): [(7, MAKER)]}, {})),
        isolated_case("final text isolated, tall tree", fill_quiet=True, word248=9000, rounds=([(1, 47, 0, TARGET)], []), markets=markets, oracles=prices, users={TARGET: account(50, tall(30, size=1, tag=1, raw=5)), MAKER: account(9000, tall(30, size=-5))}, ranks=({(47, 0): [(7, MAKER)]}, {}), totals={}),
        isolated_case("final text isolated, miss between", word248=9000, rounds=([(1, 47, 0, TARGET)],), markets=markets, oracles=prices, users={TARGET: account(50, tall(30, skip=(47,), size=1, tag=1)), MAKER: maker}, values={TARGET: [-1, 0]}),
        isolated_case("sweep on a tall tree", word248=9000, rounds=([(1, 47, 0, TARGET)], []), markets=markets, oracles=prices, users={TARGET: account(50, tall(30, size=1, tag=1, raw=5)), MAKER: account(9000, tall(30, size=-5))}, ranks=({(47, 0): [(7, MAKER)]}, {}), values={TARGET: [-1, 30]}, totals={}),
        isolated_case("sweep makes a default row, tag 0 panics", word248=9000, users={TARGET: account(50, {2: position(1)}), MAKER: maker}, values={TARGET: [-600, 25]}),
        isolated_case("sweep makes a default row", word248=9000, users={TARGET: account(50, {2: position(1)}), MAKER: maker}, values={TARGET: [-600, 25]}, defaults={1: (1, 4, 9)}),
        isolated_case("sweep default row on an empty tree", word248=9000, users={TARGET: account(50), MAKER: maker}, values={TARGET: [-600, 25]}, defaults={1: (1, 4, 9)}),
        isolated_case("sweep absent user", word248=9000, users={MAKER: maker}, values={None: [-600], TARGET: [25]}, defaults={1: (1, 4, 9)}),
        cross_case("sweep absent cross user", word248=0, users={MAKER: maker}, values={None: [-600], TARGET: [25]}),
        cross_case("balance over on the way back", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, users={TARGET: account(I64_MAX, {1: position(10)}), MAKER: maker}, pay={TARGET: (0, 650)}),
        cross_case("balance wraps low on the way back", rounds=([(3, 0, 0, TARGET)],), word248=0, summary={TARGET: (900, 200)}, users={TARGET: account(50, {1: position(10)}), MAKER: maker}, pay={TARGET: (0, I64_MAX)}),
        isolated_case("margin over on the way back", word248=9000, pay={TARGET: (1, I64_MAX - 5)}),
        cross_case("same side overflows the running size", users={TARGET: account(50, {1: position(I64_MAX)}), MAKER: account(9000, {1: position(5)}), THIRD: account(9000, {1: position(-1)})}, ranks=({(1, 0): [(3, THIRD), (7, MAKER)]},)),
        cross_case("same side overflows low", users={TARGET: account(50, {1: position(I64_MIN + 1)}), MAKER: account(9000, {1: position(-5)}), THIRD: account(9000, {1: position(1)})}, ranks=({(1, 1): [(3, THIRD), (7, MAKER)]},)),
        isolated_case("total low on the way back", word248=9000, users={TARGET: account(50, {1: position(2, tag=1, raw=70)}), MAKER: account(9000, {1: position(4)}), THIRD: account(9000, {1: position(-6)})}, ranks=({(1, 0): [(3, THIRD), (7, MAKER)]},), totals={1: I64_MIN + 3}),
        isolated_case("size min on the way back", word248=9000, users={TARGET: account(50, {1: position(2, tag=1, raw=70)}), MAKER: account(9000, {1: position(I64_MIN + 2)}), THIRD: account(9000, {1: position(-6)})}, ranks=({(1, 1): [(3, THIRD), (7, MAKER)]},), oracles=(1, 0)),
        isolated_case("total saturates low on the way back", word248=9000, users={TARGET: account(50, {1: position(5, tag=1, raw=70)}), MAKER: account(9000, {1: position(4)}), THIRD: account(9000, {1: position(-20)})}, ranks=({(1, 0): [(3, THIRD), (7, MAKER)]},), totals={1: I64_MIN + 3}),
        cross_case("settle off, no rows", settle=0, rounds=([],)),
        cross_case("settle off, no target", settle=0, word248=1, values={TARGET: [-1]}, users={TARGET: account(50), MAKER: maker}),
        cross_case("no fills, one list row", values={TARGET: [-600, 0]}, users={TARGET: account(5), MAKER: maker}, rounds=([(0, 0, 0, TARGET)],), ranks=({},)),
        cross_case("flag row, no target, under word", exempt=[TARGET], word248=9000, users={TARGET: account(5), MAKER: maker}, ranks=({},)),
    ]


def all_cases():
    return scan_cases() + target_cases() + walk_cases() + margin_cases() + sweep_cases() + round_cases() + depth_cases()


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x3bc3b00, 0x3bc4080", "parallel build of the row map from the address set; set pointer, user map, dex and oracle pointers checked, rows of 0x30 given per round"),
    ("0x3baca10", "row map to a vector; iterator words checked, the given rows returned in map order"),
    ("0x33c58e0", "candidate collection for the (id, side) keys; 5 words checked, key list recorded, sets given per round"),
    ("0x37d77e0", "account value; 6 arguments checked, word given by the case. Held by open #950"),
    ("0x37d79e0", "account summary; 5 arguments checked, words 0 and 1 given"),
    ("0x36fe830", "fill of one side; dex, id, price, signed size, address and last argument checked, status given; size applied to the row so that the walk and rounds see it"),
    ("0x37067b0", "fee credit; dex, 0, amount and the outer argument checked"),
    ("0x36f57f0, 0x3596940", "account read and entry; map pointer and key checked"),
    ("0x339b590", "address set add; pointers +0x188, the round set and each value of the id map told apart"),
    ("0x399c7a0", "address hash; hasher pointer checked, SipHash 1-3 of the key so that the inline finish in the body must agree"),
    ("0x3bfffd0", "default margin of an id; id and dex checked, 16 bytes given"),
    ("0x33f1980, 0x33f3fc0, 0x33fcb30, 0x33ae610, 0x33f3150, 0x37646d0", "drops; count words read and call order recorded"),
    ("0x1344760", "text format; text address and every argument read back, the string freed by the body"),
)
REAL_HELPERS = (("0x33100d0", "key walk of the (id, side) map"), ("0x33ae240", "owning walk of the (id, side) map"), ("0x33ad470, 0x2fdc550", "remove of a key from the candidate map"), ("0x2fdad90", "remove of a candidate"), ("0x33bb3e0, 0x33bb000, 0x33bb960", "map entry inserts"),
                ("0x2fdd500", "(id, side) search"), ("0x33bc4d0, 0x33bd420, 0x36f7350", "total entry, position entry, total update"), ("0x3a00700", "SipHash write"), ("0x2f8d190, 0x2f0e3d0, 0x2f24930, 0x2f18f20, 0x2fccfa0, 0x2f53670, 0x2fcefa0, 0x2fa4c50, 0x2faf3b0, 0x2faa750", "node inserts, splits and rebalance"))
COLD = "not stepped by any case: lazy init, allocation failure, unwind or the 8 step unrolled part of a tree walk"
SAME_ROW = "the target row was read earlier in this step and is the row the entry returns, so the default row arm cannot run"
SAME_SIZE = "size and leverage do not change between the read and this compare, so the active count, set and leverage note arms cannot run"
NO_USERS = "a target needs a row, so the empty user map arm cannot run here"
SENTINEL = "the map value is a vector whose capacity is never i64::MIN, so the early end of the walk cannot run"
TOTAL_FIRST = "the first half of the move has already made the total entry, so the second half always finds it"
REASONS = {}
for _start, _end, _text in ((0x36FA962, 0x36FAB50, SAME_ROW), (0x36FB2DF, 0x36FBA23, SAME_ROW), (0x36FABD8, 0x36FAC0B, SAME_SIZE), (0x36FBAA4, 0x36FBACF, SAME_SIZE), (0x36FADBE, 0x36FAF7B, SAME_SIZE), (0x36FBCA3, 0x36FBE60, SAME_SIZE), (0x36FAF92, 0x36FAFDF, SAME_SIZE),
                            (0x36FBE77, 0x36FBEC4, SAME_SIZE), (0x36FD071, 0x36FD0A2, SAME_SIZE), (0x36FD0C1, 0x36FD0DB, SAME_SIZE), (0x36FD161, 0x36FD180, SAME_SIZE), (0x36F9955, 0x36F9972, NO_USERS), (0x36F9E35, 0x36F9E45, NO_USERS), (0x36FA64F, 0x36FA653, NO_USERS),
                            (0x36FC6F1, 0x36FC75F, SENTINEL), (0x36FD7BA, 0x36FD812, SENTINEL), (0x36FBB7D, 0x36FBC30, TOTAL_FIRST), (0x36FC378, 0x36FC40B, TOTAL_FIRST)):
    for _at in range(_start, _end):
        REASONS[_at] = _text


def rows_of(image, start):
    begin, end = image.exact_fde(start)
    return decode_range(image, begin, end)


def groups(image):
    return [("core", *image.exact_fde(ADL)), ("key remove", *image.exact_fde(0x33AD470)), ("total update", *image.exact_fde(0x36F7350)), ("id map entry", *image.exact_fde(0x33BB3E0)), ("key map entry", *image.exact_fde(0x33BB000)), ("final map entry", *image.exact_fde(0x33BB960))]


CONSTANT_SITES = (
    ("id divisor 10000 by the /10000 magic", 0x36F8336, b"\x48\xba\x4b\x59\x86\x38\xd6\xc5\x6d\x34", 0x346DC5D63886594B),
    ("row word 0 that means a single market row", 0x36F8326, b"\x83\x3e\x01", 1),
    ("list end word", 0x36F97FC, b"\x48\x83\xf8\x02", ROW_END),
    ("mode that builds no text", 0x36F8386, b"\x80\xbc\x24\x04\x03\x00\x00\x02", 2),
    ("dex byte that turns settlement on", 0x36FA3C4, b"\x80\xb8\xec\x02\x00\x00\x01", 1),
    ("fill row stride", 0x36FC1B5, b"\x49\x69\xce\x48\x02\x00\x00", FILL_STRIDE),
    ("fill status ok", 0x36FB17D, b"\x66\x81\xbc\x24\x90\x00\x00\x00\x86\x01", OK),
    ("round limit", 0x36FD935, b"\x3d\xff\xff\xff\x7f", 0x7FFFFFFF),
)
SHORTFALL_WORD = (0x36F86D9, b"\x48\x8b\x8c\x24\x00\x05\x00\x00", 0x36F7CCD, b"\x48\x8d\x96\x48\x02\x00\x00")
TEXT_SITES = ((0x36F83D5, "immediate"), (0x36F92EB, "trigger"), (0x36F936A, "none"), (0x36FC967, "balance"), (0x36FCD63, "final cross"), (0x36FCE60, "final"))


def constants(image):
    rows = []
    for name, va, pattern, value in CONSTANT_SITES:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(pattern)]) != pattern:
            raise EvidenceError("constant moved: " + name)
        rows.append({"name": name, "address": "%#x" % va, "bytes": pattern.hex(), "value": value})
    for va, pattern in (SHORTFALL_WORD[:2], SHORTFALL_WORD[2:]):
        at = image.offset(va)
        if bytes(image.blob[at:at + len(pattern)]) != pattern:
            raise EvidenceError("shortfall word moved")
    return rows


def text_rows(image):
    """Each log text site: the lea target and the bytes there, cut at the first NUL, with format marks shown as %."""
    rows = []
    for va, kind in TEXT_SITES:
        at = image.offset(va)
        data = bytes(image.blob[at:at + 7])
        if data[:3] != b"\x48\x8d\x35":
            raise EvidenceError("text lea moved")
        target = va + 7 + struct.unpack_from("<i", data, 3)[0]
        if TEXTS.get(target) != kind:
            raise EvidenceError("text target of " + kind)
        place = image.offset(target)
        raw = bytes(image.blob[place:place + 160]).split(b"\0")[0]
        words, skip = [], False
        for byte in raw:
            if skip:
                skip = False
            elif byte == 0xC0:
                words.append("%")
                skip = True
            elif 0x20 <= byte < 0x7F:
                words.append(chr(byte))
        rows.append(("%#x" % va, "%#x" % target, kind, "".join(words)))
    return rows


def caller_rows(image):
    slot = [address_ for address_, target in relative_slots(image).items() if target == ADL]
    base, text = image.text_bytes()
    rows = []
    for at in range(len(text) - 6):
        if text[at] == 0xFF and text[at + 1] == 0x15 and base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] in slot:
            rows.append({"site": "%#x" % (base + at), "function": "%#x" % image.fde(base + at)[0]})
    return dict(slots=["%#x" % item for item in slot], callers=rows)


# ---- mutation ----

MUTANT_CASES = 4
MUTANT_EVERY = 4


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


# ---- evidence ----

def outcome_of(case):
    try:
        Spec(case).run()
    except Panicked as panic:
        return "panic " + str(panic)
    return "finished"


def path_rows():
    return [
        ("1", "round start", "0x36f7c40, 0x3bc3b00, 0x3bc4080", "each round builds a row map of 0x30 rows from the address set in argument 6: words 0 and 1 (position_index), word 2 (margin_available), address at +0x18"),
        ("2", "scan", "0x36f7c40, 0x37d77e0", "account value of every row in map order, i64::MIN panics, shortfall = max(0, -value). A row with word 0 low dword 1 needs dex id == dex +0x30 and index < dex +0x10, else panic; market byte +0x28 != 0 makes it immediate. Otherwise a search of the address set in argument 8 can make it immediate. An immediate row is copied to the first list and adds nothing to the total; all others add to total_shortfall, u64 saturating with a log"),
        ("3", "trigger", "0x36f7c40, 0x3baca10", "total_shortfall >= dex +0x248 (adl_shortfall_remaining), unsigned: the whole row map replaces the list. Below it only the immediate rows go on. 0 >= 0 takes this arm"),
        ("4", "targets", "0x36f7c40, 0x33bb3e0, 0x2fdd500", "word 0 low dword 1: the row of id word 1 when it exists, any size and tag. Otherwise every position with size != 0 and tag dword 0. Each adds the address to id map out +0x20 and a row (word 0, word 1, address) to key (id, size <= 0)"),
        ("5", "texts", "0x36f7c40, 0x1344760", "mode byte != 2: `immediate adl`, `Auto-deleveragings triggered` with total and word when a key exists, else `Not performing auto-deleveraging` when total != 0. These and the two later texts go to a list that is only freed"),
        ("6", "candidates", "0x33100d0, 0x33c58e0, 0x33ad470", "keys go to the collector once; each key then removes its set from the map; a key with no set leaves root 0"),
        ("7", "oracle", "0x36f7c40", "key loop in key order: index id % 10000 past argument 5 panics bounds; price = +0x20 of row 0x60 * index"),
        ("8", "target step", "0x36f7c40", "rows in list order; word 0 == 2 ends the list; no position or size 0 skips; left = size"),
        ("9", "candidate", "0x36f7c40, 0x2fdad90", "last key of the set (highest rank, then address). No root or no key panics none. Candidate with no row or size 0 is removed and the next is read"),
        ("10", "match", "0x36f7c40", "|size| > |left|: candidate stays, delta = -left, left i64::MIN panics. Otherwise it is removed and delta = its size. Sign is not checked: a candidate on the target side grows the target"),
        ("11", "fill id", "0x36f7c40", "exchange +0x38 read as the id, then + 1 saturating, also with settlement off"),
        ("12", "pair", "0x36f7c40", "key side 1: target first, candidate second. Side 0: candidate first. Each with its size before this step"),
        ("13", "margin out", "0x36f7c40, 0x37d79e0, 0x3596940, 0x33bc4d0", "dex +0x2ec == 1 only. Word 0 == 0: no move. Low dword 1: row of id word 1, oracle * size + raw margin, saturating; oracle below 0 or overflow panics none, tag bit 0 clear panics text. Other word 0: summary word 0 - word 1, word 1 below 0 panics unwrap. Amount > 0 leaves raw margin when the row of the key has tag byte != 0, else the balance, saturating; account joins +0x188; total of the id rewritten"),
        ("14", "fills", "0x36fe830", "fill(id, price, delta, target), then the same amount goes back in the same way, then delta i64::MIN panics, then fill(id, price, -delta, candidate). Status != 0x186 panics unwrap"),
        ("15", "fill row", "0x36f7c40, 0x2f0e3d0", "|delta| * price as unsigned above 2^63 - 2 panics none. Row of 0x248 in the round map under the key: tag 1 and start size, id, first address at +0x8/+0xd0/+0xd8; second at +0x108/+0x1d0/+0x1d8; price +0x200, id +0x208, |delta| +0x210, notional +0x218, exchange +0x60 bytes at +0x228, side +0x234, words 0 and 1 of the target row at +0x238"),
        ("16", "running size", "0x36f7c40", "left += delta saturating with a log, never reread from the row; loop until 0"),
        ("17", "sweep", "0x36f7c40, 0x37d77e0, 0x37067b0", "dex +0x2ec == 1, list order until word 0 == 2: value below margin_available builds `balance decreased`; a row still open builds `non-zero final szi`. Value > 0: the value leaves raw margin (word 0 low dword 1, tag byte 0 panics text) or the balance, saturating, then goes to the fee credit 0x37067b0 with argument 7"),
        ("18", "round end", "0x36f7c40, 0x33bb960", "settlement on and rows made: both addresses of every row join the set in argument 6, rows move to out +0, and the round runs again. Otherwise exit"),
        ("19", "exit", "0x36f7c40, 0x37646d0", "out +0 key map of rows, +0x18 round count, +0x20 id map of addresses. Settlement off: rows are freed and out +0 stays empty, the fill id still moved"),
    ]


def reference_rows():
    return [
        ("core body", "only the collector side exists: collect_adl_candidates_for_side, compute_adl_candidate_score", "0x36f7c40, 27626 bytes, is called by 0x27078a0, 0x4cf37f0, 0x4cf94a0 through one slot", "the steps of path-map.tsv have no counterpart in the reference"),
        ("candidate use", "AdlCandidate vector per side", "a B-tree set per (id, side) with keys of (rank word, address), read from the highest key", "the reference text stops at the score; how it is consumed is here"),
        ("dex +0x248", "no field", "text names it self.adl_shortfall_remaining", "see text-sites.tsv"),
        ("equity left over", "no text", "positive value after the walk leaves the account and goes to 0x37067b0", "path-map.tsv step 17"),
    ]


def sample_rows(image, cases):
    harness = Harness(image)
    rows = []
    wanted = ("one cross target", "under the word", "at the word", "exempt user is immediate", "flag market row is immediate", "first candidate takes part", "candidate bigger", "candidate equal", "candidate same side grows", "short target", "candidate without the id", "no key panics", "settle off rows are dropped",
              "isolated moves value + margin", "word 3 row reads the summary", "sweep moves value to fees", "isolated sweep", "floor by one", "three rounds", "second round drops a map", "notional at the top", "notional over the top", "row word 2 ends the list")
    for case in cases:
        if case["label"] not in wanted:
            continue
        if compare_run(harness, case):
            raise EvidenceError("sample mismatch: " + case["label"])
        spec = Spec(case)
        try:
            want = spec.run()
        except Panicked as panic:
            rows.append((case["label"], "panic " + str(panic), "", "", "", "", ""))
            continue
        fills = "; ".join("%d/%d %d" % (key[0], key[1], len(want["final"][key])) for key in sorted(want["final"]))
        credits = sum(1 for event in spec.events if event[0] == "credit")
        rows.append((case["label"], "finished", want["rounds"], fills, want["counter"], credits, want["logs"]))
    return rows


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached, steps = [], []
    outcomes = {}
    for case in cases:
        machine.seen = set()
        before = machine.steps
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        steps.append(machine.steps - before)
        if failed:
            mismatches += 1
            first = first or failed
        key = outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "core_callers": caller_rows(image),
        "constants": constants(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "real_helpers": [{"function": edge, "role": role} for edge, role in REAL_HELPERS],
        "cases": {"total": len(cases), "outcomes": dict(sorted(outcomes.items()))},
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


def reason_for(row_):
    return REASONS.get(row_["va"], COLD if row_["result"] == "unreached" else UNCLASSIFIED)


UNCLASSIFIED = "no case in the budget tells it apart; see README Limits"


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
    write_tsv(out / "text-sites.tsv", ("site", "text_address", "kind", "text"), text_rows(image))
    write_tsv(out / "samples.tsv", ("label", "outcome", "rounds", "final_rows_by_key", "fill_id_after", "credits", "overflow_logs"), sample_rows(image, all_cases()))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row_ in results:
        reason = "" if row_["result"] == "killed" else reason_for(row_)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row_["group"], row_["va"], row_["kind"], row_["result"], row_["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
