#!/usr/bin/env python3
"""Pin the node #94 liquidation hand-over 0x36fff10 from ELF bytes: receiver gates, plan rows, receiver margin check, commit and source clear.

The plan body and the tree, clone and collect helpers it owns run whole in a Python evaluator. A separately written specification
predicts every stub argument, refusal, output row and final account, and every condition, immediate and field offset of those bodies
is flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

PLAN = 0x36FFF10
POSITION_ENTRY = 0x33BD420
TOTAL_ENTRY = 0x33BC4D0
PLAN_INSERT = 0x3396940
CLONE_ROW = 0x33DE780
COLLECT = 0x3316D60
BULK = 0x2FBAA70
CLONE_INSERT = 0x33C0ED0
ROW_INSERT = 0x33C2600
PLAN_ITER = 0x33B0F60
CLONE_ITER = 0x33B25E0
POSITION_ITER = 0x33B4700
DROP_CLONES = 0x3401DE0
ROW_VECTOR = 0x3BB0970
USER_READ = 0x36F57F0
MARGIN_LIST = 0x37D7360
ACCOUNT_VALUE = 0x37D77E0
SUMMARY = 0x37D79E0
USER_ENTRY = 0x3596940
SET_ADD = 0x339B590
SET_REMOVE = 0x33ACFE0
LEVERAGE_NOTE = 0x370E6A0
LEVERAGE_MOVE = 0x370E2A0
DECODE = 0x3BFFFD0
PLAN_ROWS = 0x3BD1220
CLONE_POSITIONS = 0x33EB860
CLONE_EXTRA = 0x33E35C0
DROP_EXTRA = 0x33F2DF0
HASH_ADDRESS = 0x399C7A0
HASH_ID = 0x399C4A0
GROW_ITEMS = 0x32D57F0
PANIC_NONE = 0x157A9F0
PANIC_UNWRAP = 0x157AA10
PANIC_ADD = 0x157B480
PANIC_MUL = 0x157B4A0
PANIC_NEG = 0x157B4C0
PANIC_BOUNDS = 0x157B64F
PANIC_TEXT = 0x157B7F0
OVERFLOW_LOG = 0x358DCD0
ONCE_CALL = 0x4EE3B20
ONCE_WORD = 0x577AB98
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
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
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 300000
DEX = HEAP_BASE + 0x1000
EXCHANGE = HEAP_BASE + 0x2000
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

NOT_ELIGIBLE = 0x20
ISOLATED_RECEIVER = 0x21
RECEIVER_SHORT = 0x22
DEX_STEP = 10000
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)
U64_MAX = (1 << 64) - 1
ROW_STRIDE = 0x68
ITEM_STRIDE = 24
LIST_STRIDE = 0x30
PLAN_ROW_STRIDE = 0x20
DEFAULT_LEVERAGE = 20
DEFAULT_WORD = 50
TAG, LEVERAGE, RAW, SIZE, WORD18, WORD20, WORD28, WORD30, WORD38 = range(9)


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def word_of(value):
    return value & MASK[8]


def position(size=0, tag=0, leverage=5, raw=0, words=(0x18, 0x20, 0x28, 0x30), last=7):
    return [tag, leverage, raw, size] + list(words) + [last]


def account(balance=0, positions=None, count=None, tail=0x51, extra=False):
    held = positions or {}
    return dict(balance=balance, positions={key: list(value) for key, value in held.items()}, count=sum(1 for value in held.values() if value[SIZE]) if count is None else count, tail=tail, extra=extra)


def need_of(case, row):
    return sum(abs(item[SIZE]) * case.get("rate", 1) for item in row["positions"].values())


class Spec:
    """The written model: it does not read the evaluator and shares no state with it."""

    def __init__(self, case):
        self.case = case
        self.users = copy.deepcopy(case.get("users", {}))
        self.totals = dict(case.get("totals", {}))
        self.events, self.frees = [], []
        self.logs = 0
        self.counter = case.get("counter", 100)
        self.once = bool(case.get("once"))
        self.word = case.get("word248", 500)
        self.clones = {}
        self.dex_id = case.get("dex_id", 0)

    def add(self, left, right):
        value = left + right
        if value > I64_MAX or value < I64_MIN:
            self.logs += 1
            return I64_MAX if value > 0 else I64_MIN
        return value

    def user(self, key):
        return self.users.setdefault(key, account())

    def read(self, key):
        self.events.append(("read", key))
        return self.user(key)

    def entry(self, key):
        self.events.append(("map", key))
        return self.user(key)

    def magnitude(self, value):
        if value == I64_MIN:
            raise Panicked("unwrap")
        return abs(value)

    def total_change(self, key, sub, plus):
        value = self.totals.get(key, 0)
        if sub is not None:
            value = self.add(value, -sub)
        if plus is not None:
            value = self.add(value, plus)
        self.totals[key] = value

    def fresh_position(self, key):
        self.events.append(("decode", key))
        tag, leverage, raw = self.case.get("defaults", {}).get(key, (0, 3, 0))
        return position(0, tag, leverage, raw, (0, 0, 0, 0), self.case.get("market_word", lambda at: 0x900 + at)(key % DEX_STEP))

    def eligible(self):
        row = self.user(self.case["user"])
        self.events.append(("read", self.case["user"]))
        self.events.append(("list",))
        rows = self.case.get("list", ())
        flag, asset = self.case.get("flag", 0), self.case.get("asset", 0)
        found = False
        for first, second in rows:
            if flag:
                if first == flag and second == asset:
                    found = True
                    break
            elif first == 0:
                found = True
                break
        cap = self.case.get("list_cap", len(rows))
        if cap:
            self.frees.append(cap * LIST_STRIDE)
        return found

    def prepare(self, key):
        """One receiver: every market of the dex gets a row, an empty isolated row becomes cross 20x."""
        row = self.entry(key)
        markets = self.case.get("markets", 4)
        if not markets:
            return None
        base = self.dex_id * DEX_STEP
        if base >> 64:
            raise Panicked("mul")
        refusal = None
        for index in range(markets):
            at = base + index
            if at >> 64:
                raise Panicked("add")
            self.events.append(("touch", key))
            held = row["positions"].get(at)
            if held is None:
                held = row["positions"][at] = self.fresh_position(at)
            before = held[SIZE]
            leverage = held[LEVERAGE]
            if held[TAG] == 1:
                if held[RAW] or held[SIZE]:
                    refusal = at
                else:
                    held[TAG] = 0
                    held[LEVERAGE] = DEFAULT_LEVERAGE
                    held[WORD18:WORD30 + 1] = [0, 0, 0, 0]
                    held[SIZE] = 0
                    held[WORD38] = DEFAULT_WORD
            self.total_change(at, self.magnitude(before), self.magnitude(held[SIZE]))
            if leverage != held[LEVERAGE]:
                self.events.append(("note", key, at, held[LEVERAGE]))
            if refusal is not None:
                return refusal
        return None

    def isolated_plan(self):
        row = self.user(self.case["user"])
        asset = self.case["asset"]
        held = row["positions"].get(asset)
        if held is None:
            raise Panicked("none")
        if held[TAG] & 0xFF == 0:
            raise Panicked("text")
        local = asset % DEX_STEP
        oracles = self.case.get("oracles", (1000, 1000, 1000, 1000))
        if local >= len(oracles):
            raise Panicked("bounds")
        oracle = oracles[local]
        if oracle < 0:
            raise Panicked("none")
        value = oracle * held[SIZE]
        if value > I64_MAX or value < I64_MIN:
            raise Panicked("none")
        return {asset: [held[SIZE], held[RAW], value]}, 0

    def cross_plan(self):
        row = self.user(self.case["user"])
        words = self.case.get("summary", (0, 0, 0))
        self.events.append(("summary", row["balance"]))
        self.events.append(("collect", self.value, words[0], words[2], len(row["positions"])))
        rows = self.case.get("rows", ())
        left = self.case.get("left", words[0])
        cap = self.case.get("rows_cap", len(rows))
        if cap:
            self.frees.append(cap * PLAN_ROW_STRIDE)
        plan = {key: [size, raw, value] for key, size, raw, value in sorted(rows)}
        if left:
            if self.once:
                self.once = False
                self.events.append(("once",))
            if plan:
                first = plan[min(plan)]
                first[1] = self.add(first[1], left)
                left = 0
        return plan, left

    def clone(self, key):
        if key not in self.clones:
            row = self.read(key)
            copied = copy.deepcopy(row)
            if row["positions"]:
                self.events.append(("clone", len(row["positions"])))
            if row["extra"]:
                self.events.append(("clone extra",))
            self.clones[key] = copied
        return self.clones[key]

    def receiver(self, asset):
        return self.case.get("owners", {}).get(asset, self.case["default"])

    def move_into(self, plan, residual):
        for asset in sorted(plan):
            size, raw, _ = plan[asset]
            row = self.clone(self.receiver(asset))
            held = row["positions"].get(asset)
            if held is None:
                held = row["positions"][asset] = self.fresh_position(asset)
            before = held[SIZE]
            after = self.add(before, size)
            if after != before:
                held[WORD28] = 0
                if (before > 0) - (before < 0) != (after > 0) - (after < 0):
                    held[WORD20] = 0
                held[SIZE] = after
            if before == 0 and after != 0:
                row["count"] = min(row["count"] + 1, U64_MAX)
            elif before != 0 and after == 0 and row["count"]:
                row["count"] -= 1
            row["balance"] = self.add(row["balance"], raw)
        if residual:
            row = self.clone(self.case["default"])
            row["balance"] = self.add(row["balance"], residual)

    def receivers_hold(self):
        for key in sorted(self.clones):
            row = self.clones[key]
            need = need_of(self.case, row)
            self.events.append(("summary", row["balance"]))
            if need > I64_MAX:
                raise Halt("spec fixture")
            if self.add(row["balance"], -need) < 0:
                return False
        return True

    def output(self, plan, residual):
        rows = {}

        def row_of(key):
            if key not in rows:
                rows[key] = dict(ident=self.counter, total=0, amount=0, items=[], receiver=key)
                self.counter = min(self.counter + 1, U64_MAX)
            return rows[key]
        for asset in sorted(plan):
            size, raw, value = plan[asset]
            row = row_of(self.receiver(asset))
            total = row["total"] + abs(value)
            if total > U64_MAX:
                self.logs += 1
                total = U64_MAX
            row["total"] = total
            row["amount"] = self.add(row["amount"], self.add(value, raw))
            row["items"].append((asset, size, value))
        if residual:
            row = row_of(self.case["default"])
            row["amount"] = self.add(row["amount"], residual)
        return [rows[key] for key in sorted(rows)]

    def commit(self):
        tracker = self.case.get("tracker", {})
        for key in sorted(self.clones):
            row = self.clones[key]
            if not row["tail"]:
                self.drop_rest(key)
                break
            self.events.append(("map", key))
            old = self.user(key)
            self.users[key] = row
            for at in sorted(old["positions"]):
                self.total_change(at, self.magnitude(old["positions"][at][SIZE]), None)
            for at in sorted(row["positions"]):
                held = row["positions"][at]
                self.total_change(at, None, self.magnitude(held[SIZE]))
                prior = old["positions"].get(at)
                if prior is not None and prior[LEVERAGE] == held[LEVERAGE]:
                    continue
                if tracker and key in tracker and at in tracker[key]:
                    self.events.append(("retag", key, at, held[LEVERAGE]))
            self.events.append(("drop extra", 0x7001 if old["extra"] else 0))
            if old["count"]:
                if not row["count"]:
                    self.events.append(("remove", key))
            elif row["count"]:
                self.events.append(("add", key))

    def drop_rest(self, stop):
        """Clones not consumed by the commit walk; a row with tail 0 ends the walk and is itself not dropped."""
        for key in sorted(self.clones):
            if stop is None or key > stop:
                self.events.append(("drop extra", 0x7001 if self.clones[key]["extra"] else 0))

    def clear_isolated(self, row):
        key, asset = self.case["user"], self.case["asset"]
        self.events.append(("touch", key))
        held = row["positions"].get(asset)
        if held is None:
            held = row["positions"][asset] = self.fresh_position(asset)
        size = held[SIZE]
        if size:
            held[SIZE] = held[WORD20] = held[WORD28] = 0
        if held[TAG] & 0xFF == 0:
            raise Panicked("text")
        held[RAW] = 0
        if size and row["count"]:
            row["count"] -= 1
        self.total_change(asset, self.magnitude(size), None)

    def clear_cross(self, row):
        key = self.case["user"]
        for at in sorted(row["positions"]):
            held = row["positions"][at]
            if held[TAG]:
                continue
            size = held[SIZE]
            if size:
                held[SIZE] = held[WORD20] = held[WORD28] = 0
                if row["count"]:
                    row["count"] -= 1
            self.total_change(at, self.magnitude(size), None)
        self.events.append(("touch", key))
        row["balance"] = 0

    def run(self):
        case = self.case
        user = case["user"]
        flag = case.get("flag", 0)
        if not self.eligible():
            return self.done(NOT_ELIGIBLE, (user, flag, case.get("asset", 0)))
        for key in case.get("addresses", ()):
            refused = self.prepare(key)
            if refused is not None:
                return self.done(ISOLATED_RECEIVER, (refused,))
        self.read(user)
        self.value = case.get("value", 0)
        self.events.append(("value", flag, case.get("asset", 0)))
        if self.once:
            self.once = False
            self.events.append(("once",))
        plan, residual = self.isolated_plan() if flag & 1 else self.cross_plan()
        self.move_into(plan, residual)
        if not self.receivers_hold():
            self.drop_rest(None)
            return self.done(RECEIVER_SHORT, ())
        rows = self.output(plan, residual)
        self.commit()
        self.events.append(("map", user))
        row = self.user(user)
        start = row["count"]
        if flag & 1:
            self.clear_isolated(row)
        else:
            self.clear_cross(row)
        if self.once:
            self.once = False
            self.events.append(("once",))
        if start:
            if not row["count"]:
                self.events.append(("remove", user))
        elif row["count"]:
            self.events.append(("add", user))
        if self.value < 0:
            if self.value == I64_MIN:
                raise Panicked("neg")
            self.word = max(self.word - abs(self.value), 0)
        return self.done(OK, tuple((row["ident"], row["total"], row["amount"], tuple(row["items"]), row["receiver"]) for row in rows))

    def done(self, status, words):
        users = {key: dump_view(row) for key, row in self.users.items()}
        return dict(status=status, words=words, events=self.events, frees=self.frees, logs=self.logs, counter=self.counter, word=self.word, users=users, totals={key: value for key, value in self.totals.items()})


def dump_view(row):
    return (row["balance"], row["count"], row["tail"], row["extra"], tuple((at, tuple(row["positions"][at])) for at in sorted(row["positions"])))


# ---- harness ----

POSITION_MAP = dict(leaf=0x328, inner=0x388, parent=0x2C0, slot=0x320, length=0x322, keys=0x2C8, stride=8, edges=0x328, values=0x40)
ROUTE_MAP = dict(leaf=0x140, inner=0x1A0, parent=0, slot=0x13C, length=0x13E, keys=8, stride=8, edges=0x140, values=20, value_base=0x60)
TOTAL_MAP = dict(leaf=0xC0, inner=0x120, parent=0, slot=0xB8, length=0xBA, keys=8, stride=8, edges=0xC0, values=8, value_base=0x60)
CAPACITY = 11
SPLITS = (0x2F24930, 0x2F18F20, 0x2F3A270, 0x2F926F0, 0x33B3840, 0x2F7CD20)
HASH_TOP = 0x11


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


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {PLAN, POSITION_ENTRY, TOTAL_ENTRY, PLAN_INSERT, CLONE_ROW, COLLECT, BULK, CLONE_INSERT, ROW_INSERT, PLAN_ITER, CLONE_ITER, POSITION_ITER, DROP_CLONES, ROW_VECTOR} | set(SPLITS)
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        machine.calls = {USER_READ: self.on_read, MARGIN_LIST: self.on_list, USER_ENTRY: self.on_entry, SET_ADD: self.on_add, SET_REMOVE: self.on_remove, LEVERAGE_NOTE: self.on_note, LEVERAGE_MOVE: self.on_move, DECODE: self.on_decode,
                         PLAN_ROWS: self.on_rows, CLONE_POSITIONS: self.on_clone, CLONE_EXTRA: self.on_clone_extra, DROP_EXTRA: self.on_drop_extra, HASH_ADDRESS: self.on_hash_address, HASH_ID: self.on_hash_id}
        hooks = {ACCOUNT_VALUE: self.on_value, SUMMARY: self.on_summary, OVERFLOW_LOG: self.on_log, ONCE_CALL: self.on_once, GROW_ITEMS: self.on_grow(ITEM_STRIDE),
                 PANIC_NONE: self.on_panic("none"), PANIC_UNWRAP: self.on_panic("unwrap"), PANIC_ADD: self.on_panic("add"), PANIC_MUL: self.on_panic("mul"), PANIC_NEG: self.on_panic("neg"), PANIC_BOUNDS: self.on_panic("bounds"), PANIC_TEXT: self.on_panic("text")}
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
        self.case = None
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.live = set()
        self.vectors = {}
        self.rows = {}
        self.row_keys = {}
        self.user_at = 0

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def node(self, size):
        at = self.bump(size)
        self.live.add(at)
        return at

    # edge hooks

    def on_alloc(self, machine):
        machine.regs[RAX] = self.node(machine.regs[RDI])

    def on_free(self, machine):
        at = machine.regs[RDI]
        if at in self.vectors:
            del self.vectors[at]
            self.frees.append(machine.regs[RSI])
        elif at in self.live:
            self.live.discard(at)
        else:
            raise Halt("free of an unknown block")

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

    def on_once(self, machine):
        regs = machine.regs
        if regs[RDI] != ONCE_WORD or regs[RSI] & 0xFF != 1:
            raise Halt("once arguments")
        machine.memory.statics[regs[RDI]] = 0
        self.events.append(("once",))

    def on_grow(self, size):
        def grow(machine):
            regs, memory = machine.regs, machine.memory
            vector = regs[RDI]
            cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
            wider = max(cap * 2, 4)
            fresh = self.bump(wider * size)
            if cap:
                memory.copy(fresh, data, cap * size)
            memory.write(vector, 8, wider)
            memory.write(vector + 8, 8, fresh)
        return grow

    def row_at(self, key):
        if key not in self.rows:
            self.rows[key] = self.put_account(self.bump(0x60), account())
            self.row_keys[self.rows[key]] = key
        return self.rows[key]

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
        memory.write(at + 0x28, 8, 0x7001 if row["extra"] else 0)
        memory.write(at + 0x30, 8, 0x7002 if row["extra"] else 0)
        memory.write(at + 0x38, 8, 3 if row["extra"] else 0)
        memory.write(at + 0x40, 8, 0x4040)
        memory.write(at + 0x48, 8, 0x4848)
        memory.write(at + 0x50, 4, row["tail"])
        memory.write(at + 0x54, 8, 0x5454)
        memory.write(at + 0x5C, 4, 0x5C5C)
        return at

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
        self.events.append(("map", key))
        regs[RAX] = self.row_at(key)

    def on_list(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != self.user_row() or regs[RDX] != self.user_at or regs[RCX] & 0xFF != 3 or regs[R9] != DEX + 0x60 or memory.read(regs[RSP] + 8, 8) != DEX:
            raise Halt("list arguments")
        self.events.append(("list",))
        rows = self.case.get("list", ())
        cap = self.case.get("list_cap", len(rows))
        data = self.vector(max(cap, 1) * LIST_STRIDE) if cap else 8
        for index, (first, second) in enumerate(rows):
            memory.write(data + index * LIST_STRIDE, 8, first)
            memory.write(data + index * LIST_STRIDE + 8, 8, second)
        memory.write(regs[RDI], 8, cap)
        memory.write(regs[RDI] + 8, 8, data)
        memory.write(regs[RDI] + 0x10, 8, len(rows))

    def vector(self, size):
        at = self.bump(size)
        self.vectors[at] = size
        return at

    def user_row(self):
        return self.rows[self.case["user"]]

    def on_add(self, machine):
        regs, memory = machine.regs, machine.memory
        key = memory.bytes_at(regs[RSI], 20)
        if regs[RDI] == DEX + 0x188:
            self.events.append(("touch", key))
        elif regs[RDI] == DEX + 0x158:
            self.events.append(("add", key))
        else:
            raise Halt("set pointer")

    def on_remove(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0x158:
            raise Halt("remove set")
        self.events.append(("remove", memory.bytes_at(regs[RSI], 20)))

    def on_note(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0x128:
            raise Halt("note map")
        self.events.append(("note", memory.bytes_at(regs[RSI], 20), regs[RDX], regs[RCX] & MASK[4]))

    def on_move(self, machine):
        regs, memory = machine.regs, machine.memory
        spot = self.spots.get((regs[RDI], regs[RSI]))
        if spot is None:
            raise Halt("move arguments")
        if memory.read(regs[RSI], 8) != 0x5151:
            raise Halt("move value")
        self.events.append(("retag", spot[0], spot[1], regs[RDX] & MASK[4]))

    def on_decode(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDX] != DEX:
            raise Halt("decode context")
        self.events.append(("decode", regs[RSI]))
        tag, leverage, raw = self.case.get("defaults", {}).get(regs[RSI], (0, 3, 0))
        memory.write(regs[RDI], 4, tag)
        memory.write(regs[RDI] + 4, 4, leverage)
        memory.write(regs[RDI] + 8, 8, word_of(raw))

    def on_value(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        if regs[RDI] != self.user_row() or regs[RSI] != case.get("flag", 0) or regs[RDX] != case.get("asset", 0) or regs[RCX] & 0xFF or regs[R9] != DEX + 0x60 or memory.read(regs[RSP], 8) != DEX:
            raise Halt("value arguments")
        self.events.append(("value", regs[RSI], regs[RDX]))
        regs[RAX] = word_of(case.get("value", 0))

    def on_summary(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        if regs[RDX] or regs[RCX] or regs[R9] != DEX + 0x60 or memory.read(regs[RSP], 8) != DEX:
            raise Halt("summary arguments")
        row = regs[RSI]
        self.events.append(("summary", signed(memory.read(row, 8))))
        out = regs[RDI]
        if row == self.rows.get(case["user"]) and not self.summary_seen:
            self.summary_seen = True
            for index, word in enumerate(case.get("summary", (0, 0, 0))):
                memory.write(out + index * 8, 8, word_of(word))
            return
        need = 0
        for _, at in tree_items(memory, POSITION_MAP, memory.read(row + 8, 8), memory.read(row + 0x10, 8)):
            need += abs(signed(memory.read(at + 0x10, 8))) * case.get("rate", 1)
        if need > I64_MAX:
            raise Halt("summary need")
        memory.write(out, 8, memory.read(row, 8))
        memory.write(out + 8, 8, need)
        memory.write(out + 0x10, 8, 0)

    def on_rows(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        out, source = regs[RDI], regs[RSI]
        row = self.user_row()
        root, height, count = memory.read(row + 8, 8), memory.read(row + 0x10, 8), memory.read(row + 0x18, 8)
        some = int(root != 0)
        want = [some, 0, root, height, some, 0, root, height, count if root else 0, DEX + 0x60]
        if [memory.read(source + index * 8, 8) for index in range(10)] != want:
            raise Halt("collect iterator")
        words = case.get("summary", (0, 0, 0))
        value_at, left_at = memory.read(source + 0x60, 8), memory.read(source + 0x68, 8)
        total_at, user_at = memory.read(source + 0x50, 8), memory.read(source + 0x58, 8)
        if signed(memory.read(value_at, 8)) != case.get("value", 0) or signed(memory.read(left_at, 8)) != words[0] or signed(memory.read(total_at, 8)) != words[2] or memory.read(user_at, 8) != row:
            raise Halt("collect context")
        self.events.append(("collect", signed(memory.read(value_at, 8)), signed(memory.read(left_at, 8)), signed(memory.read(total_at, 8)), count))
        memory.write(left_at, 8, word_of(case.get("left", words[0])))
        rows = case.get("rows", ())
        cap = case.get("rows_cap", len(rows))
        data = self.vector(cap * PLAN_ROW_STRIDE) if cap else 8
        for index, (key, size, raw, value) in enumerate(rows):
            at = data + index * PLAN_ROW_STRIDE
            memory.write(at, 8, key)
            memory.write(at + 8, 8, word_of(size))
            memory.write(at + 0x10, 8, word_of(raw))
            memory.write(at + 0x18, 8, word_of(value))
        memory.write(out, 8, cap)
        memory.write(out + 8, 8, data)
        memory.write(out + 0x10, 8, len(rows))

    def on_clone(self, machine):
        regs, memory = machine.regs, machine.memory
        items = tree_items(memory, POSITION_MAP, regs[RSI], regs[RDX])
        self.events.append(("clone", len(items)))
        data = [(key, memory.bytes_at(at, 0x40)) for key, at in items]
        root, height = build_tree(memory, self.node, POSITION_MAP, data, memory.put_bytes)
        memory.write(regs[RDI], 8, root)
        memory.write(regs[RDI] + 8, 8, height)
        memory.write(regs[RDI] + 0x10, 8, len(items))

    def on_clone_extra(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != 0x7001 or regs[RDX] != 0x7002:
            raise Halt("extra arguments")
        self.events.append(("clone extra",))
        memory.write(regs[RDI], 8, 0x7001)
        memory.write(regs[RDI] + 8, 8, 0x7002)
        memory.write(regs[RDI] + 0x10, 8, 3)

    def on_drop_extra(self, machine):
        self.events.append(("drop extra", self.machine.memory.read(machine.regs[RDI], 8)))

    def on_hash_address(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != DEX + 0x148:
            raise Halt("hash table")
        regs[RAX] = self.outer_hash(memory.bytes_at(regs[RSI], 20))

    def on_hash_id(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] not in self.hashers:
            raise Halt("hash inner")
        regs[RAX] = self.inner_hash(memory.read(regs[RSI], 8))

    def outer_hash(self, key):
        return HASH_TOP << 57 | key[-1] * 3 & self.mask(self.case.get("crowd"))

    def inner_hash(self, key):
        return HASH_TOP << 57 | key * 5 & self.mask(self.case.get("crowd"))

    def mask(self, crowd):
        return 63 if crowd else 15

    def lay_tracker(self, case):
        """Two nested swiss tables; every top byte equal, so a probe has to compare keys. `crowd` fills a group and pushes the row to the next."""
        memory = self.machine.memory
        tracker = case.get("tracker", {})
        self.spots, self.hashers = {}, set()
        crowd = case.get("crowd")
        buckets = self.mask(crowd) + 1

        def table(stride, rows, hash_of, fill):
            area = self.bump(buckets * stride + buckets + 16)
            ctrl = area + buckets * stride
            memory.put_bytes(ctrl, b"\xff" * (buckets + 16))

            def tag(at, value):
                memory.write(ctrl + at, 1, value)
                if at < 16:
                    memory.write(ctrl + buckets + at, 1, value)
            used = set()
            for key, payload in rows:
                start = hash_of(key) & (buckets - 1)
                if crowd:
                    for shift in range(16):
                        if (start + shift) % buckets not in used:
                            used.add((start + shift) % buckets)
                            tag((start + shift) % buckets, 0x22)
                    start = (start + 16) % buckets
                while start in used and memory.read(ctrl + start, 1) != 0x22:
                    start = (start + 1) % buckets
                used.add(start)
                tag(start, HASH_TOP)
                fill(ctrl - stride * (start + 1), key, payload)
            return ctrl

        def fill_outer(entry, key, inner):
            memory.put_bytes(entry, key)

            def fill_inner(row, asset, _):
                memory.write(row, 8, asset)
                memory.write(row + 8, 8, 0x5151)
                self.spots[(entry + 0x48, row + 8)] = (key, asset)
            ctrl = table(0x40, [(asset, None) for asset in sorted(inner)], self.inner_hash, fill_inner)
            memory.write(entry + 0x18, 8, ctrl)
            memory.write(entry + 0x20, 8, buckets - 1)
            memory.write(entry + 0x30, 8, len(inner))
            self.hashers.add(entry + 0x38)
        ctrl = table(0x50, sorted(tracker.items()), self.outer_hash, fill_outer)
        memory.write(DEX + 0x128, 8, ctrl)
        memory.write(DEX + 0x130, 8, buckets - 1)
        memory.write(DEX + 0x140, 8, len(tracker))

    # fixtures

    def run_case(self, case):
        machine, memory = self.machine, self.machine.memory
        memory.reset()
        self.case = case
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.live = set()
        self.vectors = {}
        self.rows = {}
        self.row_keys = {}
        self.summary_seen = False
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0
        markets = case.get("markets", 4)
        table = self.bump(max(markets, 1) * 0x30)
        pick = case.get("market_word", lambda at: 0x900 + at)
        for index in range(markets):
            memory.write(table + index * 0x30 + 0x18, 4, pick(index))
        memory.write(DEX + 8, 8, table)
        memory.write(DEX + 0x10, 8, markets)
        memory.write(DEX + 0x30, 8, case.get("dex_id", 0))
        oracles = case.get("oracles", (1000, 1000, 1000, 1000))
        data = self.bump(max(len(oracles), 1) * 0x60)
        for index, oracle in enumerate(oracles):
            memory.write(data + index * 0x60 + 0x20, 8, word_of(oracle))
        memory.write(DEX + 0x68, 8, data)
        memory.write(DEX + 0x70, 8, len(oracles))
        totals = case.get("totals", {})

        def put_total(at, value):
            memory.write(at, 8, word_of(value))
        root, height = build_tree(memory, self.node, TOTAL_MAP, [(word_key(key), totals[key]) for key in sorted(totals)], put_total)
        memory.write(DEX + 0x170, 8, root)
        memory.write(DEX + 0x178, 8, height)
        memory.write(DEX + 0x180, 8, len(totals))
        memory.write(DEX + 0x248, 8, case.get("word248", 500))
        self.lay_tracker(case)
        for key, row in case.get("users", {}).items():
            self.rows[key] = self.put_account(self.bump(0x60), row)
            self.row_keys[self.rows[key]] = key
        memory.write(EXCHANGE + 0x40, 8, case.get("counter", 100))
        user = self.user_at = self.bump(20)
        memory.put_bytes(user, case["user"])
        self.row_at(case["user"])
        addresses = case.get("addresses", ())
        route = self.bump(0x50)
        data = self.bump(max(len(addresses), 1) * 20)
        for index, key in enumerate(addresses):
            memory.put_bytes(data + index * 20, key)
        owners = case.get("owners", {})

        def put_owner(at, key):
            memory.put_bytes(at, key)
        root, height = build_tree(memory, self.node, ROUTE_MAP, [(word_key(key), owners[key]) for key in sorted(owners)], put_owner)
        memory.write(route, 8, len(addresses))
        memory.write(route + 8, 8, data)
        memory.write(route + 0x10, 8, len(addresses))
        memory.write(route + 0x18, 8, root)
        memory.write(route + 0x20, 8, height)
        memory.write(route + 0x28, 8, len(owners))
        memory.put_bytes(route + 0x30, case["default"])
        out = self.bump(0x70)
        memory.write(STACK_TOP - 0x100, 8, EXCHANGE)
        machine.run(PLAN, {RDI: out, RSI: DEX, RDX: user, RCX: case.get("flag", 0), R8: case.get("asset", 0), R9: route})
        status = memory.read(out, 2)
        words = ()
        if status == OK:
            data, count = memory.read(out + 0x10, 8), memory.read(out + 0x18, 8)
            rows = []
            for index in range(count):
                at = data + index * ROW_STRIDE
                if memory.read(at, 8) != case.get("flag", 0) or memory.read(at + 8, 8) != case.get("asset", 0) or memory.bytes_at(at + 0x54, 20) != case["user"]:
                    raise Halt("output row head")
                items, length = memory.read(at + 0x18, 8), memory.read(at + 0x20, 8)
                rows.append((memory.read(at + 0x28, 8), memory.read(at + 0x30, 8), signed(memory.read(at + 0x38, 8)),
                             tuple((memory.read(items + place * ITEM_STRIDE, 8), signed(memory.read(items + place * ITEM_STRIDE + 8, 8)), signed(memory.read(items + place * ITEM_STRIDE + 16, 8))) for place in range(length)),
                             memory.bytes_at(at + 0x40, 20)))
            words = tuple(rows)
        elif status == NOT_ELIGIBLE:
            words = (memory.bytes_at(out + 2, 20), memory.read(out + 0x18, 8), memory.read(out + 0x20, 8))
        elif status == ISOLATED_RECEIVER:
            words = (memory.read(out + 8, 8),)
        return dict(status=status, words=words, counter=memory.read(EXCHANGE + 0x40, 8), word=memory.read(DEX + 0x248, 8), users=self.users_view(), totals=self.totals_view())

    def users_view(self):
        memory = self.machine.memory
        users = {}
        for key, at in self.rows.items():
            root, height, count = memory.read(at + 8, 8), memory.read(at + 0x10, 8), memory.read(at + 0x18, 8)
            items = tree_items(memory, POSITION_MAP, root, height)
            if len(items) != count:
                raise Halt("tree length word")
            if memory.read(at + 0x40, 8) != 0x4040 or memory.read(at + 0x48, 8) != 0x4848 or memory.read(at + 0x54, 8) != 0x5454:
                raise Halt("account tail")
            held = []
            for name, place in items:
                held.append((struct.unpack("<Q", name)[0], (memory.read(place, 4), memory.read(place + 4, 4), signed(memory.read(place + 8, 8)), signed(memory.read(place + 0x10, 8)), memory.read(place + 0x18, 8), memory.read(place + 0x20, 8),
                                                            memory.read(place + 0x28, 8), memory.read(place + 0x30, 8), memory.read(place + 0x38, 4))))
            users[key] = (signed(memory.read(at, 8)), memory.read(at + 0x20, 8), memory.read(at + 0x50, 4), memory.read(at + 0x38, 8) == 3, tuple(held))
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
    try:
        want = Spec(case).run()
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
    if "panic" in want or "panic" in got:
        if want.get("panic") != got.get("panic"):
            return "%s: panic %r against %r" % (label, want.get("panic"), got.get("panic"))
        return None
    if harness.events != want["events"]:
        for at in range(max(len(harness.events), len(want["events"]))):
            left = harness.events[at] if at < len(harness.events) else None
            right = want["events"][at] if at < len(want["events"]) else None
            if left != right:
                return "%s: event %d got %r want %r" % (label, at, left, right)
    if sorted(harness.frees) != sorted(want["frees"]):
        return "%s: frees got %r want %r" % (label, sorted(harness.frees), sorted(want["frees"]))
    for name in ("status", "words", "counter", "word", "users", "totals"):
        if got[name] != want[name]:
            return "%s: %s %s" % (label, name, show(got[name], want[name]))
    if harness.logs != want["logs"]:
        return "%s: logs got %d want %d" % (label, harness.logs, want["logs"])
    return None


# ---- cases ----

USER = address(0x60)
BACK = address(0x20)
HELP = address(0x30)
THIRD = address(0x40, 0xBB)
LOW = address(0x05, 0x11)
EMPTY_WORDS = (0, 0, 0, 0)


def base(label, **fields):
    held = {1: position(10, 0, 5, 0), 2: position(-4, 0, 7, 0)}
    case = dict(label=label, user=USER, default=BACK, addresses=(BACK,), markets=4, list=[(0, 0)], value=9000, summary=(9000, 0, 14000), rows=[(1, 10, -1000, 10000), (2, -4, 3000, -4000)], left=0,
                users={USER: account(9000, held), BACK: account(1 << 40, {0: position(0, 0, 3), 1: position(0, 0, 5), 2: position(0, 0, 7), 3: position(0, 0, 3)}, count=0)}, totals={1: 10, 2: 4})
    case.update(fields)
    return case


def isolated(label, **fields):
    held = {1: position(10, 2, 5, 300)}
    case = base(label, flag=1, asset=1, list=[(1, 1)], value=-200, summary=(0, 0, 0), rows=[])
    case["users"] = {USER: account(77, held), BACK: account(1 << 40, {0: position(0, 0, 3), 1: position(0, 0, 5), 2: position(0, 0, 7), 3: position(0, 0, 3)}, count=0)}
    case["totals"] = {1: 10}
    case.update(fields)
    return case


def eligibility_cases():
    rows = [base("cross, listed row"), base("cross, list empty", list=[]), base("cross, list empty with capacity", list=[], list_cap=2),
            base("cross, first row other flag", list=[(1, 5), (0, 9)]), base("cross, no zero flag row", list=[(1, 5), (2, 9)]), base("cross, 3 rows, capacity 5", list=[(2, 1), (3, 1), (0, 0)], list_cap=5)]
    rows += [isolated("isolated, listed"), isolated("isolated, flag matches, id differs", list=[(1, 2)]), isolated("isolated, id matches, flag differs", list=[(2, 1)]),
             isolated("isolated, second row matches", list=[(1, 2), (1, 1)]), isolated("isolated, third row matches", list=[(3, 3), (1, 7), (1, 1)]), isolated("isolated, empty", list=[])]
    return rows


def receiver_cases():
    rows = []
    idle = {at: position(0, 0, 3) for at in range(4)}
    for label, change in (("isolated size", position(5, 1, 4, 0)), ("isolated margin", position(0, 1, 4, 7)), ("isolated both", position(-5, 1, 4, 7)), ("isolated size low word", position(1 << 32, 1, 4, 0)), ("isolated margin low word", position(0, 1, 4, 1 << 32))):
        users = {USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {**idle, 2: change})}
        rows.append(base("receiver holds " + label, users=users, totals={2: 5}))
    users = {USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {**idle, 2: position(0, 1, 9, 0, (1, 2, 3, 4), 9)})}
    rows.append(base("receiver empty isolated row becomes cross 20x", users=users))
    users = {USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {**idle, 2: position(0, 1, 20, 0, (1, 2, 3, 4), 9)})}
    rows.append(base("receiver empty isolated row already 20x", users=users))
    users = {USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {**idle, 0: position(0, 1, 9), 3: position(0, 1, 2)})}
    rows.append(base("receiver two empty isolated rows", users=users))
    rows.append(base("receiver with no rows, decoded cross", users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40)}))
    rows.append(base("receiver with no rows, decoded isolated", users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40)}, defaults={0: (1, 9, 0), 2: (1, 11, 0)}))
    rows.append(base("decoded isolated with margin", users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40)}, defaults={1: (1, 9, 5)}))
    rows.append(base("no markets", markets=0, oracles=(), rows=[], summary=(9000, 0, 0), left=9000))
    rows.append(base("no receivers listed", addresses=()))
    rows.append(base("two receivers", addresses=(BACK, HELP), owners={2: HELP}, users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40), HELP: account(1 << 39)}))
    rows.append(base("two receivers, second refuses", addresses=(BACK, HELP), owners={2: HELP}, users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40), HELP: account(1 << 39, {3: position(9, 1, 3, 1)})}))
    rows.append(base("second dex", dex_id=2, rows=[(20001, 10, -1000, 10000)], summary=(9000, 0, 10000), asset=0, users={USER: account(9000, {20001: position(10)}), BACK: account(1 << 40)}, totals={20001: 10}))
    rows.append(base("dex index mul overflow", dex_id=1 << 61))
    rows.append(base("dex index add overflow", dex_id=(1 << 64) // DEX_STEP))
    rows.append(base("twelve markets", markets=12, oracles=(1000,) * 12, users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40)}))
    rows.append(base("receiver size minimum", users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {1: position(I64_MIN)})}))
    rows.append(base("total low overflow", totals={1: I64_MIN + 3, 2: 4}, users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {1: position(5, 0, 5)})}))
    rows.append(base("total high overflow", totals={1: I64_MAX - 1, 2: 4}, users={USER: account(9000, {1: position(10), 2: position(-4)}), BACK: account(1 << 40, {1: position(5, 0, 5)})}))
    return rows


def plan_cases():
    rows = []
    rows.append(base("cross one row", rows=[(1, 10, -1000, 10000)], summary=(9000, 0, 10000), users={USER: account(9000, {1: position(10)}), BACK: account(1 << 40)}, totals={1: 10}))
    rows.append(base("cross rows unsorted", rows=[(3, 2, 7, 2000), (0, 1, 8, 1000), (2, -4, 9, -4000), (1, 3, 5, 3000)], users={USER: account(9000, {0: position(1), 1: position(3), 2: position(-4), 3: position(2)}), BACK: account(1 << 40)}, totals={}))
    rows.append(base("cross remainder goes to the first row", left=7))
    rows.append(base("cross remainder negative", left=-7))
    rows.append(base("cross remainder saturates raw", left=I64_MAX, rows=[(1, 10, 5, 10000)]))
    rows.append(base("cross remainder low saturates raw", left=I64_MIN, rows=[(1, 10, -5, 10000)]))
    rows.append(base("cross no rows, remainder to default", rows=[], left=33))
    rows.append(base("cross no rows, negative remainder", rows=[], left=-33))
    rows.append(base("cross no rows, no remainder", rows=[], left=0))
    rows.append(base("cross no rows, capacity 2", rows=[], rows_cap=2, left=33))
    rows.append(base("cross no rows, remainder and once", rows=[], left=33, once=True))
    rows.append(base("cross remainder and once", left=5, once=True))
    rows.append(base("cross once, no remainder", once=True))
    rows.append(base("isolated once", flag=1, once=True))
    rows.append(base("cross, list of rows capacity 9", rows_cap=9))
    for count in (3, 8, 12):
        held = {at: position(at + 1) for at in range(count)}
        rows.append(base("cross %d rows" % count, markets=count, oracles=(1000,) * count, rows=[(at, at + 1, 2 * at - count, 1000 * (at + 1)) for at in reversed(range(count))], users={USER: account(9000, held), BACK: account(1 << 40)}, totals={at: at + 1 for at in range(count)}))
    rows.append(isolated("isolated oracle zero", oracles=(1000, 0, 1000, 1000)))
    rows.append(isolated("isolated oracle negative", oracles=(1000, -1, 1000, 1000)))
    rows.append(isolated("isolated product overflow", oracles=(1000, 1 << 62, 1000, 1000)))
    rows.append(isolated("isolated negative size", users={USER: account(77, {1: position(-10, 2, 5, 300)}), BACK: account(1 << 40)}))
    rows.append(isolated("isolated asset absent", asset=3, list=[(1, 3)]))
    rows.append(isolated("isolated row is cross", users={USER: account(77, {1: position(10, 0, 5, 300)}), BACK: account(1 << 40)}))
    rows.append(isolated("isolated tag 1 row in user", users={USER: account(77, {1: position(10, 256, 5, 300)}), BACK: account(1 << 40)}))
    rows.append(isolated("isolated id past the oracle list", asset=5, markets=6, list=[(1, 5)], users={USER: account(77, {5: position(10, 2, 5, 300)}), BACK: account(1 << 40)}))
    rows.append(isolated("isolated id second tree level", asset=30, markets=31, oracles=(1000,) * 31, list=[(1, 30)], users={USER: account(77, {at: position(at + 1, 2, 5, 3) for at in range(31)}), BACK: account(1 << 40)}, totals={}))
    rows.append(isolated("isolated other row stays", users={USER: account(77, {1: position(10, 2, 5, 300), 2: position(-3, 2, 5, 40), 3: position(8, 0, 5)}), BACK: account(1 << 40)}, totals={}))
    return rows


def move_cases():
    rows = []
    both = {USER: account(9000, {1: position(10), 2: position(-4)})}
    rows.append(base("receiver same side", users={**both, BACK: account(1 << 40, {1: position(3, 0, 5)})}))
    rows.append(base("receiver flips side", users={**both, BACK: account(1 << 40, {1: position(-13, 0, 5)})}))
    rows.append(base("receiver closes to zero", users={**both, BACK: account(1 << 40, {1: position(-10, 0, 5)})}))
    rows.append(base("receiver closes to zero, count 0", users={**both, BACK: account(1 << 40, {1: position(-10, 0, 5)}, count=0)}))
    rows.append(base("receiver both close, count 5", users={**both, BACK: account(1 << 40, {1: position(-10, 0, 5), 2: position(4, 0, 7)}, count=5)}))
    rows.append(base("receiver last position closes, set removal", users={**both, BACK: account(1 << 40, {1: position(-10, 0, 5), 2: position(4, 0, 7)}, count=2)}))
    rows.append(base("receiver count at u64 max", users={**both, BACK: account(1 << 40, {}, count=U64_MAX)}))
    rows.append(base("receiver size saturates", rows=[(1, I64_MAX, 0, 5)], users={**both, BACK: account(1 << 40, {1: position(5, 0, 5)})}, rate=0))
    rows.append(base("receiver size low saturates", rows=[(1, I64_MIN + 1, 0, 5)], users={**both, BACK: account(1 << 40, {1: position(-5, 0, 5)})}, rate=0))
    rows.append(base("zero size row", rows=[(1, 0, 3, 0)]))
    rows.append(base("balance saturates", rows=[(1, 1, I64_MAX, 5)], users={**both, BACK: account(9, {})}, rate=0))
    rows.append(base("balance low saturates", rows=[(1, 1, I64_MIN, 5)], users={**both, BACK: account(-9, {})}, rate=0))
    rows.append(base("receiver takes a loss and fails", rows=[(1, 10, -1000, 10000)], users={**both, BACK: account(500)}))
    rows.append(base("receiver margin passes at equality", rows=[(1, 10, -1000, 10000)], users={**both, BACK: account(1010)}))
    rows.append(base("receiver margin fails by one", rows=[(1, 10, -1000, 10000)], users={**both, BACK: account(1009)}))
    rows.append(base("receiver need above balance, positive", rows=[(1, 10, 0, 10000)], rate=1000, users={**both, BACK: account(9999)}))
    rows.append(base("receiver need saturating gap", rows=[(1, 10, 0, 10000)], rate=(1 << 62) // 10, users={**both, BACK: account(-(1 << 62))}))
    rows.append(base("two receivers, first fails", owners={2: HELP}, addresses=(BACK, HELP), rows=[(1, 10, -5000, 10000), (2, -4, 0, -4000)], users={**both, BACK: account(10), HELP: account(1 << 40)}))
    rows.append(base("two receivers, second fails", owners={2: HELP}, addresses=(BACK, HELP), rows=[(1, 10, 0, 10000), (2, -4, -9000, -4000)], users={**both, BACK: account(1 << 40), HELP: account(10)}))
    rows.append(base("low address sorts first", owners={2: LOW}, addresses=(BACK, LOW), users={**both, BACK: account(1 << 40), LOW: account(1 << 40)}))
    rows.append(base("all to one owner", owners={1: HELP, 2: HELP}, addresses=(BACK, HELP), users={**both, BACK: account(1 << 40), HELP: account(1 << 40)}))
    rows.append(base("third owner, three rows", owners={1: THIRD, 2: HELP}, addresses=(BACK, HELP, THIRD), rows=[(0, 1, 10, 1000), (1, 2, 20, 2000), (2, -1, 30, -1000)], users={USER: account(9000, {0: position(1), 1: position(2), 2: position(-1)}), BACK: account(1 << 40), HELP: account(1 << 40), THIRD: account(1 << 40)}, totals={}))
    many = {at: address(0x60 + at, 0xCC) for at in range(5)}
    rows.append(base("owner tree, many keys", markets=16, oracles=(1000,) * 16, owners={at: address(0x60 + at % 3, 0xCC) for at in range(14)}, addresses=(BACK,) + tuple(many[at] for at in range(3)),
                     rows=[(at, at + 1, at * 3 - 7, (at + 1) * 1000) for at in (15, 13, 12, 7, 2, 0)], users={USER: account(9000, {at: position(at + 1) for at in (15, 13, 12, 7, 2, 0)}), BACK: account(1 << 40), many[0]: account(1 << 40), many[1]: account(1 << 40), many[2]: account(1 << 40)}, totals={}))
    rows.append(base("default gets remainder, owner gets rows", owners={1: HELP, 2: HELP}, addresses=(BACK, HELP), rows=[], left=11, users={**both, BACK: account(5), HELP: account(1 << 40)}))
    rows.append(base("user is the receiver", default=USER, addresses=(USER,)))
    rows.append(isolated("user is the isolated receiver", default=USER, addresses=(USER,), users={USER: account(77, {1: position(10, 0, 5, 300)})}))
    rows.append(base("extra map on the receiver", users={**both, BACK: account(1 << 40, {1: position(1, 0, 5)}, extra=True)}))
    rows.append(base("extra map on the user", users={USER: account(9000, {1: position(10), 2: position(-4)}, extra=True), BACK: account(1 << 40)}))
    rows.append(base("clone fails margin with extra map", rows=[(1, 10, -1000, 10000)], users={**both, BACK: account(1, {1: position(1, 0, 5)}, extra=True), HELP: account(5)}))
    rows.append(base("output total saturates", owners={1: HELP, 2: HELP}, addresses=(BACK, HELP), rows=[(0, 1, 0, I64_MAX), (1, 1, 0, I64_MAX), (2, 1, 0, I64_MAX), (3, 1, 0, I64_MAX)], rate=0, users={USER: account(9000, {0: position(1)}), BACK: account(1), HELP: account(1)}))
    rows.append(base("output amount saturates inside", rows=[(1, 1, 1, I64_MAX)], rate=0))
    rows.append(base("output amount low saturates inside", rows=[(1, 1, -1, I64_MIN)], rate=0))
    rows.append(base("output amount saturates outer", rows=[(1, 1, I64_MAX - 1, 1), (2, 1, I64_MAX - 1, 1)], rate=0, users={**both, BACK: account(0)}))
    rows.append(base("output negative value", rows=[(1, -1, 0, I64_MIN)], rate=0))
    rows.append(base("remainder row amount saturates", rows=[], left=-3, counter=5, users={**both, BACK: account(1 << 40)}))
    rows.append(base("counter at max", counter=U64_MAX, owners={2: HELP}, addresses=(BACK, HELP), users={**both, BACK: account(1 << 40), HELP: account(1 << 40)}))
    rows.append(base("nine items in one row", markets=9, oracles=(1000,) * 9, rows=[(at, at + 1, at, 1000 * (at + 1)) for at in range(9)], users={USER: account(9000, {at: position(at + 1) for at in range(9)}), BACK: account(1 << 40)}, totals={}))
    return rows


def commit_cases():
    rows = []
    both = {USER: account(9000, {1: position(10), 2: position(-4)})}
    wide = {at: position(at % 3 - 1, 0, 3 + at % 4) for at in range(14)}
    rows.append(base("leverage changes through defaults", users={**both, BACK: account(1 << 40)}, tracker={BACK: {1: 1, 2: 2}}))
    rows.append(base("tracker misses the address", users={**both, BACK: account(1 << 40)}, tracker={HELP: {1: 1}}))
    rows.append(base("tracker misses the id", users={**both, BACK: account(1 << 40)}, tracker={BACK: {3: 1}}))
    rows.append(base("tracker inner map empty", users={**both, BACK: account(1 << 40)}, tracker={BACK: {}}))
    rows.append(base("tracker several addresses", owners={2: HELP}, addresses=(BACK, HELP), users={**both, BACK: account(1 << 40), HELP: account(1 << 40, {2: position(1, 0, 8)})}, tracker={BACK: {0: 1, 1: 2, 2: 3, 3: 4}, HELP: {0: 5, 2: 6}}))
    rows.append(base("tracker groups full", crowd=True, users={**both, BACK: account(1 << 40)}, tracker={BACK: {0: 1, 1: 2, 2: 3, 3: 4}}))
    rows.append(base("tracker same leverage, no move", users={**both, BACK: account(1 << 40, {1: position(1, 0, 5), 2: position(1, 0, 7), 0: position(0, 0, 3), 3: position(0, 0, 3)})}, tracker={BACK: {1: 1, 2: 2}}))
    rows.append(base("deep receiver tree", markets=4, users={**both, BACK: account(1 << 40, wide, count=9)}, tracker={BACK: {5: 1}}))
    rows.append(base("receiver stored with empty tail stops commit", users={**both, BACK: account(1 << 40, tail=0)}))
    rows.append(base("second receiver empty tail", owners={2: HELP}, addresses=(BACK, HELP), users={**both, BACK: account(1 << 40), HELP: account(1 << 40, tail=0)}))
    rows.append(base("user cross with isolated row left", users={USER: account(9000, {1: position(10), 2: position(-4), 3: position(6, 1, 4, 9)}), BACK: account(1 << 40)}))
    rows.append(base("user count 0", users={USER: account(9000, {1: position(10), 2: position(-4)}, count=0), BACK: account(1 << 40)}))
    rows.append(base("user count 1 with two rows", users={USER: account(9000, {1: position(10), 2: position(-4)}, count=1), BACK: account(1 << 40)}))
    rows.append(base("user keeps a count", users={USER: account(9000, {1: position(10), 2: position(-4)}, count=7), BACK: account(1 << 40)}))
    rows.append(base("user no positions", rows=[], left=0, users={USER: account(9000, count=0), BACK: account(1 << 40)}))
    rows.append(base("user no positions, count 3", rows=[], left=0, users={USER: account(9000, count=3), BACK: account(1 << 40)}))
    rows.append(base("user zero size row", users={USER: account(9000, {1: position(0), 2: position(-4), 0: position(0)}, count=1), BACK: account(1 << 40)}))
    rows.append(base("user deep tree", markets=4, users={USER: account(9000, {at: position(at + 1) for at in range(30)}), BACK: account(1 << 40)}))
    rows.append(base("user position minimum, cross clear", rows=[(1, 1, 0, 5)], rate=0, users={USER: account(9000, {1: position(I64_MIN + 1), 2: position(I64_MIN)}), BACK: account(1 << 40)}))
    rows.append(base("receiver old row minimum", rows=[(1, 1, 0, 5)], rate=0, users={**both, BACK: account(1 << 40, {1: position(I64_MIN + 1, 0, 5)})}))
    rows.append(isolated("isolated count 1", users={USER: account(77, {1: position(10, 2, 5, 300)}, count=1), BACK: account(1 << 40)}))
    rows.append(isolated("isolated count 0", users={USER: account(77, {1: position(10, 2, 5, 300)}, count=0), BACK: account(1 << 40)}))
    rows.append(isolated("isolated count 3", users={USER: account(77, {1: position(10, 2, 5, 300)}, count=3), BACK: account(1 << 40)}))
    rows.append(isolated("isolated zero size", users={USER: account(77, {1: position(0, 2, 5, 300)}, count=2), BACK: account(1 << 40)}))
    rows.append(isolated("isolated zero size, count 0", users={USER: account(77, {1: position(0, 2, 5, 300)}, count=0), BACK: account(1 << 40)}))
    rows.append(isolated("isolated position minimum", oracles=(1000, 1, 1000, 1000), rate=0, users={USER: account(77, {1: position(I64_MIN, 2, 5, 300)}), BACK: account(1 << 40)}))
    for value, word in ((-1, 500), (-500, 500), (-501, 500), (-(1 << 40), 500), (0, 500), (1, 500), (I64_MIN, 500), (-1, 0), (-1, U64_MAX)):
        rows.append(base("value %d over word %d" % (value, word), value=value, word248=word))
        rows.append(isolated("isolated value %d over word %d" % (value, word), value=value, word248=word))
    return rows


def mixed_cases():
    """A fixed walk over counts, owners and amounts."""
    rows = []
    state = 0x1234567
    def next_word(top):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & U64_MAX
        return (state >> 33) % top
    owners_pool = (HELP, THIRD, LOW)
    for index in range(30):
        count = 1 + next_word(9)
        ids = sorted({next_word(12) for _ in range(count)})
        held = {at: position(next_word(2000) - 1000 or 1, 0, 2 + next_word(9), 0, (1 + at, 2 + at, 3 + at, 4 + at), 3 + at) for at in ids}
        back = {at: position(next_word(40) - 20, 0, 2 + next_word(9), 0, (5 + at, 6 + at, 7 + at, 8 + at), 9 + at) for at in sorted({next_word(12) for _ in range(next_word(6))})}
        owners = {at: owners_pool[next_word(3)] for at in ids if next_word(3) == 0}
        users = {USER: account(next_word(1 << 30) - (1 << 29), held), BACK: account((1 << 45) - next_word(1000), back)}
        for key in owners_pool:
            users[key] = account((1 << 44) + next_word(1 << 40), {3: position(next_word(9), 0, 4)} if next_word(2) else None)
        plan = [(at, held[at][SIZE], next_word(20000) - 10000, held[at][SIZE] * (900 + at)) for at in ids]
        rows.append(base("walk %d" % index, markets=12, oracles=tuple(900 + at for at in range(12)), rows=plan[::-1] if index % 2 else plan, summary=(next_word(1 << 20), 0, sum(abs(item[3]) for item in plan)), left=next_word(41) - 20, users=users, owners=owners,
                         addresses=(BACK,) + tuple(sorted(set(owners.values()))), totals={at: next_word(5000) for at in sorted({next_word(12) for _ in range(5)})}, tracker={BACK: {at: 1 for at in ids[:2]}}, value=next_word(40000) - 20000, once=index % 7 == 0, rate=1 + next_word(2)))
        pick = ids[0]
        side = {pick: position(held[pick][SIZE], 2, held[pick][LEVERAGE], next_word(9000) - 3000, (1, 2, 3, 4), 11)}
        for at in ids[1:]:
            side[at] = held[at]
        rows.append(isolated("walk isolated %d" % index, asset=pick, list=[(1, 0), (1, pick)], markets=12, oracles=tuple(900 + at for at in range(12)), users={USER: account(next_word(1 << 30), side), BACK: account((1 << 45) - next_word(1000), back)}, totals={at: next_word(5000) for at in ids}, value=next_word(40000) - 20000))
    return rows


def all_cases():
    return eligibility_cases() + receiver_cases() + plan_cases() + move_cases() + commit_cases() + mixed_cases()


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x36f57f0", "account read; map pointer and key checked, row given by the case"),
    ("0x3596940", "account entry; map pointer and key checked, row given by the case"),
    ("0x37d7360", "liquidatable row list; account, user, mode 3, dex and oracle pointers checked, rows of 0x30 given. Row words 0 and 1 are what the plan reads"),
    ("0x37d77e0", "account value of the user, 6 arguments checked, word given. Held by open #950"),
    ("0x37d79e0", "account summary; 5 arguments checked. First call on the user gives case words; every clone gets word 0 = balance and word 1 = sum of |size| * rate, so the receiver gate sees the clone contents"),
    ("0x3bd1220", "plan row list; 13 iterator and context words read back and the remainder word written. Rows of 0x20 given. Bound by #746, with its closure 0x37615c0 bound by #954, so neither runs here"),
    ("0x33eb860", "clone of the position tree; source words checked, the tree rebuilt with its bytes"),
    ("0x33e35c0, 0x33f2df0", "clone and drop of the account map at +0x28; words checked, call order recorded"),
    ("0x339b590, 0x33acfe0", "address set add and remove; set pointer +0x158 or +0x188 and key checked"),
    ("0x370e6a0, 0x370e2a0", "leverage notes under +0x128; map or entry pointer, key, id and leverage checked"),
    ("0x399c7a0, 0x399c4a0", "hashes; hasher pointer checked, top byte fixed so that a probe compares keys"),
    ("0x3bfffd0", "default margin of an id; id and dex checked, 16 bytes given"),
    ("0x32d57f0", "item vector growth, doubling from 4"),
)
REAL_HELPERS = (("0x33bd420", "position entry, default row on a miss"), ("0x33bc4d0", "total entry, 0 on a miss"), ("0x3396940", "plan insert of the isolated arm"), ("0x33de780", "account clone"), ("0x3316d60, 0x2fbaa70", "sort and bulk build of plan rows"),
                ("0x33c0ed0, 0x33c2600", "clone map and output map inserts"), ("0x33b0f60, 0x33b25e0, 0x33b4700, 0x33b3840", "map iterators"), ("0x3401de0", "drop of the clones"), ("0x3bb0970", "output rows to a vector"), ("0x2f24930, 0x2f18f20, 0x2f3a270, 0x2f926f0, 0x2f7cd20", "node splits"))
GROUP_REASONS = "cold unwind, panic or allocation failure path"
TALL = "height of 8 or more, not built by the fixtures"
DEAD_COUNT = "size is unchanged in this loop, so the active count and set arms cannot run"
PAD = "field copied by a stub-free path and not read afterwards"
SAME = "both words hold the same value at this point"
ALLOC = "allocation size off by one byte, not visible in the bump heap"
HASHED = "probe group walk; the fixture key is found either way"
LENGTH = "node length read at another offset; poison keys end the walk at the same row"
REASONS = {}
for _start, _end, _text in ((0x3700E70, 0x3700EAE, TALL), (0x37017C0, 0x37017FE, TALL), (0x3700F40, 0x3700F81, TALL), (0x3701890, 0x37018D1, TALL), (0x3702660, 0x370269E, TALL), (0x3702730, 0x3702771, TALL), (0x3702B90, 0x3702BCE, TALL), (0x3702C60, 0x3702CA1, TALL), (0x3703350, 0x370338E, TALL),
                            (0x3703410, 0x3703451, TALL), (0x3700C60, 0x3700C9E, TALL), (0x3700390, 0x37003AB, DEAD_COUNT), (0x370034B, 0x370037D, DEAD_COUNT), (0x3700702, 0x370074C, DEAD_COUNT)):
    for _at in range(_start, _end):
        REASONS[_at] = _text

BODY = "byte of a refusal row past the status and words that are compared"
ROWCOPY = "account row copy; no later read or final compare in these cases tells the moved bytes apart"
INIT = "first word of an iterator, an empty vector or a saturation value that these cases do not tell apart"
MAGIC = "/10000 arithmetic on small ids, where the flipped bit gives the same quotient"
WALK = "key walk step, length offset or unrolled loop bound; the fixture keys end the walk at the same row"
ROOM = "assert bound of a node with room, not hit by the fixtures"
TEXT = "panic text length"
for _at in (0x3700520, 0x370052c, 0x370053c, 0x3700541, 0x3700546, 0x3700690, 0x370069c, 0x37006c4, 0x37006c9, 0x37006ce, 0x3700759, 0x3700765, 0x3700775, 0x370077a, 0x370077f, 0x3700a45, 0x3700a51, 0x3700a75, 0x3700a79, 0x3700a7d,):
    REASONS[_at] = BODY
for _at in (0x33c0f7f, 0x33c0f8c, 0x33c0f9d, 0x33c0fa2, 0x33c0fa7, 0x33c1020, 0x3701513, 0x37023e8, 0x3702409, 0x370244c, 0x370245b, 0x3702460, 0x3702465, 0x37024a3, 0x37024e7, 0x37024f3, 0x3702506, 0x370250a, 0x370253e, 0x3702561, 0x370256b,):
    REASONS[_at] = ROWCOPY
for _at in (0x3316e7d, 0x33969ff, 0x33de818, 0x3700334, 0x3700341, 0x3700597, 0x37013ca, 0x370146f, 0x370161e, 0x37019fa, 0x3701d34, 0x3701d74, 0x3701e16, 0x3701ff8, 0x3702077, 0x3702121, 0x37021b6, 0x37021e9, 0x37021f2, 0x3702296, 0x3702314, 0x37028fa, 0x370300b, 0x37032c8, 0x3703556,):
    REASONS[_at] = INIT
for _at in (0x37000ff, 0x37002c2, 0x37002cf, 0x37002e1, 0x3700951, 0x3700969, 0x370096d,):
    REASONS[_at] = MAGIC
for _at in (0x33bd593, 0x3700194, 0x37001c8, 0x37003cb, 0x370085b, 0x3700cd2, 0x3700df2, 0x3700e4d, 0x3700eea, 0x3700f23, 0x3700f38, 0x3700fe8, 0x3701029, 0x3701308, 0x370131a, 0x3701333, 0x3701748, 0x3701803, 0x3701ac8, 0x3701b09, 0x3702645, 0x37026a3, 0x3702713, 0x3702728, 0x37027e5, 0x3702b75, 0x3702bd3, 0x3702c43, 0x3702c58, 0x3702d15, 0x3702d27, 0x3702d43, 0x3702e20, 0x3702e5a, 0x3702e73, 0x37031f6, 0x3703230, 0x370324a, 0x3703315, 0x3703392, 0x37033f3, 0x3703408, 0x37034f5, 0x370376d, 0x3703784,):
    REASONS[_at] = WALK
for _at in (0x3316df4, 0x3396a08, 0x33bc556, 0x33bd53a, 0x33c0f4a, 0x33c267d,):
    REASONS[_at] = ALLOC
for _at in (0x370369d, 0x37039b0, 0x37039ce, 0x3703bf6,):
    REASONS[_at] = TEXT
for _at in (0x3396a40, 0x33bc588, 0x33bd574, 0x33c0fc7, 0x33c26bc,):
    REASONS[_at] = ROOM


def rows_of(image, start):
    begin, end = image.exact_fde(start)
    return decode_range(image, begin, end)


def groups(image):
    return [("plan", *image.exact_fde(PLAN)), ("position entry", *image.exact_fde(POSITION_ENTRY)), ("total entry", *image.exact_fde(TOTAL_ENTRY)), ("plan insert", *image.exact_fde(PLAN_INSERT)), ("account clone", *image.exact_fde(CLONE_ROW)),
            ("plan rows sort", *image.exact_fde(COLLECT)), ("clone insert", *image.exact_fde(CLONE_INSERT)), ("output insert", *image.exact_fde(ROW_INSERT))]


CONSTANT_SITES = (
    ("list mode", 0x36FFF7E, b"\xb9\x03\x00\x00\x00", 3),
    ("list row stride", 0x36FFFC0, b"\x48\x83\xc1\x30", LIST_STRIDE),
    ("refusal 0x20", 0x370090D, b"\x66\xc7\x00\x20\x00", NOT_ELIGIBLE),
    ("dex step for market ids", 0x37000FF, b"\xb9\x10\x27\x00\x00", DEX_STEP),
    ("refusal 0x21", 0x370028E, b"\x66\xc7\x44\x24\x40\x21\x00", ISOLATED_RECEIVER),
    ("cross tag 0, leverage 20 written as one word", 0x3700300, b"\x48\xba\x00\x00\x00\x00\x14\x00\x00\x00", DEFAULT_LEVERAGE << 32),
    ("row word +0x38 reset", 0x3700322, b"\xc7\x41\x38\x32\x00\x00\x00", DEFAULT_WORD),
    ("refusal 0x22", 0x3701FD1, b"\x66\xc7\x00\x22\x00", RECEIVER_SHORT),
    ("output row stride", 0x3701DAD, b"\x48\x6b\x8c\x24\xe0\x01\x00\x00\x68", ROW_STRIDE),
    ("loss word on the dex row", 0x370388F, b"\x48\x8b\x8e\x48\x02\x00\x00", 0x248),
    ("ok status", 0x37038C6, b"\x66\xc7\x00\x86\x01", OK),
)
STATUS_TABLE = 0x59A8D0


def constants(image):
    rows = []
    for name, va, pattern, value in CONSTANT_SITES:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(pattern)]) != pattern:
            raise EvidenceError("constant moved: " + name)
        rows.append({"name": name, "address": "%#x" % va, "bytes": pattern.hex(), "value": value})
    return rows


def status_text(image, status):
    """Message of a status from the Display table: table entry, then the text lea in that arm (rsi with an edx length, or rdx at a length byte)."""
    entry = struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE + status * 4))[0]
    arm = STATUS_TABLE + entry
    base = image.offset(arm)
    data = bytes(image.blob[base:base + 0x60])
    for at in range(0x50):
        if data[at:at + 3] in (b"\x48\x8d\x35", b"\x48\x8d\x15"):
            target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
            place = image.offset(target)
            if data[at + 2] == 0x35:
                if data[at + 7] != 0xBA:
                    raise EvidenceError("text length")
                size = struct.unpack_from("<I", data, at + 8)[0]
                text = bytes(image.blob[place:place + size])
            else:
                size = image.blob[place]
                text = bytes(image.blob[place + 1:place + 1 + size])
            return arm, target, text.decode("ascii")
    raise EvidenceError("no text in the arm of %#x" % status)


def status_rows(image):
    rows = []
    for status, carried in ((NOT_ELIGIBLE, "user, flag word, asset word"), (ISOLATED_RECEIVER, "asset id at +8"), (RECEIVER_SHORT, "none")):
        arm, target, text = status_text(image, status)
        rows.append(("%#x" % status, status, "%#x" % arm, "%#x" % target, text, carried))
    return rows


def caller_rows(image):
    slot = [address_ for address_, target in relative_slots(image).items() if target == PLAN]
    base, text = image.text_bytes()
    rows = []
    for at in range(len(text) - 6):
        if text[at] == 0xFF and text[at + 1] == 0x15 and base + at + 6 + struct.unpack_from("<i", text, at + 2)[0] in slot:
            rows.append({"site": "%#x" % (base + at), "function": "%#x" % image.fde(base + at)[0]})
    return dict(slots=["%#x" % item for item in slot], callers=rows)


# ---- mutation ----

MUTANT_CASES = 14


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
        for va, at, xor, kind in mutation_targets(image, decode_range(image, begin, end)):
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
        want = Spec(case).run()
    except Panicked as panic:
        return "panic " + str(panic)
    return "status %#x" % want["status"]


def path_rows():
    return [
        ("1", "eligible", "0x36fff10, 0x37d7360", "list mode 3 on the user; flag != 0 needs a row with word 0 == flag and word 1 == id, flag 0 needs a row with word 0 == 0 and ignores word 1; no row = 0x20 with user, flag, id"),
        ("2", "receivers", "0x36fff10, 0x33bd420, 0x33bc4d0", "for every route address and every market id (dex row +0x30 * 10000 + index): add the address to set +0x188, get or make its position row, tag 1 with margin or size != 0 = 0x21 with the id; tag 1 and empty = rewritten as tag 0, leverage 20, words +0x10..+0x37 zero, +0x38 = 50; the total row of the id is rewritten with the same size, and a leverage change is noted at +0x128"),
        ("3", "account value", "0x37d77e0", "read once before the arms with (flag, id); the word is kept for step 13"),
        ("4a", "isolated arm, flag bit 0 set", "0x36fff10, 0x3396940", "one plan row: id -> (size, margin +0x8, oracle * size). Oracle row = dex +0x68 + (id % 10000) * 0x60, word +0x20; negative or a product overflow panics; a missing id panics; tag byte 0 panics"),
        ("4b", "cross arm, flag bit 0 clear", "0x37d79e0, 0x3316d60, 0x2fbaa70", "summary word 0 and word 2 go into the plan row list; rows of 0x20 (id, size, margin share, value) are sorted by insertion below 21 rows and bulk built"),
        ("5", "remainder", "0x36fff10", "the list leaves a remainder in summary word 0. Nonzero: added to the middle word of the first plan row with saturation; no rows: kept for the default receiver"),
        ("6", "receiver of a row", "0x36fff10", "route map id -> address, else the default at route +0x30"),
        ("7", "clones", "0x33de780, 0x33c0ed0", "first use of a receiver clones its account into a map keyed by address; rows run in id order; size += row size saturating; a change clears +0x28, a sign change clears +0x20; 0 to nonzero adds to the count saturating, nonzero to 0 subtracts when above 0; balance += middle word saturating; remainder goes to the default clone balance"),
        ("8", "receiver gate", "0x36fff10, 0x37d79e0", "in address order: word 1 of the clone summary below 0 panics; word 0 - word 1 saturating below 0 = 0x22 with nothing written to accounts; steps 2 and its set adds stay"),
        ("9", "output rows", "0x36fff10, 0x33c2600", "one row of 0x68 per receiver in address order: flag, id, item vector, id word from exchange +0x40 taken at first use saturating, +0x30 unsigned sum of |value| saturating, +0x38 sum of value + middle word saturating, receiver +0x40, user +0x54; remainder adds to +0x38 of the default row, making one when absent"),
        ("10", "commit", "0x3596940, 0x33bc4d0", "in address order the clone replaces the account: every old size leaves the id total, every new size enters it; an id with a new leverage moves its note under +0x128 when that map holds address and id; old +0x28 dropped; count 0 to nonzero adds to set +0x158, nonzero to 0 removes"),
        ("11a", "clear, isolated", "0x36fff10", "user added to set +0x188; size, +0x20, +0x28 and margin of that id are zero; count falls by 1 when size was nonzero and count above 0; total falls by |size|. Balance stays"),
        ("11b", "clear, cross", "0x36fff10", "every tag 0 row: size, +0x20, +0x28 zero and count falls by 1 floor 0 when size was nonzero; total falls by |size|, the row is kept; isolated rows stay; then the user joins set +0x188 and balance = 0"),
        ("12", "active set", "0x36fff10", "user count nonzero to 0 removes from +0x158, 0 to nonzero adds"),
        ("13", "loss word", "0x36fff10", "account value below 0: dex row +0x248 falls by its size, floor 0; i64::MIN panics. Returns 0x186 with the rows"),
    ]


def reference_rows():
    return [
        ("plan body", "trait method execute_liquidation_plan with no body", "0x36fff10, 16386 bytes, is called by the executor copies 0x2725150, 0x4d2b3c0, 0x4d2cd20", "the steps of path-map.tsv have no counterpart in the reference"),
        ("status 32", "absent from LiquidateError", "0x20, carries user, flag, id", "see status-texts.tsv"),
        ("status 33", "absent from LiquidateError", "0x21, carries the id of the first isolated row", "see status-texts.tsv"),
        ("status 34", "absent from LiquidateError", "0x22, no words", "see status-texts.tsv"),
        ("LiquidationPlan", "request carrier with single asset and a per-address asset vector", "route of a 20 byte address vector, map id -> address, default address; per receiver result rows of 0x68", "the name fits the input, the executor reads rows"),
    ]


def sample_rows(image, cases):
    harness = Harness(image)
    rows = []
    wanted = ("cross, no zero flag row", "isolated, flag matches, id differs", "receiver holds isolated margin", "receiver holds isolated size", "receiver empty isolated row becomes cross 20x", "receiver with no rows, decoded isolated", "cross remainder goes to the first row", "cross no rows, remainder to default",
              "receiver margin passes at equality", "receiver margin fails by one", "receiver flips side", "receiver closes to zero", "two receivers", "low address sorts first", "user is the receiver", "user count 0", "user cross with isolated row left", "isolated other row stays", "isolated zero size",
              "value -501 over word 500", "value -1 over word 0", "isolated value -500 over word 500", "output total saturates")
    for case in cases:
        if case["label"] not in wanted:
            continue
        if compare_run(harness, case):
            raise EvidenceError("sample mismatch: " + case["label"])
        want = Spec(case).run()
        user = want["users"][case["user"]]
        rows.append((case["label"], "%#x" % want["status"], len(want["words"]) if want["status"] == OK else 0, "; ".join("%d %d %d" % (row[0], row[1], row[2]) for row in want["words"]) if want["status"] == OK else "", user[0], user[1], want["word"], want["logs"]))
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
        "plan_callers": caller_rows(image),
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
    return evidence, results


def reason_for(row_):
    return REASONS.get(row_["va"], GROUP_REASONS if row_["result"] == "unreached" else UNCLASSIFIED)


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
    write_tsv(out / "status-texts.tsv", ("status", "decimal", "display_arm", "text_address", "text", "words_carried"), status_rows(image))
    write_tsv(out / "samples.tsv", ("label", "status", "output_rows", "row_id_total_amount", "user_balance", "user_count", "dex_word_248", "overflow_logs"), sample_rows(image, all_cases()))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row_ in results:
        reason = "" if row_["result"] == "killed" else reason_for(row_)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row_["group"], row_["va"], row_["kind"], row_["result"], row_["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
