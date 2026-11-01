#!/usr/bin/env python3
"""Pin the node #94 wire form of the bridge validator actions and of BridgeValidatorSet.

Real serializer and deserializer bytes run in an emulator on fixtures. ValidatorSignWithdrawalAction,
VoteEthFinalizedWithdrawalAction, SignValidatorSetUpdateAction and VoteEthFinalizedValidatorSetUpdateAction are
read and written in every form, a validator profile is one "power-validator-signer" string, and profiles sort in
a B-tree set. A separately written rule list predicts every output byte and every error text, and reached rows of
the named functions are edited. No objdump or readelf output is parsed and the binary is never executed.
Standard library only.

    python3 tools/bridge_validator_action_wire.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
import multiprocessing
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

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
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
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


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
        self.relative_map = None
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

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
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


def fdiv(left, right):
    return left / right


def to_float(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & MASK[8]))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

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
        elif byte != 0x2E:
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
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98 and wide:
        return finish("cdqe")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
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
    if byte == 0xCC:
        return finish("int3")
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
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
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
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
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
        if two == 0xAF:
            reg, rm = modrm()
            return finish("imul2", ("r", reg), rm, width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
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
        row.data = bytes(read(va, row.size))
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
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

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
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
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
        elif op == "jmp":
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
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
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
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
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
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
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = fdiv(left, right)
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
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
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



SIGN_MP = 0x1E9E2E0
SIGN_JC = 0x1E9E590
SIGN_JP = 0x1E9EB20
VF_MA = 0x2213720
VF_MP = 0x2213B00
VF_JP = 0x2213D70
VF_JC = 0x2213FE0
SS_MP = 0x1E9CFD0
SS_JC = 0x1E9CEB0
SS_JP = 0x1E9CA00
VS_MP = 0x1EA1B30
VS_JC = 0x1EA18A0
VS_JP = 0x1EA1C80
SET_MP = 0x37DBB10
SET_JP = 0x37DBE50
SET_JC = 0x45A0AC0
DE_SIGN_R = 0x20CFBC0
DE_SIGN_J = 0x213A2F0
DE_VF_R = 0x20E6570
DE_VF_J = 0x212C160
DE_SS_R = 0x20C4C10
DE_SS_J = 0x20FA240
DE_VS_R = 0x2124BF0
DE_VS_J = 0x21349C0
DE_SET_R = 0x210AD70
DE_SET_J = 0x20ACCC0

NAMES = {SIGN_MP: "sign_msgpack", SIGN_JC: "sign_json", SIGN_JP: "sign_pretty", VF_MA: "finalize_msgpack_a", VF_MP: "finalize_msgpack_b", VF_JP: "finalize_pretty", VF_JC: "finalize_json", SS_MP: "set_sign_msgpack", SS_JC: "set_sign_json", SS_JP: "set_sign_pretty", VS_MP: "set_vote_msgpack", VS_JC: "set_vote_json", VS_JP: "set_vote_pretty", SET_MP: "set_msgpack", SET_JP: "set_pretty", SET_JC: "set_json",
         DE_SIGN_R: "sign_from_rmp", DE_SIGN_J: "sign_from_json", DE_VF_R: "finalize_from_rmp", DE_VF_J: "finalize_from_json", DE_SS_R: "set_sign_from_rmp", DE_SS_J: "set_sign_from_json", DE_VS_R: "set_vote_from_rmp", DE_VS_J: "set_vote_from_json", DE_SET_R: "set_from_rmp", DE_SET_J: "set_from_json"}

SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_MEMCMP = 0x576E488
SLOT_REALLOC = 0x576E030
SLOT_BCMP = 0x576E378
STOP_SLOTS = (0x576E470, 0x576E098, 0x576E108, 0x576E020, 0x576E2E0, 0x576E468, 0x576E118)
MARK_BASE = 0x7700000000
# The std backtrace style cache: 1 is "off", so an anyhow error captures nothing.
BACKTRACE_STYLE = 0x5788590
TEXT_LOW, TEXT_HIGH = 0x1343C80, 0x1343C80 + 0x431C430

ARENA = HEAP_BASE + 0x10000
HEAP_USED = 0x40000
ARENA_END = HEAP_BASE + HEAP_USED
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x1000
SERIALIZER = HEAP_BASE + 0x2000
WRITER = SERIALIZER + 0x40
INDENT = HEAP_BASE + 0x4000
TAGS = HEAP_BASE + 0x5000
VARIANT = HEAP_BASE + 0x6000
CONTENT = HEAP_BASE + 0x7000
STATIC_BYTES = HEAP_BASE + 0x8000
TREE = HEAP_BASE + 0xA000
TAG_KEY = "type"
TAG_SIGN = "ValidatorSignWithdrawalAction"
TAG_VF = "VoteEthFinalizedWithdrawalAction"
TAG_SS = "SignValidatorSetUpdateAction"
TAG_VS = "VoteEthFinalizedValidatorSetUpdateAction"
LEAF_SIZE, BRANCH_SIZE = 0x220, 0x280
KEY_SIZE, NODE_KEYS, NODE_PARENT, NODE_INDEX, NODE_LEN, NODE_EDGES = 0x30, 11, 0x210, 0x218, 0x21A, 0x220

NULL, BOOL, U8, U16, U32, U64, I8, I16, I32, I64, F32, F64, CHAR, STRING, STR, BYTEBUF, BYTES, NONE, SOME, UNIT, NEWTYPE, SEQ, MAP = "null", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21
LONG_STEP_LIMIT = 600000
MUTANT_STEP_LIMIT = LONG_STEP_LIMIT


class Con:
    """One serde Content value; `kind` is the enum byte."""

    def __init__(self, kind, value=None):
        self.kind, self.value = kind, value

    def __repr__(self):
        return "Con(%s, %r)" % (self.kind, self.value)


def wrap(value):
    """Plain python shapes to Content: str, int, list, dict, Con."""
    if isinstance(value, Con):
        return value
    if isinstance(value, bool):
        return Con(BOOL, value)
    if isinstance(value, str):
        return Con(STRING, value)
    if isinstance(value, int):
        return Con(U64, value)
    if isinstance(value, list):
        return Con(SEQ, [wrap(item) for item in value])
    if isinstance(value, dict):
        return Con(MAP, [(wrap(key), wrap(item)) for key, item in value.items()])
    raise EvidenceError("no content form")


class TextRange:
    """Every call into .text runs real bytes; only the marked slots are hooks."""

    def __contains__(self, va):
        return TEXT_LOW <= va < TEXT_HIGH


class Harness:
    def __init__(self, image, patches=None, cache=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = TextRange()
        machine.memory.statics = image.static_view()
        table = {SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_MEMCPY: self.on_copy, SLOT_MEMMOVE: self.on_copy, SLOT_MEMCMP: self.on_compare, SLOT_BCMP: self.on_compare, SLOT_REALLOC: self.on_realloc}
        for slot in STOP_SLOTS:
            table[slot] = self.on_stop
        for slot, hook in table.items():
            machine.slots[MARK_BASE + slot] = hook
        if cache:
            machine.cache = dict(cache)
            for va in (patches or {}):
                for back in range(16):
                    machine.cache.pop(va - back, None)
        self.top = ARENA
        self.live = {}

    def expect(self, condition, text):
        if not condition:
            raise Halt("fixture check failed: " + text)

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def data(self, at, size):
        return self.machine.memory.bytes_at(at, size)

    def write(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def put(self, at, data):
        self.machine.memory.put_bytes(at, data)

    def alloc(self, size):
        at = self.top
        self.top += (size + 15) & ~15
        if self.top > ARENA_END:
            raise Halt("fixture arena full")
        self.live[at] = size
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.get(at) == size, "freed block size")
        del self.live[at]

    def on_realloc(self, machine):
        old, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(old in self.live, "realloc of a live block")
        at = self.alloc(size)
        self.put(at, self.data(old, min(size, self.live[old])))
        del self.live[old]
        machine.regs[RAX] = at

    def on_copy(self, machine):
        self.put(machine.regs[RDI], self.data(machine.regs[RSI], machine.regs[RDX]))
        machine.regs[RAX] = machine.regs[RDI]

    def on_compare(self, machine):
        left, right = self.data(machine.regs[RDI], machine.regs[RDX]), self.data(machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = 0 if left == right else 1 if left > right else MASK[4]

    def on_stop(self, machine):
        raise Panicked("panic path reached")

    def fresh(self):
        self.machine.memory.reset(HEAP_USED)
        self.top = ARENA
        self.live = {}

    def put_signature(self, at, signature):
        self.write(at, signature.r, 8)
        for limb in range(4):
            self.write(at + 8 * limb, signature.r >> (64 * limb))
            self.write(at + 0x20 + 8 * limb, signature.s >> (64 * limb))
        self.write(at + 0x40, signature.v, 1)

    def put_tree(self, at, rows):
        """A two level tree at TREE, or one leaf. Layout read from a real decode."""
        self.next_node = TREE
        if len(rows) <= NODE_KEYS:
            root, height = self.put_leaf(rows), 0
        else:
            root, height = self.next_node, 1
            self.next_node += BRANCH_SIZE
            pieces = [rows[start:start + NODE_KEYS + 1] for start in range(0, len(rows), NODE_KEYS + 1)]
            if len(pieces[-1]) == NODE_KEYS + 1:
                pieces.append([])
            self.expect(len(pieces) <= NODE_KEYS + 1, "two levels only")
            edge = 0
            for index, piece in enumerate(pieces):
                last = index == len(pieces) - 1
                leaf = self.put_leaf(piece if last else piece[:NODE_KEYS])
                self.write(leaf + NODE_PARENT, root)
                self.write(leaf + NODE_INDEX, edge, 2)
                self.write(root + NODE_EDGES + 8 * edge, leaf)
                edge += 1
                if not last:
                    self.put_key(root + KEY_SIZE * index, piece[NODE_KEYS])
            self.write(root + NODE_PARENT, 0)
            self.write(root + NODE_LEN, len(pieces) - 1, 2)
        self.write(at, root if rows else 0)
        self.write(at + 8, height)
        self.write(at + 0x10, len(rows))

    def put_key(self, at, row):
        self.write(at, row[0])
        self.put(at + 8, row[1])
        self.put(at + 0x1C, row[2])

    def put_leaf(self, rows):
        node = self.next_node
        self.next_node += LEAF_SIZE
        for index, row in enumerate(rows):
            self.put_key(node + KEY_SIZE * index, row)
        self.write(node + NODE_PARENT, 0)
        self.write(node + NODE_LEN, len(rows), 2)
        return node

    def put_action(self, action):
        kind = action.kind
        if kind == "sign":
            self.write(ACTION, action.usd)
            self.write(ACTION + 8, action.nonce)
            self.put_signature(ACTION + 0x10, action.signature)
            self.put(ACTION + 0x58, action.user)
            self.put(ACTION + 0x6C, action.destination)
        elif kind == "vf":
            self.put(ACTION, action.digest)
            self.write(ACTION + 0x20, action.nonce)
            self.write(ACTION + 0x28, action.usd)
            self.put(ACTION + 0x30, action.user)
            self.put(ACTION + 0x44, action.destination)
        else:
            self.put_tree(ACTION, action.profiles)
            self.write(ACTION + 0x18, action.epoch)
            if kind == "ss":
                self.put_signature(ACTION + 0x20, action.signature)

    def vector(self, at, capacity):
        pointer = self.alloc(capacity) if capacity else 1
        self.write(at, capacity)
        self.write(at + 8, pointer)
        self.write(at + 16, 0)

    def write_form(self, entry, subject, named, capacity):
        """Run one writer on the action at `subject`; returns the bytes."""
        form = FORMS[entry]
        run = self.machine.run
        if form[0] == "a":
            self.vector(SERIALIZER, capacity)
            self.write(SERIALIZER + 0x18, 0)
            self.write(SERIALIZER + 0x1B, named, 1)
            sink, vector = SERIALIZER, SERIALIZER
        elif form[0] == "b":
            self.vector(WRITER, capacity)
            self.write(SERIALIZER, WRITER)
            self.write(SERIALIZER + 8, 0)
            self.write(SERIALIZER + 0xB, named, 1)
            sink, vector = SERIALIZER, WRITER
        else:
            self.vector(WRITER, capacity)
            self.put(INDENT, b"  ")
            self.write(SERIALIZER, WRITER)
            self.write(SERIALIZER + 8, INDENT)
            self.write(SERIALIZER + 16, 2)
            self.write(SERIALIZER + 0x18, 0)
            self.write(SERIALIZER + 0x20, 0, 1)
            sink, vector = SERIALIZER, WRITER
        target = sink
        tag = TAGNAMES.get(form[1])
        if tag:
            self.put(TAGS, (TAG_KEY + tag).encode())
            self.write(VARIANT + 0x20, TAGS)
            self.write(VARIANT + 0x28, len(TAG_KEY))
            self.write(VARIANT + 0x30, TAGS + len(TAG_KEY))
            self.write(VARIANT + 0x38, len(tag))
            self.write(VARIANT + 0x40, sink)
            target = VARIANT
        if form[0] in ("j", "c"):
            if form[0] == "c":
                self.write(SERIALIZER + 8, 0)
                self.expect(run(entry, {RDI: subject, RSI: target}) == 0, "compact json status")
            else:
                self.expect(run(entry, {RDI: subject, RSI: target}) == 0, "json status")
        else:
            run(entry, {RDI: OUT, RSI: subject, RDX: target})
            status = self.read(OUT)
            self.expect(status == 0x8000000000000004, "serializer status %#x" % status)
        return self.data(self.read(vector + 8), self.read(vector + 16)), vector

    def serialize(self, case):
        self.fresh()
        self.put_action(case.action)
        data, vector = self.write_form(case.entry, ACTION, case.named, case.capacity)
        self.expect(set(self.live) <= {self.read(vector + 8)}, "only the writer stays allocated")
        return data

    def lay(self, at, value):
        kind = value.kind
        self.write(at, kind, 1)
        if kind in (STRING, BYTEBUF):
            data = value.value.encode() if isinstance(value.value, str) else value.value
            pointer = self.alloc(len(data)) if data else HEAP_BASE + 1
            self.put(pointer, data)
            self.write(at + 8, len(data))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(data))
        elif kind in (STR, BYTES):
            data = value.value.encode() if isinstance(value.value, str) else value.value
            self.put(self.static_top, data)
            self.write(at + 8, self.static_top)
            self.write(at + 0x10, len(data))
            self.static_top += (len(data) + 15) & ~15
        elif kind in (U8, I8, BOOL):
            self.write(at + 1, value.value, 1)
        elif kind in (U16, I16):
            self.write(at + 2, value.value, 2)
        elif kind in (U32, I32):
            self.write(at + 4, value.value, 4)
        elif kind in (U64, I64):
            self.write(at + 8, value.value)
        elif kind == NEWTYPE or kind == SOME:
            pointer = self.alloc(0x20)
            self.write(at + 8, pointer)
            self.lay(pointer, value.value)
        elif kind == SEQ:
            rows = value.value
            pointer = self.alloc(0x20 * len(rows)) if rows else 16
            self.write(at + 8, len(rows))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(rows))
            for index, row in enumerate(rows):
                self.lay(pointer + 0x20 * index, row)
        elif kind == MAP:
            rows = value.value
            pointer = self.alloc(0x40 * len(rows)) if rows else 16
            self.write(at + 8, len(rows))
            self.write(at + 0x10, pointer)
            self.write(at + 0x18, len(rows))
            for index, (key, row) in enumerate(rows):
                self.lay(pointer + 0x40 * index, key)
                self.lay(pointer + 0x40 * index + 0x20, row)
        elif kind not in (NONE, UNIT):
            raise Halt("content kind")

    def json_text(self, word):
        """The message of a boxed serde_json error."""
        self.expect(word in self.live, "json error box")
        pointer, size = self.read(word + 8), self.read(word + 16)
        self.expect(self.read(word) == 0 and pointer in self.live, "json error code is Message")
        return self.data(pointer, size).decode(), {word, pointer}

    def read_tree(self, at):
        """The keys in order and every node, from the real tree at `at`."""
        root, height, count = self.read(at), self.read(at + 8), self.read(at + 0x10)
        rows, nodes = [], set()

        def walk(node, level, parent, index):
            self.expect(node in self.live, "tree node is a live block")
            nodes.add(node)
            self.expect(self.live[node] == (BRANCH_SIZE if level else LEAF_SIZE), "node size")
            self.expect(self.read(node + NODE_PARENT) == parent, "node parent")
            if parent:
                self.expect(self.read(node + NODE_INDEX, 2) == index, "node parent index")
            length = self.read(node + NODE_LEN, 2)
            self.expect(0 < length <= NODE_KEYS, "node length")
            for slot in range(length + 1):
                if level:
                    walk(self.read(node + NODE_EDGES + 8 * slot), level - 1, node, slot)
                if slot < length:
                    key = node + KEY_SIZE * slot
                    rows.append((self.read(key), self.data(key + 8, 20).hex(), self.data(key + 0x1C, 20).hex()))

        if count:
            walk(root, height, 0, 0)
        else:
            self.expect(root == 0, "empty tree has no root")
        self.expect(len(rows) == count, "tree count")
        return tuple(rows), nodes

    def read_signature(self, at):
        word = int.from_bytes(self.data(at, 32), "little"), int.from_bytes(self.data(at + 0x20, 32), "little"), self.read(at + 0x40, 1)
        return ("%x" % word[0], "%x" % word[1], word[2])

    def read_value(self, kind, at):
        """Decoded fields and the blocks they own."""
        if kind == "sign":
            return (self.read(at), self.read(at + 8)) + self.read_signature(at + 0x10) + (self.data(at + 0x58, 20).hex(), self.data(at + 0x6C, 20).hex()), set()
        if kind == "vf":
            return (self.data(at, 32).hex(), self.read(at + 0x20), self.read(at + 0x28), self.data(at + 0x30, 20).hex(), self.data(at + 0x44, 20).hex()), set()
        rows, nodes = self.read_tree(at)
        fields = (rows, self.read(at + 0x18))
        if kind == "ss":
            fields += self.read_signature(at + 0x20)
        return fields, nodes

    def decode_value(self, case):
        self.fresh()
        self.static_top = STATIC_BYTES
        self.lay(CONTENT, case.value)
        form = DE_FORMS[case.entry]
        self.machine.run(case.entry, {RDI: OUT, RSI: CONTENT})
        return form

    def deserialize(self, case):
        """Run one Content deserializer. Returns ("ok", fields) or ("error", text)."""
        form = self.decode_value(case)
        word = self.read(OUT)
        if word == 1:
            if form[0] == "j":
                text, kept = self.json_text(self.read(OUT + 8))
            else:
                self.expect(self.read(OUT + 8, 1) == 6, "rmp error tag")
                pointer, size = self.read(OUT + 0x18), self.read(OUT + 0x20)
                text, kept = self.data(pointer, size).decode(), {pointer}
            self.expect(set(self.live) == kept, "only the error stays allocated, %s" % sorted(self.live))
            return ("error", text)
        self.expect(word == 0, "result word")
        fields, nodes = self.read_value(form[1], OUT + 8)
        self.expect(set(self.live) == nodes, "ok leaves only tree nodes allocated")
        return ("ok",) + fields

    def trip(self, case):
        """Decode, then write the decoded value with a real writer."""
        self.decode_value(case)
        self.expect(self.read(OUT) == 0, "round trip decode")
        self.put(ACTION, self.data(OUT + 8, 0x90))
        return self.write_form(case.writer, ACTION, 1, 0x1000)[0]


FORMS = {SIGN_MP: ("b", "sign"), SIGN_JC: ("c", "sign"), SIGN_JP: ("j", "sign"), VF_MA: ("a", "vf"), VF_MP: ("b", "vf"), VF_JP: ("j", "vf"), VF_JC: ("c", "vf"), SS_MP: ("b", "ss"), SS_JC: ("c", "ss"), SS_JP: ("j", "ss"), VS_MP: ("b", "vs"), VS_JC: ("c", "vs"), VS_JP: ("j", "vs"), SET_MP: ("b", "set"), SET_JP: ("j", "set"), SET_JC: ("c", "set")}
DE_FORMS = {DE_SIGN_R: ("r", "sign"), DE_SIGN_J: ("j", "sign"), DE_VF_R: ("r", "vf"), DE_VF_J: ("j", "vf"), DE_SS_R: ("r", "ss"), DE_SS_J: ("j", "ss"), DE_VS_R: ("r", "vs"), DE_VS_J: ("j", "vs"), DE_SET_R: ("r", "set"), DE_SET_J: ("j", "set")}
TAGNAMES = {"sign": TAG_SIGN, "vf": TAG_VF, "ss": TAG_SS, "vs": TAG_VS}


def static_view(self):
    if self.static_map is None:
        table = dict(self.relative())
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_MEMCPY, SLOT_MEMMOVE, SLOT_MEMCMP, SLOT_BCMP, SLOT_REALLOC) + STOP_SLOTS:
            table[slot] = MARK_BASE + slot
        table[BACKTRACE_STYLE] = 1
        self.static_map = table
    return self.static_map


Image.static_view = static_view
Image.static_map = None
class Bad(Exception):
    """A rule-list refusal; the text is the expected error."""


class Sig:
    def __init__(self, r=0x80818283, s=0xA0A1A2A3 << 200, v=27):
        self.r, self.s, self.v = r, s, v


class Act:
    def __init__(self, kind, **fields):
        self.kind = kind
        self.usd, self.nonce, self.epoch = 5, 0x100, 77
        self.user, self.destination = bytes(range(0x40, 0x54)), bytes(range(0x60, 0x74))
        self.digest = bytes(range(0xC0, 0xE0))
        self.signature = Sig()
        self.profiles = [(9, bytes(range(1, 21)), bytes(range(0x21, 0x35)))]
        self.__dict__.update(fields)


class Ser:
    def __init__(self, name, entry, action, named=1, capacity=0x1000):
        self.name, self.entry, self.action, self.named, self.capacity = name, entry, action, named, capacity


class De:
    def __init__(self, name, entry, value):
        self.name, self.entry, self.value = name, entry, wrap(value)


class Trip:
    def __init__(self, name, entry, writer, value):
        self.name, self.entry, self.writer, self.value = name, entry, writer, wrap(value)


def run_case(harness, case):
    if isinstance(case, Ser):
        return ("bytes", harness.serialize(case).hex())
    if isinstance(case, Trip):
        return ("bytes", harness.trip(case).hex())
    return harness.deserialize(case)


def mp_uint(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return bytes([0xCC, value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def mp_str(text):
    data = text.encode()
    if len(data) < 32:
        return bytes([0xA0 | len(data)]) + data
    if len(data) < 256:
        return bytes([0xD9, len(data)]) + data
    return b"\xda" + len(data).to_bytes(2, "big") + data


def mp_head(base, count):
    if count < 16:
        return bytes([base | count])
    return (b"\xdc" if base == 0x90 else b"\xde") + count.to_bytes(2, "big")


class Arr(list):
    """A wire array; a plain list of pairs is a struct."""


def mp_pack(item, named):
    if isinstance(item, int):
        return mp_uint(item)
    if isinstance(item, str):
        return mp_str(item)
    if isinstance(item, Arr):
        return mp_head(0x90, len(item)) + b"".join(mp_pack(row, named) for row in item)
    head = mp_head(0x80 if named else 0x90, len(item))
    return head + b"".join((mp_str(key) if named else b"") + mp_pack(value, named) for key, value in item)


def json_compact(item):
    if isinstance(item, int):
        return str(item)
    if isinstance(item, str):
        return '"%s"' % item
    if isinstance(item, Arr):
        return "[" + ",".join(json_compact(row) for row in item) + "]"
    return "{" + ",".join('"%s":%s' % (key, json_compact(value)) for key, value in item) + "}"


def json_pretty(item, depth=0):
    if isinstance(item, int):
        return str(item)
    if isinstance(item, str):
        return '"%s"' % item
    pad = "  " * (depth + 1)
    if isinstance(item, Arr):
        if not item:
            return "[]"
        return "[\n" + ",\n".join(pad + json_pretty(row, depth + 1) for row in item) + "\n" + "  " * depth + "]"
    rows = ['%s"%s": %s' % (pad, key, json_pretty(value, depth + 1)) for key, value in item]
    return "{\n" + ",\n".join(rows) + "\n" + "  " * depth + "}"


def word_text(value):
    return "0x%x" % value


def signature_shape(signature):
    return [("r", word_text(signature.r)), ("s", word_text(signature.s)), ("v", signature.v)]


def profile_text(row):
    return "%d-0x%s-0x%s" % (row[0], row[1].hex(), row[2].hex())


def set_shape(action):
    return [("profiles", Arr(profile_text(row) for row in action.profiles)), ("epoch", action.epoch)]


def shape(action):
    kind = action.kind
    if kind == "sign":
        rows = [("user", "0x" + action.user.hex()), ("destination", "0x" + action.destination.hex()), ("usd", action.usd), ("nonce", action.nonce), ("signature", signature_shape(action.signature))]
    elif kind == "vf":
        rows = [("user", "0x" + action.user.hex()), ("destination", "0x" + action.destination.hex()), ("nonce", action.nonce), ("usd", action.usd), ("ethTxHash", "0x" + action.digest.hex())]
    elif kind == "ss":
        rows = [("validatorSet", set_shape(action)), ("signature", signature_shape(action.signature))]
    elif kind == "vs":
        rows = [("validatorSet", set_shape(action))]
    else:
        return set_shape(action)
    return [(TAG_KEY, TAGNAMES[kind])] + rows


def packed(entry, item, named):
    family = FORMS[entry][0]
    if family == "j":
        return json_pretty(item).encode()
    if family == "c":
        return json_compact(item).encode()
    return mp_pack(item, named)


def spec_ser(case):
    return ("bytes", packed(case.entry, shape(case.action), case.named).hex())


def describe(value, flavor):
    kind = value.kind
    if kind == BOOL:
        return "boolean `%s`" % ("true" if value.value else "false")
    if kind in (U8, U16, U32, U64):
        return "integer `%d`" % value.value
    if kind in (I8, I16, I32, I64):
        return "integer `%d`" % signed(value)
    if kind in (STRING, STR):
        return 'string "%s"' % value.value
    if kind in (BYTES, BYTEBUF):
        return "byte array"
    if kind in (NONE, SOME):
        return "Option value"
    if kind == UNIT:
        return "null" if flavor == "j" else "unit value"
    if kind == NEWTYPE:
        return "newtype struct"
    if kind == SEQ:
        return "sequence"
    return "map"


def signed(value):
    bits = {I8: 8, I16: 16, I32: 32, I64: 64}[value.kind]
    return value.value - (1 << bits) if value.value >> (bits - 1) else value.value


def spec_number(value, flavor, top, label):
    if value.kind in (U8, U16, U32, U64):
        number = value.value
    elif value.kind in (I8, I16, I32, I64):
        number = signed(value)
    else:
        raise Bad("invalid type: %s, expected %s" % (describe(value, flavor), label))
    if number < 0 or number > top:
        raise Bad("invalid value: integer `%d`, expected %s" % (number, label))
    return number


def spec_u64(value, flavor):
    return spec_number(value, flavor, MASK[8], "u64")


def spec_u8(value, flavor):
    return spec_number(value, flavor, 0xFF, "u8")


def spec_hex(value, size, flavor):
    expected = "a (both 0x-prefixed or not) hex string or byte array containing %d bytes" % size
    if value.kind in (BYTES, BYTEBUF):
        if len(value.value) != size:
            raise Bad("invalid length %d, expected %s" % (len(value.value), expected))
        return bytes(value.value).hex()
    if value.kind not in (STRING, STR):
        raise Bad("invalid type: %s, expected %s" % (describe(value, flavor), expected))
    data = value.value.encode()
    skip = 2 if data[:2] == b"0x" else 0
    body = data[skip:]
    if len(body) != 2 * size:
        raise Bad("invalid length %d, expected %s" % (len(body), expected))
    for index, byte in enumerate(body):
        if byte not in b"0123456789abcdefABCDEF":
            raise Bad("invalid hex character: %s, at %d" % (chr(byte), index + skip))
    return body.decode().lower()


def spec_word(value, flavor):
    expected = "a (both 0x-prefixed or not) hex string or byte array containing between (0; 32] bytes"
    if value.kind in (BYTES, BYTEBUF):
        if not 0 < len(value.value) <= 32:
            raise Bad("invalid length %d, expected %s" % (len(value.value), expected))
        return "%x" % int.from_bytes(bytes(value.value), "big")
    if value.kind not in (STRING, STR):
        raise Bad("invalid type: %s, expected %s" % (describe(value, flavor), expected))
    data = value.value.encode()
    skip = 2 if data[:2] == b"0x" else 0
    body = data[skip:]
    if not 0 < len(body) <= 64:
        raise Bad("invalid length %d, expected %s" % (len(body), expected))
    for index, byte in enumerate(body):
        if byte not in b"0123456789abcdefABCDEF":
            raise Bad("invalid hex character: %s, at %d" % (chr(byte), index + skip))
    return "%x" % int(body.decode(), 16)


def field_index(key, names, deny, flavor):
    """The position of a map key, or None when the key is ignored."""
    if key.kind in (STRING, STR, BYTES, BYTEBUF):
        name = key.value if key.kind in (STRING, STR) else bytes(key.value).decode()
        if name in names:
            return names.index(name)
        if deny:
            listed = ", ".join("`%s`" % item for item in names)
            if len(names) == 2:
                raise Bad("unknown field `%s`, expected `%s` or `%s`" % (name, names[0], names[1]))
            raise Bad("unknown field `%s`, expected %s" % (name, listed if len(names) == 1 else "one of " + listed))
        return None
    if key.kind in (U8, U64):
        if key.value < len(names):
            return key.value
        if deny:
            raise Bad("invalid value: integer `%d`, expected field index 0 <= i < %d" % (key.value, len(names)))
        return None
    raise Bad("invalid type: %s, expected field identifier" % describe(key, flavor))


def spec_struct(value, name, names, readers, deny, flavor):
    """Sequence and map forms of one derived struct."""
    count = len(names)
    plural = "%d element%s" % (count, "" if count == 1 else "s")
    if value.kind == SEQ:
        rows = value.value
        found = []
        for index, reader in enumerate(readers):
            if index >= len(rows):
                raise Bad("invalid length %d, expected struct %s with %s" % (index, name, plural))
            found.append(reader(rows[index], flavor))
        if len(rows) > count:
            raise Bad("invalid length %d, expected %s in sequence" % (len(rows), plural))
        return found
    if value.kind != MAP:
        raise Bad("invalid type: %s, expected struct %s" % (describe(value, flavor), name))
    found = [None] * count
    for key, item in value.value:
        index = field_index(key, names, deny, flavor)
        if index is None:
            continue
        if found[index] is not None:
            raise Bad("duplicate field `%s`" % names[index])
        found[index] = readers[index](item, flavor)
    for index, label in enumerate(names):
        if found[index] is None:
            raise Bad("missing field `%s`" % label)
    return found


def unwrap(value):
    return value.value if value.kind == NEWTYPE else value


def unwrap_all(value):
    while value.kind == NEWTYPE:
        value = value.value
    return value


def spec_address(value, flavor):
    return spec_hex(unwrap_all(value), 20, flavor)


def spec_usd(value, flavor):
    return spec_u64(unwrap(value), flavor)


def spec_nonce(value, flavor):
    return spec_u64(unwrap(value), flavor)


def spec_hash(value, flavor):
    return spec_hex(value, 32, flavor)


def parse_address(text):
    body = text[2:] if text[:2] == "0x" else text
    if len(body) != 40 or any(item not in "0123456789abcdefABCDEF" for item in body):
        raise Bad("Failed to parse user address")
    return body.lower()


def spec_profile_text(text):
    parts = text.split("-")
    if len(parts) != 3:
        raise Bad("Invalid input")
    digits = parts[0][1:] if parts[0][:1] == "+" else parts[0]
    if not digits or any(item not in "0123456789" for item in digits) or int(digits) > MASK[8]:
        raise Bad("Invalid input number")
    return (int(digits), parse_address(parts[1]), parse_address(parts[2]))


def spec_profile(value, flavor):
    if value.kind in (STRING, STR):
        return spec_profile_text(value.value)
    if value.kind in (BYTES, BYTEBUF):
        try:
            return spec_profile_text(bytes(value.value).decode())
        except UnicodeDecodeError:
            raise Bad("invalid value: byte array, expected a string")
    raise Bad("invalid type: %s, expected a string" % describe(value, flavor))


def spec_profiles(value, flavor):
    if value.kind != SEQ:
        raise Bad("invalid type: %s, expected a sequence" % describe(value, flavor))
    return tuple(sorted(set(spec_profile(item, flavor) for item in value.value), key=lambda row: (row[0], row[1], row[2])))


def spec_epoch(value, flavor):
    return spec_u64(unwrap(value), flavor)


def spec_set(value, flavor):
    return spec_struct(value, "BridgeValidatorSet", ("profiles", "epoch"), (spec_profiles, spec_epoch), False, flavor)


def spec_wrapped_set(value, flavor):
    return spec_set(unwrap(value), flavor)


def spec_signature(value, flavor):
    return spec_struct(value, "Signature", ("r", "s", "v"), (spec_word, spec_word, spec_u8), False, flavor)


SIGN_FIELDS = ("user", "destination", "usd", "nonce", "signature")
VF_FIELDS = ("user", "destination", "nonce", "usd", "ethTxHash")
SS_FIELDS = ("validatorSet", "signature")
VS_FIELDS = ("validatorSet",)


def spec_value(kind, value, flavor):
    if kind == "sign":
        user, destination, usd, nonce, signature = spec_struct(value, "ValidatorSignWithdrawalAction", SIGN_FIELDS, (spec_address, spec_address, spec_usd, spec_nonce, spec_signature), True, flavor)
        return (usd, nonce) + tuple(signature) + (user, destination)
    if kind == "vf":
        user, destination, nonce, usd, digest = spec_struct(value, "VoteEthFinalizedWithdrawalAction", VF_FIELDS, (spec_address, spec_address, spec_nonce, spec_usd, spec_hash), True, flavor)
        return (digest, nonce, usd, user, destination)
    if kind == "ss":
        rows, signature = spec_struct(value, "SignValidatorSetUpdateAction", SS_FIELDS, (spec_wrapped_set, spec_signature), True, flavor)
        return tuple(rows) + tuple(signature)
    if kind == "vs":
        return tuple(spec_struct(value, "VoteEthFinalizedValidatorSetUpdateAction", VS_FIELDS, (spec_wrapped_set,), True, flavor)[0])
    return tuple(spec_set(value, flavor))


def spec_de(case):
    family, kind = DE_FORMS[case.entry]
    try:
        return ("ok",) + spec_value(kind, case.value, family)
    except Bad as error:
        return ("error", error.args[0])


def spec_trip(case):
    family, kind = DE_FORMS[case.entry]
    fields = spec_value(kind, case.value, family)
    rows, epoch = fields[0], fields[1]
    profiles = [(row[0], bytes.fromhex(row[1]), bytes.fromhex(row[2])) for row in rows]
    action = Act(FORMS[case.writer][1], profiles=profiles, epoch=epoch)
    if kind == "ss":
        action.signature = Sig(int(fields[2], 16), int(fields[3], 16), fields[4])
    return ("bytes", packed(case.writer, shape(action), 1).hex())


def spec_run(case):
    if isinstance(case, Ser):
        return spec_ser(case)
    if isinstance(case, Trip):
        return spec_trip(case)
    return spec_de(case)


USER = "0x" + bytes(range(0x40, 0x54)).hex()
DEST = "0x" + bytes(range(0x60, 0x74)).hex()
WORD_R = "0x" + bytes(range(0x80, 0xA0)).hex()
WORD_S = "0x" + bytes(range(0xA0, 0xC0)).hex()
HASH = "0x" + bytes(range(0xC0, 0xE0)).hex()
GOOD_SIG = {"r": WORD_R, "s": WORD_S, "v": 27}
GOOD_SET = {"profiles": ["7-%s-%s" % (USER, DEST), "5-%s-%s" % (DEST, USER)], "epoch": 77}
GOOD = {"sign": {"user": USER, "destination": DEST, "usd": 100000000, "nonce": 1793483835000, "signature": GOOD_SIG},
        "vf": {"user": USER, "destination": DEST, "nonce": 1793483835000, "usd": 100000000, "ethTxHash": HASH},
        "ss": {"validatorSet": GOOD_SET, "signature": GOOD_SIG}, "vs": {"validatorSet": GOOD_SET}, "set": GOOD_SET}
FIELD_NAMES = {"sign": SIGN_FIELDS, "vf": VF_FIELDS, "ss": SS_FIELDS, "vs": VS_FIELDS, "set": ("profiles", "epoch")}
EDGES = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, MASK[8])


def changed(base, **items):
    out = dict(base)
    for key, item in items.items():
        if item is None:
            del out[key]
        else:
            out[key] = item
    return out


def map_of(*rows):
    return Con(MAP, [(wrap(key), wrap(item)) for key, item in rows])


def number(kind, value):
    return Con(kind, value)


UNIT_VALUE = Con(UNIT)
NUMBER_FORMS = {"u8": number(U8, 200), "u16": number(U16, 2000), "u32": number(U32, 70000), "u64": number(U64, MASK[8]), "i8": number(I8, 5), "i16": number(I16, 3), "i32": number(I32, 4), "i64": number(I64, 7), "i8_minus": number(I8, 0xFF), "i16_minus": number(I16, 0xFFFE), "i32_minus": number(I32, 0xFFFFFFFD), "i64_minus": number(I64, MASK[8]),
                "text": "1", "str": Con(STR, "x"), "true": True, "unit": UNIT_VALUE, "none": Con(NONE), "some": Con(SOME, number(U64, 1)), "newtype": Con(NEWTYPE, number(U64, 9)), "newtype_newtype": Con(NEWTYPE, Con(NEWTYPE, number(U64, 9))), "newtype_text": Con(NEWTYPE, wrap("x")), "seq": [], "map": {}, "bytes": Con(BYTES, b"a")}
BYTE_FORMS = {"max": 255, "over": 256, "zero": 0, "u8": number(U8, 28), "u16": number(U16, 28), "u16_big": number(U16, 300), "u32": number(U32, 28), "i8": number(I8, 28), "i8_minus": number(I8, 0xFF), "i64": number(I64, 28), "text": "27", "unit": UNIT_VALUE, "none": Con(NONE), "newtype": Con(NEWTYPE, number(U8, 28)), "seq": [], "true": True}


def hex_forms(text):
    bare = text[2:]
    size = len(bare) // 2
    return {"bare": bare, "upper": "0x" + bare.upper(), "bare_upper": bare.upper(), "cap_prefix": "0X" + bare, "double_prefix": "0x0x" + bare[4:], "short": "0x" + bare[:-2], "odd": "0x" + bare[:-1], "long": "0x" + bare + "aa", "empty": "", "prefix_only": "0x", "bad": "0x" + "zz" * size, "bad_last": "0x" + bare[:-1] + "g", "str": Con(STR, text), "bytes": Con(BYTES, bytes(range(size))), "bytebuf": Con(BYTEBUF, bytes(range(size))), "bytes_short": Con(BYTES, bytes(size - 1)), "bytes_long": Con(BYTEBUF, bytes(size + 1)), "int": 5, "seq": [1], "unit": UNIT_VALUE, "none": Con(NONE), "true": True, "map": {}, "newtype": Con(NEWTYPE, wrap(text)), "newtype_newtype": Con(NEWTYPE, Con(NEWTYPE, wrap(text))), "newtype_int": Con(NEWTYPE, number(U64, 1))}


WORD_FORMS = dict(hex_forms(WORD_R), one="0x1", one_bare="1", zero="0x0", leading="0x0000abc", odd_three="abc", max="0x" + "ff" * 32, too_long="0x" + "1" * 65, bytes_one=Con(BYTES, b"\x01"), bytes_empty=Con(BYTES, b""), bytes_leading=Con(BYTES, b"\x00\x00\x07"), bytes_33=Con(BYTES, bytes(33)))
ADDRESS_LOW = USER
PROFILE_FORMS = {"plain": "5-%s-%s" % (USER, DEST), "zero": "0-%s-%s" % (USER, DEST), "plus": "+5-%s-%s" % (USER, DEST), "padded": "005-%s-%s" % (USER, DEST), "max": "%d-%s-%s" % (MASK[8], USER, DEST), "over": "%d-%s-%s" % (1 << 64, USER, DEST), "minus": "-5-%s-%s" % (USER, DEST), "no_prefix": "5-%s-%s" % (USER[2:], DEST[2:]), "mixed_prefix": "5-%s-%s" % (USER[2:], DEST), "upper_digits": "5-0x%s-0x%s" % (USER[2:].upper(), DEST[2:].upper()), "cap_prefix": "5-0X%s-%s" % (USER[2:], DEST), "two_parts": "5-%s" % USER, "four_parts": "5-%s-%s-1" % (USER, DEST), "empty": "", "just_number": "5", "dashes": "--", "number_only_dashes": "5--", "text_number": "x-%s-%s" % (USER, DEST), "space": " 5-%s-%s" % (USER, DEST), "plus_only": "+-%s-%s" % (USER, DEST), "hex_number": "0x5-%s-%s" % (USER, DEST), "short_first": "5-0x12-%s" % DEST, "short_second": "5-%s-0x12" % USER, "both_bad": "5-zz-yy", "bad_digit": "5-0x%s-%s" % ("g" * 40, DEST), "long_first": "5-%s00-%s" % (USER, DEST), "colon": "5:%s:%s" % (USER, DEST), "str": Con(STR, "5-%s-%s" % (USER, DEST)), "bytes": Con(BYTES, b"5-a-b"), "bytes_utf8_bad": Con(BYTES, b"5-\xff-b"), "bytebuf_utf8_bad": Con(BYTEBUF, b"\xff"), "bytebuf": Con(BYTEBUF, ("5-%s-%s" % (USER, DEST)).encode()), "int": 5, "seq": ["5", USER, DEST], "map": {"a": 1}, "unit": UNIT_VALUE, "none": Con(NONE), "true": True, "newtype": Con(NEWTYPE, wrap("5-%s-%s" % (USER, DEST)))}


def struct_cases(kind, deny_probe=True):
    good = GOOD[kind]
    names = FIELD_NAMES[kind]
    ordered = [good[name] for name in names]
    cases = [("good", good), ("reordered", dict(reversed(list(good.items())))), ("seq_good", ordered), ("seq_long", ordered + [1]), ("extra_key", changed(good, z=1)), ("extra_first", map_of(*([("z", 1)] + list(good.items())))), ("extra_value", changed(good, z={"a": [1, "b"]})), ("near_key", changed(good, **{names[0] + "2": 1})), ("case_key", map_of((names[0].upper(), 1))), ("int_keys", map_of(*[(index, item) for index, item in enumerate(ordered)])), ("int_key_over", map_of((len(names), 1))), ("u8_key", map_of((number(U8, 0), ordered[0]))), ("u8_key_over", map_of((number(U8, 9), 1))), ("u16_key", map_of((number(U16, 0), 1))), ("i8_key", map_of((number(I8, 0), 1))), ("bool_key", map_of((True, 1))), ("unit_key", map_of((UNIT_VALUE, 1))), ("bytes_keys", map_of(*[(Con(BYTES, name.encode()), good[name]) for name in names])), ("bytebuf_keys", map_of(*[(Con(BYTEBUF, name.encode()), good[name]) for name in names])), ("str_keys", map_of(*[(Con(STR, name), good[name]) for name in names])), ("bytes_key_unknown", map_of((Con(BYTES, b"q"), 1))),
             ("not_unit", UNIT_VALUE), ("not_int", 5), ("not_text", "x"), ("not_true", True), ("not_none", Con(NONE)), ("not_some", Con(SOME, wrap(good))), ("not_newtype", Con(NEWTYPE, wrap(good))), ("not_bytes", Con(BYTES, b"a")), ("seq_empty", [])]
    for count in range(1, len(names)):
        cases.append(("seq_short_%d" % count, ordered[:count]))
    for mask in range(1 << len(names)):
        cases.append(("subset_%02d" % mask, dict((name, good[name]) for bit, name in enumerate(names) if mask >> bit & 1)))
    for name in names:
        cases.append(("dup_" + name, map_of((name, good[name]), (name, good[name]))))
    return cases


def field_cases(kind):
    good = GOOD[kind]
    cases = []
    for name in FIELD_NAMES[kind]:
        if name in ("user", "destination"):
            forms = hex_forms(USER)
        elif name in ("usd", "nonce", "epoch"):
            forms = NUMBER_FORMS
        elif name == "ethTxHash":
            forms = hex_forms(HASH)
        elif name == "signature":
            forms = dict({"seq": [WORD_R, WORD_S, 27], "seq_short": [WORD_R], "seq_long": [WORD_R, WORD_S, 27, 1], "empty": {}, "extra": changed(GOOD_SIG, w=1), "joined": WORD_R + WORD_S[2:] + "1b", "int": 5, "unit": UNIT_VALUE, "newtype": Con(NEWTYPE, wrap(GOOD_SIG)), "dup_r": map_of(("r", WORD_R), ("r", WORD_R)), "no_v": {"r": WORD_R, "s": WORD_S}, "no_s": {"r": WORD_R, "v": 1}, "int_keys": map_of((0, WORD_R), (1, WORD_S), (2, 27)), "key_3": map_of((3, 1), (0, WORD_R), (1, WORD_S), (2, 1))})
            for label, form in WORD_FORMS.items():
                forms["r_" + label] = changed(GOOD_SIG, r=form)
            for label in ("one", "max", "too_long", "bad", "int"):
                forms["s_" + label] = changed(GOOD_SIG, s=WORD_FORMS[label])
            for label, form in BYTE_FORMS.items():
                forms["v_" + label] = changed(GOOD_SIG, v=form)
        elif name == "validatorSet":
            forms = {"seq": [GOOD_SET["profiles"], 7], "empty": {"profiles": [], "epoch": 0}, "int": 5, "unit": UNIT_VALUE, "newtype": Con(NEWTYPE, wrap(GOOD_SET)), "newtype_newtype": Con(NEWTYPE, Con(NEWTYPE, wrap(GOOD_SET))), "no_epoch": {"profiles": []}, "no_profiles": {"epoch": 1}, "bad_profile": {"profiles": ["x"], "epoch": 1}, "extra": changed(GOOD_SET, z=1), "text": "x"}
        else:
            forms = {"seq_empty": [], "map": {}, "int": 5, "unit": UNIT_VALUE, "text": "x", "newtype": Con(NEWTYPE, Con(SEQ, [])), "none": Con(NONE), "some": Con(SOME, Con(SEQ, [])), "bytes": Con(BYTES, b"a"), "bool": True}
            for label, form in PROFILE_FORMS.items():
                forms["one_" + label] = [form]
            forms["after_good"] = [PROFILE_FORMS["plain"], "x"]
        for label, form in forms.items():
            cases.append(("%s_%s" % (name, label), changed(good, **{name: form})))
    return cases


def order_lists():
    low = "0x" + "00" * 19 + "01"
    high = "0x" + "ff" * 20
    mid = "0x" + "01" + "00" * 19
    rows = {"reverse": ["%d-%s-%s" % (value, USER, DEST) for value in (300, 256, 1, 0)], "dup": ["5-%s-%s" % (USER, DEST)] * 3, "dup_forms": ["5-%s-%s" % (USER, DEST), "+5-%s-%s" % (USER[2:], DEST), "05-%s-%s" % (USER, DEST)], "same_power": ["5-%s-%s" % (high, USER), "5-%s-%s" % (mid, USER), "5-%s-%s" % (low, USER)], "same_validator": ["5-%s-%s" % (USER, high), "5-%s-%s" % (USER, mid), "5-%s-%s" % (USER, low)], "power_first": ["9-%s-%s" % (low, low), "1-%s-%s" % (high, high)], "validator_second": ["5-%s-%s" % (mid, low), "5-%s-%s" % (low, high)]}
    for count in (12, 13):
        rows["size_%d" % count] = ["%d-%s-%s" % ((value * 37) % 101, USER, DEST) for value in range(count)]
    return rows


def named_cases():
    cases = []
    sigs = {"zero": Sig(0, 0, 0), "one": Sig(1, 2, 28), "small": Sig(0xABC, 0xF, 255), "high": Sig(1 << 255, (1 << 256) - 1, 27), "limb": Sig(1 << 64, 1 << 128, 1), "nibble": Sig(0x1000, 0x10, 16)}
    for entry in sorted(FORMS):
        family, kind = FORMS[entry]
        label = NAMES[entry]
        for named in ((1, 0) if family in ("a", "b") else (1,)):
            tail = "_named" if family in ("a", "b") and named else "_compact" if family in ("a", "b") else ""
            base = lambda **items: Act(kind, **items)
            cases.append(Ser(label + tail + "_base", entry, base(), named))
            if kind in ("sign", "vf"):
                for value in EDGES:
                    cases.append(Ser("%s%s_usd_%x" % (label, tail, value), entry, base(usd=value), named))
                    cases.append(Ser("%s%s_nonce_%x" % (label, tail, value), entry, base(nonce=value), named))
                cases.append(Ser(label + tail + "_zero_bytes", entry, base(user=bytes(20), destination=bytes(20), digest=bytes(32)), named))
                cases.append(Ser(label + tail + "_ff_bytes", entry, base(user=b"\xff" * 20, destination=b"\xff" * 20, digest=b"\xff" * 32), named))
            if kind in ("sign", "ss"):
                for name, signature in sigs.items():
                    cases.append(Ser("%s%s_sig_%s" % (label, tail, name), entry, base(signature=signature), named))
            if kind in ("ss", "vs", "set"):
                for value in (0, 0x7F, 0x80, 0x100, 0x10000, MASK[8]):
                    cases.append(Ser("%s%s_epoch_%x" % (label, tail, value), entry, base(epoch=value), named))
                    cases.append(Ser("%s%s_power_%x" % (label, tail, value), entry, base(profiles=[(value, bytes(20), b"\xff" * 20)]), named))
                for count in (0, 1, 2, 12, 14):
                    rows = [(index, bytes([index]) * 20, bytes([255 - index]) * 20) for index in range(count)]
                    cases.append(Ser("%s%s_size_%d" % (label, tail, count), entry, base(profiles=rows), named))
            for capacity in (0, 3, 8, 40, 90):
                cases.append(Ser("%s%s_capacity_%d" % (label, tail, capacity), entry, base(), named, capacity))
    for entry in sorted(DE_FORMS):
        family, kind = DE_FORMS[entry]
        label = NAMES[entry]
        rows = struct_cases(kind) + field_cases(kind)
        # The json flavor shares every rule but the unit text; a third of its cases keeps the run short.
        for name, value in (rows if family == "r" else rows[:1] + rows[1::3] + [row for row in rows if row[0] == "not_unit"]):
            cases.append(De("%s_%s" % (label, name), entry, value))
    writers = {"ss": SS_JC, "vs": VS_JC, "set": SET_JC}
    for entry in sorted(DE_FORMS):
        family, kind = DE_FORMS[entry]
        if kind not in writers or family != "r":
            continue
        for name, rows in order_lists().items():
            value = changed(GOOD[kind], validatorSet=changed(GOOD_SET, profiles=rows)) if kind != "set" else changed(GOOD_SET, profiles=rows)
            cases.append(De("%s_order_%s" % (NAMES[entry], name), entry, value))
            cases.append(Trip("%s_trip_%s" % (NAMES[entry], name), entry, writers[kind], value))
    return cases


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 16


def vector_cases(count):
    cases = []
    random = lcg(0xB21)
    writers, decoders = sorted(FORMS), sorted(DE_FORMS)

    def blob(size):
        return bytes(next(random) & 0xFF for _ in range(size))

    def value():
        width = next(random) % 49
        return next(random) >> (48 - width)

    def word():
        return int.from_bytes(blob(32), "big") >> (next(random) % 257)

    for index in range(count):
        user, destination, digest = blob(20), blob(20), blob(32)
        signature = Sig(word(), word(), next(random) & 0xFF)
        rows = sorted((value(), blob(20), blob(20)) for _ in range(next(random) % 15))
        if index % 2:
            entry = writers[next(random) % len(writers)]
            action = Act(FORMS[entry][1], usd=value(), nonce=value(), epoch=value(), user=user, destination=destination, digest=digest, signature=signature, profiles=rows)
            cases.append(Ser("vector_%03d" % index, entry, action, next(random) & 1, next(random) % 240))
            continue
        entry = decoders[next(random) % len(decoders)]
        kind = DE_FORMS[entry][1]
        sign_map = {"r": "0x%x" % max(signature.r, 1), "s": "%X" % max(signature.s, 1), "v": signature.v}
        wire_set = {"profiles": ["%d-0x%s-%s" % (row[0], row[1].hex(), row[2].hex()) for row in rows], "epoch": value()}
        values = {"sign": {"user": "0x" + user.hex(), "destination": destination.hex(), "usd": value(), "nonce": value(), "signature": sign_map}, "vf": {"user": "0x" + user.hex(), "destination": destination.hex(), "usd": value(), "nonce": value(), "ethTxHash": "0x" + digest.hex()}, "ss": {"validatorSet": wire_set, "signature": sign_map}, "vs": {"validatorSet": wire_set}, "set": wire_set}
        cases.append(De("vector_%03d" % index, entry, values[kind]))
    return cases


def describe_case(case, outcome):
    if outcome[0] == "bytes":
        return outcome[1]
    if outcome[0] == "error":
        return "error: " + outcome[1].encode("unicode_escape").decode().replace("@", "\\x40")
    return "ok: " + " ".join(str(item) for item in outcome[1:])


def check_all(harness, cases):
    done = []
    for case in cases:
        got = run_case(harness, case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("case %s differs: %s against %s" % (case.name, got, want))
        done.append((case, got))
    return done
HELPERS = {0x37A0F80: "profile_parse", 0x209D0B0: "profile_string_rmp", 0x209D1D0: "profile_string_json", 0x2853C00: "profile_seq_collect", 0x3BC9210: "profile_tree_helper", 0x3BB0FD0: "split_collect", 0x20B97A0: "signature_from_rmp", 0x20CA000: "signature_from_json", 0x204D2F0: "word_from_rmp", 0x204D6B0: "word_from_json", 0x219B770: "signature_msgpack", 0x295E910: "signature_struct_json", 0x295F5F0: "signature_key_json", 0x2962130: "set_key_json", 0x296E1D0: "set_key_pretty", 0x37DAD30: "profiles_msgpack", 0x4C20E50: "profiles_json"}
NAMES.update(HELPERS)
TARGETS = tuple(sorted(NAMES))
STATUS_FORMATTER = 0x37FFD40
STATUS_TABLE = 0x59A8D0
STATUS_TEXT = ((0x13F, 0x59E415, "Invalid input number"), (0x140, 0x59E415, "Invalid input"), (0xB6, 0x59D6D7, "Failed to parse user address"))
FIELD_TEXT = ((0x209EBC, "user"), (0x3BF83C, "destination"), (0x3BF847, "usd"), (0x3BF790, "nonce"), (0x3BF7D3, "signature"), (0x3C005B, "validatorSet"), (0x3D371B, "ethTxHash"), (0x20B048, "profiles"), (0x3BF81F, TAG_SIGN), (0x20C3A0, TAG_VF), (0x3BF7B7, TAG_SS), (0x3BF904, TAG_VS), (0x20A074, "type"))
KEY_ROWS = ((0x1E9E5A9, "sign writer: five fields", "mov"), (0x1E9E5EE, "sign user at +0x58", "lea"), (0x1E9E618, "sign destination at +0x6c", "lea"), (0x1E9E66F, "sign nonce at +8", "lea"), (0x1E9E699, "sign signature at +0x10", "add"), (0x1E9CEC9, "set sign writer: two fields", "mov"), (0x1E9CF2F, "set sign signature at +0x20", "add"), (0x1EA18B9, "set vote writer: one field", "mov"), (0x2828C9B, "caller, sign tag", "lea"), (0x2829B37, "caller, set sign tag", "lea"), (0x2829E56, "caller, finalize tag", "lea"), (0x2829737, "caller, set vote tag", "lea"),
            (0x37A0FCB, "profile split: separator char 0x2d in both words", "mov"), (0x37A0FFE, "status 0x140 first", "mov"), (0x37A1002, "exactly three parts", "cmp"), (0x37A1018, "status 0x13f for the number", "mov"), (0x37A1047, "a lone + is refused", "cmp"), (0x37A1050, "a lone - is refused", "cmp"), (0x37A1077, "up to 16 digits cannot overflow", "cmp"), (0x37A10EC, "longer numbers are checked", "mul"), (0x37A111B, "validator address parse", "calli"), (0x37A1153, "signer address parse", "calli"), (0x37A116A, "status 0xb6 for an address", "mov"), (0x37A11E0, "status 0x186 is success", "mov"))
SERIALIZER_COPIES = ((0x3349870, SIGN_MP), (0x46E40D0, SIGN_MP), (0x46E3CD0, SIGN_JC), (0x3349B20, SIGN_JP), (0x46E3E60, SIGN_JP), (0x334A9C0, VF_MA), (0x46E4750, VF_MA), (0x334A710, VF_MP), (0x46E4B50, VF_MP), (0x334ADB0, VF_JP), (0x46E44F0, VF_JP), (0x46E4380, VF_JC), (0x342F120, SS_MP), (0x46E2860, SS_MP), (0x46E2740, SS_JC), (0x342EE70, SS_JP), (0x46E2A00, SS_JP), (0x342FF70, VS_MP), (0x46E6650, VS_MP), (0x46E6180, VS_JC), (0x342FD30, VS_JP), (0x46E6410, VS_JP), (0x28D3970, SET_MP), (0x45A0BE0, SET_MP), (0x45A0880, SET_JP))
DECODER_COPIES = ((0x3AD0DB0, DE_SIGN_R), (0x4BAD3B0, DE_SIGN_R), (0x3A858A0, DE_SIGN_J), (0x3AB5FD0, DE_VF_R), (0x4BA6C70, DE_VF_R), (0x3A796E0, DE_VF_J), (0x3AA0380, DE_SS_R), (0x4B95D10, DE_SS_R), (0x3AC9460, DE_SS_J), (0x3A67A80, DE_VS_R), (0x4BABB00, DE_VS_R), (0x3A84D60, DE_VS_J), (0x3A6A6B0, DE_SET_R), (0x4B94E70, DE_SET_R), (0x3A639C0, DE_SET_J))
COPY_STEP = 13
MUTANT_SCENARIOS = 6
WORKERS = 4
SAMPLE_EVERY = 4
SURVIVED = "class: equal outcome on every picked case that reaches the row, such as a spill slot, a register choice or a word no rule reads"
MUTANT_STATE = {}


def row_at(image, va):
    return decode(lambda at, count: bytes(image.blob[image.offset(at):image.offset(at) + count]), va)


def edits_for(image, rows):
    edits = []
    for row in rows:
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, cases, wants):
    for case, want in zip(cases, wants):
        try:
            if run_case(harness, case) != want:
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, UnicodeDecodeError, struct.error):
            return case
    return None


def spread(items, count):
    """The cheapest half of the picked count and an even walk over the rest, so rare cases stay in."""
    if len(items) <= count:
        return items
    head = items[:count // 2]
    rest = items[count // 2:]
    step = len(rest) / (count - count // 2)
    return head + [rest[int(index * step)] for index in range(count - count // 2)]


def mutant_job(job):
    va, kind, patch = job
    state = MUTANT_STATE
    picked = spread([case for case in state["order"] if va in state["reach"][case.name]], MUTANT_SCENARIOS)
    harness = Harness(state["image"], patch, state["cache"])
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    hit = first_failure(harness, picked, [state["wants"][case.name] for case in picked])
    return va, kind, "killed" if hit is not None else "survived", hit.name if hit is not None else SURVIVED


def run_mutants(image, table, cases):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    wants, reach, cost = {}, {}, {}
    for case in cases:
        control.machine.seen = set()
        before = control.machine.steps
        got = run_case(control, case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("an unedited image fails on %s" % case.name)
        wants[case.name], reach[case.name], cost[case.name] = want, control.machine.seen, control.machine.steps - before
    order = sorted(cases, key=lambda item: (cost[item.name], item.name))
    jobs = []
    for target in sorted(table):
        jobs += edits_for(image, table[target])[::SAMPLE_EVERY]
    MUTANT_STATE.update(image=image, order=order, reach=reach, wants=wants, cache=control.machine.cache)
    with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
        return pool.map(mutant_job, jobs, 8)


def key_rows(image):
    out = []
    for va, text, op in KEY_ROWS:
        row = row_at(image, va)
        if row.op != op:
            raise EvidenceError("row %#x is %s" % (va, row.op))
        out.append(("%#x" % image.fde(va)[0], "%#x" % va, bytes(image.blob[image.offset(va):image.offset(va) + row.size]).hex(), op, text))
    return out


def text_rows(image):
    rows = []
    for at, text in FIELD_TEXT:
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(text)]).decode()
        if data != text:
            raise EvidenceError("text at %#x is %s" % (at, data))
        rows.append(("%#x" % at, text))
    return rows


def status_rows(image):
    """Status tag to Display text, from the u16 jump table of the status formatter."""
    rows = []
    for tag, at, text in STATUS_TEXT:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE) + 4 * tag)[0]
        data = bytes(image.blob[image.offset(at):image.offset(at) + len(text)]).decode()
        if data != text or image.fde(arm)[0] != STATUS_FORMATTER:
            raise EvidenceError("status row %#x" % tag)
        rows.append(("%#x" % tag, "%#x" % arm, "%#x" % at, text))
    return rows


def copy_rows(image, harness, cases):
    rows = []
    for copy, base in SERIALIZER_COPIES:
        FORMS[copy] = FORMS[base]
        count = 0
        for item in cases:
            if isinstance(item, Ser) and item.entry == base:
                count += 1
                if count % 11 == 0:
                    case = Ser("copy", copy, item.action, item.named, item.capacity)
                    if run_case(harness, case) != spec_ser(case):
                        raise EvidenceError("copy %#x differs" % copy)
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, NAMES[base], "%#x" % base, count // 11))
        del FORMS[copy]
    for copy, base in DECODER_COPIES:
        DE_FORMS[copy] = DE_FORMS[base]
        count = 0
        for item in cases:
            if isinstance(item, De) and item.entry == base:
                count += 1
                if count % COPY_STEP == 0:
                    case = De("copy", copy, item.value)
                    if run_case(harness, case) != spec_de(case):
                        raise EvidenceError("copy %#x differs on %s" % (copy, item.name))
        rows.append(("%#x" % copy, image.exact_fde(copy)[1] - copy, NAMES[base], "%#x" % base, count // COPY_STEP))
        del DE_FORMS[copy]
    return rows


def samples():
    signature = Sig(0xABC, 1 << 255, 28)
    rows = [(5, bytes(range(1, 21)), bytes(range(0x21, 0x35))), (300, bytes(20), b"\xff" * 20)]
    out = []
    for entry in sorted(FORMS):
        for named in ((1, 0) if FORMS[entry][0] in ("a", "b") else (1,)):
            out.append(Ser("sample", entry, Act(FORMS[entry][1], usd=100000000, nonce=1793483835000, signature=signature, profiles=rows), named))
    return out


def analyse(image, mutate=True, vectors=200):
    harness = Harness(image)
    harness.machine.step_limit = LONG_STEP_LIMIT
    cases = named_cases()
    named = check_all(harness, cases)
    generated = vector_cases(vectors)
    check_all(harness, generated)
    seen = set(harness.machine.seen)
    table = {}
    for target in TARGETS:
        low, high = image.exact_fde(target)
        table[target] = [row_at(image, va) for va in sorted(seen) if low <= va < high]
        for row in table[target]:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    wire = [(NAMES[case.entry], case.named, harness.serialize(case).hex()) for case in samples()]
    result = dict(table=table, named=named, vector_count=vectors, keys=key_rows(image), texts=text_rows(image), status=status_rows(image), copies=copy_rows(image, harness, cases), wire=wire, sizes={target: image.exact_fde(target)[1] - target for target in TARGETS})
    if mutate:
        result["mutations"] = run_mutants(image, table, [case for case, _ in named][::3] + generated[:10])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    table = result["table"]
    sizes = result["sizes"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, bytes(row.data).hex(), row.op) for target in TARGETS for row in table[target]])
    tsv("path.tsv", ("name", "address", "body_bytes", "reached_rows", "reached_bytes"), [(NAMES[target], "%#x" % target, sizes[target], len(table[target]), sum(row.size for row in table[target])) for target in TARGETS])
    tsv("texts.tsv", ("address", "text"), result["texts"])
    tsv("status.tsv", ("tag", "formatter_arm", "text_at", "text"), result["status"])
    tsv("copies.tsv", ("copy", "body_bytes", "same_rules_as", "primary", "cases_matched"), result["copies"])
    tsv("wire-samples.tsv", ("function", "named", "bytes"), result["wire"])
    tsv("key-rows.tsv", ("function", "at", "bytes", "operation", "note"), result["keys"])
    rows = []
    for case, trace in result["named"]:
        if trace[0] == "bytes":
            rows.append((case.name, "%d bytes sha256 %s" % (len(trace[1]) // 2, hashlib.sha256(trace[1].encode()).hexdigest()[:16])))
        else:
            rows.append((case.name, describe_case(case, trace)))
    tsv("scenarios.tsv", ("case", "outcome"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in result["mutations"]])
    named = result["named"]
    reached = sum(row.size for rows in table.values() for row in rows)
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "functions": len(TARGETS), "instructions": sum(len(items) for items in table.values()), "named_scenarios": len(named), "serializer_cases": sum(1 for case, _ in named if isinstance(case, Ser)), "decoder_cases": sum(1 for case, _ in named if isinstance(case, De)), "round_trip_cases": sum(1 for case, _ in named if isinstance(case, Trip)), "vector_scenarios": result["vector_count"], "body_bytes": sum(sizes.values()), "reached_bytes": reached, "unreached_rows": sum(sizes.values()) - reached, "copies": len(result["copies"])}
    if "mutations" in result:
        items = result["mutations"]
        summary["mutations"] = {"total": len(items), "killed": sum(1 for item in items if item[2] == "killed"), "survived": sum(1 for item in items if item[2] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
