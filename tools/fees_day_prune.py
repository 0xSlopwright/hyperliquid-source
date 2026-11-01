#!/usr/bin/env python3
"""Pin the node #94 volume day tree prune from ELF bytes: gate 0x26ff350 and copies, dex and clearinghouse prunes, row walk, B-tree split.

The whole path runs in a Python evaluator on real tree nodes and real hash tables. A separately written specification predicts every
tree's rows, its length word, its node blocks and every other byte, and every condition, immediate and field offset of the path is
flipped to show the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
"""

import argparse
import bisect
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

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 = range(16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_MARK = 0xA5
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x30000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 300000


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
            if value not in (0, 5):
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd" if value == 0 else "cmpnltsd", ("x", reg), rm, 8)
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
        self.frame = 0

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
        self.regs[RSP] = STACK_TOP - 0x100 - self.frame
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
        elif op == "cmpnltsd":
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            self.set_low(row.a[1], 0 if left < right else MASK[8])
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




def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


CAPACITY = 11


_decode_plain = decode


def decode(read, va):
    """One extra prefix: an fs load decodes to a row the evaluator refuses to step."""
    if read(va, 1)[0] == 0x64:
        row = _decode_plain(lambda at, count: read(at + 1, count), va)
        return Insn(va, row.size + 1, "fsload")
    return _decode_plain(read, va)


GATES = (0x26FF350, 0x4CE8920, 0x4CE8A30)
LIST_AT = (0x5C0, 0x1040, 0x5C0)
DEX_PRUNE = 0x36FF620
CH_PRUNE = 0x371FB70
COLLECT_DEX = 0x3BC9A80
COLLECT_CH = 0x3BD4F30
PAR_DEX = 0x38DCD40
PAR_CH = 0x38DC9E0
DRIVE_DEX = 0x3403EC0
DRIVE_CH = 0x3403AC0
LEAF = 0x388DE00
SPLIT = 0x2FB5180
BORDER = 0x2FB2440
LENGTHS = 0x2FB2A60
DROP = 0x33F2DF0
DATE_ADD = 0x151F870
THREAD = 0x4E17630
SLOT_DATE = 0x576E8B0
SLOT_DEX = 0x5774928
SLOT_CH = 0x5774930
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_COPY = 0x576DFE0
SLOT_ONCE = 0x576E8B8
SLOT_MOVE = 0x576E0E0
SLOT_PANIC = 0x576E468
SLOT_NONE = 0x576E470
SLOT_REGISTRY = 0x5773298
ONCE_CELL = 0x577AB98
LOC_DATE = 0x566AA98
LOC_NONE = 0x56E9FA0
DATE_TEXT = 0x219CB3
DATE_TEXT_SIZE = 0x22
WINDOW = 20
PREV = HEAP_BASE + 0x40
CELL = HEAP_BASE + 0x80
GLOBAL = HEAP_BASE + 0xC0
STATE = HEAP_BASE + 0x100
STATE_SIZE = 0x1100
REGISTRY = HEAP_BASE + 0x1300
WORKER = HEAP_BASE + 0x1600
BUMP = HEAP_BASE + 0x2000
DEX_SIZE = 0x2F0
CAPACITY = 11
LEAF_SIZE = 0xE8
INNER_SIZE = 0x148
PARENT = 0xB0
KEYS = 0xB8
SLOT_AT = 0xE4
COUNT = 0xE6
EDGES = 0xE8
MIN_YEAR = -262143
MAX_YEAR = 262142
DEX_MAP = dict(table=0xF8, tree=0x258, stride=0x78)
CH_OFFSET = 0x80
CH_MAP = dict(table=0x298, tree=0x358, stride=0x58)
ROW_VALUE = 0x18
ROW_TREE = 0x28


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & (1 << 31) else value


# ---- calendar, written from the Gregorian rule and not from the binary tables ----

def days_from_civil(year, month, day):
    year -= month <= 2
    era = year // 400
    of_era = year - era * 400
    of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    of_cycle = of_era * 365 + of_era // 4 - of_era // 100 + of_year
    return era * 146097 + of_cycle - 719468


def year_of(days):
    shifted = days + 719468
    era = shifted // 146097
    of_cycle = shifted - era * 146097
    of_era = (of_cycle - of_cycle // 1460 + of_cycle // 36524 - of_cycle // 146096) // 365
    of_year = of_cycle - (365 * of_era + of_era // 4 - of_era // 100)
    month = (5 * of_year + 2) // 153
    return of_era + era * 400 + (month >= 10)


def leap(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def pack(days):
    """chrono packed date: year << 13, ordinal << 4, year flags in the low 4 bits."""
    year = year_of(days)
    first = days_from_civil(year, 1, 1)
    weekday = (first + 3) % 7
    flags = (weekday + 5) % 7 + 1
    return signed32(year << 13 | (days - first + 1) << 4 | (0 if leap(year) else 8) | flags)


def unpack(packed):
    return days_from_civil(packed >> 13, 1, 1) + ((packed >> 4) & 0x1FF) - 1


def date_add(packed, delta):
    days = unpack(packed) + delta
    if not MIN_YEAR <= year_of(days) <= MAX_YEAR:
        return None
    return pack(days)


# ---- specification ----

def fewest(level):
    """Smallest row count of a non-root node at this level above the leaves."""
    return 5 if level == 0 else 6 * fewest(level - 1) + 5


class Tree:
    """Sorted (key, word 0, word 1) rows, and two damaged forms a real tree can take."""

    def __init__(self, items=(), hollow=False, lost=False, thin=False):
        self.items = sorted(items)
        self.hollow = hollow
        self.lost = lost
        self.thin = thin


def spec(case):
    """Outcome and every tree's rows after the step, in the order the rows are visited."""
    trees = dict((name, list(tree.items)) for name, tree in case_trees(case))
    if case["prev"] >= case["date"]:
        return dict(outcome="skipped", trees=trees)
    cutoff = date_add(case["date"], -WINDOW)
    if cutoff is None:
        return dict(outcome=LOC_DATE, trees=trees)
    for name, tree in case_trees(case):
        if tree.lost:
            return dict(outcome=LOC_NONE, trees=trees)
        trees[name] = [row for row in tree.items if row[0] >= cutoff]
    return dict(outcome="pruned", trees=trees)


def case_trees(case):
    """Visit order: each dex total then its rows by slot, then the clearinghouse the same way."""
    out = []
    for index, dex in enumerate(case["dexes"]):
        out.append((("dex", index, "total"), dex["total"]))
        for slot in sorted(dex["rows"]):
            out.append((("dex", index, slot), dex["rows"][slot]))
    out.append((("ch", 0, "total"), case["ch"]["total"]))
    for slot in sorted(case["ch"]["rows"]):
        out.append((("ch", 0, slot), case["ch"]["rows"][slot]))
    return out


# ---- evaluator ----

class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        machine.memory.reset()
        machine.real = REAL
        machine.jump_ranges = [image.exact_fde(start) for start in REAL]
        machine.step_limit = 400000
        machine.calls = {THREAD: self.on_thread}
        table = ((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_COPY, self.on_copy), (SLOT_MOVE, self.on_copy), (SLOT_ONCE, self.on_once),
                 (SLOT_PANIC, self.on_panic), (SLOT_NONE, self.on_none), (SLOT_REGISTRY, self.on_registry))
        for at, (slot, hook) in enumerate(table):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        machine.memory.statics[SLOT_DATE] = DATE_ADD
        machine.memory.statics[SLOT_DEX] = DEX_PRUNE
        machine.memory.statics[SLOT_CH] = CH_PRUNE
        self.at = BUMP
        self.case = None

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def check(self, condition, text):
        if not condition:
            raise Halt(text)

    def on_thread(self, machine):
        self.check(machine.regs[RDI] == 0, "thread index")
        machine.regs[RAX] = CELL

    def on_registry(self, machine):
        machine.regs[RAX] = GLOBAL

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        self.check(size in (LEAF_SIZE, INNER_SIZE) or (size % 16 == 0 and 0 < size <= 0x4000), "alloc size")
        where = self.bump(size)
        self.live[where] = size
        machine.regs[RAX] = where

    def on_free(self, machine):
        regs = machine.regs
        where, size = regs[RDI], regs[RSI]
        self.check(self.live.get(where) == size and regs[RDX] == 0, "free of %#x size %#x" % (where, size))
        del self.live[where]
        machine.memory.put_bytes(where, b"\xdd" * size)

    def on_copy(self, machine):
        regs = machine.regs
        self.check(regs[RDX] < 0x400, "copy size")
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_once(self, machine):
        self.check(machine.regs[RDI] == ONCE_CELL and machine.regs[RSI] & 0xFF == 1, "once args")
        self.once += 1

    def on_panic(self, machine):
        self.check(machine.regs[RDI] == DATE_TEXT and machine.regs[RSI] == DATE_TEXT_SIZE, "panic text")
        raise Panicked(machine.regs[RDX])

    def on_none(self, machine):
        raise Panicked(machine.regs[RDI])

    def node(self, level):
        where = self.bump(INNER_SIZE if level else LEAF_SIZE)
        self.live[where] = INNER_SIZE if level else LEAF_SIZE
        return where

    def lay_tree(self, at, tree, stale):
        memory = self.machine.memory
        if tree.lost:
            memory.write(at, 8, 0)
            memory.write(at + 8, 8, 0x5151)
            memory.write(at + 16, 8, 3)
            return
        if tree.hollow:
            root = self.node(0)
            memory.write(root + PARENT, 8, 0)
            memory.write(root + COUNT, 2, 0)
            memory.write(at, 8, root)
            memory.write(at + 8, 8, 0)
            memory.write(at + 16, 8, 0)
            return
        if not tree.items:
            memory.write(at, 8, 0)
            memory.write(at + 8, 8, 0x5252)
            memory.write(at + 16, 8, 0)
            return

        def make(rows, level, parent, slot):
            node = self.node(level)
            memory.write(node + PARENT, 8, parent)
            memory.write(node + SLOT_AT, 2, slot)
            room = CAPACITY
            for _ in range(level - 1):
                room = room * (CAPACITY + 1) + CAPACITY
            if level == 0:
                entries, children = rows, []
            else:
                parts = 2
                while (len(rows) - (parts - 1)) > parts * room:
                    parts += 1
                least = fewest(level - 1)
                while tree.thin and parts < CAPACITY + 1 and (len(rows) - parts) // (parts + 1) >= least:
                    parts += 1
                size = (len(rows) - (parts - 1)) // parts
                extra = (len(rows) - (parts - 1)) - size * parts
                index, entries, children = 0, [], []
                for part in range(parts):
                    take = size + (1 if part < extra else 0)
                    children.append(rows[index:index + take])
                    index += take
                    if part + 1 < parts:
                        entries.append(rows[index])
                        index += 1
            memory.write(node + COUNT, 2, len(entries))
            for index, (key, first, second) in enumerate(entries):
                memory.write(node + KEYS + 4 * index, 4, key)
                memory.write(node + index * 16, 8, first)
                memory.write(node + index * 16 + 8, 8, second)
            for index in range(len(entries), CAPACITY):
                memory.write(node + KEYS + 4 * index, 4, stale)
            for index, part in enumerate(children):
                memory.write(node + EDGES + 8 * index, 8, make(part, level - 1, node, index))
            return node

        height = tree_height(len(tree.items))
        while tree.thin and 2 * fewest(height) + 1 <= len(tree.items):
            height += 1
        memory.write(at, 8, make(tree.items, height, 0, 0))
        memory.write(at + 8, 8, height)
        memory.write(at + 16, 8, len(tree.items))

    def lay_map(self, base, shape, rows, size, walls, stale):
        """Control bytes with the row slots filled; entries sit below the control bytes."""
        memory = self.machine.memory
        stride = shape["stride"]
        start = self.bump(size * stride + size + 16)
        control = start + size * stride
        self.regions.append((start, size * stride + size + 16))
        memory.put_bytes(control, b"\xff" * (size + 16))
        for slot in walls:
            memory.write(control + slot, 1, 0x80)
        trees = {}
        for slot, tree in rows.items():
            memory.write(control + slot, 1, 0x11 + slot % 0x60)
            entry = control - (slot + 1) * stride
            memory.put_bytes(entry, bytes((slot + at) & 0xFF for at in range(20)))
            trees[slot] = entry + ROW_VALUE + ROW_TREE
            self.lay_tree(trees[slot], tree, stale)
        memory.write(base + shape["table"], 8, control)
        memory.write(base + shape["table"] + 8, 8, size - 1)
        memory.write(base + shape["table"] + 16, 8, size - len(rows))
        memory.write(base + shape["table"] + 24, 8, len(rows))
        return trees

    def lay(self, case):
        memory = self.machine.memory
        memory.reset()
        self.at = BUMP
        self.live = {}
        self.once = 0
        self.regions = [(STATE, STATE_SIZE)]
        self.places = {}
        memory.write(PREV, 4, case["prev"])
        memory.write(PREV + 4, 8, 0x2B2B2B2B2B2B2B2B)
        memory.write(STATE + 0x60, 4, case["date"])
        memory.statics[ONCE_CELL] = case["once"]
        stale = case["date"]
        memory.write(CELL, 8, WORKER if case["worker"] else 0)
        memory.write(GLOBAL, 8, REGISTRY)
        memory.write(WORKER + 0x110, 8, REGISTRY)
        memory.write(REGISTRY + 0x208, 8, case["threads"])
        at = LIST_AT[case["copy"]]
        count = len(case["dexes"])
        array = self.bump(count * DEX_SIZE + 16)
        self.regions.append((array, count * DEX_SIZE))
        memory.write(STATE + at, 8, array)
        memory.write(STATE + at + 8, 8, count)
        for index, dex in enumerate(case["dexes"]):
            base = array + index * DEX_SIZE
            self.lay_tree(base + DEX_MAP["tree"], dex["total"], stale)
            self.places[("dex", index, "total")] = base + DEX_MAP["tree"]
            for slot, where in self.lay_map(base, DEX_MAP, dex["rows"], dex["size"], dex["walls"], stale).items():
                self.places[("dex", index, slot)] = where
        ch = STATE + CH_OFFSET
        self.lay_tree(ch + CH_MAP["tree"], case["ch"]["total"], stale)
        self.places[("ch", 0, "total")] = ch + CH_MAP["tree"]
        for slot, where in self.lay_map(ch, CH_MAP, case["ch"]["rows"], case["ch"]["size"], case["ch"]["walls"], stale).items():
            self.places[("ch", 0, slot)] = where

    def image_of(self):
        memory = self.machine.memory
        parts = []
        holes = sorted(self.places.values())
        for start, size in self.regions:
            data = bytearray(memory.bytes_at(start, size))
            for hole in holes:
                if start <= hole < start + size:
                    data[hole - start:hole - start + 24] = bytes(24)
            parts.append(bytes(data))
        return parts

    def walk(self, at):
        """Every row of a tree, with parent links, slots, sizes and key order checked; also its nodes."""
        memory = self.machine.memory
        root, height, count = memory.read(at, 8), memory.read(at + 8, 8), memory.read(at + 16, 8)
        rows, nodes = [], []

        def visit(node, level, parent, slot):
            size = memory.read(node + COUNT, 2)
            self.check(size <= CAPACITY, "node size")
            self.check(self.live.get(node) == (INNER_SIZE if level else LEAF_SIZE), "node block")
            nodes.append(node)
            if parent:
                self.check(memory.read(node + PARENT, 8) == parent and memory.read(node + SLOT_AT, 2) == slot, "parent link")
                self.check(size >= 5, "node below the minimum")
            else:
                self.check(memory.read(node + PARENT, 8) == 0, "root parent")
            for index in range(size + 1):
                if level:
                    visit(memory.read(node + EDGES + 8 * index, 8), level - 1, node, index)
                if index < size:
                    rows.append((signed32(memory.read(node + KEYS + 4 * index, 4)), memory.read(node + index * 16, 8), memory.read(node + index * 16 + 8, 8)))

        if root:
            self.check(height <= 8, "height")
            visit(root, height, 0, 0)
        self.check(count == len(rows), "length word")
        self.check(all(left[0] < right[0] for left, right in zip(rows, rows[1:])), "key order")
        return rows, nodes

    def run(self, case):
        self.lay(case)
        before = self.image_of()
        machine = self.machine
        outcome = None
        try:
            machine.run(GATES[case["copy"]], {RDI: STATE, RSI: PREV})
        except Panicked as stop:
            outcome = stop.args[0]
        return outcome, before


def compare_run(harness, case):
    """Empty when the bytes did what the specification says; otherwise the first difference."""
    want = case["want"]
    try:
        outcome, before = harness.run(case)
        machine = harness.machine
        if outcome is not None:
            if outcome != want["outcome"]:
                return "panic: %#x" % outcome
            if harness.machine.steps < 0:
                return "steps"
            return ""
        if want["outcome"] not in ("skipped", "pruned"):
            return "outcome: no panic"
        reachable = []
        for name, place in harness.places.items():
            rows, nodes = harness.walk(place)
            if rows != want["trees"][name]:
                return "rows: %s" % (name,)
            reachable += nodes
        blocks = sorted(reachable)
        if blocks != sorted(harness.live):
            return "blocks: %d reachable, %d live" % (len(blocks), len(harness.live))
        if harness.image_of() != before:
            return "other bytes moved"
        if harness.once != (1 if case["once"] and want["outcome"] == "pruned" else 0):
            return "once count"
        if want["outcome"] == "skipped" and machine.memory.read(PREV + 4, 8) != 0x2B2B2B2B2B2B2B2B:
            return "previous time"
    except (Halt, EvidenceError, KeyError, ValueError, OverflowError, MemoryError, IndexError) as fault:
        return "fault: %s" % str(fault)[:40]
    return ""


# ---- vectors ----

def days(year, month, day):
    return days_from_civil(year, month, day)


TODAY = days(2026, 10, 31)


def rows_around(today, offsets):
    """Rows at today + offset days; the two value words are distinct for every row."""
    return [(pack(today + at), 0x1111000000 + (at & 0xFFFF) * 3 + 1, 0x2222000000 + (at & 0xFFFF) * 5 + 2) for at in offsets]


def world(label, kind, today=TODAY, **over):
    case = dict(label=label, kind=kind, copy=0, prev=pack(today - 1), date=pack(today), once=0, worker=False, threads=0, dexes=[], ch=dict(total=Tree(), rows={}, size=16, walls=()))
    case.update(over)
    case["want"] = spec(case)
    return case


def dex(total=(), rows=None, size=16, walls=()):
    return dict(total=total if isinstance(total, Tree) else Tree(total), rows=rows or {}, size=size, walls=walls)


def clearing(total=(), rows=None, size=16, walls=()):
    return dex(total, rows, size, walls)


def tree_cases():
    out = []
    span = (-40, -21, -20, -19, -14, -1, 0)
    for copy in range(3):
        out.append(world("edge rows, copy %d" % copy, "edge", copy=copy, dexes=[dex(rows_around(TODAY, span), {3: Tree(rows_around(TODAY, span))})], ch=clearing(rows_around(TODAY, span), {5: Tree(rows_around(TODAY, span))})))
    # one tree of each size and every cut position: only the clearinghouse total, so the sweep stays cheap
    for size in (1, 2, 5, 10, 11, 12, 13, 23, 24, 25, 36, 60, 133, 134):
        keys = list(range(-size, 0))
        for cut in sorted(set((0, 1, 2, size // 3, size // 2, size - 2, size - 1, size))):
            shifted = [at + size - cut - 21 + 1 for at in keys]
            out.append(world("size %d, %d dropped" % (size, cut), "tree", ch=clearing(rows_around(TODAY, shifted))))
    # the cutoff falls between rows, not on one
    for size in (11, 12, 40, 134):
        for cut in (1, size // 2, size - 1):
            gapped = [(at - cut) * 2 - 39 if at >= cut else (at - cut) * 2 - 21 for at in range(size)]
            out.append(world("gapped size %d, %d dropped" % (size, cut), "tree", ch=clearing(rows_around(TODAY, gapped))))
    # thin nodes: every node at the minimum, so the border repair must steal or merge
    for size in (11, 17, 23, 35, 71, 72, 100, 431):
        keys = list(range(size))
        for cut in sorted(set(list(range(0, min(size, 30), 1)) + [size // 4, size // 3, size // 2, size - 6, size - 1, size])):
            spaced = [at - cut - 20 for at in keys]
            out.append(world("thin size %d, %d dropped" % (size, cut), "thin", ch=clearing(Tree(rows_around(TODAY, spaced), thin=True))))
    # full nodes, every cut: the border node keeps 1 to 4 rows and takes rows from a sibling that has rows of its own
    for size in (23, 36, 47):
        for cut in range(1, size):
            spaced = [at - cut - 20 for at in range(size)]
            out.append(world("full size %d, %d dropped" % (size, cut), "full", ch=clearing(rows_around(TODAY, spaced))))
    for size in (72, 134, 144):
        for cut in range(3, size, 7):
            spaced = [at - cut - 20 for at in range(size)]
            out.append(world("full size %d, %d dropped" % (size, cut), "full", ch=clearing(rows_around(TODAY, spaced))))
    for cut in (1, 300, 864, 1700, 1728):
        spaced = [at - cut - 20 for at in range(1728)]
        out.append(world("tall, %d dropped" % cut, "tree", ch=clearing(rows_around(TODAY, spaced))))
    out.append(world("no rows", "tree"))
    out.append(world("hollow total", "tree", ch=clearing(Tree(hollow=True))))
    out.append(world("hollow dex total and row", "tree", dexes=[dex(Tree(hollow=True), {1: Tree(hollow=True)})]))
    out.append(world("all dropped twice", "tree", dexes=[dex(rows_around(TODAY, (-30, -25)), {1: Tree(rows_around(TODAY, (-30, -29, -28)))})]))
    return out


def gate_cases():
    out = []
    rows = rows_around(TODAY, (-30, -20, -1))
    for copy in range(3):
        for label, prev in (("same day", TODAY), ("next day", TODAY + 1), ("far later", TODAY + 400), ("one day back", TODAY - 1), ("far back", TODAY - 500)):
            out.append(world("%s, copy %d" % (label, copy), "gate", copy=copy, prev=pack(prev), dexes=[dex(rows)], ch=clearing(rows)))
        out.append(world("once pending, copy %d" % copy, "gate", copy=copy, once=3, dexes=[dex(rows)], ch=clearing(rows)))
        out.append(world("once pending, no dex, copy %d" % copy, "gate", copy=copy, once=3, ch=clearing(rows)))
        out.append(world("no dex list, copy %d" % copy, "gate", copy=copy, ch=clearing(rows)))
    out.append(world("once pending but same day", "gate", prev=pack(TODAY), once=3, ch=clearing(rows)))
    bottom = days(MIN_YEAR, 1, 1)
    for shift in (0, 1, 19, 20, 21, 366):
        out.append(world("date %d days above the lowest" % shift, "date", today=bottom + shift, prev=pack(bottom - 1 + shift if shift else bottom) - 16 if not shift else pack(bottom + shift - 1), ch=clearing(rows_around(bottom + shift, (-1, 0)) if shift > 1 else ())))
    for year, month, day in ((2024, 3, 1), (2024, 1, 5), (2023, 1, 5), (2000, 3, 10), (1900, 3, 10), (1970, 1, 10), (1969, 12, 31), (1, 1, 5), (0, 1, 5), (-1, 12, 31), (-400, 3, 1), (262142, 12, 31)):
        today = days(year, month, day)
        out.append(world("date %d-%d-%d" % (year, month, day), "date", today=today, ch=clearing(rows_around(today, (-22, -21, -20, -19, 0)))))
    return out


def map_cases():
    out = []
    keep = rows_around(TODAY, (-25, -3))
    for count in (1, 2, 4, 5, 6, 15, 16, 17, 33):
        size = max(32, count * 2)
        size = 64 if size > 32 else size
        out.append(world("%d rows packed" % count, "map", dexes=[dex(rows={slot: Tree(keep) for slot in range(count)}, size=size)], ch=clearing(rows={slot: Tree(keep) for slot in range(count)}, size=size)))
    out.append(world("rows past empty groups", "map", dexes=[dex(rows={40: Tree(keep), 41: Tree(keep), 63: Tree(keep)}, size=64)], ch=clearing(rows={17: Tree(keep), 48: Tree(keep), 63: Tree(keep)}, size=64)))
    out.append(world("only slot 16 of the second group", "map", dexes=[dex(rows={16: Tree(keep)}, size=32)], ch=clearing(rows={16: Tree(keep)}, size=32)))
    out.append(world("last slot only", "map", dexes=[dex(rows={15: Tree(keep)}, size=16)], ch=clearing(rows={31: Tree(keep)}, size=32)))
    out.append(world("tombstones", "map", dexes=[dex(rows={1: Tree(keep), 7: Tree(keep), 20: Tree(keep)}, size=32, walls=(0, 2, 3, 6, 16, 21))], ch=clearing(rows={2: Tree(keep), 18: Tree(keep)}, size=32, walls=(0, 1, 17, 19))))
    out.append(world("full table", "map", dexes=[dex(rows={slot: Tree(keep) for slot in range(16)}, size=16)]))
    out.append(world("three dex rows", "map", dexes=[dex(keep, {1: Tree(keep)}), dex(), dex(keep, {2: Tree(keep), 9: Tree(rows_around(TODAY, (-30,)))})], ch=clearing(keep)))
    for copy in (1, 2):
        out.append(world("two dex rows, copy %d" % copy, "map", copy=copy, dexes=[dex(keep, {1: Tree(keep)}), dex(keep, {0: Tree(keep)})]))
    out.append(world("empty row tree", "map", dexes=[dex(rows={1: Tree(), 2: Tree(keep)})], ch=clearing(rows={1: Tree()})))
    out.append(world("worker thread", "map", worker=True, dexes=[dex(keep, {1: Tree(keep), 4: Tree(keep)})], ch=clearing(rows={1: Tree(keep), 2: Tree(keep)})))
    out.append(world("one row, eight threads", "map", threads=8, dexes=[dex(rows={1: Tree(keep)})], ch=clearing(rows={3: Tree(keep)})))
    out.append(world("one row, worker, eight threads", "map", threads=8, worker=True, dexes=[dex(rows={1: Tree(keep)})], ch=clearing(rows={3: Tree(keep)})))
    bad = Tree(lost=True)
    out.append(world("dex total lost", "panic", dexes=[dex(bad)]))
    out.append(world("dex row lost", "panic", dexes=[dex(keep, {1: Tree(keep), 2: bad})]))
    out.append(world("clearinghouse total lost", "panic", dexes=[dex(keep)], ch=clearing(bad)))
    out.append(world("clearinghouse row lost", "panic", ch=clearing(keep, {1: bad})))
    return out


def random_cases():
    out = []
    state = 0x1234567
    def draw(limit):
        nonlocal state
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        return (state >> 33) % limit
    for index in range(60):
        today = TODAY - draw(4000)
        def rows():
            count = draw(30)
            return rows_around(today, sorted(set(-draw(45) for _ in range(count))))
        dexes = [dex(rows(), {draw(16): Tree(rows()) for _ in range(draw(4))}) for _ in range(draw(3))]
        ch = clearing(rows(), {draw(16): Tree(rows()) for _ in range(draw(4))})
        out.append(world("random %d" % index, "random", today=today, copy=draw(3), dexes=dexes, ch=ch))
    return out


def all_cases():
    return gate_cases() + tree_cases() + map_cases() + random_cases()


# ---- groups, mutation survey ----

REAL = frozenset(GATES + (DEX_PRUNE, CH_PRUNE, COLLECT_DEX, COLLECT_CH, PAR_DEX, PAR_CH, DRIVE_DEX, DRIVE_CH, LEAF, SPLIT, BORDER, LENGTHS, DROP, DATE_ADD))
FUNCTIONS = (
    ("day gate", GATES[0]), ("dex prune", DEX_PRUNE), ("clearinghouse prune", CH_PRUNE),
    ("dex row list", COLLECT_DEX), ("clearinghouse row list", COLLECT_CH), ("dex parallel entry", PAR_DEX), ("clearinghouse parallel entry", PAR_CH),
    ("dex driver", DRIVE_DEX), ("clearinghouse driver", DRIVE_CH), ("row loop", LEAF),
    ("tree split", SPLIT), ("border repair", BORDER), ("length count", LENGTHS), ("tree drop", DROP),
)
HELPERS = (("day gate copy +0x1040", GATES[1]), ("day gate copy +0x5c0", GATES[2]), ("date add", DATE_ADD))


def stepped_groups(image):
    return [(role, begin, image.exact_fde(begin)[1]) for role, begin in FUNCTIONS]


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


def run_mutants(image, reached, cases):
    results = []
    harness = Harness(image)
    machine = harness.machine
    by_va = {}
    for index, touched in enumerate(reached):
        for va in touched:
            by_va.setdefault(va, []).append(index)
    first_kill = []
    for role, begin, end in stepped_groups(image):
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
            for index in [item for item in first_kill if item in wanted] + indices:
                failed = compare_run(harness, cases[index])
                if failed:
                    if index in first_kill:
                        first_kill.remove(index)
                    first_kill.insert(0, index)
                    del first_kill[60:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"group": role, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0][:40] if failed else ""})
    return results


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    kinds, outcomes = {}, {}
    for case in cases:
        machine.seen = set()
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        if failed:
            mismatches += 1
            first = first or "%s: %s" % (case["label"], failed)
        kinds[case["kind"]] = kinds.get(case["kind"], 0) + 1
        name = case["want"]["outcome"] if isinstance(case["want"]["outcome"], str) else "panic %#x" % case["want"]["outcome"]
        outcomes[name] = outcomes.get(name, 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin in FUNCTIONS + HELPERS:
        end = image.exact_fde(begin)[1]
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched), "unstepped": ["%#x" % row.va for row in rows if row.va not in touched]})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "cases": {"total": len(cases), "by_kind": dict(sorted(kinds.items())), "by_outcome": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
    }
    results = None
    if full:
        results = run_mutants(image, reached, cases)
        summary = {}
        for row in results:
            summary[row["result"]] = summary.get(row["result"], 0) + 1
        evidence["mutations"] = {name: summary.get(name, 0) for name in ("killed", "survived", "unreached")}
    return evidence, results


ITER_END = "iterator end word: the walk stops on the item count and never reads it"
ITER_STATE = "iterator state written back to a block that is not read again"
CAPACITY_ONLY = "capacity or its size guard: alloc and free agree on any capacity at or above the item count"
EMPTY_VEC = "dangling pointer of an empty Vec, never read"
KEY_POINTER = "first word of a pair, the key pointer: the row loop reads only the value pointer"
DRAIN = "Drain bookkeeping of a Vec of plain pointers: only unwind or a drop of no elements reads it"
HUGE = "matters only for a length of u64 max"
SPLIT_WORD = "read only by the rayon split arm, which no vector runs"
LEFT_SIDE = "bytes of the left side: that side is freed right after, its keys, values and parent links are never read"
EITHER_SIDE = "picks which side to count: either side gives the same pair of lengths"
TALL = "unrolled descent threshold: height 8 or 9 is never met"
REASONS = {}
for reason, sites in (
    (ITER_END, (0x36FF6BB, 0x36FF6C2, 0x371FC04, 0x371FC0B)),
    (ITER_STATE, (0x3BC9ADF, 0x3BC9AE7, 0x3BD4F8F, 0x3BD4F97)),
    (CAPACITY_ONLY, (0x3BC9AEB, 0x3BC9AEF, 0x3BC9AFF, 0x3BC9B06, 0x3BD4F9B, 0x3BD4F9F, 0x3BD4FAF, 0x3BD4FB6)),
    (EMPTY_VEC, (0x3BC9B2C, 0x3BD4FDC)),
    (KEY_POINTER, (0x3BC9B6D, 0x3BC9BCC, 0x3BD501D, 0x3BD507C)),
    (DRAIN, (0x38DCD53, 0x38DCD66, 0x38DCD88, 0x38DCD8C, 0x38DCD92, 0x38DCD97, 0x38DCD99, 0x38DC9F3, 0x38DCA06, 0x38DCA28, 0x38DCA2C, 0x38DCA32, 0x38DCA37, 0x38DCA39)),
    (HUGE, (0x3403F00, 0x3403F0A, 0x3403B00, 0x3403B0A)),
    (SPLIT_WORD, (0x3403F12, 0x3403F1B, 0x3403B12, 0x3403B1B)),
    (LEFT_SIDE, (0x2FB54F0, 0x2FB555F, 0x2FB5569, 0x2FB5597, 0x2FB55C0, 0x2FB55CB, 0x2FB55DE, 0x2FB55E6, 0x2FB55EF, 0x2FB55F3, 0x2FB5600, 0x2FB56BB, 0x2FB56D2, 0x2FB56E9, 0x2FB5700, 0x2FB5717, 0x2FB571E, 0x2FB2528)),
    (EITHER_SIDE, (0x2FB2A63, 0x2FB2A67, 0x2FB2A6E)),
    (TALL, (0x33F2EA5, 0x33F2F98)),
):
    for site in sites:
        REASONS[site] = reason
REASONS.update({
    0x2FB5347: "child count plus one cannot be 0",
    0x2FB57A0: "left side root pop: in every vector the drop that follows frees the same blocks either way",
    0x2FB57A4: "left side root pop: in every vector the drop that follows frees the same blocks either way",
    0x2FB5880: "steal threshold of the right border, not settled by a vector",
    0x2FB5911: "copy size: key slots past the row count are never read",
    0x2FB5A26: "exit test of an unrolled child relink, not read to the end; every link stays right after the run",
    0x2FB5A46: "exit test of an unrolled child relink, not read to the end; every link stays right after the run",
    0x2FB5A66: "exit test of an unrolled child relink, not read to the end; every link stays right after the run",
    0x2FB5A91: "size threshold between the 4 step and the 1 step relink loop: both do the same work",
    0x2FB5B50: "empty root test of the border walk: a root of 1 row is not met at this test in a vector",
    0x2FB2470: "capacity assert of a merge, never fires on a valid tree",
    0x2FB2A7E: "",
    0x2FB2AA9: "descent index below the first level: the counted side never had height 2 or more where it matters in a vector",
    0x33F2F03: "count read of a tree with no rows, the value goes unused",
    0x33F301D: "height 0 and non-zero height reach the same frees in the vectors",
    0x33F30D7: "leaf size on this walk up: the vectors free inner nodes here",
})
del REASONS[0x2FB2A7E]


# ---- facts read from bytes ----

def byte_sites(image, targets):
    """Direct calls and tail jumps by e8 and e9 byte pattern, inside an FDE, to an exact target."""
    base, code = image.text_bytes()
    rows = []
    wanted = set(targets)
    for opcode, form in ((b"\xe8", "call"), (b"\xe9", "jmp")):
        at = code.find(opcode)
        while at >= 0:
            if at + 5 <= len(code):
                target = base + at + 5 + struct.unpack_from("<i", code, at + 1)[0]
                if target in wanted:
                    site = base + at
                    index = bisect.bisect_right(image.starts, site) - 1
                    if index >= 0 and site < image.fde_ends[image.starts[index]]:
                        rows.append((target, site, image.starts[index], form))
            at = code.find(opcode, at + 1)
    return rows


def slot_sites(image, slots):
    """Calls and tail jumps through a pointer slot, by ff 15 and ff 25 byte pattern."""
    base, code = image.text_bytes()
    rows = []
    wanted = set(slots)
    for second, form in ((0x15, "call [slot]"), (0x25, "jmp [slot]")):
        needle = bytes((0xFF, second))
        at = code.find(needle)
        while at >= 0:
            if at + 6 <= len(code):
                slot = base + at + 6 + struct.unpack_from("<i", code, at + 2)[0]
                if slot in wanted:
                    site = base + at
                    index = bisect.bisect_right(image.starts, site) - 1
                    if index >= 0 and site < image.fde_ends[image.starts[index]]:
                        rows.append((slot, site, image.starts[index], form))
            at = code.find(needle, at + 1)
    return rows


NAMES = {GATES[0]: "day gate", GATES[1]: "day gate copy", GATES[2]: "day gate copy", SPLIT: "tree split", LENGTHS: "length count", LEAF: "row loop", DRIVE_DEX: "dex driver", DRIVE_CH: "clearinghouse driver",
         PAR_DEX: "dex parallel entry", PAR_CH: "clearinghouse parallel entry", COLLECT_DEX: "row list shared with other callers", COLLECT_CH: "row list shared with other callers", SLOT_DEX: "dex prune slot", SLOT_CH: "clearinghouse prune slot"}


def caller_rows(image):
    relative = relative_slots(image)
    rows = []
    for slot in (SLOT_DEX, SLOT_CH):
        if relative.get(slot) != (DEX_PRUNE if slot == SLOT_DEX else CH_PRUNE):
            raise EvidenceError("slot target changed: %#x" % slot)
    for target, site, host, form in byte_sites(image, (GATES[0], GATES[1], GATES[2], SPLIT, LENGTHS, LEAF, DRIVE_DEX, DRIVE_CH, PAR_DEX, PAR_CH)):
        rows.append((NAMES[target], "%#x" % target, "%#x" % site, "%#x" % host, form))
    for slot, site, host, form in slot_sites(image, (SLOT_DEX, SLOT_CH)):
        rows.append((NAMES[slot], "%#x" % relative[slot], "%#x" % site, "%#x" % host, form))
    return sorted(rows)


STEP_NEIGHBOURS = ((0x2702760, 0x4CEF8F0, 0x4CEF2F0, "scheduled cancel fire, before the prune"), (GATES[0], GATES[2], GATES[1], "day tree prune"),
                   (0x2700390, 0x4CEC260, 0x4CEA760, "listed by open #140, not read here"), (0x26FF460, 0x4CE8B40, 0x4CE9670, "fee row rebuild, listed by open #140, not read here"))
BLOCK_STEPS = (0x22297C0, 0x470E9A0, 0x47162D0)


def order_rows(image):
    """Call order inside the 3 block steps, from e8 sites; a step that does not call the 4 in order fails."""
    rows = []
    for family in range(3):
        last = 0
        for targets in STEP_NEIGHBOURS:
            target = targets[family]
            sites = [site for _, site, host, form in byte_sites(image, (target,)) if host == BLOCK_STEPS[family] and form == "call"]
            if len(sites) != 1 or sites[0] <= last:
                raise EvidenceError("step order changed at %#x" % target)
            last = sites[0]
            rows.append(("%#x" % BLOCK_STEPS[family], "%#x" % sites[0], "%#x" % target, targets[3]))
    return rows


PINS = (
    (0x26FF362, 2, "39 3e", "cmp [rsi], edi: previous date against state +0x60"), (0x26FF364, 2, "7d 7d", "jge past the body: signed, equal or later previous date skips"),
    (0x26FF366, 5, "be ec ff ff ff", "mov esi, -20: the window"),
    (0x26FF39F, 7, "4c 8b 3d 82 55 07 03", "dex prune through slot 0x5774928"), (0x26FF3DD, 6, "ff 25 4d 55 07 03", "clearinghouse prune tail jump through slot 0x5774930"),
    (0x3BC9B65, 4, "48 6b c9 78", "dex row stride 0x78"), (0x3BC9B71, 5, "49 8d 4c 0d a0", "value pointer: entry + 0x18"),
    (0x3BD5015, 4, "48 6b c9 58", "clearinghouse row stride 0x58"), (0x3BD5021, 5, "49 8d 4c 0d c0", "value pointer: entry + 0x18"),
    (0x388DE4A, 4, "49 8d 6e 28", "row tree at value +0x28"), (0x2FB519B, 5, "bf e8 00 00 00", "leaf node 0xe8 bytes"), (0x2FB51E0, 5, "bf 48 01 00 00", "inner node 0x148 bytes"),
    (0x2FB529D, 3, "3b 5c 90", "key search: signed compare of a 32 bit key"), (0x2FB52A4, 2, "7f ea", "jg: walk on while the cutoff is above the key"),
    (0x22CE1A0, 5, "bf 3b f9 0a 00", "reassessFees handler date argument, not the prune"), (0x22CE1C4, 5, "e8 97 12 43 00", "reassessFees calls 0x26ff460 and not this gate"),
)


def pin_rows(image):
    rows = []
    for va, size, text, meaning in PINS:
        got = bytes(image.blob[image.offset(va):image.offset(va) + size]).hex(" ")
        if got != text:
            raise EvidenceError("pin %#x: %s" % (va, got))
        rows.append(("%#x" % va, got, meaning))
    return rows


def copy_rows(image):
    """Rows of the 2 gate copies that differ from the first, code addresses taken out."""
    def plain(row, start):
        return (row.op, row.a, row.b, row.width, row.cc, row.size)
    rows = []
    first = decode_range(image, GATES[0], image.exact_fde(GATES[0])[1])
    for gate in GATES[1:]:
        other = decode_range(image, gate, image.exact_fde(gate)[1])
        if len(other) != len(first):
            raise EvidenceError("gate copy length")
        for left, right in zip(first, other):
            if left.op in ("call", "jmp", "jcc", "calli", "jmpi", "lea") and left.op == right.op:
                if left.target is not None and left.target - left.va != right.target - right.va:
                    rows.append(("%#x" % gate, "%#x" % (left.va - GATES[0]), left.op, "target %#x" % left.target, "target %#x" % right.target))
                continue
            if plain(left, GATES[0]) != plain(right, gate):
                if left.a and left.b and left.b[0] == "m" and left.b[4] != right.b[4]:
                    rows.append(("%#x" % gate, "%#x" % (left.va - GATES[0]), left.op, "%#x" % left.b[4], "%#x" % right.b[4]))
    return rows


def window_rows():
    """The named retention facts, each one a run of the specification over real packed dates."""
    rows = []
    for year, month, day in ((2026, 10, 31), (2024, 3, 1), (2023, 3, 1), (2000, 1, 5), (0, 1, 5)):
        today = days(year, month, day)
        cutoff = date_add(pack(today), -WINDOW)
        rows.append(("%d-%02d-%02d" % (year, month, day), "%#010x" % (pack(today) & MASK[4]), "%#010x" % (cutoff & MASK[4]), unpack(pack(today)) - unpack(cutoff), WINDOW + 1))
    return rows


LAYOUT = (
    ("state", "+0x60", "dword", "current date, chrono packed, the first of 12 time bytes"),
    ("state", "+0x5c0 / +0x5c8", "pointer, count", "dex list, stride 0x2f0; +0x1040 / +0x1048 in copy 0x4ce8920"),
    ("state", "+0x80", "clearinghouse", "the block the second prune receives"),
    ("clearinghouse", "+0x298 ctrl, +0x2a0 mask, +0x2b0 items", "hash table", "stride 0x58, value at entry +0x18, row tree at value +0x28"),
    ("clearinghouse", "+0x358 root, +0x360 height, +0x368 length", "day tree", "state +0x3d8: the exchange total of fees-daily-view-94"),
    ("dex", "+0xf8 ctrl, +0x100 mask, +0x110 items", "hash table", "stride 0x78, value at entry +0x18, row tree at value +0x28"),
    ("dex", "+0x258 root, +0x260 height, +0x268 length", "day tree", "the dex total of fees-daily-view-94"),
    ("day node", "+0x00", "16 bytes x 11", "value: word 0, word 1"), ("day node", "+0xb0", "pointer", "parent"), ("day node", "+0xb8", "i32 x 11", "key: packed date"),
    ("day node", "+0xe4 / +0xe6", "u16, u16", "slot in parent, row count"), ("day node", "+0xe8", "pointer x 12", "edges, inner nodes only"),
    ("day node", "0xe8 / 0x148", "size", "leaf, inner"),
)

PATH = (
    (1, "block step", "0x22297c0, 0x470e9a0, 0x47162d0", "passes the previous time bytes by value; see step-order.tsv"),
    (2, "day gate", "0x26ff350, 0x4ce8920, 0x4ce8a30", "runs only when previous date < state +0x60, signed. Cutoff = state date - 20 days, panic text at 0x219cb3 when out of range"),
    (3, "once", "cell 0x577ab98", "non-zero cell calls Once before the walk, after the date add"),
    (4, "dex prune", "0x36ff620 through slot 0x5774928", "for each dex in list order: total tree, then every row"),
    (5, "clearinghouse prune", "0x371fb70, tail jump through slot 0x5774930", "total tree, then every row"),
    (6, "row list", "0x3bc9a80, 0x3bd4f30", "hash table walk into a Vec of (entry, value) pointers, capacity max(items, 4)"),
    (7, "parallel entry", "0x38dcd40, 0x38dc9e0", "drains the Vec through the driver, then frees it"),
    (8, "driver", "0x3403ec0, 0x3403ac0", "splits when 2 or more rows and a non-zero thread count; else tail jumps to the row loop"),
    (9, "row loop", "0x388de00", "one row: the same 5 steps as the total tree, on value +0x28"),
    (10, "tree split", "0x2fb5180 with border repair 0x2fb2440", "new right tree holds keys >= cutoff, borders refilled"),
    (11, "length count", "0x2fb2a60", "walks the tree of smaller height to count it, the other length is the rest; returns left length then right length"),
    (12, "tree drop", "0x33f2df0", "frees every old block not moved to the right tree"),
)

STUBS = (
    ("0x54c06b0", "alloc through slot 0x576dfd8", "size must be a node size or a multiple of 16; the block is tracked"),
    ("0x54c8cb0", "free through slot 0x576e010", "pointer and size must match a live block; freed bytes become 0xdd"),
    ("slot 0x576dfe0", "memcpy", "plain copy, size below 0x400"), ("slot 0x576e0e0", "memmove", "plain copy, size below 0x400"),
    ("0x4e17630", "worker thread pointer", "gives a test cell that holds 0 or a worker block"), ("0x4e16030", "global registry through slot 0x5773298", "gives a test cell"),
    ("0x4ee3b20", "Once through slot 0x576e8b8", "counts calls, checks the cell argument"),
    ("0x157a9f0", "Option unwrap panic through slot 0x576e470", "stops the run with the Location"), ("slot 0x576e468", "panic with text", "checks the 34 byte date text, stops the run with the Location"),
)

REFERENCE = (
    ("l1/scaled_vlm.rs DailyScaledVlms", "BTreeMap<i32, ScaledAndRawVlm> keyed by date_ordinal", "Key is a signed 32 bit chrono packed date (year << 13, ordinal << 4, flags), not an ordinal; value is 2 u64 words; matches in shape"),
    ("l1/scaled_vlm.rs clear_user", "only whole-map clear", "The bytes also cut each tree by date, below date - 20, with no clear of the row"),
    ("l1/scaled_vlm.rs record_current_day", "ten entry limit (MAX_DAILY_SCALED_VLM_ENTRIES)", "Not on this path: a kept day tree holds up to 21 rows and nothing here counts entries"),
    ("l1/fees/compute.rs", "no retention step", "The day gate and both prunes have no counterpart in the reference tree"),
)

DROP_TALL = "descent and walk blocks for trees of height 8 and above, or the 8 step unrolled parent walk; at 5 keys a node that is millions of rows"
SPLIT_ARM = "rayon split arm: needs a live worker pool and fs thread data, stubbed to a 0 thread registry"
UNWIND = "unwind pad or a panic that needs an allocator failure"
PADDING = "padding between blocks"
LIST_GROW = "Vec growth in the row list: capacity starts at the item count, so this needs items to under-report"


def unstepped_reason(role, va):
    if role in ("dex driver", "clearinghouse driver"):
        return SPLIT_ARM
    if role in ("dex row list", "clearinghouse row list"):
        return LIST_GROW
    if role == "tree drop":
        return DROP_TALL
    if role == "date add":
        return "branches for a delta of a whole 400 year cycle or more; the only delta here is -20"
    return UNWIND


def unstepped_rows(evidence):
    rows = []
    for function in evidence["functions"]:
        for va in function["unstepped"]:
            rows.append((function["start"], va, unstepped_reason(function["role"], int(va, 16))))
    return rows


def reason_for(row):
    if row["result"] == "unreached":
        return "instruction not stepped, see unstepped.tsv"
    return REASONS.get(row["va"], "not classified in this run")


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]
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
    write_tsv(out / "path-map.tsv", ("order", "stage", "address", "behaviour"), PATH)
    write_tsv(out / "layout.tsv", ("struct", "offset", "form", "meaning"), LAYOUT)
    write_tsv(out / "step-order.tsv", ("block_step", "site", "callee", "role"), order_rows(image))
    write_tsv(out / "call-sites.tsv", ("callee", "target", "site", "function", "form"), caller_rows(image))
    write_tsv(out / "copies.tsv", ("copy", "offset", "op", "first", "this"), copy_rows(image))
    write_tsv(out / "pins.tsv", ("address", "bytes", "meaning"), pin_rows(image))
    write_tsv(out / "window.tsv", ("date", "packed", "cutoff", "days_back", "days_kept"), window_rows())
    write_tsv(out / "stubs.tsv", ("address", "role", "note"), STUBS)
    write_tsv(out / "unstepped.tsv", ("function", "address", "reason"), unstepped_rows(evidence))
    write_tsv(out / "reference-diff.tsv", ("reference", "reference_says", "bytes_say"), REFERENCE)
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row in results:
        reason = "" if row["result"] == "killed" else reason_for(row)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row["group"], row["va"], row["kind"], row["result"], row["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    (out / "evidence.json").write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
