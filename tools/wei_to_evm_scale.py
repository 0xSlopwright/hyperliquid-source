#!/usr/bin/env python3
"""RE-004: scaling of a core u64 amount to a 256-bit EVM amount in node #94 (static, no execution).

Three functions (0x2715320, 0x4d0a6d0, 0x4d0bfa0) hold the same gate sequence before they
build an EVM transfer.  For a token index and a u64 amount:

    token 0 above 10^15 gives tag 0x28
    the native token uses the fixed exponent 10, and tag 0x148 if data is attached
    any other token needs record byte +0xbc == 1 (else tag 0x14a) and reads the i8 at +0xd1
    e < 0: k = -e, k >= 20 fails, a non-zero remainder fails, else amount / 10^k
    e >= 0: 10^e by a checked U256 power, then a checked U256 product; overflow fails
    every failure of the last two steps is tag 0xba, with amount / 10^weiDecimals as an f64

This tool bounds the functions and the two U256 multiply helpers with their FDEs, finds each
block from the decoded instructions, and interprets the real instructions in a small Python
x86-64 evaluator.  Nothing from the binary runs natively.  The evaluator stops on an unmodelled
mnemonic, a read of an unset register or flag, a read of unset memory outside the caller frame,
a call to an unknown target, or any write outside its own RAM.  The caller frame is filled with
bytes that change per vector, so a dependence on an unmodelled slot shows up as a mismatch.

    python3 tools/wei_to_evm_scale.py --out <dir>

writes evidence.json, exponent-table.tsv, boundaries.tsv, gates.tsv and block-bytes.txt.  Only
the Python standard library and objdump are used.
"""

import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
U256 = 1 << 256
SEED = b'RE-004-wei-to-evm-scale-94'
SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}

COPIES = (0x2715320, 0x4d0a6d0, 0x4d0bfa0)
HELPERS = (0x27a1150, 0x4de5500)
DROPS = (0x277eba0, 0x4daf4a0)
LIMIT = 10 ** 15
TAG_LIMIT, TAG_DATA, TAG_NOT_CONFIGURED, TAG_DECIMALS = 0x28, 0x148, 0x14a, 0xba
TAG_TEXTS = {TAG_LIMIT: (0x59c752, 'Withdrawal amount over single withdrawal limit.'),
             TAG_DATA: (0x59e4bc, 'Send to EVM with data not configured'),
             TAG_NOT_CONFIGURED: (0x59e4f3, 'EVM transfer not configured')}
DECIMALS_FORMAT = 0x1f11b6
DECIMALS_TEXT = b'\x1cInvalid number of decimals: \xc0\x00'
DISPLAY_TABLE = 0x59a8d0
DISPLAY_ARM = 0x3800521
F64_TABLE = 0x584b08
RECORD_STRIDE = 0xe8
OFF_NATIVE_ON, OFF_NATIVE_INDEX = 0x80, 0x88
OFF_RECORDS, OFF_LEN = 0x210, 0x218
OFF_FLAG, OFF_EXP, OFF_WEI_DEC = 0xbc, 0xd1, 0x49
GUARD_MIN, GUARD_MAX = -2, 18                 # admission pinned by the evm decimals packet

RET_MAGIC = 0x7fff0000
MEMSET_STUB, MEMCPY_STUB = 0x7fff0010, 0x7fff0020
RAM_BASE, RAM_SIZE = 0x7000000, 0x10000
FRAME = RAM_BASE + 0x8000             # 16-aligned, as in the function bodies
FRAME_SIZE = 0x620
META = RAM_BASE + 0xa000
RECORDS = RAM_BASE + 0xb000

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
REGS = {name: (i, 8) for i, name in enumerate(REG64)}
for i, name in enumerate(['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']):
    REGS[name] = (i, 4)
for i, name in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
                          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']):
    REGS[name] = (i, 2)
for i, name in enumerate(['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']):
    REGS[name] = (i, 1)


class EvidenceError(Exception):
    pass


class Unmodelled(Exception):
    pass


def check_digest(data, expected=SHA256):
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected}')
    return got


# ------------------------------------------------------------------- ELF / FDE

def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def text(self):
        addr, off, size = self.sec['.text']
        return addr, self.data[off:off + size]

    def in_rodata(self, va, size):
        addr, _, sz = self.sec['.rodata']
        return addr <= va and va + size <= addr + sz

    def slots(self):
        """GOT contents after load: RELATIVE addends, plus the two libc symbols the helpers use."""
        _, off, size = self.sec['.rela.dyn']
        _, sym_off, _ = self.sec['.dynsym']
        _, str_off, _ = self.sec['.dynstr']
        got = self.sec['.got']
        stubs = {b'memset': MEMSET_STUB, b'memcpy': MEMCPY_STUB}
        out = {}
        for where, info, addend in struct.iter_unpack('<QQq', self.data[off:off + size]):
            typ, sym = info & 0xffffffff, info >> 32
            if not got[0] <= where < got[0] + got[2]:
                continue
            if typ == 8:
                out[where] = addend & MASK
            elif typ == 6:
                n = struct.unpack_from('<I', self.data, sym_off + sym * 24)[0]
                name = self.data[str_off + n:self.data.index(b'\0', str_off + n)]
                if name in stubs:
                    out[where] = stubs[name]
        return out

    def relative_relocs(self):
        _, off, size = self.sec['.rela.dyn']
        return {where: addend for where, info, addend in
                struct.iter_unpack('<QQq', self.data[off:off + size]) if info & 0xffffffff == 8}


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[enc & 0x0f]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 != 0x00:
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & MASK, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        self.count = count

    def cie_r_encoding(self, cie):
        body = self.img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde}


# ------------------------------------------------------------ instruction reader

def disassemble(binary, start, end):
    cmd = ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
           f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


LINE_RE = re.compile(r'^\s*([0-9a-f]+):\t(.*)$')
MEM_RE = re.compile(r'^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[(.*)\]$')
HEX_RE = re.compile(r'0x[0-9a-f]+')
SHIFTS = ('shl', 'shr', 'sar')


def parse_operand(text, comment):
    if text in REGS:
        idx, size = REGS[text]
        return ('r', idx, size)
    if re.fullmatch(r'xmm[0-9]+', text):
        return ('x', int(text[3:]))
    if HEX_RE.fullmatch(text):
        return ('i', int(text, 16))
    m = MEM_RE.match(text)
    if m:
        size = SIZES.get(m.group(1), 8)
        inner = m.group(2)
        if inner.startswith('rip'):
            return ('a', size, comment)
        base = index = None
        scale, disp = 1, 0
        for part in re.findall(r'[+-]?[^+-]+', inner):
            neg = part[0] == '-'
            part = part.lstrip('+-')
            if '*' in part:
                reg, mul = part.split('*')
                index, scale = REGS[reg][0], int(mul)
            elif part in REGS:
                base = REGS[part][0]
            else:
                disp = -int(part, 16) if neg else int(part, 16)
        return ('m', size, base, index, scale, disp)
    if re.fullmatch(r'[0-9a-f]+', text):
        return ('t', int(text, 16))
    raise EvidenceError(f'unparsed operand {text!r}')


def parse_listing(listing):
    """objdump text -> ordered list of (va, mnemonic, operands, next_va)."""
    rows = []
    for line in listing.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        va, body = int(m.group(1), 16), m.group(2).strip()
        comment = None
        if '#' in body:
            body, tail = body.split('#', 1)
            comment = int(tail.split()[0], 16)
        body = re.sub(r'<[^>]*>', '', body).strip()
        if 'nop' in body or body == 'xchg   ax,ax':
            rows.append((va, 'nop', ()))
            continue
        parts = body.split(None, 1)
        mn = parts[0] if parts else 'nop'
        ops = ()
        if len(parts) > 1:
            try:
                ops = tuple(parse_operand(p.strip(), comment) for p in parts[1].split(','))
            except (EvidenceError, KeyError, ValueError):
                mn, ops = 'unparsed', ()         # stops the evaluator only if reached
        if mn in SHIFTS and ops[-1:] == (('t', 1),):
            ops = ops[:-1] + (('i', 1),)
        rows.append((va, mn, ops))
    return [(va, mn, ops, rows[i + 1][0] if i + 1 < len(rows) else None)
            for i, (va, mn, ops) in enumerate(rows)]


# ------------------------------------------------------------------ evaluator

def d2u(val):
    return struct.unpack('<Q', struct.pack('<d', val))[0]


def u2d(val):
    return struct.unpack('<d', struct.pack('<Q', val))[0]


def signed(val, bits):
    return val - (1 << bits) if val >> (bits - 1) else val


class Machine:
    """Byte-accurate integer and SSE-move subset.  Unset state is tracked and never guessed."""

    CC = {'e': lambda s: s.flag('zf'), 'ne': lambda s: not s.flag('zf'),
          'b': lambda s: s.flag('cf'), 'ae': lambda s: not s.flag('cf'),
          'a': lambda s: not (s.flag('cf') or s.flag('zf')), 'be': lambda s: s.flag('cf') or s.flag('zf'),
          's': lambda s: s.flag('sf'), 'ns': lambda s: not s.flag('sf'),
          'o': lambda s: s.flag('of'), 'no': lambda s: not s.flag('of')}

    def __init__(self, insns, img, slots, drops=()):
        self.img = img
        self.slots = slots
        self.drops = set(drops)
        table = {name[2:]: getattr(self, name) for name in dir(self) if name.startswith('i_')}
        for cc in self.CC:
            table['j' + cc] = partial(self.jcc, cc)
            table['cmov' + cc] = partial(self.cmov, cc)
            table['set' + cc] = partial(self.setcc, cc)
        self.code = {}
        for va, mn, ops, nxt in insns:
            handler = table.get(mn) or partial(self.unknown, mn, va)
            self.code[va] = (handler, ops, nxt)
        self.seen = set()
        self.reset()

    def reset(self):
        self.regs = [0] * 16
        self.known = [0] * 16
        self.xmm = [None] * 16
        self.ram = bytearray(RAM_SIZE)
        self.valid = bytearray(RAM_SIZE)
        self.cf = self.zf = self.sf = self.of = None
        self.steps = 0
        self.pc = None

    # state access

    def setreg(self, idx, val):
        self.regs[idx] = val & MASK
        self.known[idx] = MASK

    def poison(self, *idxs):
        for idx in idxs:
            self.known[idx] = 0

    def flag(self, name):
        val = getattr(self, name)
        if val is None:
            raise Unmodelled(f'read of unset {name} at {self.pc:#x}')
        return val

    def ea(self, op):
        _, _, base, index, scale, disp = op
        val = disp
        if base is not None:
            if self.known[base] != MASK:
                raise Unmodelled(f'unset base at {self.pc:#x}')
            val += self.regs[base]
        if index is not None:
            if self.known[index] != MASK:
                raise Unmodelled(f'unset index at {self.pc:#x}')
            val += self.regs[index] * scale
        return val & MASK

    def load(self, ea, size):
        lo = ea - RAM_BASE
        if 0 <= lo and lo + size <= RAM_SIZE:
            if 0 in self.valid[lo:lo + size]:
                raise Unmodelled(f'read of unset memory {ea:#x}/{size} at {self.pc:#x}')
            return int.from_bytes(self.ram[lo:lo + size], 'little')
        if size == 8 and ea in self.slots:
            return self.slots[ea]
        if self.img.in_rodata(ea, size):
            return int.from_bytes(self.img.read(ea, size), 'little')
        raise Unmodelled(f'read outside the model {ea:#x}/{size} at {self.pc:#x}')

    def store(self, ea, size, val):
        lo = ea - RAM_BASE
        if not (0 <= lo and lo + size <= RAM_SIZE):
            raise Unmodelled(f'write outside RAM {ea:#x} at {self.pc:#x}')
        self.ram[lo:lo + size] = (val & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
        self.valid[lo:lo + size] = b'\x01' * size

    def rd(self, op):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            mask = (1 << (size * 8)) - 1
            if self.known[idx] & mask != mask:
                raise Unmodelled(f'read of unset {REG64[idx]} at {self.pc:#x}')
            return self.regs[idx] & mask
        if kind == 'i':
            return op[1]
        if kind == 'm':
            return self.load(self.ea(op), op[1])
        if kind == 'a':
            return self.load(op[2], op[1])
        raise Unmodelled(f'operand {op} at {self.pc:#x}')

    def wr(self, op, val):
        kind = op[0]
        if kind == 'r':
            idx, size = op[1], op[2]
            if size >= 4:
                self.regs[idx] = val & (MASK if size == 8 else 0xffffffff)
                self.known[idx] = MASK
            else:
                mask = (1 << (size * 8)) - 1
                self.regs[idx] = (self.regs[idx] & ~mask) | (val & mask)
                self.known[idx] |= mask
        elif kind == 'm':
            self.store(self.ea(op), op[1], val)
        elif kind == 'a':
            raise Unmodelled(f'write to a static address at {self.pc:#x}')
        else:
            raise Unmodelled(f'write to {op} at {self.pc:#x}')

    def size(self, op):
        return op[2] if op[0] == 'r' else op[1]

    def nz(self, res, bits):
        self.zf = res == 0
        self.sf = bool(res >> (bits - 1))

    # moves

    def i_nop(self, ops):
        pass

    def i_mov(self, ops):
        dst, src = ops
        if dst[0] == 'r' and src[0] == 'r' and dst[2] >= 4:
            self.regs[dst[1]] = self.regs[src[1]] & (MASK if dst[2] == 8 else 0xffffffff)
            self.known[dst[1]] = self.known[src[1]] if dst[2] == 8 else (self.known[src[1]] & 0xffffffff) | ~0xffffffff & MASK
            return
        self.wr(dst, self.rd(src))

    i_movabs = i_mov

    def i_movzx(self, ops):
        self.wr(ops[0], self.rd(ops[1]))

    def i_lea(self, ops):
        dst, src = ops
        self.wr(dst, src[2] if src[0] == 'a' else self.ea(src))

    def i_push(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP] - 8
        self.regs[RSP] = rsp
        lo = rsp - RAM_BASE
        self.ram[lo:lo + 8] = self.regs[idx].to_bytes(8, 'little')
        self.valid[lo:lo + 8] = bytes((self.known[idx] >> (8 * i)) & 1 for i in range(8))

    def i_pop(self, ops):
        idx = ops[0][1]
        rsp = self.regs[RSP]
        lo = rsp - RAM_BASE
        self.regs[idx] = int.from_bytes(self.ram[lo:lo + 8], 'little')
        self.known[idx] = sum(0xff << (8 * i) for i in range(8) if self.valid[lo + i])
        self.regs[RSP] = rsp + 8

    # integer arithmetic

    def arith(self, ops, carry_in, subtract, store=True):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        a, b = self.rd(ops[0]), self.rd(ops[1]) & mask
        c = int(self.flag('cf')) if carry_in else 0
        if subtract:
            raw = a - b - c
            res = raw & mask
            self.cf = raw < 0
            self.of = bool((((a ^ b) & (a ^ res)) >> (bits - 1)) & 1)
        else:
            raw = a + b + c
            res = raw & mask
            self.cf = raw > mask
            self.of = bool((((a ^ res) & (b ^ res)) >> (bits - 1)) & 1)
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_add(self, ops):
        self.arith(ops, False, False)

    def i_adc(self, ops):
        self.arith(ops, True, False)

    def i_sub(self, ops):
        self.arith(ops, False, True)

    def i_sbb(self, ops):
        self.arith(ops, True, True)

    def i_cmp(self, ops):
        self.arith(ops, False, True, store=False)

    def logic(self, ops, fn, store=True):
        bits = self.size(ops[0]) * 8
        res = fn(self.rd(ops[0]), self.rd(ops[1]) & ((1 << bits) - 1))
        self.cf = self.of = False
        self.nz(res, bits)
        if store:
            self.wr(ops[0], res)

    def i_and(self, ops):
        self.logic(ops, lambda a, b: a & b)

    def i_or(self, ops):
        self.logic(ops, lambda a, b: a | b)

    def i_xor(self, ops):
        if ops[0] == ops[1] and ops[0][0] == 'r':
            self.wr(ops[0], 0)
            self.cf = self.of = self.sf = False
            self.zf = True
            return
        self.logic(ops, lambda a, b: a ^ b)

    def i_test(self, ops):
        self.logic(ops, lambda a, b: a & b, store=False)

    def i_inc(self, ops):
        bits = self.size(ops[0]) * 8
        res = (self.rd(ops[0]) + 1) & ((1 << bits) - 1)
        self.of = res == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_dec(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = (a - 1) & ((1 << bits) - 1)
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_neg(self, ops):
        bits = self.size(ops[0]) * 8
        a = self.rd(ops[0])
        res = -a & ((1 << bits) - 1)
        self.cf = a != 0
        self.of = a == 1 << (bits - 1)
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_not(self, ops):
        bits = self.size(ops[0]) * 8
        self.wr(ops[0], ~self.rd(ops[0]) & ((1 << bits) - 1))

    def shift(self, ops, kind):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[1]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a = self.rd(ops[0])
        if kind == 'shl':
            raw = a << count
            self.cf = bool((raw >> bits) & 1)
        elif kind == 'shr':
            raw = a >> count
            self.cf = bool((a >> (count - 1)) & 1)
        else:
            sa = signed(a, bits)
            raw = sa >> count
            self.cf = bool((sa >> (count - 1)) & 1)
        res = raw & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shl(self, ops):
        self.shift(ops, 'shl')

    def i_shr(self, ops):
        self.shift(ops, 'shr')

    def i_sar(self, ops):
        self.shift(ops, 'sar')

    def i_shld(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = (a << bits | b) << count
        self.cf = bool((wide >> (2 * bits)) & 1)
        res = (wide >> bits) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_shrd(self, ops):
        bits = self.size(ops[0]) * 8
        mask = (1 << bits) - 1
        count = self.rd(ops[2]) & (63 if bits == 64 else 31)
        if count == 0:
            return
        a, b = self.rd(ops[0]), self.rd(ops[1])
        wide = b << bits | a
        self.cf = bool((a >> (count - 1)) & 1)
        res = (wide >> count) & mask
        self.of = None
        self.nz(res, bits)
        self.wr(ops[0], res)

    def i_bsr(self, ops):
        src = self.rd(ops[1])
        if src == 0:
            raise Unmodelled(f'bsr of zero at {self.pc:#x}')
        self.zf = False
        self.cf = self.of = self.sf = None
        self.wr(ops[0], src.bit_length() - 1)

    def i_mul(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        raw = self.rd(lo_op) * self.rd(ops[0])
        self.wr(lo_op, raw)
        self.wr(hi_op, raw >> bits)
        self.cf = self.of = raw >> bits != 0
        self.zf = self.sf = None

    def i_imul(self, ops):
        bits = self.size(ops[0]) * 8
        if len(ops) == 2:
            a, b = self.rd(ops[0]), self.rd(ops[1])
        elif len(ops) == 3:
            a, b = self.rd(ops[1]), self.rd(ops[2])
        else:
            raise Unmodelled(f'one-operand imul at {self.pc:#x}')
        b &= (1 << bits) - 1
        raw = signed(a, bits) * signed(b, bits)
        res = raw & ((1 << bits) - 1)
        self.cf = self.of = signed(res, bits) != raw
        self.zf = self.sf = None
        self.wr(ops[0], res)

    def i_div(self, ops):
        size = self.size(ops[0])
        bits = size * 8
        lo_op, hi_op = ('r', RAX, size), ('r', RDX, size)
        num = (self.rd(hi_op) << bits) | self.rd(lo_op)
        den = self.rd(ops[0])
        if den == 0 or num // den >> bits:
            raise Unmodelled(f'divide fault at {self.pc:#x}')
        self.wr(lo_op, num // den)
        self.wr(hi_op, num % den)
        self.cf = self.of = self.zf = self.sf = None

    # control flow

    def jcc(self, cc, ops):
        if self.CC[cc](self):
            self.pc = ops[0][1]

    def cmov(self, cc, ops):
        dst, src = ops
        val = self.rd(src)
        if self.CC[cc](self):
            self.wr(dst, val)
        elif dst[2] == 4:
            self.wr(dst, self.rd(dst))

    def setcc(self, cc, ops):
        self.wr(ops[0], int(bool(self.CC[cc](self))))

    def target(self, op):
        return op[1] if op[0] == 't' else self.rd(op)

    def i_jmp(self, ops):
        self.pc = self.target(ops[0])

    def i_call(self, ops):
        dest = self.target(ops[0])
        self.regs[RSP] -= 8
        self.store(self.regs[RSP], 8, self.pc)
        self.pc = dest

    def i_ret(self, ops):
        self.pc = self.load(self.regs[RSP], 8)
        self.regs[RSP] += 8

    # SSE moves

    def xrd(self, op):
        if op[0] == 'x':
            if self.xmm[op[1]] is None:
                raise Unmodelled(f'read of unset xmm at {self.pc:#x}')
            return self.xmm[op[1]]
        return self.rd(op)

    def xwr(self, op, val):
        if op[0] == 'x':
            self.xmm[op[1]] = val
        else:
            self.wr(op, val)

    def i_movups(self, ops):
        self.xwr(ops[0], self.xrd(ops[1]))

    def i_movaps(self, ops):
        for op in ops:
            if op[0] == 'm' and self.ea(op) % 16:
                raise Unmodelled(f'misaligned movaps at {self.pc:#x}')
        self.xwr(ops[0], self.xrd(ops[1]))

    i_movdqu = i_movups
    i_movdqa = i_movaps
    i_movapd = i_movaps

    def i_xorps(self, ops):
        if ops[0] != ops[1]:
            raise Unmodelled(f'xorps of distinct operands at {self.pc:#x}')
        self.xmm[ops[0][1]] = 0

    i_pxor = i_xorps

    def i_movq(self, ops):
        dst, src = ops
        if dst[0] == 'x':
            self.xmm[dst[1]] = self.xrd(src) & MASK
        else:
            self.wr(dst, self.xrd(src) & MASK)

    i_movsd = i_movq

    def i_unpcklps(self, ops):
        a, b = self.xrd(ops[0]), self.xrd(ops[1])
        self.xmm[ops[0][1]] = ((a & 0xffffffff) | ((b & 0xffffffff) << 32)
                               | (((a >> 32) & 0xffffffff) << 64) | (((b >> 32) & 0xffffffff) << 96))

    def i_unpckhpd(self, ops):
        a, b = self.xrd(ops[0]), self.xrd(ops[1])
        self.xmm[ops[0][1]] = (a >> 64) | ((b >> 64) << 64)

    def i_subpd(self, ops):
        a, b = self.xrd(ops[0]), self.xrd(ops[1])
        low = d2u(u2d(a & MASK) - u2d(b & MASK))
        high = d2u(u2d(a >> 64) - u2d(b >> 64))
        self.xmm[ops[0][1]] = low | (high << 64)

    def i_addsd(self, ops):
        a, b = self.xrd(ops[0]), self.xrd(ops[1])
        self.xmm[ops[0][1]] = (a >> 64 << 64) | d2u(u2d(a & MASK) + u2d(b & MASK))

    def i_divsd(self, ops):
        a, b = self.xrd(ops[0]), self.xrd(ops[1])
        self.xmm[ops[0][1]] = (a >> 64 << 64) | d2u(u2d(a & MASK) / u2d(b & MASK))

    def unknown(self, mn, va, ops):
        raise Unmodelled(f'mnemonic {mn} at {va:#x}')

    # libc stubs

    def after_stub(self, result):
        self.setreg(RAX, result)
        self.poison(RCX, RDX, RSI, RDI, R8, R9, R10, R11)
        self.cf = self.zf = self.sf = self.of = None
        self.i_ret(())

    def memset(self):
        dst, val, n = self.regs[RDI], self.regs[RSI] & 0xff, self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, val)
        self.after_stub(dst)

    def memcpy(self):
        dst, src, n = self.regs[RDI], self.regs[RSI], self.regs[RDX]
        for i in range(n):
            self.store(dst + i, 1, self.load(src + i, 1))
        self.after_stub(dst)

    def run(self, entry, stop=(), limit=20000):
        self.pc = entry
        code = self.code
        seen = self.seen
        while True:
            pc = self.pc
            if pc == RET_MAGIC or pc in stop:
                return pc
            if pc == MEMSET_STUB:
                self.memset()
                continue
            if pc == MEMCPY_STUB:
                self.memcpy()
                continue
            if pc in self.drops:
                self.after_stub(0)
                self.poison(RAX)
                self.xmm = [None] * 16
                continue
            ins = code.get(pc)
            if ins is None:
                raise Unmodelled(f'no instruction at {pc:#x}')
            self.steps += 1
            if self.steps > limit:
                raise Unmodelled('step limit')
            seen.add(pc)
            self.pc = ins[2]
            ins[0](ins[1])


# --------------------------------------------------------------- block anchors

def checked(cond, message):
    if not cond:
        raise EvidenceError(message)


def load_code(binary, fdes, starts):
    insns, ranges = [], {}
    for start in starts:
        rng = fdes.range_of(start)
        checked(rng['start'] == start, f'{start:#x} is not an FDE start')
        insns.extend(parse_listing(disassemble(binary, rng['start'], rng['end'])))
        ranges[start] = rng
    return insns, ranges


def rsp_slot(op):
    checked(op[0] == 'm' and op[2] == RSP and op[3] is None, f'not a stack slot: {op}')
    return op[5]


def find_copy(all_insns, rng):
    """Every entry, exit and stack slot of one copy, read from its own instructions."""
    insns = [ins for ins in all_insns if rng['start'] <= ins[0] < rng['end']]
    at = {ins[0]: i for i, ins in enumerate(insns)}
    pos = next(i for i, ins in enumerate(insns) if ins[1] == 'movabs' and ins[2][1] == ('i', LIMIT))
    entry, sete, limit, compare = insns[pos - 2], insns[pos - 1], insns[pos], insns[pos + 1]
    checked(entry[1] == 'test' and entry[2][0] == entry[2][1] and sete[1] == 'sete', 'limit gate shape')
    token_reg = entry[2][0][1]
    checked(compare[1] == 'cmp' and insns[pos + 2][1] == 'seta', 'limit compare shape')
    token_load = insns[pos - 4]
    checked(token_load[1] == 'mov' and token_load[2][0] == ('r', token_reg, 8), 'token load shape')
    token_slot = rsp_slot(token_load[2][1])
    wei_slot = rsp_slot(compare[2][0])
    i = pos + 2
    while not (insns[i][1] == 'mov' and insns[i][2][0] == ('r', RBX, 2) and insns[i][2][1] == ('i', TAG_LIMIT)):
        i += 1
    limit_tag = insns[i][0]
    while insns[i][1] != 'jmp':
        i += 1
    tail = insns[i][2][0][1]
    while not (insns[i][1] == 'cmp' and insns[i][2][0] == ('r', token_reg, 8)):
        i += 1
    native_cmp = insns[i]
    checked(native_cmp[2][1][5] == OFF_NATIVE_INDEX, 'native index offset')
    meta_reg = native_cmp[2][1][2]
    meta_load = next(ins for ins in reversed(insns[pos:i]) if ins[2] and ins[2][0] == ('r', meta_reg, 8))
    meta_slot = rsp_slot(meta_load[2][1])
    data_load = next(k for k in range(i, i + 12) if insns[k][1] == 'mov' and insns[k][2][0] == ('r', RAX, 8))
    data_slot = rsp_slot(insns[data_load][2][1])
    checked(insns[data_load + 1][1] == 'test' and insns[data_load + 2][1] == 'je', 'data gate shape')
    native_block = insns[data_load + 2][2][0][1]
    checked(insns[data_load + 3][2] == (('r', RBX, 2), ('i', TAG_DATA)), 'tag 0x148 block')
    tail_data = insns[data_load + 4][2][0][1]
    checked(insns[at[native_block] + 1][2] == (('r', RDX, 1), ('i', 10)), 'native exponent is not 10')
    k = data_load
    while not (insns[k][1] == 'cmp' and insns[k][2][0] == ('r', token_reg, 8)):
        k += 1
    checked(insns[k][2][1][5] == OFF_LEN and insns[k + 1][1] == 'jae', 'bounds check shape')
    panic = insns[k + 1][2][0][1]
    guard = next(ins for ins in insns[k:k + 6] if ins[1] == 'cmp' and ins[2][0][0] == 'm')
    checked(guard[2][0][5] == OFF_FLAG and guard[2][1] == ('i', 1), 'record guard shape')
    stride = next(ins for ins in insns[k:k + 6] if ins[1] == 'imul')
    checked(stride[2][2] == ('i', RECORD_STRIDE), 'record stride')
    load = next(ins for ins in insns[k:] if ins[1] == 'movzx' and ins[2][1][0] == 'm'
                and ins[2][1][5] == OFF_EXP)
    load_at = at[load[0]]
    checked(load[2] == (('r', RDX, 4), ('m', 1, RBX, None, 1, OFF_EXP)), 'exponent load shape')
    fail_jump = next(ins for ins in insns[load_at:load_at + 60]
                     if ins[1] == 'je' and insns[at[ins[0]] - 1][2] == (('r', RAX, 1), ('i', 0x10)))
    fail = fail_jump[2][0][1]
    exact = next(j for j in range(load_at, len(insns))
                 if insns[j][1] == 'test' and insns[j][2] == (('r', RDX, 8), ('r', RDX, 8)))
    jump_ok = next(ins for ins in insns[exact:] if ins[1] == 'je')
    block = at[jump_ok[2][0][1]]
    while insns[block][1] != 'jmp':
        block += 1
    checked(insns[block - 1][2] == (('r', RDX, 1), ('i', 1)), 'quotient block does not set dl')
    success = insns[block][2][0][1]
    store = insns[at[success]]
    checked(store[1] == 'mov' and store[2][1] == ('r', R13, 8), 'success block does not store r13')
    out_slot = rsp_slot(store[2][0])
    tag_at = at[fail]
    while insns[tag_at][2] != (('r', RBX, 2), ('i', TAG_DECIMALS)):
        tag_at += 1
    float_store = insns[tag_at - 1]
    checked(float_store[1] == 'movapd' and float_store[2][1] == ('x', 1), 'f64 store shape')
    float_slot = rsp_slot(float_store[2][0])
    checked(insns[tag_at + 1][0] == tail, 'tag 0xba does not reach the shared tail')
    return {'start': rng['start'], 'end': rng['end'], 'entry': entry[0], 'token_reg': REG64[token_reg],
            'token_idx': token_reg, 'token_slot': token_slot, 'wei_slot': wei_slot, 'meta_slot': meta_slot, 'data_slot': data_slot,
            'limit_tag_at': limit_tag, 'tail': tail, 'tail_data': tail_data, 'native_block': native_block,
            'panic': panic, 'exponent_load': load[0], 'fail': fail, 'exact_test': insns[exact][0],
            'success': success, 'out_slot': out_slot, 'float_slot': float_slot, 'guard_at': guard[0]}


# ------------------------------------------------------------------- harness

def filler(seed):
    return hashlib.sha256(SEED + seed).digest() * (FRAME_SIZE // 32 + 1)


def run_gate(machine, copy, token, wei, native=None, data=0, records=(), fill=b''):
    """One evaluation from the limit gate to an exit.  records: list of (flag, e, weiDecimals)."""
    machine.reset()
    lo = FRAME - RAM_BASE
    machine.ram[lo:lo + FRAME_SIZE] = filler(fill)[:FRAME_SIZE]
    machine.valid[lo:lo + FRAME_SIZE] = b'\x01' * FRAME_SIZE
    machine.setreg(RSP, FRAME)
    machine.setreg(RDX, 0)
    machine.setreg(copy['token_idx'], token)
    machine.store(FRAME + copy['token_slot'], 8, token)
    machine.store(FRAME + copy['wei_slot'], 8, wei)
    machine.store(FRAME + copy['meta_slot'], 8, META)
    machine.store(FRAME + copy['data_slot'], 8, data)
    machine.store(META + OFF_NATIVE_ON, 1, 0 if native is None else 1)
    machine.store(META + OFF_NATIVE_INDEX, 8, 0 if native is None else native)
    machine.store(META + OFF_RECORDS, 8, RECORDS)
    machine.store(META + OFF_LEN, 8, len(records))
    for i, (flag, exponent, wei_decimals) in enumerate(records):
        base = RECORDS + i * RECORD_STRIDE
        machine.store(base + OFF_WEI_DEC, 1, wei_decimals)
        machine.store(base + OFF_FLAG, 1, flag)
        for off in range(0xbd, 0xd1):
            machine.store(base + off, 1, 0)
        machine.store(base + OFF_EXP, 1, exponent & 0xff)
    stop = machine.run(copy['entry'], stop={copy['tail'], copy['tail_data'], copy['panic'], copy['success']})
    if stop == copy['panic']:
        return ('panic',)
    if stop == copy['success']:
        out = machine.regs[R13] | (machine.load(FRAME + copy['out_slot'] + 8, 24) << 64)
        return ('ok', machine.rd(('r', RDX, 1)) & 1, out)
    tag = machine.rd(('r', RBX, 2))
    if tag == TAG_DECIMALS:
        return ('tag', tag, machine.load(FRAME + copy['float_slot'], 8))
    return ('tag', tag)


# --------------------------------------------------------------------- models

def scale_model(exponent, wei, wei_decimals):
    if exponent < 0:
        k = -exponent
        if k < 20 and wei % 10 ** k == 0:
            return wei // 10 ** k
    else:
        wide = wei * 10 ** exponent
        if 10 ** exponent < U256 and wide < U256:
            return wide
    return None


def gate_model(token, wei, native, data, records):
    """The expected exit for one gate input; the f64 is bit-exact for weiDecimals in the table."""
    if token == 0 and wei > LIMIT:
        return ('tag', TAG_LIMIT)
    if native is not None and token == native:
        if data:
            return ('tag', TAG_DATA)
        exponent, token_flag = 10, 0
    else:
        if token >= len(records):
            return ('panic',)
        if records[token][0] != 1:
            return ('tag', TAG_NOT_CONFIGURED)
        exponent, token_flag = records[token][1], 1
    amount = scale_model(exponent, wei, 0)
    if amount is None:
        if token >= len(records):
            return ('panic',)
        return ('tag', TAG_DECIMALS, d2u(float(wei) / 10.0 ** records[token][2]))
    return ('ok', token_flag, amount)


def lead_u64(exponent, amount):
    """Reference lead `evm_amount_to_internal_wei`, for comparison only.  None for any error."""
    k = abs(exponent)
    if k >= 20:
        return None
    power = 10 ** k
    if exponent >= 0:
        wide = amount * power
        return wide if wide <= MASK else None
    return amount // power if amount % power == 0 else None


def seeded(count):
    out = []
    for i in range(count):
        raw = hashlib.sha256(SEED + i.to_bytes(4, 'little')).digest()
        out.append(int.from_bytes(raw[:8], 'little') >> (raw[8] % 64))
    return out


def scale_vectors():
    """(e, wei): -19..=19 on a dense set, the remaining i8 on a short set, plus the U256 limit."""
    for exponent in range(-128, 128):
        if -19 <= exponent <= 19:
            k = abs(exponent)
            near = [10 ** k + d for d in (-1, 0, 1) if 0 <= 10 ** k + d <= MASK]
            multiples = [m * 10 ** k for m in (2, 7, 12345) if m * 10 ** k <= MASK]
            base = [0, 1, 2, 9, 10, 100, 1000, 1001, 10 ** 8, 10 ** 15, 2 ** 32 - 1, 2 ** 32, 2 ** 53 + 1,
                    2 ** 63, MASK - 1, MASK]
            for wei in base + near + multiples + seeded(8):
                yield exponent, wei
        else:
            for wei in (0, 1, 10 ** 8, MASK):
                yield exponent, wei
    for exponent in range(55, 78):
        limit = (U256 - 1) // 10 ** exponent
        if limit <= MASK:
            for wei in (limit - 1, limit, limit + 1):
                if 0 <= wei <= MASK:
                    yield exponent, wei


def gate_vectors():
    """(token, wei, native, data, flag of the chosen token) over the gate conditions."""
    for token in (0, 1, 2, 3):
        for wei in (0, 100, 101, LIMIT, LIMIT + 1, MASK):
            for native in (None, 2):
                for data in (0, 0x1234):
                    for flag in (0, 1, 2):
                        yield token, wei, native, data, flag


def gate_records(token, flag):
    """Three tokens with e = -2 and weiDecimals = 6, and `flag` on the chosen one."""
    rows = [(1, -2, 6), (1, -2, 6), (1, -2, 6)]
    if token < 3:
        rows[token] = (flag, -2, 6)
    return rows


# ------------------------------------------------------------------ analysis

def check_texts(img):
    for address, text in TAG_TEXTS.values():
        checked(img.read(address, len(text)).decode() == text, f'text at {address:#x} changed')
    checked(img.read(DECIMALS_FORMAT, len(DECIMALS_TEXT)) == DECIMALS_TEXT, 'decimals format changed')
    arm = DISPLAY_TABLE + struct.unpack('<i', img.read(DISPLAY_TABLE + 4 * TAG_DECIMALS, 4))[0]
    checked(arm == DISPLAY_ARM, 'Display arm of tag 0xba moved')
    return {hex(tag): text for tag, (_, text) in TAG_TEXTS.items()} | {hex(TAG_DECIMALS): 'Invalid number of decimals: {}'}


def gate_functions(img, fdes):
    """FDE starts holding both a movabs of 10^15 and a byte load at displacement 0xd1."""
    addr, text = img.text()
    limits = set()
    for m in re.finditer(rb'[\x48\x49][\xb8-\xbf]' + re.escape(LIMIT.to_bytes(8, 'little')), text):
        try:
            limits.add(fdes.range_of(addr + m.start())['start'])
        except EvidenceError:
            pass
    loads = set()
    plain = re.compile(rb'\x0f[\xb6\xbe][\x80-\xbf]\xd1\x00\x00\x00', re.S)
    sib = re.compile(rb'\x0f[\xb6\xbe][\x84\x8c\x94\x9c\xa4\xac\xb4\xbc].\xd1\x00\x00\x00', re.S)
    for pattern in (plain, sib):
        for m in pattern.finditer(text):
            if pattern is plain and text[m.start() + 2] & 7 == 4:
                continue
            try:
                loads.add(fdes.range_of(addr + m.start())['start'])
            except EvidenceError:
                pass
    return {'limit_functions': len(limits), 'load_functions': len(loads), 'both': sorted(limits & loads)}


def f64_table(img):
    """How many leading entries of the table equal 10.0^d exactly."""
    count = 0
    while struct.unpack('<d', img.read(F64_TABLE + 8 * count, 8))[0] == 10.0 ** count:
        count += 1
    return count


def describe(result):
    if result[0] == 'ok':
        return f'ok:{result[2]}'
    if result[0] == 'tag':
        return f'tag:{result[1]:#x}'
    return 'panic'


def analyse(binary, data):
    check_digest(data)
    img = Image(data)
    fdes = Fdes(img)
    insns, ranges = load_code(binary, fdes, COPIES + HELPERS)
    texts = check_texts(img)
    decimals_entries = f64_table(img)
    gates_scan = gate_functions(img, fdes)
    checked(tuple(gates_scan['both']) == COPIES, f'gate functions changed: {gates_scan}')
    checked(decimals_entries >= 19, 'f64 power table is too short')
    slots = img.slots()
    copies = [find_copy(insns, ranges[start]) for start in COPIES]
    machines = [Machine(insns, img, slots, DROPS) for _ in COPIES]

    digests = []
    counts = {}
    for copy, machine in zip(copies, machines):
        digest = hashlib.sha256()
        total = oks = fails = 0
        for number, (exponent, wei) in enumerate(scale_vectors()):
            records = [(1, 0, 8), (1, exponent, 6)]
            got = run_gate(machine, copy, 1, wei, 2, 0, records, str(number).encode())
            want = gate_model(1, wei, 2, 0, records)
            if got != want:
                raise EvidenceError(f'{copy["start"]:#x} e={exponent} wei={wei}: {got} != {want}')
            total += 1
            oks += got[0] == 'ok'
            fails += got[0] == 'tag'
            digest.update(f'{exponent} {wei} {got}\n'.encode())
        gate_total = 0
        for number, (token, wei, native, data, flag) in enumerate(gate_vectors()):
            records = gate_records(token, flag)
            got = run_gate(machine, copy, token, wei, native, data, records, b'g%d' % number)
            want = gate_model(token, wei, native, data, records)
            if got != want:
                raise EvidenceError(f'{copy["start"]:#x} gate {token, wei, native, data, flag}: {got} != {want}')
            gate_total += 1
            digest.update(f'{token} {wei} {native} {data} {flag} {got}\n'.encode())
        digests.append(digest.hexdigest())
        counts[copy['start']] = {'scale': total, 'scale_ok': oks, 'scale_tag': fails, 'gates': gate_total}
    checked(len(set(digests)) == 1, 'the three copies disagree')
    checked(len({tuple(sorted(c.items())) for c in counts.values()}) == 1, 'copy counts disagree')

    copy, machine = copies[0], machines[0]
    table = []
    for exponent in range(-128, 128):
        row = [exponent]
        for wei in (0, 1, 10 ** 8):
            records = [(1, 0, 8), (1, exponent, 6)]
            row.append(describe(run_gate(machine, copy, 1, wei, None, 0, records, b't')))
        table.append(row)

    bounds = []
    for exponent in range(0, 128):
        records = [(1, 0, 8), (1, exponent, 6)]
        limit = (U256 - 1) // 10 ** exponent
        top = min(limit, MASK) if 10 ** exponent < U256 else None
        if top is None:
            checked(run_gate(machine, copy, 1, 0, None, 0, records, b'b')[0] == 'tag', 'e >= 78 must fail')
            bounds.append((exponent, 'none', 'all'))
            continue
        checked(run_gate(machine, copy, 1, top, None, 0, records, b'b')[0] == 'ok', f'bound at {exponent}')
        first = top + 1 if top < MASK else None
        if first is not None:
            checked(run_gate(machine, copy, 1, first, None, 0, records, b'b')[0] == 'tag', f'bound at {exponent}')
        bounds.append((exponent, top, first if first is not None else 'none'))

    gate_rows = []
    for token, wei, native, data, flag, note in (
            (0, LIMIT, None, 0, 1, 'token 0 at the limit'),
            (0, LIMIT + 1, None, 0, 1, 'token 0 above the limit'),
            (1, LIMIT + 100, None, 0, 1, 'other token above the limit'),
            (2, 100, 2, 0x1234, 1, 'native with data present'),
            (2, 100, 2, 0, 0, 'native, record flag ignored'),
            (1, 100, 2, 0, 0, 'token without the flag'),
            (1, 100, 2, 0, 2, 'flag must equal 1'),
            (3, 100, None, 0, 1, 'index past the table'),
            (1, 101, None, 0, 1, 'e=-2, remainder 1'),
            (1, 100, None, 0, 1, 'e=-2, exact')):
        records = gate_records(token, flag)
        gate_rows.append((token, wei, native, data, flag, note,
                          describe(run_gate(machine, copy, token, wei, native, data, records, b'r'))))

    guard_ok = all(run_gate(machine, copy, 1, 0, None, 0, [(1, 0, 8), (1, e, 6)], b'q')[0] == 'ok'
                   for e in range(GUARD_MIN, GUARD_MAX + 1))
    checked(guard_ok, 'a guarded exponent failed at amount zero')
    largest = MASK * 10 ** GUARD_MAX
    checked(largest < U256, 'guarded product exceeds U256')

    helper = {hex(start): {'start': ranges[start]['start'], 'end': ranges[start]['end'],
                           'executed': sum(1 for m in machines for ins in insns
                                           if ranges[start]['start'] <= ins[0] < ranges[start]['end']
                                           and ins[0] in m.seen)}
              for start in HELPERS}
    lead = []
    for exponent, wei in ((18, 10 ** 8), (10, 5 * 10 ** 9), (-2, 1000), (-2, 1001), (0, MASK), (19, 2)):
        lead.append({'exponent': exponent, 'amount': wei, 'binary': scale_model(exponent, wei, 0),
                     'lead': lead_u64(exponent, wei)})
    published = [{k: v for k, v in copy.items() if k != 'token_idx'} for copy in copies]
    result = {
        'target': {'path': BINARY, 'sha256': SHA256, 'coordinates': 'ELF virtual addresses'},
        'copies': published,
        'helpers': helper,
        'constants': {'token0_limit': LIMIT, 'native_exponent': 10, 'record_stride': RECORD_STRIDE,
                      'record_flag_offset': OFF_FLAG, 'record_exponent_offset': OFF_EXP,
                      'record_wei_decimals_offset': OFF_WEI_DEC, 'f64_table': F64_TABLE,
                      'f64_table_exact_entries': decimals_entries},
        'texts': texts,
        'gate_function_scan': gates_scan,
        'vectors': {'per_copy': counts[COPIES[0]], 'copies': len(copies), 'mismatches': 0, 'sha256': digests[0]},
        'guarded_range': {'min': GUARD_MIN, 'max': GUARD_MAX, 'largest_product': largest,
                          'largest_product_bits': largest.bit_length()},
        'lead': {'name': 'evm_amount_to_internal_wei', 'witnesses': lead},
    }
    return result, table, bounds, gate_rows, copies


def write_outputs(out, result, table, bounds, gate_rows, copies, data):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    lines = ['exponent_i8\tamount_0\tamount_1\tamount_1e8']
    lines += ['\t'.join(str(v) for v in row) for row in table]
    (out / 'exponent-table.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['exponent\tlargest_admitted_u64\tfirst_rejected_u64']
    lines += ['\t'.join(str(v) for v in row) for row in bounds]
    (out / 'boundaries.tsv').write_text('\n'.join(lines) + '\n')
    lines = ['token\tamount\tnative_index\tdata\trecord_flag\tcase\texit']
    lines += ['\t'.join(str(v) for v in row) for row in gate_rows]
    (out / 'gates.tsv').write_text('\n'.join(lines) + '\n')
    img = Image(data)
    rows = []
    for copy in copies:
        start, end = copy['exponent_load'], copy['exact_test'] + 3
        rows.append(f'# {start:#x}..{end:#x} exponent load to remainder test, VA then hex')
        for va in range(start, end, 16):
            rows.append(f'{va:#x} {img.read(va, min(16, end - va)).hex()}')
    (out / 'block-bytes.txt').write_text('\n'.join(rows) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    binary = ROOT / BINARY
    data = binary.read_bytes()
    result, table, bounds, gate_rows, copies = analyse(binary, data)
    write_outputs(args.out, result, table, bounds, gate_rows, copies, data)
    v = result['vectors']
    print(f"copies {v['copies']}, vectors per copy {v['per_copy']}, mismatches {v['mismatches']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
