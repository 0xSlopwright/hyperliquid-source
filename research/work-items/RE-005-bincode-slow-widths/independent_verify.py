#!/usr/bin/env python3
"""Independent check of slow-sites.json. Imports nothing from tools/.

Re-derives from artifacts/node/94/hl-node with its own ELF/relocation/FDE
reader: the two Reader FDEs and jump tables, the u32 slice decoder and its
slow-branch GOT, the u64 slice slow-branch GOT, the shared error builder, and
the call-site counts into each Reader. Prints exactly one verdict line:
PASS, FAIL or INCONCLUSIVE. Exit codes: 0 PASS, 1 FAIL, 2 INCONCLUSIVE.
No assert; valid under -O.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / 'artifacts/node/94/hl-node'
BIN_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

READERS = {
    0x466d850: (0x466d975, 0x6f6ec8, (0x466d8b7, 0x466d8c4, 0x466d945, 0x466d92d)),
    0x466d980: (0x466dabc, 0x6f6ed8, (0x466d9e7, 0x466da01, 0x466d9f4, 0x466da8c)),
}
U32_SLICE = (0x466bc10, 0x466bd03, 0x6f6e98, (0x466bc79, 0x466bc85, 0x466bcd3, 0x466bcbb),
             0x5775138, 0x466d850)
U64_SLOW_GOT = (0x57745e0, 0x466d980)
ERR_BUILDER = (0x466dac0, 0x466dace, 0x57745e8)
CALL_COUNTS = {0x466d850: 2, 0x466d980: 12}
ANCHORS = (
    (0x466bc3d, bytes.fromhex('4883f804')),
    (0x466bc41, bytes.fromhex('7664')),
    (0x466bcb0, bytes.fromhex('ff1582941001')),
    (0x466bd3d, bytes.fromhex('4883f808')),
    (0x466bd41, bytes.fromhex('766e')),
    (0x466bdba, bytes.fromhex('ff1520881001')),
    (0x466d870, bytes.fromhex('4181f8fb000000')),
    (0x466d9a0, bytes.fromhex('4981f8fb000000')),
    (0x466da8f, bytes.fromhex('be03000000')),
    (0x466d930, bytes.fromhex('be02000000')),
    (0x466dac3, bytes.fromhex('c60703')),
)


class Bad(Exception):
    pass


def verdict(word, msg, code):
    print(f'RE-005 slow/widths independent verify: {word}: {msg}')
    raise SystemExit(code)


class Img:
    def __init__(self, d):
        self.d = d
        phoff, = struct.unpack_from('<Q', d, 0x20)
        phent, phnum = struct.unpack_from('<HH', d, 0x36)
        self.loads = []
        for i in range(phnum):
            p = phoff + i * phent
            typ, = struct.unpack_from('<I', d, p)
            off, va, _pa, fsz = struct.unpack_from('<QQQQ', d, p + 8)
            if typ == 1:
                self.loads.append((va, off, fsz))
        shoff, = struct.unpack_from('<Q', d, 0x28)
        shent, shnum, shstr = struct.unpack_from('<HHH', d, 0x3A)
        hdr = [struct.unpack_from('<IIQQQQ', d, shoff + i * shent) for i in range(shnum)]
        so = hdr[shstr][4]
        self.sec = {}
        for name, typ, _f, va, off, size in hdr:
            nm = d[so + name:d.index(b'\0', so + name)].decode()
            self.sec[nm] = (typ, va, off, size)

    def off(self, va):
        for v, o, s in self.loads:
            if v <= va < v + s:
                return o + va - v
        raise Bad(f'unmapped {va:#x}')

    def rd(self, va, n):
        o = self.off(va)
        return self.d[o:o + n]

    def relative(self):
        out = {}
        for nm, (typ, _va, off, size) in self.sec.items():
            if typ != 4:
                continue
            for k in range(off, off + size, 24):
                r_off, info, add = struct.unpack_from('<QQq', self.d, k)
                if info & 0xFFFFFFFF == 8:
                    out[r_off] = add
        return out

    def fde_extents(self):
        """{pc_begin: pc_end} from .eh_frame_hdr's binary-search table + each FDE body."""
        _t, hva, hoff, _hs = self.sec['.eh_frame_hdr']
        h = self.d
        if h[hoff:hoff + 4] != b'\x01\x1b\x03\x3b':
            raise Bad('eh_frame_hdr encoding')
        count, = struct.unpack_from('<I', h, hoff + 8)
        _t, eva, eoff, _es = self.sec['.eh_frame']
        out = {}
        for i in range(count):
            start_rel, fde_rel = struct.unpack_from('<ii', h, hoff + 12 + i * 8)
            start = hva + start_rel
            fde_va = hva + fde_rel
            fo = eoff + fde_va - eva
            length, cie_ptr = struct.unpack_from('<II', h, fo)
            if length in (0, 0xffffffff) or cie_ptr == 0:
                raise Bad(f'FDE at {fde_va:#x} malformed')
            begin_rel, pc_range = struct.unpack_from('<iI', h, fo + 8)
            begin = fde_va + 8 + begin_rel
            if begin != start:
                raise Bad(f'FDE at {fde_va:#x} disagrees with index')
            out[begin] = begin + pc_range
        return out


def i32(b, k):
    return struct.unpack_from('<i', b, k)[0]


def h(x):
    return int(x, 16) if isinstance(x, str) else x


def check(img, js):
    if js.get('target', {}).get('sha256') != BIN_SHA:
        raise Bad('json target sha256')
    rel = img.relative()
    fdes = img.fde_extents()
    for start, (end, table, targets) in READERS.items():
        if fdes.get(start) != end:
            raise Bad(f'Reader FDE {start:#x}')
        tb = img.rd(table, 16)
        got = tuple(table + i32(tb, 4 * i) for i in range(4))
        if got != targets:
            raise Bad(f'Reader table {table:#x}')
    start, end, table, targets, got_slot, got_tgt = U32_SLICE
    if fdes.get(start) != end:
        raise Bad('u32 slice FDE')
    tb = img.rd(table, 16)
    got = tuple(table + i32(tb, 4 * i) for i in range(4))
    if got != targets:
        raise Bad('u32 slice table')
    if rel.get(got_slot) != got_tgt:
        raise Bad('u32 GOT')
    if rel.get(U64_SLOW_GOT[0]) != U64_SLOW_GOT[1]:
        raise Bad('u64 GOT')
    eb_s, eb_e, eb_got = ERR_BUILDER
    if fdes.get(eb_s) != eb_e or rel.get(eb_got) != eb_s:
        raise Bad('error builder')
    for va, want in ANCHORS:
        if img.rd(va, len(want)) != want:
            raise Bad(f'anchor {va:#x}')
    text = img.sec['.text']
    _t, tva, toff, tsize = text
    tb = img.d[toff:toff + tsize]
    counts = dict.fromkeys(CALL_COUNTS, 0)
    for i in range(len(tb) - 6):
        if tb[i:i + 2] != b'\xff\x15':
            continue
        slot = tva + i + 6 + i32(tb, i + 2)
        tgt = rel.get(slot)
        if tgt in counts:
            counts[tgt] += 1
    if counts != CALL_COUNTS:
        raise Bad(f'call counts {counts}')
    if {h(k): v for k, v in js['reader_call_counts'].items()} != CALL_COUNTS:
        raise Bad('json call counts')
    if len(js['readers']) != 2 or len(js['decode_vectors']) != 22:
        raise Bad('json reader/vector counts')
    for r in js['readers']:
        start = h(r['fde_start'])
        if start not in READERS or h(r['fde_end']) != READERS[start][0]:
            raise Bad(f'json reader FDE {r["name"]}')
        want = {f'{0xfb + i:#x}': f'{t:#x}' for i, t in enumerate(READERS[start][2])}
        if r['jump_targets_by_tag'] != want:
            raise Bad(f'json reader table {r["name"]}')
    u32 = js['u32_slice_decoder']
    if (h(u32['fde_start']), h(u32['slow_path']['reader']), h(u32['slow_path']['got_slot'])) != (
            U32_SLICE[0], U32_SLICE[5], U32_SLICE[4]):
        raise Bad('json u32 slice')
    br = js['u64_slice_slow_branch']
    if (h(br['slow_path']['got_slot']), h(br['slow_path']['reader'])) != U64_SLOW_GOT:
        raise Bad('json u64 slow branch')
    return counts


def main():
    pj = HERE / 'slow-sites.json'
    if not BIN.is_file() or not pj.is_file():
        verdict('INCONCLUSIVE', f'missing {BIN if not BIN.is_file() else pj}', 2)
    d = BIN.read_bytes()
    if hashlib.sha256(d).hexdigest() != BIN_SHA:
        verdict('INCONCLUSIVE', 'binary is not the pinned node #94 hl-node', 2)
    try:
        js = json.loads(pj.read_text())
        counts = check(Img(d), js)
    except (Bad, KeyError, ValueError, struct.error, IndexError) as e:
        verdict('FAIL', str(e), 1)
    verdict('PASS', f'readers {[hex(k) for k in CALL_COUNTS]}, calls {list(counts.values())}, vectors 22', 0)


if __name__ == '__main__':
    main()
