#!/usr/bin/env python3
"""RE-009-C: the per-entry hashing mechanism inside three node #94 leaf functions.

Derives, from the instruction bytes of three pinned leaves, a blake3 XOF read of
0x800 bytes, a 16-bit lattice add whose byte order is decoded by register
dataflow (not assumed), and a saturating 64-bit count add. Output is sorted,
deterministic JSON. Uses only main-branch ELF helpers (elf_index, fde_extents).
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
BINARY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SLOT_NEW, SLOT_UPDATE, SLOT_XOF = 0x57700c0, 0x57700c8, 0x57700b0
XOF_LEN = 0x800
SAT_CONST = 0xffffffffffffffff
# Canonical Intel multi-byte NOP encodings (SDM Vol. 2B, NOP), used as loop alignment.
NOPS = {bytes.fromhex(h) for h in ('', '90', '6690', '0f1f00', '0f1f4000', '0f1f440000',
                                   '660f1f440000', '0f1f8000000000', '0f1f840000000000',
                                   '660f1f840000000000')}
REG = {0: 'ax', 1: 'cx', 2: 'dx', 3: 'bx', 4: 'sp', 5: 'bp', 6: 'si', 7: 'di'}

# One record per leaf. Field names are an inference from Locations (see README).
LEAVES = (
    {'leaf': 0x37f3f00, 'end': 0x37f4277, 'field_inference': 'accounts',
     'producer': 0x37d3070, 'top_call': 0x3269cbe,
     'fold': 0x3bc4760, 'producer_fold_calls': (0x37d3574, 0x37d386c),
     'rayon': 0x3443160, 'fold_rayon_call': 0x3bc47f4, 'rayon_leaf_call': 0x344320e,
     'preparer': 0x3284d90, 'leaf_preparer_call': 0x37f3f59,
     'call_new': 0x37f3f96, 'call_update': 0x37f4045, 'xof_len': 0x37f408a, 'call_xof': 0x37f408f,
     'loop_a': (0x37f40c3, 0x37f40d0, 0x37f4128), 'count': (0x37f4170, 0x37f41ba),
     'loop_b': (0x37f41ba, 0x37f41c0, 0x37f4218)},
    {'leaf': 0x37f4280, 'end': 0x37f4607, 'field_inference': 'contracts',
     'producer': 0x37d3bd0, 'top_call': 0x3269ed9,
     'fold': 0x3bc50e0, 'producer_fold_calls': (0x37d4080, 0x37d43ae),
     'rayon': 0x3440b50, 'fold_rayon_call': 0x3bc5174, 'rayon_leaf_call': 0x3440bfe,
     'preparer': 0x3284ad0, 'leaf_preparer_call': 0x37f42e7,
     'call_new': 0x37f4324, 'call_update': 0x37f43d6, 'xof_len': 0x37f441b, 'call_xof': 0x37f4420,
     'loop_a': (0x37f4454, 0x37f4460, 0x37f44b8), 'count': (0x37f4500, 0x37f454a),
     'loop_b': (0x37f454a, 0x37f4550, 0x37f45a8)},
    {'leaf': 0x37f4610, 'end': 0x37f49a7, 'field_inference': 'storage',
     'producer': 0x37d2550, 'top_call': 0x326a0e5,
     'fold': 0x3bc4a40, 'producer_fold_calls': (0x37d29c2, 0x37d2d00),
     'rayon': 0x343c390, 'fold_rayon_call': 0x3bc4ad4, 'rayon_leaf_call': 0x343c43e,
     'preparer': 0x3284c70, 'leaf_preparer_call': 0x37f4689,
     'call_new': 0x37f46c6, 'call_update': 0x37f477b, 'xof_len': 0x37f47c0, 'call_xof': 0x37f47c5,
     'loop_a': (0x37f47f9, 0x37f4800, 0x37f4858), 'count': (0x37f48a0, 0x37f48ea),
     'loop_b': (0x37f48ea, 0x37f48f0, 0x37f4948)},
)
TOP_FN, WRITER, WRITER_CALL = 0x3269ae0, 0x32699c0, 0x326a2e0


class Image:
    def __init__(self, data):
        self.data = data
        self.text = next(s for s in sections(data) if s['name'] == '.text')

    def read(self, va, n):
        t = self.text
        if not (t['address'] <= va and va + n <= t['address'] + t['size']):
            raise ValueError(f'{va:#x}+{n} outside .text')
        off = va - t['address'] + t['offset']
        return self.data[off:off + n]

    def rel32_target(self, va):
        b = self.read(va, 5)
        if b[0] != 0xe8:
            raise ValueError(f'{va:#x}: not call rel32')
        return va + 5 + struct.unpack('<i', b[1:])[0]

    def got_slot(self, va):
        b = self.read(va, 6)
        if b[:2] != b'\xff\x15':
            raise ValueError(f'{va:#x}: not call [rip+disp32]')
        return va + 6 + struct.unpack('<i', b[2:])[0]


def decode_lattice(img, init_va, body_va, end_va):
    """Straight-line dataflow over one loop body; returns the derived semantics."""
    b = img.read(body_va, end_va - body_va)
    init = img.read(init_va, body_va - init_va)
    if init[:1] == b'\xb8':
        start, pad = struct.unpack('<I', init[1:5])[0], init[5:]
    elif init[:2] == b'\x31\xc0':
        start, pad = 0, init[2:]
    else:
        raise ValueError(f'{init_va:#x}: unknown index init')
    if pad not in NOPS:
        raise ValueError(f'{init_va:#x}: index init padding is not a canonical NOP')
    val, stores, loads, swaps, pos = {}, [], 0, 0, 0
    step = bound = None
    while pos < len(b):
        if b[pos:pos + 2] == b'\x0f\xb7':          # movzx r32, WORD [rsp+rax*2+d32]
            modrm, sib = b[pos + 2], b[pos + 3]
            if modrm >> 6 != 2 or modrm & 7 != 4 or sib != 0x44:
                raise ValueError(f'{body_va + pos:#x}: unexpected movzx form')
            disp = struct.unpack_from('<i', b, pos + 4)[0]
            val[(modrm >> 3) & 7] = ('load', disp)
            loads += 1
            pos += 8
        elif b[pos:pos + 2] == b'\x66\xc1' and b[pos + 2] >> 3 == 0x18 and b[pos + 3] == 8:
            r = b[pos + 2] & 7                         # rol r16, 8  == 16-bit byte swap
            val[r] = ('swap', val[r])
            swaps += 1
            pos += 4
        elif b[pos] == 0x01 and b[pos + 1] >> 6 == 3:  # add r32, r32
            src, dst = (b[pos + 1] >> 3) & 7, b[pos + 1] & 7
            val[dst] = ('add', val[dst], val[src])
            pos += 2
        elif b[pos:pos + 2] == b'\x66\x89':          # mov WORD [rsp+rax*2+d32], r16
            modrm, sib = b[pos + 2], b[pos + 3]
            if modrm >> 6 != 2 or modrm & 7 != 4 or sib != 0x44:
                raise ValueError(f'{body_va + pos:#x}: unexpected store form')
            disp = struct.unpack_from('<i', b, pos + 4)[0]
            stores.append((disp, val[(modrm >> 3) & 7]))
            pos += 8
        elif b[pos:pos + 3] == b'\x48\x83\xc0':      # add rax, imm8
            step = b[pos + 3]
            pos += 4
        elif b[pos:pos + 2] == b'\x48\x3d':          # cmp rax, imm32
            bound = struct.unpack_from('<I', b, pos + 2)[0]
            pos += 6
        elif b[pos] == 0x75:                           # jne rel8
            if body_va + pos + 2 + struct.unpack_from('<b', b, pos + 1)[0] != body_va:
                raise ValueError(f'{body_va + pos:#x}: back-edge does not close the loop')
            pos += 2
        else:
            raise ValueError(f'{body_va + pos:#x}: undecoded byte {b[pos]:#04x}')
    if pos != len(b) or step is None or bound is None:
        raise ValueError(f'{body_va:#x}: incomplete loop')

    def be_add(v):
        return (v[0] == 'swap' and v[1][0] == 'add'
                and v[1][1][0] == 'swap' and v[1][1][1][0] == 'load'
                and v[1][2][0] == 'swap' and v[1][2][1][0] == 'load')
    if not stores or not all(be_add(v) for _, v in stores):
        raise ValueError(f'{body_va:#x}: store values are not swap(add(swap(load),swap(load)))')
    addend_offsets = set()
    for disp, v in stores:
        a, c = v[1][1][1][1], v[1][2][1][1]
        if disp not in (a, c):
            raise ValueError(f'{body_va:#x}: accumulator lane is not stored back in place')
        addend_offsets.add((c if disp == a else a) - disp)
    if len(addend_offsets) != 1:
        raise ValueError(f'{body_va:#x}: lanes do not share one addend buffer')
    base = min(d for d, _ in stores) + start * 2
    iters = len(range(start, bound, step))
    lanes = len(stores)
    return {
        'body': [hex(body_va), hex(end_va)], 'body_len': len(b),
        'body_sha256': hashlib.sha256(b).hexdigest(),
        'index_start': start, 'index_bound': hex(bound), 'index_step': step,
        'iterations': iters, 'lanes_per_iteration': lanes, 'u16_words_total': iters * lanes,
        'bytes_covered': iters * lanes * 2,
        'word_loads': loads, 'rol16_8_swaps': swaps, 'u16_stores': lanes,
        'accumulator_base': hex(base),
        'addend_minus_accumulator': hex(addend_offsets.pop()),
        'byte_order': 'big-endian', 'add_width_bits': 32, 'store_width_bits': 16,
        'overflow': 'wrapping-mod-2^16',
    }


def decode_count(img, va, end):
    b = img.read(va, end - va)
    sat = b.count(b'\x48\xc7\xc1\xff\xff\xff\xff')    # mov rcx, -1
    cmovb = b.count(b'\x48\x0f\x42')
    cmovae = b.count(b'\x48\x0f\x43')
    adds = b.count(b'\x48\x03')                        # add r64, [mem]
    if sat != 1 or cmovb < 1 or adds != 2:
        raise ValueError(f'{va:#x}: saturating count block not found')
    disps = []
    for i in range(len(b) - 7):
        # REX.W 8b/03/89 with ModRM mod=10 rm=100 and SIB 0x24: [rsp+disp32]
        if b[i] == 0x48 and b[i + 1] in (0x8b, 0x03, 0x89) and b[i + 2] >> 6 == 2 \
                and b[i + 2] & 7 == 4 and b[i + 3] == 0x24:
            disps.append(struct.unpack_from('<i', b, i + 4)[0])
    return {'block': [hex(va), hex(end)], 'block_len': len(b),
            'rsp_operands': [hex(x) for x in sorted(set(disps))],
            'block_sha256': hashlib.sha256(b).hexdigest(),
            'u64_adds': adds, 'saturate_const': hex(SAT_CONST), 'cmovb': cmovb, 'cmovae': cmovae,
            'overflow': 'saturating-u64'}


def leaf_extents(data):
    return {f['start']: f['end'] for f in fde_extents(data)[1]}


def analyse(data, require_sha=True, extents=None):
    """require_sha/extents exist so tests can tamper one byte and hit one check."""
    if require_sha and hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError('binary sha256 mismatch')
    img = Image(data)
    if extents is None:
        extents = leaf_extents(data)
    out_leaves = []
    for L in LEAVES:
        if extents.get(L['leaf']) != L['end']:
            raise ValueError(f"{L['leaf']:#x}: FDE extent mismatch")
        chain = {
            'top_to_producer': img.rel32_target(L['top_call']) == L['producer'],
            'producer_to_fold': all(img.rel32_target(v) == L['fold'] for v in L['producer_fold_calls']),
            'fold_to_rayon': img.rel32_target(L['fold_rayon_call']) == L['rayon'],
            'rayon_to_leaf': img.rel32_target(L['rayon_leaf_call']) == L['leaf'],
            'leaf_to_preparer': img.rel32_target(L['leaf_preparer_call']) == L['preparer'],
        }
        if not all(chain.values()):
            raise ValueError(f"{L['leaf']:#x}: call chain mismatch {chain}")
        slots = {'new': img.got_slot(L['call_new']), 'update': img.got_slot(L['call_update']),
                 'finalize_xof': img.got_slot(L['call_xof'])}
        if slots != {'new': SLOT_NEW, 'update': SLOT_UPDATE, 'finalize_xof': SLOT_XOF}:
            raise ValueError(f"{L['leaf']:#x}: blake3 slot mismatch")
        if img.read(L['xof_len'], 5) != b'\xba' + struct.pack('<I', XOF_LEN):
            raise ValueError(f"{L['xof_len']:#x}: xof length is not 0x800")
        merge = decode_lattice(img, *L['loop_b'])
        count = decode_count(img, *L['count'])
        mb, ma = int(merge['accumulator_base'], 16), int(merge['addend_minus_accumulator'], 16)
        trailer = sorted({mb + 0x800, mb + 0x808, mb + ma + 0x800, mb + ma + 0x808})
        if [int(x, 16) for x in count['rsp_operands']] != trailer:
            raise ValueError(f"{L['leaf']:#x}: count operands are not the +0x800/+0x808 trailer")
        out_leaves.append({
            'leaf': hex(L['leaf']), 'fde_end': hex(L['end']),
            'field_inference': L['field_inference'],
            'chain': {k: hex(L[k]) for k in ('producer', 'fold', 'rayon', 'preparer')},
            'chain_calls': {'top_call': hex(L['top_call']),
                            'producer_fold_calls': [hex(v) for v in L['producer_fold_calls']],
                            'fold_rayon_call': hex(L['fold_rayon_call']),
                            'rayon_leaf_call': hex(L['rayon_leaf_call']),
                            'leaf_preparer_call': hex(L['leaf_preparer_call'])},
            'blake3_slots': {k: hex(v) for k, v in slots.items()},
            'blake3_calls': {'new': hex(L['call_new']), 'update': hex(L['call_update']),
                             'finalize_xof': hex(L['call_xof'])},
            'xof_len': hex(XOF_LEN), 'xof_len_va': hex(L['xof_len']),
            'lattice_entry_add': decode_lattice(img, *L['loop_a']),
            'count_add': count,
            'lattice_merge_add': merge,
            'state_layout': {'size': hex(0x810), 'lattice': ['0x0', '0x800'],
                             'u64_counters': ['0x800', '0x808']},
        })
    if img.rel32_target(WRITER_CALL) != WRITER:
        raise ValueError('top function writer call mismatch')
    return {
        'schema': 're009c-lthash-mechanism/1',
        'binary_sha256': BINARY_SHA256,
        'coordinates': 'virtual addresses (VA), ELF64 x86-64',
        'top_function': hex(TOP_FN), 'writer': hex(WRITER), 'writer_call': hex(WRITER_CALL),
        'leaves': out_leaves,
        'counts': {'leaves': len(out_leaves), 'lattice_loops': 2 * len(out_leaves),
                   'count_blocks': len(out_leaves)},
    }


def render(result):
    return json.dumps(result, indent=2, sort_keys=True) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path)
    a = p.parse_args(argv)
    text = render(analyse(a.binary.read_bytes()))
    if a.out:
        a.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
