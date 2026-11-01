#!/usr/bin/env python3
"""Recover two #94 tagged price-scaling helpers from pinned ELF bytes.

The arithmetic evaluator follows the selected instruction sequence; it does not
execute native code. Output contains no disassembler-dependent records.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
COPIES = {
    0x232e2e0: 'fb67f9fba157362f742ba683c41c0e1c38898148ac193d052010d6ef076fa600',
    0x49e4ca0: 'd918d6f12091130454759fd45b1e3320684c8b7009f315ef9463b777652fdde4',
}
MASKS = ((0x127, 4), (0x12d, 4), (0x134, 4), (0x13a, 4))
# Instructions selected for branch-table extraction, offsets from either entry.
BRANCHES = (0xd, 0x32, 0x46, 0x60, 0x80, 0x91, 0x96, 0xa0,
            0xbb, 0xce, 0xe0, 0xf2, 0xf7)


def verified(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node #94 SHA-256 mismatch')


def section_offset(sections, va, size=1):
    if size < 1:
        raise ValueError('empty or negative range')
    found = [s['offset'] + va - s['address'] for s in sections
             if s['type'] != 8 and s['address'] <= va and
             va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('address has no unique file-backed section')
    return found[0]


def decode_branch(code, offset):
    op = code[offset]
    if 0x70 <= op <= 0x7f:
        length, disp = 2, struct.unpack_from('<b', code, offset + 1)[0]
        name = ('jcc8-%x' % (op & 15))
    elif op == 0x0f and 0x80 <= code[offset + 1] <= 0x8f:
        length, disp = 6, struct.unpack_from('<i', code, offset + 2)[0]
        name = ('jcc32-%x' % (code[offset + 1] & 15))
    else:
        raise ValueError('expected conditional branch')
    target = offset + length + disp
    if not 0 <= target < len(code):
        raise ValueError('conditional branch outside function')
    return name, target


def examine(data):
    verified(data)
    secs = elf_index.sections(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    records = []
    for start, expected in COPIES.items():
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1:
            raise ValueError('missing or duplicate FDE')
        f = found[0]
        size = f['end'] - start
        off = section_offset(secs, start, size)
        raw = bytes(data[off:off + size])
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('function bytes do not match')
        records.append((start, f, off, raw))
    a, b = (r[3] for r in records)
    ma, mb = bytearray(a), bytearray(b)
    for at, count in MASKS:
        ma[at:at + count] = b'\x00' * count
        mb[at:at + count] = b'\x00' * count
    if ma != mb:
        raise ValueError('copies differ outside RIP displacements')
    # Also resolve the masked displacements: equal normalized bytes alone do not
    # establish that the panic paths refer to the same locations and slots.
    refs = []
    for start, f, off, code in records:
        row = []
        for at, count in MASKS:
            displacement = struct.unpack_from('<i', code, at)[0]
            row.append(start + at + count + displacement)
        refs.append(row)
    if refs[0] != refs[1]:
        raise ValueError('masked operands resolve to different targets')
    # Fixed-form checks guard the little-endian immediate extraction below.
    expected = {
        0x1a: '48ba', 0x38: '4869c2', 0x5d: '83f8',
        0x82: '486bf6', 0xae: '4869f6', 0xbd: '4869f6',
        0xd5: '48f7f6',
    }
    # Verify important instruction prefixes, while the whole-body hash above
    # also protects every unselected byte and every branch destination.
    for at, prefix in expected.items():
        raw = bytes.fromhex(prefix)
        if a[at:at + len(raw)] != raw:
            raise ValueError('unexpected instruction form at %#x' % at)
    for at in BRANCHES:
        decode_branch(a, at)
    return secs, records, refs


def constants(code):
    return {
        'bypass_tag': code[0x0c],
        'reciprocal': struct.unpack_from('<Q', code, 0x1c)[0],
        'quotient_shift': code[0x2d],
        'asset_radix': struct.unpack_from('<I', code, 0x3b)[0],
        'decimal_limit': code[0x5f],
        'exponent_bias': code[0x70],
        'error_status': struct.unpack_from('<H', code, 0x9b)[0],
        'success_status': struct.unpack_from('<H', code, 0x116)[0],
        'times_100': code[0x85],
        'times_10000': struct.unpack_from('<I', code, 0xb1)[0],
        'times_100000000': struct.unpack_from('<I', code, 0xc0)[0],
    }


def ladder(d, c):
    """The exact bit-selected multiply sequence after the decimal guard."""
    if not 0 <= d < c['decimal_limit']:
        raise ValueError('decimal guard')
    e = d + c['exponent_bias']
    n = 1 + 9 * (e & 1)
    if e == 1:
        return n
    if e & 2:
        n *= c['times_100']
        if e & 14 == 2:
            return n
    if e & 4:
        n *= c['times_10000']
        if e & 12 == 4:
            return n
    elif d != c['decimal_limit'] - 1:
        raise ValueError('unreachable ladder error arm')
    return n * c['times_100000000']


def evaluate(tag, x, extra, asset, dex, count, decimals, c):
    """Emulate the checked arithmetic and branches, not memory/panic helpers."""
    if not (0 <= tag <= 255 and 0 <= extra <= 255 and
            0 <= x < 2**64 and 0 <= asset < 2**64 and
            0 <= dex < 2**64 and 0 <= count < 2**64 and 0 <= decimals <= 255):
        raise ValueError('input out of range')
    if tag == c['bypass_tag']:
        return ('passthrough', x & 255, tag)
    q = (asset * c['reciprocal']) >> (64 + c['quotient_shift'])
    index = asset - q * c['asset_radix']
    if q != dex or index >= count:
        return ('asset_panic',)
    if decimals >= c['decimal_limit']:
        return ('decimal_panic',)
    scale = ladder(decimals, c)
    # Both x86 DIV branches start with a zero high half and use identical
    # quotient/remainder arithmetic; the OR selects operand width only.
    quotient, rem = divmod(x, scale)
    if x < scale or rem:
        return ('error', c['error_status'])
    return ('ok', quotient, extra, tag)


def oracle(tag, x, extra, asset, dex, count, decimals):
    if tag == 2:
        return ('passthrough', x & 255, tag)
    q, index = divmod(asset, 10000)
    if q != dex or index >= count:
        return ('asset_panic',)
    if decimals >= 7:
        return ('decimal_panic',)
    scale = 10 ** (decimals + 2)
    if x < scale or x % scale:
        return ('error', 0x65)
    return ('ok', x // scale, extra, tag)


def write_tsv(path, header, rows):
    path.write_text('\t'.join(header) + '\n' + ''.join('\t'.join(map(str, r)) + '\n' for r in rows), encoding='utf-8')


def generate(data, out):
    secs, records, refs = examine(data)
    c = constants(records[0][3])
    if c != {'bypass_tag': 2, 'reciprocal': 0x346dc5d63886594b,
             'quotient_shift': 11, 'asset_radix': 10000, 'decimal_limit': 7,
             'exponent_bias': 2, 'error_status': 0x65, 'success_status': 0x186,
             'times_100': 100, 'times_10000': 10000, 'times_100000000': 100000000}:
        raise ValueError('unexpected arithmetic constants')
    # M = ceil(2^75 / 10000). For x = q*10000 + r, q<=Q,
    # r<=9999: q*(M*10000-2^75)+r*M < 2^75 proves
    # floor(x*M/2^75) == floor(x/10000) over all u64 values.
    power = 1 << (64 + c['quotient_shift'])
    radix, m = c['asset_radix'], c['reciprocal']
    delta = m * radix - power
    qmax = ((1 << 64) - 1) // radix
    bound = qmax * delta + (radix - 1) * m
    if not (0 <= delta < radix and bound < power):
        raise ValueError('reciprocal proof failed')
    out.mkdir(parents=True, exist_ok=True)
    code = records[0][3]
    prefix = code[:40]
    text = next(s for s in secs if s['name'] == '.text')
    text_data = data[text['offset']:text['offset'] + text['size']]
    hits, at = [], 0
    while True:
        at = text_data.find(prefix, at)
        if at < 0:
            break
        hits.append(text['address'] + at)
        at += 1
    if hits != list(COPIES):
        raise ValueError('unexpected prefix census')
    (out / 'function-bytes.txt').write_text(
        ''.join('%s %s\n' % (hex(start + i), raw[i:i + 16].hex())
                for start, f, off, raw in records for i in range(0, len(raw), 16)), encoding='utf-8')
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('truncated relocation section')
    relocs = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, pos)
        if info & 0xffffffff == 8:
            if where in relocs:
                raise ValueError('duplicate relative relocation')
            relocs[where] = addend
    locations = []
    for location in (refs[0][0], refs[0][2]):
        off = section_offset(secs, location, 24)
        length, line, col = struct.unpack_from('<QII', data, off + 8)
        if not 0 < length <= 256 or location not in relocs:
            raise ValueError('invalid location record')
        file_off = section_offset(secs, relocs[location], length)
        path = data[file_off:file_off + length]
        # Keep the public source suffix, not the original builder's path.
        suffix = b'l1/src/perp_meta.rs'
        if not path.endswith(suffix):
            raise ValueError('unexpected source location')
        locations.append((hex(location), suffix.decode('ascii'), line, col))
    write_tsv(out / 'locations.tsv', ['record_va', 'path_suffix', 'line', 'column'], locations)
    write_tsv(out / 'copies.tsv', ['entry_va', 'end_va', 'file_offset', 'fde_va', 'body_sha256'],
              [(hex(start), hex(f['end']), hex(off), hex(f['fde']), hashlib.sha256(raw).hexdigest())
               for start, f, off, raw in records])
    write_tsv(out / 'branches.tsv', ['offset', 'instruction', 'target_offset'],
              [(hex(p), *[v if isinstance(v, str) else hex(v) for v in decode_branch(code, p)]) for p in BRANCHES])
    divisor_rows = []
    for d in range(256):
        if d < c['decimal_limit']:
            s = ladder(d, c)
            if s != 10 ** (d + 2):
                raise ValueError('ladder mismatch')
            divisor_rows.append((d, 'divide', s))
        else:
            divisor_rows.append((d, 'panic', '-'))
    write_tsv(out / 'decimal-bytes.tsv', ['byte', 'outcome', 'divisor'], divisor_rows)
    values = {0, 1, (1 << 32) - 1, 1 << 32, (1 << 64) - 1}
    cases = []
    for d in range(7):
        scale = ladder(d, c)
        for x in sorted(values | {scale - 1, scale, scale + 1, 2 * scale, (1 << 64) // scale * scale}):
            cases.append((0, x, 0xa5, 10023, 1, 24, d))
    for tag in range(256):
        cases.append((tag, 100, 0xa5, 10023, 1, 24, 0))
    cases += [(0, 100, 7, 10023, 1, 24, d) for d in range(256)]
    cases += [(0, 100, 7, 10023, 0, 24, 0), (0, 100, 7, 10023, 1, 23, 0),
              (0, 100, 7, 10023, 1, 24, 7), (2, 0, 7, 10023, 0, 0, 255)]
    rows = []
    for case in cases:
        got = evaluate(*case, c)
        if got != oracle(*case):
            raise ValueError('model mismatch')
        rows.append((*case, json.dumps(got, separators=(',', ':'))))
    write_tsv(out / 'vectors.tsv', ['tag', 'value', 'extra', 'asset', 'dex', 'count', 'decimals', 'result'], rows)
    summary = {
        'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual address; offsets are file offsets',
        'copies': len(records), 'prefix_bytes': len(prefix), 'prefix_hits': [hex(x) for x in hits],
        'body_size': len(code), 'masked_rip_displacements': [[hex(a), n] for a, n in MASKS],
        'resolved_rip_targets': [hex(x) for x in refs[0]], 'constants_from_bytes': c,
        'reciprocal_proof': {'shift': 64 + c['quotient_shift'], 'delta': delta, 'maximum_quotient': qmax,
                             'upper_bound': bound, 'power': power},
        'decimal_values_checked': len(divisor_rows), 'vector_cases': len(rows), 'vector_mismatches': 0,
        'scope': 'Static code patterns and arithmetic model; no captured binary execution.',
    }
    (out / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
