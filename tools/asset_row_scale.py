#!/usr/bin/env python3
"""Node 94 asset-row quantity display conversion; static, digest-bound evidence."""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x23118b0: (0x2311bdc, '2a2acf86c04aec45e7e555461586e0b6a6f635415dec76db87ad1366199eda55'),
    0x25670c0: (0x2567241, 'e09aa1bd86d6fe7e30c71146278899147bdd0b035d5cbaaf215f1a2021674636'),
    0x2a3deb0: (0x2a3e0f6, '705ec77be9f966d52e7f1d2c792814a1052b64e24f31f1315d9ab26f5bf08c31'),
    0x26b2530: (0x26b2724, '214babef37de9aa016d8c4153b6e7870b73122a7fb1626c82b371e30c6204716'),
}
# Bytes spanning instructions that connect the conversion, metadata and wrapper.
ANCHORS = {
    0x23118fe: '48ba4b598638d6c56d344889c848f7e248c1ea0b493b5530',
    0x23119cb: '420fb644382a660f28c8660f15c8f20f58c8488d0d9c000bfe f20f5e0cc1'.replace(' ', ''),
    0x2311a1e: '420fb644382a66480f6ecd660f620d',
    0x2311b43: '48c1e80548b97187602f277b5e0448f7e148c1ea05',
    0x26b2629: '488dbc24c80000004c89fe4889dae874f2c5ff',
}


def fail(message):
    raise ValueError(message)


def file_offset(secs, va, size):
    found = [s['offset'] + va - s['address'] for s in secs
             if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        fail('address has no unique file-backed section')
    return found[0]


def read_va(data, secs, va, size):
    off = file_offset(secs, va, size)
    return data[off:off + size]


def round_even_ratio(n, d):
    q, r = divmod(n, d)
    return q + (2 * r > d or (2 * r == d and q & 1))


def to_binary64(value):
    """Correctly round a positive normal rational to IEEE binary64 bits."""
    if value == 0:
        return 0
    if value < 0:
        fail('negative value')
    n, d = value.numerator, value.denominator
    exponent = n.bit_length() - d.bit_length()
    if exponent >= 0:
        if n < d << exponent:
            exponent -= 1
    elif n << -exponent < d:
        exponent -= 1
    if not -1022 <= exponent <= 1023:
        fail('outside normal binary64 range')
    shift = 52 - exponent
    significand = round_even_ratio(n << shift, d) if shift >= 0 else round_even_ratio(n, d << -shift)
    if significand == 1 << 53:
        significand >>= 1
        exponent += 1
    if exponent > 1023:
        fail('overflow')
    return ((exponent + 1023) << 52) | (significand - (1 << 52))


def as_fraction(bits):
    if bits == 0:
        return Fraction(0)
    exponent = ((bits >> 52) & 0x7ff) - 1023 - 52
    significand = (1 << 52) | (bits & ((1 << 52) - 1))
    return Fraction(significand << exponent, 1) if exponent >= 0 else Fraction(significand, 1 << -exponent)


def convert(raw, divisor):
    if not 0 <= raw < 1 << 64 or divisor <= 0:
        fail('invalid raw value or divisor')
    # Two roundings: u64 -> binary64, then the scalar division.
    first = to_binary64(Fraction(raw))
    second = to_binary64(as_fraction(first) / divisor)
    return first, second


def quotient_lemma(m, d, shift, max_input):
    # m=ceil(2^shift/d), and the reciprocal excess is less than one
    # denominator unit throughout the domain. Therefore floor(x*m/2^shift)=x//d.
    scale = 1 << shift
    excess = m * d - scale
    if not (0 <= excess < d and excess * max_input < scale):
        fail('reciprocal proof failed')
    return {'divisor': d, 'multiplier': hex(m), 'shift': shift, 'max_input': str(max_input),
            'excess': str(excess), 'inequality_left': str(excess * max_input),
            'inequality_right': str(scale)}


def inspect(data, check_hash=True):
    if check_hash and hashlib.sha256(data).hexdigest() != SHA:
        fail('node #94 digest mismatch')
    secs = elf_index.sections(data)
    _, fdes = fde_extents.eh_frame_records(data, secs)
    by_start = {}
    for row in fdes:
        by_start.setdefault(row['start'], []).append(row)
    functions = []
    for start, (end, digest) in FUNCTIONS.items():
        rows = by_start.get(start, [])
        if len(rows) != 1 or rows[0]['end'] != end:
            fail('missing, duplicate or changed FDE')
        raw = read_va(data, secs, start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            fail('function bytes changed')
        functions.append({'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'file_offset': hex(file_offset(secs, start, len(raw))),
                          'size': len(raw), 'sha256': digest, 'bytes_hex': raw.hex()})
    anchors = []
    for va, pattern in sorted(ANCHORS.items()):
        expected = bytes.fromhex(pattern)
        actual = read_va(data, secs, va, len(expected))
        if actual != expected:
            fail('instruction anchor changed at ' + hex(va))
        anchors.append({'va': hex(va), 'bytes': actual.hex()})
    constants = []
    for va, length, name in [(0x203e80, 16, 'u64 unpack mask'), (0x202ea0, 16, 'u64 subtract lanes'),
                              (0x20ae60, 8, 'notional divisor'), (0x20af40, 8, 'factor'),
                              (0x20a510, 8, 'u64 upper endpoint'), (0x20a218, 8, 'largest f64 below 2^64'),
                              (0x20a7f0, 8, '2^63')]:
        b = read_va(data, secs, va, length)
        constants.append({'name': name, 'va': hex(va), 'file_offset': hex(file_offset(secs, va, length)), 'bytes': b.hex()})
    if read_va(data, secs, 0x203e80, 8).hex() != '0000304300003045' or read_va(data, secs, 0x202ea0, 16).hex() != '00000000000030430000000000003045':
        fail('conversion constants changed')
    powers = []
    for exponent in range(7):
        va = 0x3c1a80 + 8 * exponent
        b = read_va(data, secs, va, 8)
        bits = struct.unpack('<Q', b)[0]
        if bits != to_binary64(Fraction(10 ** exponent)):
            fail('power table mismatch')
        powers.append({'index': exponent, 'va': hex(va), 'file_offset': hex(file_offset(secs, va, 8)),
                       'bytes_le': b.hex(), 'binary64_bits': f'{bits:016x}', 'divisor': 10 ** exponent})
    branch_specs = [
        (0x2311916, 'quotient differs from metadata id', 0x75),
        (0x2311926, 'remainder outside asset row count', 0x73),
        (0x23119b0, 'first quantity is zero', 0x74),
        (0x23119f8, 'second quantity is nonzero', 0x75),
        (0x2311a0d, 'second quantity is zero', 0x74),
    ]
    branches = []
    for va, condition, opcode in branch_specs:
        raw = read_va(data, secs, va, 2)
        if raw[0] != opcode:
            fail('branch opcode changed')
        branches.append({'site_va': hex(va), 'condition': condition,
                         'bytes': raw.hex(), 'target_va': hex(va + 2 + struct.unpack('<b', raw[1:])[0])})
    panic_branch = read_va(data, secs, 0x2311974, 6)
    if panic_branch[:2] != bytes.fromhex('0f85'):
        fail('invalid-id branch changed')
    branches.append({'site_va': '0x2311974', 'condition': 'invalid id and either quantity nonzero',
                     'bytes': panic_branch.hex(),
                     'target_va': hex(0x231197a + struct.unpack('<i', panic_branch[2:])[0])})
    # Both LEAs must resolve to the same power table; the following indexed DIVSD
    # loads have already been pinned by the whole-function byte hash.
    for va in (0x23119dd, 0x2311a45):
        lea = read_va(data, secs, va, 7)
        if lea[:3] != bytes.fromhex('488d0d') or va + 7 + struct.unpack('<i', lea[3:])[0] != 0x3c1a80:
            fail('table reference changed')
    # The independently located serializer ties record offsets to key bytes.
    specs = [
        (0x2a3df1e, 0x2a3df2d, 0, '4c89f1'),
        (0x2a3df42, 0x2a3df3e, 0x40, '498d4e40'),
        (0x2a3df63, 0x2a3df5f, 0x54, '498d4e54'),
        (0x2a3df84, 0x2a3df80, 0x18, '498d4e18'),
        (0x2a3dfa5, 0x2a3dfa1, 0x20, '498d4e20'),
        (0x2a3dfc6, 0x2a3dfc2, 0x28, '498d4e28'),
        (0x2a3dfe3, 0x2a3dfdf, 0x30, '498d4e30'),
        (0x2a3e000, 0x2a3dffc, 0x55, '498d4e55'),
        (0x2a3e01d, 0x2a3e019, 0x56, '498d4e56'),
        (0x2a3e03a, 0x2a3e036, 0x38, '4983c638'),
    ]
    fields = []
    calls = [0x2a3df30, 0x2a3df51, 0x2a3df72, 0x2a3df93, 0x2a3dfb4,
             0x2a3dfd5, 0x2a3dff2, 0x2a3e00f, 0x2a3e02c, 0x2a3e04c]
    for (key_site, field_site, offset, pattern), call_va in zip(specs, calls):
        expected = bytes.fromhex(pattern)
        if read_va(data, secs, field_site, len(expected)) != expected:
            fail('field pointer instruction changed')
        lea = read_va(data, secs, key_site, 15)
        if lea[:3] != bytes.fromhex('488d35') or lea[7:11] != bytes.fromhex('4889e7ba'):
            fail('key instruction changed')
        key_va = key_site + 7 + struct.unpack('<i', lea[3:7])[0]
        length = struct.unpack('<I', lea[11:15])[0]
        if not 0 < length <= 16:
            fail('bad serializer key length')
        key = read_va(data, secs, key_va, length).decode('ascii')
        call = read_va(data, secs, call_va, 14)
        if call[0] != 0xe8 or call[5:8] != bytes.fromhex('4885c0'):
            fail('serializer call or error test changed')
        target = call_va + 5 + struct.unpack('<i', call[1:5])[0]
        branch_va = call_va + 8
        if call[8:10] == bytes.fromhex('0f85'):
            error = branch_va + 6 + struct.unpack('<i', call[10:14])[0]
        elif call[8] == 0x75:
            error = branch_va + 2 + struct.unpack('<b', call[9:10])[0]
        elif call[8] == 0x74:  # last field: success branches over the error block
            error = branch_va + 2
        else:
            fail('serializer error branch changed')
        if error != 0x2a3e056:
            fail('serializer error destination changed')
        fields.append({'key': key, 'record_offset': hex(offset), 'key_va': hex(key_va),
                       'key_instruction_va': hex(key_site), 'field_instruction_va': hex(field_site),
                       'call_va': hex(call_va), 'callee_va': hex(target), 'error_va': hex(error)})
    if [f['key'] for f in fields] != ['coin', 'user', 'side', 'sz', 'executedSz', 'executedNtl',
                                      'minutes', 'reduceOnly', 'randomize', 'timestamp']:
        fail('serializer keys changed')
    # The wrapper's rel32 direct call must reach the selected conversion entry.
    call = read_va(data, secs, 0x26b2637, 5)
    if call[0] != 0xe8 or 0x26b263c + struct.unpack('<i', call[1:])[0] != 0x23118b0:
        fail('wrapper edge changed')
    allocation_call = read_va(data, secs, 0x256718a, 5)
    if allocation_call[0] != 0xe8 or 0x256718f + struct.unpack('<i', allocation_call[1:])[0] != 0x26b2530:
        fail('allocation wrapper edge changed')
    limit_bytes = read_va(data, secs, 0x25670e2, 8)
    if int.from_bytes(limit_bytes, 'little') != ((1 << 63) - 1) // 96:
        fail('allocation count limit changed')
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rela) != 1 or rela[0]['size'] % 24:
        fail('bad relocation section')
    slots = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where in (0x576f6d8, 0x576e470):
            if info & 0xffffffff != 8:
                fail('unexpected relocation type')
            slots.append({'slot_va': hex(where), 'type': info & 0xffffffff, 'target_va': hex(addend)})
    if sorted(x['slot_va'] for x in slots) != sorted(['0x576f6d8', '0x576e470']):
        fail('missing or duplicate relocation')
    slots.sort(key=lambda x: x['slot_va'])
    return {'binary_sha256': SHA, 'coordinate_system': 'ELF virtual address, file offset',
            'functions': functions, 'anchors': anchors, 'conditional_branches': branches, 'constants': constants,
            'power_table': powers, 'serializer_fields': fields, 'wrapper_call_va': '0x26b2637',
            'allocation_call_va': '0x256718a', 'allocation_limit_bytes': limit_bytes.hex(), 'relocation_slots': slots,
            'proofs': [quotient_lemma(0x346dc5d63886594b, 10000, 75, (1 << 64) - 1),
                       quotient_lemma(0x45e7b272f608771, 1875, 69, (1 << 59) - 1)]}


def vectors(powers):
    cases = [0, 1, 9, 10, 999999, 1000000, (1 << 53) - 1, 1 << 53,
             (1 << 53) + 1, (1 << 53) + 2, (1 << 64) - 1]
    rows = []
    for p in powers:
        d = p['divisor']
        for x in cases:
            first, result = convert(x, d)
            exact = Fraction(x, d)
            actual = as_fraction(result)
            rows.append({'exponent': p['index'], 'raw': str(x), 'cast_bits': f'{first:016x}',
                         'quotient_bits': f'{result:016x}', 'exact_numerator': str(exact.numerator),
                         'exact_denominator': str(exact.denominator), 'binary_equals_exact': actual == exact})
    return rows


def generate(out):
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    evidence = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (out / 'vectors.json').write_text(json.dumps(vectors(evidence['power_table']), indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(args.out)

if __name__ == '__main__':
    main()
