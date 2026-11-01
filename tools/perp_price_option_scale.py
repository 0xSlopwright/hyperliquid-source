#!/usr/bin/env python3
"""Static node #94 option-price scaling evidence; no binary execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PATH = ROOT / 'artifacts/node/94/hl-node'
FUNCS = {
    0x232e2e0: 'fb67f9fba157362f742ba683c41c0e1c38898148ac193d052010d6ef076fa600',
    0x49e4ca0: 'd918d6f12091130454759fd45b1e3320684c8b7009f315ef9463b777652fdde4',
}
U64 = (1 << 64) - 1
# Offsets of branch instructions, relative to either FDE entry.
BRANCHES = (0x0d, 0x12, 0x32, 0x46, 0x60, 0x80, 0x91, 0x96,
            0xa0, 0xbb, 0xce, 0xe0, 0xe2, 0xf2, 0xf7)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data, expected=SHA256):
        require(digest(data) == expected, 'target SHA-256 mismatch')
        self.data = data
        self.sections = elf_index.sections(data)
        _, fdes = fde_extents.eh_frame_records(data, self.sections)
        self.fdes = fdes

    def offset(self, va, size=1):
        require(size >= 0, 'negative size')
        choices = [s for s in self.sections if s['type'] != 8 and s['size'] and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(choices) == 1, 'VA range has no unique file-backed section')
        s = choices[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'truncated range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def function(self, va):
        matches = [r for r in self.fdes if r['start'] == va]
        require(len(matches) == 1, 'FDE start is missing or ambiguous')
        f = matches[0]
        require(f['end'] > va, 'empty FDE')
        sec = [s for s in self.sections if s['type'] != 8 and s['flags'] & 4 and
               s['address'] <= va and f['end'] <= s['address'] + s['size']]
        require(len(sec) == 1, 'FDE is not uniquely executable')
        return f, self.read(va, f['end'] - va)

    def relocations(self):
        secs = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        require(len(secs) == 1 and secs[0]['size'] % 24 == 0, 'bad relocation section')
        s = secs[0]
        result = {}
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, value = struct.unpack_from('<QQq', self.data, off)
            if info == 8:
                require(where not in result, 'duplicate relative relocation')
                result[where] = value
        return result


def branch(raw, at, start):
    require(0 <= at < len(raw), 'branch out of range')
    op = raw[at]
    if op in (0xeb, 0x73, 0x74, 0x75, 0x76, 0x77):
        n, disp = 2, struct.unpack_from('<b', raw, at + 1)[0]
    elif op == 0xe9:
        n, disp = 5, struct.unpack_from('<i', raw, at + 1)[0]
    elif op == 0x0f and raw[at + 1] in (0x83, 0x84, 0x85):
        n, disp = 6, struct.unpack_from('<i', raw, at + 2)[0]
    else:
        raise ValueError('unexpected branch encoding')
    dest = at + n + disp
    require(0 <= dest < len(raw), 'branch target outside FDE')
    return {'va': start + at, 'bytes': raw[at:at+n].hex(),
            'taken': start + dest, 'fallthrough': start + at + n}


def inspect(im):
    rows = []
    bodies = []
    for start, expected in FUNCS.items():
        f, raw = im.function(start)
        require(len(raw) == 318 and digest(raw) == expected, 'function bytes differ')
        # Immediate and instruction shapes which feed the mathematical model.
        require(raw[0x1a:0x1c] == bytes.fromhex('48ba'), 'reciprocal opcode changed')
        require(raw[0x2a:0x2d] == bytes.fromhex('48c1ea'), 'shift opcode changed')
        require(raw[0x38:0x3b] == bytes.fromhex('4869c2'), 'divisor opcode changed')
        require(raw[0x5d:0x60] == bytes.fromhex('83f807'), 'decimal guard changed')
        require(raw[0xc7:0xca] == bytes.fromhex('4809f0'), 'division-width guard changed')
        rec = struct.unpack_from('<Q', raw, 0x1c)[0]
        den = struct.unpack_from('<I', raw, 0x3b)[0]
        shift = raw[0x2d]
        locs = []
        relocs = im.relocations()
        for off in (0x124, 0x131):
            require(raw[off:off+3] == bytes.fromhex('488d3d'), 'bad location LEA')
            target = start + off + 7 + struct.unpack_from('<i', raw, off+3)[0]
            require(target in relocs, 'location missing relative relocation')
            size, line, col = struct.unpack('<QII', im.read(target+8, 16))
            require(0 < size < 256, 'invalid path length')
            path = im.read(relocs[target], size).decode('ascii')
            require('l1/src/' in path, 'unexpected location path')
            path = path[path.index('l1/src/'):]
            locs.append({'va': hex(target), 'file_offset': hex(im.offset(target)),
                         'path': path, 'line': line, 'column': col})
        slots = []
        for off in (0x12b, 0x138):
            require(raw[off:off+2] == bytes.fromhex('ff15'), 'call encoding changed')
            slot = start + off + 6 + struct.unpack_from('<i', raw, off+2)[0]
            im.read(slot, 8)
            slots.append(hex(slot))
        branches = [branch(raw, at, start) for at in BRANCHES]
        rows.append({'start': hex(start), 'end': hex(f['end']), 'fde': hex(f['fde']),
                     'file_offset': hex(im.offset(start, len(raw))), 'size': len(raw),
                     'sha256': digest(raw), 'body_hex': raw.hex(), 'reciprocal': rec,
                     'index_divisor': den, 'high_product_shift': shift,
                     'locations': locs, 'failure_call_slots': slots, 'branches': branches})
        bodies.append(raw)
    require(rows[0]['failure_call_slots'] == rows[1]['failure_call_slots'], 'failure slots differ')
    differences = [i for i, (a, b) in enumerate(zip(*bodies)) if a != b]
    permitted = set(range(0x127, 0x12b)) | set(range(0x12d, 0x131)) | set(range(0x134, 0x138)) | set(range(0x13a, 0x13e))
    require(set(differences) <= permitted, 'copies differ outside four PC-relative operands')
    return rows, differences


def display_evidence(im):
    start = 0x2396c00
    f, raw = im.function(start)
    require(len(raw) == 329 and digest(raw) == 'dfcd66f3a66bc80e24ab7337294c5b15cc35bca9a1e2b13a1d78038d74e3092c', 'display function bytes differ')
    # Resolve both LEAs from their signed RIP displacements, rather than assuming the table address.
    tables = []
    for at in (0x9b, 0x115):
        require(raw[at:at+3] == bytes.fromhex('488d05'), 'display table LEA changed')
        tables.append(start + at + 7 + struct.unpack_from('<i', raw, at+3)[0])
    require(tables[0] == tables[1], 'table targets differ')
    bits = struct.unpack('<7Q', im.read(tables[0], 56))
    expected = tuple(struct.unpack('<Q', struct.pack('<d', float(10**n)))[0] for n in range(7))
    require(bits == expected, 'display power table changed')
    constants = []
    for at in (0x7a, 0x82, 0xf4, 0xfc):
        require(raw[at:at+4] in (bytes.fromhex('660f6215'), bytes.fromhex('660f5c15')), 'packed constant opcode changed')
        target = start + at + 8 + struct.unpack_from('<i', raw, at+4)[0]
        constants.append({'va': hex(target), 'bytes': im.read(target, 16).hex()})
    require(constants[0] == constants[2] and constants[1] == constants[3], 'packed constants differ')
    relocs = im.relocations()
    location_vas = []
    for at in (0x12f, 0x13c):
        require(raw[at:at+3] == bytes.fromhex('488d3d'), 'display location LEA changed')
        target = start + at + 7 + struct.unpack_from('<i', raw, at+3)[0]
        require(target in relocs, 'display location missing relocation')
        location_vas.append(hex(target))
    branches = [branch(raw, at, start) for at in (0x20,0x3b,0x4f,0x6a,0xaa,0xc1,0xd1,0xe8)]
    return {'start': hex(start), 'end': hex(f['end']), 'fde': hex(f['fde']),
            'file_offset': hex(im.offset(start, len(raw))), 'size': len(raw),
            'sha256': digest(raw), 'body_hex': raw.hex(), 'table_va': hex(tables[0]),
            'table_file_offset': hex(im.offset(tables[0], 56)),
            'table_bits': [f'0x{n:016x}' for n in bits], 'packed_constants': constants[:2], 'location_vas': location_vas, 'branches': branches}


def display_component(value, decimal):
    """Model scalar result, assuming the usual IEEE-754 round-to-nearest mode."""
    require(0 <= value <= U64 and 0 <= decimal < 7, 'bad display input')
    # The two packed subtractions recover low and high halves before addsd.
    lo = float(value & 0xffffffff)
    hi = float(value >> 32) * 4294967296.0
    return (hi + lo) / float(10 ** (6-decimal))


def display_pair(a, b, key, group, length, decimal):
    for x in (a,b,key,group,length):
        require(0 <= x <= U64, 'bad display u64')
    require(0 <= decimal <= 255, 'bad decimal byte')
    result = []
    for value in (a,b):
        if value == 0:
            result.append(0.0)
            continue
        q = ((key * 0x346dc5d63886594b) >> 64) >> 11
        if q != group:
            return ('panic-group',)
        if key-q*10000 >= length:
            return ('panic-index',)
        if decimal >= 7:
            return ('panic-decimals',)
        result.append(display_component(value, decimal))
    return ('ok', *result)


def scale_ladder(decimal):
    """Hand-lift of 0x232e34e..0x232e3a4 for admitted byte values."""
    require(0 <= decimal < 7, 'decimal byte is outside admitted range')
    e = decimal + 2
    s = 10 if e & 1 else 1
    if e & 2:
        s *= 100
        if e & 0xe == 2:
            return s
    if e & 4:
        s *= 10000
        if e & 0xc == 4:
            return s
    else:
        require(decimal == 6, 'unreachable ladder fallthrough')
    return s * 100000000


def evaluate(mode, raw_value, payload_byte, key, table_group, table_length, decimals, pointer):
    """Hand-lift of observed control flow; payload is described, not target execution."""
    for n in (raw_value, key, table_group, table_length, pointer):
        require(0 <= n <= U64, 'non-u64 argument')
    require(0 <= mode <= 255 and 0 <= payload_byte <= 255 and 0 <= decimals <= 255, 'non-byte argument')
    if mode == 2:
        # RCX is reused as the upper eight output bytes; no memory read here.
        return ('ok-bypass', raw_value & 255, pointer, mode)
    q = ((key * 0x346dc5d63886594b) >> 64) >> 11
    rem = key - q * 10000
    if q != table_group:
        return ('panic-group',)
    if rem >= table_length:
        return ('panic-index',)
    if decimals >= 7:
        return ('panic-decimals',)
    divisor = scale_ladder(decimals)
    if raw_value < divisor or raw_value % divisor:
        return ('error-0x65',)
    quotient = raw_value // divisor
    upper = (quotient >> 8) | (payload_byte << 56)
    return ('ok-scaled', quotient & 255, upper, mode)


def walk_scale(raw, start, mode, value, payload, key, group, length, decimal, pointer):
    """Concrete block walker over hash-qualified bytes and their encoded branch displacements.

    The block operations are a manual lift. Only the 15 recorded direct branches are
    decoded; an unexpected destination stops the walk. It never executes target code.
    """
    trace = []
    def edge(offset, taken):
        b = branch(raw, offset, start)
        dest = (b['taken'] if taken else b['fallthrough']) - start
        trace.append(f'{start+offset:#x}:{"T" if taken else "F"}')
        return dest
    pc = edge(0x0d, mode != 2)
    if pc == 0x0f:
        require(edge(0x12, True) == 0x108, 'bad bypass jump')
        return ('ok-bypass', value & 255, pointer, mode), trace
    require(pc == 0x17, 'bad mode branch')
    magic = struct.unpack_from('<Q', raw, 0x1c)[0]
    shift = raw[0x2d]
    index_den = struct.unpack_from('<I', raw, 0x3b)[0]
    quotient = ((key * magic) >> 64) >> shift
    pc = edge(0x32, quotient != group)
    if pc == 0x124:
        return ('panic-group',), trace
    require(pc == 0x38, 'bad group branch')
    remainder = key - quotient * index_den
    pc = edge(0x46, remainder >= length)
    if pc == 0x124:
        return ('panic-index',), trace
    require(pc == 0x4c, 'bad index branch')
    pc = edge(0x60, decimal >= raw[0x5f])
    if pc == 0x131:
        return ('panic-decimals',), trace
    require(pc == 0x66, 'bad decimal branch')
    exponent = decimal + raw[0x70]
    divisor = (exponent & raw[0x75]) * 9 + 1
    pc = edge(0x80, not (exponent & raw[0x7f]))
    if pc == 0x82:
        divisor *= raw[0x85]
        pc = edge(0x91, (exponent & raw[0x8c]) == raw[0x90])
        if pc == 0xc4:
            pass
        else:
            require(pc == 0x93, 'bad exponent branch 2')
    else:
        require(pc == 0x93, 'bad exponent test')
    if pc == 0x93:
        pc = edge(0x96, bool(exponent & raw[0x95]))
        if pc == 0xae:
            divisor *= struct.unpack_from('<I', raw, 0xb1)[0]
            pc = edge(0xbb, (exponent & raw[0xb7]) == raw[0xba])
            if pc != 0xc4:
                require(pc == 0xbd, 'bad exponent branch 4')
        else:
            require(pc == 0x98, 'bad exponent branch')
            pc = edge(0xa0, decimal == raw[0x9f])
            if pc == 0xa2:
                return ('error-0x65',), trace
            require(pc == 0xbd, 'bad exponent fallthrough')
        if pc == 0xbd:
            divisor *= struct.unpack_from('<I', raw, 0xc0)[0]
    require(0 < divisor <= U64, 'invalid machine divisor')
    pc = edge(0xce, (value | divisor) < 2**32)
    if pc == 0xe4:
        require(value < 2**32 and divisor < 2**32, 'unsafe 32-bit division')
        quotient, remainder = divmod(value, divisor)
        pc = edge(0xf2, divisor > value)
        if pc == 0xa2:
            return ('error-0x65',), trace
        require(pc == 0xf4, 'bad narrow division compare')
    else:
        require(pc == 0xd0, 'bad division width branch')
        quotient, remainder = divmod(value, divisor)
        pc = edge(0xe0, divisor <= value)
        if pc == 0xe2:
            require(edge(0xe2, True) == 0xa2, 'bad error jump')
            return ('error-0x65',), trace
        require(pc == 0xf4, 'bad wide division compare')
    pc = edge(0xf7, remainder != 0)
    if pc == 0xa2:
        return ('error-0x65',), trace
    require(pc == 0xf9, 'bad remainder branch')
    return ('ok-scaled', quotient & 255, (quotient >> 8) | (payload << 56), mode), trace


def generate(im, out):
    rows, diff = inspect(im)
    display = display_evidence(im)
    r = rows[0]['reciprocal']; d = rows[0]['index_divisor']; shift = rows[0]['high_product_shift']
    require((r, d, shift) == (0x346dc5d63886594b, 10000, 11), 'unexpected reciprocal')
    error = d*r - (1 << (64 + shift))
    require(0 < error and U64*error < (1 << (64 + shift)), 'reciprocal proof bound fails')
    sections = [x for x in im.sections if x['name'] == '.text' and x['type'] != 8]
    require(len(sections) == 1, 'ambiguous text section')
    sec = sections[0]
    text_data = im.data[sec['offset']:sec['offset']+sec['size']]
    needle = bytes.fromhex('6641ba6500')
    hits = []
    pos = 0
    while True:
        pos = text_data.find(needle, pos)
        if pos < 0:
            break
        hits.append(hex(sec['address']+pos))
        pos += 1
    require(len(hits) == 6, 'unexpected error-tag byte census')
    ladder = []
    for decimal in range(256):
        if decimal < 7:
            value = scale_ladder(decimal)
            require(value == 10 ** (decimal+2), 'ladder mismatch')
            ladder.append((decimal, value, 'divide-exact'))
        else:
            ladder.append((decimal, '', 'panic-decimals'))
    cases = []
    for dec in range(7):
        s = ladder[dec][1]
        inputs = sorted({0, 1, s-1, s, s+1, 2*s, (1<<32)-1, 1<<32,
                         ((1<<32)//s)*s, (U64//s)*s, U64})
        for value in inputs:
            mode=1; key=30005
            result = evaluate(mode, value, 0xa7, key, 3, 6, dec, 0x1234)
            cases.append((dec, value, s, (32 if (value | s) < (1<<32) else 64), result))
    controls = [
        ('bypass-invalid-metadata', 2, 0x123456789abcdef0, 0x88, U64, 0, 0, 255, 0x1020304050607080),
        ('group-mismatch-first', 1, 100, 0, 30005, 4, 0, 255, 0x1234),
        ('index-equals-length', 1, 100, 0, 30005, 3, 5, 255, 0x1234),
        ('decimal-seven', 1, 100, 0, 30005, 3, 6, 7, 0x1234),
        ('decimal-255', 1, 100, 0, 30005, 3, 6, 255, 0x1234),
        ('zero-refused', 1, 0, 0, 30005, 3, 6, 0, 0x1234),
        ('not-divisible', 1, 101, 0, 30005, 3, 6, 0, 0x1234),
        ('exact', 1, 100, 0xa7, 30005, 3, 6, 0, 0x1234),
    ]
    traces = []
    walks = 0
    for row in rows:
        raw = bytes.fromhex(row['body_hex'])
        start = int(row['start'], 16)
        inputs = [(1, value, 0xa7, 30005, 3, 6, dec, 0x1234) for dec, value, _, _, _ in cases]
        inputs += [tuple(c[1:]) for c in controls]
        inputs += [(1, 100, 0, 30005, 3, 6, dec, 0x1234) for dec in range(256)]
        for args in inputs:
            actual, trace = walk_scale(raw, start, *args)
            require(actual == evaluate(*args), 'lift differs from branch walker')
            walks += 1
            if args in [tuple(c[1:]) for c in controls]:
                traces.append((row['start'], *args, actual[0], ','.join(trace)))
    out.mkdir(parents=True, exist_ok=True)
    evidence = {'target_sha256': SHA256, 'coordinate': 'ELF virtual address',
                'functions': rows, 'display_function': display, 'error_tag_pattern_hits': hits, 'different_byte_offsets': diff,
                'proof': {'divisor': d, 'reciprocal': r, 'power': 64+shift,
                          'error': error, 'max_input_times_error': U64*error,
                          'power_value': 1 << (64+shift)},
                'coverage': {'decimal_values': len(ladder), 'sample_cases': len(cases),
                             'fde_count': len(rows)+1, 'branches_per_scale_fde': len(BRANCHES), 'display_branches': len(display['branches']), 'concrete_block_walks': walks}}
    (out/'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
    lines = ['decimal\tdivisor\toutcome']
    lines += [f'{d}\t{s}\t{o}' for d,s,o in ladder]
    (out/'decimal-cases.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['decimal\tvalue\tdivisor\tdivision_width\toutcome\tbyte_at_8\tword_at_9\tmode_at_17']
    for dec,value,s,width,result in cases:
        cols = [str(x) for x in result] + ['']*(4-len(result))
        lines.append('\t'.join(map(str,(dec,value,s,width,*cols))))
    (out/'boundary-cases.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['case\tmode\tvalue\tpayload_byte\tkey\tgroup\tlength\tdecimal\trcx\toutcome\tbyte_at_8\tword_at_9\tmode_at_17']
    for label, *args in controls:
        result = evaluate(*args)
        lines.append('\t'.join(map(str, (label, *args, *result, *([''] * (4-len(result)))))))
    (out/'control-cases.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['function\tmode\tvalue\tpayload\tkey\tgroup\tlength\tdecimal\trcx\toutcome\tbranches']
    lines += ['\t'.join(map(str, row)) for row in traces]
    (out/'control-traces.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['decimal\tinput\tencode_divisor\tdisplay_divisor\tdisplay_f64_bits']
    for dec in range(7):
        for value in (0, 1, 99, 100, 2**32-1, 2**32, 2**53-1, 2**53, 2**53+1, U64):
            result = display_component(value, dec)
            bits = struct.unpack('<Q', struct.pack('<d', result))[0]
            lines.append(f'{dec}\t{value}\t{scale_ladder(dec)}\t{10**(6-dec)}\t0x{bits:016x}')
    (out/'display-cases.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['function\tbranch_va\topcode\ttaken_va\tfallthrough_va']
    for row in rows:
        for b in row['branches']:
            lines.append('\t'.join((row['start'], hex(b['va']), b['bytes'], hex(b['taken']), hex(b['fallthrough']))))
    for b in display['branches']:
        lines.append('\t'.join((display['start'], hex(b['va']), b['bytes'], hex(b['taken']), hex(b['fallthrough']))))
    (out/'branches.tsv').write_text('\n'.join(lines)+'\n')
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    im = Image(PATH.read_bytes())
    generate(im, args.out)

if __name__ == '__main__':
    main()
