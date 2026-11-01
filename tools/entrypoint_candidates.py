#!/usr/bin/env python3
"""Digest-bound ELF entrypoint membership and raw E8 candidate census; no execution."""
import argparse
import bisect
import collections
import json
from pathlib import Path
import struct

from artifacts import ROOT, check
from elf_index import sections
from fde_extents import fde_extents

U64 = 1 << 64
MAX_ARRAY_ENTRIES = 4096
MAX_DYNAMIC_ENTRIES = 65536
LIMITATIONS = (
    'FDE extents describe unwind ranges, not validated functions. Every E8 byte '
    'with four following bytes in each file-backed executable section is a '
    'candidate, including bytes inside immediates or data. Candidate targets do '
    'not establish calls, instruction boundaries or reachability. Other-byte '
    'gaps are not necessarily code or padding. No CFG, component ownership or '
    'equivalence is established. Original PR373 reports remain historical artifacts.'
)


def section_headers(data):
    """Retain entry widths locally without changing the shared ELF/FDE parser."""
    secs = sections(data)
    shoff = struct.unpack_from('<Q', data, 40)[0]
    width = struct.unpack_from('<H', data, 58)[0]
    for index, sec in enumerate(secs):
        sec['entsize'] = struct.unpack_from('<Q', data, shoff + index * width + 56)[0]
    return secs


def section_for(secs, address, size=1):
    if not 0 <= address < U64 or size < 0 or address + size > U64:
        raise ValueError('Invalid virtual address range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= address < s['address'] + s['size']
               and address + size <= s['address'] + s['size']]
    if len(matches) > 1:
        raise ValueError('Ambiguous allocated section mapping')
    return matches[0] if matches else None


def read_va(data, secs, address, size):
    sec = section_for(secs, address, size)
    if sec is None:
        raise ValueError('Array/address range is not wholly file backed')
    off = sec['offset'] + address - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('Mapped range exceeds input')
    return data[off:off + size]


def table_blob(data, secs, name, kind, width):
    matches = [s for s in secs if s['name'] == name]
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError(f'Duplicate {name} section')
    sec = matches[0]
    if sec['type'] != kind or sec['entsize'] != width or sec['size'] % width:
        raise ValueError(f'Invalid {name} table type, entry width or size')
    lo, hi = sec['offset'], sec['offset'] + sec['size']
    if lo < 0 or hi > len(data):
        raise ValueError(f'Truncated {name} table')
    return data[lo:hi]


def relocations(data, secs):
    blob = table_blob(data, secs, '.rela.dyn', 4, 24)
    values, unsupported, seen = {}, set(), set()
    for off in range(0, len(blob or b''), 24):
        slot, info, addend = struct.unpack_from('<QQq', blob, off)
        kind = info & 0xffffffff
        if kind == 0:  # R_X86_64_NONE does not write a slot.
            continue
        if slot in seen:
            raise ValueError('Duplicate relocation destination')
        seen.add(slot)
        if kind == 8:
            if info != 8:
                raise ValueError('RELATIVE relocation has a symbol index')
            values[slot] = addend % U64
        else:
            unsupported.add(slot)
    return values, unsupported


def entrypoints(data, secs, rows):
    starts = {r['start'] for r in rows}
    relative, unsupported = relocations(data, secs)
    if len(data) < 64:
        raise ValueError('Truncated ELF header')
    found = {'elf_entry': struct.unpack_from('<Q', data, 24)[0]}
    blob = table_blob(data, secs, '.dynamic', 6, 16)
    tags = {}
    if blob is not None:
        if len(blob) // 16 > MAX_DYNAMIC_ENTRIES:
            raise ValueError('Dynamic table exceeds explicit entry limit')
        terminated = False
        for off in range(0, len(blob), 16):
            tag, value = struct.unpack_from('<qQ', blob, off)
            if tag == 0:
                terminated = True
                break
            if tag in (12, 25, 26, 27, 28):
                if tag in tags:
                    raise ValueError('Duplicate singleton dynamic tag')
                tags[tag] = value
        if not terminated:
            raise ValueError('Dynamic table lacks DT_NULL')
    if 12 in tags:
        found['DT_INIT'] = tags[12]
    for name, addr_tag, size_tag in [('DT_INIT_ARRAY', 25, 27), ('DT_FINI_ARRAY', 26, 28)]:
        if addr_tag not in tags and size_tag not in tags:
            continue
        if addr_tag not in tags or size_tag not in tags:
            raise ValueError('Array address/size dynamic tags must be paired')
        address, size = tags[addr_tag], tags[size_tag]
        if address % 8 or size % 8:
            raise ValueError('Array address/size must be qword aligned')
        count = size // 8
        if count > MAX_ARRAY_ENTRIES:
            raise ValueError('Array exceeds explicit entry limit; refusing partial census')
        raw = read_va(data, secs, address, size) if size else b''
        values = []
        exceptions = []
        for i in range(count):
            slot = address + i * 8
            if slot in unsupported:
                raise ValueError('Unsupported relocation on entrypoint array slot')
            value = relative.get(slot, struct.unpack_from('<Q', raw, i * 8)[0])
            values.append(value)
            if value not in starts:
                exceptions.append({'slot': slot, 'target': value})
        found[name] = {
            'address': address, 'address_on_fde_start': address in starts,
            'entries': count, 'relocated_entries': sum(address + i * 8 in relative for i in range(count)),
            'entries_on_fde_start': sum(v in starts for v in values),
            'entries_in_executable_section': sum(bool((section_for(secs, v) or {}).get('flags', 0) & 4) for v in values),
            'entries_not_on_fde_start': exceptions,
        }
    return {name: value if isinstance(value, dict) else {
        'address': value, 'section': (section_for(secs, value) or {}).get('name'),
        'on_fde_start': value in starts} for name, value in found.items()}


def raw_e8_targets(data, secs, rows, gaps):
    ordered = sorted(rows, key=lambda r: r['start'])
    starts = [r['start'] for r in ordered]
    start_set = set(starts)
    max_ends, reach = [], 0
    for row in ordered:
        reach = max(reach, row['end'])
        max_ends.append(reach)
    gaps = sorted(gaps, key=lambda g: g['start'])
    gap_starts = [g['start'] for g in gaps]
    with_fdes = {r['section'] for r in rows}
    counts = collections.defaultdict(collections.Counter)
    hit_gaps = collections.defaultdict(set)
    for sec in (s for s in secs if s['flags'] & 4 and s['type'] != 8 and s['size']):
        lo, hi = sec['offset'], sec['offset'] + sec['size']
        if lo < 0 or hi > len(data):
            raise ValueError('Executable section exceeds input')
        blob = data[lo:hi]
        pos = blob.find(b'\xe8')
        while pos >= 0 and pos + 5 <= len(blob):
            target = (sec['address'] + pos + 5 + struct.unpack_from('<i', blob, pos + 1)[0]) % U64
            pos = blob.find(b'\xe8', pos + 1)
            holder = section_for(secs, target)
            if holder is None or not holder['flags'] & 4:
                counts['outside_executable']['outside_executable'] += 1
                continue
            name = holder['name']
            if name not in with_fdes:
                counts[name]['section_without_fdes'] += 1
                continue
            k = bisect.bisect_right(starts, target) - 1
            if k >= 0 and target < max_ends[k]:
                counts[name]['fde_start' if target in start_set else 'fde_interior'] += 1
                continue
            k = bisect.bisect_right(gap_starts, target) - 1
            if k >= 0 and target < gaps[k]['end'] and gaps[k]['section'] == name:
                counts[name]['gap_start' if target == gaps[k]['start'] else 'gap_interior'] += 1
                hit_gaps[name].add(k)
            else:
                counts[name]['unclassified'] += 1
    report = {name: dict(sorted(row.items())) for name, row in sorted(counts.items())}
    hits = {}
    for name, indexes in sorted(hit_gaps.items()):
        other = [i for i in indexes if not gaps[i]['int3_only']]
        hits[name] = {'gaps_with_candidates': len(indexes),
                      'gap_bytes_with_candidates': sum(gaps[i]['end'] - gaps[i]['start'] for i in indexes),
                      'other_byte_gaps_with_candidates': len(other),
                      'other_gap_bytes_with_candidates': sum(gaps[i]['end'] - gaps[i]['start'] for i in other)}
    totals = collections.Counter()
    for row in report.values():
        totals.update(row)
    return {'by_section': report, 'totals': dict(sorted(totals.items()))}, hits


def analyze(data):
    summary, rows, gaps = fde_extents(data)
    secs = section_headers(data)
    candidates, hit_gaps = raw_e8_targets(data, secs, rows, gaps)
    return {**{key: summary[key] for key in ['binary_sha256', 'fde_records', 'executable_sections', 'same_section_gaps']},
            'entrypoints': entrypoints(data, secs, rows),
            'raw_e8_candidates': candidates, 'gaps_with_raw_e8_targets': hit_gaps,
            'limitations': LIMITATIONS}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=['94', '115'], required=True)
    p.add_argument('--output-dir', type=Path, default=ROOT / 'work/index')
    args = p.parse_args()
    rel = f'artifacts/node/{args.release}/hl-node'
    identity = next(v for v in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if v['path'] == rel)
    binary = ROOT / rel
    check(binary, identity)
    data = binary.read_bytes()
    # Authenticate the exact snapshot consumed by the analyzer too.
    import hashlib
    if len(data) != identity['size'] or hashlib.sha256(data).hexdigest() != identity['sha256']:
        raise ValueError('Artifact changed while reading')
    result = analyze(data)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f'node-{args.release}-entrypoint-candidates.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
