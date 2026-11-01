#!/usr/bin/env python3
"""Bind node94's complete 198-byte divide leaf to a published compiler artifact.

Static immutable-byte parsing only. The inspect_* seams do not authenticate
origin; only analyze admits the two full pinned inputs. No code is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf, ar_members

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARCHIVE_SHA256 = 'f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6'
BODY_SHA256 = '45f632dd0c1fc0915e680ad7ad98cabda1fcf34ba7835c2e73e3569b570a288d'
BEGIN, SIZE, SLOT = 0x565f5a0, 198, 0x576e1a8
PREFIX = 'compiler_builtins-58c8d4715a55733a.compiler_builtins.b67a5f131a5b1bd5-cgu.'
MANGLED = '_ZN17compiler_builtins3int4udiv9__udivti317h7f7f8794247d2394E'
DEFINITIONS = {
    PREFIX + '019.rcgu.o': (MANGLED, 'cef03767df991d42e3ad613ff963a7878ea17d2962d038f40774bcd80fee826d'),
    PREFIX + '129.rcgu.o': ('__udivti3', 'cc3613e3e208e899fdfeca485bcdf23a59dbac31eefae9c312ddb5a162294861'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect_target(data):
    """Unpinned counterfactual seam: derive coordinates, never grant origin."""
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, SIZE, executable=True)
    require(bool(mapping['section']['flags'] & 4) == bool(mapping['PT_LOAD']['flags'] & 1),
            'Captured section/PT_LOAD executable flags disagree')
    cies, fdes = eh_frame_records(data)
    intersecting = [f for f in fdes if f['start'] < BEGIN + SIZE and f['end'] > BEGIN]
    require(len(intersecting) == 1 and intersecting[0]['start'] == BEGIN and
            intersecting[0]['end'] == BEGIN + SIZE, 'No unique complete 198-byte FDE')
    fde = intersecting[0]
    require(fde['lsda'] is None, 'Unexpected leaf LSDA')
    slot = image.relative(SLOT)
    require(slot['addend'] == BEGIN, 'Divide slot resolves elsewhere')
    slot_bytes, slot_mapping = image.va_bytes(SLOT, 8)
    selected_writes = []
    for table in image.sections:
        require(table['type'] != 9, 'Captured REL encoding is not supported')
        if table['type'] != 4:
            continue
        require(table['entsize'] == 24 and table['size'] % 24 == 0, 'Invalid captured RELA table')
        for pos in range(table['offset'], table['offset'] + table['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, pos)
            if destination < SLOT + 8 and destination + 8 > SLOT:
                require(destination == SLOT and info == 8 and addend == BEGIN,
                        'Conflicting or partial RELA write overlaps the selected slot')
                selected_writes.append(pos)
            # No relocation is credited. An unknown field within seven bytes
            # before the leaf is conservatively rejected, rather than masked.
            require(not (destination < BEGIN + SIZE and destination + 8 > BEGIN),
                    'A captured relocation may overlap the leaf')
    require(selected_writes == [slot['record_file_offset']],
            'Global RELA writes to the selected slot are not unique')
    return {'origin': 'UNQUALIFIED', 'body_hex': body.hex(), 'body_sha256': sha(body),
            'mapping': mapping, 'fde': fde, 'cie': cies[fde['cie']],
            'slot': slot, 'slot_mapping': slot_mapping,
            'unrelocated_slot_hex': slot_bytes.hex(), 'body_relocations': []}


def inspect_member(data, name):
    """Unpinned seam; every symbol, extent and byte is derived from this object."""
    require(name in (MANGLED, '__udivti3'), 'Unexpected division symbol name')
    image = Elf(data, 1)
    named = [s for t in image.sections if t['type'] == 2 for s in image.symbols(t['index'])
             if s['name'] == name and s['section'] != 0]
    require(len(named) == 1, 'Missing or duplicate defined division symbol')
    symbol = named[0]
    require(symbol['info'] == (34 if name == '__udivti3' else 18) and symbol['other'] == 2,
            'Division symbol binding/type/visibility differs')
    symbol = image.function(symbol['section'], name)
    section = image.section(symbol['section'])
    require(symbol['size'] == SIZE and section['flags'] & 2, 'Division function extent/allocation differs')
    require(not any(t['type'] == 9 and t['info'] == section['index'] for t in image.sections),
            'Division code uses unsupported REL encoding')
    relocations = image.relocations(section['index'])
    require(not relocations, 'Official division body has code relocations')
    body = image.section_bytes(section['index'])
    return {'origin': 'UNQUALIFIED', 'symbol': symbol, 'section': section,
            'member_sha256': sha(data), 'member_bytes': len(data),
            'body_hex': body.hex(), 'body_sha256': sha(body), 'code_relocations': []}


def inspect_archive(data):
    """Enumerate all named declarations; do not select one convenient body."""
    members = ar_members(data)
    declarations, definitions = [], []
    for name, raw in members.items():
        if raw[:4] != b'\x7fELF':
            continue
        image = Elf(raw, 1)
        for table in image.sections:
            if table['type'] != 2:
                continue
            for symbol in image.symbols(table['index']):
                if '__udivti3' not in symbol['name']:
                    continue
                row = {'member': name, 'symbol': symbol, 'member_sha256': sha(raw)}
                declarations.append(row)
                if symbol['section']:
                    require(name in DEFINITIONS and symbol['name'] == DEFINITIONS[name][0],
                            'Unexpected additional defined division candidate')
                    fact = inspect_member(raw, symbol['name'])
                    fact['member'] = name
                    definitions.append(fact)
    require(len(definitions) == 2 and {r['member'] for r in definitions} == set(DEFINITIONS),
            'The complete two-definition candidate set differs')
    return {'origin': 'UNQUALIFIED', 'members_scanned': len(members),
            'declarations': declarations, 'definitions': definitions}


def analyze(target, archive):
    """Admit and compare the same immutable bytes, not later pathname reopens."""
    require(type(target) is bytes and len(target) == 91774280 and sha(target) == TARGET_SHA256,
            'Target identity differs')
    require(type(archive) is bytes and len(archive) == 4400606 and sha(archive) == ARCHIVE_SHA256,
            'Official archive identity differs')
    native = inspect_target(target)
    official = inspect_archive(archive)
    comparisons = []
    raw = bytes.fromhex(native['body_hex'])
    for candidate in official['definitions']:
        require(candidate['member_sha256'] == DEFINITIONS[candidate['member']][1],
                'Official member identity differs')
        source = bytes.fromhex(candidate['body_hex'])
        differences = [i for i, (a, b) in enumerate(zip(raw, source)) if a != b]
        comparisons.append({'member': candidate['member'], 'symbol': candidate['symbol']['name'],
                            'compared_bytes': SIZE, 'raw_equal': not differences,
                            'different_offsets': differences, 'normalization_fields': []})
    equal = all(r['raw_equal'] for r in comparisons)
    return {'status': 'PINNED_ARTIFACT_RAW_CORRESPONDENCE' if equal else 'PINNED_INPUT_RAW_DIFFERENCES',
            'all_candidates_raw_equal': equal,
            'target': {**native, 'sha256': TARGET_SHA256, 'bytes': len(target),
                       'origin': 'FULL_SHA256_ADMITTED_TARGET'},
            'official': {**official, 'sha256': ARCHIVE_SHA256, 'bytes': len(archive),
                         'origin': 'FULL_SHA256_ADMITTED_OFFICIAL_ARCHIVE'},
            'comparison': comparisons,
            'limits': [
                'Complete one-leaf raw correspondence; zero normalization and both defined candidates retained.',
                'Named published artifact correspondence is not an independent all-input quotient proof.',
                'No original compiler, source build, ABI, zero-divisor environment, caller/fee or whole-ELF theorem.',
                'No source, object, captured binary or instruction emulator is executed.',
                'Only full analyze admission grants pinned origin; inspect seams remain unqualified.',
                'compiler-builtins retains its complete upstream multi-license; it is not MIT-only.',
            ]}


def collect(binary, builtins, output):
    output = Path(output)
    require(not os.path.lexists(output), 'Output already exists')
    target, archive = Path(binary).read_bytes(), Path(builtins).read_bytes()
    record = analyze(target, archive)
    output.mkdir(mode=0o700, parents=False)
    (output / 'record.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n',
                                       encoding='utf-8', newline='\n')
    (output / 'target-198.bin').write_bytes(bytes.fromhex(record['target']['body_hex']))
    for candidate in record['official']['definitions']:
        suffix = 'unmangled' if candidate['symbol']['name'] == '__udivti3' else 'mangled'
        (output / ('official-' + suffix + '-198.bin')).write_bytes(bytes.fromhex(candidate['body_hex']))
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--builtins', type=Path, required=True, help='Local pinned published rlib; never downloaded')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        record = collect(args.binary, args.builtins, args.output)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps({'status': record['status'], 'all_candidates_raw_equal':
                      record['all_candidates_raw_equal'], 'compared_bytes_per_candidate': SIZE,
                      'defined_candidates': len(record['comparison'])}, sort_keys=True))


if __name__ == '__main__':
    main()
