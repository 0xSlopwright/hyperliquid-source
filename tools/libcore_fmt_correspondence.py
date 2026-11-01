#!/usr/bin/env python3
"""Compare three captured spans with an admitted, published libcore artifact.

Static ELF/ar parsing only. This does not build source, execute objects, infer
the original compiler, or erase the adapter's two non-relocation differences.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
CORE_SHA256 = 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
MEMBER_SHA256 = '57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13'
MEMBER = 'core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o'
MIT_SHA256 = 'b71bd43a069ca0641a9ecfe585ca7b3c53b5cc1608f8b68321168698e28b5ea1'
LICENSE = ROOT / 'research/work-items/RE-002-libcore-fmt-correspondence/third_party/LICENSE-MIT'
SPECS = (
    ('parent', 0x1571f50, 390, 381,
     '_ZN4core3fmt8builders11DebugStruct5field17h1d514c80a2f1f809E'),
    ('adapter', 0x157d000, 622, 883,
     '_ZN68_$LT$core..fmt..builders..PadAdapter$u20$as$u20$core..fmt..Write$GT$9write_str17h26b230683c3cc8feE'),
    ('decimal', 0x1570470, 444, 111,
     '_ZN4core3fmt3num3imp21_$LT$impl$u20$u64$GT$10_fmt_inner17hfc3ea2f2419bfacbE'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def admit_file(path, expected_sha256):
    """Hash exactly the immutable bytes later parsed; no stable-path claim."""
    data = Path(path).read_bytes()
    require(sha256(data) == expected_sha256, 'Input SHA-256 differs')
    return data


def ar_members(data):
    require(type(data) is bytes and data[:8] == b'!<arch>\n', 'Expected immutable GNU ar bytes')
    position, names, members = 8, None, {}
    while position < len(data):
        header = data[position:position + 60]
        require(len(header) == 60 and header[58:] == b'`\n', 'Invalid ar header')
        try:
            label = header[:16].decode('ascii').rstrip()
            size_text = header[48:58].decode('ascii').strip()
        except UnicodeDecodeError as error:
            raise ValueError('Invalid ar header encoding') from error
        require(size_text.isdigit(), 'Invalid ar member size')
        size = int(size_text)
        start, end = position + 60, position + 60 + size
        require(end <= len(data), 'Truncated ar member')
        raw = data[start:end]
        if label == '//':
            require(names is None, 'Duplicate ar long-name table')
            names = raw
        elif label != '/':
            if label.startswith('/'):
                require(label[1:].isdigit() and names is not None, 'Unsupported ar member name')
                offset = int(label[1:])
                require(offset < len(names) and (offset == 0 or names[offset - 1:offset] == b'\n'),
                        'Invalid ar long-name offset')
                stop = names.find(b'/\n', offset)
                require(stop >= offset, 'Unterminated ar long name')
                try:
                    name = names[offset:stop].decode('utf-8')
                except UnicodeDecodeError as error:
                    raise ValueError('Invalid ar member name encoding') from error
            else:
                name = label.removesuffix('/')
            require(name and name not in members, 'Duplicate or empty ar member name')
            members[name] = raw
        position = end + (size & 1)
        require(position <= len(data), 'Missing ar alignment byte')
        if size & 1:
            require(data[end:position] == b'\n', 'Invalid ar alignment byte')
    require(position == len(data), 'Trailing ar bytes')
    return members


class Elf:
    """The ELF64-LE/x86-64 subset actually used by these two admitted inputs."""

    def __init__(self, data, expected_type):
        require(type(data) is bytes and len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01',
                'Expected immutable ELF64-LE bytes')
        self.data = data
        kind, machine, version = struct.unpack_from('<HHI', data, 16)
        require(kind == expected_type and machine == 62 and version == 1, 'ELF type/machine/version differs')
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        ehsize, phsize, phcount, shsize, shcount, names_index = struct.unpack_from('<HHHHHH', data, 52)
        require(ehsize == 64 and shsize == 64 and shcount > 0 and names_index < shcount,
                'Unsupported ELF section header encoding')
        require(shoff + shcount * shsize <= len(data), 'ELF section table outside input')
        self.sections, self.segments, self._symbols = [], [], {}
        keys = ('name_offset', 'type', 'flags', 'address', 'offset', 'size', 'link', 'info', 'align', 'entsize')
        for index in range(shcount):
            row = dict(zip(keys, struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * shsize)))
            row['index'] = index
            require(row['type'] == 8 or row['offset'] + row['size'] <= len(data), 'ELF section outside input')
            self.sections.append(row)
        names = self.sections[names_index]
        require(names['type'] == 3, 'ELF section names are not STRTAB')
        name_bytes = self.section_bytes(names_index)
        for row in self.sections:
            row['name'] = self.string(name_bytes, row.pop('name_offset'))
        if phcount:
            require(phsize == 56 and phoff + phsize * phcount <= len(data), 'Invalid ELF program headers')
            for index in range(phcount):
                values = struct.unpack_from('<IIQQQQQQ', data, phoff + phsize * index)
                row = dict(zip(('type', 'flags', 'offset', 'address', 'paddr', 'filesz', 'memsz', 'align'), values))
                require(row['offset'] + row['filesz'] <= len(data), 'ELF segment outside input')
                require(row['filesz'] <= row['memsz'], 'ELF segment file size exceeds memory')
                self.segments.append(row)

    @staticmethod
    def string(table, offset):
        require(0 <= offset < len(table), 'ELF string offset outside table')
        end = table.find(b'\0', offset)
        require(end >= offset, 'Unterminated ELF string')
        try:
            return table[offset:end].decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('Invalid ELF string encoding') from error

    def section(self, index):
        require(0 <= index < len(self.sections), 'ELF section index outside table')
        return self.sections[index]

    def section_bytes(self, index):
        row = self.section(index)
        require(row['type'] != 8, 'NOBITS has no source bytes')
        return self.data[row['offset']:row['offset'] + row['size']]

    def by_name(self, name):
        matches = [s for s in self.sections if s['name'] == name]
        require(len(matches) == 1, 'Missing or duplicate ELF section: ' + name)
        return matches[0]

    def symbols(self, index):
        if index not in self._symbols:
            table = self.section(index)
            require(table['type'] in (2, 11) and table['entsize'] == 24 and table['size'] % 24 == 0,
                    'Invalid ELF symbol table')
            strings = self.section(table['link'])
            require(strings['type'] == 3, 'Symbol table does not link STRTAB')
            names = self.section_bytes(strings['index'])
            rows = []
            for ordinal, position in enumerate(range(table['offset'], table['offset'] + table['size'], 24)):
                name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', self.data, position)
                rows.append({'index': ordinal, 'symtab': index, 'name': self.string(names, name),
                             'info': info, 'other': other, 'section': section, 'value': value, 'size': size})
            self._symbols[index] = rows
        return self._symbols[index]

    def relocations(self, target_index):
        target = self.section(target_index)
        rows = []
        for table in self.sections:
            if table['type'] != 4 or table['info'] != target_index:
                continue
            require(table['entsize'] == 24 and table['size'] % 24 == 0, 'Invalid RELA table')
            require(self.section(table['link'])['type'] == 2, 'Source RELA does not link SYMTAB')
            symbols = self.symbols(table['link'])
            for position in range(table['offset'], table['offset'] + table['size'], 24):
                offset, info, addend = struct.unpack_from('<QQq', self.data, position)
                require(info >> 32 < len(symbols), 'RELA symbol outside SYMTAB')
                require(offset < target['size'], 'RELA offset outside target section')
                rows.append({'offset': offset, 'kind': info & 0xffffffff, 'addend': addend,
                             'symbol': symbols[info >> 32], 'relocation_section': table['index']})
        return rows

    def function(self, section_index, expected_name=None):
        section = self.section(section_index)
        require(section['type'] == 1 and section['flags'] & 4, 'Source code section is not executable PROGBITS')
        symbols = [s for table in self.sections if table['type'] == 2 for s in self.symbols(table['index'])
                   if s['section'] == section_index and s['info'] & 15 == 2]
        require(len(symbols) == 1, 'Source function symbol is ambiguous')
        symbol = symbols[0]
        require(symbol['value'] == 0 and symbol['size'] == section['size'], 'Function does not cover complete section')
        require(expected_name is None or symbol['name'] == expected_name, 'Source function symbol name differs')
        return symbol

    def va_bytes(self, address, size, executable=False):
        require(size > 0 and 0 <= address < address + size <= 1 << 64, 'Invalid virtual address range')
        sections = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                    and (not executable or s['flags'] & 4)
                    and s['address'] <= address and address + size <= s['address'] + s['size']]
        loads = [s for s in self.segments if s['type'] == 1
                 and (not executable or s['flags'] & 1)
                 and s['address'] <= address and address + size <= s['address'] + s['filesz']]
        require(len(sections) == len(loads) == 1, 'Ambiguous or absent section/PT_LOAD mapping')
        section, load = sections[0], loads[0]
        offset = section['offset'] + address - section['address']
        require(offset == load['offset'] + address - load['address'], 'Section/PT_LOAD coordinates disagree')
        return self.data[offset:offset + size], {'va': address, 'file_offset': offset,
                'bytes': size, 'section': section, 'PT_LOAD': load}

    def relative(self, address):
        """Resolve a selected non-null captured slot, not an arbitrary loader."""
        self.va_bytes(address, 8)
        table = self.by_name('.rela.dyn')
        require(table['type'] == 4 and table['entsize'] == 24 and table['size'] % 24 == 0,
                'Invalid captured .rela.dyn')
        matches = []
        for position in range(table['offset'], table['offset'] + table['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, position)
            if slot == address:
                matches.append({'slot': slot, 'kind': info & 0xffffffff, 'symbol': info >> 32,
                                'addend': addend, 'record_file_offset': position})
        require(len(matches) == 1 and matches[0]['kind'] == 8 and matches[0]['symbol'] == 0,
                'Captured slot does not have one symbol-zero RELATIVE relocation')
        self.va_bytes(matches[0]['addend'], 1)
        return matches[0]


def compare_code(official, captured, relocations):
    require(type(official) is bytes and type(captured) is bytes and len(official) == len(captured) > 0,
            'Code lengths/types differ; no trimming is allowed')
    fields, occupied = [], set()
    for row in relocations:
        require(row['kind'] in (2, 9) and row['addend'] == -4,
                'Unsupported selected-code relocation type/addend')
        width = 4  # R_X86_64_PC32 and R_X86_64_GOTPCREL, not a guessed input width.
        offset = row['offset']
        require(isinstance(offset, int) and 0 <= offset <= len(official) - width, 'Code RELA field outside span')
        positions = set(range(offset, offset + width))
        require(not occupied & positions, 'Overlapping code RELA fields')
        occupied.update(positions)
        fields.append({**row, 'width': width, 'official_field_hex': official[offset:offset + width].hex(),
                       'captured_field_hex': captured[offset:offset + width].hex()})
    differences = [i for i, (a, b) in enumerate(zip(official, captured)) if a != b]
    gaps = [i for i in differences if i not in occupied]
    return {'bytes': len(official), 'official_sha256': sha256(official), 'captured_sha256': sha256(captured),
            'raw_equal': official == captured, 'raw_difference_offsets': differences,
            'raw_difference_count': len(differences), 'actual_RELA_field_bytes': len(occupied),
            'actual_RELA_field_offsets': sorted(occupied), 'non_RELA_bytes': len(official) - len(occupied),
            'equal_non_RELA_bytes': len(official) - len(occupied) - len(gaps),
            'non_RELA_difference_offsets': gaps, 'relocations': fields}


def compare_data(official, captured):
    require(type(official) is bytes and type(captured) is bytes and len(official) > 0,
            'Expected immutable, nonempty referenced data')
    require(official == captured, 'Referenced raw data differs; no trimming or field masks')
    return {'bytes': len(official), 'raw_equal': True, 'sha256': sha256(official)}


def bind_symbol(actual, expected):
    require(actual == expected, 'Reference does not name the compared official function symbol')
    return actual


def unique_fde(fdes, start, size):
    matches = [row for row in fdes if row['start'] == start and row['end'] == start + size]
    require(len(matches) == 1, 'Selected span does not have one exact FDE')
    return matches[0]


def analyze(target_bytes, archive_bytes):
    require(type(target_bytes) is bytes and sha256(target_bytes) == TARGET_SHA256, 'Captured input identity differs')
    require(type(archive_bytes) is bytes and sha256(archive_bytes) == CORE_SHA256, 'Core archive identity differs')
    members = ar_members(archive_bytes)
    require(MEMBER in members and sha256(members[MEMBER]) == MEMBER_SHA256, 'Core member identity differs')
    source, target = Elf(members[MEMBER], 1), Elf(target_bytes, 3)
    _, fdes = eh_frame_records(target_bytes, target.sections)
    exports, bodies, references = {}, [], []

    def export(name, raw):
        require(name not in exports or exports[name] == raw, 'Conflicting deterministic export')
        exports[name] = raw

    for role, start, size, index, name in SPECS:
        symbol = source.function(index, name)
        official = source.section_bytes(index)
        require(len(official) == size, 'Source body length differs')
        captured, mapping = target.va_bytes(start, size, executable=True)
        fde = unique_fde(fdes, start, size)
        relas = source.relocations(index)
        comparison = compare_code(official, captured, relas)
        bodies.append({'role': role, 'source_section': source.section(index), 'source_symbol': symbol,
                       'target_mapping': mapping, 'target_FDE': fde, 'comparison': comparison})
        export('official/' + role + '.bin', official)
        export('captured/' + role + '.bin', captured)
        for row in comparison['relocations']:
            offset, source_symbol = row['offset'], row['symbol']
            displacement = int.from_bytes(captured[offset:offset + 4], 'little', signed=True)
            referenced_va = start + offset + displacement - row['addend']
            reference = {'role': role, 'offset': offset, 'kind': row['kind'], 'width': 4,
                         'source_symbol': source_symbol, 'captured_reference_va': referenced_va}
            if row['kind'] == 2:
                section = source.section(source_symbol['section'])
                length = source_symbol['size'] or section['size'] - source_symbol['value']
                require(0 <= source_symbol['value'] < section['size'] and length > 0
                        and source_symbol['value'] + length <= section['size'], 'Referenced source data outside section')
                raw = source.section_bytes(section['index'])[source_symbol['value']:source_symbol['value'] + length]
                captured_data, data_mapping = target.va_bytes(referenced_va, length)
                reference.update(compare_data(raw, captured_data))
                reference.update({'source_data_section': section, 'captured_data_mapping': data_mapping})
                export(f"official/data-{section['index']}-{source_symbol['value']}-{length}.bin", raw)
                export(f'captured/data-{referenced_va:x}-{length}.bin', captured_data)
            else:
                relative = target.relative(referenced_va)
                # The slot binding is not a claim of complete callee or runtime closure.
                target.va_bytes(referenced_va, 8)
                reference['captured_slot_RELA'] = relative
            references.append(reference)

    # Distinct data-relocation domains: these do NOT enlarge the 76 code bytes.
    layout_ref = next(r for r in references if r['role'] == 'parent' and r.get('bytes') == 48)
    layout_section = layout_ref['source_symbol']['section']
    layout = source.section_bytes(layout_section)
    layout_relas = source.relocations(layout_section)
    require(len(layout) == 48 and struct.unpack_from('<QQQ', layout) == (0, 24, 8), 'Fixed layout header differs')
    require([r['offset'] for r in layout_relas] == [24, 32, 40], 'Layout pointer fields differ')
    links = []
    for row in layout_relas:
        require(row['kind'] == 1 and row['addend'] == 0, 'Layout field is not actual ABS64')
        if row['offset'] == 24:
            bind_symbol(row['symbol'], bodies[1]['source_symbol'])
        relative = target.relative(layout_ref['captured_reference_va'] + row['offset'])
        links.append({'source_RELA': {**row, 'width': 8}, 'captured_RELA': relative,
                      'body_qualification': 'separately partial adapter comparison' if row['offset'] == 24 else 'OPEN'})
    require(links[0]['captured_RELA']['addend'] == SPECS[1][1], 'Layout adapter link differs')
    for reference in references:
        if reference['role'] == 'parent' and reference['kind'] == 9:
            bind_symbol(reference['source_symbol'], bodies[1]['source_symbol'])
    require(all(r['captured_slot_RELA']['addend'] == SPECS[1][1]
                for r in references if r['role'] == 'parent' and r['kind'] == 9), 'Parent GOT adapter link differs')

    location_ref = next(r for r in references if r['role'] == 'decimal' and r.get('bytes') == 24)
    location_index = location_ref['source_symbol']['section']
    location = source.section_bytes(location_index)
    require(len(location) == 24, 'Location record length differs')
    pointer, length, line, column = struct.unpack('<QQII', location)
    require((pointer, length, line, column) == (0, 75, 599, 5), 'Raw Location fields differ')
    path_relas = source.relocations(location_index)
    require(len(path_relas) == 1, 'Location pointer RELA is ambiguous')
    path_rela = path_relas[0]
    require(path_rela['offset'] == 0 and path_rela['kind'] == 1, 'Location pointer is not ABS64')
    path_symbol = path_rela['symbol']
    path_section = source.section_bytes(path_symbol['section'])
    path_offset = path_symbol['value'] + path_rela['addend']
    require(0 <= path_offset <= len(path_section) - length, 'Source path outside section')
    path = path_section[path_offset:path_offset + length]
    path_relative = target.relative(location_ref['captured_reference_va'])
    captured_path, path_mapping = target.va_bytes(path_relative['addend'], length)
    compare_data(path, captured_path)
    export('official/num-source-path.bin', path)
    export('captured/num-source-path.bin', captured_path)

    panic_ref = next(r for r in references if r['role'] == 'decimal' and r['kind'] == 9)
    require(all(r['captured_slot_RELA'] == panic_ref['captured_slot_RELA']
                for r in references if r['role'] == 'decimal' and r['kind'] == 9), 'Decimal GOT callee slots differ')
    panic_symbol = source.function(panic_ref['source_symbol']['section'], panic_ref['source_symbol']['name'])
    for reference in references:
        if reference['role'] == 'decimal' and reference['kind'] == 9:
            bind_symbol(reference['source_symbol'], panic_symbol)
    panic = source.section_bytes(panic_symbol['section'])
    captured_panic, panic_mapping = target.va_bytes(panic_ref['captured_slot_RELA']['addend'], len(panic), True)
    require(len(panic) == 61, 'Supporting callee length differs')
    panic_fde = unique_fde(fdes, panic_mapping['va'], len(panic))
    panic_comparison = compare_code(panic, captured_panic, source.relocations(panic_symbol['section']))
    export('official/supporting-panic61.bin', panic)
    export('captured/supporting-panic61.bin', captured_panic)

    counts = {'selected_code_bytes': sum(b['comparison']['bytes'] for b in bodies),
              'actual_code_RELA_fields': sum(len(b['comparison']['relocations']) for b in bodies),
              'actual_code_RELA_bytes': sum(b['comparison']['actual_RELA_field_bytes'] for b in bodies),
              'non_RELA_bytes': sum(b['comparison']['non_RELA_bytes'] for b in bodies),
              'equal_non_RELA_bytes': sum(b['comparison']['equal_non_RELA_bytes'] for b in bodies),
              'non_RELA_gap_bytes': sum(len(b['comparison']['non_RELA_difference_offsets']) for b in bodies),
              'raw_differing_code_bytes': sum(b['comparison']['raw_difference_count'] for b in bodies)}
    require(list(counts.values()) == [1456, 19, 76, 1380, 1378, 2, 78], 'Pinned three-span comparison result differs')
    require(bodies[1]['comparison']['non_RELA_difference_offsets'] == [464, 467], 'Adapter gaps were erased or changed')
    report = {'schema_version': 1, 'task': 'RE-002', 'target_release': 'node94', 'python_version': sys.version,
              'inputs': {'target_sha256': sha256(target_bytes), 'target_bytes': len(target_bytes),
                         'core_archive_sha256': sha256(archive_bytes), 'core_archive_bytes': len(archive_bytes),
                         'core_member': MEMBER, 'core_member_sha256': sha256(members[MEMBER]),
                         'core_member_bytes': len(members[MEMBER])},
              'analysis_source_bindings': {name: sha256((ROOT / 'tools' / name).read_bytes())
                                           for name in ('libcore_fmt_correspondence.py', 'fde_extents.py', 'elf_index.py')},
              'immutable_admission': 'All target/archive content facts derive from two admitted immutable bytes objects; no later artifact pathname reads.',
              'analysis_source_binding_limit': 'Tool-file hashes are observational reads in a trusted stable analysis environment, not atomic execution provenance.',
              'source_artifact': 'Published rust-std1.94.1 x86_64-unknown-linux-gnu libcore; no source build performed.',
              'bodies': bodies, 'counts': counts, 'references': references,
              'layout': {'bytes': 48, 'fixed_bytes': 24, 'actual_pointer_RELA_bytes': 24, 'raw_equal': True,
                         'links': links, 'other_method_bodies': 'OPEN; no runtime/private-ABI qualification'},
              'location_path': {'source_ABS64': {**path_rela, 'width': 8}, 'captured_RELATIVE': path_relative,
                                'raw_path_hex': path.hex(), 'raw_equal': True, 'target_mapping': path_mapping,
                                'length': length, 'line': line, 'column': column},
              'supporting_callee': {'source_symbol': panic_symbol, 'target_mapping': panic_mapping,
                                   'target_FDE': panic_fde,
                                   'comparison': panic_comparison, 'counted_in_primary_denominator': False,
                                   'transitive_data_callees': 'OPEN'},
              'limits': ['Two adapter non-RELA differences remain genuine raw gaps.',
                         'No masks beyond byte positions of actual typed code RELA records; no byte rewriting or trimming.',
                         'No original compiler/version/fork/type identity, source build, CPU/runtime or whole-ELF equivalence.',
                         'Partial GOT/layout links do not establish transitive call/data closure.',
                         'No captured/compatible-object/emulator execution; no component gate change.']}
    return report, exports


def collect(target_path, core_path, out):
    out = Path(out)
    require(not out.exists(), 'Output already exists')
    target = admit_file(target_path, TARGET_SHA256)
    archive = admit_file(core_path, CORE_SHA256)
    license_bytes = admit_file(LICENSE, MIT_SHA256)
    report, exports = analyze(target, archive)
    exports['official/LICENSE-MIT'] = license_bytes
    exports['official/NOTICE.txt'] = (
        'Selected compiled libcore excerpts from the published rust-std1.94.1\n'
        'x86_64-unknown-linux-gnu component; MIT option elected.\n'
        'Copyright (c) The Rust Project Contributors. See LICENSE-MIT.\n'
        'Archive SHA-256: ' + CORE_SHA256 + '\nMember SHA-256: ' + MEMBER_SHA256 + '\n'
        'These are published-artifact excerpts, not a source build or original-compiler attribution.\n'
        'Captured Hyperliquid evidence is separate and retains its existing ownership.\n'
    ).encode()
    # Exclusive directory creation occurs after analysis, so failures preserve it.
    out.mkdir(parents=False, exist_ok=False, mode=0o700)
    for name, raw in sorted(exports.items()):
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
    (out / 'REPORT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    rows = [f'{sha256(p.read_bytes())}  {p.relative_to(out).as_posix()}'
            for p in sorted(out.rglob('*')) if p.is_file()]
    (out / 'MANIFEST.sha256').write_text('\n'.join(rows) + '\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--core-archive', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = collect(args.target, args.core_archive, args.out)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(report['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
