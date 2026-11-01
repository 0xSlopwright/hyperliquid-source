#!/usr/bin/env python3
"""RE-002: bind a used node94 edge to one complete licensed libcore body.

Static container/relocation parsing and a tiny native disassembly only. There
is no compiler, instruction interpreter, object execution or relocation mask.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import tempfile

import libcore_fmt_correspondence as containers
import node115_field_adapter_drift as indexed

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SIZE = 91774280
TARGET_SHA256 = containers.TARGET_SHA256
CORE_SIZE = 2917630
CORE_SHA256 = containers.CORE_SHA256
MEMBER = containers.MEMBER
MEMBER_SHA256 = containers.MEMBER_SHA256
NAME = '_ZN4core3fmt5write17h469843d235cc4241E'
SECTION = '.text.' + NAME
START, SIZE = 0x1571d90, 448
BODY_SHA256 = '1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561'
CALLER, CALLER_SIZE, FIELD = 0x1571150, 19, 15
CALLER_PREFIX = bytes.fromhex('4889d14889f2488d35b3301004ff25')
SLOT = 0x576e008
PROVIDER = Path('/usr/bin/x86_64-linux-gnu-objdump')
PROVIDER_SHA256 = '96afb8521834982d0e711b5d6e9785252bf82129fb0106b93a6bd54d83fae11f'
RETAINED = {
    'default-linked': (3, 3913384, 'a104289d093d55a3c0c0a467da69db727a1cb34655c5d34704eb0cefcf479175'),
    'thin-linked': (3, 1714648, '09c1fbb88fbb637452eb570e9b08d19b42f9d4c7b21ff65ed80bf67a0b81567e'),
    'thin-object': (1, 216632, 'affd45f96d6b380c047729ddb0bc7893bcd481460e6714507434da315bcd9640'),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def admit_file(path, size, digest):
    """Admit the immutable bytes used later, not a stable pathname guarantee."""
    with Path(path).open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size == size, 'Input file size/type differs')
        data = stream.read()
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    need(identity(before) == identity(after), 'Input changed during admission')
    need(type(data) is bytes and len(data) == size and sha(data) == digest, 'Input SHA-256 differs')
    return data


def source_leaf(member):
    """Below archive identity: validate the actual complete symbol and zero RELA."""
    image = containers.Elf(member, 1)
    named = [s for table in image.sections if table['type'] == 2
             for s in image.symbols(table['index'])
             if s['name'] == NAME and s['info'] & 15 == 2]
    need(len(named) == 1, 'Published function symbol is absent or ambiguous')
    section = image.by_name(SECTION)
    symbol = image.function(section['index'], NAME)
    need(symbol == named[0] and symbol['info'] == 18 and symbol['other'] == 0,
         'Published global/default FUNC binding differs')
    need(symbol['size'] == SIZE and section['size'] == SIZE and section['flags'] & 2,
         'Published complete448-byte allocated function differs')
    need(not any(table['type'] in (9, 19) and table['info'] == section['index']
                 and table['size'] for table in image.sections),
         'Selected source has unsupported relocation encoding; masking is forbidden')
    relocations = image.relocations(section['index'])
    need(not relocations, 'Selected source code has RELA fields; masking is forbidden')
    return image.section_bytes(section['index']), {'symbol': symbol, 'section': section,
                                                   'actual_code_RELA': relocations}


def compare_raw(official, captured):
    need(type(official) is bytes and type(captured) is bytes
         and len(official) == len(captured) == SIZE, 'Both complete448-byte bodies are required')
    differences = [i for i in range(SIZE) if official[i] != captured[i]]
    return {'bytes': SIZE, 'source_sha256': sha(official), 'target_sha256': sha(captured),
            'raw_equal': not differences, 'raw_differing_offsets': differences,
            'normalization_masks': [], 'trimmed_bytes': 0}


def bind_edge(caller, relative_rows, slot_raw):
    """The actual19-byte caller's selected GOT field; other input data stays open."""
    need(type(caller) is bytes and len(caller) == CALLER_SIZE
         and caller[:FIELD] == CALLER_PREFIX, 'Actual caller opcode/context differs')
    slot = CALLER + FIELD + 4 + struct.unpack_from('<i', caller, FIELD)[0]
    need(slot == SLOT, 'Actual used GOT field points elsewhere')
    need(type(slot_raw) is bytes and slot_raw == bytes(8), 'Observed zero-initialized GOT bytes differ')
    need(len(relative_rows) == 1, 'Selected GOT has missing or duplicate relocation')
    row = relative_rows[0]
    need(row['slot'] == slot and row['kind'] == 8 and row['symbol'] == 0
         and row['addend'] == START, 'Selected GOT RELATIVE does not bind the448-byte callee')
    return {'caller_start': CALLER, 'caller_bytes': CALLER_SIZE, 'caller_raw_hex': caller.hex(),
            'field_offset': FIELD, 'field_bytes': 4, 'GOT_slot': slot,
            'slot_raw_hex': slot_raw.hex(), 'RELATIVE': row,
            'runtime_address_scope': 'Linked coordinates; a normal loader adds unknown image load bias.'}


def target_leaf(target):
    """Below full identity: use maintained ELF mappings and indexed FDE reader."""
    image = containers.Elf(target, 3)
    caller, caller_mapping = image.va_bytes(CALLER, CALLER_SIZE, executable=True)
    slot_raw, slot_mapping = image.va_bytes(SLOT, 8)
    relative = image.relative(SLOT)
    edge = bind_edge(caller, [relative], slot_raw)
    frame = indexed.selected_frame(indexed.Image(target, 3), START, SIZE)
    need(frame['FDE_raw_length_bytes'] == 52, 'Observed complete selected FDE footprint differs')
    code, mapping = image.va_bytes(START, SIZE, executable=True)
    need(mapping['file_offset'] == frame['body_file_offset'], 'Selected FDE/code coordinates differ')
    return code, {'edge': edge, 'caller_mapping': caller_mapping, 'slot_mapping': slot_mapping,
                  'frame': frame, 'code_mapping': mapping}


def retained_leaf(data, kind):
    """Select the actual named complete body; linked ELF comparison is raw only."""
    if kind == 1:
        return source_leaf(data)
    image = containers.Elf(data, kind)
    symbols = [s for table in image.sections if table['type'] == 2
               for s in image.symbols(table['index'])
               if s['name'] == NAME and s['info'] & 15 == 2
               and 0 < s['section'] < len(image.sections)]
    need(len(symbols) == 1, 'Retained named FUNC is absent or ambiguous')
    symbol = symbols[0]
    section = image.section(symbol['section'])
    offset = symbol['value'] - section['address']
    need(symbol['size'] == SIZE and section['type'] == 1 and section['flags'] & 6 == 6
         and 0 <= offset <= section['size'] - SIZE, 'Retained complete FUNC footprint differs')
    code, mapping = image.va_bytes(symbol['value'], SIZE, executable=True)
    need(mapping['section']['index'] == section['index']
         and mapping['file_offset'] == section['offset'] + offset,
         'Retained symbol/section/PT_LOAD coordinates differ')
    return code, {'symbol': symbol, 'section': section, 'code_mapping': mapping,
                  'comparison_scope': 'raw only; no linked relocation masks'}


def derive(target, archive, retained=None):
    """Semantic/metadata seams below admission support real changed-input controls."""
    members = containers.ar_members(archive)
    need(MEMBER in members, 'Exact published core member missing')
    member, offset = indexed.archive_member(archive)
    need(member == members[MEMBER], 'Maintained ar readers disagree on selected member')
    official, source = source_leaf(member)
    captured, target_record = target_leaf(target)
    comparison = compare_raw(official, captured)
    candidate_rows = []
    for label, data in sorted((retained or {}).items()):
        need(label in RETAINED, 'Unknown retained recipe')
        code, metadata = retained_leaf(data, RETAINED[label][0])
        candidate_rows.append({'recipe': label, 'artifact_bytes': len(data),
                               'artifact_sha256': sha(data), 'metadata': metadata,
                               'comparison_to_source': compare_raw(official, code)})
    report = {'schema': 'libcore-write-fmt448-dependency-v1',
              'target': {'bytes': len(target), 'sha256': sha(target)},
              'source': {'archive_bytes': len(archive), 'archive_sha256': sha(archive),
                         'member': MEMBER, 'member_data_offset': offset,
                         'member_bytes': len(member), 'member_sha256': sha(member), **source},
              'target_binding': target_record, 'primary_comparison': comparison,
              'retained_inputs_not_new_builds': candidate_rows,
              'denominators': {'new_primary_code_bytes': SIZE, 'revisited_caller_context_bytes': CALLER_SIZE,
                               'accepted_primary1456_changed': False, 'prior_supporting114_changed': False},
              'limits': ['Four dynamic transfers/input-referenced data remain open.',
                         'No renderer, input/private ABI, runtime/unwind or whole-ELF equivalence.',
                         'Official artifact compatibility is not original compiler/version/fork uniqueness.',
                         'No compiler, captured/object execution, instruction interpreter or progress gate.']}
    return report, {'target.hex': captured.hex().encode() + b'\n',
                    'official.hex': official.hex().encode() + b'\n'}


def analyze(target, archive, retained=None):
    need(type(target) is bytes and len(target) == TARGET_SIZE and sha(target) == TARGET_SHA256,
         'Captured node94 identity differs')
    need(type(archive) is bytes and len(archive) == CORE_SIZE and sha(archive) == CORE_SHA256,
         'Published core archive identity differs')
    for label, data in (retained or {}).items():
        need(label in RETAINED, 'Unknown retained recipe')
        _, size, digest = RETAINED[label]
        need(type(data) is bytes and len(data) == size and sha(data) == digest,
             'Retained artifact identity differs: ' + label)
    report, exports = derive(target, archive, retained)
    need(report['source']['member_sha256'] == MEMBER_SHA256, 'Selected published member identity differs')
    need(report['primary_comparison']['raw_equal']
         and all(x['comparison_to_source']['raw_equal'] for x in report['retained_inputs_not_new_builds']),
         'Complete raw body comparison failed')
    return report, exports


def native_view(raw):
    """Trusted GNU rendering of one private nonexecutable448-byte input only."""
    need(type(raw) is bytes and len(raw) == SIZE and sha(raw) == BODY_SHA256,
         'Native rendering is limited to the admitted matched448-byte body')
    need(PROVIDER.is_file() and os.access(PROVIDER, os.X_OK)
         and sha(PROVIDER.read_bytes()) == PROVIDER_SHA256, 'Native provider differs')
    with tempfile.TemporaryDirectory(prefix='fmt448-') as temporary:
        path = Path(temporary) / 'body.bin'
        path.write_bytes(raw)
        path.chmod(0o600)
        argv = [str(PROVIDER), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + str(START), 'body.bin']
        result = subprocess.run(argv, cwd=temporary,
                                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'},
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        need(result.returncode == 0 and path.read_bytes() == raw, 'Native rendering/input changed')
    need(sha(PROVIDER.read_bytes()) == PROVIDER_SHA256, 'Native provider changed')
    rows, cursor = [], 0
    for line in result.stdout.decode('utf-8').splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if not match:
            continue
        address = int(match[1], 16)
        data = bytes.fromhex(match[2])
        need(address == START + cursor and data == raw[cursor:cursor + len(data)],
             'Native bytes/address coverage differs')
        rows.append({'address': address, 'raw_hex': data.hex(), 'assembly': match[3]})
        cursor += len(data)
    need(cursor == SIZE and len(rows) == 138, 'Native complete448-byte instruction extent differs')
    calls = [r for r in rows if r['assembly'].startswith('call')]
    tail = [r for r in rows if r['raw_hex'] == 'ffe0']
    need([r['raw_hex'] for r in calls] == ['ff55a8', 'ff55a8', 'ff540308'] and len(tail) == 1,
         'Observed dynamic transfer witnesses differ')
    rip = [r for r in rows if 'rip' in r['assembly'].lower()]
    need(not rip, 'Observed GNU RIP-relative data operands differ')
    boundaries = {r['address'] for r in rows}
    direct = []
    for row in rows:
        code = bytes.fromhex(row['raw_hex'])
        if code[0] in (0xeb, *range(0x70, 0x80)):
            need(len(code) == 2, 'Unsupported observed short branch')
            destination = row['address'] + 2 + struct.unpack_from('<b', code, 1)[0]
        elif code[0] == 0xe9:
            need(len(code) == 5, 'Unsupported observed near branch')
            destination = row['address'] + 5 + struct.unpack_from('<i', code, 1)[0]
        elif code[:1] == b'\x0f' and len(code) > 1 and 0x80 <= code[1] <= 0x8f:
            need(len(code) == 6, 'Unsupported observed conditional branch')
            destination = row['address'] + 6 + struct.unpack_from('<i', code, 2)[0]
        else:
            need(code[0] != 0xe8, 'Unexpected fixed direct CALL')
            continue
        need(destination in boundaries, 'Observed direct branch leaves the complete body')
        direct.append({'address': row['address'], 'destination': destination,
                       'raw_hex': row['raw_hex']})
    need(len(direct) == 26, 'Observed local direct-branch extent differs')
    return result.stdout, {'provider_sha256': PROVIDER_SHA256, 'argv': argv, 'exit': result.returncode,
                           'input_bytes': SIZE, 'instruction_rows': len(rows),
                           'indirect_calls': calls, 'indirect_tail_jumps': tail,
                           'direct_local_branches': direct, 'fixed_direct_external_calls': 0,
                           'RIP_relative_rows': rip, 'output_sha256': sha(result.stdout),
                           'stderr_sha256': sha(result.stderr),
                           'scope': 'Provider observation, not a private ABI/input/callback semantic proof.'}


def source_pins():
    names = ('libcore_write_fmt_leaf.py', 'libcore_fmt_correspondence.py',
             'node115_field_adapter_drift.py', 'elf_index.py', 'fde_extents.py',
             'build_provenance.py', 'artifacts.py')
    return {str(Path('tools') / n): sha((ROOT / 'tools' / n).read_bytes()) for n in names}


def collect(binary, libcore, output, retained_paths=None):
    output = Path(output)
    need(not os.path.lexists(output), 'Output path must be new; previous evidence is preserved')
    before = source_pins()
    target = admit_file(binary, TARGET_SIZE, TARGET_SHA256)
    archive = admit_file(libcore, CORE_SIZE, CORE_SHA256)
    candidates = {label: admit_file(path, RETAINED[label][1], RETAINED[label][2])
                  for label, path in (retained_paths or {}).items()}
    report, exports = analyze(target, archive, candidates)
    listing, observation = native_view(bytes.fromhex(exports['target.hex'].decode().strip()))
    report['native_observation'] = observation
    report['source_helpers'] = before
    report['source_binding_scope'] = 'Before/after digests with trusted Python loading, not atomic module admission'
    license_bytes = admit_file(containers.LICENSE, 1068, containers.MIT_SHA256)
    exports.update({'target.objdump.txt': listing, 'official/LICENSE-MIT': license_bytes,
                    'official/NOTICE.txt': ("Compiled libcore excerpt copyright The Rust Project Contributors.\n"
                                            "MIT option retained in LICENSE-MIT; captured bytes retain separate ownership.\n"
                                            "No Rust/unlicensed inferred source copied; no new compiler/build.\n").encode()})
    need(source_pins() == before, 'Analysis helper source changed')
    exports['report.json'] = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=False)
    for name, data in exports.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--libcore', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    for label in RETAINED:
        parser.add_argument('--' + label, type=Path)
    args = parser.parse_args()
    paths = {label: getattr(args, label.replace('-', '_')) for label in RETAINED
             if getattr(args, label.replace('-', '_')) is not None}
    report = collect(args.binary, args.libcore, args.output, paths)
    print(json.dumps({'primary_bytes': SIZE, 'raw_equal': report['primary_comparison']['raw_equal'],
                      'retained_artifacts': len(report['retained_inputs_not_new_builds'])}))


if __name__ == '__main__':
    main()
