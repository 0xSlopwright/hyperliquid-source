#!/usr/bin/env python3
"""Build the independently authored character request protocol, not captured code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pad_character_protocol_static as native
import pad_character_protocol_reference as reference

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'src/node94-newline-writer-protocol'
SOURCE = COMPONENT / 'lib.rs'
INPUTS = COMPONENT / 'character-inputs.txt'
EXPECTED = COMPONENT / 'character-expected.txt'
CRATE = 'node94_newline_writer_protocol'
COMPILER_SHA256 = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
INPUTS_SHA256 = 'e88f6dc5b9322ab44bcaf2106e2471b7576f27ef8fccc2438ea639c4892d5d2e'
EXPECTED_SHA256 = '1973757de32c42aedaa9cacef21001d1821132d4cac25b9cb16cbcd6a2536a46'
REFERENCE_SHA256 = '275004ec8f9761e0263cea8e072babae21b97ffdd865a0201a75127e8934f10c'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def parse_stimulus(line):
    fields = line.split('|')
    need(len(fields) == 11 and fields[0] and len(fields[1]) == 6,
         'expected eleven input-only character stimulus fields')
    def byte(text):
        value = int(text)
        need(0 <= value <= 255, 'callback/flag byte is outside chosen domain')
        return value
    def optional(text):
        return None if text == '-' else byte(text)
    codepoint = int(fields[1], 16)
    need(0 <= codepoint <= 0x10ffff and not 0xd800 <= codepoint <= 0xdfff,
         'character is outside chosen valid-char domain')
    mode, next_mode = byte(fields[3]), optional(fields[6])
    need(mode in (0, 1) and next_mode in (None, 0, 1), 'scripted method mode is invalid')
    return fields[0], {'codepoint': codepoint, 'initial_flag': byte(fields[2]),
                      'initial_mode': mode, 'w_status': byte(fields[4]),
                      'w_flag': optional(fields[5]), 'w_mode': next_mode,
                      'c_status': [byte(fields[7]), byte(fields[9])],
                      'c_flag': [optional(fields[8]), optional(fields[10])]}


def expected_transcript(line):
    identity, given = parse_stimulus(line)
    observed = reference.observe(given)
    events = []
    for event in observed['events']:
        payload = event['hex'] if event['kind'] == 'bytes' else format(event['codepoint'], '06x')
        kind = 'W' if event['kind'] == 'bytes' else 'C'
        events.append(f"{kind}:{payload}:{event['flag_seen']}:{event['mode_seen']}")
    return (f"{identity}|{observed['status']}|{observed['final_flag']}|"
            f"{observed['final_mode']}|{','.join(events)}")


def oracle(binary, libcore):
    # All native facts come from one immutable full-digest admitted object.
    # It is released before the compiler is invoked. No captured process runs.
    record = native.analyze(Path(binary).read_bytes(), Path(libcore).read_bytes())
    facts = record['target_proof']['parameters']
    need(facts == {'indent_bytes': 4, 'byte_method_slot': 24, 'character_method_slot': 32,
                   'character_width_bits': 32, 'LF_scalar': 10, 'status_width_bits': 8,
                   'indent_error_status': 1, 'flag_store_offset': 74},
         'independent request relation does not match native certificate')
    inputs = INPUTS.read_bytes()
    need(sha(inputs) == INPUTS_SHA256, 'independent pre-Rust stimulus bytes changed')
    need(file_digest(ROOT / 'tools/pad_character_protocol_reference.py') == REFERENCE_SHA256,
         'independent pre-Rust reference bytes changed')
    lines = inputs.decode('ascii').splitlines()
    need(len(lines) == 320 and len({line.split('|')[0] for line in lines}) == 320,
         'independent 320-case input inventory differs')
    expected = ('\n'.join(expected_transcript(line) for line in lines) + '\n').encode('ascii')
    need(sha(expected) == EXPECTED_SHA256, 'independent pre-Rust expected relation changed')
    need(expected == EXPECTED.read_bytes(), 'expected fixture differs from independent native request relation')
    return {'inputs': inputs, 'expected': expected, 'record': record,
            'metadata': {'case_count': len(lines), 'input_sha256': sha(inputs),
                         'expected_sha256': sha(expected), 'native_parameters': facts,
                         'body_sha256': record['frame']['body_sha256'],
                         'reference_sha256': file_digest(ROOT / 'tools/pad_character_protocol_reference.py'),
                         'method': 'Independent pre-Rust three-case abstract callback relation; no CPU/PC/opcode evaluator.'}}


def source_inputs():
    names = ['pad_character_protocol_rust.py', 'pad_character_protocol_static.py',
             'pad_character_protocol_reference.py', 'node115_field_adapter_drift.py',
             'elf_index.py', 'build_provenance.py', 'source_files.py']
    paths = [ROOT / 'tools' / name for name in names]
    paths += [p for p in COMPONENT.iterdir() if p.is_file()]
    return {str(p.relative_to(ROOT)): file_digest(p) for p in sorted(paths)}


def build(binary, libcore, rustc, output, controls=False):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('output already exists; preserve previous evidence')
    before = source_inputs()
    expected = oracle(binary, libcore)
    rustc = Path(rustc).absolute()
    need(file_digest(rustc) == COMPILER_SHA256, 'research compiler differs from verified 1.94.1')
    linker = shutil.which('cc')
    need(linker is not None, 'C linker driver cc is required')
    linker_sha = file_digest(linker)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'inputs.txt').write_bytes(expected['inputs'])
    (output / 'expected.txt').write_bytes(expected['expected'])
    (output / 'oracle.json').write_text(json.dumps(expected['metadata'], indent=2) + '\n')
    calls = []
    def execute(label, argv, *, given=None, required=0):
        start = time.monotonic()
        process = subprocess.run([str(value) for value in argv], input=given,
                                 cwd=ROOT, capture_output=True,
                                 env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        logs = {}
        for kind, data in [('stdout', process.stdout), ('stderr', process.stderr)]:
            path = output / (label + '.' + kind)
            path.write_bytes(data)
            logs[kind] = {'file': path.name, 'bytes': len(data), 'sha256': sha(data)}
        calls.append({'label': label, 'argv': [str(value) for value in argv],
                      'exit_code': process.returncode, 'seconds': round(time.monotonic() - start, 3),
                      'stdin_sha256': None if given is None else sha(given), 'logs': logs})
        (output / 'CALLS.json').write_text(json.dumps(calls, indent=2) + '\n')
        if required is not None:
            need(process.returncode == required, label + ' failed; raw outputs retained')
        return process
    def flags(opt):
        return ['--edition=2021', '-D', 'warnings', '-C', f'opt-level={opt}',
                '-C', 'codegen-units=1', '-C', 'overflow-checks=on', '-C', 'linker=' + linker,
                '--remap-path-prefix', str(ROOT) + '=/reconstruction']
    def library(label, source, opt, directory):
        directory.mkdir(parents=True, exist_ok=False)
        path = directory / ('lib' + CRATE + '.rlib')
        execute(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', source, '-o', path,
                        '-C', 'metadata=node94-character-protocol', *flags(opt)])
        return path
    def client(label, lib, opt, directory):
        path = directory / 'character-input-only'
        execute(label + '-link', [rustc, '--crate-name', 'character_input_only',
                COMPONENT / 'character_input_only.rs', '--extern', CRATE + '=' + str(lib),
                '-o', path, *flags(opt)])
        actual = execute(label + '-run', [path], given=expected['inputs']).stdout
        need(len(actual.splitlines()) == 320, 'production client did not emit all 320 actual rows')
        return actual
    def character_test(label, lib, opt, directory, required=0):
        path = directory / 'character-tests'
        execute(label + '-build', [rustc, '--crate-name', 'character_contract_tests', '--test',
                COMPONENT / 'character_tests.rs', '--extern', CRATE + '=' + str(lib), '-o', path, *flags(opt)])
        return execute(label + '-run', [path, '--nocapture'], required=required)
    try:
        version = execute('rustc-identity', [rustc, '-vV']).stdout.decode()
        need(version.startswith('rustc 1.94.1 ') and 'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'measured research compiler identity differs')
        execute('linker-identity', [linker, '--version'])
        profiles = []
        for name, opt in [('debug', 0), ('optimized', 3)]:
            directory = output / name
            lib = library(name + '-library', SOURCE, opt, directory)
            old_unit = directory / 'byte-tests'
            execute(name + '-byte-test-build', [rustc, '--crate-name', CRATE, '--test', SOURCE,
                    '-o', old_unit, *flags(opt)])
            old = execute(name + '-byte-tests', [old_unit, '--nocapture'])
            need(b'1 passed; 0 failed; 0 ignored' in old.stdout, 'existing 3023-byte-case test did not run')
            character = character_test(name + '-character-tests', lib, opt, directory)
            need(b'1 passed; 0 failed; 0 ignored' in character.stdout, 'new 320-character-case test did not run')
            actual = client(name + '-production', lib, opt, directory)
            need(actual == expected['expected'], name + ' production character request transcript differs')
            profiles.append({'name': name, 'old_byte_cases': 3023, 'character_cases': 320,
                             'Rust_test_functions': 2, 'production_character_rows': 320,
                             'actual_sha256': sha(actual), 'matched': True})
        a = library('own-rebuild-a', SOURCE, 3, output / 'own-rebuild-a')
        b = library('own-rebuild-b', SOURCE, 3, output / 'own-rebuild-b')
        need(a.read_bytes() == b.read_bytes(), 'own unnormalized library rebuilds differ')
        rebuilt = {'bytes': a.stat().st_size, 'sha256': file_digest(a), 'raw_equal': True,
                   'normalization': 'none', 'captured_body_match_claimed': False}
        mutations = []
        if controls:
            source = SOURCE.read_text()
            split = source.index('pub fn write_indented_character')
            prefix, selected = source[:split], source[split:]
            changes = [
                ('flag-only-one', 'flag.get() > 0', 'flag.get() == 1'),
                ('three-spaces', 'b"    "', 'b"   "'),
                ('low8-LF-predicate', "character == '\\n'", '(character as u32 as u8) == 10'),
                ('raw-indent-status', 'if flag.get() > 0 && writer.write_bytes(b"    ", flag) != 0 {\n        return 1;\n    }',
                 'if flag.get() > 0 { let status = writer.write_bytes(b"    ", flag); if status != 0 { return status; } }'),
                ('normalize-character-status', 'writer.write_character(character, flag)',
                 'u8::from(writer.write_character(character, flag) != 0)'),
                ('post-character-store', "flag.set(u8::from(character == '\\n'));\n    writer.write_character(character, flag)",
                 "let status = writer.write_character(character, flag);\n    flag.set(u8::from(character == '\\n'));\n    status"),
                ('ignore-indent-error', 'if flag.get() > 0 && writer.write_bytes(b"    ", flag) != 0 {\n        return 1;\n    }',
                 'if flag.get() > 0 { let _ = writer.write_bytes(b"    ", flag); }')]
            for name, needle, replacement in changes:
                need(selected.count(needle) == 1, 'ambiguous character mutation: ' + name)
                directory = output / ('mutant-' + name)
                directory.mkdir()
                altered = directory / 'lib.rs'
                altered.write_text(prefix + selected.replace(needle, replacement))
                for companion in ['test_driver.rs', 'target-transcripts.tsv']:
                    shutil.copyfile(COMPONENT / companion, directory / companion)
                lib = library('mutant-' + name + '-library', altered, 0, directory / 'library')
                actual = client('mutant-' + name + '-production', lib, 0, directory)
                mismatches = [(index, wanted.decode(), got.decode()) for index, (wanted, got)
                              in enumerate(zip(expected['expected'].splitlines(), actual.splitlines())) if wanted != got]
                need(mismatches, 'compiled character mutation escaped the independent oracle')
                failure = character_test('mutant-' + name + '-tests', lib, 0, directory, required=None)
                need(failure.returncode == 101 and b'assertion' in failure.stdout + failure.stderr,
                     'compiled mutation did not fail an actual semantic assertion')
                mutations.append({'name': name, 'compiled': True, 'rows': 320,
                                  'mismatch_count': len(mismatches), 'first_witness': mismatches[0],
                                  'assertion_exit': failure.returncode, 'source_sha256': file_digest(altered)})
        need(before == source_inputs(), 'computational source/fixture changed during build')
        need(file_digest(rustc) == COMPILER_SHA256 and file_digest(linker) == linker_sha,
             'compiler/linker changed during build')
        need(file_digest(binary) == native.TARGET_SHA256 and file_digest(libcore) == native.ARCHIVE_SHA256,
             'target or official artifact changed during build')
        result = {'status': 'CHARACTER_REQUEST_COMPONENT_PASS', 'compiler_version': version,
                  'compiler_sha256': COMPILER_SHA256, 'compiler_is_research_provider': True,
                  'sources': before, 'source_compiler_target_unchanged': True,
                  'oracle': expected['metadata'], 'profiles': profiles, 'own_rebuild': rebuilt,
                  'compiled_mutants': mutations, 'commands': calls,
                  'captured_execution_or_emulation': False,
                  'limits': ['Chosen safe valid-char/Cell/normal-proxy request protocol only.',
                             'Raw low8 statuses do not establish original Result discriminant validity.',
                             'No original ABI/type/frame/renderer/UTF8/unwind/whole-node/gate claim.']}
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except Exception as error:
        (output / 'FAILURE.json').write_text(json.dumps({'error': str(error), 'commands': calls,
                                                       'outputs_preserved': True}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=native.TARGET)
    parser.add_argument('--libcore', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = build(args.binary, args.libcore, args.rustc, args.output, args.controls)
    print(json.dumps({'status': result['status'], 'profiles': result['profiles'],
                      'compiled_mutants': len(result['compiled_mutants'])}, sort_keys=True))
