"""Fixed own-Rust qualification for the closed 414-byte prefixed-hex domain.

Only new Rust/unit/client code executes. Captured inputs are streamed for
identity; no instruction evaluator or compatible assembly object is run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

CRATE = 'node94_prefixed_hex'
RUSTC_SHA = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
LIB_SHA = 'c2e8088b75b2ae5dd404d82b07b7a87a56d99caa20e3b9720533c73d42eebf44'
DRIVER_SHA = '879e8e9f7c880858bddd615f030d11d6ec308c9c89cbf73cec3c08c443ac5167'
ORACLE_SHA = '619c55aa90171ab770fb2868e21e5d40eae1e3b4a0920c1ae012d618f0100b81'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def resource_snapshot():
    root = Path('/sys/fs/cgroup')
    maximum = int((root / 'memory.max').read_text())
    current = int((root / 'memory.current').read_text())
    values = dict((key, int(value)) for key, value in
                  (line.split() for line in (root / 'memory.stat').read_text().splitlines()))
    clean_non_shmem = max(0, values['file'] - values['shmem'] -
                         values.get('file_dirty', 0) - values.get('file_writeback', 0))
    credit = max(0, min(values['inactive_file'], clean_non_shmem))
    return {'maximum': maximum, 'current': current,
            'raw_headroom': max(0, maximum - current),
            'clean_inactive_file_credit': credit,
            'available': max(0, maximum - current) + credit,
            'reserve': 256 << 20, 'slab_credit': 0,
            'active_file_credit': 0, 'shmem_credit': 0}


def differences(actual, expected):
    rows, wanted = actual.splitlines(), expected.splitlines()
    need(len(rows) == len(wanted), 'Client row count differs')
    result = []
    for observed, answer in zip(rows, wanted):
        fields, target = observed.split(b' '), answer.split(b' ')
        need(len(fields) == len(target) == 4 and fields[0] == target[0],
             'Client identity/order/shape differs')
        need(fields[1] in [b'ok', b'unsupported'], 'Not an ordinary API status')
        need(re.fullmatch(rb'0|[1-9][0-9]*', fields[2]) is not None,
             'Client length is not canonical unsigned decimal')
        need(fields[3] == b'-' or (len(fields[3]) % 2 == 0 and
             re.fullmatch(rb'[0-9a-f]+', fields[3]) is not None),
             'Client output is not complete canonical hex')
        capacity = 0 if fields[3] == b'-' else len(fields[3]) // 2
        need(int(fields[2]) <= capacity, 'Returned length exceeds visible output')
        need(fields[1] != b'unsupported' or fields[2] == b'0',
             'Unsupported result must carry policy length zero')
        if observed != answer:
            result.append({'id': fields[0].decode('ascii'),
                           'expected_status': target[1].decode('ascii'),
                           'actual_status': fields[1].decode('ascii')})
    return result


def qualify(repo, oracle, rustc, output):
    repo, oracle, rustc, output = [Path(p).absolute() for p in (repo, oracle, rustc, output)]
    need(not os.path.lexists(output), 'Output must be new; preserve earlier records')
    component = repo / 'src/node94-prefixed-hex'
    source, driver = component / 'lib.rs', component / 'input_only_driver.rs'
    need(digest(source) == LIB_SHA and digest(driver) == DRIVER_SHA, 'Frozen source/driver changed')
    need(digest(oracle / 'ORACLE-FREEZE.json') == ORACLE_SHA, 'Pre-Rust oracle changed')
    authority = json.loads((oracle / 'ORACLE-FREEZE.json').read_text(encoding='utf-8'))
    need((authority['fixture_records'], authority['qualified_normal_records'],
          authority['separate_safe_API_policy_records']) == (2664, 2634, 30),
         'Normal/API policy denominator changed')
    for local, original in [('target-inputs.txt', 'INPUTS.txt'),
                            ('target-expected.txt', 'EXPECTED.txt'),
                            ('target-vectors.txt', 'target-vectors.txt')]:
        need(digest(component / local) == authority['files'][original]['sha256'],
             'Frozen corpus changed: ' + local)
    inputs = (component / 'target-inputs.txt').read_bytes()
    expected = (component / 'target-expected.txt').read_bytes()
    need(len(inputs.splitlines()) == len(expected.splitlines()) == 2664, 'Case count differs')
    need(digest(rustc) == RUSTC_SHA, 'Use the admitted research rustc1.94.1')
    prefix = rustc.resolve().parents[1]
    provider_manifest = repo / 'research/work-items/RE-005-integer-digit-span-94/RUST-BEFORE.json'
    provider = json.loads(provider_manifest.read_text(encoding='utf-8'))['compiler103']
    need(len(provider) == 103, 'Research compiler manifest denominator changed')
    linker = Path(shutil.which('cc') or '')
    need(linker.is_file(), 'A host C linker is required')
    target = repo / 'artifacts/node/94/hl-node'
    need(digest(target) == authority['target_sha256'], 'Original capture identity changed')
    watched = [source, driver, component / 'target-inputs.txt', component / 'target-expected.txt',
               component / 'target-vectors.txt', oracle / 'ORACLE-FREEZE.json', Path(__file__), provider_manifest]
    metadata_calls = []

    def git_metadata(arguments):
        argv = ['git', *arguments]
        result = subprocess.run(argv, env={**os.environ, 'GIT_NO_LAZY_FETCH': '1'},
                                stdin=subprocess.DEVNULL, capture_output=True)
        number = len(metadata_calls) + 1
        streams = {}
        for kind in ['stdout', 'stderr']:
            name = f'metadata-{number:03d}.' + kind
            (output / name).write_bytes(getattr(result, kind))
            streams[kind] = {'file': name, 'bytes': (output / name).stat().st_size,
                             'sha256': digest(output / name)}
        metadata_calls.append({'argv': argv, 'exit_code': result.returncode,
                               'environment': 'Inherited host environment, not fully recorded; only GIT_NO_LAZY_FETCH=1 is overridden.',
                               'streams': streams})
        (output / 'METADATA-CALLS.json').write_text(json.dumps(metadata_calls, indent=2) + '\n', encoding='utf-8')
        need(result.returncode == 0, 'Read-only Git metadata probe failed')
        return result.stdout

    def audit():
        payloads = {}
        for relative, pinned in provider.items():
            path = prefix / relative
            value = {'bytes': path.stat().st_size, 'sha256': digest(path)}
            need(value == {'bytes': pinned['bytes'], 'sha256': pinned['sha256']},
                 'Research compiler payload differs: ' + relative)
            payloads[relative] = value
        pins = []
        for row in json.loads((repo / 'provenance/sources.json').read_text(encoding='utf-8'))['repositories']:
            actual = git_metadata(['-C', str(repo / row['path']), 'rev-parse', 'HEAD']).decode().strip()
            need(actual == row['commit'], 'An imported pin changed')
            pins.append({'path': row['path'], 'commit': actual})
        need(len(pins) == 7, 'Imported pin denominator changed')
        return {'sources': {str(p): digest(p) for p in watched}, 'compiler103': payloads,
                'rustc': digest(rustc), 'linker': digest(linker),
                'target_sha256_streamed': digest(target), 'seven_pins': pins}

    snapshot = resource_snapshot()
    need(snapshot['available'] >= snapshot['reserve'], 'External working-set reserve below256MiB')
    output.mkdir(parents=True, exist_ok=False); (output / 'tmp').mkdir()
    before = audit()
    (output / 'BEFORE.json').write_text(json.dumps(before, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (output / 'inputs.txt').write_bytes(inputs)
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                   'TZ': 'UTC', 'TMPDIR': str(output / 'tmp')}
    calls = []

    def run(label, argv, exit_code=0):
        memory = resource_snapshot()
        need(memory['available'] >= memory['reserve'], 'Pause: external working-set reserve below256MiB')
        start = time.monotonic()
        result = subprocess.run([str(x) for x in argv], cwd=repo, env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True)
        streams = {}
        for kind in ['stdout', 'stderr']:
            raw = getattr(result, kind); name = label + '.' + kind
            (output / name).write_bytes(raw)
            streams[kind] = {'file': name, 'bytes': len(raw), 'sha256': digest(output / name)}
        calls.append({'label': label, 'argv': [str(x) for x in argv],
                      'exit_code': result.returncode, 'seconds': time.monotonic() - start,
                      'resource_before': memory, 'streams': streams})
        (output / 'CALLS.json').write_text(json.dumps(calls, indent=2) + '\n', encoding='utf-8')
        need(result.returncode == exit_code, label + ' unexpected exit; raw streams retained')
        return result

    try:
        version = run('rustc-identity', [rustc, '-vV']).stdout.decode()
        need('rustc 1.94.1 ' in version and 'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'Compiler identity differs')
        linker_version = run('linker-identity', [linker, '--version']).stdout.decode()

        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1',
                    '-C', f'opt-level={opt}', '-C', 'overflow-checks=on',
                    '-C', 'linker=' + str(linker), '--remap-path-prefix',
                    str(repo) + '=/node94-prefixed-hex']

        def library(label, rust_source, opt, directory):
            directory.mkdir(parents=True, exist_ok=False)
            path = directory / ('lib' + CRATE + '.rlib')
            run(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', rust_source,
                        '-o', path, '-C', 'metadata=node94-prefixed-hex', *flags(opt)])
            return path

        def client(label, lib, opt, directory):
            path = directory / 'input-only-client'
            run(label + '-build', [rustc, '--crate-name', 'prefixed_hex_input_client',
                                   driver, '--extern', CRATE + '=' + str(lib),
                                   '-o', path, *flags(opt)])
            actual = run(label + '-run', [path, output / 'inputs.txt']).stdout
            return path, actual

        def units(label, rust_source, opt, directory, altered=False):
            path = directory / 'unit-tests'
            run(label + '-build', [rustc, '--crate-name', CRATE, '--test', rust_source,
                                   '-o', path, *flags(opt)])
            result = run(label + '-run', [path, '--nocapture', '--test-threads=1'], 101 if altered else 0)
            transcript = result.stdout + result.stderr
            if altered:
                need(b'assertion `left == right` failed' in transcript, 'No actual value assertion failed')
            else:
                need(b'test result: ok. 1 passed; 0 failed; 0 ignored;' in transcript,
                     'One ordinary unit did not pass')
            return {'functions': 1, 'available_fixture_records': 2664,
                    'exit_code': result.returncode, 'program_sha256': digest(path)}

        profiles = []
        for name, opt in [('debug', 0), ('optimized', 3)]:
            directory = output / name
            lib = library(name + '-library', source, opt, directory)
            unit = units(name + '-unit', source, opt, directory)
            program, actual = client(name + '-client', lib, opt, directory)
            need(differences(actual, expected) == [], name + ' actual full output differs')
            profiles.append({'name': name, 'opt_level': opt,
                             'library': str(lib), 'library_sha256': digest(lib),
                             'client': str(program), 'client_sha256': digest(program),
                             'unit': unit, 'input_only_records': 2664,
                             'normal_domain_records': 2634, 'separate_API_policy_records': 30,
                             'stdout_sha256': hashlib.sha256(actual).hexdigest()})
        a = library('rebuild-a', source, 3, output / 'rebuild-a')
        b = library('rebuild-b', source, 3, output / 'rebuild-b')
        same = a.read_bytes() == b.read_bytes()
        rebuild = {'a_bytes': a.stat().st_size, 'b_bytes': b.stat().st_size,
                   'a_sha256': digest(a), 'b_sha256': digest(b), 'raw_equal': same,
                   'normalization': 'none', 'original_target_byte_identity': False}
        # Record a genuine own-artifact gap rather than search more flags.
        text = source.read_text(encoding='utf-8')
        changes = [
            ('uppercase-digits', "b'a' + (nibble - 10)", "b'A' + (nibble - 10)"),
            ('omit-whole-first-byte', 'for (index, &byte) in input.iter().enumerate() {',
             'for (index, &byte) in input.iter().enumerate() {\n        if index == 0 && trim_first_nibble && byte < 16 { continue; }'),
            ('trim-every-small-byte', 'index == 0 && trim_first_nibble && byte < 16',
             'index < input.len() && trim_first_nibble && byte < 16'),
        ]
        mutants = []
        for name, needle, replacement in changes:
            need(text.count(needle) == 1, 'Control needs one source location: ' + name)
            directory = output / ('mutant-' + name); directory.mkdir()
            shutil.copy2(component / 'target-vectors.txt', directory / 'target-vectors.txt')
            mutated = directory / 'lib.rs'
            mutated.write_text(text.replace(needle, replacement), encoding='utf-8', newline='\n')
            lib = library('mutant-' + name + '-library', mutated, 0, directory / 'library')
            _, actual = client('mutant-' + name + '-client', lib, 0, directory)
            changed = differences(actual, expected)
            need(changed and all(x['expected_status'] == x['actual_status'] == 'ok' for x in changed),
                 'Control must produce normal-valued discrepancies without policy changes')
            unit = units('mutant-' + name + '-unit', mutated, 0, directory, True)
            mutants.append({'name': name, 'source_sha256': digest(mutated),
                            'complete_records': 2664, 'different_normal_results': len(changed),
                            'changed_API_policy_results': 0, 'sample_ids': [x['id'] for x in changed[:8]],
                            'unit': unit})
        after = audit(); need(before == after, 'Source/provider/target/pin identity changed')
        (output / 'AFTER.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        result = {'schema': 'prefixed-hex-own-Rust-component-run-v1', 'status': 'PASS',
                  'repo_base_head': git_metadata(['-C', str(repo), 'rev-parse', 'HEAD']).decode().strip(),
                  'compiler': {'path': str(rustc), 'sha256': RUSTC_SHA, 'identity': version, 'prefix_payloads': 103},
                  'linker': {'path': str(linker), 'sha256': digest(linker), 'identity': linker_version},
                  'measured_scientific_child_environment': environment, 'profiles': profiles,
                  'own_rebuild': rebuild, 'mutants': mutants, 'calls': calls,
                  'commands': len(calls), 'raw_streams': 2 * len(calls),
                  'separate_read_only_git_metadata_probes': {'count': len(metadata_calls),
                      'raw_streams': 2 * len(metadata_calls), 'calls': metadata_calls,
                      'excluded_from_scientific_commands': True,
                      'scope': 'Direct Git metadata invocations only; not an OS process-tree trace. Their inherited host environment is trusted and not fully recorded.'},
                  'before_sha256': digest(output / 'BEFORE.json'),
                  'after_sha256': digest(output / 'AFTER.json'), 'before_after_equal': True,
                  'case_denominator': '2664 records:2634 normal-domain +30 separate safe-API policy;512 byte checks support static proof, not additional native calls.',
                  'limits': ['Only independently authored Rust/library/unit/client code executes.',
                             'Captured target is streamed for identity only; static414B proof qualifies normal domain; no emulator/captured/compatible object execution.',
                             'Chosen safe API unsupported policy is not native panic/error equivalence; no original Rust/ABI/compiler, wholecaller/node or target machine-byte identity.',
                             'Observed before/after host/input hashes are not atomic hostile-host guarantees. No gate changes.']}
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        return result
    except Exception as error:
        (output / 'FAILURE.json').write_text(json.dumps({'error': str(error), 'calls': calls}, indent=2) + '\n', encoding='utf-8')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.repo, args.oracle, args.rustc, args.output)
    print(json.dumps({'status': result['status'], 'commands': result['commands'],
                      'raw_streams': result['raw_streams'], 'mutants': len(result['mutants'])}))
