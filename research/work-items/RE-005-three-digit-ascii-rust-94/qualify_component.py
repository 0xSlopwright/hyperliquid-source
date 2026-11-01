"""Fixed own-Rust qualification for the established 85-byte parser contract.

No captured code, evaluator or compatible assembly object executes here.
The native certificate and original oracle were frozen before this source.
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

CRATE = 'node94_three_digit_ascii'
RUSTC_SHA = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
LIB_SHA = 'f74f7d0c2cb9a86deee5e7fc2976afb42d39b4b8829a018df8cc36ab27db05ed'
DRIVER_SHA = 'cafbd5e2bd062b344c5f451ff733928316bc74b8d64162b370d237e201a63442'
ORACLE_SHA = 'c57cd38b84627e3a6dbd2a2d4741de73da7886249006f2baccea9ea91574ca5e'

def need(condition, message):
    if not condition:
        raise ValueError(message)

def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()

def differences(actual, expected):
    rows, wanted = actual.splitlines(), expected.splitlines()
    need(len(rows) == len(wanted), 'Client row count differs')
    result = []
    for observed, answer in zip(rows, wanted):
        fields, target = observed.split(b' '), answer.split(b' ')
        need(len(fields) == len(target) == 2 and fields[0] == target[0], 'Client ID/order/shape differs')
        need(re.fullmatch(rb'[0-9]+', fields[1]) is not None and int(fields[1]) <= 65535,
             'Client scalar is not a normal u16 value')
        need(fields[1] == str(int(fields[1])).encode('ascii'), 'Client scalar is not canonical decimal')
        if observed != answer:
            result.append(fields[0].decode('ascii'))
    return result

def qualify(repo, oracle, rustc, output):
    repo, oracle, rustc, output = [Path(p).absolute() for p in (repo, oracle, rustc, output)]
    need(not os.path.lexists(output), 'Output must be new; preserve earlier records')
    component = repo / 'src/node94-three-digit-ascii'
    source, driver = component / 'lib.rs', component / 'input_only_driver.rs'
    need(digest(source) == LIB_SHA and digest(driver) == DRIVER_SHA, 'Qualified source/driver changed')
    need(digest(oracle / 'ORACLE-FREEZE.json') == ORACLE_SHA, 'Pre-Rust oracle authority changed')
    authority = json.loads((oracle / 'ORACLE-FREEZE.json').read_text(encoding='utf-8'))
    need(authority['case_count'] == 1663 and authority['valid_distinct_triples'] == 900,
         'Pre-Rust case denominator changed')
    for row in authority['files']:
        if row['file'].startswith('target-'):
            need(digest(component / row['file']) == row['sha256'], 'Frozen corpus changed')
    inputs = (component / 'target-inputs.txt').read_bytes()
    expected = (component / 'target-expected.txt').read_bytes()
    need(len(inputs.splitlines()) == len(expected.splitlines()) == 1663, 'Case count differs')
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
               component / 'target-vectors.tsv', oracle / 'ORACLE-FREEZE.json', Path(__file__), provider_manifest]
    def audit():
        payloads = {}
        for relative, pinned in provider.items():
            path = prefix / relative
            value = {'bytes': path.stat().st_size, 'sha256': digest(path)}
            need(value['bytes'] == pinned['bytes'] and value['sha256'] == pinned['sha256'],
                 'Research compiler payload differs: ' + relative)
            payloads[relative] = value
        pins = []
        for row in json.loads((repo / 'provenance/sources.json').read_text(encoding='utf-8'))['repositories']:
            actual = subprocess.check_output(['git', '-C', str(repo / row['path']), 'rev-parse', 'HEAD'],
                                             env={**os.environ, 'GIT_NO_LAZY_FETCH': '1'}).decode().strip()
            need(actual == row['commit'], 'An imported pin changed')
            pins.append({'path': row['path'], 'commit': actual})
        need(len(pins) == 7, 'Imported pin denominator changed')
        return {'sources': {str(p): digest(p) for p in watched}, 'compiler103': payloads,
                'rustc': digest(rustc), 'linker': digest(linker), 'target_sha256_streamed': digest(target),
                'seven_pins': pins}
    output.mkdir(parents=True, exist_ok=False); (output / 'tmp').mkdir()
    before = audit()
    (output / 'BEFORE.json').write_text(json.dumps(before, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (output / 'inputs.txt').write_bytes(inputs)
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': str(output / 'tmp')}
    calls = []
    def run(label, argv, exit_code=0):
        memory = Path('/sys/fs/cgroup/memory.max').read_text().strip()
        headroom = None
        if memory.isdigit():
            headroom = int(memory) - int(Path('/sys/fs/cgroup/memory.current').read_text())
            need(headroom > 256 << 20, 'Pause own component: external reserve below256MiB')
        start = time.monotonic()
        result = subprocess.run([str(x) for x in argv], cwd=repo, env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True)
        streams = {}
        for kind in ['stdout', 'stderr']:
            raw = getattr(result, kind); name = label + '.' + kind
            (output / name).write_bytes(raw)
            streams[kind] = {'file': name, 'bytes': len(raw), 'sha256': digest(output / name)}
        calls.append({'label': label, 'argv': [str(x) for x in argv], 'exit_code': result.returncode,
                      'seconds': time.monotonic() - start, 'headroom_before': headroom, 'streams': streams})
        (output / 'CALLS.json').write_text(json.dumps(calls, indent=2) + '\n', encoding='utf-8')
        need(result.returncode == exit_code, label + ' unexpected exit; raw streams retained')
        return result
    try:
        version = run('rustc-identity', [rustc, '-vV']).stdout.decode()
        need('rustc 1.94.1 ' in version and 'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'Compiler identity differs')
        linker_version = run('linker-identity', [linker, '--version']).stdout.decode()
        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1', '-C', f'opt-level={opt}',
                    '-C', 'overflow-checks=on', '-C', 'linker=' + str(linker),
                    '--remap-path-prefix', str(repo) + '=/node94-three-digit-ascii']
        def library(label, rust_source, opt, directory):
            directory.mkdir(parents=True, exist_ok=False)
            path = directory / ('lib' + CRATE + '.rlib')
            run(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', rust_source, '-o', path,
                        '-C', 'metadata=node94-three-digit-ascii', *flags(opt)])
            return path
        def client(label, lib, opt, directory):
            path = directory / 'input-only-client'
            run(label + '-build', [rustc, '--crate-name', 'three_digit_input_client', driver,
                                   '--extern', CRATE + '=' + str(lib), '-o', path, *flags(opt)])
            result = run(label + '-run', [path, output / 'inputs.txt'])
            return path, result.stdout
        def units(label, rust_source, opt, directory, altered=False):
            path = directory / 'unit-tests'
            run(label + '-build', [rustc, '--crate-name', CRATE, '--test', rust_source, '-o', path, *flags(opt)])
            result = run(label + '-run', [path, '--nocapture', '--test-threads=1'], 101 if altered else 0)
            transcript = result.stdout + result.stderr
            if altered:
                need(b'assertion `left == right` failed' in transcript, 'Control did not fail an actual value assertion')
            else:
                need(b'test result: ok. 1 passed; 0 failed; 0 ignored;' in transcript, 'One ordinary unit did not pass')
            return {'functions': 1, 'fixture_cases': 1663, 'exit_code': result.returncode, 'program_sha256': digest(path)}
        profiles = []
        for name, opt in [('debug', 0), ('optimized', 3)]:
            directory = output / name; lib = library(name + '-library', source, opt, directory)
            unit = units(name + '-unit', source, opt, directory)
            program, actual = client(name + '-client', lib, opt, directory)
            need(differences(actual, expected) == [], name + ' actual scalar outputs differ')
            profiles.append({'name': name, 'opt_level': opt, 'library': str(lib), 'library_sha256': digest(lib),
                             'client': str(program), 'client_sha256': digest(program), 'unit': unit,
                             'input_only_cases': 1663, 'stdout_sha256': hashlib.sha256(actual).hexdigest()})
        a = library('rebuild-a', source, 3, output / 'rebuild-a')
        b = library('rebuild-b', source, 3, output / 'rebuild-b')
        need(a.read_bytes() == b.read_bytes(), 'Own library rebuild bytes differ; no masks or flag search')
        rebuild = {'bytes': a.stat().st_size, 'sha256': digest(a), 'raw_equal': True,
                   'normalization': 'none', 'original_target_byte_identity': False}
        text = source.read_text(encoding='utf-8')
        changes = [('allow-leading-zero', "first < b'1'", "first < b'0'"),
                   ('accept-long-prefix', 'if input.len() != 3', 'if input.len() < 3'),
                   ('hundreds-weight', "u16::from(first - b'0') * 100", "u16::from(first - b'0') * 10")]
        mutants = []
        for name, needle, replacement in changes:
            need(text.count(needle) == 1, 'Control no longer has one source location: ' + name)
            directory = output / ('mutant-' + name); directory.mkdir()
            for filename in ['lib.rs', 'target-vectors.tsv']:
                shutil.copy2(component / filename, directory / filename)
            mutated = directory / 'lib.rs'; mutated.write_text(text.replace(needle, replacement), encoding='utf-8', newline='\n')
            lib = library('mutant-' + name + '-library', mutated, 0, directory / 'library')
            _, actual = client('mutant-' + name + '-client', lib, 0, directory)
            changed = differences(actual, expected); need(changed, 'No normal-valued discrepancy: ' + name)
            unit = units('mutant-' + name + '-unit', mutated, 0, directory, True)
            mutants.append({'name': name, 'source_sha256': digest(mutated), 'normal_rows': 1663,
                            'different_scalar_results': len(changed), 'sample_ids': changed[:8], 'unit': unit})
        after = audit(); need(before == after, 'Source/provider/target/pin identity changed')
        (output / 'AFTER.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        result = {'schema': 'three-digit-own-Rust-component-run-v1', 'status': 'PASS',
                  'repo_base_head': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD']).decode().strip(),
                  'compiler': {'path': str(rustc), 'sha256': RUSTC_SHA, 'identity': version, 'prefix_payloads': 103},
                  'linker': {'path': str(linker), 'sha256': digest(linker), 'identity': linker_version},
                  'environment': environment, 'profiles': profiles, 'own_rebuild': rebuild, 'mutants': mutants,
                  'calls': calls, 'commands': len(calls), 'raw_streams': 2 * len(calls),
                  'before_sha256': digest(output / 'BEFORE.json'), 'after_sha256': digest(output / 'AFTER.json'),
                  'before_after_equal': True, 'case_denominator': 'Original1663 distinct cases:900 valid,739 single-invalid,24 other boundaries. One unit per profile.',
                  'limits': ['Only independently authored Rust/library/test/client code executes.',
                             'Frozen native certificate and closed algebraic proof qualify the target relation; capture hashes are streamed only, never executed or interpreted.',
                             'Chosen safe-slice/u16 API, not original private type/ABI, fault/read trace, whole caller/node, original compiler or target-byte identity.',
                             'Source/provider audits are observed before/after, not atomic hostile-host guarantees. No progress gate is asserted.']}
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
