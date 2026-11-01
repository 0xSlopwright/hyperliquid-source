#!/usr/bin/env python3
"""Build the independently authored field controller against native contracts.

Only our Rust libraries, clients and supplied normal callbacks execute. The
independent reference admits one immutable node94 bytes object and uses the
preserved static producer; it does not execute the captured target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import bincode_diagnostic_parent_reference as reference

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/node/94/hl-node'
COMPONENT = ROOT/'src/node94-field-request-protocol'
SOURCE = COMPONENT/'lib.rs'
DRIVER = COMPONENT/'test_driver.rs'
INDEPENDENT = COMPONENT/'independent_tests.rs'
FIXTURE_TEST = COMPONENT/'fixture_tests.rs'
FIXTURE = COMPONENT/'target-transcripts.tsv'
ADAPTER = ROOT/'src/node94-newline-writer-protocol/lib.rs'
CRATE = 'node94_field_request_protocol'
ADAPTER_CRATE = 'node94_newline_writer_protocol'
PACKET = ROOT/'research/work-items/RE-005-field-parent-rust-94'
MUTATIONS = PACKET/'SEMANTIC-MUTANTS.json'
COMPILER_SHA256 = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            h.update(raw)
    return h.hexdigest()


def verify_fixture(expected, path=FIXTURE):
    need(Path(path).read_bytes() == expected['fixture'],
         'Checked transcript fixture differs from fresh certificate-derived expectations')


HARNESS = r'''extern crate node94_field_request_protocol;
#[path = "__DRIVER__"] mod test_driver;
use std::io::{self, Write};
fn main() {
    let path = std::env::args().nth(1).expect("input-only stimuli path");
    let inputs = std::fs::read_to_string(path).expect("input-only stimuli");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        writeln!(output, "{}", test_driver::transcript(line)).unwrap();
    }
}
'''


def compare(actual, expected):
    rows, wanted = actual.splitlines(), expected.splitlines()
    need(len(rows) == len(wanted), 'Actual production row count differs; not a semantic mutant result')
    mismatches = []
    for row, answer in zip(rows, wanted):
        identity = answer.split(b';', 1)[0]
        need(row.split(b';', 1)[0] == identity, 'Actual production identities/order differ')
        if row != answer:
            mismatches.append(identity.decode('ascii'))
    return mismatches


def build(binary, rustc, output, controls=False):
    output = Path(output)
    need(not output.exists(), 'Output directory must be new; previous evidence is preserved')
    expected = reference.oracle(Path(binary), repo=ROOT)
    verify_fixture(expected)
    rustc = Path(rustc).absolute()
    compiler_before = file_digest(rustc)
    need(compiler_before == COMPILER_SHA256, 'Research compiler differs from authenticated1.94.1 executable')
    linker = shutil.which('cc')
    need(linker is not None, 'C linker driver cc is required')
    linker_before = file_digest(linker)
    paths = tuple(sorted(COMPONENT.glob('*'))) + (
        Path(__file__), Path(reference.__file__), ADAPTER, MUTATIONS,
        ROOT/'tools/bincode_diagnostic_field_static.py',
        ROOT/'tools/bincode_diagnostic_adapter_static.py')
    source_before = {str(p.relative_to(ROOT)): file_digest(p) for p in paths if p.is_file()}
    output.mkdir(parents=True, exist_ok=False)
    (output/'oracle.json').write_text(json.dumps(expected['metadata'], indent=2)+'\n')
    (output/'inputs.txt').write_bytes(expected['inputs'])
    (output/'expected.txt').write_bytes(expected['expected'])
    (output/'comparison-main.rs').write_text(HARNESS.replace('__DRIVER__', str(DRIVER)))
    calls = []
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def execute(label, argv, required_exit=0):
        start = time.monotonic()
        process = subprocess.run([str(a) for a in argv], cwd=ROOT, env=environment,
                                 stdin=subprocess.DEVNULL, capture_output=True)
        logs = {}
        for kind, raw in (('stdout', process.stdout), ('stderr', process.stderr)):
            path = output/(label+'.'+kind)
            path.write_bytes(raw)
            logs[kind] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [str(a) for a in argv],
                      'exit_code': process.returncode,
                      'seconds': round(time.monotonic()-start, 3), 'logs': logs})
        (output/'CALLS.json').write_text(json.dumps(calls, indent=2)+'\n')
        if required_exit is not None:
            need(process.returncode == required_exit, label+' failed; exact raw outputs retained')
        return process

    try:
        version = execute('rustc-identity', [rustc, '-vV']).stdout.decode()
        need(version.startswith('rustc 1.94.1 ') and
             'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'Actual research compiler full identity differs')
        linker_version = execute('linker-identity', [linker, '--version']).stdout.decode()

        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1',
                    '-C', f'opt-level={opt}', '-C', 'overflow-checks=on',
                    '-C', 'linker='+linker,
                    '--remap-path-prefix', str(ROOT)+'=/reconstruction']

        def adapter(label, opt, directory):
            directory.mkdir(parents=True, exist_ok=False)
            path = directory/('lib'+ADAPTER_CRATE+'.rlib')
            execute(label, [rustc, '--crate-name', ADAPTER_CRATE, '--crate-type=rlib',
                            ADAPTER, '-o', path, '-C', 'metadata=node94-newline-protocol', *flags(opt)])
            return path

        def library(label, source, opt, directory, dependency):
            directory.mkdir(parents=True, exist_ok=False)
            path = directory/('lib'+CRATE+'.rlib')
            execute(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', source,
                            '--extern', ADAPTER_CRATE+'='+str(dependency),
                            '-L', 'dependency='+str(dependency.parent), '-o', path,
                            '-C', 'metadata=node94-field-protocol', *flags(opt)])
            return path

        def client_args(path, dependency):
            return ['--extern', CRATE+'='+str(path),
                    '-L', 'dependency='+str(path.parent),
                    '-L', 'dependency='+str(dependency.parent)]

        def tests(label, source, path, dependency, opt, directory, count, failure=False):
            program = directory/(label+'-tests')
            execute(label+'-build', [rustc, '--crate-name', label.replace('-', '_'),
                    '--test', source, *client_args(path, dependency), '-o', program, *flags(opt)])
            process = execute(label+'-run', [program, '--nocapture', '--test-threads=1'],
                              required_exit=101 if failure else 0)
            combined = process.stdout+process.stderr
            if failure:
                need(b'FAILED' in combined and b'panicked at' in combined,
                     label+' did not retain an actual semantic test failure')
            else:
                need(f'{count} passed; 0 failed; 0 ignored'.encode() in combined,
                     label+' did not execute the required ordinary Rust tests')
            return {'program': str(program), 'actual_tests': count,
                    'expected_exit': 101 if failure else 0}

        def production(label, path, dependency, opt, directory):
            program = directory/'production'
            execute(label+'-link', [rustc, '--crate-name', 'field_comparison',
                    output/'comparison-main.rs', *client_args(path, dependency),
                    '-o', program, *flags(opt)])
            actual = execute(label+'-run', [program, output/'inputs.txt']).stdout
            return program, actual

        profiles = []
        dependencies = {}
        for name, opt in (('debug', 0), ('optimized', 3)):
            directory = output/name
            dependency = adapter(name+'-adapter', opt, directory/'adapter')
            path = library(name+'-library', SOURCE, opt, directory/'parent', dependency)
            independent = tests(name+'-independent', INDEPENDENT, path, dependency,
                                opt, directory, 12)
            fixture = tests(name+'-fixture', FIXTURE_TEST, path, dependency,
                            opt, directory, 1)
            program, actual = production(name+'-production', path, dependency, opt, directory)
            need(not compare(actual, expected['expected']), name+' transcript differs from fresh native contracts')
            events = [event for row in actual.decode('ascii').splitlines()
                      for event in row.split(';X=', 1)[1].split(',')]
            writer_calls = sum(event.startswith('w:') for event in events)
            value_calls = sum(event.startswith('g:') for event in events)
            need(writer_calls == expected['metadata']['expected_writer_calls'] and
                 value_calls == expected['metadata']['expected_value_calls'],
                 'Actual callback transcript counts differ')
            dependencies[name] = dependency
            profiles.append({'name': name, 'opt_level': opt,
                             'independent_tests': independent, 'fixture_tests': fixture,
                             'production': str(program), 'production_cases': len(expected['cases']),
                             'actual_writer_calls': writer_calls, 'actual_value_calls': value_calls,
                             'matched': True, 'actual_sha256': sha(actual),
                             'expected_sha256': sha(expected['expected']),
                             'library_sha256': file_digest(path),
                             'adapter_sha256': file_digest(dependency)})
        rebuilds = []
        for name in ('repro-a', 'repro-b'):
            directory = output/name
            dependency = adapter(name+'-adapter', 3, directory/'adapter')
            path = library(name+'-library', SOURCE, 3, directory/'parent', dependency)
            rebuilds.append((path, dependency))
        repro = {}
        for index, label in ((0, 'parent'), (1, 'adapter')):
            a, b = rebuilds[0][index], rebuilds[1][index]
            repro[label] = {'a_bytes': a.stat().st_size, 'b_bytes': b.stat().st_size,
                            'a_sha256': file_digest(a), 'b_sha256': file_digest(b),
                            'raw_equal': a.read_bytes() == b.read_bytes(), 'normalization': 'none'}
            need(repro[label]['raw_equal'], 'Own '+label+' rebuilds differ')
        mutants = []
        if controls:
            design = json.loads(MUTATIONS.read_text())
            source = SOURCE.read_text()
            need(sha(source.encode()) == design['core_sha256'] and
                 file_digest(reference.__file__) == design['independent_reference_sha256'],
                 'Mutation design source/reference binding differs')
            need(len(design['controls']) == 9 and
                 len({row['name'] for row in design['controls']}) == 9,
                 'Expected nine distinct semantic controls')
            for item in design['controls']:
                name = item['name']
                need(source.count(item['needle']) == item['expected_occurrences'] == 1,
                     name+' mutation no longer uniquely matches source')
                directory = output/('mutant-'+name)
                directory.mkdir()
                altered = directory/'lib.rs'
                altered.write_text(source.replace(item['needle'], item['replacement']))
                dependency = dependencies['debug']
                path = library('mutant-'+name+'-library', altered, 0, directory/'parent', dependency)
                _, actual = production('mutant-'+name+'-production', path, dependency, 0, directory)
                mismatches = compare(actual, expected['expected'])
                need(item['witness_stimulus_id'] in mismatches,
                     name+' did not fail its independently selected semantic witness')
                independent = tests('mutant-'+name+'-independent', INDEPENDENT, path,
                                    dependency, 0, directory, 12, failure=True)
                fixture = tests('mutant-'+name+'-fixture', FIXTURE_TEST, path,
                                dependency, 0, directory, 1, failure=True)
                mutants.append({'name': name, 'relation': item['relation'],
                                'mutated_source_sha256': file_digest(altered),
                                'production_exit': 0, 'different_transcripts': len(mismatches),
                                'witness_stimulus_id': item['witness_stimulus_id'],
                                'witness_failed': True, 'independent_tests': independent,
                                'fixture_tests': fixture})
        source_after = {str(p.relative_to(ROOT)): file_digest(p) for p in paths if p.is_file()}
        need(source_after == source_before and file_digest(rustc) == compiler_before
             and file_digest(linker) == linker_before, 'Source/compiler/linker bytes changed')
        result = {'status': 'PASS', 'compiler': {'path': str(rustc), 'sha256': compiler_before,
                  'identity': version, 'meaning': 'Repo research toolchain; not recovered original node compiler'},
                  'linker': {'path': linker, 'sha256': linker_before, 'identity': linker_version},
                  'oracle': expected['metadata'], 'source_before': source_before,
                  'source_after': source_after, 'profiles': profiles,
                  'own_reproducibility': repro, 'semantic_mutants': mutants, 'calls': calls,
                  'limits': ['Only newly authored Rust executes; no captured target execution.',
                             'Production reads input stimuli only; no filesystem sandbox claim.',
                             'Supplied real W/G proxies implement a qualified logical callback contract, not value formatting.',
                             'Safe references, immutable name and separated/preserved roles narrow the native domain.',
                             'No original ABI, physical rendering/store trace, original compiler, byte match or gate claim.']}
        (output/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error': str(error), 'calls': calls,
            'source_before': source_before}, indent=2)+'\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = build(args.binary, args.rustc, args.output, args.controls)
    print(json.dumps({'status': result['status'], 'cases': result['oracle']['case_count'],
                      'commands': len(result['calls']), 'mutants': len(result['semantic_mutants'])}))


if __name__ == '__main__':
    main()
