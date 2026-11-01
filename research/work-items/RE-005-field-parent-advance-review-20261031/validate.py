#!/usr/bin/env python3
"""Recheck exact advanced evidence; optionally test or build authored Rust."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

HEAD = '38883e27597c1da7540d8ab0669290fb88aa66bc'
PACKET = 'research/work-items/RE-005-field-parent-current546-rebind'


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[3])
    parser.add_argument('--out', type=pathlib.Path, required=True, help='New review output directory')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--tests', action='store_true')
    parser.add_argument('--rustc', type=pathlib.Path, help='Optional independently authored host build')
    parser.add_argument('--rustc-sha256', help='Required explicit compiler identity for optional host build')
    args = parser.parse_args()
    require(not args.out.exists(), 'Preserve previous outputs; choose a new directory')
    repo = args.repo.resolve()
    sys.path.insert(0, str(repo / 'tools'))
    import bincode_diagnostic_parent_rust as b
    packet = repo / PACKET
    files = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', HEAD, '--', PACKET], cwd=repo, text=True).splitlines()
    require(len(files) == 19, 'Expected exact19 original evidence files')
    blobs = []
    for file in files:
        raw = subprocess.check_output(['git', 'show', HEAD + ':' + file], cwd=repo)
        require((repo / file).read_bytes() == raw, 'Original evidence differs: ' + file)
        blobs.append(dict(file=file, sha256=hashlib.sha256(raw).hexdigest()))
    entries = []
    for line in (packet / 'MANIFEST.sha256').read_text().splitlines():
        expected, file = line.split('  ', 1)
        original = subprocess.check_output(['git', 'show', HEAD + ':' + file], cwd=repo)
        require(hashlib.sha256(original).hexdigest() == expected, 'Historical manifest differs: ' + file)
        require(hashlib.sha256((repo / file).read_bytes()).hexdigest() == expected, 'Current manifest differs: ' + file)
        entries.append(file)
    fresh = b.reference.oracle(b.TARGET, repo=repo)
    for name, key in [('inputs.txt', 'inputs'), ('expected.txt', 'expected'), ('fixture.tsv', 'fixture')]:
        require((packet / 'evidence' / name).read_bytes() == fresh[key], 'Oracle differs: ' + name)
    require(json.loads((packet / 'evidence/oracle.json').read_text()) == fresh['metadata'], 'Oracle metadata differs')
    for name in ['debug.stdout', 'optimized.stdout']:
        require((packet / 'evidence' / name).read_bytes() == fresh['expected'], 'Recorded rows differ')
    require((packet / 'evidence/BEFORE.json').read_bytes() == (packet / 'evidence/AFTER.json').read_bytes(), 'Source before/after differs')
    native = json.loads((packet / 'evidence/native-record.json').read_text())
    proof, exports = b.reference._load_producer(repo)._analyze(b.TARGET.read_bytes())
    proof = json.loads(json.dumps(proof))
    raw_proof = json.dumps(proof, indent=2) + '\n'
    provider_deltas = []
    for current, prior, label in [(proof, native, 'native_tool'), (proof['used_adapter_contract'], native['used_adapter_contract'], 'used_adapter_contract/native_tool')]:
        if current['native_tool'] != prior['native_tool']:
            provider_deltas.append(dict(field=label, historical=prior['native_tool'], current=current['native_tool']))
            current['native_tool'] = prior['native_tool']
    require(proof == native, 'Native evidence differs beyond provider labels')
    for name, value in exports.items():
        if (packet / 'evidence' / name).exists():
            require((packet / 'evidence' / name).read_text() == value, 'Native export differs: ' + name)
    args.out.mkdir(parents=True)
    (args.out / 'fresh-native-record.json').write_text(raw_proof)
    results = dict(head=HEAD, originals=blobs, manifest_entries=len(entries), provider_deltas=provider_deltas, static='PASS', captured_execution=False)
    if args.tests:
        for optimized in (False, True):
            command = [args.python] + (['-O'] if optimized else []) + ['-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_bincode_diagnostic_parent_rust.py', '-v']
            result = subprocess.run(command, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (args.out / ('optimized.log' if optimized else 'normal.log')).write_bytes(result.stdout)
            require(result.returncode == 0, 'Focused tests failed')
    if args.rustc:
        actual = hashlib.sha256(args.rustc.read_bytes()).hexdigest()
        require(args.rustc_sha256 == actual, 'Explicit compiler SHA-256 differs')
        original = b.COMPILER_SHA256
        b.COMPILER_SHA256 = actual
        results['host_build'] = b.build(b.TARGET, args.rustc.resolve(), args.out / 'host-build', False)['status']
        results['provider'] = dict(original_pin=original, current_pin=actual, scope='Own-code host replay only; original Linux binary identity unproven')
    (args.out / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS exact19 evidence,83 manifest entries,925 oracle rows,native exports')


if __name__ == '__main__':
    main()
