"""Abstract grouped arithmetic oracle for the proved capacity20 contract.

No Rust/expected fixture is read to calculate an answer. These are the proved
numeric quotient/pair relations, not PC/register/opcode or memory execution.
"""
import hashlib
from pathlib import Path

import integer_digit_span_static as native

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT/'src/node94-integer-digit-span/target-inputs.txt'
INPUTS_SHA256 = '612aa39a2621b6b5d6b6e6a7cb240e89c0362bc6ba071e1f4cfebbc0788cd5f3'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def numeric_relation(value, initial, parameters, pairs):
    """Use only the all-u64 mathematical decomposition proved by native data."""
    require(0 <= value < 1 << 64 and len(initial) == 20, 'Invalid chosen numeric input')
    original = value
    groups = []
    while value >= parameters['group_threshold']:
        quotient = (value*parameters['division_magic']) >> parameters['division_shift']
        remainder = value-parameters['chunk_divisor']*quotient
        high = (remainder*parameters['pair_magic']) >> parameters['pair_shift']
        low = remainder-100*high
        require(0 <= high < 100 and 0 <= low < 100, 'Proved pair range changed')
        groups.append(pairs[2*high:2*high+2]+pairs[2*low:2*low+2])
        value = quotient
    if value >= 10:
        high = ((value >> parameters['tail_quarter_shift'])*parameters['tail_pair_magic']) >> parameters['tail_pair_shift']
        low = value-100*high
        tail = (pairs[2*high+1:2*high+2] if high else b'')+pairs[2*low:2*low+2]
    elif value or original == 0:
        tail = pairs[2*value+1:2*value+2]
    else:
        tail = b''
    digits = tail+b''.join(reversed(groups))
    require(1 <= len(digits) <= 20, 'Proved decimal length changed')
    start = 20-len(digits)
    return start, initial[:start]+digits


def oracle(binary, repo=ROOT):
    repo = Path(repo)
    # One immutable admission supplies all metadata, raw native and table facts.
    data = Path(binary).read_bytes()
    proof = native.analyze(data)
    parameters = proof['primary']['parameters']
    pairs = bytes.fromhex(proof['metadata']['tables']['pairs']['raw'])
    inputs = (repo/'src/node94-integer-digit-span/target-inputs.txt').read_bytes()
    require(sha(inputs) == INPUTS_SHA256, 'Independent frozen input identity changed')
    rows, cases = [], []
    for line in inputs.decode('ascii').splitlines():
        fields = line.split(' ')
        require(len(fields) == 3, 'Expected three input-only tokens')
        ident, number, initial_hex = fields
        require(ident and ident.isalnum() and len(number) == 16 and len(initial_hex) == 40,
                'Malformed canonical stimulus')
        require(all(c in '0123456789abcdef' for c in number+initial_hex), 'Expected lowercase hex')
        start, result = numeric_relation(int(number, 16), bytes.fromhex(initial_hex), parameters, pairs)
        rows.append(f'{ident} {start} {result.hex()}')
        cases.append({'id': ident, 'start': start})
    require(len(cases) == 1697 and len({r['id'] for r in cases}) == 1697,
            'Independent1697-stimulus domain changed')
    expected = ('\n'.join(rows)+'\n').encode('ascii')
    fixture = b''.join(g+b'\t'+e+b'\n' for g, e in zip(inputs.splitlines(), expected.splitlines()))
    metadata = {'target_sha256': native.SHA256, 'primary_range': proof['primary']['range'],
                'primary_bytes': 444, 'case_count': len(cases), 'input_sha256': sha(inputs),
                'expected_sha256': sha(expected), 'fixture_sha256': sha(fixture),
                'source': 'Fresh authenticated native proof parameters/pair table plus independent frozen input stimuli',
                'no_PC_register_or_opcode_execution': True, 'no_production_Rust_or_answers_read': True,
                'context_selector_is_not_Rust_coverage': True}
    return {'inputs': inputs, 'expected': expected, 'fixture': fixture, 'cases': cases,
            'metadata': metadata, 'native_proof': proof}
