from pathlib import Path
import datetime
import hashlib
import json
import struct

BASE = Path('/tmp/hl-three-digit-rust-intake-20261101')
NATIVE = BASE / 'native-admission-1'
OUT = BASE / 'pre-Rust-oracle'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

assert not OUT.exists()
admission = json.loads((NATIVE / 'ADMISSION.json').read_text())
body = (NATIVE / 'primary.bin').read_bytes()
assert len(body) == 85 and sha(body) == '90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca'
assert admission['target_sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
assert body[0:4] == bytes.fromhex('4883fe03')
assert body[22:25] == bytes.fromhex('8d71c6')
assert body[25:33] == bytes.fromhex('4080fef7400f92c6')
assert body[66:69] == bytes.fromhex('6bc964')
assert body[72:80] == bytes.fromhex('01c08d04800fb6c0')
parameters = {'length': body[3], 'first_gate_bias': struct.unpack('b', body[24:25])[0],
              'first_gate_threshold': body[28], 'byte_bias': body[14],
              'tail_gate_threshold': body[34], 'hundreds': body[68],
              'tens_double': 2, 'tens_lea_scale': 1 << (body[76] >> 6),
              'tens_post_width': 8}
assert body[14] == body[21] == body[62] == 208
assert body[34] == body[41] == 10
assert body[4] == 0x75 and 6 + struct.unpack('b', body[5:6])[0] == 54
assert body[52] == 0x74 and 54 + struct.unpack('b', body[53:54])[0] == 57

def relation(raw):
    """Closed scalar predicate/payload equation; no PC/register/instruction model."""
    if len(raw) != parameters['length']:
        return 0
    first, middle, last = raw
    gate0 = ((first + parameters['first_gate_bias']) & 255) < parameters['first_gate_threshold']
    mid = (middle + parameters['byte_bias']) & 255
    tail = (last + parameters['byte_bias']) & 255
    if gate0 or mid >= parameters['tail_gate_threshold'] or tail >= parameters['tail_gate_threshold']:
        return 0
    head = (first + parameters['byte_bias']) & 255
    tens = (mid * parameters['tens_double'] * (1 + parameters['tens_lea_scale'])) & 255
    return head * parameters['hundreds'] + tens + tail

class_support = []
for position in range(3):
    accepted = []
    for value in range(256):
        gate = (((value + parameters['first_gate_bias']) & 255) >= parameters['first_gate_threshold']
                if position == 0 else ((value + parameters['byte_bias']) & 255) < parameters['tail_gate_threshold'])
        conventional = (49 <= value <= 57) if position == 0 else (48 <= value <= 57)
        assert gate == conventional
        if gate:
            accepted.append(value)
    class_support.append({'position': position, 'all_byte_values_checked': 256, 'accepted': accepted})

raw_cases = {}
for value in range(100, 1000):
    raw = str(value).encode('ascii')
    assert relation(raw) == value
    raw_cases[raw] = 'all900_valid_values'
anchor = bytearray(b'581')
for position in range(3):
    for value in range(256):
        raw = anchor.copy(); raw[position] = value; raw = bytes(raw)
        if relation(raw) == 0:
            assert raw not in raw_cases
            raw_cases[raw] = 'single_invalid_byte_position_' + str(position)
assert len(raw_cases) == 900 + 739
for raw in [b'', b'1', b'12', b'1234', b'100\0', b'999x', b'0123', b'\x00123',
            b'12345', b'1' * 16, b'9' * 255, bytes(range(256)), b'1' * 4096,
            b'\0' * 3, b'\xff' * 3, b'\x80' * 3, b'000', b'0:0', b'/\x00\xff',
            b':\x80/', b'\xff9\x00', b'00x', b'99\xff', b'  1']:
    raw_cases.setdefault(raw, 'additional_length_or_multi_invalid_boundary')

ordered = sorted(raw_cases, key=lambda raw: hashlib.sha256(b'node94-three-byte-before-Rust-v1\0' + raw).digest())
stimuli = []; expected = []; input_rows = []; expected_rows = []
for raw in ordered:
    identifier = 'c' + sha(b'node94-parser-stimulus-id-v1\0' + raw)[:12]
    value = relation(raw)
    stimuli.append({'id': identifier, 'bytes_hex': raw.hex(), 'length': len(raw)})
    expected.append({'id': identifier, 'return_u16': value, 'classification': raw_cases[raw]})
    token = raw.hex() or '-'
    input_rows.append(identifier + ' ' + token)
    expected_rows.append(identifier + ' ' + str(value))
assert len({x['id'] for x in stimuli}) == len(stimuli)
assert sum(x['return_u16'] != 0 for x in expected) == 900
inputs = ('\n'.join(input_rows) + '\n').encode()
answers = ('\n'.join(expected_rows) + '\n').encode()
fixture = b''.join(a + b'\t' + b + b'\n' for a, b in zip(inputs.splitlines(), answers.splitlines()))
OUT.mkdir(mode=0o700)
for name, raw in [('target-inputs.txt', inputs), ('target-expected.txt', answers), ('target-vectors.tsv', fixture)]:
    (OUT / name).write_bytes(raw)
for name, value in [('STIMULI.json', stimuli), ('EXPECTED.json', expected), ('BYTE-PREDICATES.json', class_support)]:
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
files = [{'file': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
         for p in sorted(OUT.iterdir()) if p.is_file()]
freeze = {'schema': 'three-digit-native-equation-before-Rust-oracle-v1',
          'status': 'FROZEN_BEFORE_ANY_NEW_RUST_SOURCE', 'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'generator': {'path': str(Path(__file__)), 'sha256': sha(Path(__file__).read_bytes())},
          'native_admission_sha256': sha((NATIVE / 'ADMISSION.json').read_bytes()),
          'target_sha256': admission['target_sha256'], 'primary_sha256': sha(body),
          'decoded_parameters': parameters, 'files': files, 'case_count': len(stimuli),
          'valid_distinct_triples': 900, 'single_invalid_byte_distinct_triples': 739,
          'additional_boundary_cases': len(stimuli) - 1639,
          'complete_byte_predicate_checks': 3 * 256,
          'proof_cardinality': '9*10*10=900 accepted length3 byte triples; all other triples return0 by the composed OR predicate.',
          'runtime_protocol': 'id bytes_hex_or_dash -> id decimal_return. Input-only file contains no expected value or role/classification field.',
          'source_separation': 'Generator was authored from actual admitted raw predicates/closed arithmetic; no new production Rust exists or was read. It does not read inferred/reference or official library implementation.',
          'no_instruction_evaluator_or_target_execution': True,
          'not_claimed': ['16M target executions', 'Original Rust symbol/ABI/type/compiler identity', 'Full caller or node behavior', 'Machine-byte match or progress gate']}
(OUT / 'ORACLE-FREEZE.json').write_text(json.dumps(freeze, indent=2, sort_keys=True) + '\n')
print(json.dumps({'cases': len(stimuli), 'valid': 900, 'single_invalid': 739,
                  'other_boundaries': len(stimuli) - 1639,
                  'oracle_freeze_sha256': sha((OUT / 'ORACLE-FREEZE.json').read_bytes())}))
