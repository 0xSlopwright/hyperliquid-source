"""Pre-Rust closed scalar/byte oracle; not a machine/instruction evaluator."""
from pathlib import Path
import datetime
import hashlib
import json

ROOT = Path('/tmp/hl-re005-next-codec-intake-20261101')
OUT = ROOT / 'pre-Rust-oracle'
assert not OUT.exists()
sha = lambda data: hashlib.sha256(data).hexdigest()
admission = ROOT / 'authenticated-native/ADMISSION.json'
assert sha(admission.read_bytes()) == '682850d3c89dcbbe73059b3643bba0d19c0f3e45efdf9026b642964f467405d0'
table = (ROOT / 'authenticated-native/digit-table.bin').read_bytes()
assert len(table) == 16
assert table == bytes(48 + n if n < 10 else 97 + n - 10 for n in range(16))

# Separate, exhaustive byte-level support uses the authenticated table and
# actual nibble widths, and compares against Python's independent hex codec.
byte_checks = []
for value in range(256):
    full = bytes((table[value // 16], table[value % 16]))
    assert full == bytes((value,)).hex().encode('ascii')
    for trim in (False, True):
        delta = int(trim and value < 16)
        payload = full[delta:]
        byte_checks.append({'value': value, 'mode': int(trim),
                            'delta': delta, 'payload_hex': payload.hex()})
assert len(byte_checks) == 512


def initial(seed, size):
    return bytes((seed + 73 * i + i // 3) & 255 for i in range(size))


def expectation(raw, mode, before):
    # This is the explicitly chosen safe API's relation and policy, separate
    # from the native panic paths. No target helper/interpreter is called.
    if not raw or len(before) < 2 * len(raw) + 2:
        return {'status': 'unsupported', 'length': 0, 'after_hex': before.hex()}
    encoded = b'0x' + raw.hex().encode('ascii')
    if mode and raw[0] < 16:
        encoded = encoded[:2] + encoded[3:]
    assert len(encoded) == 2 * len(raw) + 2 - int(mode and raw[0] < 16)
    return {'status': 'ok', 'length': len(encoded),
            'after_hex': (encoded + before[len(encoded):]).hex()}


cases = []
seen = set()


def add(group, raw, mode, capacity=None, seed=0xa7):
    if capacity is None:
        capacity = 2 * len(raw) + 7
    before = initial(seed, capacity)
    identity = bytes((mode,)) + len(raw).to_bytes(8, 'little') + raw + before
    if identity in seen:
        return
    seen.add(identity)
    expected = expectation(raw, mode, before)
    cases.append({'id': 'h' + sha(identity)[:18], 'group': group,
                  'mode': mode, 'input_hex': raw.hex(),
                  'initial_output_hex': before.hex(), 'expected': expected})


for value in range(256):
    for mode in (0, 1):
        add('all256-single-byte-both-modes', bytes((value,)), mode)
        add('two-byte-split-exit', bytes((value, 255 - value)), mode)
        add('three-byte-loop-entry', bytes((value, value ^ 0xa5, value * 73 & 255)), mode)

for n in range(1, 129):
    raw = bytes((n * 19 + 37 * i) & 255 for i in range(n))
    for mode in (0, 1):
        add('finite-length-sweep-1-through128', raw, mode,
            capacity=2 * n + 2 + (n % 7), seed=n)

for n in (20, 32):
    for position in range(n):
        for boundary in (0, 1, 15, 16, 127, 128, 254, 255):
            raw = bytearray((0x60 + 29 * i) & 255 for i in range(n))
            raw[position] = boundary
            for mode in (0, 1):
                add('real-caller-length-position-boundaries', bytes(raw), mode,
                    capacity=2 * n + 2 + position % 5, seed=position + 9)

# Explicit safe-policy checks. Even a trimmed result that would fit into
# 2*n+1 bytes must be refused because the native entry requires 2*n+2.
for n in (1, 2, 3, 20, 32):
    raw = bytes((i * 17) & 255 for i in range(n))
    for mode in (0, 1):
        for cap in (0, 2 * n + 1):
            add('separate-safe-API-short-capacity-policy', raw, mode, cap)
        add('exact-untrimmed-capacity-required', raw, mode, 2 * n + 2)
for mode in (0, 1):
    for cap in (0, 1, 2, 3, 7):
        add('separate-safe-API-empty-policy', b'', mode, cap)

cases.sort(key=lambda c: c['id'])
assert len({c['id'] for c in cases}) == len(cases)
qualified = [c for c in cases if c['expected']['status'] == 'ok']
policy = [c for c in cases if c['expected']['status'] != 'ok']
assert all(c['input_hex'] and len(c['initial_output_hex']) // 2 >= len(c['input_hex']) + 2 for c in qualified)
inputs = ''.join(c['id'] + ' ' + str(c['mode']) + ' ' + (c['input_hex'] or '-') + ' ' +
                 (c['initial_output_hex'] or '-') + '\n' for c in cases)
expected = ''.join(c['id'] + ' ' + c['expected']['status'] + ' ' + str(c['expected']['length']) + ' ' +
                   (c['expected']['after_hex'] or '-') + '\n' for c in cases)
vectors = ''.join(c['id'] + ' ' + str(c['mode']) + ' ' + (c['input_hex'] or '-') + ' ' +
                  (c['initial_output_hex'] or '-') + ' ' + c['expected']['status'] + ' ' +
                  str(c['expected']['length']) + ' ' + (c['expected']['after_hex'] or '-') + '\n' for c in cases)
OUT.mkdir(mode=0o700)
(OUT / 'INPUTS.txt').write_text(inputs, encoding='ascii')
(OUT / 'EXPECTED.txt').write_text(expected, encoding='ascii')
(OUT / 'target-vectors.txt').write_text(vectors, encoding='ascii')
(OUT / 'CASES.json').write_text(json.dumps(cases, indent=2) + '\n')
(OUT / 'BYTE-CHECKS.json').write_text(json.dumps(byte_checks, indent=2) + '\n')
files = [p for p in OUT.iterdir() if p.is_file()]
record = {'schema': 'prefixed-hex-pre-Rust-oracle-freeze-v1',
          'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'chronology': 'Authored from independently authenticated native proof before any proposed Rust implementation; no production Rust or expected-answer consumer read/call.',
          'target_sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
          'admission_sha256': sha(admission.read_bytes()),
          'proof_sha256': sha((ROOT / 'PROOF-before-Rust.md').read_bytes()),
          'generator_sha256': sha(Path(__file__).read_bytes()),
          'oracle': 'Python byte.hex scalar specification plus first-digit omission; independent table/math byte checks; not captured execution, interpreter or instruction emulator.',
          'fixture_records': len(cases), 'qualified_normal_records': len(qualified),
          'separate_safe_API_policy_records': len(policy), 'byte_primitive_checks': len(byte_checks),
          'group_counts': {g: sum(c['group'] == g for c in cases) for g in sorted({c['group'] for c in cases})},
          'exact_input_protocol': 'id mode0or1 input_hex_or_dash initial_output_hex_or_dash; no expected fields',
          'exact_output_protocol': 'id ok|unsupported decimal_length complete_output_hex_or_dash; input order/identity preserved',
          'files': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in files},
          'limits': 'Finite fixture supports the separate complete static normal-domain argument, not exhaustive multi-byte/caller/runtime equivalence. Short/empty refusals are safe-API policy only. No program/compiler/emulator/target execution.'}
(OUT / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': 'FROZEN', 'fixture_records': len(cases),
                  'qualified_normal_records': len(qualified),
                  'policy_records': len(policy),
                  'freeze_sha256': sha((OUT / 'ORACLE-FREEZE.json').read_bytes())}, indent=2))
