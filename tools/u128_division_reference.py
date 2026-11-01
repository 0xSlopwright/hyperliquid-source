"""Pure independent native-branch mathematical oracle, authored before Rust.

No filesystem, provider, client, compiler or fixture side effects.
"""

B = 1 << 64

MASK = B - 1

MAX = (1 << 128) - 1

def need(condition, message):
    if not condition:
        raise ValueError(message)

def oracle(n, d):
    need(0 <= n <= MAX and 0 < d <= MAX, 'Outside nonzero u128 contract')
    a, b, l, h = n & MASK, n >> 64, d & MASK, d >> 64
    detail = {}
    if h == 0:
        if b < l:
            q = n // l
            need(q < B, 'Unsafe single64 quotient')
            detail = {'path': 'single64', 'ret': '0x565f631'}
        else:
            small = (b | l) < (1 << 32)
            high, remainder = divmod(b, l)
            need(high < (1 << 32 if small else B) and remainder < l, 'Unsafe first digit DIV')
            low = (remainder * B + a) // l
            need(low < B, 'Unsafe second digit DIV')
            q = high * B + low
            detail = {'path': 'digits32_64' if small else 'digits64_64', 'ret': '0x565f665' if small else '0x565f652', 'first_high_quotient': high}
    else:
        s = h.bit_length() - 1
        e = s + 1
        # This explicit endpoint is required by TEST AL,64 + CMOVE after
        # x86's six-bit shift-count masking, not a shift-by64 language rule.
        normal = h if e == 64 else (l >> e) | (h << (64 - e))
        need((1 << 63) <= normal < B and normal == d >> e, 'Wrong normalized divisor')
        need((b >> 1) < normal, 'Unsafe normalized hardware DIV high word')
        digit = (n // 2) // normal
        need(digit < B, 'Normalized hardware DIV quotient does not fit')
        estimate = digit >> s
        truncated_divisor = normal << e
        delta = d - truncated_divisor
        need(0 <= delta < (1 << e), 'Wrong truncated divisor residue')
        predecessor = max(estimate - 1, 0)
        product = predecessor * d
        need(product <= n and product <= MAX, 'Product overflow/underflow premise failed')
        low_product = l * predecessor
        low = low_product & MASK
        high = ((low_product >> 64) + ((h * predecessor) & MASK)) & MASK
        need(low + B * high == product, 'Native MUL/IMUL reconstruction differs')
        remainder = n - product
        low_borrow = int(a < low)
        low_remainder = (a - low) & MASK
        high_remainder = (b - high - low_borrow) & MASK
        need(low_remainder + B * high_remainder == remainder, 'SUB/SBB product residue differs')
        comparison_low_borrow = int(low_remainder < l)
        carry = int(high_remainder < h + comparison_low_borrow)
        need(carry == int(remainder < d), 'CMP/SBB pair comparison differs')
        q = predecessor + 1 - carry
        need(q < B, 'Corrected high-divisor quotient overflow')
        need(estimate in (q, q + 1) and predecessor <= q <= predecessor + 1, 'Estimate-error theorem violated')
        detail = {'path': 'normalized', 'ret': '0x565f61d', 's': s, 'e': e, 'estimate_error': estimate - q, 'correction': q - predecessor, 'product_low_borrow': low_borrow, 'comparison_low_borrow': comparison_low_borrow, 'delta_zero': delta == 0}
    expected, remainder = divmod(n, d)
    need(q == expected and n == q * d + remainder and 0 <= remainder < d, 'Independent bigint disagreement')
    return q, detail


# Later preparation wrapper. The exact independently frozen pure core above
# predates all new Rust; this wrapper does not change its native equations.
from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA256 = '6d911dd88abcef6e6190b6ec040947d89778a2cd54fb0c6822ab0c5cf8ed6d8b'


def serialize_inputs(stimulus):
    """Pure native-equation model only; this alone does not admit target origin."""
    need(type(stimulus) is bytes and stimulus.endswith(b'\n'), 'Canonical stimulus bytes required')
    lines = stimulus.decode('ascii').splitlines()
    seen, outputs, fixture, cases = set(), [], ['id\tdividend_hex\tdivisor_hex\tquotient_hex'], []
    for line in lines:
        fields = line.split('|')
        need(len(fields) == 3 and re.fullmatch(r'[A-Za-z0-9_]+', fields[0]) is not None,
             'Invalid stimulus fields')
        identifier, numerator, divisor = fields
        need(identifier not in seen, 'Duplicate primary stimulus identifier')
        seen.add(identifier)
        need(all(re.fullmatch('[0-9a-f]{32}', value) for value in (numerator, divisor)),
             'Canonical128-bit lowercase hexadecimal required')
        n, d = int(numerator, 16), int(divisor, 16)
        q, detail = oracle(n, d)
        outputs.append(f'{identifier}|{q:032x}')
        fixture.append(f'{identifier}\t{numerator}\t{divisor}\t{q:032x}')
        cases.append({'id': identifier, 'dividend': n, 'divisor': d, 'quotient': q, 'native_detail': detail})
    need(cases, 'Nonempty primary corpus required')
    return {'inputs': stimulus, 'expected': ('\n'.join(outputs) + '\n').encode('ascii'),
            'fixture': ('\n'.join(fixture) + '\n').encode('ascii'), 'cases': cases,
            'origin': 'UNQUALIFIED_MODEL_ONLY'}


def fresh(binary):
    """Admit one immutable target before deriving any expected quotient."""
    from u128_division_contract import inspect, load_target
    native = inspect(load_target(binary))
    source = ROOT / 'src/node94-u128-division'
    stimulus = (source / 'target-inputs.txt').read_bytes()
    need(hashlib.sha256(stimulus).hexdigest() == INPUT_SHA256, 'Frozen primary inputs differ')
    result = serialize_inputs(stimulus)
    need(len(result['cases']) == 7587, 'Primary count differs')
    need(result['expected'] == (source / 'target-expected.txt').read_bytes(),
         'Stored expected rows differ from fresh native equations')
    need(result['fixture'] == (source / 'target-vectors.tsv').read_bytes(),
         'Stored Rust fixture differs from fresh native equations')
    result.update(origin='ACTUAL_NATIVE_CONTRACT_ADMITTED', native_proof=native,
                  metadata={'case_count': len(result['cases']),
                            'method': 'Independently frozen native branch/digit/estimate/borrow equations, crosschecked by exact divmod',
                            'zero_input': 'Outside NonZeroU128 contract; no native fault parity',
                            'Rust_output_read_for_expectations': False})
    return result
