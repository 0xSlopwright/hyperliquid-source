"""Fixed native proof/data and independent-oracle controls; no code interpreter."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_division_contract as contract
import u128_division_reference as reference


class DivisionContractTests(unittest.TestCase):
    def test_complete_71_rows_and_actual_constants(self):
        rows = json.loads((contract.PACKET / 'native/rows.json').read_text())
        body = b''.join(bytes.fromhex(row['bytes_hex']) for row in rows)
        proof = contract.prove_body(body)
        self.assertEqual(proof['rows'], 71)
        self.assertEqual(proof['bytes'], 198)
        self.assertEqual(proof['constants']['word_bits'], 64)
        self.assertEqual(proof['constants']['small_digit_bits'], 32)
        self.assertEqual(proof['constants']['final_signed_immediate'], -1)
        self.assertEqual(len(proof['returns']), 4)

    def test_immediates_borrow_and_return_cannot_be_changed(self):
        rows = json.loads((contract.PACKET / 'native/rows.json').read_text())
        original = b''.join(bytes.fromhex(row['bytes_hex']) for row in rows)
        for offset in (0x12, 0x14, 0x2a, 0x36, 0x4e, 0x78, 0x9b, 0xc5):
            body = bytearray(original)
            body[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'encoding differs'):
                contract.prove_body(bytes(body))

    def test_short_or_mutable_input_never_admits_target(self):
        for data in (bytes(198), bytearray(198)):
            with self.assertRaisesRegex(ValueError, 'Target identity'):
                contract.inspect(data)

    def test_all_frozen_inputs_rederive_exact_expected_and_unit_fixture(self):
        source = ROOT / 'src/node94-u128-division'
        result = reference.serialize_inputs((source / 'target-inputs.txt').read_bytes())
        self.assertEqual(result['origin'], 'UNQUALIFIED_MODEL_ONLY')
        self.assertEqual(len(result['cases']), 7587)
        self.assertEqual(result['expected'], (source / 'target-expected.txt').read_bytes())
        self.assertEqual(result['fixture'], (source / 'target-vectors.tsv').read_bytes())
        self.assertEqual(hashlib.sha256(result['expected']).hexdigest(),
                         '9f70dff8dd8faf22e46a7446acba59330bc2bf6918fc50463e25b15d6dcd58e4')

    def test_native_estimate_and_masked_shift_endpoints(self):
        for base, exponent in ((1 << 64, 1), (1 << 127, 64)):
            below, a = reference.oracle(base, base + 1)
            exact, b = reference.oracle(base + 1, base + 1)
            self.assertEqual((below, exact), (0, 1))
            self.assertEqual((a['e'], b['e']), (exponent, exponent))
            self.assertEqual((a['estimate_error'], b['estimate_error']), (1, 0))
            self.assertEqual((a['correction'], b['correction']), (0, 1))
        for numerator, divisor, path in ((0, 1, 'single64'),
                                         (1 << 64, 1, 'digits32_64'),
                                         (1 << 96, 1, 'digits64_64')):
            self.assertEqual(reference.oracle(numerator, divisor)[1]['path'], path)

    def test_zero_is_outside_the_numeric_model(self):
        with self.assertRaisesRegex(ValueError, 'nonzero'):
            reference.oracle(1, 0)
        with self.assertRaises(ValueError):
            reference.serialize_inputs(b'zero|' + b'0' * 32 + b'|' + b'0' * 32 + b'\n')

    def test_primary_stimulus_has_no_expected_output_field(self):
        row = b'case|' + b'0' * 31 + b'1|' + b'0' * 31 + b'1\n'
        for bad in (row.replace(b'\n', b'|answer\n'), row + row):
            with self.assertRaises(ValueError):
                reference.serialize_inputs(bad)

    def test_independent_pure_core_preserved_exactly(self):
        raw = (ROOT / 'tools/u128_division_reference.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw[:3284]).hexdigest(),
                         'e9a7e7f0f91f4e808226bf52507c03f134723802412dfd8755c0c820df7bb482')


if __name__ == '__main__':
    unittest.main()
