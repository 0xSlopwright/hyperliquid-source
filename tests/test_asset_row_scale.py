import hashlib
import random
import struct
import unittest
from fractions import Fraction
from pathlib import Path

from tools import asset_row_scale as a


class AssetRowScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray((a.ROOT / 'artifacts/node/94/hl-node').read_bytes())
        cls.sections = a.elf_index.sections(cls.data)
        cls.evidence = a.inspect(cls.data)

    def test_boundaries_and_table(self):
        self.assertEqual([f['end_va_exclusive'] for f in self.evidence['functions']], ['0x2311bdc', '0x2567241', '0x2a3e0f6', '0x26b2724'])
        self.assertEqual([p['divisor'] for p in self.evidence['power_table']], [10 ** i for i in range(7)])
        self.assertEqual(len(self.evidence['conditional_branches']), 6)
        self.assertEqual([(f['key'], f['record_offset']) for f in self.evidence['serializer_fields']][3:7],
                         [('sz', '0x18'), ('executedSz', '0x20'), ('executedNtl', '0x28'), ('minutes', '0x30')])
        self.assertEqual(len(a.vectors(self.evidence['power_table'])), 77)

    def test_corrupt_hash_rejected(self):
        self.data[0] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                a.inspect(self.data)
        finally:
            self.data[0] ^= 1

    def test_corrupt_instruction_rejected_even_without_digest_gate(self):
        off = a.file_offset(self.sections, 0x23119e4, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'function bytes changed'):
                a.inspect(self.data, check_hash=False)
        finally:
            self.data[off] ^= 1

    def test_corrupt_power_table_rejected_without_digest_gate(self):
        off = a.file_offset(self.sections, 0x3c1a80 + 24, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'power table mismatch'):
                a.inspect(self.data, check_hash=False)
        finally:
            self.data[off] ^= 1

    def test_corrupt_serializer_key_rejected(self):
        off = a.file_offset(self.sections, 0x420feb, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'serializer keys changed'):
                a.inspect(self.data, check_hash=False)
        finally:
            self.data[off] ^= 1

    def test_no_unbacked_va_resolution(self):
        bss = next(s for s in self.sections if s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            a.file_offset([bss], bss['address'], 1)
        with self.assertRaises(ValueError):
            a.file_offset(self.sections, 1 << 63, 1)

    def test_reciprocal_proofs_and_negative_control(self):
        a.quotient_lemma(0x346dc5d63886594b, 10000, 75, (1 << 64) - 1)
        a.quotient_lemma(0x45e7b272f608771, 1875, 69, (1 << 59) - 1)
        with self.assertRaisesRegex(ValueError, 'proof failed'):
            a.quotient_lemma(0x346dc5d63886594a, 10000, 75, (1 << 64) - 1)
        rng = random.Random(94)
        for x in [0, 1, 9999, 10000, (1 << 64) - 1] + [rng.getrandbits(64) for _ in range(1000)]:
            self.assertEqual((x * 0x346dc5d63886594b) >> 75, x // 10000)
            self.assertEqual(((x >> 5) * 0x45e7b272f608771) >> 69, x // 60000)

    def test_rounding_model_against_host_ieee754(self):
        rng = random.Random(94)
        for exp in range(7):
            d = 10 ** exp
            for x in [0, 1, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 64) - 1] + [rng.getrandbits(64) for _ in range(100)]:
                cast, quotient = a.convert(x, d)
                self.assertEqual(cast, struct.unpack('<Q', struct.pack('<d', float(x)))[0])
                self.assertEqual(quotient, struct.unpack('<Q', struct.pack('<d', float(x) / d))[0])
        self.assertEqual(a.convert((1 << 53), 1), a.convert((1 << 53) + 1, 1))

    def test_rounding_half_even_and_bad_inputs(self):
        self.assertEqual(a.round_even_ratio(5, 2), 2)
        self.assertEqual(a.round_even_ratio(7, 2), 4)
        self.assertEqual(a.to_binary64(Fraction((1 << 53) + 1)), a.to_binary64(Fraction(1 << 53)))
        for x, d in [(-1, 1), (1 << 64, 1), (1, 0)]:
            with self.assertRaises(ValueError):
                a.convert(x, d)


if __name__ == '__main__':
    unittest.main()
