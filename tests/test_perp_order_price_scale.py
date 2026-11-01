"""Controls for the #94 tagged perp price-scaling evidence packet."""
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import perp_order_price_scale as p

ITEM = ROOT / 'research/work-items/RE-004-perp-order-price-scale-94'


class PriceScale(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.TARGET.read_bytes()
        cls.secs, cls.records, cls.refs = p.examine(cls.data)
        cls.c = p.constants(cls.records[0][3])

    def test_evidence_regenerates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p.generate(self.data, out)
            for generated in out.iterdir():
                self.assertEqual(generated.read_bytes(), (ITEM / generated.name).read_bytes(), generated.name)
            self.assertEqual({x.name for x in out.iterdir()}, {
                'branches.tsv', 'copies.tsv', 'decimal-bytes.tsv', 'evidence.json',
                'function-bytes.txt', 'locations.tsv', 'vectors.tsv'})

    def test_body_hash_and_fde_bounds(self):
        self.assertEqual([(r[0], r[1]['end'] - r[0]) for r in self.records],
                         [(0x232e2e0, 318), (0x49e4ca0, 318)])
        self.assertEqual(self.refs[0], self.refs[1])
        self.assertEqual(self.refs[0], [0x56f21c0, 0x576e470, 0x56f3350, 0x576e150])

    def test_corrupt_input_digest_is_rejected(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.verified(data)

    def test_corrupt_instruction_rejected_even_when_digest_check_is_bypassed(self):
        data = bytearray(self.data)
        data[self.records[0][2] + 0x5f] ^= 1
        with patch.object(p, 'verified'):
            with self.assertRaisesRegex(ValueError, 'function bytes'):
                p.examine(data)

    def test_out_of_range_address_and_nonbranch_are_rejected(self):
        with self.assertRaises(ValueError):
            p.section_offset(self.secs, (1 << 64) - 1)
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            p.section_offset(self.secs, bss['address'])
        with self.assertRaises(ValueError):
            p.decode_branch(self.records[0][3], 0)

    def test_decimal_byte_partition_and_ladder(self):
        for d in range(256):
            if d < 7:
                self.assertEqual(p.ladder(d, self.c), 10 ** (d + 2))
            else:
                with self.assertRaises(ValueError):
                    p.ladder(d, self.c)

    def test_reciprocal_proof_and_adversarial_boundary_values(self):
        m = self.c['reciprocal']
        radix = self.c['asset_radix']
        p75 = 1 << 75
        delta = m * radix - p75
        qmax = ((1 << 64) - 1) // radix
        self.assertGreaterEqual(delta, 0)
        self.assertLess(qmax * delta + (radix - 1) * m, p75)
        for x in list(range(65536)) + [2**64 - 1, 2**64 - 2, 2**63, 2**32 - 1, 2**32, 10000, 9999]:
            self.assertEqual((x * m) >> 75, x // 10000)
        self.assertNotEqual((10000 * (m - (1 << 52))) >> 75, 1)

    def test_division_exactness_and_zero_are_distinct(self):
        for d in range(7):
            scale = 10 ** (2 + d)
            for x, expected in ((0, 'error'), (scale - 1, 'error'), (scale, 'ok'),
                                (scale + 1, 'error'), (2 * scale, 'ok'),
                                ((2**64 - 1) // scale * scale, 'ok')):
                result = p.evaluate(1, x, 8, 10023, 1, 24, d, self.c)
                self.assertEqual(result[0], expected)
                self.assertEqual(result, p.oracle(1, x, 8, 10023, 1, 24, d))

    def test_guards_and_tag_precedence(self):
        self.assertEqual(p.evaluate(0, 100, 7, 10023, 0, 24, 255, self.c), ('asset_panic',))
        self.assertEqual(p.evaluate(0, 100, 7, 10023, 1, 23, 255, self.c), ('asset_panic',))
        self.assertEqual(p.evaluate(0, 100, 7, 10023, 1, 24, 7, self.c), ('decimal_panic',))
        self.assertEqual(p.evaluate(2, 12345, 7, 10023, 0, 0, 255, self.c), ('passthrough', 57, 2))
        self.assertEqual(p.evaluate(3, 100, 7, 10023, 1, 24, 0, self.c), ('ok', 1, 7, 3))
        with self.assertRaises(ValueError):
            p.evaluate(0, 2**64, 0, 0, 0, 1, 0, self.c)

    def test_manifest(self):
        manifest = {}
        for line in (ITEM / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertNotIn(name, manifest)
            manifest[name] = digest
        self.assertEqual(set(manifest), {x.name for x in ITEM.iterdir() if x.name != 'MANIFEST.sha256'})
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((ITEM / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
