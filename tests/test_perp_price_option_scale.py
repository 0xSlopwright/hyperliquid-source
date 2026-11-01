import hashlib
import unittest

from tools import perp_price_option_scale as p


class PerpPriceOptionScale(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.PATH.read_bytes()
        cls.image = p.Image(cls.data)
        cls.rows, cls.diff = p.inspect(cls.image)

    def run_case(self, **changes):
        args = dict(mode=1, raw_value=100, payload_byte=0xa7, key=30005,
                    table_group=3, table_length=6, decimals=0, pointer=0x1234)
        args.update(changes)
        return p.evaluate(**args)

    def test_fde_extents_and_location(self):
        self.assertEqual([r['size'] for r in self.rows], [318, 318])
        for row in self.rows:
            self.assertEqual([(x['path'], x['line'], x['column']) for x in row['locations']],
                             [('l1/src/perp_meta.rs', 194, 38), ('l1/src/perp_meta.rs', 319, 28)])
            self.assertEqual(len(row['branches']), 15)

    def test_divisor_ladder(self):
        self.assertEqual([p.scale_ladder(i) for i in range(7)],
                         [100, 1000, 10000, 100000, 1000000, 10000000, 100000000])
        for bad in (-1, 7, 255):
            with self.assertRaises(ValueError):
                p.scale_ladder(bad)

    def test_reciprocal_bound_and_edges(self):
        m = self.rows[0]['reciprocal']
        err = 10000*m - 2**75
        self.assertEqual(err, 432)
        self.assertLess(((1 << 64)-1)*err, 2**75)
        for n in (0, 1, 9999, 10000, 10001, 2**32-1, 2**63, 2**64-1):
            self.assertEqual(((n*m) >> 64) >> 11, n//10000)
        self.assertNotEqual(((10000*(m-1)) >> 64) >> 11, 1)

    def test_bypass_skips_every_metadata_guard(self):
        self.assertEqual(self.run_case(mode=2, raw_value=0x1234, key=2**64-1,
                         table_group=0, table_length=0, decimals=255,
                         pointer=0x1020304050607080),
                         ('ok-bypass', 0x34, 0x1020304050607080, 2))

    def test_failure_order(self):
        self.assertEqual(self.run_case(table_group=4, table_length=0, decimals=255), ('panic-group',))
        self.assertEqual(self.run_case(table_length=5, decimals=255), ('panic-index',))
        self.assertEqual(self.run_case(decimals=7), ('panic-decimals',))
        self.assertEqual(self.run_case(decimals=255), ('panic-decimals',))

    def test_zero_and_inexact_are_errors(self):
        for value in (0, 1, 99, 101, 199):
            self.assertEqual(self.run_case(raw_value=value), ('error-0x65',))
        self.assertEqual(self.run_case(raw_value=100), ('ok-scaled', 1, 0xa700000000000000, 1))
        self.assertEqual(self.run_case(raw_value=25600), ('ok-scaled', 0, 0xa700000000000001, 1))

    def test_maximum_exact_and_adjacent(self):
        v = (p.U64 // 100) * 100
        self.assertEqual(self.run_case(raw_value=v)[0], 'ok-scaled')
        self.assertEqual(self.run_case(raw_value=v + 1), ('error-0x65',))

    def test_input_range_rejection(self):
        for kw in ({'raw_value': -1}, {'key': 2**64}, {'mode': 256}, {'decimals': -1}, {'pointer': -1}):
            with self.assertRaises(ValueError):
                self.run_case(**kw)

    def test_block_walker_observes_encoded_paths(self):
        for row in self.rows:
            start = int(row['start'], 16)
            raw = bytes.fromhex(row['body_hex'])
            def walk(mode, value, key=30005, group=3, length=6, decimal=0):
                return p.walk_scale(raw, start, mode, value, 0xa7, key, group, length, decimal, 0x1234)
            result, trace = walk(1, 100)
            self.assertEqual(result, ('ok-scaled', 1, 0xa700000000000000, 1))
            self.assertIn(f'{start+0xce:#x}:T', trace)
            result, trace = walk(1, 2**32)
            self.assertEqual(result, ('error-0x65',))
            self.assertIn(f'{start+0xce:#x}:F', trace)
            self.assertEqual(walk(1, 0)[0], ('error-0x65',))
            self.assertEqual(walk(1, 100, decimal=7)[0], ('panic-decimals',))
            self.assertEqual(walk(2, 100, group=99, length=0, decimal=255)[0],
                             ('ok-bypass', 100, 0x1234, 2))

    def test_block_walker_detects_changed_target_and_factor(self):
        start = int(self.rows[0]['start'], 16)
        raw = bytearray.fromhex(self.rows[0]['body_hex'])
        args = (1, 100, 0xa7, 30005, 3, 6, 0, 0x1234)
        raw[0x0e] += 1
        with self.assertRaisesRegex(ValueError, 'bad mode branch'):
            p.walk_scale(raw, start, *args)
        raw = bytearray.fromhex(self.rows[0]['body_hex'])
        raw[0x85] = 101
        actual, _ = p.walk_scale(raw, start, *args)
        self.assertNotEqual(actual, p.evaluate(*args))

    def test_display_scale_and_zero_short_circuit(self):
        display = p.display_evidence(self.image)
        self.assertEqual(display['location_vas'], ['0x56f21c0', '0x56f3350'])
        self.assertEqual(len(display['table_bits']), 7)
        for d in range(7):
            self.assertEqual(p.scale_ladder(d) * 10**(6-d), 100000000)
        self.assertEqual(p.display_pair(0, 0, 12345, 0, 0, 255), ('ok', 0.0, 0.0))
        self.assertEqual(p.display_pair(0, 1, 12345, 0, 0, 255), ('panic-group',))
        self.assertEqual(p.display_pair(1, 0, 12345, 1, 2346, 0), ('ok', 0.000001, 0.0))
        self.assertEqual(p.display_pair(1, 1, 12345, 1, 2345, 255), ('panic-index',))
        self.assertEqual(p.display_pair(1, 1, 12345, 1, 2346, 7), ('panic-decimals',))

    def test_display_rounding_above_exact_integer_range(self):
        self.assertEqual(p.display_component(2**53+1, 6), float(2**53))
        self.assertEqual(p.display_component(2**64-1, 6), float(2**64))
        self.assertEqual(p.display_component(123456, 3), 123.456)

    def test_corrupt_display_table_rejected(self):
        damaged = bytearray(self.data)
        damaged[self.image.offset(0x3e0e90)] ^= 1
        im = p.Image(bytes(damaged), hashlib.sha256(damaged).hexdigest())
        with self.assertRaisesRegex(ValueError, 'table changed'):
            p.display_evidence(im)

    def test_invalid_image_hash_rejected(self):
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.Image(damaged)

    def test_changed_instruction_rejected_even_with_new_image_hash(self):
        damaged = bytearray(self.data)
        damaged[self.image.offset(0x232e340)] ^= 1
        im = p.Image(bytes(damaged), hashlib.sha256(damaged).hexdigest())
        with self.assertRaisesRegex(ValueError, 'function bytes differ'):
            p.inspect(im)

    def test_branch_corruption_rejected(self):
        raw = bytearray.fromhex(self.rows[0]['body_hex'])
        raw[0x0d:0x0f] = b'\x75\x80'
        with self.assertRaisesRegex(ValueError, 'outside FDE'):
            p.branch(raw, 0x0d, 0x232e2e0)
        raw[0x0d] = 0x90
        with self.assertRaisesRegex(ValueError, 'unexpected branch'):
            p.branch(raw, 0x0d, 0x232e2e0)

    def test_bad_address_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            self.image.offset(0xffffffffffffffff, 8)
        bss = next(s for s in self.image.sections if s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            self.image.offset(bss['address'], bss['size'])

    def test_copy_differences_are_displacement_fields(self):
        self.assertEqual(self.diff, [0x127,0x128,0x129,0x12a,0x12d,0x12e,0x12f,0x130,
                                     0x134,0x135,0x136,0x137,0x13a,0x13b,0x13c,0x13d])


if __name__ == '__main__':
    unittest.main()
