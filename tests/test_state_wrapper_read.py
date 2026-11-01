import hashlib
import unittest
from tools import state_wrapper_read as m


class StateWrapperReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.result = m.extract(cls.data)

    def test_functions_and_tables(self):
        self.assertEqual([x['size'] for x in self.result['functions']], [5283, 5283, 1730, 287])
        self.assertEqual([x['entries'] for x in self.result['tables']], [225, 18, 225, 18, 32])
        self.assertEqual(self.result['key'], 'exchange')

    def test_routes_and_errors(self):
        edges = {(x['site'], x['role']): x['target'] for x in self.result['edges']}
        self.assertEqual(edges[('0x1799f44', 'empty-map-missing')], '0x179a703')
        self.assertEqual(edges[('0x179a667', 'duplicate-field')], '0x179ad4c')
        self.assertEqual(edges[('0x405c4c7', 'duplicate-field')], '0x405cbac')
        self.assertEqual(m.rel32(self.data, 0x432fea7, b'\xe8'), 0x405b970)

    def test_key_controls(self):
        key = m.decode_key(self.data, m.PARSERS[0])
        self.assertEqual(m.classify(key, False, key), 'decode-value')
        self.assertEqual(m.classify(key, True, key), 'duplicate-field')
        for pos in range(len(key)):
            bad = key[:pos] + bytes([key[pos] ^ 1]) + key[pos+1:]
            self.assertEqual(m.classify(bad, False, key), 'skip-unknown-value')
        self.assertEqual(m.classify(key+b'x', False, key), 'skip-unknown-value')

    def test_bad_digest(self):
        with self.assertRaises(ValueError):
            m.verified(b'not the captured ELF')

    def test_bad_compare_and_branch(self):
        raw = bytearray(self.data)
        # .text mapping is checked independently; mutate a compare opcode.
        sec = next(s for s in m.sections(raw) if s['name'] == '.text')
        offset = sec['offset'] + 0x179a1d6 - sec['address']
        raw[offset] ^= 1
        with self.assertRaises(ValueError):
            m.decode_key(raw, m.PARSERS[0])
        raw[offset] ^= 1
        raw[offset + 5] ^= 1
        with self.assertRaises(ValueError):
            m.decode_key(raw, m.PARSERS[0])

    def test_wrong_opcode_and_out_of_bounds(self):
        with self.assertRaises(ValueError):
            m.rel32(self.data, 0x28e9bac, b'\xe9')
        with self.assertRaises(ValueError):
            m.at(self.data, 0xffffffffffffffff, 8)
        with self.assertRaises(ValueError):
            m.at(self.data, 0, -1)

    def test_table_corruption(self):
        raw = bytearray(self.data)
        sec = next(s for s in m.sections(raw) if s['address'] <= 0x2c88a0 < s['address'] + s['size'] and s['type'] != 8)
        off = sec['offset'] + 0x2c88a0 - sec['address']
        raw[off] ^= 1
        with self.assertRaises(ValueError):
            m.verified(raw)
        self.assertNotEqual(m.at(raw, 0x2c88a0, 4), m.at(self.data, 0x2c88a0, 4))

if __name__ == '__main__':
    unittest.main()
