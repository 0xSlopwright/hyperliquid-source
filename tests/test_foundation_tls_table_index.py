"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tls_table_index as index
from elf_index import sections


class TlsTableIndexEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not index.TARGET.is_file() or index.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = index.inspect(index.TARGET)
        cls.data = index.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = index.ROOT / 'research/work-items/foundation-tls-table-index-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_index_edges_from_decoded_formula(self):
        edges = self.result['index']['index_edges']
        self.assertEqual(edges['0x1000'], 0)
        self.assertEqual(edges['0x1001'], 1)
        self.assertEqual(edges['0x1234'], 0)
        self.assertEqual(edges['0x0'], 2)
        self.assertEqual(edges['0x5'], 7)
        self.assertEqual(edges['0x1002'], 4100)
        self.assertEqual(edges['0x1235'], 4663)
        self.assertEqual(edges['0xffffffffffffffff'], 1)

    def test_entry_address_edges(self):
        edges = self.result['index']['entry_edges']
        self.assertEqual(edges['0'], '0x599a688')
        self.assertEqual(edges['1'], '0x599a690')
        self.assertEqual(edges['7'], '0x599a6c0')

    def test_table_address_from_rip_relative(self):
        self.assertEqual(self.result['index']['table_va'], '0x599a670')

    def test_tls_gate_recorded(self):
        tls = self.result['tls']
        self.assertEqual(tls['slow_path_target'], '0x555a760')
        self.assertIn('fs byte', tls['flag'])

    def test_incoming_callers(self):
        incoming = self.result['incoming']
        self.assertEqual(len(incoming['direct_e8_callers']), 174)
        self.assertEqual(incoming['direct_e8_callers'][0], '0x54f32b4')
        self.assertEqual(incoming['direct_e8_callers'][-1], '0x5513508')
        self.assertEqual(incoming['validated_caller_fdes'], ['0x54f3200'])
        self.assertFalse(incoming['complete_xref_census'])

    def test_identity_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                index.inspect(path)

    def test_instruction_mutations_rejected(self):
        # The sentinel immediates, plus-two step, indexed load, and slow-path
        # call bytes sit inside the locked 98-byte body, so any displacement
        # mutation is caught by the body lock first.
        for va in (index.START, index.START + 30, index.START + 56, index.START + 71, index.START + 91):
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window'):
                    index.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(index.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            index.analyze(self.mutated(index.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            index.analyze(self.mutated(eh['address'] + 0x2c40f0 + 12, struct.pack('<I', 0x61)))

    def test_caller_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            index.analyze(self.mutated(0x54f32b4 + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = index.ROOT / 'research/work-items/foundation-tls-table-index-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('54f3190:', window)
        self.assertIn('call', window)
        self.assertIn('cmove', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('54f32b4:', caller)
        self.assertIn('call', caller)


if __name__ == '__main__':
    unittest.main()
