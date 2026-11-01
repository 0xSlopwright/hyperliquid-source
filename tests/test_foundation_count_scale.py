"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_count_scale as scale
from elf_index import sections


class CountScaleEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not scale.TARGET.is_file() or scale.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = scale.inspect(scale.TARGET)
        cls.data = scale.TARGET.read_bytes()
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
        record = scale.ROOT / 'research/work-items/foundation-count-scale-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_aligned_identity_from_decoded_formula(self):
        edges = self.result['arithmetic']['aligned_edges']
        self.assertEqual(edges['0'], 0)
        self.assertEqual(edges['1'], 1)
        self.assertEqual(edges['10'], 10)
        self.assertEqual(edges['4096'], 4096)
        self.assertEqual(edges['4294967295'], 4294967295)

    def test_raw_scaled_edges(self):
        edges = self.result['arithmetic']['raw_edges']
        self.assertEqual(edges['1'], 0)
        self.assertEqual(edges['16'], 0xcccccccd)
        self.assertEqual(edges['79'], 858993460)
        self.assertEqual(edges['81'], 1)
        self.assertEqual(edges['-80'], 0xFFFFFFFF)
        self.assertEqual(edges['800'], 10)

    def test_pointer_edges(self):
        edges = self.result['arithmetic']['pointer_edges']
        self.assertEqual(edges['0'], '0x100000')
        self.assertEqual(edges['1'], '0x100050')
        self.assertEqual(edges['10'], '0x100320')
        self.assertEqual(edges['4096'], '0x150000')

    def test_incoming_callers(self):
        incoming = self.result['incoming']
        self.assertEqual(incoming['direct_e8_callers'],
                         ['0x51c976d', '0x51c9d4d', '0x51ca374'])
        self.assertEqual(incoming['validated_caller_fdes'],
                         ['0x51c9710', '0x51c9d10', '0x51ca1f0'])
        self.assertFalse(incoming['complete_xref_census'])

    def test_identity_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                scale.inspect(path)

    def test_instruction_mutations_rejected(self):
        # The call, shift, and magic bytes sit inside the locked 49-byte body,
        # so any displacement mutation is caught by the body lock first.
        for va in (scale.START, scale.START + 29, scale.START + 24, scale.START + 44):
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window'):
                    scale.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(scale.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            scale.analyze(self.mutated(scale.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            scale.analyze(self.mutated(eh['address'] + 0x2a0eac + 12, struct.pack('<I', 0x32)))

    def test_caller_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            scale.analyze(self.mutated(0x51c976d + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = scale.ROOT / 'research/work-items/foundation-count-scale-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('51c96d0:', window)
        self.assertIn('imul', window)
        self.assertIn('call', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('51c976d:', caller)
        self.assertIn('call', caller)


if __name__ == '__main__':
    unittest.main()
