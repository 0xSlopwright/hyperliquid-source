"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_div_million as divm
from elf_index import sections


class DivMillionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not divm.TARGET.is_file() or divm.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = divm.inspect(divm.TARGET)
        cls.data = divm.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def mutated_slot(self, addend):
        data = bytearray(self.data)
        rel = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rel['offset']:rel['offset'] + rel['size']]
        for off in range(0, len(raw), 24):
            address, info, old = struct.unpack_from('<QQq', raw, off)
            if address == divm.SLOT:
                struct.pack_into('<q', data, rel['offset'] + off + 16, addend)
                return data
        raise AssertionError('Slot record not found')

    def test_retained_record_matches_authenticated_target(self):
        record = divm.ROOT / 'research/work-items/foundation-div-million-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_division_edges_from_decoded_formula(self):
        edges = self.result['arithmetic']['edges']
        self.assertEqual(edges['0'], 0)
        self.assertEqual(edges['999999'], 0)
        self.assertEqual(edges['1000000'], 1)
        self.assertEqual(edges['1000001'], 1)
        self.assertEqual(edges['123456789'], 123)
        self.assertEqual(edges['9223372036854775807'], 9223372036854)
        self.assertEqual(edges['18446744073709551615'], 18446744073709)

    def test_division_rule_on_boundaries(self):
        for x in (0, 1, 999998, 999999, 1000000, 1000001, 10**12 + 999999, 2**64 - 1):
            self.assertEqual(divm.div_million(x), x // 1000000)
        self.assertTrue(self.result['arithmetic']['checked_sample'] == 5000)

    def test_incoming_edge_is_slot_only(self):
        incoming = self.result['incoming']
        self.assertEqual(incoming['direct_e8_callers'], [])
        self.assertEqual(incoming['relocation_slot'], '0x5788170')
        self.assertEqual(incoming['ff15_ff25_slot_call_sites'], [])
        self.assertFalse(incoming['complete_xref_census'])

    def test_identity_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                divm.inspect(path)

    def test_instruction_mutations_rejected(self):
        # The magic, shift, and call bytes sit inside the locked 38-byte body,
        # so any displacement mutation is caught by the body lock first.
        for va in (divm.START, divm.START + 9, divm.START + 19, divm.START + 36):
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window'):
                    divm.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(divm.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            divm.analyze(self.mutated(divm.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            divm.analyze(self.mutated(eh['address'] + 0x2c9938 + 12, struct.pack('<I', 0x27)))

    def test_slot_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'slot'):
            divm.analyze(self.mutated_slot(0x55243d1))

    def test_retained_disassembly_contains_key_lines(self):
        packet = divm.ROOT / 'research/work-items/foundation-div-million-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('55243d0:', window)
        self.assertIn('call', window)
        self.assertIn('mul', window)
        self.assertIn('shr', window)


if __name__ == '__main__':
    unittest.main()
