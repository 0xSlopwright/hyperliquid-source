"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_error_band_range as rule
from elf_index import sections


class ErrorBandRangeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not rule.TARGET.is_file() or rule.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = rule.inspect(rule.TARGET)
        cls.data = rule.TARGET.read_bytes()
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
        record = rule.ROOT / 'research/work-items/foundation-error-band-range-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_band_edges_from_decoded_rule(self):
        edges = self.result['rule']['edges']
        band = {(e['callee_result'], e['esi'], e['rdx_post']): e['result'] for e in edges}
        # -120 itself passes the band gate; -119 and -1 are rejected.
        self.assertEqual(band[('0xffffffffffffff88', 0, '0x0')], 1)
        self.assertEqual(band[('0xffffffffffffff89', 0, '0x0')], 0)
        self.assertEqual(band[('0xffffffffffffffff', 0, '0x0')], 0)
        self.assertEqual(band[('0x0', 0, '0x0')], 1)
        self.assertEqual(band[('0xffffffffffffff87', 0, '0x0')], 1)

    def test_range_edges_from_decoded_rule(self):
        edges = self.result['rule']['edges']
        ranged = {(e['esi'], e['rdx_post']): e['result'] for e in edges if e['callee_result'] == '0x0'}
        self.assertEqual(ranged[(3, '0x500000003')], 1)
        self.assertEqual(ranged[(2, '0x500000003')], 0)
        self.assertEqual(ranged[(5, '0x500000003')], 1)
        self.assertEqual(ranged[(6, '0x500000003')], 0)
        self.assertEqual(ranged[(-5, '0xafffffffb')], 1)
        self.assertEqual(ranged[(-6, '0xafffffffb')], 0)
        self.assertEqual(ranged[(10, '0xafffffffb')], 1)
        self.assertEqual(ranged[(11, '0xafffffffb')], 0)

    def test_band_failure_overrides_in_range_input(self):
        edges = self.result['rule']['edges']
        combined = [e for e in edges if e['callee_result'] == '0xffffffffffffffff' and e['esi'] == 3]
        self.assertEqual(len(combined), 1)
        self.assertEqual(combined[0]['result'], 0)

    def test_shared_callee_recorded_not_claimed(self):
        call = self.result['call']
        self.assertEqual(call['site'], '0x555e874')
        self.assertEqual(call['target'], '0x555e670')
        self.assertEqual(call['target_bytes'], 505)
        self.assertFalse(call['target_claimed_here'])

    def test_incoming_callers(self):
        incoming = self.result['incoming']
        self.assertEqual(len(incoming['direct_e8_callers']), 26)
        self.assertEqual(incoming['direct_e8_callers'][0], '0x555e938')
        self.assertEqual(incoming['direct_e8_callers'][-1], '0x555ee57')
        self.assertEqual(incoming['validated_caller_fdes'], ['0x555e8a0'])
        self.assertFalse(incoming['complete_xref_census'])

    def test_identity_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                rule.inspect(path)

    def test_instruction_mutations_rejected(self):
        # The band immediate, band/low-bound branches, setle step, and ret sit
        # inside the locked 40-byte body, so any displacement mutation is
        # caught by the body lock first.
        for va in (rule.START, rule.START + 0x11, rule.START + 0x12, rule.START + 0x20, rule.START + 39):
            with self.subTest(va=hex(va)):
                old = self.data[self.offset(va)]
                with self.assertRaisesRegex(ValueError, 'instruction window'):
                    rule.analyze(self.mutated(va, bytes([old ^ 1])))

    def test_padding_mutation_rejected(self):
        old = self.data[self.offset(rule.END)]
        with self.assertRaisesRegex(ValueError, 'FDE padding'):
            rule.analyze(self.mutated(rule.END, bytes([old ^ 1])))

    def test_fde_extent_mutation_rejected(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        with self.assertRaisesRegex(ValueError, 'FDE record'):
            rule.analyze(self.mutated(eh['address'] + 0x2cfdd8 + 12, struct.pack('<I', 0x29)))

    def test_caller_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            rule.analyze(self.mutated(0x555e938 + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = rule.ROOT / 'research/work-items/foundation-error-band-range-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('555e870:', window)
        self.assertIn('call', window)
        self.assertIn('setle', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('555e938:', caller)
        self.assertIn('call', caller)


if __name__ == '__main__':
    unittest.main()
