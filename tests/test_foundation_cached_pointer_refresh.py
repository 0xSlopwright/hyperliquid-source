"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_cached_pointer_refresh as rule
from elf_index import sections


class CachedPointerRefreshEvidenceTests(unittest.TestCase):
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
        record = rule.ROOT / 'research/work-items/foundation-cached-pointer-refresh-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_self_referential_edges_from_decoded_rule(self):
        edges = self.result['rule']['edges']
        flags = {(e['second'], e['link']): e['flag'] for e in edges}
        # Link equal to its own address (second + 0x18) clears the flag.
        self.assertEqual(flags[('0x1000', '0x1018')], 0)
        self.assertEqual(flags[('0x0', '0x18')], 0)
        self.assertEqual(flags[('0x5000', '0x5018')], 0)

    def test_non_self_referential_edges_from_decoded_rule(self):
        edges = self.result['rule']['edges']
        flags = {(e['second'], e['link']): e['flag'] for e in edges}
        self.assertEqual(flags[('0x1000', '0x2000')], 1)
        self.assertEqual(flags[('0x1000', '0x0')], 1)
        self.assertEqual(flags[('0x5000', '0x5017')], 1)
        self.assertEqual(flags[('0x5000', '0x5019')], 1)

    def test_wraparound_edge_from_decoded_rule(self):
        # second = 2**64 - 0x18, so second + 0x18 wraps to 0; link 0 matches.
        edges = self.result['rule']['edges']
        wrapped = [e for e in edges if e['second'] == '0xffffffffffffffe8']
        self.assertEqual(len(wrapped), 1)
        self.assertEqual(wrapped[0]['link'], '0x0')
        self.assertEqual(wrapped[0]['flag'], 0)
        self.assertEqual(wrapped[0]['cache'], '0xabcd')

    def test_cache_passthrough_from_decoded_rule(self):
        edges = self.result['rule']['edges']
        caches = {(e['callee_result'], e['second'], e['link']): e['cache'] for e in edges}
        self.assertEqual(caches[('0x1234', '0x1000', '0x2000')], '0x1234')
        self.assertEqual(caches[('0xffffffffffffffff', '0x1000', '0x0')], '0xffffffffffffffff')
        self.assertEqual(caches[('0x0', '0x1000', '0x1018')], '0x0')

    def test_shared_callee_recorded_not_claimed(self):
        call = self.result['call']
        self.assertEqual(call['site'], '0x5172e2c')
        self.assertEqual(call['target'], '0x5172b00')
        self.assertEqual(call['target_bytes'], 257)
        self.assertFalse(call['target_claimed_here'])

    def test_incoming_callers(self):
        incoming = self.result['incoming']
        self.assertEqual(len(incoming['direct_e8_callers']), 7)
        self.assertEqual(incoming['direct_e8_callers'][0], '0x5173afd')
        self.assertEqual(incoming['direct_e8_callers'][-1], '0x5175f8f')
        self.assertEqual(incoming['validated_caller_fdes'], ['0x5173a90'])
        self.assertFalse(incoming['complete_xref_census'])

    def test_identity_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                rule.inspect(path)

    def test_instruction_mutations_rejected(self):
        # The entry, call, cache store, link compare, and ret sit inside the
        # locked 41-byte body, so any displacement mutation is caught by the
        # body lock first.
        for va in (rule.START, rule.START + 0xc, rule.START + 0x11, rule.START + 0x1d, rule.START + 40):
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
            rule.analyze(self.mutated(eh['address'] + 0x29c4f0 + 12, struct.pack('<I', 0x2a)))

    def test_caller_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Call-pattern candidate set'):
            rule.analyze(self.mutated(0x5173afd + 1, b'\x00'))

    def test_retained_disassembly_contains_key_lines(self):
        packet = rule.ROOT / 'research/work-items/foundation-cached-pointer-refresh-94'
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('5172e20:', window)
        self.assertIn('call', window)
        self.assertIn('setne', window)
        caller = (packet / 'caller.objdump.txt').read_text()
        self.assertIn('5173afd:', caller)
        self.assertIn('call', caller)


if __name__ == '__main__':
    unittest.main()
