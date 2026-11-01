"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_min_cap_gap as rule
from elf_index import sections


class MinCapGapEvidenceTests(unittest.TestCase):
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
        record = rule.ROOT / 'research/work-items/foundation-min-cap-gap-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_min_zero_skip_edge(self):
        edges = self.result['rule']['edges']
        skipped = [e for e in edges if e['a_second'] == '0x5' and e['b_second'] == '0x0']
        self.assertEqual(len(skipped), 1)
        # The callee result is meaningless on the skip path, even nonzero.
        self.assertEqual(skipped[0]['callee_result'], 12345)
        self.assertEqual(skipped[0]['result'], 1)

    def test_callee_gate_edges(self):
        edges = self.result['rule']['edges']
        by_pair = {(e['a_second'], e['b_second'], e['callee_result']): e['result'] for e in edges}
        self.assertEqual(by_pair[('0xa', '0x7', 0)], 1)
        self.assertEqual(by_pair[('0xa', '0x7', 5)], 0)
        self.assertEqual(by_pair[('0x2a', '0x2a', 0)], 1)
        self.assertEqual(by_pair[('0x2a', '0x2a', 1)], 0)

    def test_order_rejection_edges(self):
        edges = self.result['rule']['edges']
        by_pair = {(e['a_second'], e['b_second'], e['callee_result']): e['result'] for e in edges}
        self.assertEqual(by_pair[('0x7', '0xa', 0)], 0)
        self.assertEqual(by_pair[('0x7', '0xa', 9)], 0)

    def test_range_guard_trap_edges(self):
        # Both -2**32 traps have low32 == 0 yet must reject: the range guard
        # is observable, not redundant.
        edges = self.result['rule']['edges']
        traps = [e for e in edges if e['b_second'] in ('0x100000000', '0x100000003')]
        self.assertEqual(len(traps), 2)
        self.assertTrue(all(e['result'] == 0 for e in traps))
        boundary = [e for e in edges if e['b_second'] == '0x80000005']
        self.assertEqual(len(boundary), 1)
        self.assertEqual(boundary[0]['result'], 0)

    def test_top_of_range_and_mod_edges(self):
        edges = self.result['rule']['edges']
        by_pair = {(e['a_second'], e['b_second']): e['result'] for e in edges}
        self.assertEqual(by_pair[('0xffffffffffffffff', '0xffffffffffffffff')], 1)
        self.assertEqual(by_pair[('0xffffffffffffffff', '0xfffffffffffffffe')], 1)
        # Gap mod 2**64 is 2: in range but nonzero, so it rejects.
        self.assertEqual(by_pair[('0x1', '0xffffffffffffffff')], 0)

    def test_derived_form_agrees_on_every_edge(self):
        for e in self.result['rule']['edges']:
            got = rule.derived_rule(int(e['a_second'], 16), int(e['b_second'], 16), e['callee_result'])
            self.assertEqual(got, e['result'])

    def test_shared_callee_recorded_not_claimed(self):
        call = self.result['call']
        self.assertEqual(call['site'], '0x5430dd7')
        self.assertEqual(call['target'], '0x5660150')
        self.assertIsNone(call['target_bytes'])
        self.assertFalse(call['target_fde_start'])
        self.assertFalse(call['target_claimed_here'])

    def test_incoming_callers(self):
        incoming = self.result['incoming']
        self.assertEqual(len(incoming['direct_e8_callers']), 8)
        self.assertEqual(incoming['direct_e8_callers'][0], '0x522d600')
        self.assertEqual(incoming['validated_caller_fdes'], ['0x522d4b0'])
        self.assertFalse(incoming['complete_xref_census'])

    def test_no_padding_after_window(self):
        function = self.result['function']
        self.assertEqual(function['padding_bytes'], 0)
        self.assertEqual(function['next_fde_start'], '0x5430e07')
        self.assertEqual(function['end_va_exclusive'], '0x5430e07')

    def test_retained_disassembly_lines(self):
        work = rule.ROOT / 'research/work-items/foundation-min-cap-gap-94'
        window = (work / 'window.objdump.txt').read_text()
        self.assertIn('5430db0:', window)
        self.assertIn('5430e06:', window)
        self.assertIn('\tret', window)
        caller = (work / 'caller.objdump.txt').read_text()
        self.assertIn('522d600:', caller)
        self.assertIn('call', caller)
        frames = (work / 'frames.txt').read_text()
        self.assertIn('pc=0000000005430db0..0000000005430e07', frames)
        self.assertIn('pc=000000000522d4b0..000000000522d933', frames)

    def test_body_mutation_is_caught(self):
        with self.assertRaises(ValueError):
            rule.analyze(self.mutated(0x5430dc5, b'\x90\x0f\x46\xdd'))

    def test_call_target_mutation_is_caught(self):
        with self.assertRaises(ValueError):
            rule.analyze(self.mutated(0x5430dd7, b'\xe8\x00\x00\x00\x00'))

    def test_fde_mutation_is_caught(self):
        with self.assertRaises(ValueError):
            rule.analyze(self.mutated(0xce1518 + 0x2bae74 + 12, b'\x00\x00\x00\x00'))

    def test_caller_call_mutation_is_caught(self):
        with self.assertRaises(ValueError):
            rule.analyze(self.mutated(0x522d600, b'\xe8\x00\x00\x00\x00'))


if __name__ == '__main__':
    unittest.main()
