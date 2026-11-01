"""Independent native/math controls for the capacity-20 digit converter.

Expectations were frozen before the new Rust existed. These tests inspect raw
facts and integer theorems; they never step a captured PC/register machine.
The decimal Rust component's actual build/client evidence is separate. The
235-byte selector is conditional native context, not a Rust formatter stub.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import integer_digit_span_static as subject

CASES = ROOT / 'research/work-items/RE-005-integer-digit-span-94/independent-cases'
DECIMAL_STIMULI_SHA = '0479e941b54e51ec98d71fc678d68f0fd12c6aedab67c4ce0a7524610b058fc8'
DECIMAL_EXPECTED_SHA = 'bd1a83fbd5beb1b44b34ffc3c1b637dd5d97647744a9a0025a028ea7f0dc3ad2'
CONTROL_SHA = '7546391eadbcacd7387f7492f992181663071d718d861db36dc8c1e215d0e097'
PRIMARY_BASE, PRIMARY_END = 0x1570470, 0x157062c
SELECTOR_BASE, SELECTOR_END = 0x14f7660, 0x14f774b
PRIMARY_SHA = 'bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f'
SELECTOR_SHA = 'a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf'
PAIR_SHA = 'bedfbc17dfedc3a783c817da8b2eec13baff8e36c4e6a61c346332973895315a'
U64 = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_fixture(name, digest):
    raw = (CASES / name).read_bytes()
    if sha(raw) != digest:
        raise ValueError('Independent pre-Rust fixture identity changed: ' + name)
    return json.loads(raw)


def number(value):
    return int(value, 0) if isinstance(value, str) else value


class IntegerDigitNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('objdump') is None:
            raise unittest.SkipTest('Native provider unavailable; no digit-span qualification')
        data = subject.TARGET.read_bytes()
        # One immutable admitted image; only tiny spans/tables survive setup.
        cls.result = subject.analyze(data)
        cls.primary = data[0x156f470:0x156f470 + 444]
        cls.selector = data[0x14f6660:0x14f6660 + 235]
        cls.pairs = data[0x252b1d:0x252b1d + 200]
        cls.lower = data[0x208620:0x208620 + 16]
        cls.upper = data[0x203830:0x203830 + 16]
        cls.prefix = data[0x252bed:0x252bed + 2]
        del data
        cls.primary_rows, cls.primary_listing, _ = subject.decode_span(cls.primary, PRIMARY_BASE)
        cls.selector_rows, cls.selector_listing, _ = subject.decode_span(cls.selector, SELECTOR_BASE)
        cls.proof = subject.prove_primary(cls.primary, cls.pairs, listing=cls.primary_listing)
        cls.context = subject.prove_selector(cls.selector, cls.lower, cls.upper, cls.prefix,
                                            listing=cls.selector_listing)

    def test_complete_primary_rows_actual_constants_and_store_sites(self):
        self.assertEqual((len(self.primary), sha(self.primary)), (444, PRIMARY_SHA))
        self.assertEqual(self.proof['body_sha256'], PRIMARY_SHA)
        self.assertEqual((len(self.primary_rows), self.proof['instruction_rows']), (114, 114))
        p = self.proof['parameters']
        expected = {'capacity': 20, 'group_threshold': 1000,
                    'continuation_threshold': 9999999,
                    'chunk_divisor': 10000,
                    'division_magic': 0x346dc5d63886594b, 'division_shift': 75,
                    'pair_magic': 5243, 'pair_shift': 19,
                    'tail_quarter_shift': 2, 'tail_pair_shift': 17}
        for key, value in expected.items():
            with self.subTest(parameter=key):
                self.assertEqual(p[key], value)
        cfg = self.proof['cfg']
        self.assertEqual((len(cfg['branches']), len(cfg['guard_call_sites']),
                          len(cfg['normal_return_sites'])), (14, 3, 1))
        stores = self.proof['store_sites']
        self.assertEqual([number(s['va']) for s in stores],
                         [0x15704eb,0x1570507,0x157052d,0x1570548,0x15705a2,0x15705b5,0x15705e7])
        self.assertTrue(all(s['width_bits'] == 8 for s in stores))
        self.assertEqual(sha(self.pairs), PAIR_SHA)
        self.assertEqual(self.pairs, ''.join(f'{n:02d}' for n in range(100)).encode())
        self.assertEqual(self.result['primary']['body_sha256'], PRIMARY_SHA)
        # The three opaque guard calls exist in the body; their unreachability
        # at capacity20 is a theorem, not a false zero-CALL instruction count.

    def test_actual_reciprocal_ranges_and_independent_decimal_boundaries(self):
        p = self.proof['parameters']
        magic, shift = p['division_magic'], p['division_shift']
        self.assertEqual(10000 * magic - (1 << shift), 432)
        self.assertLess(432 * U64, 1 << shift)
        self.assertEqual(100 * p['pair_magic'] - (1 << p['pair_shift']), 12)
        self.assertLess(12 * 9999, 1 << p['pair_shift'])
        self.assertEqual(25 * p['pair_magic'] - (1 << p['tail_pair_shift']), 3)
        self.assertLess(3 * 249, 1 << p['tail_pair_shift'])
        # Pure integer identities over the proved finite remainder domains.
        # No PC, register, opcode evaluator or original callable is involved.
        for x in range(10000):
            self.assertEqual((x * p['pair_magic']) >> p['pair_shift'], x // 100)
        for x in range(1000):
            self.assertEqual(((x >> p['tail_quarter_shift']) * p['pair_magic'])
                             >> p['tail_pair_shift'], x // 100)
        stimuli = fixed_fixture('DECIMAL-STIMULI.json', DECIMAL_STIMULI_SHA)
        expected = fixed_fixture('DECIMAL-EXPECTED.json', DECIMAL_EXPECTED_SHA)
        self.assertEqual((len(stimuli), len(expected)), (621, 621))
        self.assertEqual({e['length'] for e in expected}, set(range(1, 21)))
        for stimulus, observation in zip(stimuli, expected):
            value = stimulus['value']
            with self.subTest(value=value):
                self.assertEqual((value * magic) >> shift, value // p['chunk_divisor'])
                before = bytes.fromhex(stimulus['buffer_hex'])
                after = bytes.fromhex(observation['buffer_hex'])
                start = observation['start']
                self.assertEqual(after[:start], before[:start])
                self.assertEqual(after[start:], str(value).encode('ascii'))
                self.assertEqual((observation['end'], start), (20, 20 - len(str(value))))
        # Explicit mathematical counterexamples keep constant corruption live.
        self.assertEqual((10000 * (magic - 1)) >> shift, 0)
        self.assertEqual((100 * 5242) >> 19, 0)
        self.assertEqual(((100 // 4) * 5242) >> 17, 0)

    def test_separate_selector_priority_buffer_coordinates_and_opaque_sink(self):
        self.assertEqual((len(self.selector), sha(self.selector)), (235, SELECTOR_SHA))
        self.assertEqual((len(self.selector_rows), self.context['instruction_rows']), (63, 63))
        self.assertEqual(self.context['flag_priority'], [25, 26, 'decimal'])
        self.assertEqual((self.context['decimal_buffer_end'], self.context['hex_buffer_end']), (20, 16))
        self.assertEqual(number(self.context['decimal_callee']), PRIMARY_BASE)
        self.assertEqual(number(self.context['opaque_sink_slot']), 0x576e2d8)
        self.assertFalse(self.context['complete_G'])
        self.assertEqual((self.lower, self.upper, self.prefix),
                         (b'0123456789abcdef', b'0123456789ABCDEF', b'0x'))
        self.assertEqual(self.result['selector_context']['body_sha256'], SELECTOR_SHA)
        # No Rust flags/hex implementation, original private type, downstream
        # rendered-prefix or complete679-byte formatter claim follows here.

    def test_actual_byte_counterfactuals_use_fresh_native_views_below_image_gate(self):
        design = fixed_fixture('NATIVE-CONTROL-DESIGN.json', CONTROL_SHA)
        self.assertEqual((design['control_count'], design['primary_converter_controls'],
                          design['separate_selector_controls']), (29, 17, 12))
        for control in design['controls']:
            with self.subTest(control=control['label']):
                is_primary = control['body_start'] == PRIMARY_BASE
                original = self.primary if is_primary else self.selector
                changed = bytearray(original)
                offset = control['address'] - control['body_start']
                old, new = bytes.fromhex(control['before']), bytes.fromhex(control['after'])
                self.assertEqual(changed[offset:offset+len(old)], old)
                self.assertEqual(len(old), len(new))
                changed[offset:offset+len(old)] = new
                proposed = bytes(changed)
                # A genuine fresh decode of private tiny bytes, not an old
                # forged listing and not merely the full-target SHA refusal.
                _, listing, _ = subject.decode_span(proposed, control['body_start'])
                with self.assertRaises(subject.EvidenceError) as rejection:
                    if is_primary:
                        subject.prove_primary(proposed, self.pairs, listing=listing)
                    else:
                        subject.prove_selector(proposed, self.lower, self.upper, self.prefix,
                                               listing=listing)
                self.assertNotIn('full target identity', str(rejection.exception).lower())

    def test_observed_tables_and_prefix_are_semantic_inputs_not_regenerated_answers(self):
        changed_pairs = bytearray(self.pairs); changed_pairs[1] = ord('1')
        with self.assertRaises(subject.EvidenceError):
            subject.prove_primary(self.primary, bytes(changed_pairs), listing=self.primary_listing)
        for name in ('lower', 'upper', 'prefix'):
            with self.subTest(table=name):
                lower, upper, prefix = bytearray(self.lower), bytearray(self.upper), bytearray(self.prefix)
                if name == 'lower': lower[10] = ord('A')
                elif name == 'upper': upper[10] = ord('a')
                else: prefix[1] = ord('X')
                with self.assertRaises(subject.EvidenceError):
                    subject.prove_selector(self.selector, bytes(lower), bytes(upper), bytes(prefix),
                                           listing=self.selector_listing)

    def test_listing_raw_bytes_addresses_and_real_padding_are_bound(self):
        first = re.search(r'(?m)^([ \t]*)(0*1570470):([ \t]+)(55)(?=[ \t])', self.primary_listing)
        self.assertIsNotNone(first)
        wrong_byte = self.primary_listing[:first.start(4)] + '54' + self.primary_listing[first.end(4):]
        wrong_address = self.primary_listing[:first.start(2)] + '1570471' + self.primary_listing[first.end(2):]
        missing_padding = '\n'.join(line for line in self.primary_listing.splitlines()
                                    if not re.match(r'^\s*0*15704ac:', line))
        for label, listing in (('byte', wrong_byte), ('address', wrong_address), ('padding', missing_padding)):
            with self.subTest(control=label), self.assertRaises(subject.EvidenceError):
                subject.verify_listing(listing, self.primary, PRIMARY_BASE)

    def test_rendered_branch_prose_cannot_override_raw_semantic_authority(self):
        # The API deliberately authenticates byte tiling, not arbitrary human
        # mnemonic prose. Production uses owned GNU exports. This seam checks
        # that forged text cannot redirect the raw semantic/CFG proof; it does
        # not pretend that such prose is independently decoded or rejected.
        lines = self.primary_listing.splitlines()
        index = next(i for i, line in enumerate(lines) if re.match(r'^\s*0*157048b:', line))
        self.assertIn('0x1570567', lines[index])
        lines[index] = lines[index].replace('0x1570567', '0x1570568')
        changed = subject.prove_primary(self.primary, self.pairs, listing='\n'.join(lines))
        for key in ('parameters', 'cfg', 'store_sites', 'mathematics'):
            with self.subTest(authority=key):
                self.assertEqual(changed[key], self.proof[key])

    def test_identity_failures_and_prior_outputs_do_not_publish_or_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='digit-output-control-', dir='/tmp') as temp:
            base = Path(temp)
            wrong = base / 'wrong-target'; wrong.write_bytes(b'\x7fELF' + bytes(60))
            absent = base / 'not-created'
            with self.assertRaises(subject.EvidenceError):
                subject.generate(wrong, absent)
            self.assertFalse(absent.exists())
            previous = base / 'previous'; previous.mkdir()
            marker = previous / 'retained'; marker.write_bytes(b'preserve earlier evidence\n')
            with self.assertRaises(FileExistsError):
                subject.generate(base / 'missing-target', previous)
            self.assertEqual(marker.read_bytes(), b'preserve earlier evidence\n')
            with self.assertRaises(subject.EvidenceError):
                subject.authenticate(bytearray(b'not immutable target bytes'))


if __name__ == '__main__':
    unittest.main()
