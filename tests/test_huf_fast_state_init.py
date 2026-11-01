"""Native-derived constructor controls, plus an actual checked Rust client.

The 51 complete expectations were frozen from the original native proof before
reading the new Rust. The driver receives stimuli only. No captured code,
compatible assembly or instruction emulator is executed. Marker-state changes
witness refusal phases; they do not measure physical Rust store order.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import huf_fast_state_init as subject

PACKET = ROOT / 'research/work-items/RE-001-huf-fast-state-init'
CASES = PACKET / 'evidence/independent-cases'
STIMULI_SHA = '36c2a3ec7a576830f9cb1c043e4c2f5cc083a3c95ca0f58b014f981950505659'
EXPECTED_SHA = 'c9d6c51fadad055eb28c27b5be14823be990c3a632255c66263d9dd71e6cda4e'
SPAN_SHA = 'e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63'
OBJDUMP_SHA = '96afb8521834982d0e711b5d6e9785252bf82129fb0106b93a6bd54d83fae11f'
RUSTC_SHA = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
START, END = 0x55dc5e0, 0x55dc79b
NATIVE_STORE_ORDER = [120,128,136,144,32,0,8,40,48,16,24,56,64,72,80,104,112,96,88]
# Fixed-size copied-byte changes, selected before implementation inspection.
# Each has a boundary/partial-state witness in the independently frozen cases.
MUTATIONS = (
    ('zero-guard-jle-to-jl', 0x55dc5f9, '8e', '8c'),
    ('N9-jbe-to-jb', 0x55dc603, '86', '82'),
    ('header-byte1-not-byte2', 0x55dc60a, '10', '08'),
    ('header-value10', 0x55dc60d, '0b', '0a'),
    ('first-length-BYTE-not-WORD', 0x55dc622, 'b7', 'b6'),
    ('start-store-wrong-slot', 0x55dc635, '78', '70'),
    ('start-store-DWORD-not-QWORD', 0x55dc632, '4c', '44'),
    ('first-size-threshold8', 0x55dc659, '07', '08'),
    ('residual-guard-reversed', 0x55dc679, '76', '73'),
    ('underflow-guard-reversed', 0x55dc67f, '82', '83'),
    ('ceil-add0', 0x55dc687, '03', '00'),
    ('late-ja-not-jae', 0x55dc6c9, '83', '87'),
    ('BSF-not-BSR', 0x55dc6da, 'bd', 'bc'),
    ('drop-OR1', 0x55dc6e9, '01', '00'),
    ('SHR-not-SHL', 0x55dc6ec, 'e0', 'e8'),
    ('invert-lastbyte-zero-guard', 0x55dc6d7, '74', '75'),
    ('fourth-lastbyte-offset6', 0x55dc73c, '07', '06'),
    ('table-payload-pointer-plus8', 0x55dc750, '04', '08'),
    ('raw-error-minus21', 0x55dc78f, 'ec', 'eb'),
    ('raw-success2', 0x55dc769, '01', '02'),
    ('last-cell-duplicate-slot', 0x55dc767, '58', '50'),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def independent_cases():
    stimuli = (CASES / 'STIMULI.json').read_bytes()
    expected = (CASES / 'EXPECTED.json').read_bytes()
    if digest(stimuli) != STIMULI_SHA or digest(expected) != EXPECTED_SHA:
        raise ValueError('Independent native-derived expectation identity changed')
    return json.loads(stimuli), json.loads(expected)


def native_view(raw, start):
    """Real GNU decode of a tiny non-executable copied span, never the image."""
    provider = Path(shutil.which('objdump') or '/missing-objdump').resolve()
    if not provider.is_file() or digest(provider.read_bytes()) != OBJDUMP_SHA:
        raise ValueError('Qualified pinned GNU objdump is unavailable')
    with tempfile.TemporaryDirectory(prefix='hufs-test-native-', dir='/tmp') as temporary:
        folder = Path(temporary)
        path = folder / 'span.bin'
        path.write_bytes(raw)
        path.chmod(0o400)
        argv = [str(provider), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(start), path.name]
        result = subprocess.run(argv, cwd=folder, stdin=subprocess.DEVNULL,
                                capture_output=True, check=True)
        if result.stderr or path.read_bytes() != raw or digest(provider.read_bytes()) != OBJDUMP_SHA:
            raise ValueError('Native view or qualified provider changed')
    listing = result.stdout.decode('ascii')
    return subject.parse_native_listing(listing, start, raw), listing


class HufNativeConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        provider = Path(shutil.which('objdump') or '/missing-objdump').resolve()
        if not provider.is_file() or digest(provider.read_bytes()) != OBJDUMP_SHA:
            raise unittest.SkipTest('Pinned native provider unavailable; no constructor qualification')
        cls.admitted = subject.admit_target()
        cls.raw = cls.admitted['raw']
        cls.rows, cls.listing = native_view(cls.raw, START)
        cls.facts = subject.validate_constructor(cls.raw, cls.rows)

    def test_actual_complete_function_rows_stores_and_scope(self):
        self.assertEqual((len(self.raw), digest(self.raw)), (443, SPAN_SHA))
        self.assertEqual((self.facts['instruction_rows'], self.facts['reachable_rows']), (130, 128))
        self.assertEqual(len(self.facts['unreachable_padding']), 2)
        self.assertEqual(len(self.facts['raw_verified_branches']), 16)
        self.assertEqual(sum(r['mnemonic'] == 'ret' for r in self.rows), 2)
        self.assertFalse(any(r['mnemonic'].startswith('call') for r in self.rows))
        self.assertEqual([r['offset'] for r in self.facts['ordered_state_stores']], NATIVE_STORE_ORDER)
        self.assertEqual(self.facts['raw_statuses'], [0, 0xffffffffffffffec, 1])
        self.assertEqual(self.facts['late_output_refusal_positive_lengths'], [1,2,3,5,6,9])
        for key in ('table_payload_qualified', 'runtime_dispatch_qualified',
                    'whole_loop_or_decoder_qualified', 'progress_gate_changed'):
            self.assertFalse(self.facts[key])

    def test_actual_byte_guard_store_shift_mutants_fail_below_image_identity(self):
        for name, address, before, after in MUTATIONS:
            with self.subTest(mutation=name):
                changed = bytearray(self.raw)
                at = address - START
                old, new = bytes.fromhex(before), bytes.fromhex(after)
                self.assertEqual(changed[at:at + len(old)], old)
                self.assertEqual(len(old), len(new))
                changed[at:at + len(old)] = new
                proposed = bytes(changed)
                # Actual new bytes get a fresh native decode. This is not a
                # forged old listing or the full-target SHA rejection gate.
                rows, _ = native_view(proposed, START)
                with self.assertRaises(ValueError) as rejected:
                    subject.validate_constructor(proposed, rows)
                self.assertNotIn('Input identity mismatch', str(rejected.exception))

    def test_native_listing_bytes_coordinates_and_complete_padding_are_bound(self):
        first = re.search(r'(?m)^(\s*)(55dc5e0):(\s*)(48)(\s+89\s+d0)', self.listing)
        self.assertIsNotNone(first)
        wrong_byte = self.listing[:first.start(4)] + '49' + self.listing[first.end(4):]
        wrong_address = self.listing[:first.start(2)] + '55dc5e1' + self.listing[first.end(2):]
        without_padding = '\n'.join(line for line in self.listing.splitlines()
                                    if not re.match(r'^\s*55dc61b:', line))
        for name, listing in (('byte', wrong_byte), ('address', wrong_address), ('padding-gap', without_padding)):
            with self.subTest(control=name), self.assertRaises(ValueError):
                subject.parse_native_listing(listing, START, self.raw)

    def test_rendered_branch_destination_cannot_override_actual_displacement(self):
        lines = self.listing.splitlines()
        index = next(i for i, line in enumerate(lines) if re.match(r'^\s*55dc5f8:', line))
        self.assertIn('0x55dc778', lines[index])
        lines[index] = lines[index].replace('0x55dc778', '0x55dc779')
        rows = subject.parse_native_listing('\n'.join(lines), START, self.raw)
        with self.assertRaisesRegex(ValueError, 'raw displacement'):
            subject.validate_constructor(self.raw, rows)

    def test_selected_caller_context_is_separate_and_does_not_qualify_decoder(self):
        sizes = []
        for name, context in self.admitted['contexts'].items():
            rows, _ = native_view(context['raw'], context['start'])
            facts = subject.validate_context(name, context['raw'], rows)
            sizes.append(facts['context_bytes'])
            if name.startswith('wrapper'):
                self.assertEqual(facts['constructor_target'], START)
                self.assertFalse(facts['complete_wrapper_implemented'])
                is_a = name == 'wrapper-A'
                saved_at = 0x55dd2f2 if is_a else 0x55dceb4
                called_at = 0x55dd35a if is_a else 0x55dcf1a
                original_register = 'r15' if is_a else 'r14'
                other_register = 'r14' if is_a else 'r15'
                # Change actual saved/called register bytes in private copied
                # spans and obtain a fresh native view. This context admission
                # gate must reject the changed consumer, independently of the
                # primary constructor's identity.
                for role, address, original, replacement in (
                    ('saved', saved_at, '4d89cf' if is_a else '4d89ce',
                     '4d89ce' if is_a else '4d89cf'),
                    ('called', called_at, '41ffd7' if is_a else '41ffd6',
                     '41ffd6' if is_a else '41ffd7'),
                ):
                    with self.subTest(context=name, role=role, control='actual-byte'):
                        changed = bytearray(context['raw'])
                        at = address - context['start']
                        self.assertEqual(changed[at:at+3], bytes.fromhex(original))
                        changed[at:at+3] = bytes.fromhex(replacement)
                        changed_rows, _ = native_view(bytes(changed), context['start'])
                        with self.assertRaisesRegex(ValueError, 'Selected context identity mismatch'):
                            subject.validate_context(name, bytes(changed), changed_rows)
                # With authentic bytes retained, rendered saved-register and
                # indirect-call operand changes must also be rejected by the
                # actual used callback-flow checks, beyond raw admission.
                for role, address, wrong_operand, reason in (
                    ('saved', saved_at, other_register + ',r9', 'Saved callback operand mismatch'),
                    ('called', called_at, other_register, 'Callback register mismatch'),
                ):
                    with self.subTest(context=name, role=role, control='rendered-operand'):
                        changed_rows = copy.deepcopy(rows)
                        row = next(row for row in changed_rows if row['address'] == address)
                        self.assertEqual(row['operands'], original_register + ',r9'
                                         if role == 'saved' else original_register)
                        row['operands'] = wrong_operand
                        with self.assertRaisesRegex(ValueError, reason):
                            subject.validate_context(name, context['raw'], changed_rows)
            else:
                self.assertFalse(facts['runtime_CPUID_or_CPU_support_proved'])
                self.assertFalse(facts['complete_caller_reach_proved'])
        self.assertEqual(sorted(sizes), [109,109,313])
        self.assertEqual(sum(sizes), 531)
        self.assertEqual(self.facts['semantic_bytes'], 443)

    def test_wrong_target_and_prior_outputs_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix='hufs-output-control-', dir='/tmp') as temporary:
            root = Path(temporary)
            wrong = root / 'wrong-node'; wrong.write_bytes(b'\x7fELF' + bytes(60))
            absent = root / 'uncreated'
            with self.assertRaises(ValueError):
                subject.collect(absent, target_path=wrong)
            self.assertFalse(absent.exists())
            existing = root / 'existing'; existing.mkdir()
            marker = existing / 'prior-result'; marker.write_bytes(b'preserve old evidence\n')
            with self.assertRaises(FileExistsError):
                subject.collect(existing, target_path=root / 'missing-node')
            self.assertEqual(marker.read_bytes(), b'preserve old evidence\n')
            with self.assertRaises(FileExistsError):
                subject.run_rust_cases([], existing, rustc_path=root / 'missing-rustc')
            self.assertEqual(marker.read_bytes(), b'preserve old evidence\n')


class HufCheckedRustWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rustc = Path(subject.RUSTC)
        if not rustc.is_file() or digest(rustc.read_bytes()) != RUSTC_SHA:
            raise unittest.SkipTest('Pinned research compiler unavailable; no Rust component qualification')
        cls.stimuli, cls.expected = independent_cases()
        cls.temporary = tempfile.TemporaryDirectory(prefix='hufs-actual-client-', dir='/tmp')
        cls.output = Path(cls.temporary.name) / 'actual'
        # Every supplied dictionary is stimulus-only. Expectations stay on this
        # test side; the actual library/driver must compute its own result.
        cls.report = subject.run_rust_cases(cls.stimuli, cls.output)
        cls.responses = cls.report['responses']

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_all_independently_frozen_statuses_and_complete_partial_states(self):
        self.assertEqual((len(self.stimuli), len(self.expected), len(self.responses)), (51,51,51))
        for expected, actual in zip(self.expected, self.responses):
            with self.subTest(case=expected['label'], phase=expected['native_phase']):
                self.assertEqual(actual['state'], expected['state'])
                self.assertEqual(actual['raw_status'], expected['raw_status'])
                if expected['domain_error_expected']:
                    self.assertIsInstance(actual['domain_error'], str)
                    self.assertTrue(actual['domain_error'])
                else:
                    self.assertIsNone(actual['domain_error'])
        self.assertEqual(sum(r['raw_status'] == 1 for r in self.responses), 17)
        self.assertEqual(sum(r['raw_status'] == 0 for r in self.responses), 18)
        self.assertEqual(sum(r['raw_status'] == 0xffffffffffffffec for r in self.responses), 3)
        self.assertEqual(sum(r['domain_error'] is not None for r in self.responses), 13)

    def test_distinct_entry_markers_expose_refusal_phase_effects(self):
        # Changed marker cells expose the 4/12/19 effects; this does not assert
        # generated CPU instruction counts/order or absence of same-value stores.
        phase_cells = {'none': set(), 'starts': {15,16,17,18},
                       'cursors': set(range(8)) | {15,16,17,18},
                       'full': set(range(19)), 'unsupported': set()}
        for stimulus, expected, actual in zip(self.stimuli, self.expected, self.responses):
            with self.subTest(case=expected['label']):
                changed = {i for i, (old, new) in enumerate(zip(stimulus['state'], actual['state'])) if old != new}
                self.assertEqual(changed, phase_cells[expected['native_phase']])

    def test_boundary_cases_bind_guard_priority_wrap_and_nonzero_bit_values(self):
        results = {e['label']: r for e, r in zip(self.expected, self.responses)}
        self.assertEqual(results['L0-wins-empty-input-and-bad-table']['raw_status'], 0)
        self.assertEqual(results['positive-L-N9-error-wins-bad-table']['raw_status'], 0xffffffffffffffec)
        self.assertEqual(results['a7-wins-residual-underflow']['raw_status'], 0)
        self.assertEqual(results['residual-underflow-raw-minus20-after-four-writes']['raw_status'], 0xffffffffffffffec)
        failed = {L for L in range(1,14) if results['output-L'+str(L)]['raw_status'] == 0}
        self.assertEqual(failed, {1,2,3,5,6,9})
        self.assertEqual(results['lastbytes-0-1-128-255']['state'][8:12], [1,256,2,0xfe00000000000002])
        self.assertEqual(results['wrapped-failed-stream-start-values']['state'][15:19],
                         [(1<<64)-33,65502,131037,196572])
        self.assertEqual(results['wrapped-start-values-first-size7-zero']['state'][15:19],
                         [(1<<64)-5,2,65537,131072])
        self.assertEqual(results['adjacent-half-open-ranges']['raw_status'], 1)
        self.assertEqual(results['empty-input-output-ranges-not-overlap']['raw_status'], 0)
        self.assertIsNotNone(results['O-plus3ceil-overflow-despite-output-end-fit']['domain_error'])

    def test_actual_driver_wire_is_input_only_and_toolchain_is_rebound(self):
        expected_wire = ('\n'.join(subject.driver_request(case) for case in self.stimuli) + '\n').encode()
        self.assertEqual((self.output / 'driver.stdin').read_bytes(), expected_wire)
        extra = copy.deepcopy(self.stimuli[0])
        extra['expected'] = {'raw_status': 123, 'state': [7] * 19}
        self.assertEqual(subject.driver_request(extra), subject.driver_request(self.stimuli[0]))
        self.assertFalse(self.report['driver_receives_expected_results'])
        self.assertTrue(self.report['toolchain_inputs_unchanged'])
        self.assertEqual(len(self.report['toolchain_inputs']), 107)
        self.assertFalse(self.report['captured_or_compatible_assembly_executed'])


if __name__ == '__main__':
    unittest.main()
