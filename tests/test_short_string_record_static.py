"""Target-byte controls for one compact-carrier consumer; no target execution."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import short_string_record_static as record


def gnu_tools():
    try:
        return all(shutil.which(tool) and 'GNU' in subprocess.check_output(
            [tool, '--version'], text=True, encoding='utf-8').splitlines()[0]
                   for tool in ['objdump', 'readelf'])
    except (OSError, subprocess.SubprocessError):
        return False


class RecordContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / 'artifacts/node/94/hl-node'
        cls.data = cls.binary.read_bytes()
        cls.observed = record.analyze(cls.data)
        cls.sections = record.sections(cls.data)

    def changed_va(self, va, delta=1):
        changed = bytearray(self.data)
        offset, _ = record.read_va(changed, self.sections, va, 1)
        changed[offset] ^= delta
        return changed

    def test_target_fde_and_record_store_observations(self):
        r = self.observed
        self.assertEqual(r['target']['sha256'], record.SHA256)
        self.assertEqual(r['body'], {'start_va': '0x13c6430', 'end_va': '0x13c65e7',
                         'file_offset': '0x13c5430', 'bytes': 439,
                         'sha256': '8b998c0b8617fecd669e8ea2c722e988b30a992c30575cc2c9b75bfa9cce81bd'})
        self.assertEqual(r['record_store_observation']['step_bytes'], 48)
        self.assertEqual([(s['offset'], s['bytes']) for s in r['record_store_observation']
                         ['visible_stores_relative_to_record_start']], [(0, 8), (8, 8), (16, 16), (32, 4)])
        self.assertEqual(len(r['calls']), 10)
        self.assertEqual(len(r['lsda']['rows']), 6)
        self.assertFalse(r['component_gates_requested'])
        self.assertFalse(r['captured_binary_executed'])

    def test_normal_failure_and_drain_branch_destinations(self):
        edges = {r['va']: r['target_va'] for r in self.observed['branches']}
        self.assertEqual(edges, {'0x13c64a7': '0x13c6526', '0x13c64ed': '0x13c6565',
                                '0x13c6521': '0x13c6490', '0x13c6551': '0x13c6540',
                                '0x13c6599': '0x13c65a8', '0x13c65d1': '0x13c65c0'})
        self.assertEqual(self.observed['record_store_observation']['index_store_vas'],
                         ['0x13c652a', '0x13c65ac'])

    def test_call_ownership_uses_return_pc_predecessor_at_exclusive_end(self):
        calls = {c['va']: c for c in self.observed['calls']}
        self.assertEqual(calls['0x13c64cb']['target_va'], '0x1449a80')
        call = calls['0x13c64e2']
        self.assertEqual((call['return_pc'], call['unwind_lookup_pc'], call['lsda_row_index']),
                         ('0x13c64e8', '0x13c64e7', 0))
        self.assertEqual(self.observed['lsda']['rows'][0]['landing_pad'], '0x13c6596')
        self.assertEqual(calls['0x13c658e']['lsda_row_index'], 2)
        self.assertEqual(self.observed['lsda']['rows'][2]['landing_pad'], '0x13c659b')
        self.assertEqual(self.observed['lsda']['action1'], {'type_filter': -1, 'next_action': 0, 'bytes': '7f00'})

    def test_source_and_external_resume_are_concrete_bindings(self):
        source = self.observed['source_record']
        self.assertEqual((source['path'], source['line'], source['column']),
                         ('/home/ubuntu/hl/code_Mainnet/base/src/cid.rs', 28, 73))
        self.assertEqual(self.observed['resume_import']['symbol'], '_Unwind_Resume')
        self.assertEqual(self.observed['resume_import']['slot_va'], '0x5778db0')
        self.assertEqual(self.observed['resume_import']['type'], 'R_X86_64_JUMP_SLOT')

    def test_global_identity_and_truncation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'pinned node94'):
            record.analyze(self.data[:2048])
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'pinned node94'):
            record.analyze(changed)

    def test_real_instruction_mutations_rejected_below_global_identity(self):
        for va in [0x13c6477, 0x13c6483, 0x13c64cb, 0x13c64e8,
                   0x13c6503, 0x13c6507, 0x13c6510, 0x13c6517,
                   0x13c651d, 0x13c652a, 0x13c65ac, 0x13c65d6]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'Instruction control changed'):
                    record.inspect_bytes(self.changed_va(va))

    def test_real_relocated_addends_and_resume_type_rejected(self):
        for binding in self.observed['relative_bindings']:
            with self.subTest(slot=binding['slot_va']):
                changed = bytearray(self.data)
                changed[int(binding['file_offset'], 16) + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'Relative binding changed'):
                    record.inspect_bytes(changed)
        changed = bytearray(self.data)
        changed[int(self.observed['resume_import']['relocation_file_offset'], 16) + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'Resume JUMP_SLOT changed'):
            record.inspect_bytes(changed)

    def test_real_source_and_failure_literal_mutations_rejected(self):
        for va, diagnostic in [(0x5666ce0, 'Source Location fields'),
                               (0x1e4c4a, 'Source path bytes'),
                               (0x216f9d, 'Failure literal')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, diagnostic):
                    record.inspect_bytes(self.changed_va(va))

    def test_real_lsda_rows_encoding_and_signed_action_mutations_rejected(self):
        origin = int(self.observed['lsda']['file_offset'], 16)
        for delta, diagnostic in [(3, 'call-site encoding'), (6, 'call-site rows'),
                                  (7, 'call-site rows'), (39, 'signed action pair')]:
            with self.subTest(lsda_offset=delta):
                changed = bytearray(self.data)
                changed[origin + delta] ^= 1
                with self.assertRaisesRegex(ValueError, diagnostic):
                    record.inspect_bytes(changed)

    @unittest.skipUnless(gnu_tools(), 'GNU binutils required; not a native evidence PASS')
    def test_native_bounded_regeneration_matches_python_record(self):
        parent = ROOT / 'work'
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='record-static-', dir=parent) as folder:
            output = Path(folder) / 'observed'
            self.assertEqual(record.generate(self.binary, output), self.observed)
            self.assertEqual(json.loads((output / 'records.json').read_text()), self.observed)
            self.assertEqual({p.name for p in output.iterdir()},
                             {'records.json', 'consumer.objdump.txt', 'frames.txt', 'relocations.txt'})
            self.assertIn('<authenticated-node94>', (output / 'consumer.objdump.txt').read_text())


if __name__ == '__main__':
    unittest.main()
