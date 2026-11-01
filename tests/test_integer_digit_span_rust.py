"""Admission/comparator controls; actual Rust build evidence is separate."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import integer_digit_span_rust as runner


class DigitSpanRustAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fresh = runner.reference.oracle(runner.TARGET, repo=ROOT)

    def test_fresh_static_relation_matches_pre_Rust1697_fixture(self):
        runner.verify_fixture(self.fresh)
        metadata = self.fresh['metadata']
        self.assertEqual(metadata['case_count'], 1697)
        self.assertEqual(metadata['input_sha256'],
                         '612aa39a2621b6b5d6b6e6a7cb240e89c0362bc6ba071e1f4cfebbc0788cd5f3')
        self.assertEqual(metadata['expected_sha256'],
                         'b3ce83f568c0f89a2b140d75ccf755863c03a66e575b41d0fdebc084fab53954')
        self.assertTrue(metadata['no_PC_register_or_opcode_execution'])
        self.assertTrue(metadata['no_production_Rust_or_answers_read'])
        self.assertEqual(len(self.fresh['inputs'].splitlines()), 1697)
        self.assertNotIn(b'\t', self.fresh['inputs'])

    def test_changed_expected_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'fixture.tsv'
            for changed in (b'', self.fresh['fixture'][:-2]+b'00\n'):
                path.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'fixture differs'):
                    runner.verify_fixture(self.fresh, path)

    def test_wrong_target_and_prior_output_stop_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            wrong = folder/'wrong'; wrong.write_bytes(b'\x7fELF'+bytes(60))
            output = folder/'uncreated'
            with mock.patch.object(runner.subprocess, 'run', side_effect=AssertionError('no native/compiler')):
                with self.assertRaisesRegex(ValueError, 'authenticated immutable node94'):
                    runner.build(wrong, folder/'uninvoked-rustc', output)
            self.assertFalse(output.exists())
            output.mkdir(); marker = output/'previous'; marker.write_bytes(b'keep exact previous evidence\n')
            with mock.patch.object(runner.reference, 'oracle', side_effect=AssertionError('no input read')):
                with self.assertRaisesRegex(ValueError, 'directory must be new'):
                    runner.build(wrong, folder/'uninvoked-rustc', output)
            self.assertEqual(marker.read_bytes(), b'keep exact previous evidence\n')

    def test_comparator_keeps_raw_start_all20bytes_and_case_domain(self):
        wanted = self.fresh['expected']
        first, *remaining = wanted.splitlines()
        ident, start, buffer = first.split(b' ')
        wrong_start = b' '.join([ident, b'20', buffer])
        wrong_prefix = b' '.join([ident, start, b'00'+buffer[2:]])
        for altered in (wrong_start, wrong_prefix):
            actual = b'\n'.join([altered, *remaining])+b'\n'
            self.assertEqual(runner.mismatch_ids(actual, wanted), [ident.decode('ascii')])
        with self.assertRaisesRegex(ValueError, 'row count'):
            runner.mismatch_ids(b'', wanted)
        with self.assertRaisesRegex(ValueError, 'identities/order'):
            runner.mismatch_ids(b'wrong'+wanted[wanted.index(b' '):], wanted)
