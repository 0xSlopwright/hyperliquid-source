"""Fresh native-certificate admission controls; real Rust builds are separate."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import bincode_diagnostic_parent_rust as rust


class DiagnosticParentOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = rust.reference.oracle(rust.TARGET, repo=ROOT)

    def test_fresh_target_certificates_and_input_only_fixture(self):
        expected = self.expected
        rust.verify_fixture(expected)
        metadata = expected['metadata']
        self.assertEqual(metadata['case_count'], 925)
        self.assertEqual((metadata['flat_certificates'], metadata['pretty_certificates']), (5, 9))
        self.assertEqual((metadata['expected_writer_calls'], metadata['expected_value_calls']), (4061, 510))
        self.assertEqual(rust.sha(expected['fixture']),
                         '5405aa3eefb0e7572379d8f4a4564532cb9a79499871335fdd0c06fd7c33f63d')
        self.assertEqual(len(metadata['used_certificate_paths']), 15)
        self.assertIn('chosen-domain-refusal', metadata['used_certificate_paths'])
        self.assertNotIn(b'\t', expected['inputs'])
        self.assertEqual(len(expected['inputs'].splitlines()), 925)
        self.assertFalse(metadata['references_production_rust'])
        self.assertFalse(metadata['native_execution_or_emulation'])

    def test_raw_flat_AL_versus_pretty_normalization_and_prior_error(self):
        rows = {line.split(';', 1)[0]: line for line in self.expected['expected'].decode().splitlines()}
        self.assertIn(';S=2:1:', rows['value_al_0_0_0_2'])
        self.assertIn(';S=1:1:', rows['value_al_1_0_0_2'])
        self.assertIn(';S=1:1:', rows['prior_1_255'])
        self.assertNotIn('w:', rows['prior_1_255'])
        self.assertNotIn('g:', rows['prior_1_255'])
        # The comparator rejects missing/misordered rows, rather than crediting a crash.
        with self.assertRaisesRegex(ValueError, 'row count'):
            rust.compare(b'', self.expected['expected'])
        with self.assertRaisesRegex(ValueError, 'identities/order'):
            rust.compare(b'wrong'+self.expected['expected'][self.expected['expected'].find(b';'):],
                         self.expected['expected'])

    def test_edited_expected_fixture_cannot_replace_fresh_certificate_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)/'vectors.tsv'
            for raw in (b'', self.expected['fixture'].replace(b';S=0:', b';S=1:', 1)):
                fixture.write_bytes(raw)
                with self.assertRaisesRegex(ValueError, 'fixture differs'):
                    rust.verify_fixture(self.expected, fixture)

    def test_bad_target_and_existing_output_rejected_before_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            target = folder/'wrong'; target.write_bytes(b'\x7fELF'+bytes(60))
            output = folder/'uncreated'
            with mock.patch.object(rust.subprocess, 'run', side_effect=AssertionError('no compiler')):
                with self.assertRaisesRegex(ValueError, 'Unauthenticated immutable node94'):
                    rust.build(target, folder/'uninvoked-rustc', output)
            self.assertFalse(output.exists())
            output.mkdir(); marker = output/'previous'; marker.write_bytes(b'preserved\n')
            with mock.patch.object(rust.reference, 'oracle', side_effect=AssertionError('no fresh input')):
                with self.assertRaisesRegex(ValueError, 'directory must be new'):
                    rust.build(target, folder/'uninvoked-rustc', output)
            self.assertEqual(marker.read_bytes(), b'preserved\n')
