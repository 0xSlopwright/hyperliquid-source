"""Actual 95-byte correspondence and request-contract corruption controls."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pad_character_protocol_static as native
import pad_character_protocol_rust as rust

PACKET = ROOT / 'research/work-items/RE-001-pad-character-protocol-94'


def replace(raw, offset, payload):
    return raw[:offset] + payload + raw[offset + len(payload):]


class CharacterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        provider = os.environ.get('HL_PAD_CHARACTER_LIBCORE')
        if not provider:
            raise unittest.SkipTest('Supply HL_PAD_CHARACTER_LIBCORE for actual artifact qualification; no download or passing correspondence is implied.')
        cls.target = native.TARGET.read_bytes()
        cls.archive = Path(provider).read_bytes()
        cls.record = native.analyze(cls.target, cls.archive)

    @classmethod
    def tearDownClass(cls):
        del cls.target, cls.archive, cls.record

    def test_actual_function_fields_data_and_complete_roles(self):
        record = self.record
        self.assertTrue(record['identity_admitted'])
        self.assertEqual(record['source_FUNC']['size'], 95)
        self.assertEqual(record['frame']['start'], 0x157cfa0)
        self.assertEqual(record['frame']['end'], 0x157cfff)
        self.assertEqual(record['target_proof']['row_count'], 37)
        self.assertEqual(record['comparison']['equal_nonRELA_bytes'], 91)
        self.assertEqual(record['comparison']['masked_offsets'], [31, 32, 33, 34])
        self.assertFalse(record['comparison']['raw_equal'])
        self.assertEqual(record['indent_data']['raw_hex'], '20202020')
        self.assertEqual(record['selected_layout']['target_pointer']['addend'], 0x157cfa0)
        self.assertEqual(record['selected_layout']['target_pointer']['raw_slot_hex'], '0000000000000000')
        self.assertEqual(record['target_proof']['parameters']['character_width_bits'], 32)
        self.assertEqual(record['target_proof']['parameters']['status_width_bits'], 8)
        self.assertFalse(record['target_proof']['instruction_evaluator'])

    def test_actual_raw_control_and_width_changes(self):
        raw = bytes.fromhex(self.record['raw_target_hex'])
        changes = [(71, '80fe0a'), (71, '83ff0a'), (56, '85c0'), (52, '20'),
                   (81, '18'), (76, '95'), (27, '32'), (44, '89fc'), (61, '02'),
                   (36, '03000000')]
        for offset, encoded in changes:
            with self.subTest(offset=offset, encoded=encoded):
                with self.assertRaisesRegex(ValueError, 'operand/control changed'):
                    native.prove_body(replace(raw, offset, bytes.fromhex(encoded)))

    def test_shared_wrong_predicate_cannot_pass_only_by_matching_source(self):
        record = self.record
        member, _ = native.archive_member(self.archive)
        image = native.Image(member, 1)
        source_offset = record['official_archive']['member_data_offset'] + image.named(native.SECTION)['offset']
        target_offset = record['body_file_offset']
        changed_source = replace(self.archive, source_offset + 71, bytes.fromhex('80fe0a'))
        changed_target = replace(self.target, target_offset + 71, bytes.fromhex('80fe0a'))
        with self.assertRaisesRegex(ValueError, 'operand/control changed'):
            native.derive(changed_target, changed_source)

    def test_code_relocation_requires_actual_typed_data_reference(self):
        record = self.record
        offset = record['official_archive']['member_data_offset'] + record['code_RELA']['record_file_offset']
        info = record['code_RELA']['symbol_index'] << 32
        for kind in (1, 9):
            changed = replace(self.archive, offset + 8, struct.pack('<Q', info | kind))
            with self.assertRaisesRegex(ValueError, 'PC32 field kind/addend'):
                native.derive(self.target, changed)
        changed = replace(self.target, record['body_file_offset'] + 31, bytes(4))
        with self.assertRaises(ValueError):
            native.derive(changed, self.archive)

    def test_actual_literal_and_pointer_relationships(self):
        record = self.record
        changed = replace(self.target, record['indent_data']['target_file_offset'], b'\t')
        with self.assertRaisesRegex(ValueError, 'four-space reference'):
            native.derive(changed, self.archive)
        pointer = record['selected_layout']['target_pointer']
        for offset, payload in [(pointer['record_file_offset'] + 8, struct.pack('<Q', 1)),
                                (pointer['record_file_offset'] + 16, struct.pack('<q', native.START + 1))]:
            with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                native.derive(replace(self.target, offset, payload), self.archive)
        source_pointer = record['selected_layout']['source_pointer']
        position = record['official_archive']['member_data_offset'] + source_pointer['record_file_offset'] + 8
        changed = replace(self.archive, position, struct.pack('<Q', (1265 << 32) | 1))
        with self.assertRaisesRegex(ValueError, 'selected complete FUNC'):
            native.derive(self.target, changed)

    def test_exact_FDE_extent_and_in_record_header(self):
        frame = self.record['frame']
        changes = [(frame['FDE_file_offset'], struct.pack('<I', 4)),
                   (frame['FDE_range_file_offset'], struct.pack('<I', 94)),
                   (frame['FDE_augmentation_length_file_offset'], b'\x80'),
                   (frame['CIE_encoding_file_offset'], b'\x00')]
        for offset, payload in changes:
            with self.subTest(offset=offset):
                with self.assertRaises(ValueError):
                    native.derive(replace(self.target, offset, payload), self.archive)


class CharacterAdmissionTests(unittest.TestCase):
    def test_independent_pre_Rust_transcripts_and_existing_byte_cases(self):
        inputs = rust.INPUTS.read_text().splitlines()
        expected = rust.EXPECTED.read_text().splitlines()
        self.assertEqual(len(inputs), 320)
        self.assertEqual([rust.expected_transcript(line) for line in inputs], expected)
        self.assertNotIn('\t', rust.INPUTS.read_text())
        self.assertEqual(hashlib.sha256((rust.COMPONENT / 'target-transcripts.tsv').read_bytes()).hexdigest(),
                         '0948969e5bd003de115a77092a50bc69c58622bf4025231cbd5d34be9ae64134')
        self.assertEqual(hashlib.sha256(rust.SOURCE.read_bytes()[:1663]).hexdigest(),
                         'c7e6c24c5ad8a698ada18cf2641b050b1a42655c2450af58df7ec855359f7e6d')
        for codepoint in ('00000a', '00010a', '01000a'):
            self.assertTrue(any(line.split('|')[1] == codepoint for line in inputs))

    def test_wrong_identity_and_preserved_output_stop_before_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong = root / 'not-node'
            wrong.write_bytes(b'\x7fELF' + bytes(60))
            with self.assertRaisesRegex(ValueError, 'authenticated node94'):
                native.analyze(wrong.read_bytes(), b'')
            output = root / 'previous'
            output.mkdir()
            marker = output / 'retained'
            marker.write_bytes(b'previous evidence\n')
            with self.assertRaises(FileExistsError):
                native.generate(root / 'absent-node', root / 'absent-archive', output)
            with self.assertRaises(FileExistsError):
                rust.build(root / 'absent-node', root / 'absent-archive', root / 'absent-compiler', output)
            self.assertEqual(marker.read_bytes(), b'previous evidence\n')


if __name__ == '__main__':
    unittest.main()
