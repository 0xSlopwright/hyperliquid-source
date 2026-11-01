"""Actual448-byte/typed-edge controls; no compiler or captured execution.

Portable relations use real previously admitted tiny excerpts. Actual container
and capture tests require the explicitly pinned local artifact; an unavailable
input may skip those tests, and a skip never qualifies that missing input.
"""
from pathlib import Path
import hashlib
import mmap
import os
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import libcore_write_fmt_leaf as subject

FIXTURES = ROOT / 'research/work-items/RE-002-libcore-write-fmt448/fixtures'
ARCHIVE = Path(os.environ.get('HL_LIBCORE_ARCHIVE',
    '/tmp/hl-rem-rust-1.94.1-20261031/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'))
BUILD = Path(os.environ.get('HL_FMT_RETAINED_BUILD',
    '/tmp/hl-libcore-pad-codegen-production-546-20261101'))


def fixture(name):
    return bytes.fromhex((FIXTURES / name).read_text(encoding='utf-8').strip())


def edge():
    import json
    original = json.loads((FIXTURES / 'TARGET-CORRESPONDENCE.json').read_text(encoding='utf-8'))
    actual = original['actual_used_edge']
    row = actual['RELATIVE']
    converted = {'slot': row['offset'], 'kind': row['type'], 'symbol': row['symbol_index'],
                 'addend': row['addend'], 'record_file_offset': row['record_file_offset']}
    return bytes.fromhex(actual['caller_raw_hex']), converted, bytes.fromhex(actual['slot_raw_hex'])


def capture_snapshot(edits=()):
    """One immutable negative snapshot from nonexecutable private COW pages.

    The original digest is checked before edits and again through the real
    source FD afterward. Changed snapshots are explicitly unqualified inputs,
    not alternate admitted targets. No original/bytearray duplicate is held.
    """
    with subject.TARGET.open('rb') as stream:
        before = os.fstat(stream.fileno())
        if before.st_size != subject.TARGET_SIZE:
            raise AssertionError('Actual node94 size differs')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as private:
            if hashlib.sha256(private).hexdigest() != subject.TARGET_SHA256:
                raise AssertionError('Actual original node94 digest differs')
            for offset, form, value in edits:
                struct.pack_into('<' + form, private, offset, value)
            snapshot = bytes(private)
        after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if identity(before) != identity(after):
            raise AssertionError('Original source changed during private snapshot')
        stream.seek(0)
        if hashlib.file_digest(stream, 'sha256').hexdigest() != subject.TARGET_SHA256:
            raise AssertionError('Private edit changed original source')
    return snapshot


class PortableActualRelations(unittest.TestCase):
    def test_complete_real448_and_terminal_nonrela_differences_stay_visible(self):
        source, captured = fixture('official.hex'), fixture('target.hex')
        self.assertEqual(hashlib.sha256(source).hexdigest(), subject.BODY_SHA256)
        comparison = subject.compare_raw(source, captured)
        self.assertTrue(comparison['raw_equal'])
        self.assertEqual((comparison['normalization_masks'], comparison['trimmed_bytes']), ([], 0))
        for offset in (0, 117, 357, 447):
            changed = bytearray(captured)
            changed[offset] ^= 1
            with self.subTest(offset=offset):
                result = subject.compare_raw(source, bytes(changed))
                self.assertFalse(result['raw_equal'])
                self.assertEqual(result['raw_differing_offsets'], [offset])
                self.assertEqual(result['normalization_masks'], [])
        for shortened in (source[:-1], source + b'\0'):
            with self.assertRaises(ValueError):
                subject.compare_raw(shortened, captured)

    def test_actual19_field_and_typed_relative_cannot_be_substituted(self):
        caller, row, slot = edge()
        actual = subject.bind_edge(caller, [row], slot)
        self.assertEqual((actual['caller_bytes'], actual['GOT_slot'], row['addend']),
                         (19, 0x576e008, 0x1571d90))
        for offset in (0, 13, 15):
            bad = bytearray(caller)
            bad[offset] ^= 1
            with self.subTest(caller_offset=offset), self.assertRaises(ValueError):
                subject.bind_edge(bytes(bad), [row], slot)
        for field, value in [('slot', row['slot'] + 8), ('kind', 9), ('symbol', 1),
                             ('addend', row['addend'] + 1)]:
            changed = {**row, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.bind_edge(caller, [changed], slot)
        for rows in ([], [row, row]):
            with self.assertRaises(ValueError):
                subject.bind_edge(caller, rows, slot)
        with self.assertRaises(ValueError):
            subject.bind_edge(caller, [row], b'\1' + bytes(7))

    def test_existing_empty_populated_and_broken_output_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / 'empty'
            empty.mkdir()
            occupied = root / 'occupied'
            occupied.mkdir()
            marker = occupied / 'marker'
            marker.write_bytes(b'preserve\n')
            link = root / 'broken'
            link.symlink_to(root / 'missing')
            for output in (empty, occupied, link):
                with self.subTest(path=output.name), self.assertRaisesRegex(ValueError, 'Output path'):
                    subject.collect(root / 'absent-node', root / 'absent-core', output)
            self.assertEqual(list(empty.iterdir()), [])
            self.assertEqual(marker.read_bytes(), b'preserve\n')
            self.assertTrue(link.is_symlink())
            wrong = root / 'wrong'
            wrong.write_bytes(b'not a captured node')
            output = root / 'new-output'
            with self.assertRaises(ValueError):
                subject.collect(wrong, root / 'absent-core', output)
            self.assertFalse(os.path.lexists(output))

    def test_immutable_admission_does_not_reopen_a_replaced_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'small-data'
            path.write_bytes(b'first')
            admitted = subject.admit_file(path, 5, hashlib.sha256(b'first').hexdigest())
            replacement = Path(temporary) / 'replacement'
            replacement.write_bytes(b'other')
            replacement.replace(path)
            self.assertIs(type(admitted), bytes)
            self.assertEqual(admitted, b'first')
            self.assertEqual(path.read_bytes(), b'other')
            with self.assertRaises(ValueError):
                subject.admit_file(path, 5, hashlib.sha256(b'first').hexdigest())

    def test_tiny_native_view_keeps_four_dynamic_transfers_open(self):
        if not subject.PROVIDER.is_file() or subject.sha(subject.PROVIDER.read_bytes()) != subject.PROVIDER_SHA256:
            self.skipTest('Exact native provider absent; raw/native facts not qualified here')
        _, result = subject.native_view(fixture('target.hex'))
        self.assertEqual((result['instruction_rows'], len(result['direct_local_branches'])), (138, 26))
        self.assertEqual((len(result['indirect_calls']), len(result['indirect_tail_jumps'])), (3, 1))
        self.assertEqual([r['address'] for r in result['indirect_calls']],
                         [0x1571e05, 0x1571e54, 0x1571ef6])
        self.assertEqual(result['indirect_tail_jumps'][0]['address'], 0x1571f39)
        self.assertEqual((result['RIP_relative_rows'], result['fixed_direct_external_calls']), ([], 0))


class ActualPublishedContainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE.is_file():
            raise unittest.SkipTest('Exact official archive absent; no actual archive qualification')
        cls.archive = subject.admit_file(ARCHIVE, subject.CORE_SIZE, subject.CORE_SHA256)
        cls.member = subject.containers.ar_members(cls.archive)[subject.MEMBER]
        cls.raw, cls.record = subject.source_leaf(cls.member)

    @classmethod
    def tearDownClass(cls):
        cls.archive = cls.member = cls.raw = cls.record = None

    def test_actual_complete_global_func_and_zero_code_relocations(self):
        symbol, section = self.record['symbol'], self.record['section']
        self.assertEqual((symbol['name'], symbol['info'], symbol['other']), (subject.NAME, 18, 0))
        self.assertEqual((symbol['value'], symbol['size'], section['size']), (0, 448, 448))
        self.assertEqual(self.raw, fixture('official.hex'))
        self.assertEqual(self.record['actual_code_RELA'], [])

    def test_actual_serialized_symbol_and_section_substitutions_reject_below_identity(self):
        image = subject.containers.Elf(self.member, 1)
        symbol, section = self.record['symbol'], self.record['section']
        symtab = image.section(symbol['symtab'])
        at = symtab['offset'] + 24 * symbol['index']
        shoff = struct.unpack_from('<Q', self.member, 40)[0]
        tests = [(at + 4, 'B', 17), (at + 5, 'B', 2), (at + 6, 'H', 0),
                 (at + 8, 'Q', 1), (at + 16, 'Q', 447),
                 (shoff + 64 * section['index'] + 4, 'I', 8),
                 (shoff + 64 * section['index'] + 8, 'Q', 2)]
        for offset, form, value in tests:
            changed = bytearray(self.member)
            struct.pack_into('<' + form, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.source_leaf(bytes(changed))

    def test_real_relocation_table_retargeting_cannot_create_a_mask(self):
        image = subject.containers.Elf(self.member, 1)
        shoff = struct.unpack_from('<Q', self.member, 40)[0]
        candidates = []
        for table in image.sections:
            if table['type'] == 4 and table['size'] and table['entsize'] == 24:
                entries = [struct.unpack_from('<QQq', self.member, offset)
                           for offset in range(table['offset'], table['offset'] + table['size'], 24)]
                if all(row[0] < 448 for row in entries):
                    candidates.append(table)
        self.assertTrue(candidates, 'Actual source has no eligible relocation control')
        table = candidates[0]
        for new_kind in (None, 2, 99):
            changed = bytearray(self.member)
            struct.pack_into('<I', changed, shoff + 64 * table['index'] + 44, self.record['section']['index'])
            if new_kind is not None:
                original_info = struct.unpack_from('<Q', changed, table['offset'] + 8)[0]
                struct.pack_into('<Q', changed, table['offset'] + 8, (original_info & ~0xffffffff) | new_kind)
            with self.subTest(kind=new_kind), self.assertRaisesRegex(ValueError, 'RELA.*masking'):
                subject.source_leaf(bytes(changed))
        for kind in (9, 19):
            changed = bytearray(self.member)
            struct.pack_into('<I', changed, shoff + 64 * table['index'] + 44, self.record['section']['index'])
            struct.pack_into('<I', changed, shoff + 64 * table['index'] + 4, kind)
            with self.subTest(format=kind), self.assertRaisesRegex(ValueError, 'unsupported relocation.*masking'):
                subject.source_leaf(bytes(changed))

    def test_real_member_code_change_is_an_unmasked_difference(self):
        changed = bytearray(self.member)
        changed[self.record['section']['offset'] + 447] ^= 1
        raw, meta = subject.source_leaf(bytes(changed))
        self.assertEqual(meta['actual_code_RELA'], [])
        result = subject.compare_raw(raw, fixture('target.hex'))
        self.assertFalse(result['raw_equal'])
        self.assertEqual((result['raw_differing_offsets'], result['normalization_masks']), ([447], []))

    def test_actual_linked_candidate_requires_executable_congruent_pt_load(self):
        path = BUILD / 'default/libpad_probe.so'
        if not path.is_file():
            self.skipTest('Exact retained default linked input absent')
        data = subject.admit_file(path, subject.RETAINED['default-linked'][1],
                                  subject.RETAINED['default-linked'][2])
        raw, metadata = subject.retained_leaf(data, 3)
        self.assertEqual(raw, fixture('official.hex'))
        image = subject.containers.Elf(data, 3)
        mapping = metadata['code_mapping']
        index = image.segments.index(mapping['PT_LOAD'])
        phoff = struct.unpack_from('<Q', data, 32)[0]
        for field, form, value in [(4, 'I', mapping['PT_LOAD']['flags'] & ~1),
                                   (8, 'Q', mapping['PT_LOAD']['offset'] + 1)]:
            changed = bytearray(data)
            struct.pack_into('<' + form, changed, phoff + 56 * index + field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.retained_leaf(bytes(changed), 3)


class ActualCapturedBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE.is_file() or not subject.TARGET.is_file() or subject.TARGET.stat().st_size != subject.TARGET_SIZE:
            raise unittest.SkipTest('Exact capture/archive unavailable; no actual capture qualification')
        cls.archive = subject.admit_file(ARCHIVE, subject.CORE_SIZE, subject.CORE_SHA256)
        data = capture_snapshot()
        cls.raw, cls.binding = subject.target_leaf(data)
        image = subject.containers.Elf(data, 3)
        cls.shoff = struct.unpack_from('<Q', data, 40)[0]
        cls.phoff = struct.unpack_from('<Q', data, 32)[0]
        cls.segment_index = image.segments.index(cls.binding['code_mapping']['PT_LOAD'])
        del image, data

    @classmethod
    def tearDownClass(cls):
        cls.archive = cls.raw = cls.binding = None

    def test_actual_used_edge_complete_fde_and_raw_correspondence(self):
        report, _ = subject.analyze(capture_snapshot(), self.archive)
        self.assertTrue(report['primary_comparison']['raw_equal'])
        self.assertEqual(report['source']['actual_code_RELA'], [])
        self.assertEqual(self.binding['frame']['FDE_raw_length_bytes'], 52)
        self.assertEqual(self.binding['frame']['bytes'], 448)
        self.assertEqual(self.raw, fixture('target.hex'))
        self.assertEqual(report['denominators'], {'new_primary_code_bytes': 448,
                         'revisited_caller_context_bytes': 19,
                         'accepted_primary1456_changed': False, 'prior_supporting114_changed': False})

    def test_actual_got_and_fde_header_substitutions_reject_below_identity(self):
        frame = self.binding['frame']
        row = self.binding['edge']['RELATIVE']
        tests = [(row['record_file_offset'] + 8, 'Q', 9),
                 (row['record_file_offset'] + 8, 'Q', (1 << 32) | 8),
                 (row['record_file_offset'] + 16, 'q', subject.START + 1),
                 (frame['FDE_range_file_offset'], 'I', 447),
                 (frame['FDE_file_offset'], 'I', 12),
                 (frame['FDE_augmentation_length_file_offset'], 'B', 1),
                 (frame['CIE_encoding_file_offset'], 'B', 0)]
        for offset, form, value in tests:
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                subject.target_leaf(capture_snapshot([(offset, form, value)]))

    def test_actual_mapping_changes_reject_and_code_changes_remain_raw(self):
        mapping = self.binding['code_mapping']
        section_offset = self.shoff + 64 * mapping['section']['index']
        with self.assertRaises(ValueError):
            subject.target_leaf(capture_snapshot([(section_offset + 8, 'Q', 2)]))
        with self.assertRaises(ValueError):
            subject.target_leaf(capture_snapshot([(self.phoff + 56 * self.segment_index + 4,
                                                  'I', mapping['PT_LOAD']['flags'] & ~1)]))
        with self.assertRaises(ValueError):
            subject.target_leaf(capture_snapshot([(self.phoff + 56 * self.segment_index + 8,
                                                  'Q', mapping['PT_LOAD']['offset'] + 1)]))
        report, _ = subject.derive(capture_snapshot([(mapping['file_offset'] + 447, 'B', self.raw[-1] ^ 1)]),
                                   self.archive)
        self.assertEqual(report['primary_comparison']['raw_differing_offsets'], [447])
        self.assertEqual(report['primary_comparison']['normalization_masks'], [])

    def test_actual_retained_artifacts_are_pinned_and_compared_without_linked_masks(self):
        paths = {'default-linked': BUILD / 'default/libpad_probe.so',
                 'thin-linked': BUILD / 'thin/libpad_probe.so',
                 'thin-object': BUILD / 'thin/pad_probe.core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o.rcgu.o'}
        if not all(p.is_file() for p in paths.values()):
            self.skipTest('Retained build inputs absent; no retained-build qualification')
        inputs = {name: subject.admit_file(p, subject.RETAINED[name][1], subject.RETAINED[name][2])
                  for name, p in paths.items()}
        data = capture_snapshot()
        report, _ = subject.analyze(data, self.archive, inputs)
        rows = report['retained_inputs_not_new_builds']
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row['comparison_to_source']['raw_equal'] for row in rows))
        self.assertTrue(all(row['comparison_to_source']['normalization_masks'] == [] for row in rows))
        for label in ('thin-object', 'default-linked'):
            changed = bytearray(inputs[label])
            changed[-1] ^= 1
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'Retained artifact identity'):
                subject.analyze(data, self.archive, {label: bytes(changed)})

    def test_exact_immutable_inputs_reproduce_the_same_report(self):
        data = capture_snapshot()
        first, exports = subject.analyze(data, self.archive)
        second, repeated = subject.analyze(data, self.archive)
        self.assertEqual((first, exports), (second, repeated))
        self.assertIs(type(data), bytes)


if __name__ == '__main__':
    unittest.main()
