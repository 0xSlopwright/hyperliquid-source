"""Actual captured aggregate-output and caller controls; no target execution."""
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import hourly_rotation_static as hourly
from elf_index import sections


@unittest.skipUnless(hourly.TARGET.stat().st_size == 91774280, 'materialize node94')
class HourlyRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = hourly.TARGET.read_bytes()
        cls.report = hourly.analyze(cls.data)

    def test_actual_output_member_and_symbol_bindings(self):
        self.assertEqual([r['bytes'] for r in self.report['ranges']], [902, 387])
        self.assertEqual(self.report['aggregate_copy_bytes'], 176)
        self.assertEqual(self.report['member_copy_bytes'], 80)
        self.assertEqual(self.report['memcpy']['symbol'], 'memcpy')
        self.assertEqual(self.report['relative_bindings']['0x576ef78'], '0x14019b0')
        self.assertEqual(self.report['object_field_offsets']['mode_byte_store'], '0xa8')
        self.assertFalse(self.report['captured_binary_executed'])

    def test_pointer_width_return_and_cleanup_corruptions_rejected(self):
        for va in [0x14019c3, 0x1401a0f, 0x1401a1a, 0x1401b38,
                   0x1401b42, 0x1401b5a, 0x1401bcf, 0x1401bf9,
                   0x1401ca4, 0x1401784, 0x14017b7, 0x1e9396]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = hourly.locate(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    hourly.analyze(changed)

    def test_memcpy_and_entry_relocations_are_real_requirements(self):
        position = int(self.report['memcpy']['relocation_file_offset'], 16)
        changed = bytearray(self.data)
        changed[position + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'dynamic symbol'):
            hourly.analyze(changed)
        changed = bytearray(self.data)
        # Change the caller's GOT displacement, retaining the call opcode.
        offset, _ = hourly.locate(changed, 0x1401790, 1)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'target'):
            hourly.analyze(changed)

    @unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'), 'GNU binutils required')
    def test_native_packet_regenerates_identically(self):
        packet = ROOT / 'research/work-items/RE-001-hourly-rotation-abi-94'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(hourly.generate(hourly.TARGET, output), self.report)
            for name in ['records.json', 'frames.txt', '14019b0.objdump.txt', '14016d0.objdump.txt']:
                self.assertEqual((output / name).read_bytes(), (packet / name).read_bytes(), name)

    def test_wrong_capture_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.elf'
            path.write_bytes(b'not the capture')
            output = Path(directory) / 'out'
            with self.assertRaises(ValueError):
                hourly.generate(path, output)
            self.assertFalse(output.exists())


@unittest.skipUnless(hourly.TARGET.stat().st_size == 91774280, 'materialize node94')
class DuplicateSectionAndRelocationTests(unittest.TestCase):
    """analyze() reads .dynsym/.dynstr through a name->section dict that
    keeps only the last same-named section, and folds every SHT_RELA
    section into one RELATIVE slot map that likewise keeps the last
    entry. Duplicates must be refused: with a decoy .dynstr (or a decoy
    RELATIVE entry for a checked slot) first, the pinned checks silently
    ran against the real section/entry and passed; with it last, the
    same bytes were rejected for the decoy's contents — the verdict
    flipped on section order alone."""

    @classmethod
    def setUpClass(cls):
        cls.data = hourly.TARGET.read_bytes()

    def with_extra_section(self, name, section_type, blob, va, position):
        data = self.data
        shoff = struct.unpack_from('<Q', data, 40)[0]
        entsize, count, names_index = struct.unpack_from('<HHH', data, 58)
        raw = [data[shoff + i * entsize:shoff + (i + 1) * entsize]
               for i in range(count)]
        secs = sections(data)
        target = next(i for i, s in enumerate(secs) if s['name'] == name)
        name_off = struct.unpack_from('<I', raw[target], 0)[0]
        out = bytearray(data)
        blob_off = len(out)
        out += blob
        extra = struct.pack('<IIQQQQIIQQ', name_off, section_type, 0, va,
                            blob_off, len(blob), 0, 0, 1, 0)
        if position == 'first':
            rows = raw[:1] + [extra] + raw[1:]
            names_index += 1
        else:
            rows = raw + [extra]
        table_off = len(out)
        for row in rows:
            out += row
        struct.pack_into('<Q', out, 40, table_off)
        struct.pack_into('<HHH', out, 58, entsize, len(rows), names_index)
        return bytes(out)

    def decoy_dynstr(self):
        secs = sections(self.data)
        sym_index = None
        for section in secs:
            if section['type'] != 4:
                continue
            for pos in range(section['offset'],
                             section['offset'] + section['size'], 24):
                slot, info, _ = struct.unpack_from('<QQq', self.data, pos)
                if slot == 0x576dfe0:
                    sym_index = info >> 32
        self.assertIsNotNone(sym_index)
        dynsym = next(s for s in secs if s['name'] == '.dynsym')
        st_name = struct.unpack_from(
            '<I', self.data, dynsym['offset'] + sym_index * 24)[0]
        blob = bytearray(st_name + 7)
        blob[st_name:st_name + 7] = b'notcpy\0'
        return bytes(blob)

    def test_duplicate_dynstr_rejected_in_either_order(self):
        for position in ('first', 'last'):
            with self.subTest(position=position):
                changed = self.with_extra_section(
                    '.dynstr', 1, self.decoy_dynstr(), 0x7e000000, position)
                with self.assertRaisesRegex(ValueError,
                                            r'Duplicate section: \.dynstr'):
                    hourly.analyze(changed)

    def test_duplicate_dynsym_rejected(self):
        changed = self.with_extra_section(
            '.dynsym', 11, b'\0' * 24, 0x7e200000, 'last')
        with self.assertRaisesRegex(ValueError,
                                    r'Duplicate section: \.dynsym'):
            hourly.analyze(changed)

    def test_duplicate_relative_slot_rejected_in_either_order(self):
        decoy = struct.pack('<QQq', 0x576ef78, 8, 0xdead)
        for position in ('first', 'last'):
            with self.subTest(position=position):
                changed = self.with_extra_section(
                    '.rela.dyn', 4, decoy, 0x7e100000, position)
                with self.assertRaisesRegex(
                        ValueError,
                        'duplicate RELATIVE relocation slot 0x576ef78'):
                    hourly.analyze(changed)

    def test_duplicate_unconsumed_section_name_tolerated(self):
        changed = self.with_extra_section(
            '.comment', 1, b'decoy\0', 0x7e300000, 'last')
        report = hourly.analyze(changed)
        self.assertEqual(report['memcpy']['symbol'], 'memcpy')
        self.assertEqual(report['relative_bindings']['0x576ef78'],
                         '0x14019b0')


if __name__ == '__main__':
    unittest.main()
