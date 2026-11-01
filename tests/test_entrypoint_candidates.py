"""Malformed metadata controls and authenticated target census regression."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import entrypoint_candidates as ec
from test_fde_extents import build


def fixture(tags=None, rels=None):
    data = bytearray(0x500)
    struct.pack_into('<Q', data, 24, 0x1000)
    tags = tags if tags is not None else [(25, 0x2000), (27, 8), (0, 0)]
    rels = rels if rels is not None else [(0x2000, 8, 0x1000)]
    for i, row in enumerate(tags):
        struct.pack_into('<qQ', data, 0x100 + 16 * i, *row)
    for i, row in enumerate(rels):
        struct.pack_into('<QQq', data, 0x200 + 24 * i, *row)
    secs = [dict(name='.dynamic', type=6, flags=3, address=0x3000, offset=0x100, size=len(tags)*16, entsize=16),
            dict(name='.rela.dyn', type=4, flags=2, address=0x4000, offset=0x200, size=len(rels)*24, entsize=24),
            dict(name='.init_array', type=14, flags=3, address=0x2000, offset=0x300, size=16, entsize=8),
            dict(name='.text', type=1, flags=6, address=0x1000, offset=0x400, size=0x80, entsize=0)]
    return data, secs, [dict(start=0x1000, end=0x1010, section='.text')]


class MetadataControls(unittest.TestCase):
    def test_section_entry_width_is_read_without_shared_parser_changes(self):
        data, _ = build()
        self.assertTrue(all('entsize' in s for s in ec.section_headers(data)))

    def test_relative_and_raw_slots_are_distinct(self):
        data, secs, rows = fixture()
        result = ec.entrypoints(data, secs, rows)
        self.assertTrue(result['elf_entry']['on_fde_start'])
        self.assertEqual(result['DT_INIT_ARRAY']['entries_on_fde_start'], 1)
        secs[1]['size'] = 0
        result = ec.entrypoints(data, secs, rows)['DT_INIT_ARRAY']
        self.assertEqual(result['entries_on_fde_start'], 0)
        self.assertEqual(result['entries_not_on_fde_start'], [{'slot': 0x2000, 'target': 0}])
        struct.pack_into('<Q', data, 0x300, 0x1000)
        self.assertEqual(ec.entrypoints(data, secs, rows)['DT_INIT_ARRAY']['entries_on_fde_start'], 1)

    def test_zero_array_size_is_not_inferred_from_section_size(self):
        data, secs, rows = fixture([(25, 0x2000), (27, 0), (0, 0)])
        self.assertEqual(ec.entrypoints(data, secs, rows)['DT_INIT_ARRAY']['entries'], 0)

    def test_null_terminates_dynamic_tags(self):
        data, secs, rows = fixture([(0, 0), (25, 0x2000), (25, 3)])
        self.assertEqual(set(ec.entrypoints(data, secs, rows)), {'elf_entry'})

    def test_tag_controls(self):
        for tags, message in [([(25, 0x2000), (0, 0)], 'paired'),
                              ([(27, 8), (0, 0)], 'paired'),
                              ([(12, 0x1000), (12, 0x1000), (0, 0)], 'Duplicate'),
                              ([(12, 0x1000)], 'DT_NULL'),
                              ([(25, 0x2001), (27, 8), (0, 0)], 'aligned'),
                              ([(25, 0x2000), (27, 9), (0, 0)], 'aligned'),
                              ([(25, 0x2000), (27, 24), (0, 0)], 'wholly file backed'),
                              ([(25, 0x2000), (27, 4097*8), (0, 0)], 'explicit entry limit')]:
            with self.subTest(tags=tags), self.assertRaisesRegex(ValueError, message):
                ec.entrypoints(*fixture(tags))

    def test_dynamic_limit_is_explicit(self):
        with patch.object(ec, 'MAX_DYNAMIC_ENTRIES', 2), self.assertRaisesRegex(ValueError, 'explicit entry limit'):
            ec.entrypoints(*fixture())

    def test_table_controls(self):
        for index in (0, 1):
            for key, value in [('type', 8), ('entsize', 1), ('size', 1), ('offset', 0x500)]:
                data, secs, rows = fixture()
                secs[index][key] = value
                with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                    ec.entrypoints(data, secs, rows)
            data, secs, rows = fixture()
            secs.append(copy.deepcopy(secs[index]))
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                ec.entrypoints(data, secs, rows)

    def test_relocation_controls(self):
        for rels, message in [([(0x2000, 8, 0x1000)] * 2, 'Duplicate'),
                              ([(0x2000, (1 << 32) | 8, 0x1000)], 'symbol index'),
                              ([(0x2000, 6, 0x1000)], 'Unsupported')]:
            with self.subTest(rels=rels), self.assertRaisesRegex(ValueError, message):
                ec.entrypoints(*fixture(rels=rels))
        data, secs, rows = fixture(rels=[(0x2000, 0, 0), (0x2000, 8, 0x1000)])
        self.assertEqual(ec.entrypoints(data, secs, rows)['DT_INIT_ARRAY']['relocated_entries'], 1)

    def test_address_and_file_mapping_controls(self):
        data, secs, rows = fixture()
        for addr, size in [(-1, 1), (ec.U64, 1), (ec.U64 - 1, 2)]:
            with self.assertRaisesRegex(ValueError, 'Invalid virtual'):
                ec.section_for(secs, addr, size)
        secs.append(copy.deepcopy(secs[2]))
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            ec.entrypoints(data, secs, rows)
        secs.pop()
        secs[2]['offset'] = len(data)
        with self.assertRaisesRegex(ValueError, 'exceeds input'):
            ec.entrypoints(data, secs, rows)
        secs[2]['type'] = 8
        with self.assertRaisesRegex(ValueError, 'wholly file backed'):
            ec.entrypoints(data, secs, rows)


class RawCandidateControls(unittest.TestCase):
    def scan(self, positions, *, rows=None):
        data, secs, default_rows = fixture(tags=[(0, 0)], rels=[])
        rows = rows if rows is not None else default_rows
        gaps = [dict(start=0x1010, end=0x1080, section='.text', int3_only=False)]
        data[0x400:0x480] = b'\x90' * 128
        for pos, target in positions:
            struct.pack_into('<Bi', data, 0x400 + pos, 0xe8, target - (0x1000 + pos + 5))
        return data, secs, rows, gaps

    def test_buckets_and_candidates_inside_immediates(self):
        args = self.scan([(1, 0x1000), (8, 0x1004), (16, 0x1010), (24, 0x1011), (32, 0x2000)])
        # B8 E8 ... is a MOV immediate, but this intentionally byte-based scan counts E8.
        args[0][0x400] = 0xb8
        report, gaps = ec.raw_e8_targets(*args)
        self.assertEqual(report['totals'], dict(fde_start=1, fde_interior=1, gap_start=1, gap_interior=1, outside_executable=1))
        self.assertEqual(gaps['.text']['gaps_with_candidates'], 1)

    def test_section_end_and_nobits(self):
        args = self.scan([(123, 0x1000)])
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {'fde_start': 1})
        args[0][0x47b] = 0x90
        args[0][0x47c] = 0xe8
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {})
        args = self.scan([(0, 0x1000)])
        args[1][-1]['type'] = 8
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {})

    def test_overlapping_fde_membership_uses_union(self):
        rows = [dict(start=0x1000, end=0x1040, section='.text'), dict(start=0x1010, end=0x1020, section='.text')]
        args = self.scan([(0, 0x1030)], rows=rows)
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {'fde_interior': 1})

    def test_sections_without_fdes_and_u64_wrap(self):
        args = self.scan([(0, 0x1000)], rows=[])
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {'section_without_fdes': 1})
        args = self.scan([])
        args[1][-1]['address'] = ec.U64 - 128
        struct.pack_into('<Bi', args[0], 0x400, 0xe8, 124)
        args[1].append(dict(name='.low', type=1, flags=6, address=0, size=8, offset=0x350))
        self.assertEqual(ec.raw_e8_targets(*args)[0]['totals'], {'section_without_fdes': 1})


class TargetCensus(unittest.TestCase):
    def test_authenticated_reports_and_original_counts(self):
        packet = ROOT / 'research/work-items/RE-001-entrypoints'
        for release in ('94', '115'):
            with self.subTest(release=release):
                original = json.loads((packet / f'node-{release}-entrypoints.json').read_text())
                data = (ROOT / f'artifacts/node/{release}/hl-node').read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), original['binary_sha256'])
                current = ec.analyze(data)
                # Native readelf/objdump cross-check: the startup FDE includes
                # the argument setup, six-byte indirect call and final HLT.
                _, fdes, gaps = ec.fde_extents(data)
                entry = current['entrypoints']['elf_entry']['address']
                row = next(f for f in fdes if f['start'] == entry)
                self.assertEqual(row['end'], entry + 38)
                headers = ec.section_headers(data)
                self.assertEqual(ec.read_va(data, headers, entry + 37, 1), b'\xf4')
                gap = next(g for g in gaps if g['start'] == row['end'])
                blob = ec.read_va(data, headers, gap['start'], gap['end'] - gap['start'])
                offsets = [i for i in range(len(blob)) if blob.startswith(b'\xf3\x0f\x1e\xfa', i)]
                exceptions = [current['entrypoints'][name]['entries_not_on_fde_start'][0]['target']
                              for name in ('DT_FINI_ARRAY', 'DT_INIT_ARRAY')]
                self.assertEqual([gap['start'] + i for i in offsets], exceptions)
                self.assertEqual(current, json.loads((packet / f'node-{release}-entrypoint-candidates.json').read_text()))
                self.assertEqual(current['raw_e8_candidates'], original['direct_e8_call_targets'])
                for key in ('fde_records', 'executable_sections', 'same_section_gaps'):
                    self.assertEqual(current[key], original[key])
                for name, value in original['entrypoints'].items():
                    self.assertEqual({k: current['entrypoints'][name][k] for k in value}, value)
                old = original['gaps_reached_by_direct_calls']['.text']
                new = current['gaps_with_raw_e8_targets']['.text']
                self.assertEqual(list(old.values()), list(new.values()))


if __name__ == '__main__':
    unittest.main()
