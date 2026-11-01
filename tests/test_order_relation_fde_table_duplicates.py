"""Synthetic ELF fixtures for tools/order_relation_transitions.py fde_table.

Fourth copy of the duplicate-FDE-start gap fixed by open #1084 (ntl),
#1087/#1088 (wei_saturating_ops) and open #1089 (match_resting_order):
fde_table required the search table to be sorted but never rejected equal
adjacent starts, and fde() bisects with bisect_right, so two entries naming
the same start VA kept the wider range and silently shadowed the narrower
FDE. tools/bincode_varint.py, consensus_wire.py, exchange_dispatch.py,
info_request_path.py and state_roots.py all already reject duplicate FDE
starts, so this copy is the divergent path.

No target binary is needed: Image() parses any blob passing its ELF checks,
so the fixture is a minimal ELF carrying .text and .eh_frame_hdr sections
plus one LOAD segment mapping VA == file offset. Each FDE body honestly
claims its start, so the existing begin cross-check in fde() passes.
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import order_relation_transitions as tool  # noqa: E402

BASE_VA = 0x400000
TEXT_VA, HDR_VA = 0x401000, 0x402000
S = HDR_VA + 0x100
S2 = HDR_VA + 0x200


def build(entries):
    blob = bytearray(0x5000)
    blob[0:5] = b"\x7fELF\x02"
    struct.pack_into("<H", blob, 18, 62)
    struct.pack_into("<QQ", blob, 32, 64, 0x1000)
    struct.pack_into("<HHHH", blob, 56, 1, 64, 4, 3)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0, BASE_VA, 0, 0x5000, 0, 0x1000)
    shstr = b"\0.text\0.eh_frame_hdr\0.shstrtab\0"
    blob[0x200:0x200 + len(shstr)] = shstr
    rows = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, TEXT_VA, 0x300, 0x100, 0, 0, 16, 0),
        (7, 1, 2, HDR_VA, 0x400, 0x100, 0, 0, 8, 0),
        (21, 3, 0, 0, 0x200, len(shstr), 0, 0, 1, 0),
    ]
    for i, row in enumerate(rows):
        struct.pack_into("<IIQQQQIIQQ", blob, 0x1000 + 64 * i, *row)
    hdr = 0x400
    blob[hdr:hdr + 4] = b"\x01\x1b\x03\x3b"
    struct.pack_into("<I", blob, hdr + 8, len(entries))
    for i, (start, size) in enumerate(entries):
        fde_va = HDR_VA + 0x200 + 0x100 * i
        struct.pack_into("<ii", blob, hdr + 12 + 8 * i, start - HDR_VA, fde_va - HDR_VA)
        struct.pack_into("<IIiI", blob, fde_va - BASE_VA, 20, 0, start - fde_va - 8, size)
    return bytes(blob)


class FdeTableDuplicateTests(unittest.TestCase):
    def test_duplicate_starts_with_different_ranges_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.Image(build([(S, 0x40), (S, 0x80), (S2, 0x30)]))

    def test_duplicate_starts_with_identical_ranges_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.Image(build([(S, 0x40), (S, 0x40)]))

    def test_distinct_starts_still_parse_and_fde_resolves(self):
        image = tool.Image(build([(S, 0x40), (S2, 0x30)]))
        self.assertEqual(image.starts, [S, S2])
        self.assertEqual(image.fde(S + 0x10), (S, S + 0x40))

    def test_unordered_distinct_entries_still_rejected_as_unsorted(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'unsorted'):
            tool.Image(build([(S2, 0x30), (S, 0x40)]))


if __name__ == '__main__':
    unittest.main()
