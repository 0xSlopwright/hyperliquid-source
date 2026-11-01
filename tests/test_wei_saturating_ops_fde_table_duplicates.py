"""Synthetic .eh_frame_hdr fixtures for tools/wei_saturating_ops.py fde_table.

Sibling of open #1084, which fixed the same duplicate-start gap in
tools/ntl_ten_thousand_add.py and explicitly left this byte-identical copy
untouched: fde_table sorted its rows and enclosing() bisects them, so two
entries naming the same start VA kept the wider range and silently shadowed
the narrower FDE. tools/bincode_varint.py, consensus_wire.py,
exchange_dispatch.py, info_request_path.py and state_roots.py all already
reject duplicate FDE starts, so this copy is the divergent path.

No target binary is needed: the blob is laid out in the tool's own format
(header at HDR_VA, VA == offset, each FDE body honestly claiming its start).
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import wei_saturating_ops as tool  # noqa: E402

HDR = tool.HDR_VA
S = HDR + 0x1000
S2 = HDR + 0x2000


def build(entries):
    blob = bytearray(HDR + 0x5000)
    struct.pack_into('<4B', blob, HDR, 1, 0x1b, 0x03, 0x3b)
    struct.pack_into('<I', blob, HDR + 8, len(entries))
    for i, (start, size) in enumerate(entries):
        fde = HDR + 0x3000 + 0x100 * i
        struct.pack_into('<ii', blob, HDR + 12 + 8 * i, start - HDR, fde - HDR)
        struct.pack_into('<iI', blob, fde + 8, start - fde - 8, size)
    return bytes(blob)


class FdeTableDuplicateTests(unittest.TestCase):
    def test_duplicate_starts_with_different_ranges_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.fde_table(build([(S, 0x40), (S, 0x80), (S2, 0x30)]))

    def test_duplicate_starts_with_identical_ranges_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate FDE start'):
            tool.fde_table(build([(S, 0x40), (S, 0x40)]))

    def test_distinct_starts_still_parse_and_enclosing_resolves(self):
        table = tool.fde_table(build([(S, 0x40), (S2, 0x30)]))
        self.assertEqual(table, [(S, S + 0x40), (S2, S2 + 0x30)])
        starts = [item[0] for item in table]
        self.assertEqual(tool.enclosing(table, starts, S + 0x10), (S, S + 0x40))

    def test_unordered_distinct_entries_still_sorted(self):
        table = tool.fde_table(build([(S2, 0x30), (S, 0x40)]))
        self.assertEqual(table, [(S, S + 0x40), (S2, S2 + 0x30)])


if __name__ == '__main__':
    unittest.main()
