"""order_relation_transitions Image: a duplicate section name must fail.

Image.__init__ stores sections in a dict keyed by name with a plain
overwrite, so an ELF carrying two `.text` sections silently kept only the
last one, and `self.text`, `fde_table` and every later section lookup read
the duplicate. The sibling parsers refuse the ambiguity instead:
consensus_wire (#1125), exchange_dispatch (#1148), info_request_path
(#1147) and state_roots (#1146) all raise on a repeated section name, and
action_signable is covered by #1166. No open or merged PR covers the
duplicate-name case in this file.

No target binary is needed: Image() parses any blob passing its ELF checks,
so the fixture is a minimal ELF carrying .text and .eh_frame_hdr (empty
search table) plus one LOAD segment mapping VA == file offset.
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


def build(duplicate=False):
    blob = bytearray(0x5000)
    blob[0:5] = b"\x7fELF\x02"
    struct.pack_into("<H", blob, 18, 62)
    struct.pack_into("<QQ", blob, 32, 64, 0x1000)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0, BASE_VA, 0, 0x5000, 0, 0x1000)
    shstr = b"\0.text\0.eh_frame_hdr\0.shstrtab\0"
    blob[0x200:0x200 + len(shstr)] = shstr
    rows = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, TEXT_VA, 0x300, 0x100, 0, 0, 16, 0),
        (7, 1, 2, HDR_VA, 0x400, 0x100, 0, 0, 8, 0),
        (21, 3, 0, 0, 0x200, len(shstr), 0, 0, 1, 0),
    ]
    if duplicate:
        rows.append((1, 1, 6, 0x409000, 0x900, 0x99, 0, 0, 16, 0))
    struct.pack_into("<HHHH", blob, 56, 1, 64, len(rows), 3)
    for i, row in enumerate(rows):
        struct.pack_into("<IIQQQQIIQQ", blob, 0x1000 + 64 * i, *row)
    blob[0x400:0x404] = b"\x01\x1b\x03\x3b"
    struct.pack_into("<I", blob, 0x408, 0)
    return bytes(blob)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_single_sections_parse(self):
        image = tool.Image(build())
        self.assertEqual(image.text, {"addr": TEXT_VA, "offset": 0x300, "size": 0x100})
        self.assertEqual(image.starts, [])

    def test_duplicate_section_name_is_evidence_error(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate section name'):
            tool.Image(build(duplicate=True))

    def test_duplicate_section_name_is_not_silently_collapsed(self):
        try:
            image = tool.Image(build(duplicate=True))
        except tool.EvidenceError:
            return
        self.fail('duplicate section name silently collapsed to %r' % (image.text,))


if __name__ == '__main__':
    unittest.main()
