"""decimal_scaled_u64 Image: a duplicate section name must fail.

Image.__init__ stores sections in a dict keyed by name with a plain
overwrite, so an ELF carrying two `.rodata` sections silently kept only
the last one, and `self.rodata`, `read_only` and every later section
lookup read the duplicate. The sibling parsers refuse the ambiguity
instead: consensus_wire (#1125), exchange_dispatch (#1148),
info_request_path (#1147) and state_roots (#1146) all raise on a repeated
section name, and wire_asset_codec is covered by #1170. No open or merged
PR covers the duplicate-name case in this file.

No target binary is needed: Image() parses any blob passing its ELF checks,
so the fixture is a minimal ELF carrying .text, .rodata, .eh_frame_hdr
(empty search table, encoding byte 0x3b) and a .rela.dyn holding exactly
the NOTE and panic slots Image.__init__ reads, plus one entry for each.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import decimal_scaled_u64 as tool  # noqa: E402


def build(duplicate=False):
    names = b"\0.shstrtab\0.text\0.rodata\0.eh_frame_hdr\0.rela.dyn\0"
    data = bytearray(4096)
    data[:5] = b"\x7fELF\x02"
    struct.pack_into("<Q", data, 0x28, 512)

    def off(name):
        return names.index(name.encode())

    rela_off = 2048
    slots = [tool.SLOT_NOTE] + list(tool.SLOTS_PANIC)
    for i, slot in enumerate(slots):
        struct.pack_into("<QQq", data, rela_off + i * 24, slot, 8, 0)
    rows = [
        (0, 0, 0, 0, 0, 0),
        (off('.shstrtab'), 3, 0, 0, 64, len(names)),
        (off('.text'), 1, 6, 0x1000, 256, 32),
        (off('.rodata'), 1, 2, 0x2000, 512, 16),
        (off('.eh_frame_hdr'), 1, 2, 0x3000, 1024, 16),
        (off('.rela.dyn'), 4, 2, 0x4000, rela_off, 7 * 24),
    ]
    if duplicate:
        rows.append((off('.rodata'), 1, 2, 0x9000, 3072, 99))
    struct.pack_into("<HHH", data, 0x3a, 64, len(rows), 1)
    for i, row in enumerate(rows):
        struct.pack_into("<IIQQQQIIQQ", data, 512 + i * 64, *row, 0, 0, 1, 0)
    data[64:64 + len(names)] = names
    data[1024 + 3] = 0x3b
    struct.pack_into("<I", data, 1024 + 8, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_single_sections_parse(self):
        image = tool.Image(build())
        self.assertEqual(image.rodata, (0x2000, 512, 16))
        self.assertEqual((image.text_va, image.text_off, image.text_size),
                         (0x1000, 256, 32))
        self.assertEqual(image.starts, [])

    def test_duplicate_section_name_is_tool_error(self):
        with self.assertRaisesRegex(tool.ToolError, 'duplicate section name'):
            tool.Image(build(duplicate=True))

    def test_duplicate_section_name_is_not_silently_collapsed(self):
        try:
            image = tool.Image(build(duplicate=True))
        except tool.ToolError:
            return
        self.fail('duplicate section name silently collapsed to %r'
                  % (image.rodata,))


if __name__ == '__main__':
    unittest.main()
