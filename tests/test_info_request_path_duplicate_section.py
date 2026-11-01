"""info_request_path.Elf must refuse repeated section names instead of keeping the last one."""
import struct
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import info_request_path as tool  # noqa: E402


def synthetic_elf(text_rows, name='.text'):
    """Minimal ELF64 with one PT_LOAD, .shstrtab and the given (address, size) rows named `name`."""
    names = b"\0.shstrtab\0" + name.encode() + b"\0"
    phoff, shoff = 64, 128
    shnum = 2 + len(text_rows)
    header = bytearray(64)
    header[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 2, 62, 1, 0, phoff, shoff, 0, 64, 56, 1, 64, shnum, 1)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000).ljust(64, b"\0")
    stroff = shoff + shnum * 64
    rows = [bytes(64), struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, stroff, len(names), 0, 0, 1, 0)]
    rows += [struct.pack("<IIQQQQIIQQ", 11, 1, 6, addr, 0, size, 0, 0, 16, 0) for addr, size in text_rows]
    return bytes(header) + program + b"".join(rows) + names


class DuplicateSectionNameTests(unittest.TestCase):
    def test_duplicate_consumed_section_rejected_in_either_order(self):
        for name in ('.data.rel.ro', '.eh_frame_hdr', '.rela.dyn', '.rodata', '.text'):
            for rows in ([(0x1000, 0x10), (0x2000, 0x20)], [(0x2000, 0x20), (0x1000, 0x10)]):
                with self.subTest(name=name, rows=rows):
                    with self.assertRaisesRegex(tool.EvidenceError, "duplicate section name " + re.escape(name)):
                        tool.Elf(synthetic_elf(rows, name=name))

    def test_identical_duplicate_consumed_section_is_still_ambiguous(self):
        for name in ('.data.rel.ro', '.eh_frame_hdr', '.rela.dyn', '.rodata', '.text'):
            with self.subTest(name=name), self.assertRaisesRegex(tool.EvidenceError, "duplicate section name " + re.escape(name)):
                tool.Elf(synthetic_elf([(0x1000, 0x10), (0x1000, 0x10)], name=name))

    def test_repeated_empty_names_are_not_consumed_sections(self):
        elf = tool.Elf(synthetic_elf([(0x1000, 0x10), (0x2000, 0x20)], name=""))
        self.assertEqual(elf.section(""), (0x2000, 0, 0x20))

    def test_single_section_still_parses(self):
        elf = tool.Elf(synthetic_elf([(0x1000, 0x10)]))
        self.assertEqual(elf.section('.text'), (0x1000, 0, 0x10))

    def test_duplicate_unconsumed_section_tolerated(self):
        elf = tool.Elf(synthetic_elf([(0x1000, 0x10), (0x2000, 0x20)], name=".comment"))
        self.assertIn(".comment", elf.sections)


if __name__ == "__main__":
    unittest.main()
