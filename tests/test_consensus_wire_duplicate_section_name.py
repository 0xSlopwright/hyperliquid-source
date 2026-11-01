"""consensus_wire Elf: a duplicate section name must fail as EvidenceError.

Elf.__init__ stores sections in a dict keyed by name, so an ELF carrying
two sections with the same name silently kept only the last one, and every
later section() lookup read whichever duplicate happened to come last.
The sibling parsers refuse the ambiguity instead: bincode_varint
(#1025), build_provenance (#984), elf_index (#989), fde_extents (#994),
and foundation_millis (#520) all raise "Duplicate section: <name>".
No open PR covers the duplicate-name case in this file.
"""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)


def elf_bytes(duplicate=False):
    data = bytearray(1024)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)      # phoff, no program headers
    struct.pack_into('<Q', data, 0x28, 512)    # shoff
    names = b'\0.shstrtab\0.text\0'
    data[64:64 + len(names)] = names
    text_off = names.index(b'.text')
    entries = [(0, 0, 0, 0, 0, 0),
               (1, 3, 0, 0, 64, len(names)),
               (text_off, 1, 6, 0x1000, 256, 32)]
    if duplicate:
        entries.append((text_off, 1, 6, 0x9000, 768, 99))
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, len(entries), 1)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *e, 0, 0, 1, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_valid_names_parse(self):
        elf = cw.Elf(elf_bytes())
        self.assertEqual(sorted(elf.sections),
                         ['', '.shstrtab', '.text'])
        self.assertEqual(elf.section('.text'), (0x1000, 256, 32))

    def test_duplicate_section_name_is_evidence_error(self):
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(elf_bytes(duplicate=True))

    def test_duplicate_section_name_is_not_silently_collapsed(self):
        try:
            elf = cw.Elf(elf_bytes(duplicate=True))
        except cw.EvidenceError:
            return
        self.fail('duplicate section name silently collapsed to %r'
                  % (elf.section('.text'),))


if __name__ == '__main__':
    unittest.main()
