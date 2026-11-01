"""action_signable Elf: a duplicate section name must fail as EvidenceError.

Elf.__init__ stores sections in a dict keyed by name, so an ELF carrying
two sections with the same name silently kept only the last one, and every
later lookup (e.g. '.rodata' for rodata_hits, '.text' for disassembly)
read whichever duplicate happened to come last. The sibling parsers refuse
the ambiguity instead: consensus_wire (#1125), exchange_dispatch (#1148),
info_request_path (#1147) and state_roots (#1146) all raise on a repeated
section name. No open or merged PR covers the duplicate-name case in
this file.
"""
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "action_signable", ROOT / "tools/action_signable.py")
asg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asg)


def elf_bytes(duplicate=False):
    names = (b'\0.shstrtab\0.text\0.rodata\0.data.rel.ro\0.rela.dyn'
             b'\0.eh_frame_hdr\0.dynsym\0.dynstr\0')
    data = bytearray(2048)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)      # phoff, no program headers
    struct.pack_into('<Q', data, 0x28, 512)    # shoff
    data[64:64 + len(names)] = names

    def off(name):
        return names.index(name.encode())

    rows = [(0, 0, 0, 0, 0, 0),
            (off('.shstrtab'), 3, 0, 0, 64, len(names)),
            (off('.text'), 1, 6, 0x1000, 256, 32),
            (off('.rodata'), 1, 2, 0x2000, 512, 16),
            (off('.data.rel.ro'), 1, 2, 0x3000, 768, 16),
            (off('.rela.dyn'), 4, 2, 0x4000, 1024, 24),
            (off('.eh_frame_hdr'), 1, 2, 0x5000, 1280, 16),
            (off('.dynsym'), 11, 2, 0x6000, 1536, 24),
            (off('.dynstr'), 3, 2, 0x7000, 1792, 16)]
    if duplicate:
        rows.append((off('.rodata'), 1, 2, 0x9000, 1900, 99))
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, len(rows), 1)
    for i, row in enumerate(rows):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *row, 0, 0, 1, 0)
    return bytes(data)


class DuplicateSectionNameTests(unittest.TestCase):
    def test_single_sections_parse(self):
        elf = asg.Elf(elf_bytes())
        self.assertEqual(elf.sections['.rodata'], (0x2000, 512, 16))
        self.assertEqual(elf.sections['.text'], (0x1000, 256, 32))

    def test_duplicate_section_name_is_evidence_error(self):
        with self.assertRaises(asg.EvidenceError):
            asg.Elf(elf_bytes(duplicate=True))

    def test_duplicate_section_name_is_not_silently_collapsed(self):
        try:
            elf = asg.Elf(elf_bytes(duplicate=True))
        except asg.EvidenceError:
            return
        self.fail('duplicate section name silently collapsed to %r'
                  % (elf.sections['.rodata'],))


if __name__ == '__main__':
    unittest.main()
