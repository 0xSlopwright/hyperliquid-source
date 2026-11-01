import importlib.util
import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location(
    "exchange_dispatch", ROOT / "tools/exchange_dispatch.py")
ed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ed)

TOTAL = 512
RELA_OFF = 380
RELATIVE = 8


def make_elf(entries):
    """Elf with .rela.dyn and .shstrtab sections; .rela.dyn holds `entries`
    as (r_offset, r_info, r_addend) triples."""
    table = b'\x00.rela.dyn\x00.shstrtab\x00'
    data = bytearray(TOTAL)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 64)    # phoff
    struct.pack_into('<Q', data, 0x28, 128)   # shoff
    struct.pack_into('<HHHHH', data, 0x36, 56, 1, 64, 3, 2)
    # Program header: PT_LOAD, offset 0, VA 0x400000, filesz = TOTAL.
    struct.pack_into('<IIQQQQQQ', data, 64,
                     1, 0, 0, 0x400000, 0, TOTAL, 0, 0)
    # Section headers: null, .rela.dyn, .shstrtab.
    struct.pack_into('<IIQQQQIIQQ', data, 192,
                     1, 4, 0, 0x402000, RELA_OFF, 24 * len(entries),
                     0, 0, 8, 24)
    struct.pack_into('<IIQQQQIIQQ', data, 256,
                     11, 3, 0, 0, 340, len(table), 0, 0, 1, 0)
    data[340:340 + len(table)] = table
    for i, (r_off, info, add) in enumerate(entries):
        struct.pack_into('<QQq', data, RELA_OFF + 24 * i, r_off, info, add)
    return bytes(data)


class RelativeRelocsDuplicateTests(unittest.TestCase):
    """relative_relocs() folds .rela.dyn into a slot->addend dict. Two
    RELATIVE records for the same slot must be refused, not folded
    last-wins: the map resolves the call slots the classifier checks,
    so the surviving addend must not depend on record order."""

    def test_duplicate_slot_rejected_with_differing_addends(self):
        for entries in ([(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x2222)],
                        [(0x5000, RELATIVE, 0x2222), (0x5000, RELATIVE, 0x1111)]):
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(ed.EvidenceError,
                                            'duplicate RELATIVE relocation slot'):
                    ed.relative_relocs(ed.Elf(make_elf(entries)))

    def test_duplicate_slot_rejected_with_identical_addend(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5000, RELATIVE, 0x1111)]
        with self.assertRaisesRegex(ed.EvidenceError,
                                    'duplicate RELATIVE relocation slot'):
            ed.relative_relocs(ed.Elf(make_elf(entries)))

    def test_distinct_slots_still_parse(self):
        entries = [(0x5000, RELATIVE, 0x1111), (0x5008, RELATIVE, 0x2222)]
        self.assertEqual(ed.relative_relocs(ed.Elf(make_elf(entries))),
                         {0x5000: 0x1111, 0x5008: 0x2222})

    def test_non_relative_duplicate_offset_is_not_a_relocation(self):
        # The map only admits RELATIVE records; a repeated slot under a
        # different relocation type never enters it and must not raise.
        entries = [(0x5000, 6, 0x1111), (0x5000, 6, 0x2222),
                   (0x5008, RELATIVE, 0x3333)]
        self.assertEqual(ed.relative_relocs(ed.Elf(make_elf(entries))),
                         {0x5008: 0x3333})


if __name__ == "__main__":
    unittest.main()
