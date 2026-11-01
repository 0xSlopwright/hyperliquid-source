"""relocation_slots() must refuse a slot bound twice in .rela.dyn.

Sibling of open #1098 (api_suffix_static): that packet built its
RELATIVE-relocation map with a plain overwrite, so a later duplicate
entry carrying the expected addend masked a corrupted genuine entry and
the map-value check passed. order_relation_transitions.relocation_slots()
has the same shape — a plain overwrite keyed by slot — and its only
caller pins a binding from the returned map
(`slots[GOT_MEMCPY]["symbol"] != "memcpy"`). A genuine entry binding the
slot to another symbol, followed by a duplicate entry binding it to
'memcpy', passes that check on base: the duplicate silently decides
which binding the report certifies. The foundation packets already
reject duplicate relocation addresses; this helper never adopted a guard.

No target binary is needed: Image() parses any blob passing its ELF
checks, so the fixture is a minimal ELF carrying .text and
.eh_frame_hdr sections plus .rela.dyn/.dynsym/.dynstr sections. The
symbol names resolve through the fixture's own .dynsym/.dynstr, exactly
as the tool resolves them.
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
SLOT = 0x600000


def build(rela_entries):
    """rela_entries: list of (slot, symbol_index, addend)."""
    blob = bytearray(0x5000)
    blob[0:5] = b"\x7fELF\x02"
    struct.pack_into("<H", blob, 18, 62)
    struct.pack_into("<QQ", blob, 32, 64, 0x1000)
    struct.pack_into("<HHHH", blob, 56, 1, 64, 7, 6)
    struct.pack_into("<IIQQQQQQ", blob, 64, 1, 5, 0, BASE_VA, 0, 0x5000, 0, 0x1000)
    shstr = b"\0.text\0.eh_frame_hdr\0.rela.dyn\0.dynsym\0.dynstr\0.shstrtab\0"
    blob[0x200:0x200 + len(shstr)] = shstr
    # Name offsets inside shstr.
    names = {}
    off = 1
    for name in (".text", ".eh_frame_hdr", ".rela.dyn", ".dynsym", ".dynstr", ".shstrtab"):
        names[name] = off
        off += len(name) + 1
    rows = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (names[".text"], 1, 6, TEXT_VA, 0x300, 0x100, 0, 0, 16, 0),
        (names[".eh_frame_hdr"], 1, 2, HDR_VA, 0x400, 0x100, 0, 0, 8, 0),
        (names[".rela.dyn"], 4, 2, 0, 0x600, 24 * len(rela_entries), 0, 0, 8, 0),
        (names[".dynsym"], 11, 2, 0, 0x700, 24 * 3, 0, 0, 8, 0),
        (names[".dynstr"], 3, 2, 0, 0x800, 14, 0, 0, 1, 0),
        (names[".shstrtab"], 3, 0, 0, 0x200, len(shstr), 0, 0, 1, 0),
    ]
    for i, row in enumerate(rows):
        struct.pack_into("<IIQQQQIIQQ", blob, 0x1000 + 64 * i, *row)
    hdr = 0x400
    blob[hdr:hdr + 4] = b"\x01\x1b\x03\x3b"
    struct.pack_into("<I", blob, hdr + 8, 1)
    struct.pack_into("<ii", blob, hdr + 12, TEXT_VA - HDR_VA, 0)
    dynstr = b"\0memcpy\0other\0"
    blob[0x800:0x800 + len(dynstr)] = dynstr
    # .dynsym entries: index 0 null, 1 -> 'memcpy' (name offset 1),
    # 2 -> 'other' (name offset 8).
    struct.pack_into("<I", blob, 0x700 + 24 * 1, 1)
    struct.pack_into("<I", blob, 0x700 + 24 * 2, 8)
    for i, (slot, sym, addend) in enumerate(rela_entries):
        struct.pack_into("<QQq", blob, 0x600 + 24 * i, slot, (sym << 32) | 6, addend)
    return bytes(blob)


def slots(rela_entries):
    return tool.Image(build(rela_entries)).relocation_slots({SLOT})


class RelocationSlotDuplicateTests(unittest.TestCase):
    def test_duplicate_slot_rejected(self):
        # Genuine entry binds SLOT to 'other'; a later duplicate binds it
        # to 'memcpy'. On base, relocation_slots() returns the duplicate's
        # binding, so the caller's `symbol != "memcpy"` check passes and
        # the report certifies a binding the genuine entry does not make.
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate relocation slot'):
            slots([(SLOT, 2, 0x1000), (SLOT, 1, 0x1000)])

    def test_exact_duplicate_slot_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'duplicate relocation slot'):
            slots([(SLOT, 1, 0x1000), (SLOT, 1, 0x1000)])

    def test_single_binding_still_resolves(self):
        found = slots([(SLOT, 1, 0x1000)])
        self.assertEqual(found[SLOT]["symbol"], "memcpy")
        self.assertEqual(found[SLOT]["addend"], 0x1000)

    def test_unwatched_slot_duplicates_ignored(self):
        # Duplicates of slots the caller did not ask about decide nothing.
        found = slots([(SLOT, 1, 0x1000), (0x600008, 2, 0x2000), (0x600008, 1, 0x2000)])
        self.assertEqual(found[SLOT]["symbol"], "memcpy")


if __name__ == '__main__':
    unittest.main()
