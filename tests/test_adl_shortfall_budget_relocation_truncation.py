"""Synthetic-ELF controls for adl_shortfall_budget.Image.load_relocs truncation.

load_relocs() steps the named .rela.dyn section by 24 bytes with no
remainder check, so a section ending in a partial ELF64 Rela entry is
silently accepted: the partial entry is completed from whatever bytes
follow the section in the file, and — when those bytes form a RELATIVE
(type 8) entry — a bogus slot is stored as if the input were
well-formed. A trailing byte at the end of the file escapes as a raw
struct.error instead of a tooling error. The sibling adl_core parser
already rejects this case with a truncation error (own open #1185), as
do book_mid_sampler (own open #1239) and the other single-section
siblings listed in that PR.

The real node #94 binary is an LFS pointer on this machine, so these
tests build a minimal ELF64-LE document in memory. Image() itself has no
digest gate, and its .eh_frame requirement is satisfied with a single
zero-length terminator record. Note the layout difference from the
book_mid_sampler harness: adl_shortfall_budget keeps only sections with
a nonzero address, so .rela.dyn and .text carry addresses here, and the
bytes following .rela.dyn are the .text bytes (whose contents are
unparsed, unlike .eh_frame).
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from adl_shortfall_budget import Image, ToolError  # noqa: E402

SLOT = 0x6000
SHSTR = b'\x00.rela.dyn\x00.eh_frame\x00.shstrtab\x00.text\x00'


def header_and_rows(shoff, shnum, shstrndx, rela_off, rela_size, eh_frame_off,
                    eh_frame_size, shstr_off, text_off, text_size):
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0x5000, rela_off, rela_size, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, eh_frame_off, eh_frame_size, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 21, 3, 0, 0, shstr_off, len(SHSTR), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 31, 1, 0, 0x4000, text_off, text_size, 0, 0, 0, 0)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, shnum, shstrndx)
    return bytes(header), rows


def build(rela_size, rela, text):
    """ELF with .rela.dyn followed by .text bytes, so a partial entry is
    completed from the (unparsed) .text contents on base."""
    shstr_off = 64
    shoff = shstr_off + len(SHSTR)
    eh_frame = b'\x00' * 32
    eh_frame_off = shoff + 5 * 64
    rela_off = eh_frame_off + len(eh_frame)
    text_off = rela_off + len(rela)
    header, rows = header_and_rows(shoff, 5, 3, rela_off, rela_size,
                                   eh_frame_off, len(eh_frame), shstr_off,
                                   text_off, len(text))
    return header + SHSTR + rows + eh_frame + rela + text


def pack(entries):
    return b''.join(struct.pack('<QQq', slot, info, addend) for slot, info, addend in entries)


def load_relocs(data):
    return Image(data).load_relocs()


class AdlShortfallBudgetRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_section_returns_entries(self):
        rows = load_relocs(build(24, pack([(SLOT, 8, 0x1234)]), b'\x00' * 16))
        self.assertEqual(rows, {SLOT: 0x1234})

    def test_trailing_byte_at_end_of_file_rejected(self):
        # .rela.dyn is last in file order here: the partial entry has no
        # following bytes, so base escapes as raw struct.error.
        shstr_off = 64
        shoff = shstr_off + len(SHSTR)
        eh_frame = b'\x00' * 32
        eh_frame_off = shoff + 5 * 64
        text = b'\x00' * 16
        text_off = eh_frame_off + len(eh_frame)
        rela = pack([(SLOT, 8, 0x1234)]) + b'\x00'
        rela_off = text_off + len(text)
        header, rows = header_and_rows(shoff, 5, 3, rela_off, 25,
                                       eh_frame_off, len(eh_frame),
                                       shstr_off, text_off, len(text))
        data = header + SHSTR + rows + eh_frame + text + rela
        with self.assertRaisesRegex(ToolError, 'truncated RELA section'):
            load_relocs(data)

    def test_partial_entry_completed_from_following_bytes_rejected(self):
        # Declared size 32 = one full entry plus an 8-byte where-part;
        # the loop's second step reads the info/addend from the following
        # .text bytes, which are crafted as a RELATIVE entry, so base
        # silently stores a bogus slot.
        text = struct.pack('<Q', 8) + struct.pack('<q', 0x7777)
        data = build(32, pack([(SLOT, 8, 0x1234)]) + struct.pack('<Q', 0x9999), text)
        with self.assertRaisesRegex(ToolError, 'truncated RELA section'):
            load_relocs(data)


if __name__ == '__main__':
    unittest.main()
