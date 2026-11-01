"""Synthetic-ELF controls for bole_liquidation_step.Image.relocations truncation.

relocations() steps the named .rela.dyn section by 24 bytes with no
remainder check, so a section ending in a partial ELF64 Rela entry is
silently accepted: the partial entry is completed from whatever bytes
follow the section in the file, and a bogus (slot, type, addend, symbol)
row is yielded as if the input were well-formed. A trailing byte at the
end of the file escapes as a raw struct.error instead of a tooling error.
The sibling adl_core parser already rejects this case with a truncation
error (own open #1185), as do block_admission_path (own open #1189),
bole_borrow_rate (own open #1193), and bole_generated_px (own open #1196).

The real node #94 binary is an LFS pointer on this machine, so these
tests build a minimal ELF64-LE document in memory. Image() itself has no
digest gate (the digest check lives in load_image()), and its .eh_frame
requirement is satisfied with a single zero-length terminator record.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from bole_liquidation_step import EvidenceError, Image  # noqa: E402

SLOT = 0x5000


def build(rela_size, rela, eh_frame=b'\x00' * 32):
    """ELF with .rela.dyn of declared size rela_size followed by a
    terminator-only .eh_frame, so Image() construction succeeds."""
    shstr = b'\x00.rela.dyn\x00.eh_frame\x00.shstrtab\x00'
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    rela_off = shoff + 4 * 64
    eh_frame_off = rela_off + len(rela)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 4, 3)
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, rela_size, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, eh_frame_off, len(eh_frame), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 21, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    return bytes(header) + shstr + rows + rela + eh_frame


def pack(entries):
    return b''.join(struct.pack('<QQq', slot, info, addend) for slot, info, addend in entries)


def relocations(data):
    return list(Image(data).relocations())


class BoleLiquidationStepRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_section_returns_entries(self):
        rows = relocations(build(24, pack([(SLOT, 8, 0x1234)])))
        self.assertEqual(rows, [(SLOT, 8, 0x1234, 0)])

    def test_trailing_byte_at_end_of_file_rejected(self):
        # .rela.dyn is last in file order here: the partial entry has no
        # following bytes, so base escapes as raw struct.error.
        shstr = b'\x00.rela.dyn\x00.eh_frame\x00.shstrtab\x00'
        shstr_off = 64
        shoff = shstr_off + len(shstr)
        eh_frame = b'\x00' * 32
        eh_frame_off = shoff + 4 * 64
        rela = pack([(SLOT, 8, 0x1234)]) + b'\x00'
        rela_off = eh_frame_off + len(eh_frame)
        header = bytearray(64)
        header[0:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', header, 40, shoff)
        struct.pack_into('<HHH', header, 58, 64, 4, 3)
        rows = b''
        rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, 25, 0, 0, 0, 0)
        rows += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, eh_frame_off, len(eh_frame), 0, 0, 0, 0)
        rows += struct.pack('<IIQQQQIIQQ', 21, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
        data = bytes(header) + shstr + rows + eh_frame + rela
        with self.assertRaisesRegex(EvidenceError, 'truncated RELA section'):
            relocations(data)

    def test_partial_entry_completed_from_following_bytes_rejected(self):
        # Declared size 32 = one full entry plus 8 trailing bytes; the
        # loop's second step reads 16 bytes past the section end (into
        # .eh_frame) and would silently yield a bogus row on base.
        data = build(32, pack([(SLOT, 8, 0x1234)]) + b'\x00' * 8)
        with self.assertRaisesRegex(EvidenceError, 'truncated RELA section'):
            relocations(data)


if __name__ == '__main__':
    unittest.main()
