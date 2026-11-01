"""Synthetic-ELF controls for visor_rust_unwind.relocation truncation.

relocation() steps every SHT_RELA section by 24 bytes with no remainder
check, so a section ending in a partial ELF64 Rela entry is silently
accepted: the partial entry is completed from whatever bytes follow the
section in the file, and the selected-slot verdict is returned as if the
input were well-formed. The sibling heartbeat_status parser scans the
same kind of sections and already rejects this case with
'Truncated relocation section', as do open #1177 (singleton_lifecycle),
#1179 (build_mode_route_static), #1181 (build_mode_static) and #1182
(compact_string_unwind).

The real visor capture is an LFS pointer on this machine, so these tests
build a minimal ELF64-LE document in memory, mirroring
tests/test_compact_string_unwind_relocation_truncation.py.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from visor_rust_unwind import relocation  # noqa: E402
from elf_index import sections  # noqa: E402

SLOT = 0x5000


def build(rela, extra_size=0, extra=b''):
    """ELF with .rela.dyn holding the selected slot, plus one extra
    SHT_RELA section whose declared size may end mid-entry."""
    shstr = b'\x00.rela.dyn\x00.rela.extra\x00.shstrtab\x00'
    shstr_off = 64
    shoff = shstr_off + len(shstr)
    rela_off = shoff + 4 * 64
    extra_off = rela_off + len(rela)
    header = bytearray(64)
    header[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, 4, 3)
    rows = b''
    rows += struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 1, 4, 0, 0, rela_off, len(rela), 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 11, 4, 0, 0, extra_off, extra_size, 0, 0, 0, 0)
    rows += struct.pack('<IIQQQQIIQQ', 24, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0)
    return bytes(header) + shstr + rows + rela + extra


def pack(entries):
    return b''.join(struct.pack('<QQq', slot, info, addend) for slot, info, addend in entries)


def selected(data):
    return relocation(data, sections(data), SLOT)


class VisorRelocationTruncationTests(unittest.TestCase):
    def test_valid_relocation_sections_return_selected_slot(self):
        result = selected(build(pack([(SLOT, 8, 0x1234)])))
        self.assertEqual((result['slot_va'], result['type'], result['addend']),
                         ('0x5000', 8, '0x1234'))

    def test_trailing_byte_in_rela_dyn_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            selected(build(pack([(SLOT, 8, 0x1234)]) + b'\x00'))

    def test_partial_entry_in_other_rela_section_rejected(self):
        data = build(pack([(SLOT, 8, 0x1234)]), extra_size=8,
                     extra=b'\x99' * 8 + b'\x00' * 64)
        with self.assertRaisesRegex(ValueError, 'Truncated relocation section'):
            selected(data)


if __name__ == '__main__':
    unittest.main()
