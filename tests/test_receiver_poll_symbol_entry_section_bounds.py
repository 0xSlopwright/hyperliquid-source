"""Dynamic symbol entry must lie inside the .dynsym section.

receiver_poll_static.relocations() already rejects a symbol table index
out of range, a string table index out of range, and a symbol entry past
the end of the file. But it never checked the entry against the linked
symbol table's own extent: an entry index past the table's last entry
still resolved, reading the following section's bytes as a symbol entry.
With .dynstr directly after a one-entry .dynsym, those bytes forge a
name offset pointing back at 'exit' inside .dynstr, so the forged entry
was accepted as the exit import binding even though no such symbol
entry exists in .dynsym at all.

These tests build a minimal ELF64-LE document in memory, following the
existing receiver_poll synthetic harnesses: a .rela.dyn section carrying
every RELATIVE slot plus the exit-import slot, and the .dynsym/.dynstr
pair the exit resolution follows.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from receiver_poll_static import RELATIVE, relocations

EXIT = 0x5777378


def build(dynstr, pad, name_off, sym_entry):
    shstr = b'\x00.rela.dyn\x00.shstrtab\x00.dynsym\x00.dynstr\x00.pad\x00'
    names = {n: shstr.index(n) for n in (b'.rela.dyn', b'.shstrtab', b'.dynsym', b'.dynstr', b'.pad')}
    shoff = 64 + len(shstr)
    nsec = 6
    dynsym_off = shoff + nsec * 64
    dynstr_off = dynsym_off + 24
    pad_off = dynstr_off + len(dynstr)
    rela_off = pad_off + len(pad)
    rela = b''.join(struct.pack('<QQq', slot, 8, addend) for slot, addend in sorted(RELATIVE.items()))
    rela += struct.pack('<QQq', EXIT, (sym_entry << 32) | 6, 0)
    data = bytearray(rela_off + len(rela))
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, shoff)
    struct.pack_into('<HHH', data, 58, 64, nsec, 2)

    def shdr(index, name, typ, off, size, link, entsize):
        struct.pack_into('<IIQQQQIIQQ', data, shoff + index * 64,
                         names.get(name, 0), typ, 0, 0, off, size, link, 0, 0, entsize)

    shdr(0, b'', 0, 0, 0, 0, 0)
    shdr(1, b'.rela.dyn', 4, rela_off, len(rela), 3, 0)
    shdr(2, b'.shstrtab', 3, 64, len(shstr), 0, 0)
    shdr(3, b'.dynsym', 11, dynsym_off, 24, 4, 24)
    shdr(4, b'.dynstr', 3, dynstr_off, len(dynstr), 0, 0)
    shdr(5, b'.pad', 3, pad_off, len(pad), 0, 0)
    data[64:64 + len(shstr)] = shstr
    struct.pack_into('<I', data, dynsym_off, name_off)
    data[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    data[pad_off:pad_off + len(pad)] = pad
    data[rela_off:rela_off + len(rela)] = rela
    return bytes(data)


class ReceiverPollSymbolEntrySectionBoundsTests(unittest.TestCase):
    def test_entry_past_symbol_table_is_rejected(self):
        # .dynsym holds exactly one entry; index 1 lands in .dynstr, whose
        # first four bytes forge a name offset (4) at 'exit' in .dynstr.
        dynstr = struct.pack('<I', 4) + b'exit\x00'
        with self.assertRaisesRegex(ValueError, 'outside symbol table'):
            relocations(build(dynstr, b'', 0, 1))

    def test_valid_entry_inside_symbol_table_passes(self):
        rows = relocations(build(b'exit\x00', b'', 0, 0))
        self.assertEqual(len(rows), len(RELATIVE) + 1)
        self.assertEqual(rows[-1]['symbol'], 'exit')


if __name__ == '__main__':
    unittest.main()
