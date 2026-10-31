"""slots() in tools/evm_amount_scale.py must fail closed on out-of-bounds
dynamic symbol references.

Sibling of the .rela.dyn truncation fix (merged in #1071, ex-open #441):
slots() guards the relocation section itself, but the type-6 arm then
reads the dynamic symbol entry and its name with no bounds at all, so a
symbol index past .dynsym escapes as struct.error and a name offset past
.dynstr (or with no NUL inside .dynstr) escapes as ValueError, instead
of the tool's EvidenceError.
"""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'evm_amount_scale.py'

spec = importlib.util.spec_from_file_location('evm_amount_scale_slots_dynsym', TOOL)
eas = importlib.util.module_from_spec(spec)
sys.modules['evm_amount_scale_slots_dynsym'] = eas
spec.loader.exec_module(eas)

GOT_ADDR = 0x5000


def sym_entry(name_offset):
    return struct.pack('<IBBHQQ', name_offset, 0, 0, 0, 0, 0)


def build(rela_bytes, dynsym=b'\x00' * 24, dynstr=b'\x00'):
    """Minimal ELF64-LE with .rela.dyn at EOF, plus .dynsym/.dynstr/.got."""
    names = b'\x00.rela.dyn\x00.dynsym\x00.dynstr\x00.got\x00.shstrtab\x00'
    o_rela = 1
    o_dynsym = 1 + len(b'.rela.dyn\x00')
    o_dynstr = o_dynsym + len(b'.dynsym\x00')
    o_got = o_dynstr + len(b'.dynstr\x00')
    o_shstr = o_got + len(b'.got\x00')
    hdr = bytearray(64)
    hdr[:6] = b'\x7fELF\x02\x01'
    dynsym_off = 64
    dynstr_off = dynsym_off + len(dynsym)
    got_off = dynstr_off + len(dynstr)
    got = b'\x00' * 16
    shstr_off = got_off + len(got)
    shoff = shstr_off + len(names)
    rela_off = shoff + 6 * 64
    struct.pack_into('<Q', hdr, 0x28, shoff)
    struct.pack_into('<HHH', hdr, 0x3a, 64, 6, 5)

    def sh(name, typ, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, 0, addr, off, size, 0, 0, 0, 0)

    headers = b''.join([
        sh(0, 0, 0, 0, 0),
        sh(o_rela, 4, 0, rela_off, len(rela_bytes)),
        sh(o_dynsym, 11, 0, dynsym_off, len(dynsym)),
        sh(o_dynstr, 3, 0, dynstr_off, len(dynstr)),
        sh(o_got, 1, GOT_ADDR, got_off, len(got)),
        sh(o_shstr, 3, 0, shstr_off, len(names)),
    ])
    return bytes(hdr) + dynsym + dynstr + got + names + headers + rela_bytes


def reloc6(where, sym):
    return struct.pack('<QQq', where, (sym << 32) | 6, 0)


class SlotsDynsymTests(unittest.TestCase):
    def test_symbol_index_past_dynsym_rejected(self):
        data = build(reloc6(GOT_ADDR, 100))
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).slots()

    def test_symbol_name_past_dynstr_rejected(self):
        dynsym = b'\x00' * 24 + sym_entry(1000)
        data = build(reloc6(GOT_ADDR, 1), dynsym, b'\x00memset\x00')
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).slots()

    def test_symbol_name_unterminated_in_dynstr_rejected(self):
        # Name runs to the end of .dynstr with no NUL inside it; the next
        # file byte (the .got) must not be read as part of the name.
        dynsym = b'\x00' * 24 + sym_entry(1)
        data = build(reloc6(GOT_ADDR, 1), dynsym, b'\x00memsetx')
        with self.assertRaises(eas.EvidenceError):
            eas.Image(data).slots()

    def test_valid_stub_name_still_resolves(self):
        dynsym = b'\x00' * 24 + sym_entry(1)
        data = build(reloc6(GOT_ADDR, 1), dynsym, b'\x00memset\x00')
        self.assertEqual(eas.Image(data).slots(), {GOT_ADDR: eas.MEMSET_STUB})

    def test_valid_unknown_name_still_ignored(self):
        dynsym = b'\x00' * 24 + sym_entry(1)
        data = build(reloc6(GOT_ADDR, 1), dynsym, b'\x00other\x00')
        self.assertEqual(eas.Image(data).slots(), {})


if __name__ == '__main__':
    unittest.main()
