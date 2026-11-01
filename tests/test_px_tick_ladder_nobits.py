"""NOBITS sections must not map VAs to file bytes in px_tick_ladder.

A SHT_NOBITS section (e.g. .bss, .tbss) occupies no file bytes, so resolving
one of its VAs must fail closed. On base, sections() kept the
NOBITS rows, so Image.off() matched a NOBITS range and returned whatever
file bytes its sh_offset happened to point at. Same defect class and guard
as tests/test_bincode_nobits.py (#105).
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import px_tick_ladder as m  # noqa: E402

TEXT = b'\x90' * 16
BIN94 = ROOT / 'artifacts/node/94/hl-node'


def synthetic_elf(bss_first=False, bss_addr=0x500000, bss_off=None):
    """Minimal ELF64-LE: .text (PROGBITS) + .bss (NOBITS) + the PROGBITS
    sections the tool's constructor reads.

    The .bss sh_offset deliberately points at real file bytes, so a
    NOBITS-mapping bug is observable instead of reading past the end.
    """
    blobs = {'.rodata': b'\x00' * 4}
    names = ['.text', '.bss'] + list(blobs) + ['.shstrtab']
    shstr = b'\x00' + b''.join(n.encode() + b'\x00' for n in names)
    idx = {}
    pos = 1
    for n in names:
        idx[n] = pos
        pos += len(n) + 1
    body = TEXT
    offs = {}
    for n, b in blobs.items():
        offs[n] = 64 + len(body)
        body += b
    shstr_off = 64 + len(body)
    shoff = shstr_off + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', idx[name] if name else 0, typ, flags, addr, off, size, 0, 0, 1, 0)

    text = sh('.text', 1, 6, 0x400000, 64, len(TEXT))
    bss = sh('.bss', 8, 3, bss_addr, 64 if bss_off is None else bss_off, 16)
    rows = [sh(None, 0, 0, 0, 0, 0)] + ([bss, text] if bss_first else [text, bss])
    rows += [sh(n, 1, 2, 0x700000 + 0x100 * i, offs[n], len(b)) for i, (n, b) in enumerate(blobs.items())]
    rows.append(sh('.shstrtab', 3, 0, 0, shstr_off, len(shstr)))
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, 64, len(rows), len(rows) - 1)
    return bytes(ehdr) + body + shstr + b''.join(rows)


def resolve(va, **kw):
    return m.Image(synthetic_elf(**kw)).off(va)


class NobitsTests(unittest.TestCase):
    def test_nobits_va_rejected(self):
        with self.assertRaises(m.EvidenceError):
            resolve(0x500000)

    def test_nobits_absent_from_sections(self):
        self.assertNotIn('.bss', m.sections(synthetic_elf()))

    def test_progbits_resolution_unaffected(self):
        self.assertEqual(resolve(0x400004), 68)

    def test_outside_all_sections_still_rejected(self):
        with self.assertRaises(m.EvidenceError):
            resolve(0x600000)

    def test_nobits_does_not_shadow_progbits(self):
        # .bss header first, same VA range as .text, sh_offset pointing at
        # other file bytes: base returns that offset, fixed code resolves
        # to the .text bytes.
        self.assertEqual(resolve(0x400000, bss_first=True, bss_addr=0x400000, bss_off=80), 64)

    @unittest.skipUnless(BIN94.exists(), 'node #94 artifact not present')
    def test_real_tbss_does_not_shadow_init_array(self):
        # Node #94: .tbss (NOBITS) is VA 0x5662d50 size 0x650 at sh_offset
        # 0x5660d48, while .init_array starts at the same VA 0x5662d50 with
        # sh_offset 0x5660d50. The section header lists .tbss first, so on base
        # this VA resolved through .tbss to 0x5660d48, 8 bytes early. No
        # current output of this tool reads this VA.
        img = m.Image(BIN94.read_bytes())
        self.assertEqual(img.off(0x5662d50), 0x5660d50)
        self.assertEqual(img.off(0x56632a0), 0x56612a0)  # .data.rel.ro start


if __name__ == '__main__':
    unittest.main()
