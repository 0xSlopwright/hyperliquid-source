"""Target-grounded controls for the static vault guard packet (no node execution)."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import vault_guard_static as vg
from elf_index import sections


class VaultGuardEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not vg.TARGET.is_file() or vg.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = vg.inspect(vg.TARGET)
        cls.data = vg.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_retained_record_matches_authenticated_target(self):
        record = vg.ROOT / 'research/work-items/vault-guard-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_fde_bounds_and_body_identity(self):
        fn = self.result['function']
        self.assertEqual(fn['start_va'], '0x395b3a0')
        self.assertEqual(fn['end_va_exclusive'], '0x395bdc3')
        self.assertEqual(fn['bytes'], 2595)
        self.assertEqual(fn['sha256'],
                         'bc6d0672a761b1929e1abbe5d5ecbc93395c37e756d602426f47ae092a86de4f')

    def test_location_anchors(self):
        locs = self.result['locations']
        self.assertEqual((locs['vault']['line'], locs['vault']['column']), (407, 58))
        self.assertEqual(locs['vault']['path'], 'l1/src/vault/mod.rs')
        self.assertEqual(locs['stdlib']['rustc_commit'],
                         'e408947bfd200af42db322daf0fadfe7e26d3bd1')
        self.assertIn('navigate.rs:161:36', locs['stdlib']['path'])

    def test_identity_rejects_truncation_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                vg.inspect(path)
            path.write_bytes(self.mutated(vg.START, b'\x90'))
            with self.assertRaisesRegex(ValueError, 'size/SHA-256'):
                vg.inspect(path)

    def test_body_fde_and_window_mutations_rejected(self):
        for va in (vg.START, vg.START + 0x77c, vg.START + 0x7f4, vg.START + 0x9c7):
            with self.assertRaisesRegex(ValueError, 'Vault guard body bytes changed'):
                vg.analyze(self.mutated(va, b'\xcc'))
        with self.assertRaisesRegex(ValueError, 'Vault guard FDE record changed'):
            vg.analyze(self.mutated(vg.FDE_VA + 8, b'\x44\x44\x44\x44'))

    def test_anchor_mutations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Vault Location layout changed'):
            vg.analyze(self.mutated(vg.VAULT_LOC + 8, struct.pack('<I', 408)))
        with self.assertRaisesRegex(ValueError, 'vault path changed'):
            vg.analyze(self.mutated(vg.VAULT_PATH_VA + 6, b'X'))
        with self.assertRaisesRegex(ValueError, 'Navigate Location layout changed'):
            vg.analyze(self.mutated(vg.NAVIGATE_LOC + 8, struct.pack('<I', 162)))
        with self.assertRaisesRegex(ValueError, 'i64::MIN f64 constant changed'):
            vg.analyze(self.mutated(vg.MIN_F64_VA, struct.pack('<d', -1.0)))
        with self.assertRaisesRegex(ValueError, 'Shared 1e6 constant changed'):
            vg.analyze(self.mutated(vg.ONE_E6_VA, struct.pack('<d', 2e6)))

    def test_relocation_mutations_rejected(self):
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[rela['offset']:rela['offset'] + rela['size']]
        slots = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and address in (vg.GOT_PANIC_DISPLAY, vg.GOT_PANIC_FMT,
                                         vg.GOT_SELF, vg.VAULT_LOC, vg.NAVIGATE_LOC):
                slots[address] = (rela['address'] + off, addend)
        self.assertEqual(len(slots), 5)
        messages = {vg.GOT_PANIC_DISPLAY: 'Panic display callee changed',
                    vg.GOT_PANIC_FMT: 'Panic fmt callee changed',
                    vg.GOT_SELF: 'Self GOT slot changed',
                    vg.VAULT_LOC: 'Vault Location relocation changed',
                    vg.NAVIGATE_LOC: 'Navigate Location relocation missing|Navigate path changed'}
        for va, (slot_va, addend) in slots.items():
            with self.assertRaisesRegex(ValueError, messages[va]):
                vg.analyze(self.mutated(slot_va + 16, struct.pack('<q', addend + 4)))

    def test_call_census(self):
        census = self.result['call_census']
        self.assertEqual(census['got_indirect'],
                         ['0x2736819', '0x395b1dc', '0x4d4275c', '0x4d46699'])
        self.assertEqual(census['direct_e8'], 0)


class DuplicateSectionNameTests(unittest.TestCase):
    """Reader.by_name keeps only the last same-named section, and that
    dict supplies the .rela.dyn range relocations() parses plus the
    .eh_frame/.text sections analyze() reads. A duplicate name must be
    refused: with a decoy .rela.dyn first, the full real relocation map
    was read; with it last, the map collapsed to the decoy's single
    entry and the vault Location check failed — the verdict flipped on
    section order alone. Synthetic fixtures; no target binary needed."""

    def synthetic_elf(self, rows):
        rows = list(rows) + [('.shstrtab', 3, 0, b'')]
        names = b'\0'
        name_off = {}
        for name, _t, _a, _b in rows:
            if name not in name_off:
                name_off[name] = len(names)
                names += name.encode() + b'\0'
        shstr_row = len(rows) - 1
        rows[shstr_row] = ('.shstrtab', 3, 0, names)
        shoff = 0x1000
        data = bytearray(shoff + len(rows) * 64)
        data[0:6] = b'\x7fELF\x02\x01'
        off = 0x200
        offsets = []
        for _n, _t, _a, blob in rows:
            offsets.append(off)
            data[off:off + len(blob)] = blob
            off += max(len(blob), 1) + 0x10
        struct.pack_into('<Q', data, 40, shoff)
        struct.pack_into('<HHH', data, 58, 64, len(rows), shstr_row)
        for i, (name, typ, addr, blob) in enumerate(rows):
            struct.pack_into('<IIQQQQIIQQ', data, shoff + i * 64,
                             name_off[name], typ, 0, addr, offsets[i],
                             len(blob), 0, 0, 1, 0)
        return bytes(data)

    def base_rows(self):
        rela = struct.pack('<QQq', 0x5000, 8, 0x1234)
        return [('.rela.dyn', 4, 0x400000, rela),
                ('.eh_frame', 1, 0x500000, b'\0' * 16),
                ('.text', 1, 0x600000, b'\0' * 16)]

    def test_duplicate_rela_dyn_rejected_in_either_order(self):
        decoy = ('.rela.dyn', 4, 0x700000,
                 struct.pack('<QQq', vg.VAULT_LOC, 8, 0x1111))
        for rows in ([decoy] + self.base_rows(),
                     self.base_rows() + [decoy]):
            with self.assertRaisesRegex(ValueError,
                                        r'Duplicate section: \.rela\.dyn'):
                vg.Reader(self.synthetic_elf(rows))

    def test_duplicate_eh_frame_and_text_rejected(self):
        for name, typ, addr in (('.eh_frame', 1, 0x510000),
                                ('.text', 1, 0x610000)):
            rows = self.base_rows() + [(name, typ, addr, b'\0' * 8)]
            with self.assertRaisesRegex(
                    ValueError,
                    r'Duplicate section: ' + name.replace('.', r'\.')):
                vg.Reader(self.synthetic_elf(rows))

    def test_duplicate_unconsumed_section_name_tolerated(self):
        rows = self.base_rows() + [('.debug_info', 1, 0x700000, b'a'),
                                   ('.debug_info', 1, 0x710000, b'b')]
        reader = vg.Reader(self.synthetic_elf(rows))
        self.assertEqual(reader.by_name['.debug_info']['address'], 0x710000)

    def test_single_rela_dyn_still_parsed(self):
        reader = vg.Reader(self.synthetic_elf(self.base_rows()))
        self.assertEqual(vg.relocations(reader), {0x5000: 0x1234})


if __name__ == '__main__':
    unittest.main()
