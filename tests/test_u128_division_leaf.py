"""Portable counterfactual ELF containers, not full target/artifact fixtures.

The 198 bytes are a licensed official excerpt. Headers, virtual addresses and
symbol/relocation records below are test-built; positive seams remain unqualified.
Genuine full-input correspondence and corruption receipts are separate evidence.
"""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_division_leaf as u

BODY = (ROOT / 'research/work-items/RE-002-u128-division-leaf-94/fixtures/official-198.bin').read_bytes()


def elf(kind, sections, loads=()):
    """Build tiny, explicitly rebased containers with physical record offsets."""
    names = b'\0'
    rows = [dict(name='', type=0, flags=0, address=0, raw=b'')]
    rows += [dict(r) for r in sections]
    rows.append(dict(name='.shstrtab', type=3, flags=0, address=0, raw=b''))
    for row in rows:
        row['name_offset'] = len(names) if row['name'] else 0
        if row['name']:
            names += row['name'].encode() + b'\0'
    rows[-1]['raw'] = names
    b = bytearray(64 + 56 * len(loads))
    for i, row in enumerate(rows):
        b += b'\0' * (-len(b) % 8)
        row['offset'] = len(b) if i else 0
        if i:
            b += row['raw']
    b += b'\0' * (-len(b) % 8)
    shoff = len(b)
    for row in rows:
        b += struct.pack('<IIQQQQIIQQ', row['name_offset'], row['type'], row['flags'],
                         row['address'], row['offset'], len(row['raw']),
                         row.get('link', 0), row.get('info', 0), 1, row.get('entsize', 0))
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', b, 0, ident, kind, 62, 1, 0,
                     64 if loads else 0, shoff, 0, 64, 56 if loads else 0,
                     len(loads), 64, len(rows), len(rows) - 1)
    for i, (section_index, flags) in enumerate(loads):
        r = rows[section_index]
        struct.pack_into('<IIQQQQQQ', b, 64 + i * 56, 1, flags, r['offset'],
                         r['address'], r['address'], len(r['raw']), len(r['raw']), 1)
    return bytes(b), rows, shoff


def object_fixture(name='__udivti3', relocation=None, extra_alias=False, undefined=False):
    strings = b'\0' + name.encode() + b'\0'
    info = 16 if undefined else (34 if name == '__udivti3' else 18)
    symbols = bytes(24) + struct.pack('<IBBHQQ', 1, info, 0 if undefined else 2,
                                     0 if undefined else 1, 0, 0 if undefined else u.SIZE)
    if extra_alias:
        alias = len(strings)
        strings += b'alias\0'
        symbols += struct.pack('<IBBHQQ', alias, 18, 2, 1, 0, u.SIZE)
    sections = [dict(name='.text.__udivti3', type=1, flags=6, address=0, raw=BODY),
                dict(name='.strtab', type=3, flags=0, address=0, raw=strings),
                dict(name='.symtab', type=2, flags=0, address=0, raw=symbols,
                     link=2, info=1, entsize=24)]
    if relocation is not None:
        sections.append(dict(name='.rela.text', type=relocation, flags=0, address=0,
                             raw=struct.pack('<QQq', 1, (1 << 32) | 2, -4),
                             link=3, info=1, entsize=24))
    return elf(1, sections)


def target_fixture(extra_relocation=False, slot_write=None):
    frame_address = 0x6000000
    # Standard zR CIE; this container and its relative FDE are test-built.
    cie = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
    fde = struct.pack('<IIii', 16, 28, u.BEGIN - (frame_address + 32), u.SIZE) + bytes(4)
    frame = cie + fde + bytes(4)
    rela = struct.pack('<QQq', u.SLOT, 8, u.BEGIN)
    if extra_relocation:
        rela += struct.pack('<QQq', u.BEGIN + 1, 8, u.BEGIN)
    sections = [dict(name='.text', type=1, flags=6, address=u.BEGIN, raw=BODY),
                dict(name='.got', type=1, flags=3, address=u.SLOT, raw=bytes(8)),
                dict(name='.eh_frame', type=1, flags=2, address=frame_address, raw=frame),
                dict(name='.rela.dyn', type=4, flags=0, address=0, raw=rela, entsize=24)]
    if slot_write is not None:
        sections.append(dict(name='.rela.extra', type=4, flags=0, address=0,
                             raw=struct.pack('<QQq', *slot_write), entsize=24))
    return elf(3, sections, ((1, 5), (2, 6), (3, 4)))


def archive_fixture(entries):
    names = bytearray()
    result = bytearray(b'!<arch>\n')
    offsets = []
    for name, _ in entries:
        offsets.append(len(names))
        names += name.encode() + b'/\n'
    def add(label, raw):
        header = (label.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6) +
                  '100644'.ljust(8) + str(len(raw)).ljust(10) + '`\n').encode()
        result.extend(header + raw + (b'\n' if len(raw) & 1 else b''))
    add('//', names)
    for offset, (_, raw) in zip(offsets, entries):
        add('/' + str(offset), raw)
    return bytes(result)


class DivisionLeafTests(unittest.TestCase):
    def test_complete_unqualified_seams_and_frontdoor_refusal(self):
        target, _, _ = target_fixture()
        source, _, _ = object_fixture()
        a, b = u.inspect_target(target), u.inspect_member(source, '__udivti3')
        self.assertEqual(a['origin'], 'UNQUALIFIED')
        self.assertEqual(b['origin'], 'UNQUALIFIED')
        self.assertEqual(a['body_hex'], b['body_hex'])
        self.assertEqual(a['body_sha256'], u.BODY_SHA256)
        self.assertEqual(a['fde']['end'] - a['fde']['start'], 198)
        with self.assertRaisesRegex(ValueError, 'Target identity'):
            u.analyze(target, b'not an official archive')

    def test_all_definitions_and_undefined_declarations_retained(self):
        entries = [(member, object_fixture(name)[0]) for member, (name, _) in u.DEFINITIONS.items()]
        entries.append(('undefined.o', object_fixture(undefined=True)[0]))
        report = u.inspect_archive(archive_fixture(entries))
        self.assertEqual(report['origin'], 'UNQUALIFIED')
        self.assertEqual(len(report['declarations']), 3)
        self.assertEqual(len(report['definitions']), 2)
        for changed in [entries[:1], entries + [('extra.o', object_fixture()[0])]]:
            with self.assertRaises(ValueError):
                u.inspect_archive(archive_fixture(changed))

    def test_complete_fde_required(self):
        original, rows, _ = target_fixture()
        for offset, value in [(12, 197), (8, u.BEGIN + 1 - (0x6000000 + 32))]:
            data = bytearray(original)
            struct.pack_into('<i', data, rows[3]['offset'] + 24 + offset, value)
            with self.assertRaisesRegex(ValueError, 'complete 198-byte FDE'):
                u.inspect_target(bytes(data))

    def test_unique_consistent_executable_load_required(self):
        original, rows, shoff = target_fixture()
        for offset, form, value in [(64, '<I', 0), (72, '<Q', rows[1]['offset'] + 1),
                                    (68, '<I', 4), (shoff + 64 + 8, '<Q', 2)]:
            data = bytearray(original)
            struct.pack_into(form, data, offset, value)
            with self.assertRaises(ValueError):
                u.inspect_target(bytes(data))

    def test_all_eight_slot_bytes_must_be_mapped(self):
        data, _, shoff = target_fixture()
        data = bytearray(data)
        struct.pack_into('<Q', data, shoff + 2 * 64 + 32, 4)
        with self.assertRaisesRegex(ValueError, 'mapping'):
            u.inspect_target(bytes(data))

    def test_typed_relative_slot_and_destination(self):
        original, rows, _ = target_fixture()
        for off, fmt, value in [(8, '<Q', 7), (8, '<Q', (1 << 32) | 8),
                                (16, '<q', u.BEGIN + 1)]:
            data = bytearray(original)
            struct.pack_into(fmt, data, rows[4]['offset'] + off, value)
            with self.assertRaises(ValueError):
                u.inspect_target(bytes(data))

    def test_no_extra_body_relocation_credit(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            u.inspect_target(target_fixture(extra_relocation=True)[0])

    def test_global_slot_uniqueness_and_partial_overlap(self):
        for record in [(u.SLOT, 8, u.BEGIN), (u.SLOT, 8, u.BEGIN + 1),
                       (u.SLOT - 4, 8, u.BEGIN), (u.SLOT + 4, 8, u.BEGIN)]:
            with self.assertRaisesRegex(ValueError, 'selected slot'):
                u.inspect_target(target_fixture(slot_write=record)[0])

    def test_source_binding_type_visibility_and_extent(self):
        original, rows, _ = object_fixture()
        record = rows[3]['offset'] + 24
        for off, fmt, value in [(4, '<B', 33), (4, '<B', 18), (5, '<B', 0),
                                (8, '<Q', 1), (16, '<Q', 197), (6, '<H', 0)]:
            data = bytearray(original)
            struct.pack_into(fmt, data, record + off, value)
            with self.assertRaises(ValueError):
                u.inspect_member(bytes(data), '__udivti3')

    def test_no_source_relocations_or_ambiguous_aliases(self):
        for data in [object_fixture(relocation=4)[0], object_fixture(relocation=9)[0],
                     object_fixture(extra_alias=True)[0]]:
            with self.assertRaises(ValueError):
                u.inspect_member(data, '__udivti3')

    def test_raw_opcode_difference_is_not_normalized(self):
        data, rows, _ = object_fixture()
        data = bytearray(data)
        data[rows[1]['offset'] + 3] ^= 1
        changed = u.inspect_member(bytes(data), '__udivti3')
        actual = bytes.fromhex(changed['body_hex'])
        self.assertNotEqual(changed['body_sha256'], u.BODY_SHA256)
        self.assertEqual([i for i, (a, b) in enumerate(zip(actual, BODY)) if a != b], [3])
        self.assertEqual(changed['origin'], 'UNQUALIFIED')

    def test_existing_output_and_broken_symlink_refused_before_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'directory'
            directory.mkdir()
            alias = Path(tmp) / 'alias'
            alias.symlink_to(Path(tmp) / 'absent')
            for output in (directory, alias):
                with self.assertRaisesRegex(ValueError, 'Output already exists'):
                    u.collect('/absent-target', '/absent-archive', output)
                self.assertTrue(os.path.lexists(output))


if __name__ == '__main__':
    unittest.main()
