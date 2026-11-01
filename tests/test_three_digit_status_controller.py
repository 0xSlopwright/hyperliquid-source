"""Actual tiny-code/data corruptions for the selected node94 status relation."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import three_digit_status_controller as status

PACKET = ROOT / 'research/work-items/RE-005-three-digit-status-controller-94'


class SelectedStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caller = (PACKET / 'native/caller-boundary.bin').read_bytes()
        cls.leaf = (PACKET / 'native/existing-leaf.bin').read_bytes()
        cls.table = (PACKET / 'native/jump-table.bin').read_bytes()

    def reject_code_byte(self, va, match, xor=1):
        b = bytearray(self.caller)
        b[va - status.CALLER_START] ^= xor
        with self.assertRaisesRegex(ValueError, match):
            status.selected_facts(bytes(b), self.leaf, self.table)

    def test_actual_selected_relation_and_separate_denominators(self):
        r = status.selected_facts(self.caller, self.leaf, self.table)
        self.assertEqual((len(self.caller), len(self.leaf), len(self.table)), (1301, 85, 24))
        self.assertEqual(sum(b - a for a, b in status.SELECTED_SPANS), 262)
        self.assertEqual(r['selected_key']['length'], 7)
        self.assertEqual(r['selected_key']['raw'], '3a737461747573')
        self.assertEqual([x['target_va'] for x in r['table']],
                         ['0x168226f', '0x1682676', '0x168242c',
                          '0x1682676', '0x1682399', '0x16824ae'])
        self.assertEqual([(e['bits'], e['output_offset'], e['value'])
                          for e in r['ordered_nonzero_stores']],
                         [(16, 0, 'AX100..999'), (8, 64, 7)])
        self.assertEqual([(e['bits'], e['output_offset'], e['value'])
                          for e in r['ordered_zero_stores']],
                         [(8, 0, 7), (8, 64, 8)])
        self.assertEqual(r['observation_boundaries'],
                         {'nonzero_next_va': '0x168261d', 'zero_next_va': '0x1682306'})
        self.assertFalse(r['invalid_output_byte1_written_by_selected_stage'])
        self.assertFalse(r['whole_return_contents_qualified'])
        self.assertFalse(r['runtime_callback_targets_or_contracts_qualified'])
        self.assertFalse(r['rust_or_controller_equivalence_claim'])

    def test_actual_six_signed_table_entries_and_extent_controls(self):
        for index in range(6):
            with self.subTest(index=index):
                b = bytearray(self.table)
                displacement = struct.unpack_from('<i', b, index * 4)[0]
                struct.pack_into('<i', b, index * 4, displacement + 1)
                with self.assertRaisesRegex(ValueError, 'Selected table destination'):
                    status.selected_facts(self.caller, self.leaf, bytes(b))
        b = bytearray(self.table)
        struct.pack_into('<i', b, 8, -4)
        with self.assertRaisesRegex(ValueError, 'Selected table destination'):
            status.selected_facts(self.caller, self.leaf, bytes(b))
        for b in (self.table[:-1], self.table + b'\0'):
            with self.assertRaisesRegex(ValueError, 'Six signed-DWord table extent'):
                status.selected_facts(self.caller, self.leaf, b)
        self.reject_code_byte(0x1682267, 'Signed-DWord table read')

    def test_all_literal_bytes_and_unsigned_length_controls(self):
        for va in (0x168224a, 0x1682432, 0x16825d7, 0x16825e1,
                   0x16825eb, 0x16825f5, 0x16825fb):
            with self.subTest(va=hex(va)):
                self.reject_code_byte(va, 'literal byte')
        self.reject_code_byte(0x1682254, 'Unsigned length subtract5')
        self.reject_code_byte(0x1682258, 'Unsigned length upper bound')
        self.reject_code_byte(0x168225a, 'Selected control flow')
        self.reject_code_byte(0x16825cf, 'Third literal byte load')
        self.reject_code_byte(0x1682262, 'Table PC-relative base')

    def test_actual_argument_and_selected_edge_controls(self):
        self.reject_code_byte(0x1682601, 'Leaf pointer argument')
        self.reject_code_byte(0x1682605, 'Leaf length argument')
        # A real direct-call displacement, result-branch displacement and key
        # branch displacement are input fields, not an imaginary field mask.
        for va in (0x1682607, 0x168260f, 0x1682435, 0x168261e):
            with self.subTest(va=hex(va)):
                self.reject_code_byte(va, 'Selected control flow')
        self.reject_code_byte(0x168260c, 'AX zero test')

    def test_actual_store_width_offset_tag_and_order_controls(self):
        for va, label in (
            (0x1682614, 'Nonzero WORD'), (0x168261b, 'Nonzero tag7'),
            (0x168261c, 'Nonzero tag7'), (0x1682300, 'Invalid BYTE'),
            (0x1682304, 'Invalid tag8'), (0x1682305, 'Invalid tag8'),
        ):
            with self.subTest(va=hex(va)):
                self.reject_code_byte(va, label)
        b = bytearray(self.caller)
        at = 0x1682614 - status.CALLER_START
        # Swap the two complete real instruction encodings, keeping nine bytes.
        old = bytes(b[at:at + 9])
        b[at:at + 9] = old[4:] + old[:4]
        with self.assertRaisesRegex(ValueError, 'Nonzero WORD'):
            status.selected_facts(bytes(b), self.leaf, self.table)

    def test_callbacks_are_retained_without_effect_or_return_contract(self):
        for va, label in ((0x168231a, 'Invalid-route callback setup'),
                          (0x1682693, 'Nonzero-route callback setup'),
                          (0x16826a5, 'Common key callback setup')):
            with self.subTest(va=hex(va)):
                self.reject_code_byte(va, label)
        self.reject_code_byte(0x16826a8, 'Normal epilogue')

    def test_boundary_and_existing_leaf_identity_are_separate(self):
        self.reject_code_byte(status.CALLER_START, 'Caller boundary bytes')
        for at in (3, 84):
            b = bytearray(self.leaf)
            b[at] ^= 1
            with self.assertRaisesRegex(ValueError, 'Existing three-digit leaf bytes'):
                status.selected_facts(self.caller, bytes(b), self.table)
        with self.assertRaisesRegex(ValueError, 'Caller byte extent'):
            status.selected_facts(self.caller[:-1], self.leaf, self.table)
        with self.assertRaisesRegex(ValueError, 'Leaf byte extent'):
            status.selected_facts(self.caller, self.leaf[:-1], self.table)

    def test_raw_native_rows_close_selected_local_control_path(self):
        # This is a static graph over actual encoded branch fields. There is
        # no instruction, CPU, register, flag or memory-value execution.
        rows = json.loads((PACKET / 'native/caller.rows.json').read_text())
        self.assertEqual(len(rows), 318)
        self.assertEqual(b''.join(bytes.fromhex(r['raw']) for r in rows), self.caller)
        by = {int(r['va'], 16): r for r in rows}
        self.assertEqual(len(by), len(rows))
        at = status.CALLER_START
        for r in rows:
            self.assertEqual(int(r['va'], 16), at)
            at += len(bytes.fromhex(r['raw']))
        self.assertEqual(at, status.CALLER_END)
        table = [status.TABLE_VA + x for x in struct.unpack('<6i', self.table)]
        graph, calls = {}, set()
        for va, row in by.items():
            b = bytes.fromhex(row['raw'])
            after = va + len(b)
            op = row['assembly'].split()[0]
            if op == 'jmp':
                if b[0] == 0xe9:
                    dest = [status.relative(b, va, 'e9')]
                elif b[0] == 0xeb:
                    dest = [status.relative(b, va, 'eb')]
                else:
                    self.assertEqual((va, b), (0x168226d, bytes.fromhex('ffe1')))
                    dest = table
            elif op.startswith('j'):
                prefix = b[:1] if len(b) == 2 else b[:2]
                self.assertTrue((len(b) == 2 and 0x70 <= b[0] <= 0x7f)
                                or (len(b) == 6 and b[0] == 15 and 0x80 <= b[1] <= 0x8f))
                dest = [status.relative(b, va, prefix.hex()), after]
            elif op in ('ret', 'ud2'):
                dest = []
            else:
                dest = [after] if after < status.CALLER_END else []
                if op == 'call':
                    calls.add(va)
            self.assertTrue(all(d in by for d in dest))
            graph[va] = set(dest)
        required = ((0x168223e, 0x1682244), (0x168224b, 0x1682251),
                    (0x1682259, 0x168225f), (0x168226d, 0x168242c),
                    (0x1682433, 0x16825cc), (0x16825d3, 0x16825d5),
                    (0x16825d8, 0x16825de), (0x16825e2, 0x16825e8),
                    (0x16825ec, 0x16825f2), (0x16825f6, 0x16825f8),
                    (0x16825fc, 0x16825fe))
        for cut in required:
            seen, todo = set(), [status.CALLER_START]
            while todo:
                va = todo.pop()
                if va not in seen:
                    seen.add(va)
                    todo.extend(w for w in graph[va] if (va, w) != cut)
            self.assertNotIn(0x1682606, seen, hex(cut[0]))
        # The new claim ends before either dynamic callback. Ordinary call
        # fallthrough in this graph is an assumption, never their validation.
        self.assertIn(0x1682691, calls)
        self.assertIn(0x16826a3, calls)

    def test_full_identity_failure_and_existing_output_preservation(self):
        with tempfile.TemporaryDirectory(prefix='status-control-') as tmp:
            p = Path(tmp)
            bad = p / 'bad-input'
            bad.write_bytes(b'not the captured node94 ELF')
            with self.assertRaisesRegex(ValueError, 'full immutable input digest'):
                status.collect(bad, p / 'unpublished')
            self.assertFalse((p / 'unpublished').exists())
            existing = p / 'existing'
            existing.mkdir()
            marker = existing / 'marker'
            marker.write_bytes(b'unchanged')
            with self.assertRaises(FileExistsError):
                status.collect(p / 'does-not-exist', existing)
            self.assertEqual(marker.read_bytes(), b'unchanged')
            self.assertEqual(sorted(x.name for x in existing.iterdir()), ['marker'])

    def test_real_collector_admission_mappings_and_export_hashes(self):
        binary = ROOT / 'artifacts/node/94/hl-node'
        if not binary.is_file():
            self.skipTest('Pinned node94 capture is unavailable')
        with tempfile.TemporaryDirectory(prefix='status-collect-') as tmp:
            output = Path(tmp) / 'output'
            report = status.collect(binary, output)
            self.assertEqual(report['target_sha256'], status.TARGET_SHA256)
            self.assertEqual(report['scope'], {
                'caller_boundary_bytes': 1301, 'selected_caller_subset_bytes': 262,
                'existing_leaf_bytes': 85, 'table_bytes': 24,
                'subset_is_not_additional_code_coverage': True})
            self.assertEqual((output / 'caller-boundary.bin').read_bytes(), self.caller)
            self.assertEqual((output / 'existing-leaf.bin').read_bytes(), self.leaf)
            self.assertEqual((output / 'jump-table.bin').read_bytes(), self.table)
            table = report['source_mappings']['0x27fac8']
            self.assertEqual(table['file_offset'], 2620104)
            self.assertEqual(table['section']['name'], '.rodata')
            self.assertEqual(table['PT_LOAD']['flags'], 4)
            self.assertFalse(report['facts']['whole_return_contents_qualified'])
            manifest = json.loads((output / 'MANIFEST.json').read_text())
            self.assertEqual(set(x.name for x in output.iterdir()), set(manifest) | {'MANIFEST.json'})
            for name, entry in manifest.items():
                raw = (output / name).read_bytes()
                self.assertEqual(entry, {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            for name, expected in report['analysis_source_bindings'].items():
                self.assertEqual(expected, hashlib.sha256((ROOT / 'tools' / name).read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
