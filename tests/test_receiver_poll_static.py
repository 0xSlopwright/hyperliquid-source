"""Real-target controls for receiver poll tables and the libc exit binding."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from receiver_poll_static import CONTROLS, RELATIVE, TABLES, instruction_controls, read_va, relocations, tables

class ReceiverPollTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == 'artifacts/node/94/hl-node')
        check(target, identity)
        cls.data = target.read_bytes()

    def test_actual_controls_tables_and_exit_import(self):
        instruction_controls(self.data)
        self.assertEqual(len(tables(self.data)), 5)
        rows = relocations(self.data)
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[-1]['symbol'], 'exit')

    def test_actual_instruction_corruptions_below_digest_gate(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    instruction_controls(changed)

    def test_actual_jump_table_displacements_below_digest_gate(self):
        for va in TABLES:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 4)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'jump table changed'):
                    tables(changed)

    def test_actual_relative_call_and_source_retargets(self):
        for slot, target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = changed.find(struct.pack('<QQq', slot, 8, target))
                self.assertGreaterEqual(offset, 0)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relocations(changed)

    def test_actual_exit_symbol_cannot_be_relabelled(self):
        changed = bytearray(self.data)
        # Resolve the specific import's symbol record independently, rather
        # than mutate an unrelated printable occurrence of the word exit.
        shoff = struct.unpack_from('<Q', changed, 40)[0]
        size, count = struct.unpack_from('<HH', changed, 58)
        headers = [struct.unpack_from('<IIQQQQIIQQ', changed, shoff+i*size) for i in range(count)]
        for sec in headers:
            if sec[1] != 4:
                continue
            for offset in range(sec[4], sec[4] + sec[5], 24):
                slot, info, _ = struct.unpack_from('<QQq', changed, offset)
                if slot != 0x5777378:
                    continue
                symbols = headers[sec[6]]
                strings = headers[symbols[6]]
                name = struct.unpack_from('<I', changed, symbols[4] + (info >> 32) * symbols[9])[0]
                changed[strings[4] + name] ^= 1
        with self.assertRaisesRegex(ValueError, 'Exit import binding changed'):
            relocations(changed)

    def test_actual_source_attribution_corruption(self):
        changed = bytearray(self.data)
        offset, _ = read_va(changed, 0x1DE97C, 1)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'source path changed'):
            instruction_controls(changed)

if __name__ == '__main__':
    unittest.main()
