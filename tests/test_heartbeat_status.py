"""Corruption controls against the actual node #94 static observation."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from heartbeat_status import direct_callers, mapped, relocations, static_controls


class HeartbeatStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = ROOT / 'artifacts/node/94/hl-node'
        item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
        check(binary, item)
        cls.data = binary.read_bytes()

    def test_real_target_controls(self):
        self.assertEqual(len(static_controls(self.data)), 18)
        self.assertEqual(len(relocations(self.data)), 5)

    def test_real_branch_data_and_consumer_corruptions(self):
        # Invoke controls below the whole-artifact hash gate, so each rejection
        # demonstrates the relevant evidence check rather than only SHA mismatch.
        for va in [0x4726AC9, 0x4726B42, 0x4726B4A, 0x4726B54,
                   0x4726BC3, 0x4726C26, 0x4726C87, 0x4726CD3,
                   0x20ACD8, 0x6FB82A, 0x1447181, 0x4876FE3]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = mapped(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'control changed'):
                    static_controls(changed)

    def test_real_elapsed_relocation_retarget_is_rejected(self):
        changed = bytearray(self.data)
        # Locate the authenticated RELA triple without assuming its file offset.
        import struct
        needle = struct.pack('<QQq', 0x576E8C0, 8, 0x1447130)
        offset = changed.find(needle)
        self.assertGreaterEqual(offset, 0)
        changed[offset + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation targets changed'):
            relocations(changed)

    def test_callers_are_decoded_direct_calls_not_address_mentions(self):
        self.assertEqual(direct_callers([
            ' 4876fd9:\te8 72 fa ea ff       \tcall   4726a50 <label>',
            ' 487734c:\te8 ff f6 ea ff       \tcall   4726a50 <label>',
            ' 4726a50: 55 push %rbp',
            ' 123: ff d3 call *%rbx # 4726a50',
        ]), [0x4876FD9, 0x487734C])
