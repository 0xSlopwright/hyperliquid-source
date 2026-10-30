"""Real-target corruption controls for the compact-string static packet."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from short_string_static import CALLERS, controls, decoded_reference, read_va, relevant_relocations


class ShortStringStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == 'artifacts/node/94/hl-node')
        check(path, identity)
        cls.data = path.read_bytes()

    def test_real_admission_packing_alias_controls(self):
        self.assertEqual(len(controls(self.data)), 23)
        self.assertEqual(len(relevant_relocations(self.data)), 5)

    def test_real_representation_and_route_corruptions(self):
        # Deliberately bypass the global SHA check: exercise each local proof
        # obligation, not just rejection of an altered whole-file digest.
        for va in [0x1449A9B, 0x1449ADF, 0x1449AF2, 0x1449C99,
                   0x1449CB2, 0x1449CCA, 0x1449D8F, 0x144A018,
                   0x144A01F, 0x144A026, 0x144A02C, 0x144A035,
                   0x13C611F, 0x13C6242, 0x13C6257, 0x1EA56A]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    controls(changed)

    def test_real_got_and_source_attribution_retargets_rejected(self):
        for slot, target in [(0x576F5F0, 0x144A010), (0x576E798, 0x1449A80),
                             (0x566A9A8, 0x1EA56A)]:
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = changed.find(struct.pack('<QQq', slot, 8, target))
                self.assertGreaterEqual(offset, 0)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relevant_relocations(changed)

    def test_real_caller_bytes_resolve_to_constructor_slot(self):
        for site, _, _ in CALLERS:
            body = read_va(self.data, site, 6)[1]
            line = f' {site:x}: {body.hex(" ")}   call *displacement(%rip)'
            self.assertEqual(decoded_reference(line), (site, 'GOT', 0x576E798))

    def test_address_mentions_are_not_decoded_calls(self):
        self.assertIsNone(decoded_reference('0x576e798 mentioned as data'))
        self.assertIsNone(decoded_reference(' 144a026: ff d3 call *%rbx # 576f5f0'))
