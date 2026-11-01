#!/usr/bin/env python3
"""Unit tests for the foundation set-once cell checker (node #94, 0x1515a30).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_set_once_366 -v

Corruption controls run in memory: the evidence dict is deep-copied and
tampered, and the binary is copied as a bytearray with single-byte flips.
No file in the packet directory is modified by any test.
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import foundation_set_once_366 as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-set-once-366-94")
EVIDENCE_PATH = os.path.join(PACKET_DIR, "evidence.json")


def load_all():
    with open(EVIDENCE_PATH) as fh:
        ev = json.load(fh)
    with open(checker.TARGET, "rb") as fh:
        binary = fh.read()
    return ev, binary


class TestSetOnce366(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary = load_all()

    def test_checker_reproduces(self):
        checker.analyze(self.binary, copy.deepcopy(self.ev))

    def test_simulate_out_of_range(self):
        for original in (0, 367, 1000, 2 ** 32):
            al, eax, flag, stored = checker.simulate(0, 0, original)
            self.assertEqual((al, eax, stored), (0, 0, None))
            self.assertEqual(flag, 0)

    def test_simulate_boundaries(self):
        self.assertEqual(checker.simulate(0, 0, 1)[:2], (8, 8))
        self.assertEqual(checker.simulate(0, 0, 366)[1], 0x108)
        self.assertEqual(checker.simulate(0, 0, 255)[1], 8)
        self.assertEqual(checker.simulate(0, 0, 256)[1], 8)
        self.assertEqual(checker.simulate(0, 0, 257)[1], 0x108)

    def test_simulate_store_any_nonone_flag(self):
        for flag in (0, 2, 0xFFFFFFFF):
            al, eax, new_flag, stored = checker.simulate(flag, 999, 42)
            self.assertEqual((al, new_flag, stored), (8, 1, 42))

    def test_simulate_compare(self):
        self.assertEqual(checker.simulate(1, 42, 42)[:2], (8, 8))
        self.assertEqual(checker.simulate(1, 42, 43)[:2], (1, 1))
        self.assertEqual(checker.simulate(1, 42, 42)[3], None)

    def test_corrupt_body_byte(self):
        binary = bytearray(self.binary)
        # Flip the range immediate byte (0x6d -> 0x92): window lock fails.
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        text = by_name[".text"]
        pos = text["offset"] + (0x1515A36 - text["address"])
        binary[pos] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_padding_byte(self):
        binary = bytearray(self.binary)
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        text = by_name[".text"]
        pos = text["offset"] + (0x1515A63 - text["address"])
        binary[pos] = 0x90
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_fde_byte(self):
        binary = bytearray(self.binary)
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        eh = by_name[".eh_frame"]
        pos = eh["offset"] + (checker.FDE_VA - eh["address"]) + 8
        binary[pos] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_digest(self):
        ev = copy.deepcopy(self.ev)
        ev["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corrupt_window_hash(self):
        ev = copy.deepcopy(self.ev)
        ev["window"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corrupt_range(self):
        ev = copy.deepcopy(self.ev)
        ev["cell"]["valid_inputs"]["hi"] = 365
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == "__main__":
    unittest.main()
