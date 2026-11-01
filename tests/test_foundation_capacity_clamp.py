#!/usr/bin/env python3
"""Unit tests for the foundation capacity-clamp checker (node #94, 0x4f050a0).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_capacity_clamp -v

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
import foundation_capacity_clamp as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-capacity-clamp-94")
EVIDENCE_PATH = os.path.join(PACKET_DIR, "evidence.json")


def load_all():
    with open(EVIDENCE_PATH) as fh:
        ev = json.load(fh)
    with open(checker.BINARY, "rb") as fh:
        binary = fh.read()
    sections = checker.elf_sections(binary)
    return ev, binary, sections


class TestCapacityClamp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections = load_all()
        cls.packet_dir = os.path.abspath(PACKET_DIR)

    def test_checker_reproduces(self):
        checker.run_evidence(
            copy.deepcopy(self.ev), self.binary, self.sections,
            self.packet_dir)

    def test_edge_count(self):
        self.assertEqual(len(self.ev["rule"]["edges"]), 11)

    def test_formula_ordinary(self):
        self.assertEqual(checker.newcap(10, 5), 6)

    def test_formula_upper_clamp(self):
        self.assertEqual(checker.newcap(10, 100), 20)

    def test_formula_upper_clamp_equality(self):
        self.assertEqual(checker.newcap(10, 19), 20)

    def test_formula_floor(self):
        self.assertEqual(checker.newcap(0, 0), 4)
        self.assertEqual(checker.newcap(1, 100), 4)
        self.assertEqual(checker.newcap(3, 2), 4)

    def test_formula_floor_boundary(self):
        self.assertEqual(checker.newcap(3, 4), 5)
        self.assertEqual(checker.newcap(3, 3), 4)

    def test_formula_wraps(self):
        self.assertEqual(checker.newcap(0xFFFFFFFFFFFFFFFF, 0), 4)
        self.assertEqual(checker.newcap(10, 0xFFFFFFFFFFFFFFFF), 4)

    def test_flag_paths(self):
        edge_set = copy.deepcopy(self.ev["rule"]["edges"][2])
        result, pair, stored = checker.evaluate_edge(edge_set)
        self.assertEqual(result, 0x8000000000000001)
        self.assertIsNone(pair)
        self.assertEqual(stored, {"cap": "0x6", "ptr": "0x3000"})
        edge_pair = copy.deepcopy(self.ev["rule"]["edges"][0])
        result, pair, stored = checker.evaluate_edge(edge_pair)
        self.assertEqual(result, 0x3000)
        self.assertEqual(pair, {"rax": "0x3000", "rdx": "0x6"})
        self.assertIsNone(stored)

    def test_corrupt_body_byte(self):
        tampered = bytearray(self.binary)
        # Flip one byte inside the window body (the inc rsi at 0x4f050ae).
        off = 0x4F050AE - 0x1000
        tampered[off] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.check_window(
                self.ev, bytes(tampered), self.sections)

    def test_corrupt_padding_byte(self):
        tampered = bytearray(self.binary)
        off = 0x4F0510E - 0x1000
        tampered[off] = 0x90
        with self.assertRaises(ValueError):
            checker.check_padding(
                self.ev, bytes(tampered), self.sections)

    def test_corrupt_call_target(self):
        tampered = bytearray(self.binary)
        # Flip a byte of the call rel32 at 0x4f050db.
        off = 0x4F050DB - 0x1000 + 1
        tampered[off] ^= 0x01
        with self.assertRaises(ValueError):
            checker.check_callee_call(
                self.ev, bytes(tampered), self.sections)

    def test_corrupt_digest(self):
        ev = copy.deepcopy(self.ev)
        ev["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.check_target_digest(ev, self.binary)

    def test_corrupt_body_sha(self):
        ev = copy.deepcopy(self.ev)
        ev["function"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.check_window(ev, self.binary, self.sections)

    def test_corrupt_window_fde_offset(self):
        ev = copy.deepcopy(self.ev)
        ev["function"]["fde_section_offset"] = "0x00282369"
        with self.assertRaises(ValueError):
            checker.check_frames(ev, self.packet_dir)

    def test_corrupt_callee_extent(self):
        ev = copy.deepcopy(self.ev)
        ev["call"]["target_fde_extent"] = 143
        with self.assertRaises(ValueError):
            checker.check_callee_call(ev, self.binary, self.sections)

    def test_corrupt_caller_list(self):
        ev = copy.deepcopy(self.ev)
        ev["incoming"]["direct_e8_callers"] = []
        with self.assertRaises(ValueError):
            checker.check_callers(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_sentinel_flag(self):
        ev = copy.deepcopy(self.ev)
        ev["incoming"]["validated_caller_fdes"][0]["sentinel_check"] = False
        with self.assertRaises(ValueError):
            checker.check_callers(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_edge_result(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["result"] = "0x3001"
        with self.assertRaises(ValueError):
            checker.check_edges(ev)

    def test_corrupt_edge_newcap(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["newcap"] = "0x7"
        with self.assertRaises(ValueError):
            checker.check_edges(ev)

    def test_corrupt_edge_pair(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["pair"] = {"rax": "0x3000", "rdx": "0x7"}
        with self.assertRaises(ValueError):
            checker.check_edges(ev)

    def test_corrupt_edge_stored(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][2]["stored"] = {"cap": "0x6", "ptr": "0x3001"}
        with self.assertRaises(ValueError):
            checker.check_edges(ev)


if __name__ == "__main__":
    unittest.main()
