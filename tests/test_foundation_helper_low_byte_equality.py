#!/usr/bin/env python3
"""Unit tests for the foundation helper low-byte equality checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_helper_low_byte_equality -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_helper_low_byte_equality as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-helper-low-byte-equality-94",
    "evidence.json")
BINARY = os.path.join("artifacts", "node", "94", "hl-node")


def load_fixture():
    with open(EVIDENCE) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = checker.elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(EVIDENCE))
    return ev, binary, sections, packet_dir


class TestHelperLowByteEquality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_plain_match_and_mismatch(self):
        self.assertEqual(checker.evaluate_rule(0x42, 0x42), 1)
        self.assertEqual(checker.evaluate_rule(0x42, 0x43), 0)

    def test_upper_bytes_ignored(self):
        self.assertEqual(checker.evaluate_rule(0x1234, 0x34), 1)
        self.assertEqual(checker.evaluate_rule(0x1200, 0x34), 0)
        self.assertEqual(checker.evaluate_rule(0x1FF, 0xFF), 1)
        self.assertEqual(checker.evaluate_rule(0x100, 0x00), 1)

    def test_zero_and_max_edges(self):
        self.assertEqual(checker.evaluate_rule(0x00, 0x00), 1)
        self.assertEqual(checker.evaluate_rule(0x00, 0x01), 0)
        self.assertEqual(checker.evaluate_rule(0xFF, 0xFF), 1)
        self.assertEqual(checker.evaluate_rule(0xFFFFFFFFFFFFFFFF, 0xFF), 1)
        self.assertEqual(
            checker.evaluate_rule(0xFFFFFFFFFFFFFF00, 0x00), 1)
        self.assertEqual(checker.evaluate_rule(0x80, 0x7F), 0)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_rule(
                int(edge["callee_result"], 16), int(edge["stored_byte"], 16))
            self.assertEqual(got, edge["result"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x4ff8ac0")
        self.assertTrue(call["target_fde_start"])
        self.assertEqual(call["target_fde_extent"], 104)

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], ["0x50071c9"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x50070f0"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        packet_dir = self.packet_dir
        with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("5004e91:", window)
        self.assertIn("5004ea1:", window)
        self.assertIn("5004e70:", window)
        with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("50071c9:", caller)
        with open(os.path.join(packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("5004e70..0000000005004ea1", frames)
        self.assertIn("4ff8ac0..0000000004ff8b28", frames)
        self.assertIn("50070f0..00000000050073c7", frames)

    def _corrupted(self, mutate):
        ev = copy.deepcopy(self.ev)
        mutate(ev)
        return checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)

    def test_corruption_body_sha(self):
        failures = self._corrupted(
            lambda ev: ev["function"].__setitem__("sha256", "0" * 64))
        self.assertTrue(any("window body" in f for f in failures))

    def test_corruption_padding_count(self):
        failures = self._corrupted(
            lambda ev: ev["function"].__setitem__("padding_bytes", 2))
        self.assertTrue(any("padding" in f for f in failures))

    def test_corruption_window_fde_offset(self):
        failures = self._corrupted(
            lambda ev: ev["function"].__setitem__(
                "fde_section_offset", "0xdeadbeef"))
        self.assertTrue(any("frames" in f for f in failures))

    def test_corruption_call_target(self):
        failures = self._corrupted(
            lambda ev: ev["call"].__setitem__("target", "0x4ff8ac1"))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_caller_list(self):
        failures = self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x50071ca"]))
        self.assertTrue(any("callers" in f for f in failures))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["result"] = 0
        failures = self._corrupted(mutate)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_corruption_target_digest(self):
        failures = self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))
        self.assertTrue(any("target digest" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
