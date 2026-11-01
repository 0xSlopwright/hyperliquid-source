#!/usr/bin/env python3
"""Unit tests for the foundation global-bounds-gated equality checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_global_bounds_equality -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_global_bounds_equality as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-global-bounds-equality-94",
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


class TestGlobalBoundsEquality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_gate_rejects_below_global(self):
        self.assertEqual(checker.evaluate_rule(50, 100, 999), 0)
        self.assertEqual(checker.evaluate_rule(0, 100, 0), 0)

    def test_equal_seconds_match_callee_zero(self):
        self.assertEqual(checker.evaluate_rule(100, 100, 0), 1)
        self.assertEqual(checker.evaluate_rule(100, 100, 5), 0)

    def test_above_global_matches_difference(self):
        self.assertEqual(checker.evaluate_rule(150, 100, 50), 1)
        self.assertEqual(checker.evaluate_rule(150, 100, 49), 0)
        self.assertEqual(checker.evaluate_rule(150, 100, 0), 0)

    def test_max_edges(self):
        max64 = (1 << 64) - 1
        self.assertEqual(checker.evaluate_rule(max64, max64, 0), 1)
        self.assertEqual(checker.evaluate_rule(max64, 0, max64), 1)
        self.assertEqual(checker.evaluate_rule(0, 0, 0), 1)
        self.assertEqual(checker.evaluate_rule(max64, max64 - 1, 1), 1)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_rule(
                int(edge["input_second"], 16),
                int(edge["global_second"], 16),
                edge["callee_result"])
            self.assertEqual(got, edge["result"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660df0")
        self.assertFalse(call["target_fde_start"])
        self.assertIsNone(call["target_fde_extent"])

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(len(incoming["direct_e8_callers"]), 3)
        self.assertIn("0x528f20d", incoming["direct_e8_callers"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x528f020"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        packet_dir = self.packet_dir
        with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("528e936:", window)
        self.assertIn("528e953:", window)
        self.assertIn("528f20d:", caller)
        self.assertIn("528e900", caller)

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
            lambda ev: ev["call"].__setitem__("target", "0x5660df1"))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_caller_site(self):
        failures = self._corrupted(
            lambda ev: ev["incoming"].__setitem__("direct_e8_callers", []))
        self.assertTrue(any("caller" in f for f in failures))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["result"] = 1
        failures = self._corrupted(mutate)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_corruption_target_digest(self):
        failures = self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))
        self.assertTrue(any("target digest" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
