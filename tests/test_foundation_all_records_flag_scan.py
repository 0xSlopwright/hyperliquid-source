#!/usr/bin/env python3
"""Unit tests for the foundation all-records flag-scan checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_all_records_flag_scan -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_all_records_flag_scan as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-all-records-flag-scan-94",
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


class TestAllRecordsFlagScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_vacuous_zero_records(self):
        self.assertEqual(checker.evaluate_rule(0, [], None), 1)

    def test_single_record_edges(self):
        self.assertEqual(checker.evaluate_rule(1, [1], None), 1)
        self.assertEqual(checker.evaluate_rule(1, [0], None), 0)

    def test_zero_flag_position(self):
        self.assertEqual(checker.evaluate_rule(3, [0, 255, 128], None), 0)
        self.assertEqual(checker.evaluate_rule(3, [1, 0, 128], None), 0)
        self.assertEqual(checker.evaluate_rule(3, [1, 255, 0], None), 0)
        self.assertEqual(checker.evaluate_rule(3, [1, 255, 128], None), 1)

    def test_threshold_boundary(self):
        self.assertEqual(
            checker.evaluate_rule(10000, None, "all-nonzero"), 1)
        self.assertEqual(
            checker.evaluate_rule(10000, None, "contains-zero"), 0)
        self.assertEqual(
            checker.evaluate_rule(10001, None, "not-consulted (fast path)"), 1)

    def test_fast_path_ignores_flags(self):
        # Even a would-be zero flag cannot change the fast-path verdict.
        self.assertEqual(
            checker.evaluate_rule(10002, [0], "not-consulted (fast path)"), 1)
        self.assertEqual(
            checker.evaluate_rule((1 << 64) - 1, None,
                                  "not-consulted (fast path)"), 1)
        with self.assertRaises(ValueError):
            checker.evaluate_rule(10001, None, "all-nonzero")

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_rule(
                int(edge["count"], 16), edge["flags"], edge["flags_summary"])
            self.assertEqual(got, edge["result"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x3c1ada0")
        self.assertTrue(call["target_fde_start"])
        self.assertEqual(call["target_fde_extent"], 1070)

    def test_caller_list_empty(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], [])
        self.assertEqual(incoming["validated_caller_fdes"], [])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        packet_dir = self.packet_dir
        with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("3bde0cc:", window)
        self.assertIn("3bde10b:", window)
        self.assertIn("3bde0b0:", window)
        with open(os.path.join(packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("3bde0b0..0000000003bde10b", frames)
        self.assertIn("3c1ada0..0000000003c1b1ce", frames)

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
            lambda ev: ev["call"].__setitem__("target", "0x3c1ada1"))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_caller_list(self):
        failures = self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x3bde200"]))
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
