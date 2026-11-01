#!/usr/bin/env python3
"""Unit tests for the foundation struct-init flag-pack checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_struct_init_flag -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_struct_init_flag as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-struct-init-flag-94",
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


class TestStructInitFlag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_zero_second_skips_call(self):
        self.assertEqual(checker.evaluate_rule(0, 0x00, None), (0, None))
        self.assertEqual(checker.evaluate_rule(0, 0xFF, None), (0, None))
        # Even a would-be callee value is meaningless on the skip path.
        self.assertEqual(checker.evaluate_rule(0, 0x00, 999), (0, None))

    def test_flag_packing(self):
        self.assertEqual(checker.evaluate_rule(5, 0x00, 42), (42, 0x22))
        self.assertEqual(checker.evaluate_rule(5, 0x01, 42), (42, 0x40022))
        self.assertEqual(checker.evaluate_rule(5, 0xFF, 42), (42, 0x3FC0022))
        self.assertEqual(checker.evaluate_rule(5, 0xAB, 42), (42, 0x2AC0022))

    def test_minus_one_maps_to_zero(self):
        max64 = (1 << 64) - 1
        self.assertEqual(checker.evaluate_rule(5, 0x00, max64), (0, 0x22))
        self.assertEqual(checker.evaluate_rule(5, 0xAB, max64), (0, 0x2AC0022))
        # Near -1 passes through unchanged.
        self.assertEqual(
            checker.evaluate_rule(1, 0x00, max64 - 1), (max64 - 1, 0x22))

    def test_max_second(self):
        max64 = (1 << 64) - 1
        self.assertEqual(checker.evaluate_rule(max64, 0x00, 7), (7, 0x22))

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_rule(
                int(edge["second"], 16),
                int(edge["flag"], 16),
                edge["callee_result"])
            want_packed = None if edge["packed"] is None else int(edge["packed"], 16)
            self.assertEqual(got, (edge["out0"], want_packed), edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660c60")
        self.assertFalse(call["target_fde_start"])
        self.assertIsNone(call["target_fde_extent"])

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(len(incoming["direct_e8_callers"]), 1)
        self.assertIn("0x5334a41", incoming["direct_e8_callers"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x5334a20"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        packet_dir = self.packet_dir
        with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("5334a01:", window)
        self.assertIn("5334a18:", window)
        self.assertIn("5334a41:", caller)
        self.assertIn("53349d0", caller)

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
            lambda ev: ev["call"].__setitem__("target", "0x5660c61"))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_caller_site(self):
        failures = self._corrupted(
            lambda ev: ev["incoming"].__setitem__("direct_e8_callers", []))
        self.assertTrue(any("caller" in f for f in failures))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["out0"] = 1
        failures = self._corrupted(mutate)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_corruption_target_digest(self):
        failures = self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))
        self.assertTrue(any("target digest" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
