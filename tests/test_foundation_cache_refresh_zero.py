#!/usr/bin/env python3
"""Unit tests for the foundation cache-refresh zero-test checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_cache_refresh_zero -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_cache_refresh_zero as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-cache-refresh-zero-94",
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


class TestCacheRefreshZero(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        # Raises on any mismatch; silence is success.
        checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)

    def test_zero_result_returns_one_and_stores_zero(self):
        glob, low = checker.evaluate_rule(0)
        self.assertEqual((glob, low), (0, 1))

    def test_nonzero_result_returns_zero_and_stores_unchanged(self):
        self.assertEqual(checker.evaluate_rule(1), (1, 0))
        self.assertEqual(
            checker.evaluate_rule(0x123456789ABCDEF0),
            (0x123456789ABCDEF0, 0))

    def test_zero_low_byte_with_nonzero_upper_still_returns_zero(self):
        # The test is on the full rax (test rax, rax), not on al alone:
        # 0x100 has a zero low byte but is nonzero, so the verdict is 0.
        self.assertEqual(checker.evaluate_rule(0x100), (0x100, 0))

    def test_max_result(self):
        self.assertEqual(
            checker.evaluate_rule(0xFFFFFFFFFFFFFFFF),
            (0xFFFFFFFFFFFFFFFF, 0))

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            glob, low = checker.evaluate_rule(int(edge["callee_result"], 16))
            self.assertEqual(hex(glob), edge["global_after"], edge)
            self.assertEqual(low, edge["result_low_byte"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x54d5f30")
        self.assertEqual(call["site"], "0x54d6376")
        self.assertTrue(call["target_fde_start"])
        self.assertEqual(call["target_fde_extent"], 592)
        self.assertEqual(call["target_fde_section_offset"], "0x002c12c4")
        self.assertEqual(call["target_bytes"], "f30f1efa4157")

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], ["0x54b9ce3"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x54b9b60"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        with open(os.path.join(self.packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("54d6360:", window)
        self.assertIn("54d6376:", window)
        self.assertIn("54d637e:", window)
        self.assertIn("54d6385:", window)
        self.assertIn("54d638c:", window)
        with open(os.path.join(self.packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        self.assertIn("54b9ce3:", caller)
        with open(os.path.join(self.packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("54d6360..00000000054d638d", frames)
        self.assertIn("002c1438", frames)
        self.assertIn("002c12c4", frames)
        self.assertIn("002bfa24", frames)
        self.assertIn("54d6390", frames)

    def _corrupted(self, mutate):
        ev = copy.deepcopy(self.ev)
        mutate(ev)
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corruption_body_sha(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__("sha256", "0" * 64))

    def test_corruption_padding_count(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__("padding_bytes", 2))

    def test_corruption_window_fde_offset(self):
        self._corrupted(
            lambda ev: ev["function"].__setitem__(
                "fde_section_offset", "0xdeadbeef"))

    def test_corruption_call_target(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target", "0x54d5f31"))

    def test_corruption_callee_fde_claim(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target_fde_start", False))

    def test_corruption_callee_fde_extent(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target_fde_extent", 591))

    def test_corruption_caller_list(self):
        self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x5000000"]))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["result_low_byte"] = 0
        self._corrupted(mutate)

    def test_corruption_global_after(self):
        def mutate(ev):
            ev["rule"]["edges"][1]["global_after"] = "0x2"
        self._corrupted(mutate)

    def test_corruption_target_digest(self):
        self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))


if __name__ == "__main__":
    unittest.main()
