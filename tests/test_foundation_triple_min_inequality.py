#!/usr/bin/env python3
"""Unit tests for the foundation triple-min inequality checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_triple_min_inequality -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_triple_min_inequality as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-triple-min-inequality-94",
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


class TestTripleMinInequality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        # Raises on any mismatch; silence is success.
        checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)

    def test_triple_min_basic(self):
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(10, 20, 30, b"abcdefghij", b"abcdefghij"), 0)
        self.assertEqual(ev(10, 20, 30, b"abcXefghij", b"abcdefghij"), 1)

    def test_partial_mins_equal_when_first_is_minimum(self):
        # a is the overall minimum: both partial minima equal a, leg clear.
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(5, 20, 30, b"abcde", b"abcde"), 0)
        self.assertEqual(ev(5, 5, 30, b"abcde", b"abcde"), 0)
        self.assertEqual(ev(5, 20, 5, b"abcde", b"abcde"), 0)

    def test_partial_mins_differ_shapes(self):
        # Exactly one field second strictly smallest: partial minima differ.
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(30, 10, 20, b"abcdefghij", b"abcdefghij"), 1)
        self.assertEqual(ev(30, 20, 10, b"abcdefghij", b"abcdefghij"), 1)
        # Both field seconds equal and below a: partial minima agree.
        self.assertEqual(ev(30, 10, 10, b"abcdefghij", b"abcdefghij"), 0)

    def test_memcmp_length_is_triple_min(self):
        # Difference beyond the triple-min length is not compared.
        ev = checker.evaluate_low_byte
        self.assertEqual(
            ev(10, 20, 30, b"abcdefghijX", b"abcdefghijZ"), 0)
        self.assertEqual(
            ev(10, 20, 30, b"abcdefghijX", b"abcdefghijZ"[:10] + b"Y"), 0)

    def test_zero_length_memcmp(self):
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(0, 20, 30, b"abc", b"xyz"), 0)
        self.assertEqual(ev(0, 0, 0, b"", b""), 0)

    def test_max_values(self):
        ev = checker.evaluate_low_byte
        m = (1 << 64) - 1
        self.assertEqual(ev(m, 5, 5, b"abcde", b"abcde"), 0)
        self.assertEqual(ev(m, 5, 5, b"abcde", b"abcdf"), 1)
        self.assertEqual(ev(m, m, m, b"abc", b"abc"), 0)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_low_byte(
                edge["a_second"], edge.get("first_second", edge["a_second"]),
                edge.get("second_second", edge["a_second"]),
                edge["buf1"].encode(), edge["buf2"].encode())
            self.assertEqual(got, edge["result_low_byte"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660150")
        self.assertEqual(call["site"], "0x52f2b91")
        self.assertFalse(call["target_fde_start"])
        self.assertIsNone(call["target_fde_extent"])
        self.assertEqual(call["target_bytes"], "ff257a8c1100")

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], [])
        self.assertEqual(incoming["validated_caller_fdes"], [])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        with open(os.path.join(self.packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("52f2b50:", window)
        self.assertIn("52f2b91:", window)
        self.assertIn("52f2ba9:", window)
        self.assertIn("52f2baa:", window)
        with open(os.path.join(self.packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("52f2b50..00000000052f2baa", frames)
        self.assertIn("002ae0cc", frames)

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
            lambda ev: ev["call"].__setitem__("target", "0x5660151"))

    def test_corruption_callee_fde_claim(self):
        self._corrupted(
            lambda ev: ev["call"].__setitem__("target_fde_start", True))

    def test_corruption_caller_list(self):
        self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x5000000"]))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][1]["result_low_byte"] = 0
        self._corrupted(mutate)

    def test_corruption_target_digest(self):
        self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))


if __name__ == "__main__":
    unittest.main()
