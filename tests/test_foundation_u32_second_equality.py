#!/usr/bin/env python3
"""Unit tests for the foundation u32 second-field equality checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_u32_second_equality -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_u32_second_equality as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-u32-second-equality-94",
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


class TestU32SecondEquality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        # Raises on any mismatch; silence is success.
        checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)

    def test_gate_failure_returns_zero_without_call(self):
        # Unequal u32 seconds return 0 regardless of the buffers.
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(5, 6, b"abcdefgh", b"abcdefgh"), 0)
        self.assertEqual(ev(0, 1, b"abc", b"xyz"), 0)
        self.assertEqual(ev(4294967295, 0, b"abc", b"abc"), 0)

    def test_zero_count_memcmp_returns_one(self):
        # Equal zero seconds give a zero-length memcmp, which is equal.
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(0, 0, b"abcdefgh", b"ABCDEFGH"), 1)
        self.assertEqual(ev(0, 0, b"", b""), 1)

    def test_scaled_length_is_count_times_eight(self):
        # One element is 8 bytes; two elements are 16 bytes.
        ev = checker.evaluate_low_byte
        self.assertEqual(ev(1, 1, b"abcdefgh", b"abcdefgh"), 1)
        self.assertEqual(ev(1, 1, b"abcdefgX", b"abcdefgh"), 0)
        self.assertEqual(ev(2, 2, b"0123456789abcdef", b"0123456789abcdef"), 1)
        self.assertEqual(ev(2, 2, b"0123456789abcdeX", b"0123456789abcdef"), 0)

    def test_difference_beyond_scaled_length_ignored(self):
        # Buffers equal over the compared range differ only past it.
        ev = checker.evaluate_low_byte
        self.assertEqual(
            ev(2, 2, b"0123456789abcdefZZ", b"0123456789abcdefYY"), 1)
        self.assertEqual(
            ev(1, 1, b"abcdefghZZ", b"abcdefghYY"), 1)

    def test_max_u32_count(self):
        ev = checker.evaluate_low_byte
        m = (1 << 32) - 1
        self.assertEqual(ev(m, m, b"abcdefgh", b"abcdefgh"), 1)
        self.assertEqual(ev(m, m, b"abcdefgX", b"abcdefgh"), 0)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_low_byte(
                edge["a_second"], edge["b_second"],
                edge["buf_a"].encode(), edge["buf_b"].encode())
            self.assertEqual(got, edge["result_low_byte"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660150")
        self.assertEqual(call["site"], "0x552fbfa")
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
        self.assertIn("552fbe0:", window)
        self.assertIn("552fbfa:", window)
        self.assertIn("552fc10:", window)
        self.assertIn("552fc12:", window)
        with open(os.path.join(self.packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("552fbe0..000000000552fc13", frames)
        self.assertIn("002cbaa0", frames)
        self.assertIn("552fc20", frames)

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
            ev["rule"]["edges"][1]["result_low_byte"] = 1
        self._corrupted(mutate)

    def test_corruption_target_digest(self):
        self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))


if __name__ == "__main__":
    unittest.main()
