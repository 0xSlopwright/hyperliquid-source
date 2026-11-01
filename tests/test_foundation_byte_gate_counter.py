#!/usr/bin/env python3
"""Unit tests for the foundation byte-gate counter checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_byte_gate_counter -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_byte_gate_counter as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-byte-gate-counter-94",
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


class TestByteGateCounter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_nonzero_second_selects_flag(self):
        # Any pointers and bytes: a nonzero second skips the gate.
        self.assertEqual(checker.evaluate_flag(1, 0x2008, 0x3000, 0x00, 0x00), 1)
        self.assertEqual(checker.evaluate_flag(0xFF, 0x2008, 0x2008, 0xFF, 0x00), 1)
        self.assertEqual(
            checker.evaluate_flag(0xFFFFFFFFFFFFFFFF, 0x0, 0x0, 0x00, 0xFF), 1)

    def test_zero_second_pointer_equality_selects_flag(self):
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x2008, 0xFF, 0x00), 1)
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x2008, 0x00, 0xFF), 1)

    def test_zero_second_byte_gate(self):
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0x10, 0x20), 1)
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0x20, 0x20), 0)
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0x30, 0x20), 0)

    def test_byte_gate_is_unsigned_not_signed(self):
        # 0xff below 0x00 would be true signed; unsigned it is false.
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0xFF, 0x00), 0)
        # 0x00 below 0xff would be false signed; unsigned it is true.
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0x00, 0xFF), 1)
        # 0x80 below 0x7f: signed true, unsigned false.
        self.assertEqual(checker.evaluate_flag(0, 0x2008, 0x3000, 0x80, 0x7F), 0)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.ev["rule"]["edges"]:
            got = checker.evaluate_flag(
                int(edge["second"], 16), int(edge["input_plus8"], 16),
                int(edge["third"], 16), int(edge["byte_fourth"], 16),
                int(edge["byte_third"], 16))
            self.assertEqual(got, edge["result_flag"], edge)
            self.assertEqual(
                (int(edge["counter_before"], 16) + 1) % (1 << 64),
                int(edge["counter_after"], 16), edge)
            self.assertEqual(edge["return_value"], edge["fourth"], edge)

    def test_callee_record(self):
        call = self.ev["call"]
        self.assertEqual(call["target"], "0x5660550")
        self.assertFalse(call["target_fde_start"])
        self.assertIsNone(call["target_fde_extent"])

    def test_caller_list(self):
        incoming = self.ev["incoming"]
        self.assertEqual(incoming["direct_e8_callers"], [
            "0x4fe680e", "0x4fe68c7", "0x4fe69d0", "0x4fe6b54"])
        self.assertEqual(incoming["validated_caller_fdes"], ["0x4fe4e50"])
        self.assertFalse(incoming["complete_xref_census"])

    def test_retained_disassembly_lines(self):
        packet_dir = self.packet_dir
        with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
            window = fh.read()
        self.assertIn("4fd6051:", window)
        self.assertIn("4fd607c:", window)
        self.assertIn("4fd6030:", window)
        with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
            caller = fh.read()
        for site in ("4fe680e:", "4fe68c7:", "4fe69d0:", "4fe6b54:"):
            self.assertIn(site, caller)
        self.assertIn("4fd6030", caller)
        with open(os.path.join(packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        self.assertIn("4fd6030..0000000004fd607c", frames)
        self.assertIn("4fe4e50..0000000004fe72b2", frames)

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
            lambda ev: ev["call"].__setitem__("target", "0x5660551"))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_callee_fde_claim(self):
        failures = self._corrupted(
            lambda ev: ev["call"].__setitem__("target_fde_start", True))
        self.assertTrue(any("callee call" in f for f in failures))

    def test_corruption_caller_list(self):
        failures = self._corrupted(
            lambda ev: ev["incoming"].__setitem__(
                "direct_e8_callers", ["0x4fe680e"]))
        self.assertTrue(any("callers" in f for f in failures))

    def test_corruption_rule_edge(self):
        def mutate(ev):
            ev["rule"]["edges"][2]["result_flag"] = 0
        failures = self._corrupted(mutate)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_corruption_return_value(self):
        def mutate(ev):
            ev["rule"]["edges"][0]["return_value"] = "0x9999"
        failures = self._corrupted(mutate)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_corruption_target_digest(self):
        failures = self._corrupted(
            lambda ev: ev.__setitem__("target_sha256", "0" * 64))
        self.assertTrue(any("target digest" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
