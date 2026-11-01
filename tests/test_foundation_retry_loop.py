#!/usr/bin/env python3
"""Unit tests for the foundation retry-loop checker (node #94, 0x3cbefb0).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_retry_loop -v

Corruption controls run in memory: the evidence dict is deep-copied and
tampered, and the binary is copied as a bytearray with single-byte flips.
No file in the packet directory is modified by any test.
"""

import copy
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import foundation_retry_loop as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-retry-loop-94")
EVIDENCE_PATH = os.path.join(PACKET_DIR, "evidence.json")


def load_all():
    with open(EVIDENCE_PATH) as fh:
        ev = json.load(fh)
    with open(checker.BINARY, "rb") as fh:
        binary = fh.read()
    sections = checker.elf_sections(binary)
    return ev, binary, sections


class TestRetryLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections = load_all()
        cls.packet_dir = os.path.abspath(PACKET_DIR)

    def test_checker_reproduces(self):
        checker.run_evidence(
            copy.deepcopy(self.ev), self.binary, self.sections,
            self.packet_dir)

    def test_edge_count(self):
        self.assertEqual(len(self.ev["rule"]["edges"]), 8)

    def test_instruction_rows_cover_complete_target_body(self):
        # GNU --insn-width=16 shows one 15-byte NOP at 0x3cbefe1;
        # the default seven-byte display wraps it across three lines.
        body = b"".join(bytes.fromhex(checker.INSTR[va])
                        for va in sorted(checker.INSTR))
        target = checker.read_va(self.binary, self.sections, 0x3CBEFB0, 115)
        self.assertEqual(body, target)

    def test_instruction_gap_is_rejected(self):
        truncated = dict(checker.INSTR)
        truncated[0x3CBEFE1] = "6666666666662e"
        with mock.patch.object(checker, "INSTR", truncated):
            with self.assertRaises(ValueError):
                checker.check_window(self.ev, self.binary, self.sections)

    def test_simulate_zero_attempts(self):
        self.assertEqual(checker.simulate(0, []), (0, 0))

    def test_simulate_all_zero(self):
        self.assertEqual(checker.simulate(3, [0, 0, 0]), (0, 3))
        self.assertEqual(checker.simulate(5, [0, 0, 0, 0, 0]), (0, 5))

    def test_simulate_early_exit(self):
        self.assertEqual(checker.simulate(2, [3]), (3, 1))
        self.assertEqual(checker.simulate(1, [7]), (7, 1))
        self.assertEqual(checker.simulate(2, [0, 9]), (9, 2))
        self.assertEqual(checker.simulate(3, [0, 0, 5]), (5, 3))

    def test_simulate_malformed_edge(self):
        with self.assertRaises(ValueError):
            checker.simulate(3, [0, 0])

    def test_edge_trailing_results_rejected(self):
        edge = copy.deepcopy(self.ev["rule"]["edges"][6])
        edge["callee_results"] = ["0x3", "0x0"]
        with self.assertRaises(ValueError):
            checker.evaluate_edge(edge)

    def test_corrupt_body_byte(self):
        binary = bytearray(self.binary)
        sections = checker.elf_sections(bytes(binary))
        addr, off, _ = sections[".text"]
        # Flip one byte inside the window body (the call opcode).
        pos = off + (0x3CBF003 - addr)
        binary[pos] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.run_evidence(
                copy.deepcopy(self.ev), bytes(binary), sections,
                self.packet_dir)

    def test_corrupt_padding_byte(self):
        binary = bytearray(self.binary)
        sections = checker.elf_sections(bytes(binary))
        addr, off, _ = sections[".text"]
        pos = off + (0x3CBF023 - addr)
        binary[pos] = 0x90
        with self.assertRaises(ValueError):
            checker.run_evidence(
                copy.deepcopy(self.ev), bytes(binary), sections,
                self.packet_dir)

    def test_corrupt_call_target(self):
        ev = copy.deepcopy(self.ev)
        ev["call"]["target"] = "0x3cc6501"
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_digest(self):
        ev = copy.deepcopy(self.ev)
        ev["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_edge_result(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][3]["result"] = "0x8"
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_edge_calls(self):
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][4]["calls_made"] = 2
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_caller_list(self):
        ev = copy.deepcopy(self.ev)
        ev["incoming"]["direct_e8_callers"] = []
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_window_fde_offset(self):
        ev = copy.deepcopy(self.ev)
        ev["function"]["fde_section_offset"] = "0x001ccb3d"
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_callee_extent(self):
        ev = copy.deepcopy(self.ev)
        ev["call"]["target_fde_extent"] = 301
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_body_sha(self):
        ev = copy.deepcopy(self.ev)
        ev["function"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.run_evidence(
                ev, self.binary, self.sections, self.packet_dir)

    def test_corrupt_global_address(self):
        binary = bytearray(self.binary)
        sections = checker.elf_sections(bytes(binary))
        addr, off, _ = sections[".text"]
        # Flip a byte of the mov rbp rip-relative displacement.
        pos = off + (0x3CBEFCE + 3 - addr)
        binary[pos] ^= 0x01
        with self.assertRaises(ValueError):
            checker.run_evidence(
                copy.deepcopy(self.ev), bytes(binary), sections,
                self.packet_dir)

    def test_window_fde_cie_differs_from_callee(self):
        # Recorded honestly: the window uses CIE 0x00000000 while the
        # callee and caller records use CIE 0x002dc714.
        self.assertEqual(self.ev["function"]["fde_cie"], "0x00000000")
        self.assertEqual(
            self.ev["incoming"]["validated_caller_fdes"][0]["fde_cie"],
            "0x002dc714")


if __name__ == "__main__":
    unittest.main()
