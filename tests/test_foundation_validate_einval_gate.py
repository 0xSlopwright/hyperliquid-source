#!/usr/bin/env python3
"""Unit tests for the foundation validate-or-EINVAL gate checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_validate_einval_gate -v

The checker itself is exercised through its in-memory entry points so every
corruption control mutates a copy, never the pinned binary or evidence.
"""

import copy
import importlib.util
import json
import os
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOL_PATH = os.path.join(
    REPO_ROOT, "tools", "foundation_validate_einval_gate.py")
EVIDENCE_PATH = os.path.join(
    REPO_ROOT, "research", "work-items",
    "foundation-validate-einval-gate-94", "evidence.json")
BINARY_PATH = os.path.join(REPO_ROOT, "artifacts", "node", "94", "hl-node")

spec = importlib.util.spec_from_file_location(
    "foundation_validate_einval_gate", TOOL_PATH)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def load_evidence():
    with open(EVIDENCE_PATH) as fh:
        return json.load(fh)


class TestValidateEinvalGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BINARY_PATH, "rb") as fh:
            cls.binary = fh.read()
        cls.sections = checker.elf_sections(cls.binary)
        cls.packet_dir = os.path.dirname(EVIDENCE_PATH)

    def run_evidence(self, ev, binary=None):
        checker.run_evidence(
            ev, self.binary if binary is None else binary,
            self.sections, self.packet_dir)

    def test_evidence_reproduces(self):
        self.run_evidence(load_evidence())

    def test_null_base_fails(self):
        edge = load_evidence()["rule"]["edges"][0]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)
        self.assertIsNone(args)

    def test_null_second_pointer_fails(self):
        edge = load_evidence()["rule"]["edges"][1]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)
        self.assertIsNone(args)

    def test_null_third_pointer_fails(self):
        edge = load_evidence()["rule"]["edges"][2]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)
        self.assertIsNone(args)

    def test_stack_argument_below_fails(self):
        edge = load_evidence()["rule"]["edges"][3]
        result, _ = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)

    def test_stack_argument_above_fails(self):
        edge = load_evidence()["rule"]["edges"][4]
        result, _ = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)

    def test_pointee_below_fails(self):
        edge = load_evidence()["rule"]["edges"][5]
        result, _ = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)

    def test_pointee_above_fails(self):
        edge = load_evidence()["rule"]["edges"][6]
        result, _ = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)

    def test_all_gates_failing_still_22(self):
        edge = load_evidence()["rule"]["edges"][7]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x16)
        self.assertIsNone(args)

    def test_pass_returns_zero_with_derived_args(self):
        edge = load_evidence()["rule"]["edges"][8]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x0)
        self.assertEqual(args, {
            "rdi": "passthrough",
            "rsi": "0x30",
            "rdx": "0x1008",
            "rcx": "0x1010",
            "r8": "0x1018",
            "r9": "0x1020",
            "stack7": "0x1028",
            "stack8": "0x1000",
        })

    def test_second_base_derives_args(self):
        edge = load_evidence()["rule"]["edges"][9]
        result, args = checker.evaluate_gate(edge)
        self.assertEqual(result, 0x0)
        self.assertEqual(args["rdx"], "0x2008")
        self.assertEqual(args["stack8"], "0x2000")

    def test_gate_is_conjunction_not_range(self):
        # Flipping any single gate condition from a passing edge fails.
        base = load_evidence()["rule"]["edges"][8]
        for mutation in (
            {"rcx_zero": True},
            {"r8_zero": True},
            {"r9_zero": True},
            {"stack_arg": "0x7"},
            {"pointee": "0x2f"},
        ):
            edge = copy.deepcopy(base)
            edge.update(mutation)
            result, args = checker.evaluate_gate(edge)
            self.assertEqual(result, 0x16, mutation)
            self.assertIsNone(args, mutation)

    def test_corrupt_body_byte_fails(self):
        ev = load_evidence()
        mutated = bytearray(self.binary)
        addr, off, _ = self.sections[".text"]
        mutated[off + (0x54E1B14 - addr)] ^= 0xFF
        with self.assertRaises(ValueError):
            self.run_evidence(ev, binary=bytes(mutated))

    def test_corrupt_padding_byte_fails(self):
        ev = load_evidence()
        mutated = bytearray(self.binary)
        addr, off, _ = self.sections[".text"]
        mutated[off + (0x54E1B7E - addr)] = 0x90
        with self.assertRaises(ValueError):
            self.run_evidence(ev, binary=bytes(mutated))

    def test_corrupt_call_target_fails(self):
        ev = load_evidence()
        mutated = bytearray(self.binary)
        addr, off, _ = self.sections[".text"]
        mutated[off + (0x54E1B65 - addr) + 1] ^= 0xFF
        with self.assertRaises(ValueError):
            self.run_evidence(ev, binary=bytes(mutated))

    def test_corrupt_gate_constant_fails(self):
        ev = load_evidence()
        mutated = bytearray(self.binary)
        addr, off, _ = self.sections[".text"]
        # The 0x30 in cmp qword [r8], 0x30 at 0x54e1b35.
        mutated[off + (0x54E1B35 - addr) + 3] = 0x31
        with self.assertRaises(ValueError):
            self.run_evidence(ev, binary=bytes(mutated))

    def test_wrong_target_digest_fails(self):
        ev = load_evidence()
        ev["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.run_evidence(ev)

    def test_wrong_edge_result_fails(self):
        ev = load_evidence()
        ev["rule"]["edges"][8]["result"] = "0x16"
        with self.assertRaises(ValueError):
            self.run_evidence(ev)

    def test_wrong_callee_args_fail(self):
        ev = load_evidence()
        ev["rule"]["edges"][8]["callee_args"]["rdx"] = "0x1009"
        with self.assertRaises(ValueError):
            self.run_evidence(ev)

    def test_failure_edge_with_args_fails(self):
        ev = load_evidence()
        ev["rule"]["edges"][0]["callee_args"] = {"rdi": "passthrough"}
        with self.assertRaises(ValueError):
            self.run_evidence(ev)

    def test_wrong_callee_extent_fails(self):
        ev = load_evidence()
        ev["call"]["target_fde_extent"] = 993
        with self.assertRaises(ValueError):
            self.run_evidence(ev)


if __name__ == "__main__":
    unittest.main()
