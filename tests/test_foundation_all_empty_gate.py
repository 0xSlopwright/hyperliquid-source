"""Unit tests for the foundation all-empty-gate window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_all_empty_gate -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
call target, the callee stub, the caller list, the FDE records, and every
rule edge.
"""

import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-all-empty-gate-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_all_empty_gate",
        os.path.join(REPO_ROOT, "tools", "foundation_all_empty_gate.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def run_checker_on(evidence_dict):
    """Run the checker against a mutated evidence copy; return exit code."""
    tmp = tempfile.mkdtemp()
    try:
        packet_dir = os.path.join(tmp, "packet")
        shutil.copytree(os.path.dirname(EVIDENCE), packet_dir)
        path = os.path.join(packet_dir, "evidence.json")
        with open(path, "w") as fh:
            json.dump(evidence_dict, fh)
        return CHECKER.main(["prog", "--check", path])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def good_evidence():
    with open(EVIDENCE) as fh:
        return json.load(fh)


class TestAllEmptyGate(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            CHECKER.evaluate_edge(edge)

    def test_early_return_edges_call_nothing(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"][:5]:
            self.assertEqual(edge["calls"], 0)
            self.assertEqual(edge["counter_out"], edge["counter_in"])

    def test_all_equal_edges_call_once(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"][5:]:
            self.assertEqual(edge["calls"], 1)

    def test_counter_wrap_is_32_bit(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][6]
        self.assertEqual(edge["counter_in"], "0x0")
        self.assertEqual(edge["counter_out"], "0xffffffff")

    def test_no_callers_recorded(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], [])

    def test_callee_is_five_byte_noop(self):
        ev = good_evidence()
        call = ev["call"]
        self.assertTrue(call["target_fde_start"])
        self.assertEqual(call["target_fde_bytes"], 5)
        self.assertEqual(call["target_bytes"], "f30f1efac3")

    def test_corrupt_body_byte(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 2
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_call_target(self):
        ev = good_evidence()
        ev["call"]["target"] = "0x5334d61"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_result(self):
        ev = good_evidence()
        ev["rule"]["edges"][5]["counter_out"] = "0x3"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_calls(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["calls"] = 1
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = ["0x5000000"]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x002957c9"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_stub(self):
        ev = good_evidence()
        ev["call"]["target_bytes"] = "f30f1efac4"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_callee_fde_extent(self):
        ev = good_evidence()
        ev["call"]["target_fde_bytes"] = 6
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_counter_offset(self):
        ev = good_evidence()
        ev["call"]["counter_offset"] = "0x149d"
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
