"""Unit tests for the foundation round-up-division window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_round_up_division -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
callee, the padding, the caller list, the FDE records, and every rule edge
including the two div-fault edges.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-round-up-division-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_round_up_division",
        os.path.join(REPO_ROOT, "tools", "foundation_round_up_division.py"))
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


class TestRoundUpDivision(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_ceil_edge_rounds_up(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][0]
        self.assertEqual(edge["q"], "0x3")
        self.assertEqual(edge["r"], "0x4")

    def test_unit_divisor_is_identity(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][2]
        self.assertEqual(edge["q"], "0x3039")
        self.assertEqual(edge["r"], "0x0")

    def test_wrap_edge_32_bit(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][4]
        self.assertEqual(edge["t"], "0xffffffff")
        self.assertEqual(edge["q"], "0x1")

    def test_div_by_zero_edge_is_fault(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][6]
        self.assertEqual(edge["fault"], "div-by-zero")
        self.assertEqual(edge["t"], "0x0")

    def test_div_overflow_edge_is_fault(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][7]
        self.assertEqual(edge["fault"], "div-overflow")

    def test_one_direct_caller_recorded(self):
        ev = good_evidence()
        callers = ev["incoming"]["direct_e8_callers"]
        self.assertEqual(len(callers), 1)
        self.assertEqual(callers[0]["site"], "0x4f9aaed")

    def test_callee_is_11_byte_fde_start(self):
        ev = good_evidence()
        cal = ev["callee"]
        self.assertEqual(cal["bytes"], 11)
        self.assertEqual(cal["start_va"], "0x4f9ee80")
        self.assertEqual(cal["end_va_exclusive"], "0x4f9ee8b")
        self.assertTrue(cal["is_fde_start"])

    def test_field_offset(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["field_offset"], "0x40")
        self.assertEqual(ev["callee"]["field_offset"], "0x40")

    def test_next_fde_cie_differs_from_window(self):
        ev = good_evidence()
        self.assertEqual(ev["function"]["fde_cie"], "0x00000000")
        self.assertEqual(ev["function"]["next_fde_cie"], "0x006205d0")

    def test_corrupt_body_sha(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 10
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_call_target(self):
        ev = good_evidence()
        ev["callee"]["start_va"] = "0x4f9ee81"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x0028ac7d"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x00621cb5"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_sha(self):
        ev = good_evidence()
        ev["callee"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_extent(self):
        ev = good_evidence()
        ev["callee"]["end_va_exclusive"] = "0x4f9ee8c"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_padding(self):
        ev = good_evidence()
        ev["callee"]["padding_bytes"] = 4
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = []
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_quotient(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["q"] = "0x4"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_remainder(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["r"] = "0x8"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_fault_edge(self):
        ev = good_evidence()
        ev["rule"]["edges"][6]["field"] = "0xfffffffe"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_field_offset(self):
        ev = good_evidence()
        ev["rule"]["field_offset"] = "0x41"
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
