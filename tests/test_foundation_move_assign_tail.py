"""Unit tests for the foundation move-assign-tail window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_move_assign_tail -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
call target, the caller list, the FDE records, and every rule edge.
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
    REPO_ROOT, "research", "work-items", "foundation-move-assign-tail-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_move_assign_tail",
        os.path.join(REPO_ROOT, "tools", "foundation_move_assign_tail.py"))
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


class TestMoveAssignTail(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            CHECKER.evaluate_edge(edge)

    def test_self_assign_edge_is_identity(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][0]
        self.assertTrue(edge["self_assign"])
        self.assertEqual(edge["calls"], 0)
        self.assertEqual(edge["dest_bytes_out"], edge["dest_bytes_in"])
        self.assertEqual(edge["src_bytes_out"], edge["src_bytes_in"])

    def test_free_happens_iff_old_dest_tail_nonzero(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            if edge["self_assign"]:
                self.assertEqual(edge["calls"], 0)
            elif edge["dest_tail_in"] == "0x0":
                self.assertEqual(edge["calls"], 0)
                self.assertIsNone(edge["call_arg"])
            else:
                self.assertEqual(edge["calls"], 1)
                self.assertEqual(edge["call_arg"], edge["dest_tail_in"])

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
        ev["call"]["target"] = "0x5660490"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_result(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["dest_tail_out"] = "0x9999"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_calls(self):
        ev = good_evidence()
        ev["rule"]["edges"][2]["calls"] = 1
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = ev["incoming"]["direct_e8_callers"][:-1]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x002a5515"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_plt_stub(self):
        ev = good_evidence()
        ev["call"]["target_plt_stub"] = "00" * 16
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_gap_preservation(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["dest_gap_out"] = [0, 0]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_callee_not_fde_start(self):
        ev = good_evidence()
        self.assertIs(ev["call"]["target_fde_start"], False)
        self.assertIs(ev["call"]["target_claimed_here"], False)

    def test_seventeen_callers_recorded(self):
        ev = good_evidence()
        self.assertEqual(len(ev["incoming"]["direct_e8_callers"]), 17)


if __name__ == "__main__":
    unittest.main()
