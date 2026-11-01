"""Unit tests for the foundation destructor-loop window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_destructor_loop -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
call and tail targets, the PLT stub, the caller list, the FDE records,
and every rule edge.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-destructor-loop-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_destructor_loop",
        os.path.join(REPO_ROOT, "tools", "foundation_destructor_loop.py"))
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


class TestDestructorLoop(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            CHECKER.evaluate_edge(edge)

    def test_empty_range_edges_do_nothing(self):
        ev = good_evidence()
        for edge in (ev["rule"]["edges"][0], ev["rule"]["edges"][2]):
            self.assertEqual(edge["calls"], [])
            self.assertEqual(edge["writes"], [])

    def test_tail_only_edge(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][1]
        self.assertEqual(edge["calls"], [])
        self.assertEqual(edge["writes"], [])
        self.assertEqual(edge["tail"], {"ptr": "0x1000", "size": "0x40"})

    def test_zero_size_call_still_happens(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][6]
        self.assertEqual(
            edge["calls"], [{"ptr": "0x2000", "size": "0x0"}])

    def test_five_callers_recorded(self):
        ev = good_evidence()
        callers = ev["incoming"]["direct_e8_callers"]
        self.assertEqual(len(callers), 5)
        sites = [c["site"] for c in callers]
        self.assertEqual(sites, sorted(sites))

    def test_callee_is_plt_stub_not_fde(self):
        ev = good_evidence()
        call = ev["call"]
        self.assertFalse(call["target_fde_start"])
        self.assertFalse(call["target_claimed_here"])
        self.assertEqual(call["target"], "0x5660440")
        self.assertEqual(call["tail_target"], "0x5660440")
        self.assertEqual(
            call["target_bytes"], "ff25028b11006835000000e990fcffff")

    def test_stride_is_0x68(self):
        ev = good_evidence()
        self.assertEqual(ev["call"]["stride"], 104)

    def test_corrupt_body_byte(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 7
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_call_target(self):
        ev = good_evidence()
        ev["call"]["target"] = "0x5660441"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_calls(self):
        ev = good_evidence()
        ev["rule"]["edges"][3]["calls"] = []
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_writes(self):
        ev = good_evidence()
        ev["rule"]["edges"][3]["writes"] = []
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_tail(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["tail"] = None
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = (
            ev["incoming"]["direct_e8_callers"][:-1])
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_fde_offset(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"][0]["fde_section_offset"] = (
            "0x0062441d")
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x0028d725"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_stub(self):
        ev = good_evidence()
        ev["call"]["target_bytes"] = "ff25028b11006835000000e990fcfffe"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_tail_target(self):
        ev = good_evidence()
        ev["call"]["tail_target"] = "0x5660441"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_stride(self):
        ev = good_evidence()
        ev["call"]["stride"] = 103
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
