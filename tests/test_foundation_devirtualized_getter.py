"""Unit tests for the foundation devirtualized-getter window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_devirtualized_getter -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
getter, the global relocation, the virtual call encoding, the caller list,
the FDE records, and every rule edge.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-devirtualized-getter-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_devirtualized_getter",
        os.path.join(REPO_ROOT, "tools", "foundation_devirtualized_getter.py"))
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


class TestDevirtualizedGetter(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_empty_edge_stores_zero_without_call(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][0]
        self.assertEqual(edge["out"], "0x0")
        self.assertFalse(edge["called"])
        self.assertEqual(edge["ret"], 1)

    def test_match_edge_stores_field8_without_call(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][1]
        self.assertEqual(edge["out"], "0xabcd")
        self.assertFalse(edge["called"])

    def test_mismatch_edge_calls_and_stores_result(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][2]
        self.assertTrue(edge["called"])
        self.assertEqual(edge["out"], "0x777")

    def test_zero_callers_recorded(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], [])

    def test_getter_is_9_byte_fde_start(self):
        ev = good_evidence()
        gt = ev["getter"]
        self.assertEqual(gt["bytes"], 9)
        self.assertEqual(gt["start_va"], "0x4fa7e80")
        self.assertEqual(gt["end_va_exclusive"], "0x4fa7e89")

    def test_global_reloc_resolves_to_getter(self):
        ev = good_evidence()
        glob = ev["global"]
        self.assertEqual(glob["slot_va"], "0x5778020")
        self.assertEqual(glob["reloc_addend"], "0x4fa7e80")
        self.assertEqual(glob["reloc_type"], "R_X86_64_RELATIVE")

    def test_sentinel_and_field_offsets(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["elem_offset"], "0x1200")
        self.assertEqual(ev["rule"]["sentinel_delta"], "0x11e0")
        self.assertEqual(ev["rule"]["field_offset"], "0x8")
        self.assertEqual(ev["rule"]["return_value"], 1)

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

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x0029a5d5"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x0029a5ed"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_getter_sha(self):
        ev = good_evidence()
        ev["getter"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_getter_fde_offset(self):
        ev = good_evidence()
        ev["getter"]["fde_section_offset"] = "0x0028b659"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_getter_extent(self):
        ev = good_evidence()
        ev["getter"]["end_va_exclusive"] = "0x4fa7e8a"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_global_reloc_addend(self):
        ev = good_evidence()
        ev["global"]["reloc_addend"] = "0x4fa7e81"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = [{"site": "0x514b000"}]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_out(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["out"] = "0xabce"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_called(self):
        ev = good_evidence()
        ev["rule"]["edges"][2]["called"] = False
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_call_args(self):
        ev = good_evidence()
        ev["rule"]["edges"][7]["call_args"] = [
            "0x4000", "out", "0x3001", "entry-rcx"]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_sentinel_delta(self):
        ev = good_evidence()
        ev["rule"]["sentinel_delta"] = "0x11e1"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_field_offset(self):
        ev = good_evidence()
        ev["rule"]["field_offset"] = "0x9"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_return_value(self):
        ev = good_evidence()
        ev["rule"]["return_value"] = 0
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
