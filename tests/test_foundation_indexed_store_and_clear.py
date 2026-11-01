"""Unit tests for the foundation indexed-store-and-clear window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_indexed_store_and_clear -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
callee, the padding, the caller list, the FDE records, and every rule edge
including the 2-byte zeroing hole and the 32-bit index edge.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-indexed-store-and-clear-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_indexed_store_and_clear",
        os.path.join(REPO_ROOT, "tools", "foundation_indexed_store_and_clear.py"))
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


class TestIndexedStoreAndClear(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_zero_edge_preserves_hole(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][0]
        self.assertEqual(edge["obj_after"][12:16], "aabb")

    def test_index_three_strides_48(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][1]
        self.assertEqual(edge["entry"], "0x1030")

    def test_max_index_edge_64_bit_shift(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][2]
        self.assertEqual(edge["entry"], "0x1000000ff0")

    def test_zero_direct_callers_recorded(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], [])

    def test_callee_is_58_byte_fde_start(self):
        ev = good_evidence()
        self.assertEqual(ev["callee"]["bytes"], 58)
        self.assertTrue(ev["callee"]["is_fde_start"])

    def test_window_is_59_bytes_5_padding(self):
        ev = good_evidence()
        self.assertEqual(ev["function"]["bytes"], 59)
        self.assertEqual(ev["function"]["padding_bytes"], 5)

    def test_stores_are_dword_word_qword(self):
        ev = good_evidence()
        self.assertEqual(
            [(s["offset"], s["size"]) for s in ev["rule"]["stores"]],
            [("0x0", 4), ("0x4", 2), ("0x8", 8)])

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
        ev["callee"]["start_va"] = "0x54340c1"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x002a6665"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x002a6681"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_sha(self):
        ev = good_evidence()
        ev["callee"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_extent(self):
        ev = good_evidence()
        ev["callee"]["end_va_exclusive"] = "0x54340fb"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_padding(self):
        ev = good_evidence()
        ev["callee"]["padding_bytes"] = 5
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = ["0x5240c00"]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_entry(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["entry"] = "0x1040"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_zeroing(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["obj_after"] = "0" * 32
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_call_rdi(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["call_rdi"] = "0x1001"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_call_rsi(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["call_rsi"] = "0x12345679"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_return(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["ret"] = "0x2001"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_stores(self):
        ev = good_evidence()
        ev["rule"]["stores"][1]["size"] = 4
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
