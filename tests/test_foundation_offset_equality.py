"""Target-grounded controls for the static foundation packet (no node execution)."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_offset_equality as rule

PACKET_DIR = Path(__file__).resolve().parents[1] / (
    "research/work-items/foundation-offset-equality-94")
EVIDENCE = PACKET_DIR / "evidence.json"
TARGET = Path(__file__).resolve().parents[1] / "artifacts/node/94/hl-node"


class OffsetEqualityEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.is_file() or TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest("Requires materialized node #94 Git LFS input")
        cls.evidence = json.loads(EVIDENCE.read_text())
        cls.binary = TARGET.read_bytes()
        cls.sections = rule.elf_sections(cls.binary)
        cls.packet_dir = str(PACKET_DIR)

    def run_evidence(self, evidence):
        return rule.run_evidence(
            evidence, self.binary, self.sections, self.packet_dir)

    def test_full_evidence_reproduces(self):
        self.assertEqual(self.run_evidence(self.evidence), [])

    def test_run_all_entry_point(self):
        self.assertEqual(rule.run_all(str(EVIDENCE)), [])

    # Rule edges: fast paths, equality, wraparound.
    def test_rejection_fast_path_ignores_callee(self):
        self.assertEqual(rule.evaluate_rule(0x1000, 3, 0x2000, 5, 0), 0)
        self.assertEqual(rule.evaluate_rule(0x1000, 3, 0x2000, 5, 99), 0)

    def test_zero_second_fast_path_ignores_callee(self):
        self.assertEqual(rule.evaluate_rule(0x1000, 5, 0x2000, 0, 12345), 1)
        self.assertEqual(rule.evaluate_rule(0x1000, 0, 0x2000, 0, 7), 1)

    def test_equal_and_ordered_seconds(self):
        self.assertEqual(rule.evaluate_rule(0x1000, 5, 0x2000, 5, 0), 1)
        self.assertEqual(rule.evaluate_rule(0x1000, 5, 0x2000, 5, 7), 0)
        self.assertEqual(rule.evaluate_rule(0x1000, 10, 0x2000, 3, 0), 1)
        self.assertEqual(rule.evaluate_rule(0x1000, 10, 0x2000, 3, 1), 0)

    def test_wraparound_offset(self):
        # offset = (2**64 - 3 + 7) mod 2**64 == 4; only the callee
        # result decides, so callee 0 passes.
        self.assertEqual(
            rule.evaluate_rule(0xFFFFFFFFFFFFFFFD, 10, 0x2000, 3, 0), 1)

    def test_top_of_range(self):
        top = (1 << 64) - 1
        self.assertEqual(rule.evaluate_rule(top, top, 0x2000, top, 0), 1)
        self.assertEqual(rule.evaluate_rule(top, top, 0x2000, top, 1), 0)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.evidence["rule"]["edges"]:
            got = rule.evaluate_rule(
                int(edge["a_first"], 16), int(edge["a_second"], 16),
                int(edge["b_first"], 16), int(edge["b_second"], 16),
                edge["callee_result"])
            self.assertEqual(got, edge["result"], edge)

    # Corruption controls: each tampered input must fail, not pass.
    def test_corrupt_window_sha_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["sha256"] = "0" * 64
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_padding_count_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["padding_bytes"] = 4
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_fde_offset_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["fde_section_offset"] = "0x2bae5d"
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_callee_target_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["call"]["target"] = "0x5660151"
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_caller_list_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["incoming"]["direct_e8_callers"] = ev["incoming"]["direct_e8_callers"][1:]
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_edge_result_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["rule"]["edges"][0]["result"] = 1 - ev["rule"]["edges"][0]["result"]
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_target_digest_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["target_sha256"] = "0" * 64
        self.assertTrue(self.run_evidence(ev))

    # Retained disassembly lines.
    def test_retained_disassembly_lines(self):
        window = (PACKET_DIR / "window.objdump.txt").read_text()
        self.assertIn("5430d9a:", window)
        self.assertIn("5430dab:", window)
        caller = (PACKET_DIR / "caller.objdump.txt").read_text()
        self.assertIn("522d665:", caller)
        self.assertIn("5430d60", caller)
        frames = (PACKET_DIR / "frames.txt").read_text()
        self.assertIn("pc=0000000005430d60..0000000005430dab", frames)
        self.assertIn("pc=000000000522d4b0..000000000522d933", frames)


if __name__ == "__main__":
    unittest.main()
