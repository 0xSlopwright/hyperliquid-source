"""Target-grounded controls for the static foundation packet (no node execution)."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import foundation_two_mode_limit as rule

PACKET_DIR = Path(__file__).resolve().parents[1] / (
    "research/work-items/foundation-two-mode-limit-94")
EVIDENCE = PACKET_DIR / "evidence.json"
TARGET = Path(__file__).resolve().parents[1] / "artifacts/node/94/hl-node"


class TwoModeLimitEvidenceTests(unittest.TestCase):
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

    # Rule edges: mode gate, static count/limit, dynamic sum/limit.
    def test_static_nonpositive_count_returns_zero(self):
        # (field38, count, base, offset, input, callee_result)
        self.assertEqual(rule.evaluate_rule(0, 0, 5, 5, 0, 0), 0)
        self.assertEqual(rule.evaluate_rule(0, -5, 5, 5, 0, 0), 0)

    def test_negative_field_takes_static_path(self):
        top = (1 << 64) - 1
        # field38 == -1 (signed): static, limit 10, count 10 -> 0.
        self.assertEqual(rule.evaluate_rule(top, 10, 5, 5, 0, 0), 0)
        # field38 == -1: static, limit 10, count 5 -> 1.
        self.assertEqual(rule.evaluate_rule(top, 5, 5, 5, 0, 0), 1)

    def test_static_limit_strict(self):
        self.assertEqual(rule.evaluate_rule(0, 5, 5, 5, 0, 0), 1)
        self.assertEqual(rule.evaluate_rule(0, 10, 5, 5, 0, 0), 0)
        self.assertEqual(rule.evaluate_rule(0, 1, 0, 0, 0, 0), 0)

    def test_static_limit_wraparound(self):
        # limit = (2**64 - 1 + 2) mod 2**64 == 1; max i32 count not below it.
        self.assertEqual(
            rule.evaluate_rule(0, 2147483647, (1 << 64) - 1, 2, 0, 0), 0)

    def test_dynamic_boundary(self):
        self.assertEqual(rule.evaluate_rule(100, 0, 0, 0, 50, 50), 1)
        self.assertEqual(rule.evaluate_rule(100, 0, 0, 0, 50, 49), 0)
        self.assertEqual(rule.evaluate_rule(100, 0, 0, 0, 50, 0), 0)

    def test_dynamic_wraparound_and_max(self):
        top = (1 << 64) - 1
        # (2**64 - 1 + 1) mod 2**64 == 0, below field38 == 1.
        self.assertEqual(rule.evaluate_rule(1, 0, 0, 0, top, 1), 0)
        # max values at the boundary.
        self.assertEqual(rule.evaluate_rule(0x7FFFFFFFFFFFFFFF, 0, 0, 0, top, 0), 1)

    def test_evidence_edges_agree_with_rule(self):
        for edge in self.evidence["rule"]["edges"]:
            got = rule.evaluate_rule(
                int(edge["field38"], 16), edge["count_i32"],
                int(edge["base"], 16), int(edge["offset"], 16),
                int(edge["input"], 16), edge["callee_result"])
            self.assertEqual(got, edge["result"], edge)

    # Corruption controls: each tampered input must fail, not pass.
    def test_corrupt_window_sha_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["sha256"] = "0" * 64
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_padding_count_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["padding_bytes"] = 10
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_fde_offset_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["function"]["fde_section_offset"] = "0x29c42d"
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_callee_target_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["call"]["target"] = "0x5172b01"
        self.assertTrue(self.run_evidence(ev))

    def test_corrupt_caller_list_fails(self):
        ev = copy.deepcopy(self.evidence)
        ev["incoming"]["direct_e8_callers"] = []
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
        self.assertIn("5172c4b:", window)
        self.assertIn("5172c65:", window)
        caller = (PACKET_DIR / "caller.objdump.txt").read_text()
        self.assertIn("5173a41:", caller)
        self.assertIn("5172c10", caller)
        frames = (PACKET_DIR / "frames.txt").read_text()
        self.assertIn("pc=0000000005172c10..0000000005172c65", frames)
        self.assertIn("pc=00000000051739d0..0000000005173a5e", frames)
        self.assertIn("pc=0000000005172b00..0000000005172c01", frames)


if __name__ == "__main__":
    unittest.main()
