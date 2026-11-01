"""Tests for tools/adl_user_scan.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adl_user_scan", ROOT / "tools" / "adl_user_scan.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-adl-user-scan-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {case["label"]: case for case in tool.all_cases()}
ONE, TWO = tool.ONE, tool.TWO


def broken(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


class Identity(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_changed_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the target")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_inside_a_function_is_not_an_fde_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.SCAN + 1)

    def test_section_without_file_bytes_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])


class Static(unittest.TestCase):
    def test_callers(self):
        rows = EVIDENCE["callers"]
        self.assertEqual([row["function"] for row in rows if row["target"] == "0x33c58e0"], ["0x36f7c40"])
        self.assertEqual(len([row for row in rows if row["target"] == "0x3707910"]), 16)
        self.assertEqual({row["kind"] for row in rows if row["target"] == "0x3707910"}, {"slot 0x5774990"})

    def test_no_site_sets_the_byte_argument(self):
        rows = tool.site_rows(IMAGE, tool.callers(IMAGE))
        self.assertEqual({row[4] for row in rows}, {0})
        self.assertEqual([row[2] for row in rows if row[1] == "0x27078a0"], [0, 2, 0, 2, 3])
        self.assertEqual([row[3] for row in rows if row[1] == "0x27078a0"], ["none", "none", "none", "stack set", "stack set"])

    def test_a_site_with_other_bytes_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.site_rows(IMAGE, [("0x3707910", "0x3707924", "0x3707910", "slot")])

    def test_constant_with_other_bytes_is_refused(self):
        sites = tool.CONSTANT_SITES
        tool.CONSTANT_SITES = (("wrong", tool.SCAN, b"\x00\x00", 1),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.CONSTANT_SITES = sites

    def test_field_texts(self):
        self.assertEqual([row["text"] for row in EVIDENCE["field_texts"]], ["user_to_state", "users_with_positions", "check_all_users_for_liquidatables"])

    def test_field_text_with_other_bytes_is_refused(self):
        sites = tool.FIELD_SITES
        tool.FIELD_SITES = ((0x3B13FC, b"not_this_name"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.field_rows(IMAGE)
        finally:
            tool.FIELD_SITES = sites

    def test_stubs_are_not_claimed(self):
        claimed = {row["start"] for row in EVIDENCE["functions"]}
        for address in ("0x37d7360", "0x36f5d40", "0x399c7a0", "0x33f3fc0"):
            self.assertNotIn(address, claimed)
            self.assertNotIn(int(address, 16), tool.REAL_FUNCTIONS)


class Order(unittest.TestCase):
    def test_score_word_is_total_order(self):
        order = [tool.NEG_NAN, tool.NEG_INF, tool.MINUS, tool.NEG_ZERO, 0, tool.TINY, tool.HALF, tool.PLUS, tool.INF, tool.NAN]
        words = [tool.rank_word(bits) for bits in order]
        self.assertEqual(words, sorted(words))
        self.assertEqual(len(set(words)), len(words))

    def test_word_1_counts_only_with_two_tags(self):
        self.assertEqual(tool.sort_order((0, 1, 5, ONE), (0, 9, 5, ONE)), 0)
        self.assertEqual(tool.sort_order((1, 1, 5, ONE), (1, 9, 5, ONE)), -1)
        self.assertEqual(tool.search_key((0, 1, 5, ONE)), tool.search_key((0, 9, 5, ONE)))

    def test_address_comes_before_tag(self):
        self.assertEqual(tool.sort_order((1, 1, 5, ONE), (0, 1, 5, TWO)), -1)

    def test_word_2_is_signed(self):
        self.assertEqual(tool.sort_order((0, 0, tool.word_of(-1), ONE), (0, 0, 1, ONE)), -1)


class Real(unittest.TestCase):
    def setUp(self):
        self.harness = tool.Harness(IMAGE)

    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(sum(EVIDENCE["cases"].values()), len(CASES))

    def test_a_given_empty_set_beats_the_whole_table(self):
        got = self.harness.run_case(CASES["empty given beats every"])
        self.assertEqual(got["rows"], ())
        self.assertEqual(self.harness.events, [])

    def test_whole_table_calls_in_bucket_order(self):
        case = CASES["users 22 every"]
        self.harness.run_case(case)
        where, _ = tool.placements(case)
        order = [where[event[1]] for event in self.harness.events]
        self.assertEqual(order, sorted(order))

    def test_touched_arm_skips_a_user_outside_the_set(self):
        got = self.harness.run_case(CASES["rank touched only part"])
        self.assertEqual({row[1] for row in got["final"][5, 1]}, {tool.THREE})
        self.assertEqual({event[3] for event in self.harness.events}, {tool.THREE, ONE})

    def test_key_with_no_candidate_stays_with_root_0(self):
        got = self.harness.run_case(CASES["rank key with no set flag"])
        self.assertEqual(got["final"][5, 1], ())
        self.assertEqual(len(got["final"][6, 1]), 1)

    def test_highest_key_is_highest_score_then_address(self):
        got = self.harness.run_case(CASES["rank tie by address touched"])["final"][5, 1]
        self.assertEqual(got[-1][1], max(tool.HIGH, tool.THREE, ONE, TWO, tool.LOW))

    def test_side_2_is_the_end_of_the_key_fold(self):
        case = tool.rank_case("side 2", [ONE], [(7, 1), (7, 2), (7, 0)], {})
        with self.assertRaises(tool.Panicked) as caught:
            self.harness.run_case(case)
        self.assertEqual(str(caught.exception), "format")

    def test_wrong_score_is_seen(self):
        case = dict(CASES["rank order by score flag"])
        harness_run = self.harness.run_case(case)
        changed = dict(case, scores={key: tool.PLUS for key in case["scores"]})
        self.assertNotEqual(tool.Spec(changed).run(), harness_run)

    def test_leak_is_seen(self):
        original = self.harness.on_free
        self.harness.machine.slots[0x7100000 + 16] = lambda machine: None
        failed = tool.compare_run(self.harness, CASES["cross and isolated given"])
        self.harness.machine.slots[0x7100000 + 16] = original
        self.assertIn("blocks left", failed or "")


class Controls(unittest.TestCase):
    """One flipped byte in the target must change a result; each pair is (byte address, xor, case)."""

    def check(self, va, xor, label):
        self.assertIsNone(tool.compare_run(tool.Harness(IMAGE), CASES[label]))
        self.assertIsNotNone(tool.compare_run(broken(va, xor), CASES[label]))

    def test_given_set_gate(self):
        self.check(0x370793B, 1, "given beats every")

    def test_byte_argument_gate(self):
        self.check(0x37079D0, 1, "every beats touched")

    def test_flag_gate_in_the_scan(self):
        self.check(0x37079DE, 1, "flag beats touched")

    def test_flag_gate_in_the_candidate_arm(self):
        self.check(0x3761351, 1, "rank flag beats touched")

    def test_flag_offset_in_the_candidate_arm(self):
        self.check(0x376134B, 8, "rank touched only part")

    def test_score_order_sign_map(self):
        self.check(0x33A365C, 1, "rank negative below zero touched")

    def test_score_tie_goes_to_the_address_set_arm(self):
        self.check(0x33A36C4, 1, "rank tie by address touched")

    def test_row_key_word_1(self):
        self.check(0x3383C55, 1, "isolated sort by asset flag")

    def test_bucket_stride(self):
        self.check(0x3766C2B, 1, "rank order by score touched")

    def test_score_status_word(self):
        self.check(0x3767520, 1, "rank no score flag")


class Packet(unittest.TestCase):
    def test_manifest(self):
        rows = (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        names = sorted(path.name for path in PACKET.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual([row.split("  ")[1] for row in rows], names)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    def test_stored_evidence(self):
        stored = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
        for key in ("target_sha256", "functions", "callers", "constants", "field_texts", "cases", "mismatches", "instructions_stepped"):
            self.assertEqual(stored[key], EVIDENCE[key], key)

    def test_each_row_that_is_not_killed_has_a_reason(self):
        rows = [line.split("\t") for line in (PACKET / "mutations.tsv").read_text(encoding="utf-8").splitlines()[1:]]
        self.assertTrue(rows)
        self.assertEqual([row for row in rows if row[3] != "killed" and not row[5]], [])

    def test_path_map_rows(self):
        self.assertEqual(len(tool.path_rows()), 13)


if __name__ == "__main__":
    unittest.main()
