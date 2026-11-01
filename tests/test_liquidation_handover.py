"""Tests for tools/liquidation_handover.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("liquidation_handover", ROOT / "tools" / "liquidation_handover.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-liquidation-handover-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {case["label"]: case for case in tool.all_cases()}
HARNESS = tool.Harness(IMAGE)


def broken(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


def result(label, **change):
    return tool.Spec({**CASES[label], **change}).run()


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
            IMAGE.exact_fde(tool.PLAN + 1)

    def test_section_without_file_bytes_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])


class Static(unittest.TestCase):
    def test_plan_has_three_callers_through_one_slot(self):
        calls = EVIDENCE["plan_callers"]
        self.assertEqual(calls["slots"], ["0x5774ac8"])
        self.assertEqual([row["function"] for row in calls["callers"]], ["0x2725150", "0x4d2b3c0", "0x4d2cd20"])

    def test_constant_with_other_bytes_is_refused(self):
        sites = tool.CONSTANT_SITES
        tool.CONSTANT_SITES = (("wrong", tool.PLAN, b"\x00\x00", 1),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.CONSTANT_SITES = sites

    def test_status_texts(self):
        rows = {row[0]: row[4] for row in tool.status_rows(IMAGE)}
        self.assertEqual(rows["0x20"], "Position is not liquidatable: ")
        self.assertEqual(rows["0x21"], "Liquidator must use cross margin for asset ")
        self.assertEqual(rows["0x22"], "Liquidator does not have enough margin available.")

    def test_status_past_the_table_is_refused(self):
        with self.assertRaises((tool.EvidenceError, IndexError, UnicodeDecodeError, struct_error())):
            tool.status_text(IMAGE, 0x4000000)


def struct_error():
    return __import__("struct").error


class Behaviour(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(EVIDENCE["cases"]["total"], len(CASES))

    def test_each_refusal_is_covered(self):
        self.assertTrue({"status 0x20", "status 0x21", "status 0x22", "status 0x186"} <= set(EVIDENCE["cases"]["outcomes"]))

    def test_flag_0_ignores_the_id_word_of_a_list_row(self):
        self.assertEqual(result("cross, listed row", list=[(0, 99)])["status"], tool.OK)
        self.assertEqual(result("isolated, listed", list=[(1, 99)])["status"], tool.NOT_ELIGIBLE)

    def test_cross_zeroes_the_balance_and_isolated_keeps_it(self):
        self.assertEqual(result("cross, listed row")["users"][tool.USER][0], 0)
        self.assertEqual(result("isolated, listed")["users"][tool.USER][0], 77)

    def test_cross_keeps_the_rows_with_zero_size(self):
        held = dict(result("cross, listed row")["users"][tool.USER][4])
        self.assertEqual(held[1][tool.SIZE], 0)
        self.assertEqual(held[1][tool.LEVERAGE], 5)

    def test_isolated_receiver_is_refused_with_the_id(self):
        out = result("receiver holds isolated size")
        self.assertEqual((out["status"], out["words"]), (tool.ISOLATED_RECEIVER, (2,)))

    def test_empty_isolated_row_is_rewritten(self):
        held = dict(result("receiver empty isolated row becomes cross 20x")["users"][tool.BACK][4])
        self.assertEqual(held[2][:2], (0, 20))
        self.assertEqual(held[2][tool.WORD38], 50)

    def test_receiver_gate_boundary(self):
        self.assertEqual(result("receiver margin passes at equality")["status"], tool.OK)
        self.assertEqual(result("receiver margin fails by one")["status"], tool.RECEIVER_SHORT)

    def test_refusal_keeps_the_user_account_but_not_the_receiver_rows(self):
        out = result("receiver margin fails by one")
        before = CASES["receiver margin fails by one"]["users"]
        self.assertEqual(out["users"][tool.USER][0], before[tool.USER]["balance"])
        self.assertEqual(len(out["users"][tool.BACK][4]), 4)
        self.assertEqual(len(before[tool.BACK]["positions"]), 0)

    def test_remainder_goes_to_the_first_row_or_the_default(self):
        self.assertEqual(result("cross remainder goes to the first row")["users"][tool.BACK][0], (1 << 40) - 1000 + 7 + 3000)
        out = result("cross no rows, remainder to default")
        self.assertEqual(out["users"][tool.BACK][0], (1 << 40) + 33)
        self.assertEqual(out["words"][0][2], 33)

    def test_only_a_negative_value_moves_the_dex_word(self):
        self.assertEqual(result("value -501 over word 500")["word"], 0)
        self.assertEqual(result("value -1 over word 500")["word"], 499)
        self.assertEqual(result("value 1 over word 500")["word"], 500)

    def test_row_ids_follow_first_use_in_id_order(self):
        rows = result("low address sorts first")["words"]
        self.assertEqual([row[4] for row in rows], [tool.LOW, tool.BACK])
        self.assertEqual([row[0] for row in rows], [101, 100])


class Controls(unittest.TestCase):
    def test_status_0x20_byte(self):
        self.assertTrue(tool.compare_run(broken(0x3700910, 1), CASES["cross, list empty"]))

    def test_status_0x21_byte(self):
        self.assertTrue(tool.compare_run(broken(0x37002A2, 1), CASES["receiver holds isolated size"]))

    def test_status_0x22_byte(self):
        self.assertTrue(tool.compare_run(broken(0x3701FD4, 1), CASES["receiver margin fails by one"]))

    def test_reset_word(self):
        self.assertTrue(tool.compare_run(broken(0x3700325, 1), CASES["receiver empty isolated row becomes cross 20x"]))

    def test_receiver_gate_branch(self):
        self.assertTrue(tool.compare_run(broken(0x370193E, 1), CASES["receiver margin fails by one"]))

    def test_loss_word_offset(self):
        self.assertTrue(tool.compare_run(broken(0x3703892, 8), CASES["value -1 over word 500"]))

    def test_unpatched_harness_after_controls(self):
        self.assertIsNone(tool.compare_run(tool.Harness(IMAGE), CASES["cross, listed row"]))


class Packet(unittest.TestCase):
    def test_regeneration_matches_the_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(tool.main(["--out", folder]), 0)
            names = sorted(path.name for path in pathlib.Path(folder).iterdir())
            self.assertEqual(names, ["evidence.json", "mutations.tsv", "path-map.tsv", "reference-diffs.tsv", "samples.tsv", "status-texts.tsv"])
            for name in names:
                self.assertEqual((pathlib.Path(folder) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)

    def test_every_survivor_has_a_reason(self):
        rows = [line.split("\t") for line in (PACKET / "mutations.tsv").read_text().splitlines()[1:]]
        self.assertFalse([row for row in rows if row[3] != "killed" and not row[5]])

    def test_evidence_binds_the_target(self):
        doc = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(doc["target_sha256"], tool.SHA256)


if __name__ == "__main__":
    unittest.main()
