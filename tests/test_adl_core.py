"""Tests for tools/adl_core.py: real bytes against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("adl_core", ROOT / "tools" / "adl_core.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKET = ROOT / "research" / "work-items" / "RE-007-adl-core-94"
IMAGE = tool.load_image()
EVIDENCE, _ = tool.analyse(IMAGE, full=False)
CASES = {case["label"]: case for case in tool.all_cases()}


def broken(va, xor):
    harness = tool.Harness(IMAGE)
    harness.machine.patches = {va: IMAGE.blob[IMAGE.offset(va)] ^ xor}
    return harness


def result(label, **change):
    spec = tool.Spec({**CASES[label], **change})
    return spec, spec.run()


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
            IMAGE.exact_fde(tool.ADL + 1)

    def test_section_without_file_bytes_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"])


class Static(unittest.TestCase):
    def test_core_has_three_callers_through_one_slot(self):
        calls = EVIDENCE["core_callers"]
        self.assertEqual(calls["slots"], ["0x5774998"])
        self.assertEqual([row["function"] for row in calls["callers"]], ["0x27078a0", "0x4cf37f0", "0x4cf94a0"])

    def test_constant_with_other_bytes_is_refused(self):
        sites = tool.CONSTANT_SITES
        tool.CONSTANT_SITES = (("wrong", tool.ADL, b"\x00\x00", 1),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.constants(IMAGE)
        finally:
            tool.CONSTANT_SITES = sites

    def test_text_names(self):
        rows = {row[2]: row[3] for row in tool.text_rows(IMAGE)}
        self.assertIn("self.adl_shortfall_remaining", rows["trigger"])
        self.assertIn("asset_and_side_to_adl_requirements", rows["trigger"])
        self.assertIn("[margin_available: %]", rows["balance"])
        self.assertIn("immediate adl", rows["immediate"])

    def test_text_site_with_other_bytes_is_refused(self):
        sites = tool.TEXT_SITES
        tool.TEXT_SITES = ((tool.ADL, "none"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(IMAGE)
        finally:
            tool.TEXT_SITES = sites


class Behaviour(unittest.TestCase):
    def test_all_cases_match(self):
        self.assertEqual(EVIDENCE["mismatches"], 0, EVIDENCE["first_mismatch"])
        self.assertEqual(EVIDENCE["cases"]["total"], len(CASES))

    def test_trigger_is_at_or_above_the_word(self):
        self.assertTrue(any(event[0] == "flatten" for event in result("at the word")[0].events))
        self.assertFalse(any(event[0] == "flatten" for event in result("under the word")[0].events))

    def test_immediate_row_adds_nothing_to_the_total(self):
        spec, _ = result("exempt user is immediate")
        self.assertIn(("text", "trigger", 0, 9000), spec.events)

    def test_mode_2_builds_no_text(self):
        self.assertFalse([event for event in result("flag market row in mode 2")[0].events if event[0] == "text" and event[1] == "immediate"])

    def test_pair_order_follows_the_side(self):
        _, long_row = result("candidate bigger")
        _, short_row = result("short target")
        self.assertEqual(long_row["final"][(1, 0)][0][2], tool.MAKER)
        self.assertEqual(short_row["final"][(1, 1)][0][2], tool.TARGET)

    def test_positive_value_goes_to_the_credit(self):
        spec, out = result("sweep moves value to fees")
        self.assertIn(("credit", 40, 0x7777), spec.events)
        self.assertEqual(out["users"][tool.TARGET][0], 50 - 40)

    def test_settlement_off_keeps_the_fill_id_and_drops_the_rows(self):
        _, out = result("settle off rows are dropped")
        self.assertEqual(out["counter"], 101)
        self.assertEqual(out["final"], {})

    def test_margin_goes_out_and_back_around_the_first_fill(self):
        spec, _ = result("isolated moves value + margin")
        names = [event[0] for event in spec.events]
        first = names.index("fill")
        self.assertEqual(names[first - 2:first], ["entry", "touch"])
        self.assertEqual(names[first + 1:first + 3], ["entry", "touch"])

    def test_a_same_side_candidate_grows_the_running_size(self):
        with self.assertRaises(tool.Panicked):
            result("same side overflows the running size", ranks=({(1, 0): [(7, tool.MAKER)]},))


class Controls(unittest.TestCase):
    def test_trigger_branch(self):
        self.assertTrue(tool.compare_run(broken(0x36F86E5, 1), CASES["at the word"]))

    def test_list_end_word(self):
        self.assertTrue(tool.compare_run(broken(0x36F97FF, 1), CASES["row word 2 ends the list"]))

    def test_settlement_byte(self):
        self.assertTrue(tool.compare_run(broken(0x36FA3CA, 2), CASES["sweep moves value to fees"]))

    def test_fill_status_byte(self):
        self.assertTrue(tool.compare_run(broken(0x36FB185, 1), CASES["candidate bigger"]))

    def test_mode_byte(self):
        self.assertTrue(tool.compare_run(broken(0x36F838D, 1), CASES["flag market row in mode 2"]))

    def test_unpatched_harness_after_controls(self):
        self.assertIsNone(tool.compare_run(tool.Harness(IMAGE), CASES["candidate bigger"]))


class Packet(unittest.TestCase):
    def test_regeneration_matches_the_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(tool.main(["--out", folder]), 0)
            names = sorted(path.name for path in pathlib.Path(folder).iterdir())
            self.assertEqual(names, ["evidence.json", "mutations.tsv", "path-map.tsv", "reference-diffs.tsv", "samples.tsv", "text-sites.tsv"])
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
