import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import fees_tracker_wire as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "fees-tracker-wire-94"


class Shared:
    image = None
    harness = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)


def named(*names):
    cases = [case for case in tool.rule_cases() if case.name in names]
    assert len(cases) == len(names)
    return cases


class RuleList(unittest.TestCase):
    def test_every_rule_case_matches_real_bytes(self):
        cases = tool.rule_cases()
        self.assertGreaterEqual(len(cases), 110)
        tool.check_all(Shared.harness, cases)

    def test_generated_states_match(self):
        tool.check_all(Shared.harness, tool.vector_cases(4))

    def test_hash_map_is_written_in_key_order(self):
        case = named("hash_map_of_40_rows_written_sorted")[0]
        tool.check_all(Shared.harness, [case])
        rows = tool.canon(tool.ROOT, case.state)["user_states"]
        self.assertEqual([key for key, _ in rows], sorted(key for key, _ in rows))

    def test_aligned_config_absent_keeps_ones(self):
        value = tool.canon(tool.ROOT, tool.least_state())
        self.assertEqual(value["fee_schedule"]["aligned_quote_token_config"], dict(cross_scale=1.0, add_rebate_scale=1.0, vlm_contribution_scale=1.0))
        tool.check_all(Shared.harness, named("aligned_absent_is_one_one_one", "aligned_partial_refused"))

    def test_negative_zero_is_dropped_and_nan_is_kept(self):
        tool.check_all(Shared.harness, named("user_fee_b_negative_zero", "fee_b_nan_kept", "f64_nan_writes_null"))

    def test_json_reader_is_not_exact(self):
        tool.check_all(Shared.harness, named("json_reader_f64_is_not_exact"))

    def test_signed_total_and_unsigned_total(self):
        tool.check_all(Shared.harness, named("ntli_min", "ntli_above_i64", "ntl_negative", "ntl_u64_max"))

    def test_absent_required_fields(self):
        cases = [case for case in tool.struct_cases(tool.full_state()) if case.name.endswith("_absent_json") or case.name.endswith("_array_0_of_2")]
        self.assertGreater(len(cases), 5)
        tool.check_all(Shared.harness, cases)

    def test_memory_offsets_after_real_decode(self):
        rows = tool.memory_rows(Shared.harness)
        self.assertEqual(len(rows), len(tool.MEMORY_CHECKS) + len(tool.SEED_WORDS))

    def test_user_row_layout_after_real_decode(self):
        rows = tool.user_row_layout(Shared.harness)
        self.assertEqual(len(rows), len(tool.USER_LAYOUT))


class NegativeControls(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_wrong_rule_is_caught(self):
        case = tool.Case("wrong", tool.least_state(), want=("error", "not this text"))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(Shared.harness, [case])

    def test_wrong_default_is_caught(self):
        keep = tool.ALIGNED_DEFAULT["cross_scale"]
        tool.ALIGNED_DEFAULT["cross_scale"] = 0.5
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_all(Shared.harness, [tool.Case("least", tool.least_state())])
        finally:
            tool.ALIGNED_DEFAULT["cross_scale"] = keep

    def test_flipped_branch_is_caught(self):
        low, high = Shared.image.exact_fde(tool.SERIALIZE_RMP)
        rows = tool.decode_range(Shared.image, low, high)
        row = next(item for item in rows if item.op == "jcc")
        patch = tool.edits_for(Shared.image, [row])[0][2]
        harness = tool.Harness(Shared.image, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        case = tool.Case("least", tool.least_state())
        hit = tool.first_failure(harness, [case], [tool.spec_run(case)])
        self.assertIsNotNone(hit)

    def test_address_out_of_range_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_corrupt_input_does_not_decode(self):
        data = tool.wire_input(tool.ROOT, tool.least_state())
        self.assertNotEqual(Shared.harness.decode_rmp(data[:40]), ("ok",))


class Packet(unittest.TestCase):
    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["structs"], 14)
        self.assertGreater(data["named_scenarios"], 400)
        self.assertGreater(data["mutations"]["killed"], 0)

    def test_no_absolute_paths_in_evidence(self):
        marks = ("\x2ftmp", "\x2fhome", "\x2fsrv", "\x2fmnt")
        for path in FOLDER.iterdir():
            text = path.read_text()
            for mark in marks:
                self.assertNotIn(mark, text, path.name)


if __name__ == "__main__":
    unittest.main()
