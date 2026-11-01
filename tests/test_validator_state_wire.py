import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import validator_state_wire as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-validator-state-wire-94"
STAKING = tool.ROOTS["Staking"]
VOTES = tool.ROOTS["ValidatorL1VoteTracker"]
STREAM = tool.ROOTS["ValidatorL1StreamTracker"]


class Shared:
    image = None
    harness = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)


def named(*wanted):
    rows = {case.name: case for case in tool.rule_cases() + tool.all_struct_cases()}
    return [rows[name] for name in wanted]


class RuleList(unittest.TestCase):
    def test_root_cases_of_all_three_roots(self):
        cases = [case for root in tool.ROOTS for case in tool.root_cases(root)]
        self.assertGreaterEqual(len(cases), 60)
        tool.check_all(Shared.harness, cases)

    def test_generated_states_match(self):
        tool.check_all(Shared.harness, tool.vector_cases(6))

    def test_default_epoch_duration_is_100_years(self):
        tool.check_all(Shared.harness, named("staking_epoch_duration_seconds_absent"))
        self.assertEqual(tool.HUNDRED_YEARS, 3153600000)
        Shared.harness.decode_rmp(tool.emit(STAKING.kind, {k: v for k, v in tool.least_staking().items() if k != "epoch_duration_seconds"}, True), STAKING)
        self.assertEqual(Shared.harness.read(tool.DECODED), 3153600000)

    def test_zero_duration_is_refused(self):
        tool.check_all(Shared.harness, named("duration_zero"))

    def test_keys_of_validator_rows_are_32_bytes(self):
        tool.check_all(Shared.harness, named("key_address_length", "key_33_u8", "key_bin8"))

    def test_epoch_rows_sort_as_numbers(self):
        tool.check_all(Shared.harness, named("epoch_rows_sorted_as_numbers", "epoch_duplicate_key"))

    def test_vote_key_order_and_unknown_variant(self):
        tool.check_all(Shared.harness, named("vote_keys_sort_by_variant_index_then_fields", "vote_key_unknown_variant", "vote_e_unknown_field"))

    def test_every_outcome_variant_row(self):
        cases = [case for case in tool.rule_cases() if case.name.startswith("outcome_")]
        self.assertEqual(len(cases), 30)
        tool.check_all(Shared.harness, cases)

    def test_policy_defaults_differ_between_fields(self):
        rows = dict((row[0] + "." + row[2], row[4]) for row in tool.field_rows())
        self.assertIn('"q": 0.5', rows["ValidatorL1VoteTracker.hc"])
        self.assertIn('"q": 0.0', rows["RawSignatureTracker.hsc"])

    def test_median_may_be_absent_in_a_map_not_in_an_array(self):
        tool.check_all(Shared.harness, named("medianstreamtracker_m_absent", "medianstreamtracker_array_1_of_3"))

    def test_memory_offsets_after_real_decode(self):
        rows = tool.memory_rows(Shared.harness)
        self.assertEqual(len(rows), len(tool.MEMORY_CHECKS))

    def test_route_rows_reach_the_staking_writers(self):
        rows = tool.route_rows(Shared.image)
        self.assertEqual([row[2] for row in rows], ["0x2219450", "0x22196a0"])
        self.assertEqual({row[3] for row in rows}, {"staking"})

    def test_interpreter_moves_only_4_bytes_for_movss(self):
        row = tool.row_at(Shared.image, 0x199E0BB)
        self.assertEqual(row.op, "movss")


class NegativeControls(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_wrong_rule_is_caught(self):
        case = tool.Case("wrong", "Staking", tool.least_staking(), want=("error", "not this text"))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(Shared.harness, [case])

    def test_wrong_default_is_caught(self):
        state = {k: v for k, v in tool.least_staking().items() if k != "epoch_duration_seconds"}
        case = tool.Case("wrong_default", "Staking", dict(state, epoch_duration_seconds=86400), data=tool.emit(STAKING.kind, state, True))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(Shared.harness, [case])

    def test_changed_condition_is_caught(self):
        low, high = Shared.image.exact_fde(STAKING.write_rmp)
        rows = tool.decode_range(Shared.image, low, high)
        row = next(item for item in rows if item.op == "jcc")
        patch = tool.edits_for(Shared.image, [row])[0][2]
        harness = tool.Harness(Shared.image, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        case = tool.Case("least", "Staking", tool.least_staking())
        hit = tool.first_failure(harness, [case], [tool.spec_run(case)])
        self.assertIsNotNone(hit)

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_corrupt_input_does_not_decode(self):
        for root in (STAKING, VOTES, STREAM):
            data = tool.emit(root.kind, tool.LEAST[root.name](), True)
            self.assertNotEqual(Shared.harness.decode_rmp(data[:12], root), ("ok",))


class Packet(unittest.TestCase):
    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["roots"], 3)
        self.assertEqual(data["vote_variants"], 8)
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
