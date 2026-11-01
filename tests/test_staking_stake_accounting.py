import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_stake_accounting as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-stake-accounting-94"


class Shared:
    image = None
    harness = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Book2(Shared.image)


def named(*names):
    found = [case for case in tool.all_cases() if case.name in names]
    assert len(found) == len(names)
    return found


def run_one(name, patches=None):
    case = named(name)[0]
    harness = tool.Book2(Shared.image, patches) if patches else Shared.harness
    return tool.run_case(harness, case)


def status_of(name):
    return eval(run_one(name)[0][0])


class Spec(unittest.TestCase):
    def assert_cases(self, *names):
        for case in named(*names):
            self.assertEqual(tool.run_case(Shared.harness, case), tool.spec_run(case), case.name)

    def test_refusals_match(self):
        self.assert_cases("unknown_validator_with_rows", "no_history_row", "profile_disabled_delegate", "blocked_reward_row", "wei_above_balance", "undelegate_above_row", "exit_lock_one_nano_after", "exit_floor_refused")

    def test_status_of_each_refusal(self):
        self.assertEqual(status_of("unknown_validator_with_rows"), 0x91)
        self.assertEqual(status_of("no_history_row"), 0x97)
        self.assertEqual(status_of("wei_above_balance"), 0xFC)
        self.assertEqual(status_of("profile_disabled_delegate"), 0xFD)
        self.assertEqual(status_of("undelegate_above_row"), 0xFE)
        self.assertEqual(status_of("exit_lock_one_nano_after"), 0xFF)
        self.assertEqual(status_of("exit_floor_refused"), 0x130)

    def test_reward_row_skips_profile_flag_only(self):
        self.assertEqual(status_of("profile_disabled_reward_row_passes"), tool.OK)
        self.assertEqual(status_of("blocked_reward_row"), 0xFD)

    def test_window_takes_last_row_at_or_below_bound(self):
        self.assert_cases("window_early_uses_low", "window_edge_2000_uses_cur_minus_200", "window_key_between", "window_start_below_every_key", "window_three_level_many_rows")
        self.assertEqual(status_of("window_start_below_every_key"), 0x97)

    def test_window_rule_values(self):
        tracker = dict(epoch_values=dict(initial_round=500, round_to_val=[[400, 0], [500, 0], [2300, 0], [2301, 0]]), current_round=2499)
        self.assertEqual(tool.latest_key(tracker), 500)
        tracker["current_round"] = 2500
        self.assertEqual(tool.latest_key(tracker), 2300)
        tracker["current_round"] = 2600
        self.assertEqual(tool.latest_key(tracker), 2301)
        tracker["epoch_values"]["initial_round"] = 300
        tracker["current_round"] = 310
        self.assertEqual(tool.latest_key(tracker), None)

    def test_delegate_rows_match(self):
        self.assert_cases("delegate_first_row_chain_0", "delegate_first_row_chain_3", "delegate_existing_row_new_key", "delegate_target_overflow", "reward_row_new_keeps_now")

    def test_undelegate_rows_match(self):
        self.assert_cases("undelegate_member_same_key_min_drops", "undelegate_no_member", "undelegate_effective_min", "self_exit_below_floor_blocks", "undelegate_last_member_drops_group")

    def test_overflow_reports_to_the_recorder(self):
        self.assertEqual(run_one("delegate_target_overflow")[1], ("('severe', 190)",))
        self.assertIn("'over'", run_one("delegate_member_overflow")[1][0])

    def test_sink_matches(self):
        self.assert_cases("sink_stops_at_kind_2", "sink_short_balance_fails_row", "sink_kind_order", "sink_sum_overflow")

    def test_power_matches_each_chain(self):
        self.assert_cases("foundation_and_one_large_chain_1", "foundation_and_one_large_chain_2", "foundation_and_one_large_chain_3", "all_zero_stakes_chain_3", "limit_foundation_first", "same_signer_last_key_wins", "large_values_bail_raw")

    def test_boost_gives_foundation_less_top_member_over_two_thirds(self):
        members = tool.FOUNDATION[3]
        state = tool.power_state([(members[0], 9000), (members[1], 100), (members[2], 100), (members[3], 100), (members[4], 100), (tool.v(0), 100000)])
        value = tool.canon(tool.ROOT, state)
        power = dict(tool.spec_power(value, value["stakes"]["current"], 3))
        shares = sorted(amount for key, amount in power.items() if key in (tool.find(value["validator_to_profile"], member)["signer"] for member in members))
        self.assertGreater(3 * sum(shares[:-1]), 2 * sum(power.values()))

    def test_tree_rebalance(self):
        self.assert_cases("tree_delegate_many_users")

    def test_seeded_sequences(self):
        for case in tool.vector_cases(3):
            self.assertEqual(tool.run_case(Shared.harness, case), tool.spec_run(case), case.name)


class Controls(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_not_a_function_start(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(tool.CORE + 1)

    def test_wrong_pin_refused(self):
        saved = tool.PINS
        try:
            tool.PINS = (("bad", tool.CORE, "00", "wrong"),)
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(Shared.image)
        finally:
            tool.PINS = saved

    def test_patched_status_byte_changes_result(self):
        changed = run_one("unknown_validator_with_rows", {0x398DECD + 3: 0x92})
        self.assertEqual(eval(changed[0][0]), 0x92)

    def test_patched_lock_compare_changes_state(self):
        case = named("exit_lock_one_nano_after")[0]
        patched = tool.Book2(Shared.image, {0x3C0EC9C: 0x77})
        self.assertNotEqual(tool.run_case(patched, case), tool.spec_run(case))

    def test_patched_per_mille_changes_power(self):
        case = named("share_rounds_to_zero")[0]
        patched = tool.Book2(Shared.image, {0x3C11468: 0xE9})
        self.assertNotEqual(tool.run_case(patched, case), tool.spec_run(case))

    def test_wrong_lock_seconds_found_by_spec(self):
        saved = tool.LOCK_SECONDS[3]
        try:
            tool.LOCK_SECONDS[3] = saved + 1
            case = named("delegate_first_row_chain_3")[0]
            self.assertNotEqual(tool.run_case(Shared.harness, case), tool.spec_run(case))
            with self.assertRaises(tool.EvidenceError):
                tool.lock_rows(Shared.image)
        finally:
            tool.LOCK_SECONDS[3] = saved

    def test_wrong_window_rule_found(self):
        case = named("window_key_between")[0]
        saved = tool.latest_key
        try:
            tool.latest_key = lambda tracker: 501
            self.assertNotEqual(tool.run_case(Shared.harness, case), tool.spec_run(case))
        finally:
            tool.latest_key = saved


class Evidence(unittest.TestCase):
    def test_lock_table(self):
        self.assertEqual([row[3] for row in tool.lock_rows(Shared.image)], ["604800", "120", "120", "86400"])

    def test_status_texts(self):
        rows = {row[0]: row[2] for row in tool.status_rows(Shared.image)}
        self.assertEqual(rows["0xfc"], "Insufficient balance to delegate")
        self.assertEqual(rows["0xfe"], "Insufficient balance to undelegate")

    def test_every_pin_binds(self):
        self.assertEqual(len(tool.pin_rows(Shared.image)), len(tool.PINS))

    def test_function_bounds(self):
        for target in tool.NAMES:
            start, end = Shared.image.exact_fde(target)
            self.assertLess(start, end)

    def test_stored_summary(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertGreaterEqual(summary["named_scenarios"], 189)
        self.assertGreater(summary["mutations"]["killed"], summary["mutations"]["survived"])

    def test_no_external_programs(self):
        text = pathlib.Path(tool.__file__).read_text()
        self.assertNotIn("subprocess", text)
        self.assertNotIn("os.system", text)


if __name__ == "__main__":
    unittest.main()
