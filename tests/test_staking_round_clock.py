import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_round_clock as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-round-clock-94"


class Shared:
    image = None
    harness = None
    cases = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Clock(Shared.image)
    Shared.cases = {case.name: case for case in tool.all_cases()}


def run_one(name, patches=None):
    harness = tool.Clock(Shared.image, patches) if patches else Shared.harness
    return tool.run_case(harness, Shared.cases[name])


def differs(name, patches):
    try:
        return run_one(name, patches) != tool.spec_run(Shared.cases[name])
    except (tool.Panicked, tool.Halt):
        return True


class Spec(unittest.TestCase):
    def assert_group(self, *prefixes):
        names = [name for name in Shared.cases if name.startswith(prefixes)]
        self.assertTrue(names)
        for name in names:
            self.assertEqual(run_one(name), tool.spec_run(Shared.cases[name]), name)

    def test_freeze_gate_all_copies(self):
        self.assert_group("freeze_")

    def test_begin_all_copies(self):
        self.assert_group("begin_")

    def test_apply_gates_all_copies(self):
        self.assert_group("apply_")

    def test_reset(self):
        self.assert_group("reset_")

    def test_reload(self):
        self.assert_group("reload_")

    def test_record(self):
        self.assert_group("record_")

    def test_tick(self):
        self.assert_group("tick_")

    def test_history(self):
        self.assert_group("history_")

    def test_life(self):
        self.assert_group("life_")

    def test_seeded_vectors(self):
        for case in tool.vector_cases(25):
            self.assertEqual(tool.run_case(Shared.harness, case), tool.spec_run(case), case.name)


class Values(unittest.TestCase):
    def test_freeze_window_literals(self):
        row = tool.context(height=500)
        self.assertEqual(tool.spec_freeze(dict(row), 50500), (0x186,))
        self.assertEqual(tool.spec_freeze(dict(row), 50501), (0x72, 50501))
        self.assertEqual(tool.spec_freeze(dict(row), 499), (0x72, 499))
        row = tool.context(height=500, freeze_tag=1, freeze_height=800)
        self.assertEqual(tool.spec_freeze(dict(row), 800), (0x73, 800))
        self.assertEqual(tool.spec_freeze(dict(row), 799), (0x186,))

    def test_status_bytes_from_run(self):
        self.assertIn("(114, 50501)", run_one("freeze_0_empty_past")[0][0])
        self.assertIn("(115, 800)", run_one("freeze_0_set_same")[0][0])
        self.assertIn("(390,)", run_one("freeze_0_set_below")[0][0])

    def test_apply_panic_text(self):
        self.assertIn("assertion failed: !self.state.is_frozen()", run_one("apply_0_freeze_equal")[1][0])
        self.assertIn("assertion failed: freeze_height >= self.locus.context.height()", run_one("apply_0_freeze_past")[1][0])
        self.assertIn("assertion failed: round > parent_round", run_one("apply_0_round_equal")[1][0])
        self.assertIn("assertion failed: features_ok", run_one("apply_0_chain_two")[1][0])

    def test_fork_row_is_the_read_row(self):
        self.assertEqual(run_one("life_fork_read")[0][1], "8250")
        self.assertEqual(run_one("life_fork_read_key")[0][1], "8250")
        self.assertEqual(run_one("life_fork_again")[0][2], "8260")

    def test_window_after_fork(self):
        tracker = dict(epoch_values=dict(initial_round=500, round_to_val=[[500, 0], [2300, 0]]), current_round=2499)
        self.assertEqual(tool.latest_key(tracker), 500)
        tracker["current_round"] = 2500
        self.assertEqual(tool.latest_key(tracker), 2300)

    def test_time_rule(self):
        self.assertEqual(tool.millis(tool.moment(1970, 1, 0, 0)), 0)
        self.assertEqual(tool.millis(tool.moment(1970, 1, 1, 2000000)), 1002)
        self.assertEqual(tool.millis(tool.moment(1960, 1, 0, 0)), 0)
        self.assertEqual(tool.millis(tool.moment(2000, 60, 0, 0)), 951782400000)

    def test_third_copy_shift(self):
        self.assertEqual(tool.field(0x950, 2), 0x13D0)
        self.assertEqual(tool.field(0x38F8, 2), 0x4378)
        self.assertEqual(tool.field(0x30, 2), 0x30)


class Controls(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_not_a_function_start(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(tool.RESET + 1)

    def test_wrong_pin_refused(self):
        saved = tool.PINS
        try:
            tool.PINS = (("bad", tool.RESET, "00", "wrong"),)
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(Shared.image)
        finally:
            tool.PINS = saved

    def test_wrong_text_refused(self):
        saved = tool.TEXTS
        try:
            tool.TEXTS = (("bad", 0x3EF327, "scheduled_freeze_heighx", "wrong"),)
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(Shared.image)
        finally:
            tool.TEXTS = saved

    def test_patched_window_changes_result(self):
        self.assertTrue(differs("freeze_0_empty_past", {0x2703AFD + 3: 0x51}))

    def test_patched_status_changes_result(self):
        self.assertTrue(differs("freeze_0_set_same", {0x2703AF3 + 3: 0x74}))

    def test_patched_round_store_changes_begin(self):
        self.assertTrue(differs("begin_0_later_day", {0x26F8BDD + 3: 0x51}))

    def test_patched_third_mirror_changes_begin(self):
        self.assertTrue(differs("begin_2_later_day", {0x4CDF3FB + 3: 0x19}))

    def test_patched_freeze_clear_changes_reset(self):
        self.assertTrue(differs("reset_freeze_cleared", {0x2207F6A + 7: 1}))

    def test_patched_initial_round_changes_reset(self):
        self.assertTrue(differs("reset_rows", {0x2207F75 + 3: 0x29}))

    def test_patched_keep_compare_changes_reset(self):
        self.assertTrue(differs("reset_keep_one", {0x2208017: 0x77}))

    def test_patched_due_compare_changes_tick(self):
        self.assertTrue(differs("tick_stake_exact", {0x3996B6B: 0x73}))

    def test_patched_gated_compare_changes_record(self):
        self.assertTrue(differs("record_gated_exact", {0x37D9C0B: 0x83}))

    def test_wrong_window_found_by_spec(self):
        saved = tool.WINDOW
        try:
            tool.WINDOW = saved + 1
            self.assertNotEqual(run_one("freeze_0_empty_past"), tool.spec_run(Shared.cases["freeze_0_empty_past"]))
        finally:
            tool.WINDOW = saved

    def test_wrong_history_rule_found(self):
        saved = tool.latest_key
        try:
            tool.latest_key = lambda tracker: 501
            self.assertNotEqual(run_one("history_row_2500"), tool.spec_run(Shared.cases["history_row_2500"]))
        finally:
            tool.latest_key = saved

    def test_wrong_prune_rule_found(self):
        saved = tool.spec_prune
        try:
            tool.spec_prune = lambda rows, keep: None
            self.assertNotEqual(run_one("record_stakes_prune"), tool.spec_run(Shared.cases["record_stakes_prune"]))
        finally:
            tool.spec_prune = saved


class Evidence(unittest.TestCase):
    def test_status_texts(self):
        rows = {row[0]: row[3] for row in tool.status_rows(Shared.image)}
        self.assertTrue(rows["0x72"].startswith("Invalid height "))
        self.assertTrue(rows["0x73"].startswith("Already frozen at height "))

    def test_vote_arm_index(self):
        self.assertEqual([row[0] for row in tool.vote_rows(Shared.image)], [32])

    def test_every_pin_binds(self):
        self.assertEqual(len(tool.pin_rows(Shared.image)), len(tool.PINS))

    def test_every_text_binds(self):
        self.assertEqual(len(tool.text_rows(Shared.image)), len(tool.TEXTS))

    def test_function_bounds(self):
        for target in list(tool.NAMES) + list(tool.HELPERS):
            start, end = Shared.image.exact_fde(target)
            self.assertLess(start, end)

    def test_stored_summary(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["named_scenarios"], len(Shared.cases))
        self.assertGreater(summary["mutations"]["killed"], summary["mutations"]["survived"])

    def test_no_external_programs(self):
        text = pathlib.Path(tool.__file__).read_text()
        self.assertNotIn("subprocess", text)
        self.assertNotIn("os.system", text)


if __name__ == "__main__":
    unittest.main()
