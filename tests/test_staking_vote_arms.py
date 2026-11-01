import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_vote_arms as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-vote-arms-94"


class Shared:
    image = None
    harness = None
    cases = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)
    Shared.cases = dict((case.name, case) for case in tool.named_cases())


def run(name=None, case=None):
    return tool.run_case(Shared.harness, case if case is not None else Shared.cases[name])


def item(got, kind):
    return [row for row in got if row[0] == kind][0]


def word(got, at):
    rows = dict(item(got, "diff")[1])
    return int.from_bytes(bytes(rows.get(at + index, 0) for index in range(8)), "little")


class Arms(unittest.TestCase):
    def test_every_named_case_matches_real_bytes(self):
        self.assertGreaterEqual(len(Shared.cases), 900)
        for case in Shared.cases.values():
            if len(case.rows) < 1000:
                tool.check_case(Shared.harness, case)

    def test_list_edge_of_ten_thousand_rows(self):
        self.assertEqual(run("toggle_exact_cap")[0], ("status", tool.OK))
        self.assertEqual(run("toggle_over_cap")[0], ("status", tool.TOO_LONG))
        self.assertEqual(item(run("toggle_over_cap"), "left")[1], 0)

    def test_generated_cases_match(self):
        seen = set()
        for case in tool.vector_cases(80):
            seen.add(tool.check_case(Shared.harness, case)[0][1])
        self.assertTrue({tool.OK, tool.BAD_WEI} <= seen)

    def test_period_zero_keeps_and_first_write_stays_after_a_late_refusal(self):
        self.assertEqual(item(run("periods_0_0"), "diff")[1], ())
        got = run("periods_5_ccccccccccccccc")
        self.assertEqual(got[0], ("status", tool.BAD_WEI))
        self.assertEqual(word(got, tool.E_STAKES_PERIOD), 5)

    def test_none_leaves_a_table_address_in_the_value_word(self):
        self.assertEqual(word(run("max_0_0"), tool.E_MAX_VALUE), tool.TABLE)

    def test_floor_writes_only_in_mode_one(self):
        self.assertEqual(item(run("floor_3e8_0"), "diff")[1], ())
        self.assertEqual(word(run("floor_3e8_1"), tool.E_FLOOR), 1000)
        self.assertEqual(item(run("floor_3e8_101"), "diff")[1], ())

    def test_allow_all_needs_both_words(self):
        self.assertEqual(item(run("allow_all_0_1_1"), "diff")[1], ())
        self.assertEqual(item(run("allow_all_1_0_1"), "diff")[1], ())
        self.assertEqual(dict(item(run("allow_all_1_1_1"), "diff")[1])[tool.E_ALLOW_ALL], 1)

    def test_decay_guard_is_fixed_date_reward_guard_is_block_time(self):
        self.assertEqual(word(run("decay_e10"), tool.E_DECAY + 8), tool.JAN_1971_MS // 3600000)
        got = run("reward_e10")
        self.assertEqual(word(got, tool.E_REWARD), 3600000)
        case = Shared.cases["reward_e10"]
        self.assertEqual(word(got, tool.E_REWARD + 8), tool.seconds_of(case.date, case.secs, case.nanos) // 3600000)

    def test_decay_clamps_seconds_reward_refuses_them(self):
        self.assertEqual(word(run("decay_2a301"), tool.E_DECAY), 172800000)
        self.assertEqual(run("reward_2a301")[0], ("status", tool.BAD_SECONDS))
        self.assertEqual(run("reward_0")[0], ("status", tool.BAD_SECONDS))

    def test_refund_checks_the_word_only_for_a_profile_row(self):
        self.assertEqual(run("refund_nothing_over_cap")[0], ("status", tool.OK))
        self.assertEqual(run("refund_allowed_only_over_cap")[0], ("status", tool.OK))
        self.assertEqual(run("refund_one_over_cap")[0], ("status", tool.BAD_WEI))

    def test_refund_saturates_at_zero_and_uses_the_signer_key(self):
        self.assertEqual(item(run("refund_one_more"), "limits")[1][0][1], 0)
        self.assertEqual(item(run("refund_limit_row_is_validator_not_signer"), "limits")[1][0][1], 9)

    def test_shared_signer_is_charged_once_per_validator(self):
        self.assertEqual(item(run("refund_shared_signer"), "limits")[1][0][1], 0)

    def test_none_tag_ip_is_not_inserted(self):
        self.assertEqual(item(run("node_ip_insert_none_tag"), "rows")[0:2], ("rows", "allowed_validators"))
        rows = dict((row[1], row[2]) for row in run("node_ip_insert_none_tag") if row[0] == "rows")
        self.assertEqual(rows["disabled_node_ips"], ())

    def test_odd_tag_key_compares_one_byte(self):
        rows = dict((row[1], row[2]) for row in run("node_ip_odd_same_first_byte") if row[0] == "rows")
        self.assertEqual(len(rows["disabled_node_ips"]), 5)
        rows = dict((row[1], row[2]) for row in run("node_ip_odd_remove_other_tail") if row[0] == "rows")
        self.assertEqual(len(rows["disabled_node_ips"]), 4)

    def test_ipv4_key_sorts_big_endian(self):
        rows = dict((row[1], row[2]) for row in run("node_ip_order_big_endian") if row[0] == "rows")
        self.assertEqual(rows["disabled_node_ips"], ("0000000002", "0001000000", "0002000000"))

    def test_unjail_all_clears_three_maps(self):
        got = run("unjail_all_12_28672_2_7100")
        self.assertEqual(item(got, "jail_map")[1:], (0x7100, 2, 9))
        self.assertEqual(item(got, "votes")[2], 0x7000)
        self.assertEqual(dict((row[1], row[2]) for row in got if row[0] == "rows")["jailed_signers.current"], ())


class Copies(unittest.TestCase):
    def test_copies_match_with_their_own_table_word(self):
        rows = tool.copy_rows(Shared.image, [case for name, case in Shared.cases.items() if name.startswith(("max_", "refund_one", "periods_", "unjail_all_3", "cvalidator"))])
        self.assertEqual([row[3] for row in rows], ["0x0", "0xa80"])


class Negative(unittest.TestCase):
    def test_wrong_sha256_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_compare_refuses_a_changed_status(self):
        case = Shared.cases["max_1_15"]
        got = run(case=case)
        self.assertFalse(tool.compare((("status", tool.BAD_WEI),) + got[1:], tool.spec_run(case), case))

    def test_flipped_gate_branch_is_seen(self):
        site = 0x2358EE5
        offset = Shared.image.offset(site)
        byte = bytes(Shared.image.blob[offset + 1:offset + 2])[0]
        harness = tool.Harness(Shared.image, {site + 1: byte ^ 1})
        case = Shared.cases["periods_5_0"]
        self.assertIsNotNone(tool.first_failure(harness, [case], [tool.spec_run(case)]))

    def test_changed_field_offset_is_seen(self):
        site = 0x2358EEB + 3
        offset = Shared.image.offset(site)
        byte = bytes(Shared.image.blob[offset:offset + 1])[0]
        harness = tool.Harness(Shared.image, {site: byte ^ 8})
        case = Shared.cases["periods_5_0"]
        self.assertIsNotNone(tool.first_failure(harness, [case], [tool.spec_run(case)]))

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(Exception):
            Shared.image.exact_fde(0x10)

    def test_moved_constant_is_refused(self):
        saved = tool.CONSTANTS
        try:
            tool.CONSTANTS = ((0x1E80430, 6, "list cap", "000000000000"),)
            with self.assertRaises(tool.EvidenceError):
                tool.constant_rows(Shared.image)
        finally:
            tool.CONSTANTS = saved

    def test_arm_table_check_refuses_a_wrong_row(self):
        saved = tool.ARMS
        try:
            tool.ARMS = ((0x24, 0x2358000, "x", "y"),)
            with self.assertRaises(tool.EvidenceError):
                tool.table_rows(Shared.image)
        finally:
            tool.ARMS = saved

    def test_variant_check_refuses_a_wrong_tag(self):
        saved = tool.VARIANT_TAGS
        try:
            tool.VARIANT_TAGS = (("DisableCValidator", 0x1BAC883, 0x100, 0x45),)
            with self.assertRaises(tool.EvidenceError):
                tool.variant_rows(Shared.image)
        finally:
            tool.VARIANT_TAGS = saved


class Wire(unittest.TestCase):
    def test_variant_tags_bind_names(self):
        rows = tool.variant_rows(Shared.image)
        self.assertEqual([row[3] for row in rows], ["0x39", "0x3a", "0x3e", "0x43", "0x44"])

    def test_arm_table(self):
        self.assertEqual(len(tool.table_rows(Shared.image)), 14)


class Files(unittest.TestCase):
    def test_summary_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_scenarios"], len(Shared.cases))
        self.assertEqual(data["functions"], len(tool.NAMES))

    def test_manifest_lists_every_file(self):
        names = set()
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, set(path.name for path in FOLDER.iterdir()) - {"MANIFEST.sha256"})

    def test_scenarios_file_matches_the_rules(self):
        rows = dict(line.split("\t", 1) for line in (FOLDER / "scenarios.tsv").read_text().splitlines()[1:])
        for name in ("max_1_15", "refund_one", "reward_0"):
            case = Shared.cases[name]
            self.assertEqual(rows[name], tool.describe(case, tool.spec_run(case)))

    def test_no_external_tool_in_source(self):
        text = (pathlib.Path(tool.__file__)).read_text()
        for word_ in ("sub" + "process", "obj" + "dump", "read" + "elf"):
            self.assertNotIn(word_ + "(", text)


if __name__ == "__main__":
    unittest.main()
