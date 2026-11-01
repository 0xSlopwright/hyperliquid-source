import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_action_wire as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-action-wire-94"
TOKEN = tool.SHAPES["TokenDelegateAction"]


class Shared:
    image = None
    harness = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)


def named(*wanted):
    rows = {case.name: case for case in tool.rule_cases()}
    return [rows[name] for name in wanted]


def token_tree(**edits):
    values = dict(tool.values_of(TOKEN), **edits)
    return tool.tree_of(TOKEN, values)


class RuleList(unittest.TestCase):
    def test_every_action_keeps_its_rules_on_both_readers(self):
        for name in tool.SHAPES:
            cases = [case for case in tool.rule_cases() if case.shape == name and case.mode == "read"]
            self.assertGreater(len(cases), 60, name)
            tool.check_all(Shared.harness, cases)

    def test_profile_and_cvalidator_rules(self):
        cases = [case for case in tool.rule_cases() if case.mode in ("profile", "vote", "vote_write")]
        self.assertGreater(len(cases), 90)
        tool.check_all(Shared.harness, [case for case in cases])

    def test_writers_match_the_rule_list(self):
        cases = [case for case in tool.rule_cases() if case.mode == "write"]
        self.assertGreater(len(cases), 100)
        tool.check_all(Shared.harness, cases)

    def test_generated_vectors(self):
        tool.check_all(Shared.harness, tool.vector_cases(40))

    def test_undelegate_flag_is_a_bool_at_0x45(self):
        got = tool.read_action(Shared.harness, TOKEN, TOKEN.readers[0], token_tree(isUndelegate=True))
        self.assertEqual(got[0], "ok")
        self.assertEqual(Shared.harness.read(tool.DECODED + 0x45, 1), 1)
        tool.read_action(Shared.harness, TOKEN, TOKEN.readers[0], token_tree(isUndelegate=False))
        self.assertEqual(Shared.harness.read(tool.DECODED + 0x45, 1), 0)

    def test_undelegate_flag_refuses_an_integer(self):
        tool.check_all(Shared.harness, named("tokendelegateaction_isUndelegate_integer", "tokendelegateaction_isUndelegate_integer_inline"))

    def test_extend_long_term_staking_is_at_0x29(self):
        shape = tool.SHAPES["CUserModifyAction"]
        values = dict(tool.values_of(shape), extendLongTermStaking=True)
        self.assertEqual(tool.read_action(Shared.harness, shape, shape.readers[0], tool.tree_of(shape, values))[0], "ok")
        self.assertEqual(Shared.harness.read(tool.DECODED + 0x29, 1), 1)

    def test_withdraw_and_deposit_share_writers_not_readers(self):
        left, right = tool.SHAPES["CDepositAction"], tool.SHAPES["CWithdrawAction"]
        self.assertEqual(left.writers, right.writers)
        self.assertNotEqual(left.readers, right.readers)

    def test_profile_keys_differ_between_register_and_change(self):
        tool.check_all(Shared.harness, named("cvalidator_change_profile_key_name_refused", "profile_unknown_key_ignored"))
        self.assertIn("disable_delegations", tool.CHANGE_KEYS)
        self.assertIn("delegations_disabled", tool.PROFILE_KEYS)

    def test_default_commission_is_10000(self):
        tool.check_all(Shared.harness, named("profile_least", "cvalidator_register_default_commission"))

    def test_unregister_word_and_change_word(self):
        self.assertEqual(tool.read_vote(Shared.harness, tool.vote("unregister"))[1], "unregister")
        self.assertEqual(Shared.harness.read(tool.DECODED + tool.ACTION_BASE), tool.NILLED + 1)
        self.assertEqual(tool.read_vote(Shared.harness, tool.vote({"changeProfile": {}}))[1], "changeProfile")
        self.assertEqual(Shared.harness.read(tool.DECODED + tool.ACTION_BASE), tool.NILLED)

    def test_copies_match(self):
        cases = [case for case in tool.rule_cases() if case.mode in ("read", "profile")][:400]
        rows = tool.copy_rows(Shared.image, Shared.harness, cases)
        self.assertGreater(len(rows), 10)

    def test_both_readers_free_the_content_tree(self):
        tree = token_tree()
        Shared.harness.fresh()
        tool.content(Shared.harness, tool.ROOT_ROW, tree)
        blocks = list(Shared.harness.live)
        with self.assertRaises(tool.Halt):
            tool.check_blocks(Shared.harness, blocks)
        tool.read_action(Shared.harness, TOKEN, TOKEN.readers[0], tree)
        tool.read_action(Shared.harness, TOKEN, TOKEN.readers[1], tree)

    def test_ip_writes_as_bytes_in_msgpack_and_text_in_json(self):
        rows = {case.name: case for case in tool.vote_write_cases()}
        self.assertIn(bytes((0x94, 9, 8, 7, 6)).hex(), rows["cvalidator_write_register_pack_named"].want[1])
        self.assertIn(b'"Ip": "9.8.7.6"'.hex(), rows["cvalidator_write_register_pretty"].want[1])


class NegativeControls(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_wrong_error_text_is_caught(self):
        case = tool.Case("wrong", "TokenDelegateAction", "read", (tool.C_MAP, []), ("error", "not this text"))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(Shared.harness, [case])

    def test_wrong_offset_is_caught(self):
        moved = tool.Shape(TOKEN.name, TOKEN.tag, TOKEN.fields, dict(TOKEN.offsets, nonce=0x20), TOKEN.marker, TOKEN.error_at, TOKEN.readers, TOKEN.writers)
        values = tool.values_of(TOKEN)
        got = tool.read_action(Shared.harness, moved, TOKEN.readers[0], tool.tree_of(TOKEN, values))
        self.assertNotEqual(got, ("ok",) + tool.wanted_values(TOKEN, values))

    def test_changed_condition_is_caught(self):
        low, high = Shared.image.exact_fde(TOKEN.readers[0])
        rows = tool.decode_range(Shared.image, low, high)
        row = next(item for item in rows if item.op == "jcc")
        patch = tool.edits_for(Shared.image, [row])[0][2]
        harness = tool.Harness(Shared.image, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        cases = [case for case in tool.rule_cases() if case.shape == TOKEN.name and case.mode == "read" and case.entry is None]
        self.assertIsNotNone(tool.first_failure(harness, cases, [case.want for case in cases]))

    def test_address_outside_every_fde_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_truncated_msgpack_is_refused(self):
        data = tool.vote({"register": {"profile": tool.wire_profile(), "unjailed": True, "initial_wei": 1}})
        self.assertNotEqual(tool.read_vote(Shared.harness, data[:30])[0], "ok")


class Packet(unittest.TestCase):
    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["actions"], 7)
        self.assertGreater(data["named_scenarios"], 1000)
        self.assertGreater(data["mutations"]["killed"], 0)

    def test_no_absolute_paths_in_evidence(self):
        marks = ("\x2ftmp", "\x2fhome", "\x2fsrv", "\x2fmnt")
        for path in FOLDER.iterdir():
            text = path.read_text()
            for mark in marks:
                self.assertNotIn(mark, text, path.name)


if __name__ == "__main__":
    unittest.main()
