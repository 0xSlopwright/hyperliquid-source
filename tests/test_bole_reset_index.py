"""Tests for tools/bole_reset_index.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-bole-reset-index-94"
spec_ = importlib.util.spec_from_file_location("bole_reset_index", ROOT / "tools" / "bole_reset_index.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["bole_reset_index"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
OK = tool.OK
ONE = tool.ONE
CAP = tool.CAP
TOP = tool.MASK[8]
PLAN_ROUND_SET = b"\x0f\x95\xc0\x49\x01\xc0"
PLAN_INDEX_PICK = 0x373c3cb
PARAMS_ORDER = 0x373511f
ROW_GATE_FOUND = 0x3c0d889
WORD_17_FLAG_MASK = 0x235cd1f
WORD_7_BOUND = 0x373cc24


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=150)
    FILES = tool.render(RESULT)


def run(**fields):
    fields.setdefault("rows", tool.indexed(ONE, ONE))
    case = tool.Case("t", **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), (fields, got["status"], got["events"])
    return got


def one_user(borrow, supply):
    return ((tool.key_of(1), ((2, (0x71, borrow, 0x72, supply)),)),)


def row_words(got, token=2):
    return struct.unpack("<21Q", dict(got["rows"])[token][:0xA8])


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Tables(unittest.TestCase):
    def test_arm_entry(self):
        self.assertEqual(tool.COPIES[0].arm(IMAGE), 0x23593DB)

    def test_three_tables(self):
        self.assertEqual(len({tool.sub_table(IMAGE, item) for item in tool.COPIES}), 3)

    def test_word_arms(self):
        rows = {row[3]: row[4] for row in tool.word_rows(IMAGE) if row[0] == "a"}
        self.assertEqual((rows["17"], rows["16"], rows["5"], rows["4"], rows["7"]), ("0x235c2f5", "0x235c08b", "0x235c34e", "0x235c296", "0x235c52d"))

    def test_slot_targets(self):
        slots = {row[2]: row[1] for row in tool.slot_rows(IMAGE)}
        self.assertEqual(slots["reset plan, real"], "0x373c280")
        self.assertEqual(slots["reset apply, real"], "0x373be40")
        self.assertEqual(slots["adl body, hook"], "0x373cc50")
        self.assertEqual(slots["params apply, real"], "0x37350c0")

    def test_serde_texts(self):
        self.assertEqual(len(tool.serde_rows(IMAGE)), len(tool.SERDE))

    def test_a_missing_text_stops_the_tool(self):
        bad = copy.copy(IMAGE)
        bad.blob = bytes(IMAGE.blob).replace(tool.SERDE[0], b"x" * len(tool.SERDE[0]))
        with self.assertRaises(tool.EvidenceError):
            tool.serde_rows(bad)


class Reset(unittest.TestCase):
    def test_low_bit_clear_rounds_borrow_up_and_sets_its_index(self):
        got = run(flag=0, rows=tool.indexed(ONE // 3, ONE * 5), users=one_user(1, 7))
        self.assertEqual(got["users"][0][1][0][1], (0x71, 1, 0x72, 7))
        words = row_words(got)
        self.assertEqual((words[8], words[11], words[15]), (1, ONE, ONE * 5))

    def test_low_bit_set_rounds_supply_down(self):
        got = run(flag=1, rows=tool.indexed(ONE, ONE // 3), users=one_user(9, 1))
        self.assertEqual(got["users"][0][1][0][1], (0x71, 9, 0x72, 0))
        words = row_words(got)
        self.assertEqual((words[12], words[15], words[11]), (0, ONE, ONE))

    def test_only_the_low_flag_byte_bit_counts(self):
        self.assertEqual(row_words(run(flag=0x100, users=one_user(3, 3), rows=tool.indexed(2 * ONE, 5 * ONE)))[8], 6)
        self.assertEqual(row_words(run(flag=0x101, users=one_user(3, 3), rows=tool.indexed(2 * ONE, 5 * ONE)))[12], 15)

    def test_total_is_the_sum_of_rounded_words(self):
        users = tuple((tool.key_of(n), ((2, (0, 1, 0, 1)),)) for n in range(1, 8))
        got = run(flag=0, users=users, rows=tool.indexed(ONE // 3, ONE))
        self.assertEqual(row_words(got)[8], 7)

    def test_index_one_still_replaces_a_total_that_disagrees(self):
        got = run(flag=0, users=one_user(5, 5), rows=((2, tool.base_row(borrowed=999)),))
        self.assertEqual(row_words(got)[8], 5)

    def test_no_users_clears_the_total(self):
        self.assertEqual(row_words(run(flag=0, rows=tool.indexed(3 * ONE, ONE)))[8], 0)

    def test_nonzero_user_rounded_to_zero_stays_in_the_map(self):
        got = run(flag=1, users=one_user(0, 1), rows=tool.indexed(ONE, 1))
        self.assertEqual(got["users"][0][1][0], (2, (0x71, 0, 0x72, 0)))

    def test_exact_product_does_not_round_up(self):
        self.assertEqual(row_words(run(flag=0, users=one_user(3, 0), rows=tool.indexed(ONE // 3 + 1, ONE)))[8], 2)
        self.assertEqual(row_words(run(flag=0, users=one_user(4, 0), rows=tool.indexed(ONE // 2, ONE)))[8], 2)

    def test_quotient_of_exactly_2_64_refused(self):
        got = run(flag=1, users=one_user(0, 1 << 62), rows=tool.indexed(ONE, 4 * ONE))
        self.assertEqual((got["status"], got["nested"]), (tool.TAG_NESTED, tool.INNER_REFUSED))

    def test_one_below_stores(self):
        value = TOP
        got = run(flag=1, users=one_user(0, value), rows=tool.indexed(ONE, ONE))
        self.assertEqual(row_words(got)[12], value)

    def test_ceiling_past_top_refused_where_floor_stores(self):
        users = one_user(TOP, TOP)
        rows = tool.indexed(ONE + 1, ONE + 1)
        self.assertEqual(tool.scale(TOP, ONE + 1, False) >> 64, 1)
        run(flag=0, users=users, rows=rows)
        edge = tool.indexed(ONE, ONE)
        run(flag=0, users=users, rows=edge)

    def test_sum_past_top_refused_with_no_write(self):
        users = ((tool.key_of(1), ((2, (0, 0, 0, TOP)),)), (tool.key_of(2), ((2, (0, 0, 0, 1)),)))
        got = run(flag=1, users=users)
        self.assertEqual(got["status"], tool.TAG_NESTED)
        self.assertEqual(got["users"][0][1][0][1][3], TOP)

    def test_gate_order(self):
        self.assertEqual(run(token=9, users=one_user(1, 1))["word1"], 9)
        got = run(token=3, users=one_user(1, 1))
        self.assertEqual((got["status"], got["nested"]), (tool.TAG_NESTED, 0))

    def test_no_block_left(self):
        for flag in (0, 1):
            self.assertEqual(run(flag=flag, users=tool.plain_users())["left"], ())

    def test_other_tokens_keep_their_words(self):
        got = run(flag=0, users=tool.plain_users(), rows=tool.indexed(2 * ONE, 2 * ONE))
        self.assertEqual(dict(got["users"][0][1])[3], (1, 2, 3, 4))

    def test_deep_user_tree_visits_in_key_order(self):
        users = tuple((tool.key_of(n), ((2, (0, n, 0, n)),)) for n in range(1, 61))
        got = run(flag=1, height=3, users=users, rows=tool.indexed(ONE, 2 * ONE))
        self.assertEqual(row_words(got)[12], 2 * sum(range(1, 61)))


class Wrapper(unittest.TestCase):
    def test_statuses(self):
        self.assertEqual(run(kind="wrapper", token=3, side=1)["status"], tool.STATUS_NO_ROW)
        self.assertEqual(run(kind="wrapper", rows=tool.indexed(2 * ONE, 2 * ONE), users=one_user(TOP, TOP), side=1)["status"], tool.STATUS_PAST_64)
        self.assertEqual(run(kind="wrapper", users=((tool.key_of(1), ((2, (0, TOP, 0, TOP)),)), (tool.key_of(2), ((2, (0, 1, 0, 1)),))), side=0)["status"], tool.STATUS_TOTAL)
        self.assertEqual(run(kind="wrapper", side=0)["status"], tool.STATUS_OK)

    def test_every_refusal_is_one_output_at_the_arm(self):
        rows = tool.indexed(2 * ONE, 2 * ONE)
        one = run(flag=0, rows=rows, users=one_user(TOP, TOP))
        two = run(flag=0, rows=tool.indexed(ONE, ONE), users=((tool.key_of(1), ((2, (0, TOP, 0, 0)),)), (tool.key_of(2), ((2, (0, 1, 0, 0)),))))
        self.assertEqual((one["status"], one["nested"]), (two["status"], two["nested"]))

    def test_three_wrappers_are_the_three_copies(self):
        self.assertEqual([item.wrapper for item in tool.COPIES], list(tool.WRAPPERS))
        self.assertEqual([item.entry(IMAGE) for item in tool.COPIES], [0x2355F40, 0x4CAA870, 0x4CB3200])


class Adl(unittest.TestCase):
    def test_amount_gate_after_the_row_gate(self):
        self.assertEqual(run(kind="adl", token=3, amount=CAP)["status"], tool.TAG_NESTED)
        got = run(kind="adl", amount=CAP)
        self.assertEqual((got["status"], got["word1"], got["events"]), (tool.TAG_NUMBER, CAP, ()))

    def test_result_three_carries_its_byte(self):
        got = run(kind="adl", amount=1, adl_tag=3, adl_byte=0x44)
        self.assertEqual((got["status"], got["nested"]), (tool.TAG_NESTED, 0x44))

    def test_result_two_ends_with_no_reset(self):
        got = run(kind="adl", amount=1, adl_tag=2, users=one_user(5, 5), rows=tool.indexed(ONE, 7 * ONE))
        self.assertEqual(got["status"], OK)
        self.assertEqual(row_words(got)[15], 7 * ONE)

    def test_other_results_commit_then_reset_supply(self):
        got = run(kind="adl", amount=1, users=one_user(5, 5), rows=tool.indexed(3 * ONE, 7 * ONE))
        self.assertEqual(got["events"], ("user", "adl", "commit", "user"))
        words = row_words(got)
        self.assertEqual((words[12], words[15], words[11]), (35, ONE, 3 * ONE))

    def test_token_read_ignores_the_high_side_byte(self):
        got = HARNESS.run(tool.Case("t", kind="read", side=0x100, token=2, users=((2, (1, 2, 3, 4)),)))
        self.assertEqual(got["status"], 4)

    def test_token_read_sides(self):
        self.assertEqual(HARNESS.run(tool.Case("t", kind="read", side=1, token=2, users=((2, (1, 2, 3, 4)),)))["status"], 2)
        self.assertEqual(HARNESS.run(tool.Case("t", kind="read", side=0, token=5, users=((2, (1, 2, 3, 4)),)))["status"], 0)


class Texts(unittest.TestCase):
    def test_option_stores_flag_and_value(self):
        got = run(kind="option", text=b"1.5", float_bits=0x3FF8000000000000)
        self.assertEqual(got["changes"], ((tool.OPTION_AT, 1), (tool.OPTION_VALUE_AT, 0x3FF8000000000000)))

    def test_option_absent_clears_the_flag(self):
        self.assertEqual(dict(run(kind="option")["changes"])[tool.OPTION_AT], 0)

    def test_option_failed_conversion(self):
        got = run(kind="option", text=b"1")
        self.assertEqual((got["status"], got["changes"]), (tool.TAG_NOT_FINITE, ()))

    def test_length_limit(self):
        self.assertEqual(run(kind="option", text=b"0" * 101)["status"], tool.TAG_LENGTH)
        self.assertEqual(run(kind="ratio", text=b"0" * 101)["status"], tool.TAG_LENGTH)
        self.assertEqual(run(kind="ratio", text=b"0" * 100, scaled=1)["status"], OK)

    def test_word_7_bound_inclusive(self):
        self.assertEqual(run(kind="ratio", text=b"1", scaled=ONE)["changes"], ((tool.RATIO_AT, ONE),))
        self.assertEqual(run(kind="ratio", text=b"1", scaled=ONE + 1)["changes"], ())


class Params(unittest.TestCase):
    FULL = dict(w_given=1, w=5, low=b"1", low_value=4, high=b"2", high_value=9)

    def view(self, *steps, **fields):
        got = run(kind="params", steps=steps, **fields)
        return got["statuses"], got["params"]

    def test_row_order(self):
        self.assertEqual(self.view(tool.Step(**self.FULL)), ((OK,), ((2, 1, 5, 4, 9),)))

    def test_refused_pair_leaves_a_zero_row(self):
        statuses, rows = self.view(tool.Step(w_given=1, w=5, low=b"1", low_value=5, high=b"2", high_value=4))
        self.assertEqual(statuses, (tool.TAG_NESTED,))
        self.assertEqual(rows[0][1], 0)
        self.assertEqual(rows[0][3:], (0, 0))

    def test_zero_high_means_no_limit(self):
        self.assertEqual(self.view(tool.Step(low=b"1", low_value=5, high=b"2", high_value=0))[0], (OK,))

    def test_w_zero_clears_the_flag_and_keeps_the_word(self):
        got = HARNESS.run(tool.Case("t", kind="params", rows=tool.indexed(ONE, ONE), steps=(tool.Step(w_given=1, w=5), tool.Step(w_given=1, w=0))))
        self.assertEqual(got["params"], ((2, 0, 5, 0, 0),))

    def test_absent_fields_keep_stored_words(self):
        rows = self.view(tool.Step(**self.FULL), tool.Step(w_given=1, w=6))[1]
        self.assertEqual(rows, ((2, 1, 6, 4, 9),))

    def test_amount_gate_runs_after_both_texts(self):
        got = run(kind="params", steps=(tool.Step(w_given=1, w=CAP, low=b"1", low_value=1),))
        self.assertEqual(got["events"], ("price", "price"))
        self.assertEqual(got["statuses"], (tool.TAG_NUMBER,))

    def test_token_gates(self):
        self.assertEqual(self.view(tool.Step(token=6))[0], (tool.TAG_TOKEN,))
        self.assertEqual(self.view(tool.Step(token=3))[0], (tool.TAG_NESTED,))


class Controls(unittest.TestCase):
    def test_hash_is_checked(self):
        with self.assertRaises((tool.EvidenceError, OSError)):
            tool.load_image(ROOT / "work" / "does-not-exist")
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_unmodelled_status_is_seen(self):
        case = tool.Case("t", rows=tool.indexed(ONE, ONE))
        self.assertFalse(tool.same(case, HARNESS.run(case), dict(tool.spec_for(case), status=tool.TAG_NESTED)))

    def test_wrong_rule_is_seen(self):
        case = tool.Case("t", flag=0, rows=tool.indexed(ONE // 3, ONE), users=one_user(1, 1))
        want = tool.spec_for(case)
        floor = dict(want, users=((tool.key_of(1), ((2, (0x71, 0, 0x72, 1)),)),))
        self.assertFalse(tool.same(case, HARNESS.run(case), floor))

    def test_arm_flag_inverse(self):
        case = tool.Case("t", flag=0, rows=tool.indexed(ONE // 3, ONE // 3), users=one_user(1, 1))
        self.assertTrue(killed(flip(WORD_17_FLAG_MASK), case))

    def test_round_up_step(self):
        case = tool.Case("t", flag=0, rows=tool.indexed(ONE // 3, ONE), users=one_user(1, 1))
        at = tool.PLAN + bytes(IMAGE.blob[IMAGE.offset(tool.PLAN):IMAGE.offset(tool.PLAN) + 0x700]).index(PLAN_ROUND_SET)
        self.assertTrue(killed(flip(at + 1), case))

    def test_index_pick(self):
        case = tool.Case("t", flag=0, rows=tool.indexed(ONE // 3, 5 * ONE), users=one_user(3, 3))
        self.assertTrue(killed(flip(PLAN_INDEX_PICK + 2), case))

    def test_params_compare(self):
        case = tool.Case("t", kind="params", rows=tool.indexed(ONE, ONE), steps=(tool.Step(low=b"1", low_value=5, high=b"2", high_value=4),))
        self.assertTrue(killed(flip(PARAMS_ORDER + 2), case))

    def test_word_7_bound(self):
        case = tool.Case("t", kind="ratio", rows=tool.indexed(ONE, ONE), text=b"1", scaled=ONE + 1)
        self.assertTrue(killed(flip(WORD_7_BOUND), case))

    def test_row_gate_stale_key(self):
        case = tool.Case("t", rows=((2, tool.base_row()),), token=2)
        self.assertTrue(killed(flip(ROW_GATE_FOUND), case))


class Packet(unittest.TestCase):
    def test_folder_is_the_generated_set(self):
        names = sorted(path.name for path in FOLDER.iterdir())
        self.assertEqual(names, sorted(set(FILES) | {"README.md", "MANIFEST.sha256", "mutations.tsv"}))

    def test_generated_files_match(self):
        for name, text in FILES.items():
            if name == "evidence.json":
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_mutation_count_matches_summary(self):
        summary = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))["mutations"]
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        self.assertEqual(summary["total"], len(lines))
        self.assertEqual(summary["survived"], sum(1 for line in lines if line.split("\t")[2] == "survived"))

    def test_every_survivor_is_classified(self):
        lines = (FOLDER / "mutations.tsv").read_text(encoding="ascii").splitlines()[1:]
        self.assertFalse([line for line in lines if line.split("\t")[2] == "survived" and line.split("\t")[3] == tool.UNCLASSIFIED])


if __name__ == "__main__":
    unittest.main()
