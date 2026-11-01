"""Tests for tools/token_supply_summary.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-token-supply-summary-94"
spec_ = importlib.util.spec_from_file_location("token_supply_summary", ROOT / "tools" / "token_supply_summary.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["token_supply_summary"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
USER_A, USER_B, USER_C = tool.USER_A, tool.USER_B, tool.USER_C
ZERO, DEAD = tool.ZERO_USER, tool.DEAD_USER


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=20)
    FILES = tool.render(RESULT)


def run(case):
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case)), case.name
    return got


def summary(**fields):
    return run(Case("t", **fields))["result"]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Words(unittest.TestCase):
    def test_total_is_max_minus_fees(self):
        self.assertEqual(summary(maxima=((0, 1000),), fees=((0, 300),)), ("ok", (), 1000, 700, 700, 0))

    def test_fees_above_max_stop_at_zero(self):
        self.assertEqual(summary(maxima=((0, 100),), fees=((0, 300),)), ("ok", (), 100, 0, 0, 0))

    def test_burn_users_count(self):
        result = summary(maxima=((0, 1000),), rows=((ZERO, ((0, 10),)), (DEAD, ((0, 11),))))
        self.assertEqual(result, ("ok", ((ZERO, 10), (DEAD, 11)), 1000, 1000, 979, 0))

    def test_member_order_then_burn_then_link(self):
        rows = ((USER_B, ((2, 1),)), (USER_A, ((2, 2),)), (ZERO, ((2, 3),)), (DEAD, ((2, 4),)), (tool.link_user(2), ((2, 5),)))
        result = summary(token=2, maxima=((2, 100),), members=(USER_B, USER_A), links=(2,), rows=rows)
        self.assertEqual([row[0] for row in result[1]], [USER_A, USER_B, ZERO, DEAD, tool.link_user(2)])
        self.assertEqual(result[4], 85)

    def test_zero_balance_leaves_no_row(self):
        self.assertEqual(summary(members=(USER_A,))[1], ())

    def test_member_equal_to_a_burn_user_counts_twice(self):
        result = summary(maxima=((0, 100),), members=(DEAD,), rows=((DEAD, ((0, 10),)),))
        self.assertEqual(result[1], ((DEAD, 10), (DEAD, 10)))
        self.assertEqual(result[4], 80)

    def test_sum_above_total_stops_at_zero(self):
        self.assertEqual(summary(maxima=((0, 10),), members=(USER_A,), rows=((USER_A, ((0, 40),)),))[4], 0)

    def test_sum_overflow_is_add_error(self):
        self.assertEqual(summary(members=(USER_A, USER_B), rows=((USER_A, ((0, TOP),)), (USER_B, ((0, 1),)))), ("error", tool.TAG_ADD))

    def test_token_bound_panics(self):
        self.assertEqual(summary(token=4, count=4), ("panic",))

    def test_token_one_top_word_only(self):
        self.assertEqual(summary(token=1, maxima=((1, 1000),), fees=((1, 100),))[2:], (1000 + tool.BONUS, 900, 900, 0))

    def test_token_one_edge(self):
        self.assertEqual(summary(token=1, maxima=((1, TOP - tool.BONUS),))[2], TOP)
        self.assertEqual(summary(token=1, maxima=((1, TOP - tool.BONUS + 1),)), ("error", tool.TAG_ADD))

    def test_other_tokens_have_no_bonus(self):
        self.assertEqual(summary(token=2, maxima=((2, TOP),))[2], TOP)


class Native(unittest.TestCase):
    def test_three_staking_words_add(self):
        result = summary(token=2, native=2, maxima=((2, 1000),), members=(USER_A,), rows=((USER_A, ((2, 5),)),), staked=((USER_A, (1, 2, 3, 99)),))
        self.assertEqual(result[1], ((USER_A, 11),))

    def test_fourth_word_is_ignored(self):
        self.assertEqual(summary(token=2, native=2, members=(USER_A,), staked=((USER_A, (0, 0, 0, 99)),))[1], ())

    def test_other_token_reads_no_staking(self):
        got = run(Case("t", token=2, native=3, members=(USER_A,), staked=((USER_A, (1, 2, 3, 99)),)))
        self.assertNotIn("staking", [event[0] for event in got["events"]])

    def test_each_add_is_checked(self):
        for words, base in (((1, 0, 0, 0), TOP), ((1, 1, 0, 0), TOP - 1), ((1, 1, 1, 0), TOP - 2)):
            self.assertEqual(summary(token=2, native=2, members=(USER_A,), rows=((USER_A, ((2, base),)),), staked=((USER_A, words),)), ("error", tool.TAG_ADD))

    def test_reserve_leaves_the_free_word(self):
        self.assertEqual(summary(token=2, native=2, maxima=((2, 1000),), reserve=(1, 300))[3:], (1000, 700, 300))

    def test_reserve_above_free_records(self):
        got = run(Case("t", token=2, native=2, maxima=((2, 1000),), reserve=(1, 1001)))
        self.assertEqual(got["result"][3:], (1000, 0, 1001))
        self.assertIn(("recorded", tool.LOC_WEI_SUB), got["events"])

    def test_reserve_flag_clear(self):
        self.assertEqual(summary(token=2, native=2, maxima=((2, 1000),), reserve=(0, 300))[3:], (1000, 1000, 0))

    def test_reserve_needs_the_native_token(self):
        self.assertEqual(summary(token=2, native=3, maxima=((2, 1000),), reserve=(1, 300))[3:], (1000, 1000, 0))


class Links(unittest.TestCase):
    def test_absent_after_a_full_group(self):
        crowd = tuple(2 + tool.BUCKETS * index for index in range(1, 20))
        self.assertEqual(summary(token=2, crowd=crowd, rows=((tool.link_user(2), ((2, 25),)),))[1], ())

    def test_found_after_a_full_group(self):
        crowd = tuple(2 + tool.BUCKETS * index for index in range(1, 20))
        self.assertEqual(summary(token=2, crowd=crowd, links=(2,), rows=((tool.link_user(2), ((2, 25),)),))[1], ((tool.link_user(2), 25),))

    def test_user_shape(self):
        self.assertEqual(tool.link_user(0x0102), bytes.fromhex("32") + bytes(17) + bytes.fromhex("0102"))


class SetVote(unittest.TestCase):
    def test_remove_wins_over_add(self):
        self.assertEqual(run(Case("t", entry="modify", adds=(USER_A,), removes=(USER_A,)))["result"], ((),))

    def test_growth_and_shrink(self):
        many = tuple(bytes([index + 1]) * 20 for index in range(30))
        self.assertEqual(run(Case("t", entry="modify", adds=many, removes=many[:25]))["result"], (many[25:],))

    def test_arm_gate_order(self):
        users = tuple(index.to_bytes(4, "big") * 5 for index in range(1, tool.LIST_CAP + 2))
        for copy in range(3):
            self.assertEqual(run(Case("t", entry="arm", copy=copy, token=4, count=4, adds=users))["result"], ("error", tool.TAG_TOKEN, 4))
            self.assertEqual(run(Case("t", entry="arm", copy=copy, adds=users))["result"][:2], ("error", tool.TAG_LENGTH))
            self.assertEqual(run(Case("t", entry="arm", copy=copy, adds=users[:-1], fast=1))["result"], ("ok", ()))
            self.assertEqual(run(Case("t", entry="arm", copy=copy, removes=users))["result"], ("error", tool.TAG_LENGTH, 0x20))

    def test_arm_runs_the_body(self):
        for copy in range(3):
            self.assertEqual(run(Case("t", entry="arm", copy=copy, members=(USER_B,), adds=(USER_A,), removes=(USER_B,)))["result"], ("ok", (USER_A,)))


class Precompile(unittest.TestCase):
    def data(self, **fields):
        return run(Case("t", entry="precompile", data=tool.word_input(fields.get("token", 0)), **fields))["result"]

    def test_words_in_order(self):
        result = self.data(token=2, maxima=((2, 1000),), fees=((2, 100),), members=(USER_A,), rows=((USER_A, ((2, 40),)),))
        words = [int.from_bytes(result[1][index:index + 32], "big") for index in range(0, len(result[1]), 32)]
        self.assertEqual(words, [0x20, 1000, 900, 860, 0, 0xA0, 1, int.from_bytes(USER_A, "big"), 40])

    def test_gas_rule(self):
        limit = tool.BASE_GAS + 32 * tool.WORD_GAS + 224 * tool.WORD_GAS
        self.assertEqual(self.data(limit=limit)[0], "bytes")
        self.assertEqual(self.data(limit=limit)[2], limit)
        self.assertEqual(self.data(limit=limit - 1), ("halt",))

    def test_disabled_address_halts(self):
        self.assertEqual(self.data(blocked=(tool.PRECOMPILE_ADDRESS,)), ("halt",))

    def test_input_cap(self):
        self.assertEqual(run(Case("t", entry="precompile", data=bytes(2001)))["result"], ("halt",))
        self.assertEqual(run(Case("t", entry="precompile", data=bytes(2000), refuse=1))["result"][:2], ("text", b"Invalid input"))

    def test_token_bound_is_text(self):
        self.assertEqual(self.data(token=4)[1], b"status %d" % tool.TAG_TOKEN)


class Proposal(unittest.TestCase):
    def test_reads_the_free_word(self):
        for copy in range(3):
            got = run(Case("t", entry="proposal", copy=copy, native=2, maxima=((2, 1000),), fees=((2, 100),), members=(USER_A,), rows=((USER_A, ((2, 200),)),), reserve=(1, 50)))
            self.assertEqual([event for event in got["events"] if event[0] == "propose"][0][4], 650)

    def test_gate_order(self):
        for copy in range(3):
            self.assertEqual(run(Case("t", entry="proposal", copy=copy, chain=3))["result"], ("error", tool.TAG_TESTNET))
            self.assertEqual(run(Case("t", entry="proposal", copy=copy))["result"], ("error", tool.TAG_NATIVE))
            self.assertEqual(run(Case("t", entry="proposal", copy=copy, native=2, title=b"x" * 101))["result"], ("error", tool.TAG_LENGTH, 0))
            self.assertEqual(run(Case("t", entry="proposal", copy=copy, native=2, body=b"y" * 1001))["result"], ("error", tool.TAG_LENGTH, 0x18))

    def test_copy_b_uses_the_shifted_block(self):
        self.assertEqual(RESULT["copies"][1][1], "0x47ba820")
        self.assertEqual(run(Case("t", entry="proposal", copy=1, chain=3))["result"], ("error", tool.TAG_TESTNET))


class Controls(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            data = bytearray(IMAGE.blob)
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_has_no_file_bytes(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + 16)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_case_with_a_wrong_rule_fails(self):
        case = Case("t", maxima=((0, 7),))
        want = tool.spec_for(case)
        want["result"] = ("ok", (), 8, 7, 7, 0)
        self.assertFalse(tool.same(case, HARNESS.run(case), want))

    def test_bonus_constant_edit(self):
        self.assertTrue(killed(flip(0x375ED86 + 3), Case("t", token=1)))

    def test_bonus_bound_edit(self):
        self.assertTrue(killed(flip(0x375ED69 + 2), Case("t", token=1, maxima=((1, TOP - tool.BONUS),))))

    def test_bonus_token_edit(self):
        self.assertTrue(killed(flip(0x375ED63 + 3, 2), Case("t", token=1)))

    def test_link_tag_edit(self):
        self.assertTrue(killed(flip(0x375E7E5 + 7), Case("t", token=2, links=(2,), rows=((tool.link_user(2), ((2, 25),)),))))

    def test_fee_map_offset_edit(self):
        self.assertTrue(killed(flip(0x375E57F + 3, 8), Case("t", maxima=((0, 9),), fees=((0, 2),))))

    def test_reserve_offset_edit(self):
        self.assertTrue(killed(flip(0x375EDB9 + 2, 8), Case("t", token=2, native=2, maxima=((2, 9),), reserve=(0, 2))))

    def test_list_cap_edit(self):
        users = tuple(index.to_bytes(4, "big") * 5 for index in range(1, tool.LIST_CAP + 1))
        self.assertTrue(killed(flip(0x2356817 + 12 - 4), Case("t", entry="arm", adds=users, fast=1)))

    def test_input_cap_edit(self):
        self.assertTrue(killed(flip(0x3248F86 + 3), Case("t", entry="precompile", data=bytes(2001))))

    def test_base_gas_edit(self):
        self.assertTrue(killed(flip(0x3248FCD + 3), Case("t", entry="precompile", data=tool.word_input(0))))

    def test_output_gas_edit(self):
        self.assertTrue(killed(flip(0x32498AE + 1, 2), Case("t", entry="precompile", data=tool.word_input(0))))

    def test_title_cap_edit(self):
        self.assertTrue(killed(flip(0x1F68CEA + 3), Case("t", entry="proposal", native=2, title=b"x" * 101)))

    def test_body_cap_edit(self):
        self.assertTrue(killed(flip(0x1F68DF0 + 3), Case("t", entry="proposal", native=2, body=b"y" * 1000)))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.HASH)
        with self.assertRaises(tool.Halt):
            harness.run(Case("t", links=(0,)))

    def test_changed_constant_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x59963F)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))

    def test_changed_key_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x597CAA)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.field_rows(tool.Image(bytes(data)))


class Evidence(unittest.TestCase):
    def test_retained_files_match(self):
        names = sorted(path.name for path in FOLDER.iterdir() if path.name not in ("README.md", "MANIFEST.sha256", "mutations.tsv", "evidence.json"))
        for name in names:
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), FILES[name], name)

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual({line.split("  ", 1)[1] for line in lines}, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_counts(self):
        summary_ = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary_["sha256"], tool.SHA256)
        self.assertEqual(summary_["named_cases"], len(RESULT["cases"]))
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(summary_["mutations"]["total"], len(rows))
        self.assertEqual(summary_["mutations"]["killed"], sum(1 for row in rows if row.split("\t")[3] == "killed"))

    def test_every_reference_row_names_a_real_case(self):
        names = {case.name for case in RESULT["cases"]}
        for row in tool.REFERENCE:
            self.assertIn(row[3], names, row[0])

    def test_survivors_have_a_reason(self):
        for row in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            cells = row.split("\t")
            if cells[3] == "survived":
                self.assertNotEqual(cells[4], "unclassified", cells[1])

    def test_callers_are_the_four_read_here(self):
        rows = [row for row in RESULT["callers"] if row[0] == "summary"]
        self.assertEqual(sorted(row[3] for row in rows), ["0x1f68be0", "0x3248ea0", "0x47ba820", "0x47bac70"])

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word + chr(47), data, name)


if __name__ == "__main__":
    unittest.main()
