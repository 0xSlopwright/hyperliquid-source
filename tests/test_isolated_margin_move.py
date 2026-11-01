"""Tests for tools/isolated_margin_move.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-isolated-margin-move-94"
spec_ = importlib.util.spec_from_file_location("isolated_margin_move", ROOT / "tools" / "isolated_margin_move.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["isolated_margin_move"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
HIGH = tool.HIGH
USER_A, USER_B = tool.USER_A, tool.USER_B
holder = tool.holder
CROSS_KIND = ((0, 20, 7),)
STRICT_KIND = ((2, 20, 7),)


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


def move(**fields):
    base = dict(entry="move", users=(holder(),), perps=CROSS_KIND, opens=((0, 1000),))
    base.update(fields)
    return run(Case("t", **base))


def top(**fields):
    base = dict(entry="topup", users=(holder(rows=((0, 1, 20, 1000, 1000),),),), perps=STRICT_KIND, prices=(100,), opens=((0, 1000),))
    base.update(fields)
    return run(Case("t", **base))


def update(**fields):
    base = dict(entry="update", wire=("perp", 0), users=(holder(),), perps=CROSS_KIND, opens=((0, 1000),), delta=1000, dexes=2)
    base.update(fields)
    return run(Case("t", **base))


def wire(**fields):
    base = dict(entry="wire", wire=("perp", 0), users=(holder(rows=((0, 1, 20, 1000, 1000),),),), perps=STRICT_KIND, prices=(100,), opens=((0, 1000),))
    base.update(fields)
    return run(Case("t", **base))


def margin(got, asset=0):
    data = dict(got["state"]["rows"])[asset]
    return struct.unpack_from("<q", data, 8)[0]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Move(unittest.TestCase):
    def test_increase_moves_both_words(self):
        got = move(delta=1000)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual((got["state"]["account"], margin(got)), (49000, 8000))

    def test_reduction_moves_both_words_after_the_check(self):
        got = move(delta=(1 << 64) - 1000)
        self.assertEqual((got["state"]["account"], margin(got)), (51000, 6000))
        self.assertEqual(got["events"][1][:4], ("check", 0, 51000, 6000))

    def test_increase_has_no_check(self):
        self.assertEqual([event[0] for event in move(delta=1, check=TOP)["events"]], ["available"])

    def test_negative_check_refuses_and_keeps_words(self):
        got = move(delta=TOP, check=TOP)
        self.assertEqual(got["result"], ("error", tool.TAG_REDUCE))
        self.assertEqual((got["state"]["account"], margin(got)), (50000, 7000))

    def test_check_zero_admits(self):
        self.assertEqual(move(delta=TOP, check=0)["result"], ("ok",))

    def test_unknown_user(self):
        self.assertEqual(move(users=())["result"], ("error", tool.TAG_USER))

    def test_zero_delta(self):
        self.assertEqual(move(delta=0)["result"], ("error", tool.TAG_ZERO))

    def test_unknown_user_before_zero(self):
        self.assertEqual(move(users=(), delta=0)["result"], ("error", tool.TAG_USER))

    def test_strict_refuses_reduction_only(self):
        self.assertEqual(move(delta=TOP, perps=STRICT_KIND)["result"], ("error", tool.TAG_STRICT_REMOVE))
        self.assertEqual(move(delta=1, perps=STRICT_KIND)["result"], ("ok",))

    def test_available_edge(self):
        self.assertEqual(move(delta=500, available=500)["result"], ("ok",))
        self.assertEqual(move(delta=501, available=500)["result"], ("error", tool.TAG_INCREASE))

    def test_available_compare_is_signed(self):
        self.assertEqual(move(delta=1, available=TOP)["result"], ("error", tool.TAG_INCREASE))
        self.assertEqual(move(delta=TOP, available=TOP)["result"], ("ok",))

    def test_refused_move_still_adds_the_touched_user(self):
        got = move(users=(holder(rows=((0, 0, 5, 7000, 1000),),),))
        self.assertEqual(got["result"], ("error", tool.TAG_NOT_ISOLATED))
        self.assertEqual(got["state"]["touched"], (USER_A,))

    def test_early_refusal_leaves_the_touched_set(self):
        self.assertEqual(move(delta=0)["state"]["touched"], ())

    def test_missing_row_is_inserted_then_empty(self):
        got = move(users=(holder(rows=(), count=0),), opens=())
        self.assertEqual(got["result"], ("error", tool.TAG_EMPTY))
        self.assertEqual(len(got["state"]["rows"]), 1)
        self.assertEqual(got["state"]["opens"], ((0, 0),))

    def test_new_row_uses_the_default_row(self):
        got = move(users=(holder(rows=(), count=0),), default=(0, 20), opens=())
        self.assertEqual(struct.unpack_from("<II", dict(got["state"]["rows"])[0]), (0, 20))

    def test_mode_must_equal_one(self):
        for mode in (0, 2, 3):
            got = move(users=(holder(rows=((0, mode, 5, 7000, 1000),),),))
            self.assertEqual(got["result"], ("error", tool.TAG_NOT_ISOLATED), mode)

    def test_margin_add_overflow(self):
        got = move(users=(holder(rows=((0, 1, 5, (1 << 63) - 10, 1000),),),), delta=10)
        self.assertEqual(got["result"], ("error", tool.TAG_ADD))

    def test_account_sub_overflow(self):
        got = move(users=(holder(account=-(1 << 63) + 9),), delta=10)
        self.assertEqual(got["result"], ("error", tool.TAG_SUB))
        self.assertEqual(got["state"]["account"], -(1 << 63) + 9)

    def test_account_may_go_below_zero(self):
        self.assertEqual(move(users=(holder(account=5),), delta=10)["state"]["account"], -5)

    def test_smallest_size_panics_after_writing(self):
        got = move(users=(holder(rows=((0, 1, 5, 7000, -(1 << 63)),),),))
        self.assertEqual(got["result"], ("panic",))
        self.assertEqual(margin(got), 7001)

    def test_open_word_round_trip(self):
        self.assertEqual(move()["state"]["opens"], ((0, 1000),))

    def test_open_word_saturates(self):
        got = move(opens=((0, -(1 << 63) + 5),))
        self.assertEqual(got["state"]["opens"], ((0, -(1 << 63) + 1000),))
        self.assertEqual([event for event in got["events"] if event[0] == "recorded"], [("recorded", tool.LOC_OPEN_SUB)])

    def test_asset_of_another_dex_panics(self):
        self.assertEqual(move(asset=10000)["result"], ("panic",))

    def test_local_past_the_list_panics(self):
        self.assertEqual(move(asset=1)["result"], ("panic",))


class TopUp(unittest.TestCase):
    def test_long_at_level_one_needs_nothing(self):
        got = top(level=1.0)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(margin(got), 1000)

    def test_negative_margin_at_level_one_goes_to_zero(self):
        self.assertEqual(margin(top(users=(holder(rows=((0, 1, 20, -500, 1000),),),), level=1.0)), 0)

    def test_level_half_needs_double(self):
        got = top(level=0.5)
        self.assertEqual(margin(got), 100000)
        self.assertEqual(got["state"]["account"], 50000 - 99000)

    def test_short_position(self):
        got = top(users=(holder(rows=((0, 1, 20, 150000, -1000),),),), level=0.75)
        self.assertEqual(margin(got), 233333)

    def test_level_edges(self):
        self.assertEqual(top(level=0.49999999999999994)["result"], ("error", tool.TAG_LEVERAGE))
        self.assertEqual(top(level=1.0000000000000002)["result"], ("error", tool.TAG_LEVERAGE))
        self.assertEqual(top(level=0.5)["result"], ("ok",))

    def test_level_gate_runs_before_the_kind(self):
        self.assertEqual(top(level=2.0, perps=CROSS_KIND)["result"], ("error", tool.TAG_LEVERAGE))

    def test_not_strict(self):
        for kind in (0, 1, 3):
            self.assertEqual(top(perps=((kind, 20, 7),))["result"], ("error", tool.TAG_NOT_STRICT), kind)

    def test_no_user_or_row_is_ok(self):
        self.assertEqual(top(users=())["result"], ("ok",))
        self.assertEqual(top(users=(holder(rows=(), count=0),))["result"], ("ok",))

    def test_low_bit_of_the_mode_word(self):
        got = top(users=(holder(rows=((0, 3, 20, 1000, 1000),),),), level=0.5)
        self.assertEqual(got["result"], ("error", tool.TAG_NOT_ISOLATED))
        self.assertEqual(top(users=(holder(rows=((0, 2, 20, 1000, 1000),),),), level=0.5)["result"], ("ok",))

    def test_reciprocal_differs_from_a_divide_down(self):
        got = top(users=(holder(rows=((0, 1, 20, 0, 39),),),), prices=(1,), level=0.65)
        self.assertEqual(int(39 / 0.65), 60)
        self.assertEqual(margin(got), 20)

    def test_reciprocal_differs_from_a_divide_up(self):
        got = top(users=(holder(rows=((0, 1, 20, 0, 33),),),), prices=(1,), level=0.55)
        self.assertEqual(int(33 / 0.55), 59)
        self.assertEqual(margin(got), 27)

    def test_negative_price_panics(self):
        self.assertEqual(top(prices=((1 << 64) - 5,))["result"], ("panic",))

    def test_notional_overflow_panics_even_on_a_cross_row(self):
        self.assertEqual(top(users=(holder(rows=((0, 0, 20, 1000, 1 << 62),),),), prices=(4,))["result"], ("panic",))

    def test_smallest_notional_panics_on_isolated_only(self):
        self.assertEqual(top(users=(holder(rows=((0, 1, 20, 0, -(1 << 62)),),),), prices=(2,))["result"], ("panic",))
        self.assertEqual(top(users=(holder(rows=((0, 0, 20, 0, -(1 << 62)),),),), prices=(2,))["result"], ("ok",))

    def test_sub_overflow_tag(self):
        got = top(users=(holder(rows=((0, 1, 20, -(1 << 63), 1 << 61),),),), prices=(2,), level=0.5)
        self.assertEqual(got["result"], ("error", tool.TAG_SUB))

    def test_equity_saturation_records(self):
        got = top(users=(holder(rows=((0, 1, 20, (1 << 63) - 1, 1 << 62),),),), prices=(1,), level=0.5)
        self.assertEqual(got["result"], ("ok",))
        self.assertIn(("recorded", tool.LOC_SUB), got["events"])

    def test_core_refusal_passes(self):
        self.assertEqual(top(available=5, level=0.5)["result"], ("error", tool.TAG_INCREASE))


class Handlers(unittest.TestCase):
    def test_all_copies_direct(self):
        for copy in range(3):
            self.assertEqual(update(copy=copy)["result"], ("ok",))

    def test_spot_payload(self):
        for copy in range(3):
            self.assertEqual(update(copy=copy, wire=("spot", 0xBEEF))["result"], ("error", tool.TAG_SPOT, 0xBEEF))

    def test_cap_is_exclusive(self):
        self.assertEqual(update(delta=tool.CAP)["result"], ("error", tool.TAG_NUMBER, tool.CAP))
        self.assertEqual(update(delta=(1 << 64) - tool.CAP)["result"], ("error", tool.TAG_NUMBER, tool.CAP))
        self.assertEqual(update(delta=tool.CAP - 1, users=(holder(account=1 << 62),))["result"], ("ok",))

    def test_smallest_word_reports_itself(self):
        self.assertEqual(update(delta=HIGH)["result"], ("error", tool.TAG_NUMBER, HIGH))

    def test_routed_refusal_is_dropped(self):
        second = dict(wire=("perp", 10001), asset=10001, dex_id=1, users=(holder(rows=((10001, 1, 5, 7000, 1000),),),), perps=((0, 20, 7), (0, 20, 7)), opens=())
        got = update(klass=2, byte=1, post=tool.REFUSAL, pre=tool.REFUSAL, **second)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual([event[1] for event in got["events"] if event[0] == "settle dropped"], [tool.REFUSAL, tool.REFUSAL])

    def test_byte_two_skips_the_post_step(self):
        second = dict(wire=("perp", 10001), asset=10001, dex_id=1, users=(holder(rows=((10001, 1, 5, 7000, 1000),),),), perps=((0, 20, 7), (0, 20, 7)), opens=())
        self.assertEqual(sum(1 for event in update(klass=2, byte=2, **second)["events"] if event[0] == "settle"), 1)

    def test_no_set_gives_operations_tag(self):
        for copy in range(3):
            got = update(copy=copy, klass=3, sets=(0, 0))
            self.assertEqual(got["result"], ("error", tool.TAG_OPERATIONS))
            self.assertEqual(got["state"]["total"], 9)

    def test_routed_counters(self):
        got = update(klass=3, track=TOP, total=4)
        self.assertEqual((got["state"]["track"], got["state"]["total"]), (TOP, 5))

    def test_only_class_four_finishes(self):
        self.assertEqual(sum(1 for event in update(klass=4)["events"] if event[0] == "finish"), 1)
        self.assertEqual(sum(1 for event in update(klass=5)["events"] if event[0] == "finish"), 0)

    def test_flag_choice_by_class(self):
        self.assertNotIn(("tracker",), update(klass=4, flag0=1)["events"])
        self.assertIn(("tracker",), update(klass=4, flag1=1)["events"])
        self.assertNotIn(("tracker",), update(klass=3, flag1=1)["events"])
        self.assertIn(("tracker",), update(klass=3, flag0=1)["events"])

    def test_counter_top_loses_one(self):
        self.assertEqual(update(counter=TOP)["state"]["counter"], TOP - 1)

    def test_text_levels(self):
        for copy in range(3):
            self.assertEqual(wire(copy=copy, text=b"0.75")["result"], ("ok",))
            self.assertEqual(wire(copy=copy, text=b"2")["result"], ("error", tool.TAG_LEVERAGE))

    def test_length_edge(self):
        self.assertEqual(wire(text=tool.LONG)["result"], ("ok",))
        self.assertEqual(wire(length=101)["result"], ("error", tool.TAG_LENGTH, 0))

    def test_length_runs_after_the_id(self):
        self.assertEqual(wire(wire=("spot", 5), length=500)["result"], ("error", tool.TAG_SPOT, 5))

    def test_float_failure_tag(self):
        self.assertEqual(wire(nofloat=1)["result"], ("error", tool.TAG_FLOAT))

    def test_bad_text_tag(self):
        self.assertEqual(wire(text=b"abc")["result"], ("error", 0xAC))


class Controls(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "bad"
            data = bytearray(IMAGE.blob)
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_nobits_has_no_file_bytes(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + 8)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x100)

    def test_function_start_is_exact(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.CORE + 1)

    def test_level_floor_edit(self):
        self.assertTrue(killed(flip(0x370957A, 1), Case("t", entry="topup", users=(holder(),), perps=STRICT_KIND, level=0.75, opens=((0, 1000),))))

    def test_strict_byte_edit(self):
        self.assertTrue(killed(flip(0x37095D5 + 4, 3), Case("t", entry="topup", users=(), perps=STRICT_KIND)))

    def test_core_compare_edit(self):
        self.assertTrue(killed(flip(0x37071B7), Case("t", entry="move", users=(holder(),), perps=CROSS_KIND, delta=500, available=500, opens=((0, 1000),))))

    def test_strict_remove_tag_edit(self):
        self.assertTrue(killed(flip(0x37071A1 + 3), Case("t", entry="move", users=(holder(),), perps=STRICT_KIND, delta=TOP)))

    def test_cap_edit(self):
        self.assertTrue(killed(flip(0x21E2C2B + 9), Case("t", entry="update", wire=("perp", 0), users=(holder(),), perps=CROSS_KIND, delta=tool.CAP, opens=((0, 1000),))))

    def test_operations_tag_edit(self):
        self.assertTrue(killed(flip(0x272222F + 3), Case("t", entry="update", klass=3, sets=(0, 0), wire=("perp", 0), users=(holder(),), perps=CROSS_KIND, opens=((0, 1000),))))

    def test_finish_class_edit(self):
        self.assertTrue(killed(flip(0x272227B + 4), Case("t", entry="update", klass=4, wire=("perp", 0), users=(holder(),), perps=CROSS_KIND, opens=((0, 1000),))))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.USER_HASH)
        with self.assertRaises(tool.Halt):
            harness.run(Case("t", entry="move", users=(holder(),), perps=CROSS_KIND, opens=((0, 1000),)))

    def test_changed_constant_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x20A940)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))

    def test_changed_tag_text_is_noticed(self):
        data = bytearray(IMAGE.blob)
        arm = tool.TEXT_TABLE + struct.unpack_from("<i", data, IMAGE.offset(tool.TEXT_TABLE) + 4 * tool.TAG_NOT_STRICT)[0]
        start = IMAGE.offset(arm)
        at = bytes(data[start:start + 40]).find(b"\x48\x8d\x35")
        target = arm + at + 7 + struct.unpack_from("<i", data, start + at + 3)[0]
        data[IMAGE.offset(target)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.tag_rows(tool.Image(bytes(data)))


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

    def test_callers_of_the_move(self):
        rows = [row for row in RESULT["callers"] if row[0] == "move"]
        self.assertEqual(sorted({row[3] for row in rows}), ["0x2722010", "0x3709560", "0x4d27c60", "0x4d28400"])
        self.assertEqual(len(rows), 10)

    def test_callers_of_the_top_up(self):
        rows = [row for row in RESULT["callers"] if row[0] == "top up"]
        self.assertEqual(sorted(row[3] for row in rows), ["0x21e2ee0", "0x4c03ba0", "0x4c03eb0"])

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word + chr(47), data, name)


if __name__ == "__main__":
    unittest.main()
