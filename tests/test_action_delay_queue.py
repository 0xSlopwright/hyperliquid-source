"""Tests for tools/action_delay_queue.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-action-delay-queue-94"
spec_ = importlib.util.spec_from_file_location("action_delay_queue", ROOT / "tools" / "action_delay_queue.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["action_delay_queue"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
enq = tool.enq
later = tool.later
NOW_NANOS = tool.time_nanos(tool.NOW)


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    tool.Parsed.harness = tool.Harness(IMAGE)
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=20)
    FILES = tool.render(RESULT)


def run(case):
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(HARNESS, case)), case.name
    return got


def delay(mode, kind, value):
    return tool.to_float(run(Case("t", steps=(("curve", mode, kind, tool.to_bits(value)),)))["results"][0][1])


def one(*steps, **fields):
    return run(Case("t", steps=steps, **fields))


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Curve(unittest.TestCase):
    def test_floor_below_the_ramp(self):
        self.assertEqual(delay(0, 6, 0.0003), 0.76 * 0.65)
        self.assertEqual(delay(0, 6, 0.0), 0.76 * 0.65)

    def test_top_above_the_ramp(self):
        self.assertEqual(delay(0, 6, 0.0025), (1.3 + 0.76) * 0.65)
        self.assertEqual(delay(0, 6, 1.0), (1.3 + 0.76) * 0.65)

    def test_linear_not_power(self):
        value = delay(0, 6, 0.002)
        self.assertEqual(value, (tool.fma(0.002, 10000.0, -4.0) / 20.0 * 1.3 + 0.76) * 0.65)
        self.assertLess(value, 1.3)
        self.assertNotEqual(value, (1.3 + 0.76) * 0.65)

    def test_short_factor_for_frontend_and_broadcaster_ids(self):
        for kind in (10000, 109999, 100000000, 0xFFFFFFFF):
            self.assertEqual(delay(0, kind, 0.0), 0.76 * 0.2)
        for kind in (9999, 110000, 99999999):
            self.assertEqual(delay(0, kind, 0.0), 0.76 * 0.65)

    def test_chain_byte_two_lists(self):
        self.assertEqual(delay(2, 3, 1.0), (1.8 + 0.76) * 0.65)
        self.assertEqual(delay(2, 0, 1.0), (1.8 + 0.76) * 0.65)
        self.assertEqual(delay(2, 1, 1.0), (1.3 + 0.76) * 0.65)
        self.assertEqual(delay(2, 11137, 0.0), 0.76 * 0.65)

    def test_chain_byte_three_lists(self):
        for kind in (0, 1, 10142, 10151, 5):
            self.assertEqual(delay(3, kind, 1.0), (1.8 + 0.76) * 0.65, kind)
        self.assertEqual(delay(3, 3, 1.0), (1.3 + 0.76) * 0.65)

    def test_chain_byte_below_two_has_no_lists(self):
        for mode in (0, 1):
            self.assertEqual(delay(mode, 0, 1.0), (1.3 + 0.76) * 0.65)

    def test_listed_kind_is_never_short(self):
        self.assertEqual(delay(3, 10142, 0.0), 0.76 * 0.65)

    def test_infinity_skips_the_clamp(self):
        self.assertEqual(delay(0, 6, float("inf")), float("inf"))

    def test_nan_and_negative_infinity_panic(self):
        for bits in (0x7FF8000000000000, tool.to_bits(-float("inf"))):
            self.assertEqual(run(Case("t", steps=(("curve", 0, 6, bits),)))["results"], [("panic",)])

    def test_negative_input_floors(self):
        self.assertEqual(delay(0, 6, -1.0), 0.76 * 0.65)


class Host(unittest.TestCase):
    def test_zero_delay_runs_now_and_counts(self):
        got = one(enq())
        self.assertEqual(got["results"], [("ran",)])
        self.assertEqual(got["state"]["s50"], 4)
        self.assertEqual(got["state"]["events"], [("run", 4, 1)])

    def test_flag_runs_now_without_counting(self):
        got = one(enq(), flag=1)
        self.assertEqual(got["state"]["s50"], 3)

    def test_queue_row(self):
        got = one(enq(kind="four", byte=1), sopt=(1, 9))
        self.assertEqual(got["results"], [("queued", 7, 9, NOW_NANOS + 4 * 10 ** 9)])
        at, rows = got["state"]["queue"][0]
        self.assertEqual(at, NOW_NANOS + 4 * 10 ** 9)
        self.assertEqual(rows[0][2:6], (7, 9, tool.USER_A, 1))
        self.assertEqual(got["state"]["total"], 1)
        self.assertEqual(got["state"]["users"], {tool.USER_A: 1})

    def test_same_time_shares_a_key(self):
        got = one(enq(kind="four"), enq(kind="four", user=tool.USER_B))
        self.assertEqual(len(got["state"]["queue"]), 1)
        self.assertEqual(len(got["state"]["queue"][0][1]), 2)

    def test_larger_of_base_and_set(self):
        vty = ((42, tool.to_bits(1.0)),)
        self.assertEqual(one(enq(kind="arm", base=7.0, set1=(42,)), vty=vty)["results"][0][3], NOW_NANOS + 7 * 10 ** 9)
        high = (1.3 + 0.76) * 0.65
        self.assertEqual(one(enq(kind="arm", base=0.5, set1=(42,)), vty=vty, chain=0)["results"][0][3], NOW_NANOS + int(high * 1e9))

    def test_missing_tracker_counts_as_a_thousandth(self):
        self.assertEqual(one(enq(kind="arm", set1=(1,)))["results"][0][3], NOW_NANOS + 1000000)

    def test_classifier_error_defaults_to_a_fifth(self):
        self.assertEqual(one(enq(kind="arm", error=True))["results"][0][3], NOW_NANOS + 200000000)

    def test_total_cap_and_max_zero(self):
        self.assertEqual(one(enq(kind="four"), n_total=5, max_n=5)["results"], [("refused", tool.TAG_TOTAL)])
        self.assertEqual(one(enq(kind="four"), max_n=0)["results"], [("refused", tool.TAG_TOTAL)])
        self.assertEqual(one(enq(kind="four"), n_total=4, max_n=5)["results"][0][0], "queued")

    def test_user_cap(self):
        self.assertEqual(one(enq(kind="four"), users=((tool.USER_A, 100),))["results"], [("refused", tool.TAG_USER)])
        got = one(enq(kind="four"), users=((tool.USER_A, 99),))
        self.assertEqual(got["state"]["users"], {tool.USER_A: 100})

    def test_expiry_compare_is_inclusive(self):
        limit = (NOW_NANOS + 4 * 10 ** 9) // 10 ** 6
        self.assertEqual(one(enq(kind="four", expires=limit))["results"][0][0], "queued")
        got = one(enq(kind="four", expires=limit - 1))
        self.assertEqual(got["results"], [("refused", tool.TAG_EXPIRED)])
        self.assertEqual(got["state"]["row"], TOP)

    def test_refused_row_stays_in_the_user_tree(self):
        got = one(enq(kind="four", expires=1))
        self.assertEqual(got["state"]["users"], {tool.USER_A: 0})

    def test_scale(self):
        self.assertEqual(one(enq(kind="four"), scale=0.5)["results"][0][3], NOW_NANOS + 2 * 10 ** 9)
        self.assertEqual(one(enq(kind="four"), scale=0.0)["results"], [("ran",)])
        self.assertEqual(one(enq(kind="four"), scale=-1.0)["results"], [("panic",)])

    def test_infinite_delay_lands_on_now(self):
        got = one(enq(kind="arm", set1=(5,)), vty=((5, tool.to_bits(float("inf"))),))
        self.assertEqual(got["results"][0][3], NOW_NANOS)

    def test_wrap_b_notifies(self):
        self.assertEqual(one(enq(), wrap=1)["state"]["events"], [("run", 4, 1), ("notify", 4, 0)])

    def test_wrap_c_is_silent(self):
        self.assertEqual(one(enq(), wrap=2)["state"]["events"], [("run", 4, 1)])


class Window(unittest.TestCase):
    def widths(self):
        seconds = tool.window_seconds(tool.NOW)
        odd = next(width for width in range(1, 100000) if seconds // width & 1)
        even = next(width for width in range(1, 100000) if not seconds // width & 1)
        return odd, even

    def test_odd_runs_now(self):
        odd, _ = self.widths()
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), flag=1, windows=((5, odd),))["results"], [("ran",)])

    def test_even_delays(self):
        _, even = self.widths()
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), flag=1, windows=((5, even),))["results"][0][0], "queued")

    def test_zero_width_delays(self):
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), flag=1, windows=((5, 0),))["results"][0][0], "queued")

    def test_second_set_counts(self):
        _, even = self.widths()
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,), set2=(7,)), flag=1, windows=((7, even),))["results"][0][0], "queued")

    def test_no_width_passes(self):
        _, even = self.widths()
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), flag=1, windows=((6, even),))["results"], [("ran",)])

    def test_enabled_tag_never_skips(self):
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), flag=1)["results"][0][0], "queued")

    def test_flag_clear_skips_the_gate(self):
        odd, _ = self.widths()
        self.assertEqual(one(enq(kind="arm", base=1.0, set1=(5,)), windows=((5, odd),))["results"][0][0], "queued")


class Release(unittest.TestCase):
    def test_key_equal_to_now_stays(self):
        got = one(enq(kind="arm", base=2.0), ("rel", later(2)))
        self.assertEqual(got["results"][1], ("released", ()))
        self.assertEqual(got["state"]["total"], 1)

    def test_key_below_now_leaves(self):
        got = one(enq(kind="arm", base=2.0), ("rel", later(2, 1)))
        self.assertEqual(len(got["results"][1][1]), 1)
        self.assertEqual((got["state"]["total"], got["state"]["users"], got["state"]["queue"]), (0, {}, []))

    def test_order_is_key_then_arrival(self):
        got = one(enq(kind="arm", base=4.0), enq(kind="arm", base=2.0, user=tool.USER_B), enq(kind="arm", base=4.0, user=tool.USER_C), ("rel", later(9)))
        self.assertEqual([row[4] for row in got["results"][3][1]], [tool.USER_B, tool.USER_A, tool.USER_C])

    def test_wipe_clears_three_fields(self):
        got = one(enq(kind="four"), ("wipe",))
        self.assertEqual((got["state"]["total"], got["state"]["users"], got["state"]["queue"]), (0, {}, []))
        self.assertEqual(HARNESS.drops, 1)

    def test_missing_user_row_is_skipped(self):
        got = one(enq(kind="four"), ("rename", tool.USER_A, tool.USER_B), ("rel", later(9)))
        self.assertEqual(got["state"]["users"], {tool.USER_B: 1})


class Votes(unittest.TestCase):
    def test_max_bounds(self):
        for copy in range(3):
            for value, want in ((99, ("error", tool.TAG_MAX)), (100, ("ok",)), (300000, ("ok",)), (300001, ("error", tool.TAG_MAX)), (tool.CAP, ("error", tool.TAG_NUMBER, tool.CAP))):
                self.assertEqual(run(Case("t", copy=copy, chain=2, steps=(("vote", tool.WORD_MAX, value),)))["results"], [want])

    def test_testnet_only_words(self):
        for copy in range(3):
            for step in (("vote", tool.WORD_MAX, 100), ("vote", tool.WORD_CLEAR), ("vote", tool.WORD_SCALE, b"1")):
                self.assertEqual(run(Case("t", copy=copy, chain=3, steps=(step,)))["results"], [("error", tool.TAG_TESTNET)])

    def test_clear_leaves_tag_zero(self):
        got = run(Case("t", copy=0, chain=2, windows=((5, 7),), steps=(("vote", tool.WORD_CLEAR),)))
        self.assertEqual(got["state"]["window flag"], 0)

    def test_scale_bounds(self):
        for text, want in ((b"2", ("ok",)), (b"0", ("error", tool.TAG_NUMBER)), (b"2.0000000001", ("error", tool.TAG_NUMBER)), (b"1" * 101, ("error", tool.TAG_LENGTH))):
            self.assertEqual(run(Case("t", copy=0, chain=2, steps=(("vote", tool.WORD_SCALE, text),)))["results"], [want])

    def test_bounds_vote_runs_on_every_chain(self):
        for copy in range(3):
            got = run(Case("t", copy=copy, chain=3, steps=(("vote", tool.WORD_BOUNDS, b"0.01", b"1", b"0.01"),)))
            self.assertEqual(got["state"]["low"], tool.to_bits(0.01))
            self.assertEqual(got["state"]["step"], tool.to_bits(0.01))

    def test_bounds_refused(self):
        for low, high, step in ((b"0.009", b"1", b"0.01"), (b"0.6", b"0.5", b"0.01"), (b"0.5", b"1.1", b"0.01"), (b"0.5", b"1", b"0"), (b"0.5", b"1", b"0.02")):
            self.assertEqual(run(Case("t", copy=0, steps=(("vote", tool.WORD_BOUNDS, low, high, step),)))["results"], [("error", tool.TAG_INPUT)])


class Controls(unittest.TestCase):
    def test_short_factor_edit_fails(self):
        self.assertTrue(killed(flip(0x392FB6C), Case("t", steps=(("curve", 0, 10000, 0),))))

    def test_mode_compare_edit_fails(self):
        self.assertTrue(killed(flip(0x392FAB6), Case("t", steps=(("curve", 2, 0, tool.to_bits(1.0)),))))

    def test_user_cap_edit_fails(self):
        self.assertTrue(killed(flip(0x392C8D0), Case("t", users=((tool.USER_A, 99),), steps=(enq(kind="four"),))))

    def test_expiry_jump_edit_fails(self):
        self.assertTrue(killed(flip(0x392CB20), Case("t", steps=(enq(kind="four", expires=1),))))

    def test_window_parity_edit_fails(self):
        self.assertTrue(killed(flip(0x392D49A), Case("t", flag=1, windows=((5, 3),), steps=(enq(kind="arm", base=1.0, set1=(5,)),))))

    def test_max_low_edit_fails(self):
        self.assertTrue(killed(flip(0x23583ED), Case("t", copy=0, chain=2, steps=(("vote", tool.WORD_MAX, 100),))))

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "x"
            data = bytearray(IMAGE.blob)
            data[0x1000] ^= 1
            path.write_bytes(data)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_nobits_never_resolves(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + bss["size"] - 8)

    def test_inside_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.CURVE + 1)

    def test_spec_fails_on_a_wrong_result(self):
        case = Case("t", steps=(enq(kind="four"),))
        got = HARNESS.run(case)
        want = tool.spec_for(HARNESS, case)
        want["results"] = [("ran",)]
        self.assertFalse(tool.same(case, got, want))


class Evidence(unittest.TestCase):
    def test_field_names_are_in_the_binary(self):
        names = {row[3] for row in RESULT["fields"]}
        self.assertLessEqual({"delayer_mode", "PerAsset", "Enabled", "max_n_delayed_actions", "delay_scale"}, names)

    def test_tag_texts(self):
        self.assertEqual({row[1] for row in RESULT["tags"]}, set(tool.TAG_TEXTS.values()))

    def test_classifier_arms(self):
        arms = {int(row[0], 16): row[3] for row in RESULT["classifier"]}
        self.assertEqual(arms[tool.WORD_FOUR], "base 4.0, empty sets")
        self.assertEqual(arms[tool.WORD_NEST], "read the action at +0x20 and dispatch again")

    def test_reference_rows_name_real_cases(self):
        names = {case.name for case in RESULT["cases"]}
        for row in tool.REFERENCE:
            self.assertIn(row[3], names)

    def test_generated_files_match_the_folder(self):
        for name in ("constants.tsv", "tag-texts.tsv", "reference-diff.tsv", "classifier-table.tsv", "field-names.tsv", "copies.tsv", "outcomes.tsv", "function-rows.tsv"):
            self.assertEqual(FILES[name], (FOLDER / name).read_text(encoding="ascii"), name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["named_cases"], len(RESULT["cases"]))
        self.assertEqual(summary["mutations"]["killed"] + summary["mutations"]["survived"], summary["mutations"]["total"])


if __name__ == "__main__":
    unittest.main()
