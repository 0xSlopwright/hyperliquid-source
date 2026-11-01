"""Tests for tools/spot_balance_ledger.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-spot-balance-ledger-94"
spec_ = importlib.util.spec_from_file_location("spot_balance_ledger", ROOT / "tools" / "spot_balance_ledger.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["spot_balance_ledger"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
credit, debit, poke = tool.credit, tool.debit, tool.poke
ALICE, BOB = tool.ALICE, tool.BOB
SENTINEL = tool.SENTINEL
TOP = tool.MASK[8]
CAP = tool.CAP


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=20)
    FILES = tool.render(RESULT)


def run(*steps, **fields):
    case = Case("t", steps=steps, **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(HARNESS, case)), steps
    return got


def row(got, user=ALICE, token=5):
    return got["users"][user]["rows"][token]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Debit(unittest.TestCase):
    def test_total_and_hold(self):
        self.assertEqual(row(run(poke(ALICE, 5, 100, 30), debit(ALICE, 5, 20, 0))), (80, 10, 0))

    def test_hold_saturates_with_a_record(self):
        got = run(poke(ALICE, 5, 100, 3), debit(ALICE, 5, 20, 0))
        self.assertEqual(row(got), (80, 0, 0))
        self.assertEqual(got["events"], ["record %#x" % tool.SUB_LOCATION])

    def test_total_under_panics(self):
        got = run(poke(ALICE, 5, 19), debit(ALICE, 5, 20, 0))
        self.assertEqual(got["results"][-1], "panic")
        self.assertEqual(row(got), (19, 0, 0))

    def test_absent_row_is_created_for_a_zero_debit(self):
        got = run(debit(ALICE, 3, 0, 9))
        self.assertEqual(row(got, token=3), (0, 0, 0))
        self.assertEqual(got["index"], {})

    def test_notional_float_scale(self):
        self.assertEqual(row(run(poke(ALICE, 5, 1000, 0, 12345678901), debit(ALICE, 5, 999, 7)))[2], 12345678)

    def test_notional_uses_f64_not_integers(self):
        total = (1 << 53) + 1
        got = row(run(poke(ALICE, 5, total, 0, 1 << 52), debit(ALICE, 5, 1, 7)))[2]
        self.assertEqual(got, int(float(1 << 52) * (float(total - 1) / float(total))))

    def test_notional_at_the_cap_stays(self):
        self.assertEqual(row(run(poke(ALICE, 5, 1000, 0, CAP), debit(ALICE, 5, 500, 7)))[2], CAP)
        self.assertEqual(row(run(poke(ALICE, 5, 1000, 0, CAP - 1), debit(ALICE, 5, 500, 7)))[2], int(float(CAP - 1) * 0.5))

    def test_zero_notional_is_valued_from_what_is_left(self):
        self.assertEqual(row(run(poke(ALICE, 5, 1000), debit(ALICE, 5, 1, 777)))[2], 999 * 777 // 10)

    def test_old_total_zero_clears_notional(self):
        self.assertEqual(row(run(poke(ALICE, 5, 0, 0, 50), debit(ALICE, 5, 0, 7)))[2], 0)

    def test_price_zero_and_token_zero_skip(self):
        self.assertEqual(row(run(poke(ALICE, 5, 100, 0, 50), debit(ALICE, 5, 50, 0)))[2], 50)
        self.assertEqual(row(run(poke(ALICE, 0, 100, 0, 50), debit(ALICE, 0, 50, 7)), token=0)[2], 50)


class Credit(unittest.TestCase):
    def test_hold_is_not_touched(self):
        self.assertEqual(row(run(poke(ALICE, 5, 100, 30), credit(ALICE, 5, 20, 0))), (120, 30, 0))

    def test_total_saturates(self):
        got = run(poke(ALICE, 5, TOP - 1), credit(ALICE, 5, 5, 0))
        self.assertEqual(row(got)[0], TOP)
        self.assertEqual(got["events"], ["record %#x" % tool.ADD_LOCATION])

    def test_indexes_the_token(self):
        self.assertEqual(run(credit(ALICE, 5, 0, 0))["index"], {ALICE: [5]})

    def test_notional_adds_the_amount_value(self):
        self.assertEqual(row(run(poke(ALICE, 5, 1000, 0, 7), credit(ALICE, 5, 1000, 3)))[2], 7 + 300)

    def test_zero_notional_values_the_whole_balance(self):
        self.assertEqual(row(run(poke(ALICE, 5, 1000), credit(ALICE, 5, 1000, 3)))[2], 600)

    def test_overflowing_sum_values_only_the_amount(self):
        self.assertEqual(row(run(poke(ALICE, 5, TOP), credit(ALICE, 5, 2000, 3)))[2], 600)

    def test_value_falls_back_when_the_product_overflows(self):
        amount = 1 << 33
        self.assertEqual(row(run(credit(ALICE, 5, amount, 1 << 33)))[2], (amount // 10) * (1 << 33))

    def test_second_overflow_keeps_notional(self):
        self.assertEqual(row(run(poke(ALICE, 5, 9, 0, 7), credit(ALICE, 5, TOP, TOP)))[2], 7)

    def test_add_overflow_keeps_notional(self):
        self.assertEqual(row(run(poke(ALICE, 5, 9, 0, TOP), credit(ALICE, 5, 1000, 3)))[2], TOP)

    def test_scale_edges(self):
        for wei, ok in ((19, True), (20, False)):
            got = run(credit(ALICE, 3, 5, 3), tokens={3: (0, wei)})
            self.assertEqual(got["results"][-1] != "panic", ok)

    def test_sz_above_wei_panics(self):
        self.assertEqual(run(credit(ALICE, 3, 5, 3), tokens={3: (4, 2)})["results"][-1], "panic")

    def test_token_past_the_table_panics_only_with_a_price(self):
        self.assertEqual(run(credit(ALICE, 40, 5, 3))["results"][-1], "panic")
        self.assertEqual(run(credit(ALICE, 40, 5, 0))["results"][-1], None)


class Hold(unittest.TestCase):
    def test_room(self):
        got = run(poke(ALICE, 5, 100, 60), ("hold", ALICE, 5, 40))
        self.assertEqual((got["results"][-1], row(got)[1]), (1, 100))

    def test_refused(self):
        got = run(poke(ALICE, 5, 100, 60), ("hold", ALICE, 5, 41))
        self.assertEqual((got["results"][-1], row(got)[1]), (0, 60))

    def test_carry_refused(self):
        self.assertEqual(run(poke(ALICE, 5, TOP, TOP), ("hold", ALICE, 5, 1))["results"][-1], 0)

    def test_zero_needs_no_user(self):
        got = run(("hold", ALICE, 5, 0))
        self.assertEqual((got["results"], got["users"]), ([1], {}))

    def test_token_past_the_table(self):
        got = run(("hold", ALICE, 40, 0))
        self.assertEqual((got["results"], got["events"]), ([0], ["tag 0xea"]))

    def test_unknown_user_gets_no_entry(self):
        self.assertEqual(run(("hold", ALICE, 5, 3))["users"], {})

    def test_known_user_gets_a_row(self):
        self.assertEqual(row(run(poke(ALICE, 4, 9), ("hold", ALICE, 5, 3))), (0, 0, 0))


class Release(unittest.TestCase):
    def test_quote_side(self):
        self.assertEqual(row(run(poke(ALICE, 2, 9, 100), ("release", ALICE, 0, 0, 3, 4)), token=2)[1], 88)

    def test_base_side_uses_the_scale(self):
        got = run(poke(ALICE, 1, 9, 5000), ("release", ALICE, 0, 1, 3, 4))
        self.assertEqual(row(got, token=1)[1], 5000 - 4 * 10)

    def test_overflow_does_nothing(self):
        got = run(("release", ALICE, 0, 0, 1 << 32, 1 << 32))
        self.assertEqual(got["users"], {})

    def test_spot_past_the_table_panics(self):
        self.assertEqual(run(("release", ALICE, 8, 0, 1, 1))["results"][-1], "panic")

    def test_indexes(self):
        self.assertEqual(run(("release", ALICE, 0, 0, 0, 0))["index"], {ALICE: [2]})

    def test_saturates(self):
        got = run(poke(ALICE, 2, 9, 5), ("release", ALICE, 0, 0, 3, 4))
        self.assertEqual((row(got, token=2)[1], got["events"]), (0, ["record %#x" % tool.SUB_LOCATION]))


class Sweeps(unittest.TestCase):
    def test_fee_sweep(self):
        got = run(poke(SENTINEL, 5, 70), ("fees", 5, 0))
        self.assertEqual((got["fees"], row(got, SENTINEL)), ({5: 70}, (0, 0, 0)))

    def test_fee_sweep_needs_a_free_row(self):
        got = run(poke(SENTINEL, 5, 70, 1), ("fees", 5, 0))
        self.assertEqual((got["fees"], row(got, SENTINEL)), ({}, (70, 1, 0)))

    def test_fee_sweep_adds_and_saturates(self):
        got = run(poke(SENTINEL, 5, TOP), ("fees", 5, 0), poke(SENTINEL, 5, 9), ("fees", 5, 0))
        self.assertEqual((got["fees"], got["events"]), ({5: TOP}, ["record %#x" % tool.ADD_LOCATION]))

    def test_fee_sweep_makes_the_sentinel_entry(self):
        self.assertEqual(run(("fees", 5, 0))["users"][SENTINEL]["rows"], {})

    def test_user_sweep_deletes_the_row(self):
        got = run(poke(ALICE, 5, 40, 3, 9), poke(BOB, 5, 2), ("sweep", 5, (ALICE, BOB), 0, 0))
        self.assertEqual(got["users"][ALICE]["rows"], {})
        self.assertEqual(row(got, SENTINEL)[0], 42)
        self.assertEqual(got["index"][ALICE], [5])

    def test_user_sweep_of_nobody_credits_zero(self):
        got = run(("sweep", 5, (), 0, 0))
        self.assertEqual((row(got, SENTINEL), got["index"]), ((0, 0, 0), {SENTINEL: [5]}))

    def test_user_sweep_saturates_with_a_record(self):
        got = run(poke(ALICE, 5, TOP), poke(BOB, 5, 2), ("sweep", 5, (ALICE, BOB), 0, 0))
        self.assertEqual(row(got, SENTINEL)[0], TOP)
        self.assertIn("record %#x" % tool.ADD_LOCATION, got["events"])

    def test_tall_user_map(self):
        users = tuple(tool.user_of(index + 1) for index in range(3))
        self.assertEqual(row(run(*(tuple(poke(user, 5, 4) for user in users) + (("sweep", 5, users, 0, 12),))), SENTINEL)[0], 12)


class Tail(unittest.TestCase):
    def tail(self, value):
        got = HARNESS.run(Case("t", kind="tail", bits=tool.to_bits(value)))
        return got["result"]

    def test_truncates(self):
        self.assertEqual(self.tail(7.9), 7)

    def test_negative_stores_zero(self):
        self.assertEqual(self.tail(-7.9), 0)

    def test_top(self):
        self.assertEqual(self.tail(9223372036854775808.0), (1 << 63) - 1)


class Controls(unittest.TestCase):
    def test_hold_condition_edit_fails(self):
        self.assertTrue(killed(flip(0x371D233), Case("t", steps=(poke(ALICE, 5, 100, 30), debit(ALICE, 5, 20, 0)))))

    def test_cap_compare_edit_fails(self):
        self.assertTrue(killed(flip(0x371D493), Case("t", steps=(poke(ALICE, 5, 1000, 0, CAP), debit(ALICE, 5, 500, 7)))))

    def test_try_hold_bound_edit_fails(self):
        self.assertTrue(killed(flip(0x371B362), Case("t", steps=(poke(ALICE, 5, 100, 60), ("hold", ALICE, 5, 41)))))

    def test_user_sweep_edit_fails(self):
        self.assertTrue(killed(flip(0x3721ADB), Case("t", steps=(poke(ALICE, 5, TOP), poke(BOB, 5, 2), ("sweep", 5, (ALICE, BOB), 0, 0)))))

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

    def test_inside_is_not_a_start(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.UPDATE + 1)

    def test_nobits_never_resolves(self):
        bss = IMAGE.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(bss["address"] + bss["size"] - 8)

    def test_step_limit_control(self):
        harness = tool.Harness(IMAGE)
        harness.machine.step_limit = 3
        with self.assertRaises(tool.Halt):
            harness.run(Case("t", steps=(credit(ALICE, 5, 1, 0),)))


class Evidence(unittest.TestCase):
    def test_every_update_call_is_classed(self):
        rows = RESULT["calls"]
        self.assertEqual(len(rows), 65)
        self.assertFalse([row_ for row_ in rows if row_[2] == "?"])

    def test_known_sites(self):
        rows = {row_[1]: row_ for row_ in RESULT["calls"]}
        self.assertEqual(rows["0x26c7a92"][2:], ("debit", "value", "none"))
        self.assertEqual(rows["0x274ba42"][2:], ("debit", "0", "none"))
        self.assertEqual(rows["0x26fdca3"][2:], ("credit", "value", "value"))

    def test_slot_family(self):
        self.assertEqual(len([row_ for row_ in RESULT["slot_calls"] if row_[0] == "fee_sweep"]), 15)

    def test_serde_keys(self):
        self.assertEqual([row_[2] for row_ in RESULT["keys"]], ["user_states", "token_fees_collected", "entryNtl"])

    def test_outcomes_are_stable(self):
        self.assertEqual(tool.render(RESULT)["outcomes.tsv"], FILES["outcomes.tsv"])

    def test_generated_files_match_the_folder(self):
        for name in ("constants.tsv", "layouts.tsv", "reference-diff.tsv", "update-calls.tsv", "update-call-summary.tsv", "slot-calls.tsv", "tail-edges.tsv", "field-keys.tsv", "slots.tsv", "outcomes.tsv", "function-rows.tsv"):
            self.assertEqual(FILES[name], (FOLDER / name).read_text(encoding="ascii"), name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["named_cases"], len(RESULT["cases"]))
        self.assertEqual(summary["update_calls"], 65)
        self.assertEqual(summary["mutations"]["killed"] + summary["mutations"]["survived"], summary["mutations"]["total"])


if __name__ == "__main__":
    unittest.main()
