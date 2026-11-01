"""Tests for tools/spot_balance_payout.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import math
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-spot-balance-payout-94"
spec_ = importlib.util.spec_from_file_location("spot_balance_payout", ROOT / "tools" / "spot_balance_payout.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["spot_balance_payout"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
norm, poke, people, weights = tool.norm, tool.poke, tool.people, tool.weights
SENTINEL = tool.SENTINEL
TOP = tool.MASK[8]


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=20)
    FILES = tool.render(RESULT)


def run(case):
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(HARNESS, case)), case.name
    return got


def amounts(*values, target, **fields):
    return [row[2] for row in run(norm("t", values, target, **fields))["rows"]]


def text(*values, target, **fields):
    return run(norm("t", values, target, **fields))["error"][2]


def pay(*steps, **fields):
    return run(Case("t", steps=steps, **fields))


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Scale(unittest.TestCase):
    def test_shares_truncate_and_the_largest_takes_the_rest(self):
        self.assertEqual(amounts(7, 5, 3, target=100), [47, 33, 20])

    def test_largest_first_whatever_the_order(self):
        self.assertEqual(amounts(3, 5, 7, target=100), [47, 33, 20])

    def test_sort_is_stable(self):
        got = run(norm("t", (4, 9, 4), 17))["rows"]
        self.assertEqual([row[0] for row in got], [people(4, 9, 4)[1][0], people(4, 9, 4)[0][0], people(4, 9, 4)[2][0]])

    def test_zero_rows_stay_at_floor_zero(self):
        self.assertEqual(amounts(1, 0, 2, target=100), [67, 33, 0])

    def test_floor_drops_rows(self):
        self.assertEqual(amounts(1, 0, 2, target=100, floor=1), [67, 33])

    def test_floor_drops_before_the_remainder(self):
        self.assertEqual(amounts(9, 1, target=10, floor=2), [10])

    def test_target_zero(self):
        self.assertEqual(amounts(1, 2, target=0), [0, 0])

    def test_big_sort_route(self):
        values = tuple(range(1, 26))
        self.assertEqual(sum(amounts(*values, target=1000)), 1000)


class Excess(unittest.TestCase):
    TARGET = TOP - 1

    def test_single_row_trimmed(self):
        self.assertEqual(amounts(1, target=self.TARGET), [self.TARGET])

    def test_factor_zero_reports_the_remainder(self):
        self.assertEqual(text(1, target=self.TARGET, factor=0.0), b"could not distribute remainder=Wei(1) to match exactly")

    def test_nan_factor_reports_the_remainder(self):
        self.assertEqual(text(1, target=self.TARGET, factor=math.nan), b"could not distribute remainder=Wei(1) to match exactly")

    def test_factor_above_the_bound(self):
        self.assertTrue(text(1, target=self.TARGET, factor=math.nextafter(1.01, 2.0)).startswith(b"could not"))

    def test_factor_at_the_bound(self):
        self.assertEqual(amounts(1, target=self.TARGET, factor=1.01), [self.TARGET])


class Errors(unittest.TestCase):
    def test_zero_sum(self):
        self.assertEqual(text(0, 0, target=5), tool.ZERO_TEXT)

    def test_no_rows(self):
        self.assertEqual(run(norm("t", (), 5, cap=0))["error"][2], tool.ZERO_TEXT)

    def test_sum_overflow_uses_the_same_text(self):
        self.assertEqual(text(TOP, 1, target=5), tool.ZERO_TEXT)

    def test_all_dropped(self):
        self.assertEqual(text(3, 3, target=2, floor=5), tool.EMPTY_TEXT)

    def test_running_sum_overflow(self):
        got = run(norm("t", (1, 1), TOP))["error"]
        half = 1 << 63
        self.assertEqual(got[2], b"error while computing existing token balances total_wei=Wei(%d) marginal_wei=Wei(%d)" % (half, half))
        self.assertEqual(got[4], half)

    def test_final_check_texts(self):
        got = HARNESS.run(Case("t", kind="final", rows=people(5, 3), target=9))
        self.assertEqual(got["error"][2], b"BUG: distributing to existing token final_allocation_check=Some(Wei(8)) target_wei_to_distribute=Wei(9)")
        got = HARNESS.run(Case("t", kind="final", rows=people(TOP, 1), target=5))
        self.assertIn(b"final_allocation_check=None", got["error"][2])

    def test_final_check_match(self):
        self.assertTrue(HARNESS.run(Case("t", kind="final", rows=people(5, 3), target=8))["ok"])


class Payout(unittest.TestCase):
    ROWS = weights(1, 2, 3)

    def test_moves_from_the_sentinel(self):
        got = pay(poke(SENTINEL, 0, 1000, 0, 77), ("pay", self.ROWS, 600, 0))
        self.assertEqual(got["users"][SENTINEL]["rows"][0], (400, 0, 77))
        self.assertEqual(got["users"][self.ROWS[2][0]]["rows"][0], (300, 0, 0))
        self.assertEqual(got["results"][-1][0], "paid")
        self.assertEqual(got["results"][-1][2], 3)

    def test_stops_at_the_first_refused_hold(self):
        got = pay(poke(SENTINEL, 0, 500), ("pay", weights(3, 2, 1), 600, 0))
        self.assertEqual(got["results"][-1][2], 2)
        self.assertEqual(got["users"][SENTINEL]["rows"][0], (0, 0, 0))

    def test_held_fund_counts_against_the_room(self):
        got = pay(poke(SENTINEL, 0, 600, 200), ("pay", weights(3, 2, 1), 600, 0))
        self.assertEqual(got["results"][-1][2], 1)

    def test_error_leaves_balances(self):
        got = pay(poke(SENTINEL, 0, 600), ("pay", weights(0, 0), 600, 0))
        self.assertEqual(got["results"][-1][1], 0xFA)
        self.assertEqual(got["users"][SENTINEL]["rows"][0], (600, 0, 0))

    def test_recipient_row_saturates(self):
        got = pay(poke(SENTINEL, 0, 1000), poke(self.ROWS[2][0], 0, TOP - 3), ("pay", self.ROWS, 600, 0))
        self.assertEqual(got["users"][self.ROWS[2][0]]["rows"][0][0], TOP)

    def test_clock_only_runs_on_success(self):
        got = pay(poke(SENTINEL, 0, 10), ("pay", weights(1), 5, 0))
        self.assertEqual(got["events"], ["timed"])


class Controls(unittest.TestCase):
    def test_factor_bound_edit_fails(self):
        self.assertTrue(killed(flip(0x372291B), norm("t", (1,), TOP - 1, factor=1.01)))

    def test_sort_direction_edit_fails(self):
        self.assertTrue(killed(flip(0x338700F), norm("t", (3, 5, 7), 100)))

    def test_fold_floor_edit_fails(self):
        self.assertTrue(killed(flip(0x3308C4C), norm("t", (1, 0, 2), 100, floor=1)))

    def test_payout_break_edit_fails(self):
        self.assertTrue(killed(flip(0x37203E6), Case("t", steps=(poke(SENTINEL, 0, 500), ("pay", weights(3, 2, 1), 600, 0)))))

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
            IMAGE.exact_fde(tool.NORMALIZE + 1)


class Evidence(unittest.TestCase):
    def test_error_texts_are_in_the_binary(self):
        texts = {row[1] for row in RESULT["texts"]}
        self.assertIn(tool.ZERO_TEXT.decode(), texts)
        self.assertIn(tool.EMPTY_TEXT.decode(), texts)

    def test_callers(self):
        self.assertEqual(sorted(row[2] for row in RESULT["callers"] if row[0] == "normalize"), ["0x3720200", "0x3720a70"])
        self.assertEqual(len([row for row in RESULT["callers"] if row[0] == "pay_out"]), 3)

    def test_generated_files_match_the_folder(self):
        for name in ("constants.tsv", "error-texts.tsv", "reference-diff.tsv", "callers.tsv", "outcomes.tsv", "function-rows.tsv"):
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
