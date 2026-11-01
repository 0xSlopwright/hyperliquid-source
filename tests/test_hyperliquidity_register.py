"""Tests for tools/hyperliquidity_register.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-hyperliquidity-register-94"
spec_ = importlib.util.spec_from_file_location("hyperliquidity_register", ROOT / "tools" / "hyperliquidity_register.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["hyperliquidity_register"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
hype = tool.hype
LIMIT = tool.LIMIT
HIGH = tool.HIGH


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


def body(**fields):
    return run(hype("t", **fields))


def text(got):
    return got["result"][2]


def book(got):
    return got["state"]["books"][0]


def handler(copy=0, **fields):
    base = dict(entry="handler", copy=copy, available=10 ** 8, px_text="1.0", sz_text="1", n=10)
    base.update(fields)
    return run(hype("t", **base))


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Gates(unittest.TestCase):
    def test_order_bound_edges(self):
        self.assertEqual(text(body(n=4001)), tool.TOO_MANY)
        self.assertEqual(text(body(n=9)), tool.TOO_FEW)
        self.assertEqual(body(n=10)["result"], ("ok", 0))

    def test_seed_above_orders_comes_before_the_book(self):
        self.assertEqual(text(body(seeded=11, books=(1,))), tool.CANNOT_SEED)

    def test_book_comes_before_quote(self):
        self.assertEqual(text(run(Case("t", spot=2, books=(2,), held=1))), tool.EXISTS)

    def test_hold_comes_before_quote(self):
        self.assertEqual(text(run(Case("t", spot=2, hold=1))), tool.HOLD)

    def test_quote_must_be_token_zero(self):
        self.assertEqual(text(run(Case("t", spot=2, held=1))), tool.QUOTE)

    def test_supply_presence(self):
        self.assertEqual(text(body(supplied=(0, 2))), tool.NO_SUPPLY)

    def test_no_orders_no_balance_inserts_an_empty_word(self):
        got = run(Case("t", spot=2, n=0, held=0, px=77))
        self.assertEqual(got["result"], ("ok", 0))
        self.assertEqual(book(got), (2, "none"))
        self.assertEqual(got["state"]["mark"], 77)

    def test_no_orders_with_balance_is_too_few(self):
        self.assertEqual(text(body(n=0, held=5)), tool.TOO_FEW)

    def test_size_limit_edges(self):
        self.assertEqual(text(body(sz=LIMIT // 10 + 1, px=1, held=0)), tool.CONFIG)
        self.assertNotEqual(text(body(sz=LIMIT // 10, px=1, held=0)), tool.CONFIG)

    def test_px_multiple_edges(self):
        self.assertEqual(text(body(px=LIMIT // 2 + 1, sz=1, held=0)), tool.CONFIG)
        self.assertNotEqual(text(body(px=LIMIT // 2, sz=1, held=0)), tool.CONFIG)

    def test_zero_size_comes_after_the_products(self):
        self.assertEqual(text(body(sz=0, held=0)), tool.ZERO_SZ)
        self.assertEqual(text(body(sz=0, px=LIMIT, held=0)), tool.CONFIG)

    def test_balance_is_exact(self):
        self.assertEqual(body()["result"], ("ok", 0))
        for held in (999999999, 1000000001):
            self.assertEqual(text(body(held=held)), tool.BAD_BALANCE)

    def test_seeded_levels_lower_the_needed_balance(self):
        self.assertEqual(body(seeded=4)["result"][0], "ok")
        self.assertEqual(text(body(seeded=4, held=10 ** 9)), tool.BAD_BALANCE)

    def test_value_edge(self):
        self.assertEqual(text(body(px=999999, sz=1)), tool.SMALL_VALUE)
        self.assertEqual(body(px=1000000, sz=1)["result"][0], "ok")

    def test_market_cap_needs_the_band_unless_named_hype(self):
        self.assertEqual(text(run(Case("t", word=1))), tool.BAD_CAP)
        self.assertEqual(body(word=1)["result"][0], "ok")

    def test_cap_row_uses_the_supply_word(self):
        word = 5 * 10 ** 14
        got = run(Case("t", n=1450, px=2000000, sz=1, word=word))
        self.assertEqual(len(book(got)[1]), 1450)
        self.assertEqual(text(run(Case("t", n=1200, px=2000000, sz=1, word=word))), tool.BAD_CAP)

    def test_band_rows_at_their_edges(self):
        edge = dict(spots=((1, 0), (1, 0)), tokens=(("USDC", 8, 8, 0, 0), ("EDGE", 8, 8, 0, 0)), supplied=(0, 1), px=2000, sz=1000, n=1430)
        self.assertEqual(run(Case("t", word=650000000000, **edge))["result"], ("ok", 0))
        self.assertEqual(text(run(Case("t", word=650000000001, **edge))), tool.BAD_CAP)

    def test_seed_edges(self):
        self.assertEqual(body(seeded=2, avail=200300000)["result"], ("ok", 200300000))
        self.assertEqual(text(body(seeded=2, avail=200299999)), tool.NO_USDC)

    def test_mark_keeps_the_raw_price(self):
        got = body(px=1234567, sz=100)
        self.assertEqual(got["state"]["mark"], 1234567)
        self.assertEqual(book(got)[1][0], 1234500)


class Ladder(unittest.TestCase):
    def test_price_below_167_does_not_rise(self):
        self.assertEqual(text(body(px=166, sz=10000)), tool.SMALL_PX)
        self.assertEqual(book(body(px=167, sz=10000))[1][:2], (167, 168))

    def test_round_table(self):
        rows = RESULT["rises"]
        self.assertEqual(rows[0], (1, 1, "stuck"))
        self.assertEqual(rows[1], (167, 168, "rises"))
        self.assertEqual(len(rows), 2)

    def test_half_rounds_away(self):
        self.assertEqual(tool.round_half_away(2.5), 3)
        self.assertEqual(tool.round_half_away(2.4999), 2)

    def test_tick_floor_of_each_level(self):
        rows = book(body(px=1000000, sz=100))[1]
        self.assertEqual(rows[:3], (1000000, 1003000, 1006000))

    def test_tick_override(self):
        self.assertEqual(text(body(px=1000, sz=1000, tick_hit=1)), tool.SMALL_PX)
        self.assertEqual(text(body(px=5, sz=1000000, tick_hit=1)), tool.SMALL_PX)

    def test_multiple_changes_with_the_power(self):
        self.assertEqual(text(body(n=231, px=LIMIT // 3 + 1, sz=1, held=1)), tool.BAD_BALANCE)
        self.assertEqual(text(body(n=232, px=LIMIT // 3 + 1, sz=1, held=1)), tool.CONFIG)

    def test_last_level_at_the_price_cap(self):
        self.assertEqual(body(px=tool.MAX_LAND, sz=1, n=10, tick_hit=1)["result"], ("ok", 0))
        self.assertEqual(text(body(px=tool.MAX_LAND + 1000, sz=1, n=10, tick_hit=1)), tool.BAD_PX)

    def test_power_stays_below_the_multiple_bound(self):
        self.assertLess(RESULT["powers"][-1][2], 1000000)

    def test_level_head_words_are_zero(self):
        got = body()
        self.assertTrue(got["rest"])


class Band(unittest.TestCase):
    def band(self, low, high, value):
        got = run(Case("t", entry="band", lo=low, hi=high, v=value))
        return got["result"][1]

    def test_end_row_edges(self):
        self.assertEqual(self.band(tool.END_LOW, tool.END_HIGH, 7 * 10 ** 16 - 1), 0)
        self.assertEqual(self.band(tool.END_LOW, tool.END_HIGH, 7 * 10 ** 16), 1)
        self.assertEqual(self.band(tool.END_LOW, tool.END_HIGH, 13 * 10 ** 18), 1)
        self.assertEqual(self.band(tool.END_LOW, tool.END_HIGH, 13 * 10 ** 18 + 1), 0)

    def test_start_row_edges(self):
        self.assertEqual(self.band(0, tool.START_HIGH, 0), 1)
        self.assertEqual(self.band(0, tool.START_HIGH, 13 * 10 ** 14), 1)
        self.assertEqual(self.band(0, tool.START_HIGH, 13 * 10 ** 14 + 1), 0)

    def test_overflow_refuses(self):
        self.assertEqual(self.band(1 << 45, 1, 5), 0)
        self.assertEqual(self.band(1, 1 << 45, 5), 0)

    def test_sum_row_limit(self):
        self.assertEqual(run(Case("t", entry="sum", rows=(HIGH - 2,), seeded=1, sz=1))["result"], ("sum", 1, HIGH - 2))
        self.assertEqual(run(Case("t", entry="sum", rows=(HIGH - 1,), seeded=1, sz=1))["result"][1], 0)


class Handler(unittest.TestCase):
    def test_all_copies_agree(self):
        for copy in range(3):
            got = handler(copy, seeded=2)
            self.assertEqual(got["result"], ("ok",))
            self.assertEqual(got["state"]["token"][4], (1, 2003000))
            self.assertEqual([event[0] for event in got["events"]], ["dex", "scale", "send", "move", "event"])

    def test_amount_rounds_up(self):
        got = handler(seeded=1, sz=21, px_text="0.12345", sz_text="0.21")
        self.assertIn(("move", 25925), got["events"])

    def test_event_is_negative_six_decimals(self):
        got = handler(seeded=2)
        self.assertEqual(got["events"][-1], ("event", tool.to_bits(-2.003)))

    def test_token_word_is_set_once(self):
        tokens = tuple(row if row[0] != "HYPE" else ("HYPE", 2, 8, 1, 55) for row in tool.TEST_TOKENS)
        self.assertEqual(handler(seeded=1, tokens=tokens)["state"]["token"][4], (1, 55))

    def test_zero_seed_has_no_debit(self):
        self.assertEqual(handler()["events"], [])

    def test_balance_cap_edges(self):
        self.assertEqual(handler(available=tool.MAX_BALANCE)["result"], ("ok",))
        self.assertEqual(handler(available=tool.MAX_BALANCE + 1)["result"][2], tool.NO_CONVERT)

    def test_refused_debit_panics(self):
        self.assertEqual(handler(seeded=2, send=tool.REFUSAL)["result"], ("panic",))
        self.assertEqual(handler(seeded=2, move=tool.REFUSAL)["result"], ("panic",))

    def test_text_tags(self):
        self.assertEqual(handler(px_text="x1")["result"], ("error", tool.PARSE_TAG))
        self.assertEqual(handler(px_text="0")["result"], ("error", tool.TAG_PX))
        self.assertEqual(handler(sz_text="1.001")["result"], ("error", tool.TAG_SZ))


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
        with self.assertRaises(tool.EvidenceError):
            IMAGE.offset(IMAGE.named[".bss"]["address"] + 8)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x100)

    def test_function_start_is_exact(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.BODY + 1)

    def test_wrong_rule_fails(self):
        case = hype("t")
        want = tool.spec_for(case)
        want["result"] = ("ok", 1)
        self.assertFalse(tool.same(case, HARNESS.run(case), want))

    def test_order_bound_edit(self):
        self.assertTrue(killed(flip(0x3261C77), hype("t", n=4001)))

    def test_lowest_order_edit(self):
        self.assertTrue(killed(flip(0x3261EF2), hype("t", n=10)))

    def test_limit_edit(self):
        self.assertTrue(killed(flip(0x32620D9, 0xF), hype("t", px=LIMIT // 2, sz=1, held=0)))

    def test_band_low_edit(self):
        self.assertTrue(killed(flip(0x3262607), Case("t", entry="band", lo=tool.END_LOW, hi=tool.END_HIGH, v=7 * 10 ** 16)))

    def test_band_high_edit(self):
        self.assertTrue(killed(flip(0x326262B), Case("t", entry="band", lo=tool.END_LOW, hi=tool.END_HIGH, v=13 * 10 ** 18 + 1)))

    def test_equal_price_edit(self):
        self.assertTrue(killed(flip(0x32621C5), hype("t", px=166, sz=10000)))

    def test_balance_edit(self):
        self.assertTrue(killed(flip(0x3262163), hype("t", held=999999999)))

    def test_name_length_edit(self):
        self.assertTrue(killed(flip(0x32623C4), hype("t", word=1)))

    def test_round_up_edit(self):
        self.assertTrue(killed(flip(0x274FFFA), hype("t", entry="handler", available=10 ** 8, px_text="1.0", sz_text="1", seeded=2)))

    def test_message_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x584757)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.message_rows(tool.Image(bytes(data)))

    def test_constant_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x209E14)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.PROC)
        with self.assertRaises(tool.Halt):
            harness.run(hype("t", entry="handler", available=10 ** 8, px_text="1.0", sz_text="1", seeded=2, proc=1))


class Evidence(unittest.TestCase):
    def test_retained_files_match(self):
        names_ = sorted(path.name for path in FOLDER.iterdir() if path.name not in ("README.md", "MANIFEST.sha256", "mutations.tsv", "evidence.json"))
        for name in names_:
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
        names_ = {case.name for case in RESULT["cases"]}
        for row in tool.REFERENCE:
            self.assertIn(row[3], names_, row[0])

    def test_survivors_have_a_reason(self):
        for row in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            cells = row.split("\t")
            if cells[3] == "survived":
                self.assertNotEqual(cells[4], "unclassified", cells[1])

    def test_callers(self):
        rows = RESULT["callers"]
        self.assertEqual(sorted(row[3] for row in rows if row[0] == "body"), ["0x274fd60", "0x4d72a80", "0x4d73550"])
        self.assertEqual([row[3] for row in rows if row[0] == "ladder"], ["0x3261c40"])
        self.assertEqual([row[3] for row in rows if row[0] == "seed_sum"], ["0x3261c40"])
        self.assertEqual([row[3] for row in rows if row[0] == "cap_band"], ["0x3261c40"])

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word, data, name)


if __name__ == "__main__":
    unittest.main()
