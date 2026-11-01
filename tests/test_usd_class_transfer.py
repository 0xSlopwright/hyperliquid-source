"""Tests for tools/usd_class_transfer.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-usd-class-transfer-94"
spec_ = importlib.util.spec_from_file_location("usd_class_transfer", ROOT / "tools" / "usd_class_transfer.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["usd_class_transfer"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
USER_A, USER_B = tool.USER_A, tool.USER_B
FULL = ((0, TOP, 0),)


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


def core(**fields):
    return run(Case("t", **fields))


def text(value, **fields):
    fields.setdefault("balances", FULL)
    fields.setdefault("to_perp", 1)
    return run(Case("t", entry="user", text=value, **fields))


def moved(got):
    return [event[2] for event in got["events"] if event[0] == "credit"]


def names(got):
    return [event[0] for event in got["events"]]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Move(unittest.TestCase):
    def test_spot_to_perp_order(self):
        got = core(amount=7, balances=((0, 700, 0),), total=50, tally=70)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(names(got), ["spot row", "hold", "ledger", "credit", "total row"])
        self.assertEqual(got["state"]["total"], 57)

    def test_perp_to_spot_order(self):
        got = core(mode=1, amount=7, available=(7, 7), total=50)
        self.assertEqual(names(got), ["withdrawable", "withdrawable", "debit", "ledger", "total row"])
        self.assertEqual(got["state"]["total"], 43)

    def test_wei_is_one_hundred_raw(self):
        got = core(amount=7, balances=((0, 700, 0),))
        self.assertEqual(got["events"][1][3], 700)
        self.assertEqual(got["events"][2][4], 700)

    def test_balance_gate_counts_the_held_word(self):
        self.assertEqual(core(amount=7, balances=((0, 750, 50),))["result"], ("ok",))
        self.assertEqual(core(amount=7, balances=((0, 749, 50),))["result"], ("error", tool.TAG_BALANCE))

    def test_missing_row_is_zero_balance(self):
        self.assertEqual(core(amount=1)["result"], ("error", tool.TAG_BALANCE))
        self.assertEqual(core(amount=0)["result"], ("ok",))

    def test_times_one_hundred_overflow(self):
        self.assertEqual(core(amount=TOP // 100, balances=FULL)["result"], ("ok",))
        self.assertEqual(core(amount=TOP // 100 + 1, balances=FULL)["result"], ("error", tool.TAG_BALANCE))
        self.assertEqual(core(mode=1, amount=TOP // 100 + 1, available=(TOP, TOP))["result"], ("error", tool.TAG_BALANCE))

    def test_withdraw_edge(self):
        self.assertEqual(core(mode=1, amount=9, available=(9, 9))["result"], ("ok",))
        self.assertEqual(core(mode=1, amount=9, available=(8, 8))["result"], ("error", tool.TAG_WITHDRAW))

    def test_second_read_lower_is_ok_with_no_move(self):
        got = core(mode=1, amount=5, available=(5, 4), total=9)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(names(got), ["withdrawable", "withdrawable", "dropped"])
        self.assertEqual(got["state"]["total"], 9)

    def test_refused_hold_is_ok_with_no_move(self):
        got = core(amount=7, balances=((0, 700, 0),), hold_ok=0, total=9)
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(names(got), ["spot row", "hold"])

    def test_negative_amount_panics(self):
        self.assertEqual(core(amount=tool.HIGH)["result"], ("panic",))
        self.assertEqual(core(mode=1, amount=tool.HIGH, available=(TOP, TOP))["result"], ("panic",))

    def test_sweep_moves_free_margin_and_skips_gates(self):
        got = core(mode=2, amount=3, value=500, used=100, total=1000)
        self.assertEqual(names(got), ["margin row", "debit", "ledger", "total row"])
        self.assertEqual(got["events"][1][2], 400)
        self.assertEqual(got["events"][2][4], 40000)

    def test_sweep_with_nothing_free(self):
        for value, used in ((100, 100), (100, 500), ((-5) & TOP, 0)):
            self.assertEqual(names(core(mode=2, value=value, used=used)), ["margin row"])

    def test_sweep_used_top_bit_panics(self):
        self.assertEqual(core(mode=2, value=5, used=tool.HIGH)["result"], ("panic",))

    def test_mode_three_differs_between_copies(self):
        self.assertIn("credit", names(core(mode=3, value=500, used=100, balances=FULL)))
        self.assertIn("credit", names(core(copy=1, mode=3, value=500, used=100, balances=FULL)))
        self.assertIn("debit", names(core(copy=2, mode=3, value=500, used=100, balances=FULL)))

    def test_callers_use_only_three_modes(self):
        self.assertEqual({row[4] for row in RESULT["callers"]}, {"0", "1", "2", "register"})
        self.assertEqual(len(RESULT["callers"]), 39)
        self.assertEqual(sorted(row[2] for row in RESULT["callers"] if row[4] == "register"), ["0x2717d48", "0x4d0fb18", "0x4d0fcf8"])


class Gates(unittest.TestCase):
    def test_dex_bound_panics(self):
        self.assertEqual(core(index=1, dexes=1)["result"], ("panic",))
        self.assertEqual(core(index=1, dexes=2, balances=FULL)["result"], ("ok",))

    def test_vault_rule(self):
        self.assertEqual(core(vault=0, balances=FULL)["result"], ("error", tool.TAG_VAULT))
        self.assertEqual(core(vault=1, balances=FULL)["result"], ("ok",))
        self.assertEqual(core(vault=1, token=7, balances=tool.token_rows(7, tool.FULL))["result"], ("error", tool.TAG_VAULT))

    def test_vault_gate_runs_before_the_amount_sign(self):
        self.assertEqual(core(vault=0, amount=TOP)["result"], ("error", tool.TAG_VAULT))

    def test_spot_off_byte(self):
        got = run(Case("t", entry="apply", disabled=1, amount=5, to_perp=1))
        self.assertEqual(got["result"], ("error", tool.TAG_SPOT))
        self.assertEqual(got["events"], [])


class Notional(unittest.TestCase):
    def row(self, amount, bits):
        return core(amount=amount, scale=bits, balances=FULL)["state"]["tally"]

    def test_divides_by_ten_thousand(self):
        self.assertEqual(self.row(9999, tool.to_bits(1.0)), 0)
        self.assertEqual(self.row(10000, tool.to_bits(1.0)), 1)
        self.assertEqual(self.row(19999, tool.to_bits(1.0)), 1)

    def test_scale_applies_at_the_gate(self):
        self.assertEqual(self.row(tool.GATE_LIMIT, tool.to_bits(0.5)), int(float(tool.GATE_LIMIT) * 0.5) // 10000)

    def test_branch_past_the_gate_is_closed_by_the_times_one_hundred_gate(self):
        self.assertEqual(tool.GATE_LIMIT, TOP // 100)
        got = core(amount=tool.GATE_LIMIT + 1, scale=tool.to_bits(0.5), balances=FULL)
        self.assertEqual(got["result"], ("error", tool.TAG_BALANCE))

    def test_bad_scales(self):
        for bits in (0x7FF8000000000000, 0x7FF0000000000000, tool.to_bits(-1.0)):
            self.assertEqual(self.row(10 ** 6, bits), 0)

    def test_clamp(self):
        self.assertEqual(self.row(10 ** 6, tool.to_bits(1e300)), tool.CLAMP // 10000)

    def test_sign_of_the_row_word_follows_direction(self):
        got = core(mode=1, amount=10 ** 6, available=(10 ** 6, 10 ** 6), tally=1000)
        self.assertEqual(got["state"]["tally"], 900)

    def test_saturation_records(self):
        got = core(amount=7, balances=FULL, total=tool.HIGH - 3)
        self.assertEqual(got["state"]["total"], tool.HIGH - 1)
        self.assertIn(("recorded", tool.LOC_TOTAL_ADD), got["events"])
        got = core(amount=10 ** 9, balances=FULL, tally=tool.HIGH - 3)
        self.assertEqual(got["state"]["tally"], tool.HIGH - 1)
        self.assertIn(("recorded", tool.LOC_TALLY), got["events"])


class Event(unittest.TestCase):
    def event(self, got):
        return next(item for item in got["events"] if item[0] == "event")

    def test_word_and_amount(self):
        got = run(Case("t", entry="apply", to_perp=1, amount=2500000, balances=FULL))
        item = self.event(got)
        self.assertEqual(item[4], 0x800000000000000D)
        self.assertEqual(tool.to_float(item[5]), 2.5)
        self.assertEqual(item[6], 1)

    def test_sent_for_zero(self):
        self.assertEqual(self.event(run(Case("t", entry="apply", to_perp=1, amount=0, balances=FULL)))[5], 0)

    def test_sent_when_hold_refused(self):
        got = run(Case("t", entry="apply", to_perp=1, amount=7, balances=FULL, hold_ok=0))
        self.assertTrue(self.event(got))
        self.assertEqual(moved(got), [])

    def test_stamp_only_when_the_word_is_one(self):
        got = run(Case("t", entry="apply", to_perp=1, amount=7, balances=FULL, stamped=1))
        self.assertEqual(self.event(got)[3], tool.STAMP_BYTES)
        got = run(Case("t", entry="apply", to_perp=1, amount=7, balances=FULL))
        self.assertEqual(self.event(got)[3], bytes(32))

    def test_copy_c_uses_its_own_sink(self):
        self.assertEqual(tool.COPIES[2].sink_at, 0x5B8)
        self.assertTrue(self.event(run(Case("t", copy=2, entry="apply", to_perp=1, amount=7, balances=FULL))))


class AmountText(unittest.TestCase):
    def value(self, data):
        got = text(data)
        self.assertEqual(got["result"], ("ok",))
        return (moved(got) or [0])[0]

    def test_half_even_at_six_places(self):
        self.assertEqual(self.value(b"0.0000005"), 0)
        self.assertEqual(self.value(b"0.0000015"), 2)
        self.assertEqual(self.value(b"0.0000025"), 2)
        self.assertEqual(self.value(b"0.00000051"), 1)

    def test_decimal_parser_rounds_first(self):
        self.assertEqual(self.value(b"0.00000050000000000000000000001"), 0)

    def test_exponent_and_underscore_pass(self):
        self.assertEqual(self.value(b"1e3"), 10 ** 9)
        self.assertEqual(self.value(b"1_000"), 10 ** 9)
        self.assertEqual(self.value(b"1_"), 10 ** 6)

    def test_negative(self):
        self.assertEqual(self.value(b"-0.0000005"), 0)
        self.assertEqual(text(b"-0.0000006")["result"], ("error", tool.TAG_DECIMALS))
        self.assertEqual(text(b"-1")["result"], ("error", tool.TAG_DECIMALS))

    def test_top(self):
        self.assertEqual(text(b"9223372036854.775806")["result"], ("error", tool.TAG_BALANCE))
        self.assertEqual(text(b"9223372036854.775807")["result"], ("error", tool.TAG_DECIMALS))
        self.assertEqual(self.value(b"184467440737.095516"), TOP // 100)
        self.assertEqual(text(b"184467440737.095517")["result"], ("error", tool.TAG_BALANCE))

    def test_no_user_side_cap_at_the_system_bound(self):
        self.assertGreater(tool.WHOLE_CAP, tool.CAP)
        self.assertEqual(text(b"922337203685.477581")["result"], ("error", tool.TAG_BALANCE))
        self.assertEqual(text(b"922337203685.477580")["result"], ("error", tool.TAG_BALANCE))

    def test_system_bound(self):
        got = run(Case("t", entry="system", amount=tool.CAP, to_perp=1))
        self.assertEqual(got["result"], ("error", tool.TAG_NUMBER, tool.CAP))

    def test_length_bound(self):
        self.assertEqual(text(b"0" * 100)["result"], ("ok",))
        self.assertEqual(text(b"0" * 101)["result"], ("error", tool.TAG_LENGTH))

    def test_empty_is_the_only_0x131(self):
        self.assertEqual(text(b"")["result"], ("error", tool.TAG_AMOUNT))
        self.assertEqual(text(b"x")["result"], ("error", tool.TAG_PARSE))


class Suffix(unittest.TestCase):
    def test_target_is_the_sub_account(self):
        got = text(b"7 subaccount:" + tool.SUB_TEXT)
        self.assertEqual(got["state"]["user"], USER_B)
        self.assertEqual(got["events"][0], ("auth", USER_B))
        self.assertEqual(got["events"][1], ("user row", USER_B))

    def test_refused_sub_account(self):
        got = text(b"7 subaccount:" + tool.SUB_TEXT, refuse=1)
        self.assertEqual(got["result"], ("error", tool.TAG_SUB))

    def test_second_separator_stays_in_the_address(self):
        got = text(b"7 subaccount:" + tool.SUB_TEXT + b"subaccount:1")
        self.assertEqual(got["result"], ("error", tool.TAG_ADDRESS))

    def test_address_runs_before_the_amount(self):
        self.assertEqual(text(b"x subaccount:0x12")["result"], ("error", tool.TAG_ADDRESS))
        self.assertEqual(text(b"x subaccount:" + tool.SUB_TEXT)["result"], ("error", tool.TAG_PARSE))

    def test_trim_is_unicode_and_only_with_a_suffix(self):
        self.assertEqual(text("7　subaccount:".encode() + tool.SUB_TEXT)["result"], ("ok",))
        self.assertEqual(text(b"7\x1fsubaccount:" + tool.SUB_TEXT)["result"], ("error", tool.TAG_PARSE))
        self.assertEqual(text(b"7 ")["result"], ("error", tool.TAG_PARSE))

    def test_address_padding(self):
        self.assertEqual(text(b"7 subaccount:0x00" + tool.HEX_B)["result"], ("ok",))
        self.assertEqual(text(b"7 subaccount:0x10" + tool.HEX_B)["result"], ("error", tool.TAG_ADDRESS))
        self.assertEqual(text(b"7 subaccount:0X" + tool.HEX_B)["result"], ("error", tool.TAG_ADDRESS))
        self.assertEqual(text(b"7 subaccount:" + tool.HEX_B)["result"], ("ok",))


class Kinds(unittest.TestCase):
    def check(self, kind, flags):
        return run(Case("t", entry="system", amount=5, to_perp=1, balances=FULL, kind=kind, flags=flags))["result"]

    def test_kind_flags(self):
        self.assertEqual(self.check(2, (0, 0)), ("ok",))
        self.assertEqual(self.check(3, (1, 0)), ("error", tool.TAG_FEATURE))
        self.assertEqual(self.check(3, (0, 1)), ("ok",))
        self.assertEqual(self.check(4, (0, 1)), ("error", tool.TAG_FEATURE))
        self.assertEqual(self.check(4, (1, 0)), ("ok",))


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
        case = Case("t", amount=7, balances=((0, 700, 0),))
        want = tool.spec_for(case)
        want["total"] += 1
        self.assertFalse(tool.same(case, HARNESS.run(case), want))

    def test_factor_edit(self):
        self.assertTrue(killed(flip(0x270F963), Case("t", amount=7, balances=FULL)))

    def test_mode_edit(self):
        self.assertTrue(killed(flip(0x2717D22), Case("t", entry="apply", amount=7, to_perp=1, balances=FULL)))

    def test_gate_constant_edit(self):
        self.assertTrue(killed(flip(0x270FAD3, 2), Case("t", amount=tool.GATE_LIMIT - 1, scale=tool.to_bits(0.25), balances=FULL)))

    def test_divisor_edit(self):
        self.assertTrue(killed(flip(0x270FDF2), Case("t", amount=10 ** 9, balances=FULL)))

    def test_row_offset_edit(self):
        self.assertTrue(killed(flip(0x270FE09, 8), Case("t", amount=10 ** 9, balances=FULL)))

    def test_length_bound_edit(self):
        self.assertTrue(killed(flip(0x1E6086D), Case("t", entry="user", text=b"0" * 100, to_perp=1)))

    def test_rescale_mode_edit(self):
        self.assertTrue(killed(flip(0x3980BB7, 2), Case("t", entry="user", text=b"0.0000015", to_perp=1, balances=FULL)))

    def test_rescale_exponent_edit(self):
        self.assertTrue(killed(flip(0x3980BBC), Case("t", entry="user", text=b"1.5", to_perp=1, balances=FULL)))

    def test_system_cap_edit(self):
        self.assertTrue(killed(flip(0x1E64545), Case("t", entry="system", amount=tool.CAP, to_perp=1)))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.LEDGER)
        with self.assertRaises(tool.Halt):
            harness.run(Case("t", amount=7, balances=FULL))

    def test_changed_tag_text_is_noticed(self):
        data = bytearray(IMAGE.blob)
        at = IMAGE.offset(0x5A8311)
        data[at] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))


class Evidence(unittest.TestCase):
    def test_retained_files_match(self):
        names = sorted(path.name for path in FOLDER.iterdir() if path.name not in ("README.md", "MANIFEST.sha256", "mutations.tsv", "evidence.json"))
        for name in names:
            if name in FILES and name != "outcomes.tsv":
                self.assertEqual((FOLDER / name).read_text(encoding="ascii"), FILES[name], name)

    def test_outcomes_of_named_cases_match(self):
        self.assertEqual((FOLDER / "outcomes.tsv").read_text(encoding="ascii"), FILES["outcomes.tsv"])

    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertEqual({line.split("  ", 1)[1] for line in lines}, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["named_cases"], len(RESULT["cases"]))
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(summary["mutations"]["total"], len(rows))
        self.assertEqual(summary["mutations"]["killed"], sum(1 for row in rows if row.split("\t")[3] == "killed"))

    def test_every_reference_row_names_a_real_case(self):
        names = {case.name for case in RESULT["cases"]}
        for row in tool.REFERENCE:
            self.assertIn(row[3], names, row[0])

    def test_survivors_have_a_reason(self):
        for row in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            cells = row.split("\t")
            if cells[3] == "survived":
                self.assertNotEqual(cells[4], "unclassified", cells[1])

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word + chr(47), data, name)


if __name__ == "__main__":
    unittest.main()
