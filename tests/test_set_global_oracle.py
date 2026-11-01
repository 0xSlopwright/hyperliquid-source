"""Tests for tools/set_global_oracle.py: real node #94 bytes with corruption controls."""

import fractions
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-set-global-oracle-94"
spec_ = importlib.util.spec_from_file_location("set_global_oracle", ROOT / "tools" / "set_global_oracle.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["set_global_oracle"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
Dex = tool.Dex
Fraction = fractions.Fraction
DAY0 = tool.DAY0
DAY1 = tool.DAY1


def setUpModule():
    global IMAGE, HARNESS, RESULT, FILES
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=20)
    FILES = tool.render(RESULT)


def run(**fields):
    case = Case("t", **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case, HARNESS)), got["result"]
    return got


def stale(*dexes, **fields):
    case = Case("t", entry="refresh", dexes=dexes, **fields)
    got = HARNESS.run(case)
    assert tool.same(case, got, tool.spec_for(case, HARNESS)), got["events"]
    return got


def steps(got):
    return [event for event in got["events"] if event[0] == "timestep"]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Lists(unittest.TestCase):
    def test_rows_are_positional(self):
        got = run(pxs=(("1.5", None), (None, "2"), (None, None)))
        self.assertEqual(steps(got)[0][1], ((Fraction(3, 2), None, None), (None, Fraction(2), None), (None, None, None)))

    def test_external_moves_into_its_row(self):
        got = run(pxs=(("1", None), ("2", None)), ext=(("ETH", "7.25"),))
        self.assertEqual(steps(got)[0][1][1], (Fraction(2), None, Fraction(29, 4)))
        self.assertIsNone(steps(got)[0][1][0][2])

    def test_key_packs_the_dex_id(self):
        got = run(dex=2, pxs=(("1", None), ("2", None)), ext=(("ETH", "4"),))
        self.assertEqual(steps(got)[0][1][1][2], Fraction(4))

    def test_external_past_the_rows_is_dropped(self):
        got = run(ext=(("HYPE", "9"),))
        self.assertEqual(steps(got)[0][1], ())
        self.assertEqual(got["result"][0], "ok")

    def test_unknown_name_skips_its_price(self):
        for text in ("x", "-1", "1" * 101):
            self.assertEqual(run(pxs=(("1", "2"),), ext=(("DOGE", text),))["result"][0], "ok")

    def test_first_of_equal_names(self):
        got = run(names=("AAA", "BBB", "AAA"), pxs=(("1", None), ("2", None), ("3", None)), ext=(("AAA", "6"),))
        self.assertEqual([row[2] for row in steps(got)[0][1]], [Fraction(6), None, None])

    def test_length_edges(self):
        self.assertEqual(run(pxs=(("1", None),), pxs_word=10001)["result"], ("error", tool.TAG_BOUND, "pxs"))
        self.assertEqual(run(ext=(("BTC", "1"),), ext_word=10001)["result"], ("error", tool.TAG_BOUND, "externalPerpPxs"))
        self.assertEqual(run(pxs=(("0", None),), pxs_word=10000)["result"], ("error", tool.TAG_POSITIVE))

    def test_text_length_edges(self):
        self.assertEqual(run(pxs=(("1" * 101, None),))["result"][:2], ("error", tool.TAG_BOUND))
        self.assertEqual(run(pxs=(("1" * 100, None),))["result"], ("error", tool.PARSE_TAG))
        self.assertEqual(run(ext=(("BTC", "1" * 101),))["result"][:2], ("error", tool.TAG_BOUND))

    def test_positive_gate_uses_decimal(self):
        self.assertEqual(run(pxs=(("0", None),))["result"], ("error", tool.TAG_POSITIVE))
        self.assertEqual(run(pxs=(("-0.5", None),))["result"], ("error", tool.TAG_POSITIVE))
        self.assertEqual(run(pxs=(("0.0000000000000000000000000001", None),))["result"][0], "ok")
        self.assertEqual(run(pxs=(("1", "-1"),))["result"], ("error", tool.TAG_POSITIVE))

    def test_parser_forms(self):
        self.assertEqual(steps(run(pxs=(("1e3", None),)))[0][1][0][0], Fraction(1000))
        self.assertEqual(steps(run(pxs=(("1_000", None),)))[0][1][0][0], Fraction(1000))
        self.assertEqual(run(pxs=((" 1", None),))["result"], ("error", tool.PARSE_TAG))


class Order(unittest.TestCase):
    def test_price_beats_signer(self):
        self.assertEqual(run(pxs=(("0", None),), auth=0x97)["result"], ("error", tool.TAG_POSITIVE))

    def test_signer_refusal_has_one_tag(self):
        for status in (0x97, 0x91):
            got = run(pxs=(("1", "2"),), auth=status)
            self.assertEqual(got["result"], ("error", tool.TAG_SIGNER))
            self.assertEqual(steps(got), [])

    def test_timestep_runs_before_the_words(self):
        got = run(step=0x63, native="3", usdt="4")
        self.assertEqual(got["result"], ("error", 0x63))
        self.assertEqual(got["state"]["native"], 0x4242424242424242)

    def test_second_word_refusal_keeps_the_first(self):
        got = run(native="2", usdt="x")
        self.assertEqual(got["result"], ("error", tool.PARSE_TAG))
        self.assertEqual(got["state"]["native"], tool.to_bits(2.0))
        self.assertEqual(len(steps(got)), 1)
        self.assertEqual(got["state"]["history"], ())

    def test_words_have_no_sign_gate(self):
        self.assertEqual(run(native="-2.5")["state"]["native"], tool.to_bits(-2.5))
        self.assertEqual(run(usdt="0")["state"]["usdt"], 0)

    def test_all_copies_agree(self):
        for copy in range(3):
            got = run(copy=copy, pxs=(("1", "2"),), native="31.5", usdt="1.001")
            self.assertEqual(got["state"]["usdt"], tool.to_bits(1.001))
            self.assertEqual(got["state"]["native"], tool.to_bits(31.5))

    def test_no_dex_row_panics(self):
        self.assertEqual(run(dex_rows=0)["result"], ("panic",))


class Ring(unittest.TestCase):
    def rows(self, count, point):
        return tuple(point + (1,) for _ in range(count))

    def test_snapshot_is_cloned(self):
        got = run(snapshot=5)
        self.assertEqual(len(got["state"]["history"][0][1]), 5 * 0x54)

    def test_cap_needs_age(self):
        old = (tool.EARLY, 10, 0)
        self.assertEqual(len(run(hist=self.rows(100, old), room=120)["state"]["history"]), 100)
        self.assertEqual(len(run(hist=self.rows(50, old), room=60)["state"]["history"]), 51)
        self.assertEqual(len(run(hist=self.rows(110, (DAY0, 900, 0)), room=120)["state"]["history"]), 111)

    def test_age_edges(self):
        self.assertEqual(len(run(hist=self.rows(101, (DAY0, 700, 5)), room=110)["state"]["history"]), 102)
        self.assertEqual(len(run(hist=((DAY0, 700, 4, 1),) + self.rows(101, (DAY0, 700, 5)), room=110)["state"]["history"]), 102)

    def test_midnight_edges(self):
        front = self.rows(101, (DAY0, 86399, 5))
        self.assertEqual(len(run(now=(DAY1, 299, 5), hist=front, room=110)["state"]["history"]), 102)

    def test_growth_and_wrap(self):
        self.assertEqual(len(run(hist=self.rows(5, (tool.EARLY, 10, 0)), room=5, head=2)["state"]["history"]), 6)
        self.assertEqual(len(run(hist=(), room=0)["state"]["history"]), 1)


class Refresh(unittest.TestCase):
    def test_tick_word_gate(self):
        got = stale(Dex(1, (2,), (10,)), tick=2)
        self.assertEqual(got["result"], ("idle",))
        self.assertEqual(got["events"], [])

    def test_rows_scale_by_size_decimals(self):
        got = stale(Dex(1, (2,), (1234567,), (1234000,)))
        self.assertEqual(steps(got)[0], ("timestep", 1, ((Fraction(1234567, 10000), Fraction(617, 5), None),)))

    def test_float_route_keeps_its_error(self):
        got = stale(Dex(1, (3,), (4096029,), (4096030,)))
        self.assertEqual(steps(got)[0][2][0][0], Fraction(4096029000000001, 10 ** 12))

    def test_ten_second_edges(self):
        self.assertEqual(len(steps(stale(Dex(1, (2,), (10,), last=(DAY0, 990, 5))))), 1)
        self.assertEqual(len(steps(stale(Dex(1, (2,), (10,), last=(DAY0, 990, 6))))), 0)
        self.assertEqual(len(steps(stale(Dex(1, (2,), (10,), last=(DAY0, 86399, 5)), now=(DAY1, 9, 5)))), 1)

    def test_mode_three_is_skipped(self):
        got = stale(Dex(0, (2,), (10,), mode=3), Dex(1, (2,), (20,)))
        self.assertEqual([event[1] for event in steps(got)], [1])

    def test_groups_step_in_id_order(self):
        got = stale(Dex(3, (2,), (30,)), Dex(1, (2,), (10,)), Dex(2, (2,), (20,)))
        self.assertEqual([event[1] for event in steps(got)], [1, 2, 3])

    def test_same_id_keeps_the_later_rows(self):
        got = stale(Dex(1, (2,), (10,)), Dex(1, (2,), (77,)))
        self.assertEqual(len(steps(got)), 1)
        self.assertEqual(steps(got)[0][2][0][0], tool.float_decimal(77.0 / 10000.0))

    def test_refused_step_goes_on(self):
        self.assertEqual(len(steps(stale(Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), step=0x77))), 2)

    def test_table_list_mismatch_records_and_zips(self):
        got = stale(Dex(1, (2,), (10,)), Dex(2, (2,), (20,)), tables=1)
        self.assertIn(("recorder", 5, tool.RECORD), got["events"])
        self.assertEqual(len(steps(got)), 1)

    def test_panics(self):
        self.assertEqual(stale(Dex(1, (7,), (10,)))["result"], ("panic",))
        self.assertEqual(stale(Dex(1, (2, 2), (10, 11), oracle_rows=1))["result"], ("panic",))
        self.assertEqual(stale(Dex(1, (2, 2), (10, 11), book_rows=1))["result"], ("panic",))
        self.assertEqual(stale(Dex(1 << 52, (2,), (10,)))["result"], ("panic",))

    def test_changed_word_has_no_effect(self):
        one = stale(Dex(1, (2,), (10,), changed=0))
        two = stale(Dex(1, (2,), (10,)))
        self.assertEqual(one["events"], two["events"])

    def test_all_copies_agree(self):
        for copy in range(3):
            self.assertEqual(steps(stale(Dex(1, (2,), (1234567,)), copy=copy))[0][1], 1)


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
            IMAGE.exact_fde(tool.COPIES[0].handler + 1)

    def test_wrong_rule_fails(self):
        case = Case("t")
        got = HARNESS.run(case)
        want = tool.spec_for(case, HARNESS)
        want["result"] = ("error", 1)
        self.assertFalse(tool.same(case, got, want))

    def test_wrong_float_route_fails(self):
        self.assertNotEqual(tool.float_decimal(4096.029), Fraction(4096029, 1000))

    def test_list_bound_edit(self):
        self.assertTrue(killed(flip(0x1F67F50), Case("t", pxs=(("0", None),), pxs_word=10000)))

    def test_map_bound_edit(self):
        self.assertTrue(killed(flip(0x1F67BA2), Case("t", pxs=(("1", "2"),), ext=(("BTC", "1"),), ext_word=10000)))

    def test_age_edit(self):
        self.assertTrue(killed(flip(0x1F681DD), Case("t", hist=((DAY0, 699, 5, 1),) + ((DAY0, 700, 5, 1),) * 101, room=110)))

    def test_length_edit(self):
        self.assertTrue(killed(flip(0x1F68115), Case("t", hist=((tool.EARLY, 10, 0, 1),) * 99, room=120)))

    def test_positive_branch_edit(self):
        self.assertTrue(killed(flip(0x1E82BA8), Case("t", pxs=(("0", None),))))

    def test_store_slot_edit(self):
        self.assertTrue(killed(flip(0x1F68473, 8), Case("t", native="2")))

    def test_refresh_period_edit(self):
        self.assertTrue(killed(flip(0x2228B60), Case("t", entry="refresh", dexes=(Dex(1, (2,), (10,), last=(DAY0, 990, 5)),))))

    def test_refresh_mode_edit(self):
        self.assertTrue(killed(flip(0x2228B2E), Case("t", entry="refresh", dexes=(Dex(1, (2,), (10,), mode=3),))))

    def test_refresh_divisor_edit(self):
        self.assertTrue(killed(flip(0x1E826BF, 8), Case("t", entry="refresh", dexes=(Dex(1, (2,), (1234567,)),))))

    def test_constant_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x1F681DD)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))

    def test_label_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(tool.LABEL_TEXT)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))

    def test_divisor_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x3E0E90 + 8 + 6)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.divisor_rows(tool.Image(bytes(data)))

    def test_key_change_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(0x20AB70)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.wire_rows(tool.Image(bytes(data)))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.COPIES[0].step)
        harness.machine.real = set()
        with self.assertRaises(tool.Halt):
            harness.run(Case("t"))


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
        self.assertEqual(sorted(row[3] for row in rows if row[0] == "handler"), ["0x2759240", "0x4d83050", "0x4d84170"])
        self.assertEqual([row[3] for row in rows if row[1] == "0x2228a10"], ["0x22297c0"])
        self.assertEqual(sorted(row[3] for row in rows if row[1] == "0x27078a0"), ["0x1f67b30", "0x2228a10", "0x273e080"])

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word, data, name)


if __name__ == "__main__":
    unittest.main()
