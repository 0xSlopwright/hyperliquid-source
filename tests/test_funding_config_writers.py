"""Tests for tools/funding_config_writers.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-funding-config-writers-94"
spec_ = importlib.util.spec_from_file_location("funding_config_writers", ROOT / "tools" / "funding_config_writers.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["funding_config_writers"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
BTC, ETH = b"BTC", b"ETH"


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


def setter(kind, *rows, **fields):
    return run(Case("t", steps=((kind, rows, 0),), **fields))


def vote(*step, **fields):
    return run(Case("t", steps=(step,), **fields))


def bits(value):
    return tool.to_bits(value)


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Setters(unittest.TestCase):
    def test_rate_at_the_bound(self):
        got = setter("rate", (BTC, b"0.01"))
        self.assertEqual(got["state"][0, tool.RATE_AT], {0: bits(0.01)})

    def test_rate_either_sign(self):
        self.assertEqual(setter("rate", (BTC, b"-0.01"))["results"], [("ok",)])

    def test_rate_refused(self):
        self.assertEqual(setter("rate", (BTC, b"0.0100000001"))["results"], [("error", tool.TAG_TEXT, tool.RATE_TEXT)])

    def test_multiplier_bounds(self):
        self.assertEqual(setter("mult", (BTC, b"10"))["state"][0, tool.MULT_AT], {0: bits(10.0)})
        self.assertEqual(setter("mult", (BTC, b"0"))["state"][0, tool.MULT_AT], {0: 0})
        self.assertEqual(setter("mult", (BTC, b"-0.000000001"))["results"], [("error", tool.TAG_TEXT, tool.MULT_TEXT)])

    def test_bound_reads_the_rounded_float(self):
        self.assertEqual(setter("mult", (BTC, b"10.00000000000000001"))["results"], [("ok",)])
        self.assertEqual(setter("rate", (BTC, b"0.01000000000000000001"))["results"], [("ok",)])

    def test_key_is_the_whole_id_in_the_row_of_its_dex(self):
        got = setter("rate", (b"xyz:BBB", b"0.002"), (b"abc:CCC", b"0.003"))
        self.assertEqual(got["state"][1, tool.RATE_AT], {10007: bits(0.002)})
        self.assertEqual(got["state"][2, tool.RATE_AT], {20003: bits(0.003)})
        self.assertEqual(got["state"][0, tool.RATE_AT], {})

    def test_a_refused_row_writes_nothing(self):
        got = setter("rate", (b"ETH", b"0.001"), (b"xyz:AAA", b"0.5"))
        self.assertEqual(got["state"][0, tool.RATE_AT], {})

    def test_panic_keeps_earlier_rows(self):
        got = setter("rate", (BTC, b"0.001"), (b"far:OUT", b"0.002"))
        self.assertEqual(got["results"], [("panic",)])
        self.assertEqual(got["state"][0, tool.RATE_AT], {0: bits(0.001)})

    def test_value_is_read_before_the_name(self):
        self.assertEqual(setter("rate", (tool.NAME_101, b"0.5"))["results"], [("error", tool.TAG_TEXT, tool.RATE_TEXT)])

    def test_nan_passes_both_bounds(self):
        nan = 0x7FF8000000000000
        for kind in ("mult", "rate"):
            got = run(Case("t", inject=((nan, 1),), steps=((kind, ((BTC, b"1"),), 0),)))
            self.assertEqual(got["results"], [("ok",)])

    def test_replace_keeps_one_row(self):
        got = run(Case("t", steps=(("rate", ((BTC, b"0.001"),), 0), ("rate", ((BTC, b"0.002"),), 0))))
        self.assertEqual(got["state"][0, tool.RATE_AT], {0: bits(0.002)})


class Votes(unittest.TestCase):
    def test_default_floor_is_exact(self):
        self.assertEqual(vote(tool.WORD_DEFAULT, 6000000000)["state"][0, tool.DEFAULT_AT], 6000000000)
        self.assertEqual(vote(tool.WORD_DEFAULT, 5999999999)["results"], [("error", tool.TAG_IMPACT)])

    def test_default_cap(self):
        self.assertEqual(vote(tool.WORD_DEFAULT, tool.CAP)["results"], [("error", tool.TAG_NUMBER, tool.CAP)])

    def test_override_floor(self):
        self.assertEqual(vote(tool.WORD_OVERRIDE, ((BTC, 600000000),), 0, None)["state"][0, tool.OVERRIDE_AT], {0: 600000000})
        self.assertEqual(vote(tool.WORD_OVERRIDE, ((BTC, 599999999),), 0, None)["results"], [("error", tool.TAG_IMPACT)])

    def test_override_stops_midway_and_keeps_earlier_rows(self):
        got = vote(tool.WORD_OVERRIDE, ((BTC, 10 ** 9), (ETH, 5)), 0, None)
        self.assertEqual(got["results"], [("error", tool.TAG_IMPACT)])
        self.assertEqual(got["state"][0, tool.OVERRIDE_AT], {0: 10 ** 9})

    def test_override_refused_number_reports_the_previous_row(self):
        got = vote(tool.WORD_OVERRIDE, ((BTC, 10 ** 9), (ETH, tool.CAP)), 0, None)
        self.assertEqual(got["results"], [("error", tool.TAG_NUMBER, 10 ** 9)])

    def test_override_list_cap(self):
        self.assertEqual(vote(tool.WORD_OVERRIDE, (), 0, tool.LIST_CAP)["results"], [("ok",)])
        self.assertEqual(vote(tool.WORD_OVERRIDE, (), 0, tool.LIST_CAP + 1)["results"], [("error", tool.TAG_LENGTH)])

    def test_clamp_stored_on_dex_zero(self):
        self.assertEqual(vote(tool.WORD_CLAMP, b"0.5")["state"][0, tool.CLAMP_AT], bits(0.5))

    def test_clamp_refusals(self):
        self.assertEqual(vote(tool.WORD_CLAMP, b"-1")["results"], [("error", tool.TAG_CLAMP)])
        for value in (0x7FF0000000000000, 0x7FF8000000000000, 0xFFF0000000000000, 1 | 1 << 63):
            self.assertEqual(run(Case("t", inject=((value, 1),), steps=((tool.WORD_CLAMP, b"1"),)))["results"], [("error", tool.TAG_CLAMP)])

    def test_clamp_keeps_negative_zero(self):
        got = run(Case("t", inject=((1 << 63, 1),), steps=((tool.WORD_CLAMP, b"1"),)))
        self.assertEqual(got["state"][0, tool.CLAMP_AT], 1 << 63)

    def test_text_forms_the_parser_takes(self):
        for text, value in ((b"+1", 1.0), (b"1e1", 10.0), (b"1_0", 10.0), (b".5", 0.5), (b"5.", 5.0)):
            self.assertEqual(tool.parsed(text), ("value", bits(value)))
        self.assertEqual(tool.parsed(b"79228162514264337593543950336"), tool.parsed(b"79228162514264337593543950335"))

    def test_text_the_parser_refuses(self):
        for text in (b"", b" 1", b"abc", b"NaN", b"inf", b"0x10"):
            self.assertEqual(tool.parsed(text), ("tag", 0xAC))


class Controls(unittest.TestCase):
    def test_rate_bound_edit_fails(self):
        self.assertTrue(killed(flip(0x2743A0E), Case("t", steps=(("rate", ((BTC, b"0.5"),), 0),))))

    def test_multiplier_field_edit_fails(self):
        self.assertTrue(killed(flip(0x273CD1A, 0x20), Case("t", steps=(("mult", ((BTC, b"1"),), 0),))))

    def test_override_floor_edit_fails(self):
        self.assertTrue(killed(flip(0x235791D, 1), Case("t", steps=((tool.WORD_OVERRIDE, ((BTC, 600000000),), 0, None),))))

    def test_default_floor_edit_fails(self):
        self.assertTrue(killed(flip(0x235733C, 1), Case("t", steps=((tool.WORD_DEFAULT, 6000000000),))))

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
            IMAGE.exact_fde(tool.MAP_F64 + 1)


class Evidence(unittest.TestCase):
    def test_texts_are_in_the_binary(self):
        texts = {row[1] for row in RESULT["texts"]}
        self.assertLessEqual({tool.MULT_TEXT.decode(), tool.RATE_TEXT.decode()}, texts)
        self.assertEqual(len(texts), 3)
        self.assertTrue(RESULT["texts"][2][1].endswith(tool.FUNDING_STRUCT.decode()))

    def test_copies_read_the_same_arm_shape(self):
        for row in RESULT["copies"]:
            self.assertEqual(len(row), 10)

    def test_field_offsets_follow_each_setter(self):
        for copy in tool.COPIES:
            for kind, field in (("mult", 0x78), ("rate", 0xA8)):
                start, end = IMAGE.exact_fde(copy.setters[kind])
                data = bytes(IMAGE.blob[IMAGE.offset(start):IMAGE.offset(end)])
                self.assertIn(b"\x48\x83\xc7" + bytes([field]) if field < 0x80 else b"\x48\x81\xc7" + struct.pack("<I", field), data)

    def test_generated_files_match_the_folder(self):
        for name in ("constants.tsv", "error-texts.tsv", "tag-texts.tsv", "reference-diff.tsv", "callers.tsv", "copies.tsv", "outcomes.tsv", "function-rows.tsv"):
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
