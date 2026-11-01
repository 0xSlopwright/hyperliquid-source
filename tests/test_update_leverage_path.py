"""Tests for tools/update_leverage_path.py: real node #94 bytes with corruption controls."""

import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-004-update-leverage-path-94"
spec_ = importlib.util.spec_from_file_location("update_leverage_path", ROOT / "tools" / "update_leverage_path.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["update_leverage_path"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
FILES = None
Case = tool.Case
TOP = tool.TOP
USER_A, USER_B = tool.USER_A, tool.USER_B
holder = tool.holder
ROW = tool.ROW
CROSS_ROW = tool.CROSS_ROW


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
    base = dict(entry="body", users=(holder(),), opens=((0, 1000),), level=8)
    base.update(fields)
    return run(Case("t", **base))


def update(**fields):
    base = dict(entry="update", wire=("perp", 0), users=(holder(),), opens=((0, 1000),), level=8, dexes=2)
    base.update(fields)
    return run(Case("t", **base))


def row_of(got, asset=0):
    data = dict(got["state"]["rows"])[asset]
    mode, leverage, margin, size = struct.unpack_from("<IIqq", data)
    return mode, leverage, margin, size, struct.unpack_from("<I", data, 0x38)[0]


def names(got):
    return [event[0] for event in got["events"]]


def killed(patch, case):
    harness = tool.Harness(IMAGE, patch)
    harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
    return tool.first_failure(harness, [case]) is not None


def flip(address, mask=1):
    return {address: IMAGE.blob[IMAGE.offset(address)] ^ mask}


class Gates(unittest.TestCase):
    def test_raise_writes_level_and_index(self):
        got = body()
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(row_of(got)[1], 8)
        self.assertIn(("index", 0, 8), got["events"])

    def test_same_level_has_no_index_call(self):
        self.assertEqual(names(body(level=5)).count("index"), 0)

    def test_cross_needs_kind_zero(self):
        for kind in (1, 2):
            self.assertEqual(body(cross=1, perps=((kind, 20, 20),))["result"], ("error", tool.TAG_CROSS))
        self.assertEqual(body(perps=((2, 20, 20),))["result"], ("ok",))

    def test_small_table_id_is_the_cap(self):
        self.assertEqual(body(level=20)["result"], ("ok",))
        self.assertEqual(body(level=21)["result"], ("error", tool.TAG_LEVERAGE))

    def test_boundary_of_the_small_ids(self):
        got = body(perps=((0, 20, 49),), level=49, users=(holder(rows=((0, 1, 5, 7000, 1000, 49),),),))
        self.assertEqual(got["result"], ("ok",))
        self.assertEqual(body(perps=((0, 20, 50),))["result"], ("panic",))

    def test_first_tier_is_the_cap(self):
        fields = dict(perps=((0, 20, 50),), tables=((50, (25, 10)),))
        self.assertEqual(body(level=26, **fields)["result"], ("error", tool.TAG_LEVERAGE))
        self.assertEqual(body(level=25, users=(holder(rows=((0, 1, 5, 7000, 1000, 50),),),), **fields)["result"], ("ok",))

    def test_no_tiers_caps_at_three(self):
        fields = dict(perps=((0, 20, 51),), tables=((51, ()),))
        self.assertEqual(body(level=4, **fields)["result"], ("error", tool.TAG_LEVERAGE))
        self.assertEqual(body(level=3, users=(holder(rows=((0, 1, 2, 7000, 1000, 51),),),), **fields)["result"], ("ok",))

    def test_kind_gate_runs_before_the_level_gate(self):
        self.assertEqual(body(cross=1, level=21, perps=((1, 20, 20),))["result"], ("error", tool.TAG_CROSS))

    def test_switch_refused_with_a_position(self):
        self.assertEqual(body(cross=1)["result"], ("error", tool.TAG_SWITCH))
        self.assertEqual(body(users=(holder(rows=(CROSS_ROW,),),))["result"], ("error", tool.TAG_SWITCH))

    def test_mode_two_counts_as_isolated_here(self):
        self.assertEqual(body(users=(holder(rows=((0, 2, 5, 7000, 1000, 20),),),))["result"], ("ok",))

    def test_cap_helper_edge_and_payload(self):
        self.assertEqual(body(cap=7)["result"], ("error", tool.TAG_CAP, 7))
        self.assertEqual(body(cap=8)["result"], ("ok",))

    def test_cap_helper_skipped_on_empty_row(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, 0, 20),),),), cap=0)
        self.assertEqual(got["result"], ("ok",))
        self.assertNotIn("cap", names(got))

    def test_price_past_the_list_panics(self):
        self.assertEqual(body(asset=1, perps=((0, 20, 20),) * 2, users=(holder(rows=((1, 1, 5, 1, 1, 20),),),), opens=())["result"], ("panic",))


class Checks(unittest.TestCase):
    def test_lowering_runs_mode_one(self):
        got = body(level=2)
        self.assertEqual([event[1] for event in got["events"] if event[0] == "check"], [1])

    def test_raise_runs_no_check(self):
        self.assertNotIn("check", names(body()))

    def test_lowering_refusal_tags(self):
        self.assertEqual(body(level=2, checks=(TOP, 0))["result"], ("error", tool.TAG_ISOLATED_LOW))
        self.assertEqual(body(users=(holder(rows=(CROSS_ROW,),),), cross=1, level=2, checks=(TOP, 0))["result"], ("error", tool.TAG_CROSS_LOW))

    def test_refusal_leaves_the_row(self):
        got = body(level=2, checks=(TOP, 0))
        self.assertEqual(row_of(got)[1], 5)
        self.assertEqual(got["state"]["touched"], ())

    def test_table_change_runs_mode_two_first(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, 1000, 30),),),), level=3)
        self.assertEqual([event[1] for event in got["events"] if event[0] == "check"], [2, 1])

    def test_table_refusal_carries_the_name(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, 1000, 30),),),), checks=(0, TOP))
        self.assertEqual(got["result"], ("error", tool.TAG_TABLE, b"TEST"))

    def test_clone_holds_new_level_and_table(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, 1000, 30),),),), level=3)
        event = [event for event in got["events"] if event[0] == "check"][0]
        self.assertEqual(event[4:6], (3, 20))

    def test_table_word_written_on_success(self):
        self.assertEqual(row_of(body(users=(holder(rows=((0, 1, 5, 7000, 1000, 30),),),)))[4], 20)


class Writes(unittest.TestCase):
    def test_new_row_runs_default_twice(self):
        got = body(users=(holder(rows=(), count=0),), opens=())
        self.assertEqual(names(got).count("default row"), 2)
        self.assertEqual(row_of(got)[:2], (1, 8))

    def test_cross_to_isolated_clears_margin(self):
        got = body(users=(holder(rows=((0, 0, 5, 7000, 0, 20),),),))
        self.assertEqual(row_of(got)[:3], (1, 8, 0))

    def test_isolated_to_cross_keeps_margin(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, 0, 20),),),), cross=1, level=2)
        self.assertEqual(row_of(got)[:3], (0, 2, 7000))

    def test_refusal_leaves_touched_success_joins(self):
        self.assertEqual(body(level=21)["state"]["touched"], ())
        self.assertEqual(body()["state"]["touched"], (USER_A,))

    def test_smallest_size_panics_after_the_write(self):
        got = body(users=(holder(rows=((0, 1, 5, 7000, -(1 << 63), 20),),),))
        self.assertEqual(got["result"], ("panic",))
        self.assertEqual(row_of(got)[1], 8)


class Wrapper(unittest.TestCase):
    def test_all_copies_direct(self):
        for copy in range(3):
            self.assertEqual(update(copy=copy)["result"], ("ok",))

    def test_spot_payload(self):
        for copy in range(3):
            self.assertEqual(update(copy=copy, wire=("spot", 0xBEEF))["result"], ("error", tool.TAG_SPOT, 0xBEEF))

    def test_payloads_pass_the_handler(self):
        self.assertEqual(update(cap=7)["result"], ("error", tool.TAG_CAP, 7))
        self.assertEqual(update(users=(holder(rows=((0, 1, 5, 7000, 1000, 30),),),), checks=(0, TOP))["result"], ("error", tool.TAG_TABLE, b"TEST"))

    def test_no_set_gives_operations_tag(self):
        for copy in range(3):
            self.assertEqual(update(copy=copy, klass=3, sets=(0, 0))["result"], ("error", tool.TAG_OPERATIONS))

    def test_refused_settle_is_dropped(self):
        self.assertEqual(update(klass=3, post=tool.REFUSAL)["result"], ("ok",))

    def test_only_class_four_finishes(self):
        self.assertEqual(names(update(klass=4)).count("finish"), 1)
        self.assertEqual(names(update(klass=5)).count("finish"), 0)


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
        case = Case("t", entry="body", users=(holder(),), opens=((0, 1000),), level=8)
        want = tool.spec_for(case)
        want["result"] = ("error", tool.TAG_LEVERAGE)
        self.assertFalse(tool.same(case, HARNESS.run(case), want))

    def test_small_id_bound_edit(self):
        self.assertTrue(killed(flip(0x3709982 + 2), Case("t", entry="body", users=(holder(),), perps=((0, 20, 50),), tables=((50, (9,)),), level=8, opens=((0, 1000),))))

    def test_level_compare_edit(self):
        self.assertTrue(killed(flip(0x3709B90), Case("t", entry="body", users=(holder(),), level=20, opens=((0, 1000),))))

    def test_empty_table_word_edit(self):
        self.assertTrue(killed(flip(0x3709AEC + 1), Case("t", entry="body", users=(holder(),), perps=((0, 20, 51),), tables=((51, ()),), level=3, opens=((0, 1000),))))

    def test_cross_kind_edit(self):
        self.assertTrue(killed(flip(0x3709916), Case("t", entry="body", cross=1, users=(holder(rows=(CROSS_ROW,),),), opens=((0, 1000),))))

    def test_margin_clear_edit(self):
        self.assertTrue(killed(flip(0x3709E5F + 4), Case("t", entry="body", users=(holder(rows=((0, 0, 5, 7000, 0, 20),),),), opens=((0, 1000),))))

    def test_low_tag_edit(self):
        self.assertTrue(killed(flip(0x370A2F0 + 1), Case("t", entry="body", level=2, checks=(TOP, 0), users=(holder(),), opens=((0, 1000),))))

    def test_unmodelled_call_stops(self):
        harness = tool.Harness(IMAGE)
        harness.machine.calls.pop(tool.ROWS)
        with self.assertRaises(tool.Halt):
            harness.run(Case("t", entry="body", users=(holder(),), opens=((0, 1000),), level=8))

    def test_changed_text_is_noticed(self):
        data = bytearray(IMAGE.blob)
        data[IMAGE.offset(tool.CAP_TEXT)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(tool.Image(bytes(data)))


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

    def test_callers_of_the_body(self):
        rows = RESULT["callers"]
        self.assertEqual(sorted({row[3] for row in rows}), ["0x2721860", "0x4d26cc0", "0x4d27490"])
        self.assertEqual(len(rows), 9)

    def test_rendering_is_stable(self):
        self.assertEqual(tool.render(RESULT), FILES)

    def test_no_decorator_character_or_absolute_path(self):
        for name, data in FILES.items():
            self.assertNotIn(chr(64), data, name)
            for word in ("tmp", "home", "srv", "mnt"):
                self.assertNotIn(chr(47) + word + chr(47), data, name)


if __name__ == "__main__":
    unittest.main()
