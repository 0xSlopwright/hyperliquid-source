"""Tests for tools/bridge_withdraw_fee_route.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_withdraw_fee_route", ROOT / "tools" / "bridge_withdraw_fee_route.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-withdraw-fee-route-94"


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.spec = tool.Spec(tool.float_constants(cls.image))
        cls.cases = {case.label: case for case in tool.all_cases()}

    setUpClass = classmethod(prepare)

    def run_label(self, label):
        return tool.compare(self.harness, self.spec, self.cases[label])

    def poke(self, patches):
        self.harness.machine.patches = patches
        self.harness.machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()

    def flip(self, va, at, kind="branch"):
        self.poke(tool.mutate_patch(self.image, va, at, kind))


class Input(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256"):
            tool.load_image(expected="0" * 64)

    def test_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)

    def test_address_outside_every_fde(self):
        image = tool.load_image()
        with self.assertRaises(tool.EvidenceError):
            image.exact_fde(tool.SPLIT + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)


class Rules(unittest.TestCase):
    spec = tool.Spec((-9223372036854775808.0, 9223372036854775807.0, 9223372036854774784.0))

    def test_share_truncates(self):
        self.assertEqual(tool.share_of(1, 3, 10, *self.spec_floats()), 3)

    def spec_floats(self):
        return self.spec.low, self.spec.high, self.spec.top

    def test_share_zero_stake_total_rounding(self):
        self.assertEqual(tool.share_of(1, 1000000, 3, *self.spec_floats()), 0)

    def test_share_equal_to_fee_for_one_validator(self):
        self.assertEqual(tool.share_of(5, 5, 1000, *self.spec_floats()), 1000)

    def test_share_top_saturates(self):
        self.assertEqual(tool.share_of(1, 1, tool.I64_MAX, *self.spec_floats()), tool.I64_MAX)

    def test_saturate(self):
        self.assertEqual(tool.saturate(1 << 70), tool.I64_MAX)
        self.assertEqual(tool.saturate(-(1 << 70)), tool.I64_MIN)

    def test_two_copies_of_a_case_share_a_rule(self):
        cases = tool.route_cases()
        labels = {(case.kind, case.label.split("/")[1]) for case in cases}
        self.assertEqual(len(cases), 3 * len(labels))


class Static(Base):
    def test_status_texts_read(self):
        rows = {row[0]: row for row in map(lambda tag: tool.status_row(self.image, tag), tool.STATUS_TAGS)}
        self.assertTrue(rows[0x5C][3])
        self.assertTrue(rows[0x5B][3])

    def test_float_constants_are_the_i64_edges(self):
        low, high, top = tool.float_constants(self.image)
        self.assertEqual(low, -9223372036854775808.0)
        self.assertLess(top, high)

    def test_split_has_two_callers(self):
        self.assertEqual(len(tool.direct_sites(self.harness, tool.SPLIT)), 2)

    def test_debit_slot_has_three_sites_send_slot_six(self):
        self.assertEqual(len(tool.slot_sites(self.harness, tool.SLOT_DEBIT)), 3)
        self.assertEqual(len(tool.slot_sites(self.harness, tool.SLOT_SEND)), 6)

    def test_every_survivor_class_names_a_real_row(self):
        for va in tool.SURVIVOR_CLASS:
            self.image.fde(va)

    def test_route_has_one_caller(self):
        self.assertEqual(tool.direct_sites(self.harness, tool.ROUTE), [tool.WRAPPER + 0x52])

    def test_copies_pair_call_for_call(self):
        for start in tool.ROUTE_COPIES:
            self.assertEqual(len(self.harness.copy_calls[start]), 17)

    def test_location_paths_are_relative(self):
        for row in tool.location_rows(self.harness):
            self.assertFalse(row[2].startswith("/"))

    def test_folder_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)


class Bytes(Base):
    def test_every_named_split_case(self):
        for label, case in self.cases.items():
            if label.startswith("split/") and "random" not in label:
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_every_named_debit_and_send_case(self):
        for label, case in self.cases.items():
            if label.split("/")[0] in ("debit", "send") and "random" not in label:
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_route_cases_on_all_copies(self):
        for label, case in self.cases.items():
            if label[:5] in ("route", "wrap0", "wrap1", "wrap2"):
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_named_transfer_cases(self):
        for label, case in self.cases.items():
            if label.startswith(("amount0/", "prepare0/")) and "random" not in label:
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_closing_cases_on_all_copies(self):
        for label, case in self.cases.items():
            if label[:4] == "tail" or label[:6] == "finish":
                self.assertIsNone(tool.compare(self.harness, self.spec, case), label)

    def test_x_at_fee_refused_and_above_passes(self):
        self.assertIsNone(self.run_label("debit/x_at_fee"))
        self.assertIsNone(self.run_label("debit/x_above_fee_by_one"))


class Negative(Base):
    def assert_breaks(self, label):
        try:
            result = tool.compare(self.harness, self.spec, self.cases[label])
        except (tool.Halt, tool.Panicked, KeyError, tool.EvidenceError):
            return
        self.assertIsNotNone(result, label)

    def test_fee_gate_flip(self):
        self.flip(0x370DA8E, 0)
        self.assert_breaks("debit/x_at_fee")

    def test_room_gate_flip(self):
        self.flip(0x370DAB5, 0)
        self.assert_breaks("debit/x_one_over_room")

    def test_stake_read_offset(self):
        self.flip(0x370DF0E, 4, "offset")
        self.assert_breaks("split/epoch_found_three")

    def test_zero_stake_skip_flip(self):
        self.flip(0x370DF34, 0)
        self.assert_breaks("split/zero_among")

    def test_rest_test_flip(self):
        self.flip(0x370E1A6, 0)
        self.assert_breaks("split/fee_one")

    def test_hot_user_offset(self):
        self.flip(0x370E0C1, 6, "offset")
        self.assert_breaks("split/epoch_found_three")

    def test_route_class_gate_flip(self):
        self.flip(0x2732571, 1)
        self.assert_breaks("route0/class_0_00")

    def test_limit_status_immediate(self):
        self.poke({0x2732840: 0x71})
        self.assert_breaks("route0/limit_both_fail")

    def test_amount_divisor_constant(self):
        self.poke({0x272D44A: 0x29})
        self.assert_breaks("amount0/spot_to_dex")

    def test_amount_token_gate_flip(self):
        self.flip(0x272D307, 1)
        self.assert_breaks("amount0/dex_source_to_spot")

    def test_tag_gate_flip(self):
        self.flip(0x272DA2F, 1)
        self.assert_breaks("tail0/tag_2_token_listed")

    def test_finish_mode_immediate(self):
        self.poke({0x272F9E2: 0x03})
        self.assert_breaks("finish0/listed")

    def test_changed_fixture_breaks_the_match(self):
        case = self.cases["split/epoch_found_three"]
        wrong = tool.Case(case.label, case.kind, amount=case.fields["amount"] + 10, world=case.fields["world"])
        self.harness.reset()
        tool.prepare(self.harness, wrong)
        self.harness.machine.run(tool.SPLIT, {tool.RDI: tool.DEX_AT, tool.RSI: wrong.fields["amount"], tool.RDX: tool.STAKING_AT, tool.RCX: tool.TRACKER_AT})
        want = dict(case.fields["world"], rows={}, events=[])
        self.spec.split(want, case.fields["amount"], tool.TRACKER_AT)
        self.assertNotEqual(sum(word for word, _ in want["rows"].values()), sum(self.harness.machine.memory.read(at, 8) for at in self.harness.rows.values()))


class Output(unittest.TestCase):
    def test_render_is_ascii_without_mark(self):
        for path in FOLDER.iterdir():
            if path.suffix in (".tsv", ".json"):
                data = path.read_bytes()
                self.assertTrue(all(byte < 128 for byte in data), path.name)
                self.assertNotIn(b"\x40", data, path.name)


if __name__ == "__main__":
    unittest.main()
