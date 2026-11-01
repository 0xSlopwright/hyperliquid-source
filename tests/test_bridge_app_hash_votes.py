"""Tests for tools/bridge_app_hash_votes.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_app_hash_votes", ROOT / "tools" / "bridge_app_hash_votes.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-app-hash-votes-94"


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.cases = {case.label: case for case in tool.all_cases()}

    setUpClass = classmethod(prepare)

    def run_label(self, label):
        return tool.compare(self.harness, None, self.cases[label])

    def poke(self, patches):
        self.harness.machine.patches = patches
        self.harness.machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()

    def killed(self, patches, label):
        self.poke(patches)
        try:
            return bool(self.run_label(label))
        except tool.FAULTS:
            return True


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
            image.exact_fde(tool.CORE + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)


class Rules(unittest.TestCase):
    def epochs(self, stakes):
        return {1: tool.epoch_of(len(stakes), stakes)}

    def test_uint_forms(self):
        self.assertEqual(tool.uint_form(0x7F), b"\x7f")
        self.assertEqual(tool.uint_form(0x80), b"\xcc\x80")
        self.assertEqual(tool.uint_form(0x100), b"\xcd\x01\x00")
        self.assertEqual(tool.uint_form(0x10000), b"\xce\x00\x01\x00\x00")
        self.assertEqual(tool.uint_form(1 << 32), b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00")

    def test_signed_bytes_are_text_hash(self):
        data = tool.signed_bytes(5, bytes(range(32)))
        self.assertEqual(data[:6], b"\x92\x05\xd9\x42\x30\x78")
        self.assertEqual(len(data), 70)

    def test_equal_mask_ignores_nothing_in_the_tail_word(self):
        left = bytes(range(20))
        self.assertEqual(tool.equal_mask(left, left), 0xFFFF)
        self.assertEqual(tool.equal_mask(left, b"\xff" + left[1:]), 0xFFFE)
        self.assertEqual(tool.equal_mask(left, left[:16] + b"\xff" + left[17:]), 0xFFFE)

    def test_exact_two_thirds_is_short(self):
        model = tool.Model(self.epochs((100, 100, 100)), 1)
        self.assertFalse(model.quorum({tool.voter(0): b"", tool.voter(1): b""}))
        self.assertTrue(model.quorum({tool.voter(0): b"", tool.voter(1): b"", tool.voter(2): b""}))

    def test_empty_stake_and_absent_epoch_are_false(self):
        self.assertFalse(tool.Model({1: ({}, {})}, 1).quorum({tool.voter(0): b""}))
        self.assertFalse(tool.Model({}, 1).quorum({tool.voter(0): b""}))

    def test_model_prune_floor_is_vote_height(self):
        model = tool.Model(self.epochs((1,)), 1)
        model.heights[99] = {"done": None, "buckets": {}}
        model.heights[100] = {"done": None, "buckets": {}}
        sender = tool.hot_user(0)
        model.vote(sender, sender, 50100, b"h" * 32, b"s")
        self.assertEqual(sorted(model.heights), [100, 50100])

    def test_model_take_filters_empty_rows(self):
        model = tool.Model(self.epochs((1,)), 1)
        model.rows = [(1, b"a", {}), (2, b"b", {b"u": b"s"})]
        self.assertEqual(model.take(), [(2, b"b", {b"u": b"s"})])
        self.assertEqual(model.rows, [])


class HardRules(unittest.TestCase):
    def model(self, ratio, listed):
        return tool.HardModel({1: tool.epoch_of(3)}, 1, ratio, listed)

    def test_zero_ratio_needs_no_listed(self):
        self.assertTrue(self.model(0.0, ()).ratio_test({}))

    def test_ratio_is_strict(self):
        listed = tuple(tool.listed_address(index) for index in range(4))
        model = self.model(0.5, listed)
        self.assertFalse(model.ratio_test({listed[0]: b"", listed[1]: b""}))
        self.assertTrue(model.ratio_test({listed[0]: b"", listed[1]: b"", listed[2]: b""}))

    def test_outside_address_is_no_hit(self):
        model = self.model(0.25, (tool.listed_address(0),))
        self.assertFalse(model.ratio_test({tool.listed_address(9): b""}))

    def test_unknown_forms_make_no_height(self):
        model = self.model(0.5, ())
        self.assertIsNone(model.track(b"x" * 32, tool.listed_address(0), 9, b"h" * 32, b"s"))
        self.assertEqual(model.heights, {})


class RealBytes(Base):
    def test_named_cases_match(self):
        for label, case in self.cases.items():
            if "hundred" in label or label.startswith(("random", "many", "prune_many", "l1_random", "l1_many")):
                continue
            with self.subTest(label):
                self.assertIsNone(tool.compare(self.harness, None, case))

    def test_random_sample_matches(self):
        for serial in range(0, 120, 17):
            label = "random_%03d" % serial
            with self.subTest(label):
                self.assertIsNone(self.run_label(label))

    def test_hundred_heights_runs_the_scan_and_changes_nothing(self):
        self.harness.machine.seen = set()
        self.assertIsNone(self.run_label("hundred_heights"))
        self.assertIn(tool.DEAD_SCAN, self.harness.machine.seen)

    def test_short_case_skips_the_scan(self):
        self.harness.machine.seen = set()
        self.assertIsNone(self.run_label("three_of_four_crosses"))
        self.assertNotIn(tool.DEAD_SCAN, self.harness.machine.seen)

    def test_once_runs_only_on_first_use(self):
        self.assertIsNone(self.run_label("once_first_use"))
        self.assertIn(("once",), self.harness.events)
        self.assertIsNone(self.run_label("once_done"))
        self.assertNotIn(("once",), self.harness.events)


class Negative(Base):
    def test_prune_constant_flip_is_seen(self):
        self.assertTrue(self.killed({0x336A76F: 0x51}, "prune_one_below"))

    def test_prune_case_passes_unpatched(self):
        self.assertIsNone(self.run_label("prune_one_below"))

    def test_wrapper_limit_flip_is_seen(self):
        self.assertTrue(self.killed({0x1E5F5F1: 0xCA}, "height_limit_ok"))

    def test_status_flip_is_seen(self):
        self.assertTrue(self.killed({0x1E5F659: 0x7B}, "recovery_fails"))

    def test_tracker_offset_flip_is_seen(self):
        self.assertTrue(self.killed({0x1E5F6E3: 0x50}, "single_vote_short"))

    def test_done_flag_store_flip_is_seen(self):
        self.assertTrue(self.killed({0x3947096: 0}, "second_hash_reaches_after_done"))

    def test_row_filter_flip_is_seen(self):
        self.assertTrue(self.killed({0x336A3C5: 0x75}, "take_after_cross"))

    def test_l1_second_test_flip_is_seen(self):
        self.assertTrue(self.killed({0x3944141: 0x84}, "l1_hot_only_q_zero"))

    def test_l1_and_flip_is_seen(self):
        self.assertTrue(self.killed({0x39411F4: 0x08}, "l1_ratio_blocks_stake"))

    def test_mutation_helper_flips_a_jcc(self):
        patch = tool.mutate_patch(self.image, 0x336A551, 0x336A551 - 0x336A551)
        self.assertEqual(len(patch), 1)

    def test_stub_refuses_an_unknown_epoch(self):
        self.harness.reset()
        self.harness.machine.regs[tool.RDI] = tool.OUT_AT
        self.harness.machine.regs[tool.RSI] = 0x1234
        with self.assertRaises(tool.Halt):
            self.harness.on_stakes(self.harness.machine)

    def test_free_with_wrong_size_halts(self):
        self.harness.reset()
        at = self.harness.allocate(0x40)
        self.harness.machine.regs[tool.RDI] = at
        self.harness.machine.regs[tool.RSI] = 0x41
        with self.assertRaises(tool.Halt):
            self.harness.on_free(self.harness.machine)


class Static(Base):
    def test_dispatch_arm_reaches_the_wrapper(self):
        arm, site, target = tool.dispatch_arm(self.image)
        self.assertEqual(target, tool.WRAPPERS[0])
        self.assertLess(arm, site)

    def test_handler_row_name(self):
        self.assertEqual(tool.handler_name(), "VoteAppHash")

    def test_key_rows_hold(self):
        self.assertEqual(len(tool.key_row_lines(self.image)), len(tool.KEY_ROWS) + 1)

    def test_key_row_mismatch_is_refused(self):
        saved = tool.KEY_ROWS
        tool.KEY_ROWS = ((0x3947388, "4883f866", "wrong"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_row_lines(self.image)
        finally:
            tool.KEY_ROWS = saved

    def test_missing_text_is_refused(self):
        saved = tool.NAME_TEXTS
        tool.NAME_TEXTS = ("no such serde name in this file",)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(self.image)
        finally:
            tool.NAME_TEXTS = saved

    def test_status_texts(self):
        rows = {row[0]: row for row in (tool.status_row(self.image, tag) for tag in tool.STATUS_TAGS)}
        self.assertEqual(rows[0x7A][3], "Unable to recover signer.")
        self.assertEqual(rows[0x11F][3], "Signer does not match expected user")


class Folder(unittest.TestCase):
    def test_manifest_matches(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_evidence_has_no_mismatch(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["target"]["sha256"], tool.SHA256)
        self.assertEqual(doc["cases"]["total"], len(tool.all_cases()))

    def test_static_tables_regenerate(self):
        image = tool.load_image()
        self.assertEqual((FOLDER / "key-rows.tsv").read_text(), "\n".join(tool.key_row_lines(image)) + "\n")
        self.assertEqual((FOLDER / "names.tsv").read_text(), "\n".join(tool.text_rows(image)) + "\n")

    def test_every_case_row_matches(self):
        rows = (FOLDER / "cases.tsv").read_text().splitlines()[1:]
        self.assertTrue(rows)
        self.assertTrue(all(row.endswith("\tmatch") for row in rows))


if __name__ == "__main__":
    unittest.main()
