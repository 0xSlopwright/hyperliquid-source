"""Tests for tools/bridge_nonce_lifecycle.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_nonce_lifecycle", ROOT / "tools" / "bridge_nonce_lifecycle.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-nonce-lifecycle-94"
DAY = tool.DAY_MS
NOW = tool.BASE_NOW


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        if not tool.LIST_ADDRESSES:
            tool.LIST_ADDRESSES.extend(tool.read_list(cls.image))
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
            image.exact_fde(tool.VALIDATE + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)

    def test_nobits_section_gives_no_file_bytes(self):
        image = tool.load_image()
        bss = image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            image.offset(bss["address"] + 16)


class Rules(unittest.TestCase):
    def test_window_is_one_day_up_two_days_down(self):
        self.assertEqual(tool.decide(NOW, 0, NOW + DAY, []), ("ok", 100))
        self.assertEqual(tool.decide(NOW, 0, NOW + DAY + 1, []), ("high", NOW + DAY + 1, NOW + DAY))
        self.assertEqual(tool.decide(NOW, 0, NOW - 2 * DAY, []), ("ok", 100))
        self.assertEqual(tool.decide(NOW, 0, NOW - 2 * DAY - 1, []), ("low", NOW - 2 * DAY - 1, NOW - 2 * DAY))

    def test_full_set_is_tested_before_the_clock(self):
        values = [NOW + index for index in range(100)]
        self.assertEqual(tool.decide(NOW, 0, 5, values), ("low", 5, NOW))
        self.assertEqual(tool.decide(NOW, 1, NOW - 1, values), ("ok", 400))

    def test_gate_makes_an_empty_set_on_failure(self):
        sets = {}
        counters = [0, 0]
        self.assertEqual(tool.apply_gate(sets, counters, NOW, b"a", 0, NOW + 2 * DAY)[0], "high")
        self.assertEqual(sets, {b"a": []})
        self.assertEqual(counters, [1, 0])

    def test_gate_trims_to_the_cap_of_this_call(self):
        sets = {b"a": [NOW + index for index in range(150)]}
        counters = [0, 0]
        tool.apply_gate(sets, counters, NOW, b"a", 0, NOW + 1000)
        self.assertEqual(len(sets[b"a"]), 100)
        self.assertEqual(sets[b"a"][-1], NOW + 1000)

    def test_date_words(self):
        self.assertEqual(tool.year_flags(2000), 4)
        self.assertEqual(tool.year_flags(2024), 6)
        self.assertEqual(tool.year_flags(2023), 0o15)
        self.assertEqual(tool.naive_time(0), tool.struct.pack("<iII", (1970 << 13) | (1 << 4) | 0o12, 0, 0))

    def test_status_text(self):
        self.assertEqual(tool.status_text(("low", 1, 2)), "Invalid nonce: nonce too low 1 < 2")
        self.assertEqual(tool.status_text(("high", 3, 2)), "Invalid nonce: nonce too high 3 > 2")
        self.assertEqual(tool.status_text(("duplicate", 9)), "Invalid nonce: duplicate nonce 9")


class Real(Base):
    def test_every_case_matches(self):
        for label in self.cases:
            with self.subTest(label=label):
                self.assertFalse(self.run_label(label))

    def test_case_kinds(self):
        kinds = {case.kind for case in self.cases.values()}
        self.assertEqual(kinds, {"gate", "panic", "host", "bundle", "reverify", "prune", "list"})

    def test_wrong_lower_edge_in_the_rule_list_fails(self):
        real = tool.decide

        def one_day(now, flag, nonce, values):
            if nonce < now - DAY and nonce >= now - 2 * DAY:
                return "low", nonce, now - DAY
            return real(now, flag, nonce, values)
        tool.decide = one_day
        try:
            self.assertTrue(self.run_label("one_day_back_passes_0"))
        finally:
            tool.decide = real

    def test_nonce_key_of_first_address_in_the_rule_list_fails(self):
        real = tool.apply_gate

        def key_first(sets, counters, now, address, flag, nonce):
            return real(sets, counters, now, tool.A, flag, nonce)
        tool.apply_gate = key_first
        try:
            self.assertTrue(self.run_label("nonce_key_is_third_address_0"))
        finally:
            tool.apply_gate = real

    def test_table_grows_by_its_own_code(self):
        memory = self.harness.machine.memory
        self.assertFalse(self.run_label("two_addresses_separate_0"))
        self.assertGreater(memory.read(tool.STATE_AT + tool.GATE_MAP[0] + 8, 8), 0)


class Mutants(Base):
    def test_cap_100(self):
        self.assertTrue(self.killed({0x3986CE5: 0x65}, "full_set_below_smallest_0"))

    def test_cap_400(self):
        self.assertTrue(self.killed({0x3986CDF: 0x91}, "cap_400_full_0"))

    def test_upper_seconds(self):
        self.assertTrue(self.killed({0x3986E0A: 0x81}, "one_above_upper_bound_0"))

    def test_second_lower_step(self):
        self.assertTrue(self.killed({0x3987008: 0x81}, "two_days_back_passes_0"))

    def test_duplicate_status(self):
        self.assertTrue(self.killed({0x398720C: 0xC8}, "duplicate_is_0xc7_0"))

    def test_upper_compare_direction(self):
        self.assertTrue(self.killed({0x3986EFE: 0x77}, "one_above_upper_bound_0"))

    def test_expiry_weight(self):
        self.assertTrue(self.killed({0x444B7F3: 0x04}, "expired_burns_nonce_and_five_weights_0"))

    def test_expiry_edge(self):
        self.assertTrue(self.killed({0x444B7E1: 0x87}, "expired_equal_now_runs_0"))

    def test_nonce_field_of_the_envelope(self):
        self.assertTrue(self.killed({0x444B6F6: 0x40}, "duplicate_charges_nothing_0"))

    def test_gate_key_address(self):
        self.assertTrue(self.killed({0x444B70D: 0x10}, "nonce_key_is_third_address_0"))

    def test_gate_copy_map_offset(self):
        self.assertTrue(self.killed({0x4D9B6E7: 0x40}, "two_addresses_separate_0"))

    def test_success_counter(self):
        self.assertTrue(self.killed({0x4D9B7A3: 0xE0}, "first_nonce_makes_set_0"))

    def test_reverify_vote_row(self):
        self.assertTrue(self.killed({0x45487B0: 0x58}, "vote_row_only_passes"))

    def test_reverify_kind_byte(self):
        self.assertTrue(self.killed({0x45487BD: 0x03}, "row_60_kind_2_passes"))

    def test_prune_bucket_size(self):
        self.assertTrue(self.killed({0x3422D9F: 0xB8}, "ready_equal_now_removed"))

    def test_prune_user_test_skip(self):
        self.assertTrue(self.killed({0x3422E05: 0x85}, "real_user_keeps_set"))

    def test_drain_seconds_compare(self):
        self.assertTrue(self.killed({0x33BA8F2: 0x73}, "ready_equal_now_removed"))


class Static(Base):
    def test_list_is_eight_addresses(self):
        rows = tool.read_list(self.image)
        self.assertEqual(len(rows), 8)
        self.assertEqual(len(set(rows)), 8)
        self.assertTrue(all(len(row) == 20 for row in rows))

    def test_key_rows_hold(self):
        self.assertEqual(len(tool.key_row_lines(self.image)), len(tool.KEY_ROWS) + 1)

    def test_moved_key_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.KEY_ROWS[0][0])] ^= 1
        moved = tool.Image(bytes(blob))
        with self.assertRaisesRegex(tool.EvidenceError, "row moved"):
            tool.key_row_lines(moved)

    def test_tracker_rows(self):
        lines = tool.tracker_lines(self.image)
        self.assertEqual(len(lines), 6)
        self.assertIn("address_to_nonce_set\t", lines[4])
        self.assertIn("\t0x3760\t", lines[4])

    def test_moved_tracker_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.TRACKER_FIELDS[3][2]) + 3] ^= 8
        with self.assertRaisesRegex(tool.EvidenceError, "snapshot row moved"):
            tool.tracker_lines(tool.Image(bytes(blob)))

    def test_texts(self):
        lines = tool.text_lines(self.image)
        self.assertIn("nonce too low ", lines[1])
        self.assertIn("nonce too high ", lines[2])

    def test_status_names(self):
        rows = {row[0]: row[3] for row in (tool.status_row(self.image, tag) for tag in tool.STATUS_TAGS)}
        self.assertIn("nonce", rows[0xC6])


class Files(unittest.TestCase):
    def test_manifest_matches(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_tamper_is_seen(self):
        digest = hashlib.sha256(b"x").hexdigest()
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertNotIn(digest, " ".join(rows))

    def test_tables_without_mutants_regenerate(self):
        image = tool.load_image()
        if not tool.LIST_ADDRESSES:
            tool.LIST_ADDRESSES.extend(tool.read_list(image))
        files = tool.render(tool.analyse(image, full=False))
        for name in ("cases.tsv", "functions.tsv", "call-sites.tsv", "status-text.tsv", "node-layouts.tsv", "key-rows.tsv", "texts.tsv", "tracker-fields.tsv", "fixed-list.tsv", "window-bounds.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)


if __name__ == "__main__":
    unittest.main()
