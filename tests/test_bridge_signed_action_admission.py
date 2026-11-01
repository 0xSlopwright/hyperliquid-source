"""Tests for tools/bridge_signed_action_admission.py: the rule list on real bytes, static reads and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_signed_action_admission", ROOT / "tools" / "bridge_signed_action_admission.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-signed-action-admission-94"


class Base(unittest.TestCase):
    def prepare(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        tool.TABLES.append(cls.harness.tables)
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
            image.exact_fde(tool.COPIES[0]["core"] + 1)
        with self.assertRaises(tool.EvidenceError):
            image.offset(0x10)

    def test_nobits_section_gives_no_file_bytes(self):
        image = tool.load_image()
        bss = image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            image.offset(bss["address"] + 16)


class Rules(unittest.TestCase):
    def test_threshold_zero_wraps_to_refused(self):
        fix = tool.Fix(convert_user=tool.USER, users=frozenset((tool.USER, tool.COSIGNER)), signers=frozenset((tool.COSIGNER,)), threshold=0)
        self.assertEqual(tool.expect_convert(fix)[0], 0x113)

    def test_threshold_is_tested_before_the_ten_signer_cap(self):
        wide = frozenset(tool.ADDRESSES[12:23])
        users = wide | frozenset((tool.USER,))
        self.assertEqual(tool.expect_convert(tool.Fix(convert_user=tool.USER, users=users, signers=wide, threshold=12))[0], 0x113)
        self.assertEqual(tool.expect_convert(tool.Fix(convert_user=tool.USER, users=users, signers=wide, threshold=4))[0], 0x117)

    def test_clear_without_a_row_is_refused(self):
        self.assertEqual(tool.expect_convert(tool.Fix(convert_user=tool.USER, users=frozenset((tool.USER,)), signers=None))[0], 0x118)

    def test_magic_user_is_never_converted(self):
        fix = tool.Fix(convert_user=tool.MAGIC_USER, users=frozenset((tool.MAGIC_USER, tool.COSIGNER)), signers=frozenset((tool.COSIGNER,)), threshold=1)
        self.assertEqual(tool.expect_convert(fix)[0], 0x118)

    def test_row_of_a_low_tag(self):
        self.assertEqual(tool.row_of(0x10), tool.LOW_ROW)
        self.assertEqual(tool.row_of(tool.ROW_BASE), 0)
        self.assertEqual(tool.row_of(tool.MULTI_TAG), tool.MULTI_ROW)


class Real(Base):
    def test_every_case_matches(self):
        for label in self.cases:
            with self.subTest(label=label):
                self.assertFalse(self.run_label(label))

    def test_case_kinds(self):
        self.assertEqual({case.kind for case in self.cases.values()}, {"core", "wrap", "sort", "convert"})

    def test_nonce_key_of_the_user_in_the_rule_list_fails(self):
        real = tool.expect_core

        def wrong(harness, fix, copy, index=0):
            answer, events = real(harness, fix, copy, index)
            if answer[0] == "record":
                answer = answer[:4] + (answer[2],)
            return answer, events
        tool.expect_core = wrong
        try:
            self.assertTrue(self.run_label("agent_found_0"))
        finally:
            tool.expect_core = real

    def test_counting_a_duplicate_in_the_rule_list_fails(self):
        case = self.cases["multi_duplicate_not_counted_0"]
        fix = case.fixes[0]
        saved = fix.multi
        fix.multi = {tool.MULTI: (saved[tool.MULTI][0], 3)}
        real = tool.expect_core

        def counted(harness, item, copy, index=0):
            item.multi = saved
            answer, events = real(harness, item, copy, index)
            item.multi = {tool.MULTI: (saved[tool.MULTI][0], 3)}
            return ("record", 0, tool.MULTI, tool.MULTI, tool.SIGNER), events
        tool.expect_core = counted
        try:
            self.assertTrue(self.run_label("multi_duplicate_not_counted_0"))
        finally:
            tool.expect_core = real
            fix.multi = saved

    def test_sort_order_of_cancels_first_in_the_rule_list_fails(self):
        real = tool.sort_class

        def swapped(harness, fix):
            value = real(harness, fix)
            return {1: 2, 2: 1}.get(value, value)
        tool.sort_class = swapped
        try:
            self.assertTrue(self.run_label("sort_all_classes"))
        finally:
            tool.sort_class = real

    def test_real_store_keeps_the_threshold(self):
        self.assertFalse(self.run_label("convert_new_one_of_two_2"))
        found = tool.read_multi(self.harness, tool.STATE_AT + tool.MULTI_MAP)
        self.assertEqual(found[tool.USER][1], 1)
        self.assertEqual(found[tool.USER][0], frozenset((tool.COSIGNER, tool.THIRD)))

    def test_real_clear_removes_only_that_user(self):
        self.assertFalse(self.run_label("convert_remove_keeps_other_2"))
        self.assertEqual(list(tool.read_multi(self.harness, tool.STATE_AT + tool.MULTI_MAP)), [tool.OTHER])


class Mutants(Base):
    def status_patch(self, va, low):
        return {va + 3: low}

    def test_nested_status(self):
        self.assertTrue(self.killed(self.status_patch(0x46D4A3C, 0x13), "multi_nested_refused_0"))

    def test_multi_tag_compare(self):
        self.assertTrue(self.killed({0x46D4A21: 0xA9}, "multi_threshold_met_0"))

    def test_direct_use_status(self):
        self.assertTrue(self.killed(self.status_patch(0x46D50D6, 0x16), "user_is_multi_direct_refused_0"))

    def test_magic_mask_bit(self):
        self.assertTrue(self.killed({0x4C5CB0F: 0x00}, "multi_magic_allowed_row_0"))

    def test_signature_count(self):
        self.assertTrue(self.killed({0x4C5CE1B: 0x11}, "multi_too_many_signatures_0"))

    def test_threshold_compare_flip(self):
        self.assertTrue(self.killed({0x4C5D077: 0x72}, "multi_threshold_met_0"))

    def test_threshold_field(self):
        self.assertTrue(self.killed({0x4C5D076: 0x10}, "multi_threshold_met_0"))

    def test_vault_field(self):
        self.assertTrue(self.killed({0x46D4F94: 0x69}, "vault_leader_pass_0"))

    def test_agent_table_offset(self):
        self.assertTrue(self.killed({0x46D4E2F: 0x38}, "agent_found_0") or self.killed({0x4D8B07E: 0x38}, "agent_found_0"))

    def test_resolve_class_table(self):
        self.assertTrue(self.killed({0x335ECC7: 0x01}, "agent_found_0"))

    def test_store_cap(self):
        self.assertTrue(self.killed({0x34262B7: 0x0B}, "convert_eleven_signers_2"))

    def test_store_threshold_status(self):
        self.assertTrue(self.killed({0x34262A9: 0x14}, "convert_threshold_zero_2"))

    def test_user_compare_in_core(self):
        self.assertTrue(self.killed({0x2769CF2: 0x84}, "convert_new_two_of_two_2"))

    def test_text_limit(self):
        self.assertTrue(self.killed({0x1E64025: 0xEA}, "convert_json_over_limit_2"))
        self.assertTrue(self.killed({0x1E64025: 0xE8}, "convert_json_at_limit_2"))

    def test_sort_noop_tag(self):
        self.assertTrue(self.killed({0x446FC7A: 0x75}, "sort_all_classes"))


class Static(Base):
    def test_lazy_lists(self):
        tables = self.harness.tables
        self.assertEqual(tables.lazy[0], [bytes(19) + bytes([value]) for value in (1, 2, 3)])
        self.assertEqual(len(tables.lazy[1]), 3)
        self.assertEqual(len(set(tables.lazy[1])), 3)

    def test_copies_share_their_rows(self):
        tables = self.harness.tables
        self.assertEqual(tables.assets[0], tables.assets[1])
        self.assertEqual(tables.assets[0], tables.assets[2])

    def test_class_rows(self):
        tables = self.harness.tables
        self.assertEqual(len(tables.klass), tool.ROWS)
        self.assertEqual(tables.klass[1], 2)
        self.assertEqual(tables.klass[tool.LOW_ROW], 1)
        self.assertEqual(tables.klass[tool.MULTI_ROW], 3)
        self.assertEqual(tables.touch[tool.MULTI_ROW], "inner")

    def test_key_rows_hold(self):
        self.assertEqual(len(tool.key_row_lines(self.image)), len(tool.KEY_ROWS) + 1)

    def test_moved_key_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.KEY_ROWS[0][0])] ^= 1
        moved = tool.Image(bytes(blob))
        with self.assertRaisesRegex(tool.EvidenceError, "row moved"):
            tool.key_row_lines(moved)

    def test_moved_lazy_row_is_refused(self):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(tool.LAZY_INIT[0] + 0x25)] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.lazy_list(tool.Image(bytes(blob)), tool.LAZY_INIT[0])

    def test_unknown_asset_arm_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.asset_arm(self.image, tool.COPIES[0]["core"])

    def test_status_names(self):
        rows = {row[0]: row[3] for row in (tool.status_row(self.image, tag) for tag in tool.STATUS_TAGS)}
        self.assertEqual(rows[tool.STATUS_OK], "")
        self.assertTrue(rows[0x116])


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
        files = tool.render(tool.analyse(tool.load_image(), full=False))
        for name in ("cases.tsv", "functions.tsv", "call-sites.tsv", "status-text.tsv", "node-layouts.tsv", "key-rows.tsv", "action-rows.tsv", "lazy-lists.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)


if __name__ == "__main__":
    unittest.main()
