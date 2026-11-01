"""Tests for tools/fees_day_prune.py: the evaluated prune path, its specification and the negative controls."""

import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fees_day_prune as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "fees-day-prune-94"


def read_rows(name):
    lines = (FOLDER / name).read_text(encoding="utf-8").splitlines()
    return [line.split("\t") for line in lines]


def rendered(header, rows):
    return [list(header)] + [[str(item) for item in row] for row in rows]


class Base(unittest.TestCase):
    image = tool.load_image()
    harness = tool.Harness(image)

    def patched(self, patches, case):
        machine = self.harness.machine
        machine.patches = patches
        machine.cache.clear()
        try:
            return tool.compare_run(self.harness, case)
        finally:
            machine.patches = {}
            machine.cache.clear()


class Identity(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_nobits_address_has_no_file_bytes(self):
        bss = self.image.named[".bss"]
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(bss["address"])

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.fde(0x10)

    def test_gate_copies_are_fde_starts(self):
        for gate in tool.GATES:
            self.assertEqual(self.image.exact_fde(gate)[1] - gate, 259)


class Calendar(unittest.TestCase):
    def test_known_packed_dates(self):
        self.assertEqual(tool.pack(tool.days(2026, 10, 31)), 0x00FD530A)
        self.assertEqual(tool.pack(tool.days(0, 1, 5)), 0x00000054)

    def test_round_trip_across_leap_days(self):
        for day in range(tool.days(1899, 12, 1), tool.days(1904, 3, 3)):
            self.assertEqual(tool.unpack(tool.pack(day)), day)

    def test_window_crosses_a_leap_day(self):
        self.assertEqual(tool.date_add(tool.pack(tool.days(2024, 3, 1)), -20), tool.pack(tool.days(2024, 2, 10)))
        self.assertEqual(tool.date_add(tool.pack(tool.days(2023, 3, 1)), -20), tool.pack(tool.days(2023, 2, 9)))

    def test_lowest_date_has_no_cutoff(self):
        bottom = tool.days(tool.MIN_YEAR, 1, 1)
        self.assertIsNone(tool.date_add(tool.pack(bottom + 19), -20))
        self.assertIsNotNone(tool.date_add(tool.pack(bottom + 20), -20))


class Specification(Base):
    def test_all_vectors_match(self):
        evidence, _ = tool.analyse(self.image, full=False)
        self.assertEqual(evidence["mismatches"], 0, evidence["first_mismatch"])
        self.assertEqual(evidence["cases"]["total"], len(tool.all_cases()))

    def test_every_outcome_is_present(self):
        outcomes = {str(case["want"]["outcome"]) for case in tool.all_cases()}
        self.assertEqual(outcomes, {"pruned", "skipped", str(tool.LOC_DATE), str(tool.LOC_NONE)})

    def test_cutoff_row_survives(self):
        case = tool.world("edge", "test", ch=tool.clearing(tool.rows_around(tool.TODAY, (-21, -20, -19))))
        kept = case["want"]["trees"][("ch", 0, "total")]
        self.assertEqual([tool.unpack(row[0]) - tool.TODAY for row in kept], [-20, -19])
        self.assertEqual(tool.compare_run(self.harness, case), "")

    def test_rows_stay_in_the_map_when_their_tree_empties(self):
        case = tool.world("gone", "test", dexes=[tool.dex(rows={2: tool.Tree(tool.rows_around(tool.TODAY, (-30,)))})])
        self.assertEqual(tool.compare_run(self.harness, case), "")
        memory = self.harness.machine.memory
        array = memory.read(tool.STATE + 0x5C0, 8)
        self.assertEqual(memory.read(array + 0x110, 8), 1)
        place = self.harness.places[("dex", 0, 2)]
        self.assertEqual(memory.read(place + 16, 8), 0)
        self.assertNotEqual(memory.read(place, 8), 0)

    def test_a_tree_emptied_once_is_freed_on_the_next_prune(self):
        case = tool.world("hollow", "test", ch=tool.clearing(tool.Tree(hollow=True)))
        self.assertEqual(tool.compare_run(self.harness, case), "")
        self.assertEqual(self.harness.machine.memory.read(self.harness.places[("ch", 0, "total")], 8), 0)
        self.assertEqual(self.harness.live, {})

    def test_wrong_expectation_is_seen(self):
        case = tool.world("edge", "test", ch=tool.clearing(tool.rows_around(tool.TODAY, (-21, -20))))
        case["want"]["trees"][("ch", 0, "total")] = case["want"]["trees"][("ch", 0, "total")][:0]
        self.assertTrue(tool.compare_run(self.harness, case).startswith("rows"))

    def test_leak_is_seen(self):
        case = tool.world("edge", "test", ch=tool.clearing(tool.rows_around(tool.TODAY, (-21, -20))))
        lay = self.harness.lay

        def extra(item):
            lay(item)
            self.harness.live[tool.HEAP_BASE + 0x1F00] = tool.LEAF_SIZE
        self.harness.lay = extra
        try:
            self.assertTrue(tool.compare_run(self.harness, case).startswith("blocks"))
        finally:
            del self.harness.lay


class Corruption(Base):
    rows = tool.rows_around(tool.TODAY, (-40, -21, -20, -19, -1))

    def case(self, **over):
        return tool.world("corrupt", "test", dexes=[tool.dex(self.rows, {3: tool.Tree(self.rows)})], ch=tool.clearing(self.rows, {5: tool.Tree(self.rows)}), **over)

    def test_baseline_is_clean(self):
        self.assertEqual(self.patched({}, self.case()), "")

    def test_gate_branch_flipped(self):
        self.assertNotEqual(self.patched({0x26FF364: 0x7C}, self.case()), "")

    def test_window_off_by_one(self):
        self.assertNotEqual(self.patched({0x26FF367: 0xED}, self.case()), "")
        self.assertNotEqual(self.patched({0x26FF367: 0xEB}, self.case()), "")

    def test_dex_tree_offset(self):
        self.assertNotEqual(self.patched({0x36FF63A: 0x60}, self.case()), "")

    def test_row_tree_offset(self):
        self.assertNotEqual(self.patched({0x388DE4D: 0x20}, self.case()), "")

    def test_row_stride(self):
        self.assertNotEqual(self.patched({0x3BC9B68: 0x70}, self.case()), "")


class Files(Base):
    def test_manifest_lists_every_file(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        named = {}
        for line in lines:
            digest, name = line.split("  ")
            named[name] = digest
        present = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual(set(named), present)
        for name, digest in named.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_tables_match_a_fresh_read(self):
        self.assertEqual(read_rows("pins.tsv"), rendered(("address", "bytes", "meaning"), tool.pin_rows(self.image)))
        self.assertEqual(read_rows("step-order.tsv"), rendered(("block_step", "site", "callee", "role"), tool.order_rows(self.image)))
        self.assertEqual(read_rows("call-sites.tsv"), rendered(("callee", "target", "site", "function", "form"), tool.caller_rows(self.image)))
        self.assertEqual(read_rows("copies.tsv"), rendered(("copy", "offset", "op", "first", "this"), tool.copy_rows(self.image)))
        self.assertEqual(read_rows("window.tsv"), rendered(("date", "packed", "cutoff", "days_back", "days_kept"), tool.window_rows()))

    def test_wrong_pin_byte_is_refused(self):
        kept = tool.PINS
        tool.PINS = kept[:1] + ((0x26FF366, 5, "be ed ff ff ff", "wrong"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(self.image)
        finally:
            tool.PINS = kept

    def test_step_order_fails_on_a_wrong_callee(self):
        kept = tool.STEP_NEIGHBOURS
        tool.STEP_NEIGHBOURS = (kept[1], kept[0]) + kept[2:]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.order_rows(self.image)
        finally:
            tool.STEP_NEIGHBOURS = kept

    def test_survivors_all_carry_a_reason(self):
        for row in read_rows("mutations.tsv")[1:]:
            if row[3] != "killed":
                self.assertTrue(row[5], row[1])

    def test_evidence_counts_agree_with_the_mutation_table(self):
        rows = read_rows("mutations.tsv")[1:]
        text = (FOLDER / "evidence.json").read_text(encoding="utf-8")
        self.assertIn('"killed": %d' % sum(1 for row in rows if row[3] == "killed"), text)


if __name__ == "__main__":
    unittest.main()
