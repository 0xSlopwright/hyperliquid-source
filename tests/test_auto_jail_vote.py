"""Tests for tools/auto_jail_vote.py: rule list, byte pins and negative controls on corrupted copies."""

import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import auto_jail_vote as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-auto-jail-vote-94"
Case, Sample, Snapshot, File = tool.Case, tool.Sample, tool.Snapshot, tool.File
fine, DAY, WALL, NOW = tool.fine, tool.DAY, tool.WALL, tool.NOW
IMAGE = tool.load_image()


class Base(unittest.TestCase):
    image = IMAGE
    harness = tool.Harness(IMAGE)

    def run_case(self, **extra):
        case = Case("c", **extra)
        label, model = tool.spec_run(case)
        got = self.harness.run(case)
        self.assertEqual(tool.differ(got, tool.spec_view(model)), {}, label)
        return label, got

    def votes(self, **extra):
        return [(row[7], row[1]) for row in self.run_case(**extra)[1]["trace"] if row[0] == "vote"]

    def corrupted(self, va, delta=1):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= delta
        return tool.Image(bytes(blob))


def lag(key, value):
    seen = dict(tool.CALM)
    seen[key] = value
    return seen


def only(key, sample):
    rows = fine(1, 2, 3, 4)
    rows[key] = sample
    return rows


class Gates(Base):
    def test_dispatch_reaches_the_arm(self):
        self.assertEqual(tool.read_dispatch(self.image), [(0xF, tool.OUTER_TABLE, 5, 0x44AE705, tool.DISPATCH_TAGS[0][2])])

    def test_calm_set_sends_nothing(self):
        label, got = self.run_case()
        self.assertEqual(label, "no target")
        self.assertEqual(got["outbox"], [])

    def test_no_stake_row_stops_before_any_tracker_call(self):
        label, got = self.run_case(stakes={7000: dict(tool.FOUR)})
        self.assertEqual(label, "no stake row")
        self.assertEqual(got["trace"], [("error", 0x28), ("answer", 0xD, 1)])

    def test_not_a_member_keeps_the_weight_map(self):
        label, got = self.run_case(stakes={0: {2: 10}}, flag=True, weight={2: 9001})
        self.assertEqual(label, "not a member")
        self.assertEqual(got["weight"], {2: 9001})

    def test_this_node_jailed_stops_after_the_rules(self):
        label, got = self.run_case(jailed={0: frozenset((1,))}, stats=fine(1, 3, 4))
        self.assertEqual(label, "this node jailed")
        self.assertEqual(got["outbox"], [])

    def test_other_jailed_node_does_not_stop(self):
        self.assertEqual(self.run_case(jailed={0: frozenset((3,))}, stats=fine(1, 3, 4))[0], "votes sent")

    def test_no_jail_row_stops_only_when_a_target_exists(self):
        self.assertEqual(self.run_case(jailed={7000: frozenset()}, stats=fine(1, 3, 4))[0], "no jail row")
        self.assertEqual(self.run_case(jailed={7000: frozenset()})[0], "no target")

    def test_high_round_logs_three_times(self):
        got = self.run_case(valid_until=4999)[1]
        self.assertEqual(got["trace"].count(("log", "high round")), 3)

    def test_refused_bundle_leaves_outbox_empty(self):
        label, got = self.run_case(stats=fine(1, 3, 4), send_error=True)
        self.assertEqual(label, "send refused")
        self.assertEqual(got["outbox"], [])


class Lag(Base):
    def test_floor_is_exclusive(self):
        self.assertEqual(self.votes(seen=lag(2, 2000)), [])
        self.assertEqual(self.votes(seen=lag(2, 1999)), [(2, 3)])

    def test_missing_seen_row_is_no_lag(self):
        seen = dict(tool.CALM)
        del seen[2]
        self.assertEqual(self.votes(seen=seen), [])

    def test_total_over_1500_opens_the_window(self):
        stakes = {0: {1: 1000, 2: 500, 3: 500, 4: 501}}
        self.assertEqual(self.votes(stakes=stakes, seen=lag(2, 1999)), [])

    def test_top_bit_of_total_turns_the_rule_off(self):
        self.assertEqual(self.votes(stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1, 4: 1}}, seen=lag(2, 0)), [])

    def test_seen_saturates(self):
        self.assertEqual(self.votes(seen=lag(2, tool.MAX_ROUND - 5)), [])

    def test_total_overflow_panics(self):
        self.assertEqual(self.run_case(stakes={0: {1: 1 << 63, 2: 1 << 63}}, seen={1: 4999, 2: 4999})[0], "panic")


class Weight(Base):
    def test_limit_is_inclusive_and_needs_the_flag(self):
        self.assertEqual(self.votes(flag=True, weight={2: 9001}), [(2, 5)])
        self.assertEqual(self.votes(flag=True, weight={2: 9000}), [])
        self.assertEqual(self.votes(flag=False, weight={2: 20000}), [])

    def test_flag_empties_the_map_and_second_event_is_silent(self):
        got = self.run_case(flag=True, weight={2: 9001}, steps=2)[1]
        self.assertEqual(got["weight"], {})
        self.assertEqual(sum(1 for row in got["trace"] if row[0] == "vote"), 1)

    def test_no_flag_keeps_the_map(self):
        self.assertEqual(self.run_case(weight={2: 5})[1]["weight"], {2: 5})


class Status(Base):
    def test_no_row_is_reason_zero(self):
        self.assertEqual(self.votes(stats=fine(1, 3, 4)), [(2, 0)])

    def test_empty_tracker_names_every_key_with_this_node(self):
        self.assertEqual(self.votes(stats={}), [(1, 0), (2, 0), (3, 0), (4, 0)])

    def test_quiet_limit_is_exclusive(self):
        self.assertEqual(self.votes(stats=only(2, Sample(0.0, 1.0, (DAY, 39820, 0)))), [])
        self.assertEqual(self.votes(stats=only(2, Sample(0.0, 1.0, (DAY, 39819, 0)))), [(2, 1)])

    def test_ratio_limit_is_exclusive_and_mute_turns_it_off(self):
        self.assertEqual(self.votes(stats=only(2, Sample(2.0, 2.0, WALL))), [])
        self.assertEqual(self.votes(stats=only(2, Sample(3.0, 2.0, WALL))), [(2, 2)])
        self.assertEqual(self.votes(mute=1, stats=only(2, Sample(3.0, 2.0, WALL))), [])

    def test_mute_does_not_hide_the_quiet_rule(self):
        self.assertEqual(self.votes(mute=1, stats=only(2, Sample(3.0, 2.0, (DAY, 30000, 0)))), [(2, 1)])

    def test_zero_denominator_is_ratio_zero_and_negative_panics(self):
        self.assertEqual(self.votes(stats=only(2, Sample(9.0, 0.0, WALL))), [])
        self.assertEqual(self.run_case(stats=only(2, Sample(9.0, -1.0, WALL)))[0], "panic")

    def test_this_node_can_be_a_target(self):
        self.assertEqual(self.votes(stats=only(1, Sample(3.0, 2.0, WALL))), [(1, 2)])


class JailRules(Base):
    def test_member_of_stored_set_beats_every_rule(self):
        self.assertEqual(self.votes(snapshot=Snapshot(0, {}, (2,)), seen=lag(2, 0)), [])

    def test_cut_is_event_time_plus_900(self):
        self.assertEqual(self.votes(snapshot=Snapshot(1, {2: tool.CUT}), stats=fine(1, 3, 4)), [(2, 0)])
        later = (DAY, 40900, 500000001)
        self.assertEqual(self.votes(snapshot=Snapshot(1, {2: later}), stats=fine(1, 3, 4)), [])

    def test_time_map_needs_tag_bit_zero(self):
        self.assertEqual(self.votes(snapshot=Snapshot(0, {2: (DAY + 16, 0, 0)}), stats=fine(1, 3, 4)), [(2, 0)])

    def test_cut_crosses_midnight(self):
        when = (DAY, 86000, 0)
        rows = self.votes(now=when, wall=when, snapshot=Snapshot(1, {2: (DAY + 16, 501, 0), 3: (DAY + 16, 500, 0)}), stats={1: Sample(0.0, 1.0, when)})
        self.assertEqual(rows, [(3, 0), (4, 0)])


class Votes(Base):
    def test_rule_order_lag_before_weight_before_status(self):
        self.assertEqual(self.votes(flag=True, weight={2: 9500}, seen=lag(2, 10), stats=fine(1, 3, 4)), [(2, 3)])
        self.assertEqual(self.votes(flag=True, weight={2: 9500}, stats=fine(1, 3, 4)), [(2, 5)])

    def test_row_is_vote_jail_with_event_time_plus_1800(self):
        row = [item for item in self.run_case(stats=fine(1, 3, 4))[1]["trace"] if item[0] == "vote"][0]
        self.assertEqual(row[3:], (1, tool.SIGN_MILLIS, 0xB0, 2, 2, (DAY, 41800, 500000000), 0, 0, tool.KEY_BYTE))

    def test_one_bundle_in_key_order(self):
        got = self.run_case(stats=fine(1))[1]
        self.assertEqual([row for row in got["trace"] if row[0] == "bundle"], [("bundle", (2, 3, 4))])
        self.assertEqual(got["outbox"], [(9, 1, 1, 0x11, 0x22, 0x33)])

    def test_sets_over_one_leaf(self):
        stakes = {0: dict.fromkeys(range(1, 21), 10)}
        seen = {key: 4999 for key in range(1, 21)}
        self.assertEqual([key for key, _ in self.votes(stakes=stakes, seen=seen, stats=fine(*range(1, 19)))], [19, 20])


class Config(Base):
    def test_first_look_has_no_interval(self):
        self.assertEqual(self.run_case(file=File())[1]["last_check"], WALL)

    def test_interval_edge_is_inclusive(self):
        at = (DAY, 39940, 0)
        self.assertEqual(self.run_case(last_check=at, file=File())[1]["last_check"], at)
        self.assertEqual(self.run_case(last_check=(DAY, 39939, 0), file=File())[1]["last_check"], WALL)

    def test_only_newer_file_loads(self):
        self.assertEqual(self.run_case(modified=(1, 0, 0), file=File())[1]["trace"].count(("load",)), 0)
        self.assertEqual(self.run_case(modified=(1, 1, 1), file=File(modified=(1, 1, 2)))[1]["modified"], (1, 1, 2))

    def test_date_compare_is_signed(self):
        self.assertEqual(self.run_case(modified=(1, 0, 0), file=File(modified=(-1, 0, 0)))[1]["modified"], (1, 0, 0))

    def test_new_limit_takes_effect_in_the_same_event(self):
        self.assertEqual(self.votes(file=File(parsed=(0.25, 0)), stats=only(2, Sample(1.0, 2.0, WALL))), [(2, 2)])

    def test_refused_parse_keeps_limit_and_holds_error(self):
        got = self.run_case(file=File(parsed=None))[1]
        self.assertTrue(got["held_error"])
        self.assertEqual(got["limit"], tool.to_bits(1.0))
        self.assertEqual(got["modified"], (0, 0, 0))

    def test_good_parse_clears_the_error(self):
        self.assertFalse(self.run_case(held_error=True, file=File())[1]["held_error"])

    def test_metadata_error_panics(self):
        self.assertEqual(self.run_case(file=File(broken=True))[0], "panic")


class Bytes(Base):
    def test_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "bad"
            path.write_bytes(b"\x7fELF" + b"\0" * 64)
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_every_pin_refuses_a_flipped_byte(self):
        tool.check_pins(self.image)
        for group, va, _, _ in tool.PINS[::9]:
            with self.assertRaises(tool.EvidenceError):
                tool.check_pins(self.corrupted(va))

    def test_number_refuses_a_flipped_byte(self):
        self.assertEqual(len(tool.check_numbers(self.image)), 2)
        with self.assertRaises(tool.EvidenceError):
            tool.check_numbers(self.corrupted(0x20A7A6))

    def test_slot_refuses_a_changed_target(self):
        tool.check_slots(self.image)
        blob = bytearray(self.image.blob)
        text = struct.pack("<q", 0x1459CA0)
        at = bytes(blob).find(struct.pack("<QQ", tool.SLOT_BACK, 8) + text)
        self.assertGreater(at, 0)
        blob[at + 16] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.check_slots(tool.Image(bytes(blob)))

    def test_string_refuses_a_flipped_byte(self):
        va = tool.STRINGS[0][0]
        with self.assertRaises(tool.EvidenceError):
            tool.check_strings(self.corrupted(va))

    def test_dispatch_refuses_a_changed_row(self):
        with self.assertRaises(tool.EvidenceError):
            tool.read_dispatch(self.corrupted(tool.OUTER_TABLE + 20))

    def test_changed_call_target_is_seen_by_the_scan(self):
        self.assertGreater(tool.scan_triggers(self.image), 0)
        with self.assertRaises(tool.EvidenceError):
            tool.scan_triggers(self.corrupted(0x44AF049))

    def test_gate_site_inside_a_row_is_refused(self):
        rows = tool.text_rows(self.image, tool.RULE)
        self.assertIn(0x4476229, rows)
        self.assertNotIn(0x447622A, rows)

    def test_patched_threshold_fails_the_rule_list(self):
        harness = tool.Harness(self.image, {0x4476587: 0x28})
        case = Case("c", flag=True, weight={2: 9000})
        self.assertNotEqual(tool.differ(harness.run(case), tool.spec_view(tool.spec_run(case)[1])), {})

    def test_field_scan_finds_the_weight_map_writer_and_taker(self):
        rows = tool.scan_fields(self.image)
        self.assertIn(tool.BUNDLE_INTAKE, [row[2] for row in rows if row[0] == 0x1E8])
        self.assertIn(tool.DISPATCH, [row[2] for row in rows if row[0] == 0x1E8])


class Packet(Base):
    def test_manifest_covers_every_file(self):
        rows = {}
        for line in (FOLDER / "MANIFEST.sha256").read_text().strip().split("\n"):
            digest, name = line.split("  ")
            rows[name] = digest
        names = sorted(path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), names)
        for name in names:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), rows[name], name)

    def test_summary_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["cases"], data["named_cases"] + data["vector_cases"])

    def test_packet_tables_match_a_cheap_regeneration(self):
        result = tool.analyse(self.image, mutate=False, vectors=tool.VECTORS)
        files = tool.render(result, self.image)
        for name in ("gates.tsv", "reasons.tsv", "numbers.tsv", "cases.tsv", "layouts.tsv", "pins.tsv", "field-uses.tsv", "triggers.tsv"):
            self.assertEqual(files[name], (FOLDER / name).read_text(), name)


if __name__ == "__main__":
    unittest.main()
