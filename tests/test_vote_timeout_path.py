"""Tests for tools/vote_timeout_path.py: rule list, byte pins and negative controls on corrupted copies."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import vote_timeout_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-vote-timeout-path-94"
Case, Sig, Qc, Tc, V, T, F = tool.Case, tool.Sig, tool.Qc, tool.Tc, tool.VoteMsg, tool.TimeoutMsg, tool.TimerFire
send, good_block, parent_block, tc_row, DAY, NOW = tool.send, tool.good_block, tool.parent_block, tool.tc_row, tool.DAY, tool.NOW


IMAGE = tool.load_image()


class Base(unittest.TestCase):
    image = IMAGE
    harness = tool.Harness(IMAGE)

    def run_case(self, case):
        label, model = tool.spec_run(case)
        got = self.harness.run(case)
        self.assertEqual(tool.differ(got, tool.spec_view(model)), [], case.name)
        return label, got

    def corrupted(self, va, delta=1):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= delta
        return tool.Image(bytes(blob))

    def event(self, *steps, **extra):
        return self.run_case(Case("c", steps=steps, now=NOW, last_vote=(DAY, 900, 0), **extra))


class VoteDecision(Base):
    def test_plain_vote_goes_to_next_leader_and_moves_two_fields(self):
        label, got = self.run_case(send("c", leader=88))
        self.assertEqual(label, "voted")
        self.assertEqual(got["outbox"][0][0], "vote")
        self.assertEqual(got["outbox"][0][7], 88)
        self.assertEqual(got["words"]["voted"], 1000)
        self.assertEqual(got["last_vote"], NOW)
        self.assertIn(("leader", 1001), got["trace"])

    def test_vote_pair_comes_from_the_block_qc(self):
        tip = tool.Block(0x11, 1000, Qc(version=5, start=6, round=999, hash=0x10), time=(DAY, 999, 500000000))
        _, got = self.run_case(send("c", tip))
        self.assertEqual(got["outbox"][0][2:5], (5, 6, 1000))

    def test_50_ms_gap_is_inclusive(self):
        self.assertEqual(self.run_case(send("c", last_vote=(DAY, 1000, 450000000)))[0], "voted")
        self.assertEqual(self.run_case(send("c", last_vote=(DAY, 1000, 450000001)))[0], "under 50 ms")

    def test_age_limit_is_absolute_and_counts_whole_microseconds(self):
        self.assertEqual(self.run_case(send("c", now=(DAY, 1003, 999)))[0], "voted")
        self.assertEqual(self.run_case(send("c", now=(DAY, 1003, 1000)))[0], "over 3.5 s")
        old = parent_block(time=(DAY, 990, 0))
        self.assertEqual(self.run_case(send("c", parent=old, now=(DAY, 996, 0)))[0], "voted")
        self.assertEqual(self.run_case(send("c", parent=old, now=(DAY, 995, 0)))[0], "over 3.5 s")

    def test_time_must_grow_strictly_along_the_walk(self):
        self.assertEqual(self.run_case(send("c", good_block(time=(DAY, 998, 0))))[0], "time not after parent")
        self.assertEqual(self.run_case(send("c", good_block(time=(DAY, 998, 1))))[0], "voted")

    def test_fetch_keys(self):
        label, got = self.run_case(send("c", good_block(hashes=(0x21,))))
        self.assertEqual(label, "fetch tx")
        self.assertEqual(got["trace"][0][1], 3)
        self.assertEqual(bytes.fromhex(got["trace"][0][2]), tool.block_digest(good_block(hashes=(0x21,))))
        label, got = self.run_case(send("c", good_block(parent=0x55), parent=False))
        self.assertEqual(label, "fetch parent")
        self.assertEqual(got["trace"][0][1:], (4, tool.word_bytes(0x55).hex()))
        self.assertEqual(self.run_case(send("c", good_block(parent=0x55), parent=False, throttle="held"))[1]["outbox"], [])

    def test_seen_map_answer_changes_nothing_but_ancestor_set_does(self):
        tip = good_block(hashes=(0x21,))
        self.assertEqual(self.run_case(send("c", tip, txs={0x21: "ok"}))[0], "voted")
        self.assertEqual(self.run_case(send("c", tip, txs={0x21: "ok"}, ancestors=(0x21,)))[0], "tx refused")
        self.assertEqual(self.run_case(send("c", tip, txs={0x21: "flagged"}))[0], "tx refused")

    def test_timed_out_byte_stops_a_vote(self):
        self.assertEqual(self.run_case(send("c", timed_out=True))[0], "not this round")


class Rule(Base):
    def label(self, block):
        return self.run_case(send("c", block))[0]

    def test_direct_qc(self):
        self.assertEqual(self.label(good_block()), "voted")
        self.assertEqual(self.label(good_block(qc_round=998)), "rule refused")

    def test_tc_needs_previous_round_and_top_qc(self):
        rows = (tc_row(990), tc_row(989, 2))
        self.assertEqual(self.label(good_block(qc_round=990, tc=Tc(999, rows))), "voted")
        self.assertEqual(self.label(good_block(qc_round=989, tc=Tc(999, rows))), "rule refused")
        self.assertEqual(self.label(good_block(qc_round=990, tc=Tc(998, rows))), "rule refused")

    def test_empty_tc_refuses_even_a_direct_qc(self):
        self.assertEqual(self.label(good_block(qc_round=999, tc=Tc(999, ()))), "rule refused")

    def test_direct_qc_beats_a_stale_tc(self):
        self.assertEqual(self.label(good_block(qc_round=999, tc=Tc(998, (tc_row(1500),)))), "voted")

    def test_every_row_counts_for_the_top(self):
        for at in range(9):
            rows = [tc_row(900 + index, index + 1) for index in range(9)]
            rows[at] = tc_row(995, at + 1)
            self.assertEqual(self.label(good_block(qc_round=994, tc=Tc(999, rows))), "rule refused", at)


class Receipt(Base):
    def test_strict_two_thirds_of_stake_forms_one_qc(self):
        label, got = self.event(V(1), V(2), V(3))
        self.assertEqual(label, "qc formed, round moved")
        self.assertEqual(got["qcs"][1000], (2, 100, 1000, 0x99, (1, 2, 3)))
        self.assertEqual(got["best"], (2, 100, 1000, 0x99, (1, 2, 3)))
        self.assertEqual(got["words"]["current"], 1001)
        self.assertEqual(self.event(V(1), V(2), stakes={0: {1: 10, 2: 10, 3: 10}})[0], "collected")

    def test_rejected_vote_changes_no_map(self):
        for vote in (V(1, version=3), V(9), V(1, sig=Sig(good=False)), V(1, sig=Sig(broken=True)), V(1, sig=Sig(by=2))):
            _, got = self.event(vote)
            self.assertEqual((got["seen"], got["tracker"]), ({}, {}))

    def test_stale_round_is_dropped_before_the_signature(self):
        self.assertEqual(self.event(V(1, round=999, sig=Sig(broken=True)))[0], "stale round")

    def test_under_voted_round_moves_the_seen_map_only(self):
        label, got = self.event(V(1), voted=1001)
        self.assertEqual(label, "under voted round")
        self.assertEqual((got["seen"], got["tracker"]), ({1: 1000}, {}))

    def test_hashes_do_not_share_stake(self):
        label, got = self.event(V(1, hash=0x99), V(2, hash=0x98), V(3, hash=0x99), V(4, hash=0x98))
        self.assertEqual(label, "collected")
        self.assertEqual(got["tracker"][1000][1], {0x98: [2, 4], 0x99: [1, 3]})

    def test_late_vote_is_stored_and_never_read(self):
        label, got = self.event(V(4, round=1005), prefill=((1005, 0x99, {0x99: (1, 2, 3)}),))
        self.assertEqual(label, "late vote")
        self.assertEqual(got["tracker"][1005], (0x99, {0x99: [1, 2, 3, 4]}))
        self.assertEqual(got["qcs"], {})

    def test_quorum_slot_before_the_insert_never_decides(self):
        self.assertEqual(self.event(V(4, round=1005), prefill=((1005, None, {0x99: (1, 2, 3)}),))[0], "collected")

    def test_cut_is_round_minus_95_and_only_a_qc_moves_it(self):
        rows = ((904, None, {0x55: (1,)}), (905, None, {0x55: (2,)}))
        _, got = self.event(V(1), V(2), V(3), prefill=rows)
        self.assertEqual(sorted(got["tracker"]), [905, 1000])
        self.assertEqual(got["words"]["floor"], 905)
        _, got = self.event(V(1), V(2), prefill=rows)
        self.assertEqual(sorted(got["tracker"]), [904, 905, 1000])
        self.assertEqual(got["words"]["floor_on"], 0)
        self.assertEqual(self.event(V(1), V(2), V(3), floor=950)[1]["words"]["floor"], 950)

    def test_under_floor_stores_nothing(self):
        self.assertEqual(self.event(V(1), floor=1001)[1]["tracker"], {})

    def test_past_100_rounds_nothing_is_trimmed(self):
        _, got = self.event(*[V(1, round=1000 + index) for index in range(102)])
        self.assertEqual(len(got["tracker"]), 102)


class Record(Base):
    def record(self, qc, **extra):
        return self.run_case(Case("c", kind="record", qc=qc, now=NOW, last_vote=(DAY, 900, 0), **extra))

    def test_first_qc_of_a_round_stays_and_a_different_one_logs(self):
        stored = {995: Qc(round=995, hash=0x99, votes=(2,))}
        _, got = self.record(Qc(round=995, hash=0x98, votes=(1,)), stored_qcs=stored)
        self.assertIn(("log", "bad qcs"), got["trace"])
        self.assertEqual(got["qcs"][995][3], 0x99)
        _, got = self.record(Qc(round=995, hash=0x99, votes=(1,)), stored_qcs=stored)
        self.assertNotIn(("log", "bad qcs"), got["trace"])

    def test_ring_evicts_by_insert_order_not_by_round(self):
        _, got = self.record(Qc(round=5, hash=0x98, votes=(1,)), stored_qcs={7: Qc(round=7), 8: Qc(round=8)}, limit=2)
        self.assertEqual(sorted(got["qcs"]), [5, 8])

    def test_highest_needs_a_strictly_higher_round(self):
        _, got = self.record(Qc(round=990, hash=0x99, votes=(1,)))
        self.assertEqual(got["words"]["highest"], 990)
        self.assertEqual(got["best"][3], 0x66)
        _, got = self.record(Qc(round=991, hash=0x99, votes=(1,)))
        self.assertEqual(got["best"][3], 0x99)

    def test_return_value_follows_the_round_advance(self):
        self.assertEqual(self.record(Qc(round=999, hash=0x99))[0], "record stays")
        self.assertEqual(self.record(Qc(round=1000, hash=0x99))[0], "record moved")


class Timers(Base):
    def test_first_fire_sends_once_later_fires_send_again(self):
        self.assertEqual(len(self.event(F())[1]["outbox"]), 1)
        self.assertEqual(len(self.event(F(), F())[1]["outbox"]), 2)
        self.assertEqual(len(self.event(F(), fires=1)[1]["outbox"]), 2)
        self.assertEqual(len(self.event(F(), timed_out=True)[1]["outbox"]), 0)

    def test_stored_tc_is_sent_after_the_timeout(self):
        tc = Tc(998, (tool.TcRow(Qc(round=990), 998, 2),))
        rows = self.event(F(), last_tc=tc)[1]["outbox"]
        self.assertEqual([row[0] for row in rows], ["timeout", "tc"])
        self.assertEqual(rows[1][1:], ((2,), 998))

    def test_timer_carries_nanoseconds(self):
        self.assertEqual(self.event(F(), wait=(5, 100000000))[1]["trace"][-1], ("rearm", 106, 0))
        self.assertEqual(self.event(F(), wait=(5, 99999999))[1]["trace"][-1], ("rearm", 105, 999999999))

    def test_timeout_carries_the_highest_qc(self):
        rows = self.event(V(1), V(2), V(3), F())[1]["outbox"]
        self.assertEqual(rows[0][1], (2, 100, 1000, 0x99, (1, 2, 3)))


class Timeouts(Base):
    def test_one_third_join(self):
        self.assertEqual(self.event(T(2), stakes={0: {1: 10, 2: 10, 3: 10}})[0], "timeout counted")
        self.assertEqual(self.event(T(2), stakes={0: {1: 10, 2: 11, 3: 10}})[0], "timeout counted, joined")
        self.assertEqual(self.event(T(2), stakes={0: {1: 10, 2: 11, 3: 10}}, timed_out=True)[0], "timeout counted")

    def test_strict_two_thirds_builds_a_sorted_tc(self):
        label, got = self.event(T(3), T(2), T(4))
        self.assertEqual(label, "tc formed")
        self.assertIn(("tc", (2, 3, 4), 1000), got["trace"])
        self.assertEqual(got["words"]["timeouts"], 0)
        self.assertEqual(self.event(T(2), T(3), stakes={0: {2: 10, 3: 10, 4: 10}}, timed_out=True)[0], "timeout counted")

    def test_join_product_saturates_and_tc_compare_uses_128_bits(self):
        self.assertEqual(self.event(T(2), stakes={0: {1: 1 << 62, 2: 1 << 63}})[0], "timeout counted, joined")
        self.assertEqual(self.event(T(1), T(2), T(3), stakes={0: {1: 1 << 62, 2: 1 << 62, 3: 1 << 62, 4: 5}}, timed_out=True)[0], "tc formed")

    def test_qc_in_a_timeout_can_drop_the_timeout(self):
        label, got = self.event(T(1, qc=Qc(round=1000, hash=0x65, votes=(1, 2))))
        self.assertEqual(label, "qc in timeout moved round")
        self.assertEqual(got["words"]["timeouts"], 0)
        self.assertNotIn(("propose",), got["trace"])

    def test_bad_qc_is_read_twice_then_refused(self):
        label, got = self.event(T(1), bad_qcs=(0x66,))
        self.assertEqual(label, "timeout bad qc")
        self.assertEqual([row for row in got["trace"] if row[0] == "error"], [("error", 9), ("error", 9)])

    def test_round_and_repeat_tags(self):
        self.assertIn(("error", 0xF), self.event(T(1, round=1001))[1]["trace"])
        self.assertIn(("error", 0x10), self.event(T(1), T(1))[1]["trace"])


class Bytes(Base):
    def test_call_sites(self):
        self.assertEqual(tool.scan_triggers(self.image), len(tool.TRIGGERS))

    def test_call_site_list_with_a_wrong_row_fails(self):
        saved = tool.TRIGGERS
        tool.TRIGGERS = saved[:-1]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.scan_triggers(self.image)
        finally:
            tool.TRIGGERS = saved

    def test_pins_hold_and_corrupted_copy_fails(self):
        self.assertEqual(tool.check_pins(self.image), len(tool.PINS))
        for row in (tool.PINS[0], tool.PINS[30], tool.PINS[-1]):
            with self.assertRaises(tool.EvidenceError):
                tool.check_pins(self.corrupted(row[1]))

    def test_strings_and_slots(self):
        self.assertEqual(tool.check_strings(self.image), tool.STRINGS)
        with self.assertRaises(tool.EvidenceError):
            tool.check_strings(self.corrupted(tool.STRINGS[1][0]))
        self.assertEqual(len(tool.check_slots(self.image)), len(tool.SLOTS))

    def test_slot_with_wrong_target_fails(self):
        saved = tool.SLOTS
        tool.SLOTS = ((saved[0][0], saved[0][1] + 1, "x"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_slots(self.image)
        finally:
            tool.SLOTS = saved

    def test_gate_site_inside_a_row_fails(self):
        saved = tool.GATES
        row = saved[0]
        tool.GATES = ((row[0], row[1], row[2] + 1, row[3], row[4], row[5]),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_gate_sites(self.image)
        finally:
            tool.GATES = saved

    def test_location_paths_are_relative(self):
        for row in tool.check_locations(self.image):
            self.assertFalse(row[2].startswith("/"))

    def test_out_of_range_address(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x7FFFFFFF0000)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.MAYBE_VOTE + 1)

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_a_flipped_condition_is_seen(self):
        case = send("c", voted=1000)
        harness = tool.Harness(self.image, {0x44AABD5: self.image.blob[self.image.offset(0x44AABD5)] ^ 1})
        self.assertFalse(tool.same(harness.run(case), tool.spec_view(tool.spec_run(case)[1])))

    def test_a_changed_window_is_seen(self):
        rows = ((905, None, {0x55: (1,)}),)
        case = Case("c", steps=(V(1), V(2), V(3)), prefill=rows, now=NOW, last_vote=(DAY, 900, 0))
        harness = tool.Harness(self.image, {0x44AFDE7: 0xA2})
        self.assertFalse(tool.same(harness.run(case), tool.spec_view(tool.spec_run(case)[1])))

    def test_rule_list_differs_when_a_rule_is_wrong(self):
        case = send("c")
        got = self.harness.run(case)
        want = tool.spec_view(tool.spec_run(case)[1])
        want["outbox"] = []
        self.assertFalse(tool.same(got, want))


class Packet(Base):
    def test_evidence_matches_a_fresh_run(self):
        result = tool.analyse(self.image, mutate=False)
        files = tool.render(result, self.image)
        for name in ("gates.tsv", "functions.tsv", "pins.tsv", "outcomes.tsv", "cases.tsv", "layouts.tsv", "error-tags.tsv", "triggers.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), files[name], name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
        self.assertTrue(rows)
        names = set()
        for row in rows:
            digest, name = row.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(names, {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"})

    def test_summary_counts(self):
        summary = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        self.assertEqual(summary["sha256"], tool.SHA256)
        self.assertEqual(summary["pins"], len(tool.PINS))
        self.assertEqual(summary["mutations"]["killed"] + summary["mutations"]["survived"], summary["mutations"]["total"])
        self.assertGreaterEqual(summary["cases"], 700)


if __name__ == "__main__":
    unittest.main()
