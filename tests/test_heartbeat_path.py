"""Tests for tools/heartbeat_path.py: rule list, byte pins and negative controls on corrupted copies."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import heartbeat_path as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-008-heartbeat-path-94"
Case, Sig, Snap, Exec, Beat, Ack = tool.Case, tool.Sig, tool.Snap, tool.Exec, tool.Beat, tool.Ack
BIG = tool.BIG
SNAP = Snap(stakes=BIG, jailed=frozenset(), lt=9, evm=33)
OTHER = Snap(stakes={1: 10, 2: 10, 3: 10, 4: 11}, jailed=frozenset(), lt=9, evm=33)

IMAGE = tool.load_image()


class Base(unittest.TestCase):
    image = IMAGE
    harness = tool.Harness(IMAGE)

    def run_case(self, *steps, **extra):
        case = Case("c", steps, **extra)
        label, model = tool.spec_run(case)
        got = self.harness.run(case)
        self.assertEqual(tool.differ(got, tool.spec_view(model)), {}, label)
        return label, got

    def corrupted(self, va, delta=1):
        blob = bytearray(self.image.blob)
        blob[self.image.offset(va)] ^= delta
        return tool.Image(bytes(blob))

    def beats(self, *signers, snap=SNAP, round=5000, **extra):
        return self.run_case(*[Beat(signer, round, snap=snap) for signer in signers], **extra)


class Send(Base):
    def test_first_heartbeat_has_snapshot_and_seen_map(self):
        label, got = self.run_case(Exec(5000, lt=4, evm=12), seen_rounds={2: 8})
        self.assertEqual(label, "sent with snapshot")
        row = got["outbox"][0]
        self.assertEqual(row[1:3], (1, ((2, 8),)))
        self.assertEqual(row[3][1:], (4, 12))
        self.assertEqual(got["last_sent"], 5000)
        self.assertEqual(got["last_snap"], 5000)

    def test_ten_block_uses_floor_division_not_distance(self):
        self.assertEqual(self.run_case(Exec(5009), last_sent=5000, last_snap=5000)[0], "same ten block")
        self.assertEqual(self.run_case(Exec(5010), last_sent=5009, last_snap=5000)[0], "sent")

    def test_hundred_block_uses_floor_division(self):
        self.assertEqual(self.run_case(Exec(5100), last_sent=5099, last_snap=5099)[0], "sent with snapshot")
        self.assertEqual(self.run_case(Exec(5199), last_sent=5100, last_snap=5100)[0], "sent")

    def test_no_peer_map_without_a_snapshot(self):
        _, got = self.run_case(Exec(5010), last_sent=5000, last_snap=5000, seen_rounds={2: 8})
        self.assertEqual(got["outbox"][0][1:4], (0, None, None))

    def test_qc_lag_limit_is_inclusive_and_keeps_last_sent(self):
        self.assertEqual(self.run_case(Exec(4000), highest=5000)[0], "sent with snapshot")
        label, got = self.run_case(Exec(3999), highest=5000, last_sent=3980, last_snap=3900)
        self.assertEqual(label, "execution behind qc")
        self.assertEqual(got["last_sent"], 3980)
        self.assertEqual(got["trace"], [("log", "behind")])

    def test_lag_limit_saturates(self):
        self.assertEqual(self.run_case(Exec(tool.MAX_ROUND - 500), highest=tool.MAX_ROUND)[0], "sent with snapshot")

    def test_member_gate_is_silent(self):
        label, got = self.run_case(Exec(5000), stakes={0: {2: 1}})
        self.assertEqual(label, "not in stake set")
        self.assertEqual((got["trace"], got["outbox"], got["last_sent"]), ([], [], None))

    def test_no_stake_set_is_tag_0x28(self):
        self.assertEqual(self.run_case(Exec(5000), stakes={tool.FAR: {1: 1}})[1]["trace"], [("error", 0x28)])

    def test_missing_jail_row_leaves_none_in_the_snapshot(self):
        _, got = self.run_case(Exec(5000), jailed={})
        self.assertEqual(got["outbox"][0][3][0][1], None)
        self.assertIn(("error", 0x28), got["trace"])

    def test_sent_row_is_replaced_at_the_same_round(self):
        _, got = self.run_case(Exec(5010), sent={5010: (0x77, {2: (1, 1, 1)})}, last_sent=5000, last_snap=5000)
        self.assertEqual(got["sent"][5010], (0xABC0, (7, 8, 9), {}))

    def test_first_round_is_written_once(self):
        self.assertEqual(self.run_case(Exec(5000), Exec(5010))[1]["first"], 5000)
        self.assertEqual(self.run_case(Exec(5000), first=4)[1]["first"], 4)


class Tail(Base):
    def test_own_round_is_stored_even_with_no_send(self):
        label, got = self.run_case(Exec(5001, lt=5, evm=6), last_sent=5000, last_snap=5000)
        self.assertEqual(label, "same ten block")
        self.assertEqual(got["own"][5001], (6, 5))

    def test_own_ring_limit(self):
        self.assertEqual(sorted(self.run_case(Exec(5001), last_sent=5000, last_snap=5000, own=(4997, 4998, 4999), limit=3)[1]["own"]), [4998, 4999, 5001])

    def test_buffer_goes_at_or_under_round_without_any_read(self):
        got = self.run_case(Exec(5001), last_sent=5000, last_snap=5000, buffered={4990: [(1, 2, 3)], 5001: [(1, 2, 3)], 5002: [(1, 3, None)]})[1]
        self.assertEqual(sorted(got["buffered"]), [5002])

    def test_buffer_is_only_written_read_for_discard(self):
        rows = tool.scan_fields(self.image)
        dispatcher = [row for row in rows if row[0] in (0xA98, 0xAA0) and row[2] == tool.DISPATCH]
        self.assertEqual([row[1] for row in dispatcher], [0x44AF94E, 0x44B087B, 0x44B08FE])


class Receive(Base):
    def test_plain_beat_acks_to_the_sender(self):
        label, got = self.run_case(Beat(2, 5000, random=0xFFFFFFFF))
        self.assertEqual(label, "beat no snapshot, ack")
        self.assertEqual(got["outbox"][0][:4], ("ack", 5000, tool.SELF, 0xFFFFFFFF))
        self.assertEqual(got["outbox"][0][5], 2)

    def test_no_ack_when_not_a_member(self):
        self.assertEqual(self.run_case(Beat(2, 5000), stakes={0: {2: 1}})[0], "beat no snapshot, no ack")

    def test_seen_keeps_the_maximum(self):
        self.assertEqual(self.run_case(Beat(2, 5000), seen_rounds={2: 6000})[1]["seen"][2], 6000)
        self.assertEqual(self.run_case(Beat(2, 5000), seen_rounds={2: 4000})[1]["seen"][2], 5000)

    def test_peer_map_replaced_not_merged(self):
        got = self.run_case(Beat(2, 5000, peers={3: 8}), Beat(2, 5001, peers={4: 9}))[1]
        self.assertEqual(got["peers"][2], ((4, 9),))
        self.assertEqual(self.run_case(Beat(2, 5000, peers={3: 8}), Beat(2, 5001))[1]["peers"][2], ((3, 8),))

    def test_refused_signatures_touch_nothing(self):
        for sig in (Sig(broken=True), Sig(by=3), Sig(good=False)):
            label, got = self.run_case(Beat(2, 5000, peers={3: 1}, sig=sig))
            self.assertEqual(label, "beat refused: bad")
            self.assertEqual((got["seen"], got["peers"], got["outbox"], got["trace"]), ({}, {}, [], [("error", 1)]))

    def test_buffer_only_when_round_unknown(self):
        self.assertEqual(self.beats(2)[1]["buffered"], {5000: [(33, 2, 9)]})
        self.assertEqual(self.beats(2, own=(5000,))[1]["buffered"], {})

    def test_jailed_now_is_counted_nowhere_but_acked(self):
        label, got = self.beats(2, jailed={0: frozenset((2,))})
        self.assertEqual(label, "jailed sender, ack")
        self.assertEqual(got["tracker"], {})
        self.assertEqual(got["outbox"][0][0], "ack")

    def test_jail_gate_reads_the_current_round(self):
        late = {0: frozenset(), 4900: frozenset((2,))}
        self.assertEqual(self.run_case(Beat(2, 4000, snap=SNAP), jailed=late, current=5100)[0], "jailed sender, ack")
        self.assertEqual(self.run_case(Beat(2, 6000, snap=SNAP), jailed=late, current=4000)[0], "counted, ack")


class Tracker(Base):
    def test_strict_two_thirds_decides(self):
        self.assertEqual(self.beats(2, 3, stakes={0: {1: 10, 2: 10, 3: 10}})[0], "counted, ack")
        self.assertEqual(self.beats(2, 3, stakes={0: {1: 9, 2: 10, 3: 10}})[0], "decided, ack")

    def test_stake_never_adds_across_keys(self):
        got = self.run_case(Beat(2, 5000, snap=SNAP), Beat(3, 5000, snap=OTHER), Beat(4, 5000, snap=SNAP))[1]
        self.assertEqual(got["tracker"][5000][0], 0)

    def test_key_is_stakes_and_jail_only(self):
        items = [Beat(2, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), lt=1, evm=1)), Beat(3, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), lt=2, evm=2)), Beat(4, 5000, snap=Snap(stakes=BIG, jailed=frozenset(), evm=3))]
        self.assertEqual(self.run_case(*items)[0], "decided, ack")

    def test_snapshot_unlike_the_local_table_still_decides(self):
        self.assertEqual(self.beats(2, 3, 4, snap=OTHER)[0], "decided, ack")
        self.assertEqual(self.beats(2, 3, 4, snap=Snap())[0], "decided, ack")

    def test_floor_gate(self):
        self.assertEqual(self.beats(2, floor=5001)[0], "under floor, ack")
        self.assertEqual(self.beats(2, floor=5000)[0], "counted, ack")

    def test_prune_and_floor(self):
        key = SNAP.key()
        got = self.run_case(Beat(4, 5000, snap=SNAP), prefill={3999: (None, {}), 4000: (None, {}), 5000: (None, {key: (2, 3)})})[1]
        self.assertEqual(sorted(got["tracker"]), [4000, 5000])
        self.assertEqual(got["floor"], 4000)
        got = self.run_case(Beat(4, 5000, snap=SNAP), prefill={5000: (None, {key: (2, 3)})}, floor=4500)[1]
        self.assertEqual(got["floor"], 4500)

    def test_only_a_decision_prunes(self):
        got = self.beats(2, prefill={1: (None, {})})[1]
        self.assertEqual((sorted(got["tracker"]), got["floor"]), ([1, 5000], None))

    def test_slot_with_quorum_before_decision_stays_open(self):
        key = SNAP.key()
        got = self.run_case(Beat(2, 5000, snap=SNAP), prefill={5000: (None, {key: (3, 4, 9)})}, stakes={0: {1: 1, 2: 1, 3: 10, 4: 10}})[1]
        self.assertEqual(got["tracker"][5000][0], 0)

    def test_overflow_panics_after_the_slot_exists(self):
        label, got = self.beats(2, stakes={0: {1: 1, 2: tool.MAX_ROUND}})
        self.assertEqual(label, "stake overflow")
        self.assertEqual(got["panic"], "panic")


class AckPath(Base):
    def test_round_and_random_must_match(self):
        sent = {5000: (0x51, {})}
        self.assertEqual(self.run_case(Ack(2, 5000), sent=sent)[0], "ack stored")
        self.assertEqual(self.run_case(Ack(2, 5000, random=0x52), sent=sent)[0], "ack other random")
        self.assertEqual(self.run_case(Ack(2, 5001), sent=sent)[0], "ack no row")

    def test_repeat_ack_replaces_time(self):
        self.assertEqual(self.run_case(Ack(2, 5000), sent={5000: (0x51, {2: (1, 2, 3)})})[1]["sent"][5000][2], {2: (7, 8, 9)})

    def test_bad_ack_stores_nothing(self):
        got = self.run_case(Ack(2, 5000, sig=Sig(by=3)), sent={5000: (0x51, {})})[1]
        self.assertEqual((got["sent"][5000][2], got["trace"]), ({}, [("error", 1)]))
        self.assertEqual(self.run_case(Ack(9, 5000), sent={5000: (0x51, {})})[0], "ack refused: bad")

    def test_full_round_trip_with_the_drawn_random(self):
        got = self.run_case(Exec(5000), Ack(2, 5000, random=0xABC0))[1]
        self.assertEqual(got["sent"][5000][2], {2: (7, 8, 9)})


class Bytes(Base):
    def test_digest_and_size(self):
        self.assertEqual(hashlib.sha256(self.image.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(b"not the binary")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path)

    def test_pin_corruption_is_seen(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_pins(self.corrupted(tool.PINS[0][1]))

    def test_every_pin_group_binds(self):
        self.assertEqual(tool.check_pins(self.image), len(tool.PINS))

    def test_slot_table_binds(self):
        self.assertEqual(len(tool.check_slots(self.image)), len(tool.SLOTS))
        saved = tool.SLOTS
        tool.SLOTS = ((saved[0][0], saved[0][1] + 1, "wrong target"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.check_slots(self.image)
        finally:
            tool.SLOTS = saved

    def test_string_corruption_is_seen(self):
        with self.assertRaises(tool.EvidenceError):
            tool.check_strings(self.corrupted(tool.STRINGS[0][0] + 3))

    def test_dispatch_corruption_is_seen(self):
        self.assertEqual(len(tool.read_dispatch(self.image)), len(tool.DISPATCH_TAGS))
        with self.assertRaises(tool.EvidenceError):
            tool.read_dispatch(self.corrupted(tool.INNER_TABLE + 4 * 8))

    def test_call_site_corruption_is_seen(self):
        self.assertEqual(tool.scan_triggers(self.image), len(tool.TRIGGERS))
        with self.assertRaises(tool.EvidenceError):
            tool.scan_triggers(self.corrupted(tool.TRIGGERS[0][1] + 1))

    def test_out_of_range_address(self):
        with self.assertRaises((tool.EvidenceError, KeyError, IndexError)):
            self.image.offset(0x10)

    def test_mutated_branch_is_caught(self):
        harness = tool.Harness(self.image, {0x44AF1C5 + 1: self.image.blob[self.image.offset(0x44AF1C5 + 1)] ^ 1})
        case = Case("c", [Exec(4000)], highest=5000)
        self.assertFalse(tool.same(harness.run(case), tool.spec_view(tool.spec_run(case)[1])))

    def test_vectors_are_stable(self):
        names = [case.name for case in tool.vector_cases(3)]
        self.assertEqual(names, ["vector 0", "vector 1", "vector 2"])
        left, right = tool.vector_cases(5), tool.vector_cases(5)
        self.assertEqual([len(case.steps) for case in left], [len(case.steps) for case in right])


class Evidence(Base):
    def test_named_cases_match(self):
        rows = tool.check_all(self.harness, tool.named_cases())
        self.assertEqual(len(rows), len(tool.named_cases()))

    def test_gate_outcomes_reached(self):
        labels = {tool.spec_run(case)[0] for case in tool.named_cases()}
        for row in tool.GATES:
            if row[5]:
                self.assertIn(row[5], labels, row[3])

    def test_generated_summary(self):
        data = json.loads((FOLDER / "evidence.json").read_text(encoding="ascii"))
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["pins"], len(tool.PINS))
        self.assertEqual(data["gates"], len(tool.GATES))
        self.assertEqual(data["named_cases"], len(tool.named_cases()))

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
