"""Tests of tools/perp_order_insert.py: real bytes in the evaluator against the specification, with negative controls."""

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "RE-006-perp-order-insert-94"
SPEC = importlib.util.spec_from_file_location("perp_order_insert", ROOT / "tools" / "perp_order_insert.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


CACHE = {}
USER = tool.USERS[0]


def shared(cls):
    if not CACHE:
        CACHE["image"] = tool.load_image()
        CACHE["harness"] = tool.Harness(CACHE["image"])
        CACHE["doc"] = tool.analyse(CACHE["image"], full=False)
    cls.image, cls.harness, cls.doc = CACHE["image"], CACHE["harness"], CACHE["doc"]


def run(harness, world):
    case = tool.Case("test", "test", world)
    return tool.spec_run(case), harness.run(case)


def events(got, name):
    return [row for row in got["log"] if row[0] == name]


def reduce_world(oids, rows, szi=5, **extra):
    return tool.world(tool.book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=rows, positions={USER: tool.long(szi)}, reduce_lists={USER: tool.rlist(oids, extra.pop("cap", None), extra.pop("head", 0))}, **extra)


class Base(unittest.TestCase):
    setUpClass = classmethod(shared)

    def same(self, world):
        expected, got = run(self.harness, world)
        self.assertEqual(tool.normal(expected, got), expected)
        return got

    def flip(self, va, at, kind, world):
        """The patched run must differ from the prediction."""
        machine = self.harness.machine
        machine.patches = tool.mutate_patch(self.image, va, at, kind)
        machine.cache.pop(va, None)
        try:
            return tool.compare_run(self.harness, tool.Case("control", "control", world))
        finally:
            machine.patches = {}
            machine.cache.pop(va, None)


class Identity(Base):
    def test_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "copy"
            path.write_bytes(self.image.blob[:4096])
            with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
                tool.load_image(path)

    def test_wrong_expected_digest(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(tool.BINARY, "0" * 64)

    def test_function_extents(self):
        self.assertEqual(self.image.exact_fde(tool.INSERT), (0x4311140, 0x4314D9F))
        self.assertEqual(self.image.exact_fde(tool.TWIN), (0x4314DA0, 0x43189FF))

    def test_address_inside_is_not_a_start(self):
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.INSERT + 1)

    def test_outside_every_mapping(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(1 << 40)

    def test_nobits_never_maps(self):
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(self.image.named[".bss"]["address"])

    def test_no_mismatch_on_either_body(self):
        self.assertEqual(self.doc["mismatches"], 0)
        self.assertEqual(self.doc["twin_mismatches"], 0)
        self.assertGreater(self.doc["cases"]["total"], 300)

    def test_require_raises_on_other_bytes(self):
        with self.assertRaisesRegex(tool.EvidenceError, "bytes at"):
            tool.require(self.image, 0x431196F, b"\x00\x00", "control")

    def test_stray_word_raises(self):
        with self.assertRaisesRegex(tool.EvidenceError, "reason entry 4"):
            tool.table_rows(self.image, tool.REASON_TABLE, 5, "reason")


class StaticFacts(Base):
    def test_tif_table(self):
        self.assertEqual([row["arm"] for row in self.doc["tif_table"]], ["0x43117c2", "0x43117a3", "0x431182a", "0x43117a3", "0x43117a3"])

    def test_reason_table(self):
        self.assertEqual([row["arm"] for row in self.doc["reason_table"]], ["0x43124c5", "0x431254f", "0x43125c8", "0x4312863"])

    def test_assert_text(self):
        self.assertEqual(self.doc["text"]["value"], "assertion failed: reduce_only")

    def test_statuses(self):
        words = {row["status"] for row in self.doc["status_word_sites"]}
        self.assertEqual(len(words), 7)
        self.assertIn("0x8000000000000015", words)

    def test_status_texts(self):
        rows = {row["tag"]: row["text"] for row in self.doc["status_texts"]}
        self.assertEqual(rows[0x13], "Price too far from oracle")
        self.assertEqual(rows[0x15], "Cross margin currently only supports reduce-only orders")
        self.assertEqual(rows[0x16], "Cross margin disabled")
        self.assertEqual(rows[0x17], "Halted")
        self.assertEqual(rows[5], "Reduce only order would increase position.")

    def test_twin_shape(self):
        twin = self.doc["twin"]
        self.assertEqual(twin["shape_differences"], 0)
        self.assertEqual(twin["different_targets"]["0x431c530"], "0x431d020")
        self.assertIn(["0x1040", "0x5c0"], twin["state_field_pairs"])

    def test_locations_keep_no_root(self):
        for row in self.doc["locations"]:
            self.assertTrue(row["path"].startswith("l1/"), row["path"])


class Gates(Base):
    def test_halted_asset(self):
        got = self.same(tool.world(halted=[tool.ASSET]))
        self.assertEqual(got["result"]["status"], 0x8000000000000017)

    def test_builder_market_mode_zero(self):
        got = self.same(tool.world([], main_byte=1, mode=0, asset=10004))
        self.assertEqual(got["result"]["status"], 0x8000000000000016)

    def test_builder_market_mode_one_needs_reduce(self):
        got = self.same(tool.world([], main_byte=1, mode=1, asset=10004))
        self.assertEqual(got["result"]["status"], 0x8000000000000015)

    def test_listed_flag_passes(self):
        self.assertNotIn("status", self.same(tool.world([], main_byte=1, mode=0))["result"])

    def test_row_tag_passes(self):
        self.assertNotIn("status", self.same(tool.world([], main_byte=1, mode=0, asset=10004, positions={tool.TAKER: {"10004": [1, 0]}}))["result"])

    def test_tif_zero_crossing_at_equal_price(self):
        got = self.same(tool.world(tool.book(0, (1,), [100]), {"tif": 0}))
        self.assertEqual(got["result"]["status"], 0x8000000000000006)
        self.assertEqual(got["result"]["second"], 0x1111)

    def test_taker_only_without_cross(self):
        self.assertEqual(self.same(tool.world([], {"tif": 1}))["result"]["status"], 0x8000000000000008)

    def test_no_size_needs_reduce(self):
        self.assertEqual(self.same(tool.world([], {"tag": 0}))["panic"], "reduce_only text")

    def test_reduce_needs_opposite_position(self):
        self.assertEqual(self.same(tool.world([], {"reduce": 1}, positions={tool.TAKER: tool.long(5)}))["result"]["status"], 0x8000000000000005)

    def test_reduce_clamps_to_position(self):
        got = self.same(tool.world([], {"reduce": 1, "side": 1, "size": 9}, positions={tool.TAKER: tool.long(5)}))
        self.assertEqual(events(got, "first_gate")[0][4], 5)
        self.assertEqual(events(got, "reserve")[0][2:4], [5, 9])

    def test_reduce_without_size_uses_position(self):
        got = self.same(tool.world([], {"reduce": 1, "side": 1, "size": 9, "tag": 0}, positions={tool.TAKER: tool.long(5)}))
        self.assertEqual(events(got, "reserve")[0][2:4], [5, 5])

    def test_price_limit_is_inclusive(self):
        self.assertEqual(events(self.same(tool.world([], {"px": 10 ** 15})), "tick"), [["tick", tool.ASSET]])
        self.assertEqual(self.same(tool.world([], {"px": 10 ** 15 + 10}))["result"]["status"], 1 << 63)

    def test_gates_return_their_words(self):
        got = self.same(tool.world([], first_gate=[0x8000000000000001, 0x12, 0x34]))
        self.assertEqual(got["result"], {"status": 0x8000000000000001, "second": 0x12, "third": 0x34})
        self.assertEqual(self.same(tool.world([], second_gate=[0x8000000000000009, 0x21, 0x43]))["result"]["third"], 0x43)


class Walk(Base):
    def test_walk_order_buy(self):
        got = self.same(tool.world(tool.book(0), {"size": 10, "px": 120}))
        self.assertEqual([row[4] for row in events(got, "match")], [100, 110, 120])

    def test_walk_order_sell(self):
        got = self.same(tool.world(tool.book(1), {"side": 1, "size": 10, "px": 80}))
        self.assertEqual([row[4] for row in events(got, "match")], [100, 90, 80])

    def test_filled_maker_is_removed_after_the_walk(self):
        got = self.same(tool.world(tool.book(0, (2, 2)), {"size": 4, "px": 110, "tif": 3}))
        names = [row[0] for row in got["log"]]
        self.assertLess(names.index("match"), names.index("collect"))
        self.assertEqual([row[1:] for row in events(got, "remove")], [[0x100, tool.USERS[0], 1], [0x101, tool.USERS[1], 1]])

    def test_budget_comes_from_the_match_result(self):
        got = self.same(tool.world([tool.chain(100, [2, 2])], {"size": 5}, match={"0": {"budget": 9}}))
        self.assertEqual(events(got, "match")[1][3], 7)

    def test_band_with_no_fill(self):
        self.assertEqual(self.same(tool.world(tool.book(0), allowed={"100": False}))["result"]["status"], 0x8000000000000013)

    def test_band_with_fill_clears_peer(self):
        got = self.same(tool.world(tool.book(0, (2, 2)), {"oid_tag": 1, "px": 120}, allowed={"110": False}))
        self.assertEqual(events(got, "peer_clear"), [["peer_clear", tool.TAKER, 0x777]])

    def test_status_after_fill_goes_to_next_level(self):
        got = self.same(tool.world([tool.chain(100, [2, 2]), tool.chain(110, [2], 2)], {"size": 9, "px": 120}, match={"0": {"status": [0x8000000000000011, 1, 2]}}))
        self.assertEqual([row[2] for row in events(got, "match")], [0, 2])


class Reasons(Base):
    def test_reason_zero_removes_with_reason_five(self):
        got = self.same(tool.world([tool.chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": 0, "fill": None}}))
        self.assertIn(["remove", 0x200, tool.USERS[0], 5], got["log"])
        self.assertEqual(got["result"]["users"], [[tool.USERS[0], [0x200]]])

    def test_reason_one_is_skip_ten(self):
        got = self.same(tool.world([tool.chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": 1, "fill": None}}))
        self.assertIn(["skip", 0x200, tool.USERS[0], 10], got["log"])

    def test_reason_two_is_skip_nine(self):
        got = self.same(tool.world([tool.chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": 2, "fill": None}}))
        self.assertIn(["skip", 0x200, tool.USERS[0], 9], got["log"])

    def test_reason_three_has_no_row(self):
        got = self.same(tool.world([tool.chain(100, [2, 2])], {"size": 5}, match={"0": {"reason": 3, "fill": None}}))
        self.assertEqual(events(got, "skip"), [])
        self.assertEqual(got["result"]["users"], [])


class Pull(Base):
    def world(self, mode, a=0, b=0, reason=0):
        return tool.world(tool.book(0, (4,)), {"size": 3}, modes={USER: mode}, byte_5b0=a, byte_5b1=b, match={"0": {"reason": reason, "fill": None}})

    def test_class_three_retries(self):
        got = self.same(self.world(3))
        self.assertEqual(events(got, "pull"), [["pull", USER, 0x5150, 1, 1, 0]])
        self.assertEqual(len(events(got, "match")), 2)

    def test_class_four_passes_flag(self):
        self.assertEqual(events(self.same(self.world(4)), "pull")[0][5], 1)

    def test_class_below_three_keeps_reason(self):
        self.assertEqual(events(self.same(self.world(2)), "pull"), [])

    def test_state_bytes_stop_it(self):
        self.assertEqual(events(self.same(self.world(3, 0, 1)), "pull"), [])
        self.assertEqual(events(self.same(self.world(4, 1, 0)), "pull"), [])
        self.assertEqual(len(events(self.same(self.world(3, 1, 0)), "pull")), 1)

    def test_reason_three_never_looks(self):
        self.assertEqual(events(self.same(self.world(3, reason=3)), "user_hash"), [])


class Rest(Base):
    def test_fresh_rest_flag(self):
        self.assertTrue(self.same(tool.world([]))["result"]["fresh_rest"])
        self.assertFalse(self.same(tool.world([], {"oid_tag": 1}))["result"]["fresh_rest"])

    def test_key_sign(self):
        self.assertEqual(events(self.same(tool.world([])), "level")[0][1:], [0, -100])
        self.assertEqual(events(self.same(tool.world([], {"side": 1})), "level")[0][1:], [1, 100])

    def test_rest_gate_no_fills(self):
        self.assertEqual(self.same(tool.world([], may_rest=False))["result"]["status"], 0x8000000000000013)

    def test_reserve_word_with_fills_gives_status_row(self):
        got = self.same(tool.world(tool.book(0, (2,)), reserve=[0x8000000000000007, 1, 2]))
        self.assertEqual(got["book"]["sink"], [[500, tool.TAKER]])

    def test_tail_link(self):
        got = self.same(tool.world([], rest_level=[3, 1], extra_slots=[{"size": 7, "oid": 0x98}, {"size": 1, "oid": 0x96}, {"vacant": True, "oid": 0x97}]))
        self.assertEqual(got["book"]["links"], {"1": 30})

    def test_reduce_rest_joins_the_list(self):
        got = self.same(tool.world([], {"reduce": 1, "side": 1, "size": 2}, positions={tool.TAKER: tool.long(5)}))
        self.assertEqual(events(got, "reduce_push"), [["reduce_push", 500]])

    def test_kind_nine_has_no_row(self):
        got = self.same(tool.world(tool.book(0, (2,)), {"kind": 9, "tif": 3, "size": 2}))
        self.assertEqual(got["book"]["sink"], [])


class ReduceSweep(Base):
    def test_fit_is_left_alone(self):
        got = self.same(reduce_world([0x50, 0x51], [tool.ro(0x50, 2), tool.ro(0x51, 3)]))
        self.assertEqual(got["book"]["deques"], {USER: [0x50, 0x51]})
        self.assertEqual(events(got, "skip"), [])

    def test_order_above_position_is_clamped(self):
        got = self.same(reduce_world([0x50], [tool.ro(0x50, 9)]))
        self.assertEqual(events(got, "set_size")[-1][3], 5)

    def test_limit_word_caps_the_size(self):
        got = self.same(reduce_world([0x50], [tool.ro(0x50, 9, limit=3)]))
        self.assertEqual(events(got, "set_size")[-1][3], 3)

    def test_oldest_goes_first(self):
        got = self.same(reduce_world([0x50, 0x51], [tool.ro(0x50, 1), tool.ro(0x51, 5)]))
        self.assertEqual(events(got, "skip")[-1], ["skip", 0x50, USER, 10])
        self.assertEqual(got["book"]["deques"], {USER: [0x51]})

    def test_oldest_shrinks_when_larger_than_the_excess(self):
        got = self.same(reduce_world([0x50, 0x51], [tool.ro(0x50, 4), tool.ro(0x51, 4)]))
        self.assertEqual(events(got, "set_size")[-1][3], 1)
        self.assertEqual(got["book"]["deques"], {USER: [0x50, 0x51]})

    def test_wrong_side_cancels_at_once(self):
        got = self.same(reduce_world([0x50, 0x51], [tool.ro(0x50, 2, side=0), tool.ro(0x51, 2)]))
        self.assertIn(["skip", 0x50, USER, 10], got["log"])

    def test_flat_position_cancels_all(self):
        got = self.same(reduce_world([0x50, 0x51], [tool.ro(0x50, 2), tool.ro(0x51, 2)], szi=0))
        self.assertEqual([row[1] for row in events(got, "skip")][-2:], [0x50, 0x51])

    def test_unknown_oid_is_dropped_silently(self):
        got = self.same(reduce_world([0x90, 0x50], [tool.ro(0x50, 2)]))
        self.assertEqual(got["book"]["deques"], {USER: [0x50]})
        self.assertEqual(events(got, "skip"), [])

    def test_wrapped_list_keeps_order(self):
        got = self.same(reduce_world([0x50, 0x51, 0x52], [tool.ro(0x50, 1), tool.ro(0x51, 2), tool.ro(0x52, 3)], cap=4, head=3))
        self.assertEqual(events(got, "skip")[-1][1], 0x50)

    def test_only_touched_users_are_swept(self):
        got = self.same(tool.world(tool.book(0, (2,)), {"size": 2, "tif": 3}, extra_slots=[tool.ro(0x50, 3)], positions={USER: tool.long(1)}, reduce_lists={USER: tool.rlist([0x50])}, match={"0": {"reason": 3, "fill": None}}))
        self.assertEqual(got["book"]["deques"], {USER: [0x50]})


class TriggerSweep(Base):
    def world(self, rows, szi, legs):
        return tool.world(tool.book(0, (2,)), {"size": 2, "tif": 3}, positions={USER: tool.long(szi)}, untriggered={USER: rows}, match={"0": {"legs": legs}})

    def test_no_sign_change_no_sweep(self):
        self.assertEqual(events(self.same(self.world([[0x70, 1, 0, 0]], 1, [[1, 0], [1, 5]])), "skip"), [])

    def test_buy_on_long_cancels(self):
        got = self.same(self.world([[0x70, 1, 0, 1], [0x71, 1, 0, 0]], 3, [[0, 0], [1, 1]]))
        self.assertEqual(events(got, "skip")[-1], ["skip", 0x71, USER, 10])

    def test_sell_on_short_cancels(self):
        got = self.same(self.world([[0x70, 1, 0, 1], [0x71, 1, 0, 0]], -3, [[0, 0], [1, 1]]))
        self.assertEqual(events(got, "skip")[-1], ["skip", 0x70, USER, 10])

    def test_flat_cancels_both_sides(self):
        got = self.same(self.world([[0x70, 1, 0, 1], [0x71, 1, 0, 0]], 0, [[0, 0], [1, 1]]))
        self.assertEqual([row[1] for row in events(got, "skip")][-2:], [0x70, 0x71])

    def test_byte_must_be_one(self):
        self.assertEqual(events(self.same(self.world([[0x70, 2, 0, 0]], 3, [[0, 0], [1, 1]])), "skip"), [])


class Controls(Base):
    def test_flip_budget_branch(self):
        row = next(row for row in tool.decode_range(self.image, 0x4312879, 0x431287F) if row.op == "jcc")
        self.assertTrue(self.flip(row.va, 1, "branch", tool.world(tool.book(0))))

    def test_flip_limit_stop(self):
        row = next(row for row in tool.decode_range(self.image, 0x4311E7B, 0x4311E81) if row.op == "jcc")
        self.assertTrue(self.flip(row.va, 1, "branch", tool.world(tool.book(0, (2, 2)), {"size": 40, "px": 100})))

    def test_flip_sweep_excess(self):
        row = next(row for row in tool.decode_range(self.image, 0x4313E48, 0x4313E4E) if row.op == "jcc")
        self.assertTrue(self.flip(row.va, 1, "branch", reduce_world([0x50, 0x51], [tool.ro(0x50, 4), tool.ro(0x51, 4)])))

    def test_flip_trigger_side(self):
        row = next(row for row in tool.decode_range(self.image, 0x4314595, 0x431459B) if row.op == "jcc")
        self.assertTrue(self.flip(row.va, 1, "branch", tool.world(tool.book(0, (2,)), {"size": 2, "tif": 3}, positions={USER: tool.long(3)}, untriggered={USER: [[0x70, 1, 0, 0]]}, match={"0": {"legs": [[0, 0], [1, 1]]}})))

    def test_wrong_status_expected_fails(self):
        world = tool.world(halted=[tool.ASSET])
        expected, got = run(self.harness, world)
        got["result"]["status"] = 0x8000000000000016
        self.assertNotEqual(tool.normal(expected, got), expected)


class Packet(unittest.TestCase):
    def test_manifest(self):
        names = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        rows = [line.split("  ") for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines()]
        self.assertEqual({row[1] for row in rows}, names)
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_manifest_digest_change_is_seen(self):
        row = (FOLDER / "MANIFEST.sha256").read_text().splitlines()[0].split("  ")
        self.assertNotEqual(hashlib.sha256((FOLDER / row[1]).read_bytes() + b"\x00").hexdigest(), row[0])

    def test_evidence_counts(self):
        doc = json.loads((FOLDER / "evidence.json").read_text())
        rows = (FOLDER / "mutations.tsv").read_text().splitlines()[1:]
        self.assertEqual(sum(doc["mutations"].values()), len(rows))
        self.assertEqual(doc["mismatches"], 0)
        self.assertEqual(doc["twin_mismatches"], 0)

    def test_every_open_row_has_a_reason(self):
        for line in (FOLDER / "mutations.tsv").read_text().splitlines()[1:]:
            row = line.split("\t")
            if row[3] != "killed":
                self.assertTrue(row[5], line)


if __name__ == "__main__":
    unittest.main()
