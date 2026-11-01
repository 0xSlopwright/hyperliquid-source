import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_core_writer as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-core-writer-path-94"


class Shared:
    image = None
    harness = None
    cases = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Loop(Shared.image)
    Shared.cases = {case.name: case for case in tool.all_cases()}


def run_one(name, patches=None):
    harness = tool.Loop(Shared.image, patches) if patches else Shared.harness
    return tool.run_case(harness, Shared.cases[name])


def differs(name, patches):
    try:
        return run_one(name, patches) != tool.spec_run(Shared.cases[name])
    except (tool.Panicked, tool.Halt, tool.EvidenceError):
        return True


def flip(va, bit=1):
    return {va: Shared.image.blob[Shared.image.offset(va)] ^ bit}


class Spec(unittest.TestCase):
    def assert_group(self, *prefixes):
        names = [name for name in Shared.cases if name.startswith(prefixes)]
        self.assertTrue(names)
        for name in names:
            self.assertEqual(run_one(name), tool.spec_run(Shared.cases[name]), name)

    def test_arms(self):
        self.assert_group("arm_")

    def test_order_rows(self):
        self.assert_group("order_")

    def test_enums(self):
        self.assert_group("finalize_", "cancel_", "send_", "bole_", "abstraction_")

    def test_wallet(self):
        self.assert_group("wallet_")

    def test_header_and_log(self):
        self.assert_group("raw_", "version_", "action_", "log_")

    def test_sender_sets(self):
        self.assert_group("disabled_", "banned_", "blocked_", "unknown_", "known_")

    def test_writer_three_copies(self):
        self.assert_group("writer_")

    def test_row_loop(self):
        self.assert_group("loop_")

    def test_seeded_vectors(self):
        for case in tool.vector_cases(40):
            self.assertEqual(tool.run_case(Shared.harness, case), tool.spec_run(case), case.name)


class Rules(unittest.TestCase):
    def test_topic_is_keccak_of_text(self):
        self.assertEqual(tool.keccak(b"RawAction(address,bytes)"), tool.TOPIC0)

    def test_keccak_empty(self):
        self.assertEqual(tool.keccak(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_staking_arms(self):
        delegate = run_one("arm_3_good")
        self.assertEqual(delegate[0], "row")
        self.assertEqual(delegate[1], 3)
        self.assertEqual(delegate[2][0][2], tool.struct.pack("<Q", 0x95).hex())
        self.assertEqual(run_one("arm_4_good")[2][0][2], tool.struct.pack("<Q", 0xB2).hex())
        self.assertEqual(run_one("arm_5_good")[2][0][2], tool.struct.pack("<Q", 0xB1).hex())

    def test_extra_topic_accepted(self):
        self.assertEqual(run_one("log_three_topics")[0], "row")

    def test_dirty_user_topic_accepted(self):
        self.assertEqual(run_one("log_user_top_byte")[0], "row")

    def test_trailing_bytes_refused(self):
        for action in (3, 4, 5):
            self.assertEqual(run_one("arm_%d_extra_1" % action)[0], "drop")
            self.assertEqual(run_one("arm_%d_extra_32" % action)[0], "drop")

    def test_bool_low_byte_any_value(self):
        got = run_one("arm_3_bool_2_two")
        self.assertEqual(got[0], "row")
        self.assertEqual(got[2][-1][2], "01")

    def test_length_edges(self):
        self.assertEqual(run_one("raw_len_1000")[0], "drop")
        self.assertEqual(run_one("raw_pad_1001")[0], "drop")

    def test_writer_inverse_flag(self):
        got = run_one("writer_0_disable_hits")
        self.assertEqual(got[1], ((1, 4),))
        self.assertEqual(got[2], "drop")
        self.assertEqual(run_one("writer_0_disable_then_enable")[2], "row")

    def test_writer_bound(self):
        got = run_one("writer_1_id_limit")
        self.assertEqual(got[0], ((0x13F, tool.LIMIT),))

    def test_loop_system_sender(self):
        native = run_one("loop_native_token")
        other = run_one("loop_native_other")
        self.assertEqual(native[1][0][5], "22" * 20)
        self.assertTrue(other[1][0][5].startswith("20" + "00" * 11))

    def test_loop_sentinel_stops(self):
        got = run_one("loop_sentinel_second")
        self.assertEqual(got[-1], 1)
        self.assertEqual(sum(1 for item in got[1] if item[0] == "delay"), 1)


class Negative(unittest.TestCase):
    def test_detects_address_compare(self):
        self.assertTrue(differs("arm_4_good", flip(0x333B2D8 + 1, 1)))

    def test_detects_version_compare(self):
        self.assertTrue(differs("version_2", {0x333B4E6: 0x02}))

    def test_detects_action_bound(self):
        self.assertTrue(differs("action_0x11", {0x333B4F3: 0x10}))

    def test_detects_tag_change(self):
        self.assertTrue(differs("arm_3_good", {0x333BA2C: 0x96}))

    def test_detects_tif_map(self):
        self.assertTrue(differs("order_tif_2", {0x333B5B1: 0x03}))

    def test_detects_gate_swap(self):
        self.assertTrue(differs("banned_sender", flip(0x333BF1B + 1, 1)))

    def test_detects_row_push_size(self):
        self.assertTrue(differs("arm_4_good", {0x333BF90: 0x10}))

    def test_detects_sentinel(self):
        self.assertTrue(differs("loop_sentinel_second", {0x2761603: 0xCD}))

    def test_wrong_spec_refused(self):
        case = Shared.cases["arm_3_good"]
        other = tool.Case(case.name, case.kind, dict(case.world, chain=9))
        self.assertNotEqual(tool.run_case(Shared.harness, case), tool.spec_run(other))

    def test_corrupt_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_out_of_range_address_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_pin_mismatch_refused(self):
        saved = tool.PINS
        tool.PINS = (("bad", 0x333B37D, "00", "bad"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(Shared.image)
        finally:
            tool.PINS = saved

    def test_tag_site_mismatch_refused(self):
        saved = tool.TAG_SITES[4]
        tool.TAG_SITES[4] = saved + 1
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.arm_rows(Shared.image)
        finally:
            tool.TAG_SITES[4] = saved

    def test_no_external_tools(self):
        text = (pathlib.Path(tool.__file__)).read_text()
        for word in ("subprocess", "objdump", "readelf"):
            self.assertEqual(text.count("import " + word), 0)
            self.assertNotIn(word + "(", text)


class Tables(unittest.TestCase):
    def test_arm_rows(self):
        rows = tool.arm_rows(Shared.image)
        self.assertEqual(len(rows), 16)
        self.assertEqual(rows[2][2:4], ("0x333b9c9", "0x95"))
        self.assertEqual(rows[3][2:4], ("0x333babb", "0xb2"))
        self.assertEqual(rows[4][2:4], ("0x333b7f8", "0xb1"))


class Files(unittest.TestCase):
    def test_manifest(self):
        lines = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_summary(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_scenarios"], len(Shared.cases))
        self.assertGreater(data["mutations"]["killed"], 0)

    def test_regeneration_without_mutants(self):
        result = tool.analyse(Shared.image, mutate=False, vectors=5, cases=list(Shared.cases.values())[:12])
        files = tool.render(result)
        self.assertEqual(files["constants.tsv"], (FOLDER / "constants.tsv").read_text())
        self.assertEqual(files["arms.tsv"], (FOLDER / "arms.tsv").read_text())


if __name__ == "__main__":
    unittest.main()
