import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import staking_vote_quorum as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-vote-quorum-94"


class Shared:
    image = None
    harness = None
    cases = None


def setUpModule():
    Shared.image = tool.load_image()
    tool.load_image.cached = Shared.image
    Shared.harness = tool.Votes(Shared.image)
    Shared.cases = {case.name: case for case in tool.all_cases()}


def run_one(name, patches=None):
    harness = tool.Votes(Shared.image, patches) if patches else Shared.harness
    return tool.run_case(harness, Shared.cases[name])


def differs(name, patches):
    try:
        return run_one(name, patches) != tool.spec_run(Shared.cases[name])
    except (tool.Panicked, tool.Halt, tool.EvidenceError):
        return True


class Spec(unittest.TestCase):
    def assert_group(self, *prefixes):
        names = [name for name in Shared.cases if name.startswith(prefixes)]
        self.assertTrue(names)
        for name in names:
            self.assertEqual(run_one(name), tool.spec_run(Shared.cases[name]), name)

    def test_first_host(self):
        self.assert_group("h0_")

    def test_second_host(self):
        self.assert_group("h1_")

    def test_third_host(self):
        self.assert_group("h2_")

    def test_gates(self):
        self.assert_group("g0_", "g1_", "g2_")

    def test_seeded_vectors(self):
        for case in tool.vector_cases(30):
            self.assertEqual(tool.run_case(Shared.harness, case), tool.spec_run(case), case.name)


class Rules(unittest.TestCase):
    def test_stake_rule_is_strict(self):
        world = tool.world_of(stakes={b"a": 2, b"b": 1})
        self.assertFalse(tool.stake_passes(world, [b"a"]))
        self.assertTrue(tool.stake_passes(world, [b"a", b"b"]))

    def test_listed_addresses(self):
        self.assertEqual(tool.world_of()["listed"], {tool.low_address(1), tool.low_address(2), tool.low_address(3)})
        self.assertEqual(tool.world_of(chain=0)["listed"], set(tool.OTHER_LISTED))

    def test_refused_voter(self):
        self.assertEqual(run_one("h0_unknown_refused")[0], ((0x91,),))

    def test_pass_empties_other_votes(self):
        got = run_one("h0_pass_clears_other_votes")
        self.assertEqual(got[0][6], (0x186, 1))
        self.assertIsNone(got[2][6])
        self.assertEqual(got[2][7][2][0][1], (tool.key32(7).hex()[-4:],))

    def test_refused_apply_still_pops(self):
        got = run_one("h0_apply_refused")
        self.assertEqual(got[0][-1], (0x143,))
        self.assertIsNone(got[2][-1])

    def test_fast_action_ignores_threshold(self):
        self.assertEqual(run_one("h0_fast_32_4_threshold")[0][-1], (0x186, 1))
        self.assertEqual(run_one("h0_plain_threshold_same_votes")[0][-1], (0x186, 0))
        self.assertTrue(tool.fast_action((0x5C, 1)))
        self.assertFalse(tool.fast_action((0x5C, 0)))

    def test_vote_kept_after_threshold_wait(self):
        got = run_one("h0_threshold_two_waits")
        self.assertEqual(got[0][-1], (0x186, 0))
        self.assertEqual(got[2][-1][0], 0)


class Negative(unittest.TestCase):
    def flip(self, va, bit=1):
        return {va: Shared.image.blob[Shared.image.offset(va)] ^ bit}

    def test_harness_detects_gate_flip(self):
        self.assertTrue(differs("h0_five_of_seven_pass", self.flip(0x232A1B2, 1)))

    def test_harness_detects_refuse_text(self):
        self.assertTrue(differs("h0_unknown_refused", {0x270518E: 0x92}))

    def test_harness_detects_threshold_compare(self):
        self.assertTrue(differs("h0_threshold_two_waits", self.flip(0x145A972 + 1, 1)))

    def test_harness_detects_fast_zero_word(self):
        self.assertTrue(differs("h0_fast_32_4_threshold", {0x1EAC00B: 0x48}))

    def test_harness_detects_quorum_and(self):
        self.assertTrue(differs("h0_threshold_two_waits", {0x232972C: 0x08}))

    def test_harness_detects_chain_compare(self):
        self.assertTrue(differs("h0_listed_alone", {0x2704DE3: 0x02}))

    def test_harness_detects_copy_gate_flip(self):
        self.assertTrue(differs("h1_unknown_refused", self.flip(0x4E03F08 + 1, 1)))

    def test_wrong_spec_listed(self):
        case = Shared.cases["h0_listed_alone"]
        other = tool.Case(case.name, case.kind, tool.world_of(chain=0), case.index, case.ops)
        self.assertNotEqual(run_one("h0_listed_alone"), tool.spec_run(other))

    def test_corrupt_digest_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_out_of_range_address_refused(self):
        with self.assertRaises(tool.EvidenceError):
            Shared.image.exact_fde(0x10)

    def test_pin_mismatch_refused(self):
        saved = tool.PINS
        tool.PINS = (("bad", 0x2704DB4, "00", "bad"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.pin_rows(Shared.image)
        finally:
            tool.PINS = saved

    def test_no_external_tools(self):
        text = (pathlib.Path(tool.__file__)).read_text()
        for word in ("subprocess", "objdump", "readelf"):
            self.assertEqual(text.count("import " + word), 0)
            self.assertNotIn(word + "(", text)


class Tables(unittest.TestCase):
    def test_class_rows(self):
        rows = tool.class_rows(Shared.image)
        by_name = {row[5]: row for row in rows}
        self.assertEqual(len(rows), 88)
        self.assertEqual(by_name["VoteGlobalAction"][2], 1)
        self.assertEqual(by_name["SetGlobalAction"][2], 0)
        self.assertEqual(by_name["VoteAppHash"][2], 0)
        self.assertEqual(by_name["SystemBoleAction"][2], 4)

    def test_status_rows(self):
        rows = {row[0]: row[2] for row in tool.status_rows(Shared.image)}
        self.assertEqual(rows["0x91"], "Unknown validator")
        self.assertEqual(rows["0x7b"], "Signer must be a validator.")
        self.assertEqual(rows["0x7d"], "Action not allowed")

    def test_listed_rows(self):
        rows = tool.listed_rows(Shared.harness)
        self.assertEqual(len(rows), 6)
        self.assertEqual({row[4] for row in rows}, {0})
        self.assertEqual({row[5] for row in rows}, {1})


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
        self.assertEqual(files["action-classes.tsv"], (FOLDER / "action-classes.tsv").read_text())
        self.assertEqual(files["listed-sets.tsv"], (FOLDER / "listed-sets.tsv").read_text())


if __name__ == "__main__":
    unittest.main()
