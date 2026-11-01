import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import cstaking_state_wire as tool  # noqa: E402

FOLDER = pathlib.Path(__file__).resolve().parents[1] / "research" / "work-items" / "staking-cstaking-state-wire-94"


class Shared:
    image = None
    harness = None


def setUpModule():
    Shared.image = tool.load_image()
    Shared.harness = tool.Harness(Shared.image)


class RuleList(unittest.TestCase):
    def test_every_rule_case_matches_real_bytes(self):
        cases = tool.rule_cases()
        self.assertGreaterEqual(len(cases), 88)
        tool.check_all(Shared.harness, cases)

    def test_absent_status_keeps_n_in_a_map_and_a_short_array(self):
        cases = [case for case in tool.struct_cases(tool.full_state()) if case.name in ("uniquekeystate_qst_absent", "uniquekeystate_array_1_of_3")]
        self.assertEqual(len(cases), 2)
        tool.check_all(Shared.harness, cases)
        self.assertEqual(cases[1].want, ("error", "invalid length 2, expected struct UniqueKeyState with 3 elements"))

    def test_generated_states_match(self):
        tool.check_all(Shared.harness, tool.vector_cases(4))

    def test_absent_required_field_of_every_struct(self):
        cases = [case for case in tool.struct_cases(tool.full_state()) if case.name.endswith("_array_0_of_2") or case.name.endswith("_absent_json")]
        self.assertGreater(len(cases), 10)
        tool.check_all(Shared.harness, cases)

    def test_commission_default_is_ten_thousand(self):
        rows = dict((row[3], row) for row in tool.field_rows() if row[0] == "CValidatorProfile")
        self.assertIn("10000", rows["commission_bps"][5])

    def test_memory_offsets_after_real_decode(self):
        rows = tool.memory_rows(Shared.harness)
        self.assertEqual(len(rows), len(tool.MEMORY_CHECKS))

    def test_route_word_names_no_human_form(self):
        row = tool.route_row(Shared.image)
        self.assertEqual(row[2], "0x1000400")

    def test_tuple_ip_written_is_refused_on_every_reader(self):
        state = tool.sample_state()
        value = tool.canon(tool.ROOT, state)
        data = tool.emit(tool.ROOT, value, True, False)
        for entry in (tool.DECODE_RMP,) + tool.RMP_COPIES:
            self.assertEqual(Shared.harness.decode_rmp(data, entry), ("error", "invalid type: sequence, expected IPv4 address"))
        data = tool.emit(tool.ROOT, value, True, True)
        for entry in (tool.DECODE_RMP,) + tool.RMP_COPIES:
            self.assertEqual(Shared.harness.decode_rmp(data, entry), ("ok",))


class NegativeControls(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_wrong_rule_is_caught(self):
        case = tool.Case("wrong", tool.least_state(), want=("error", "not this text"))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(Shared.harness, [case])

    def test_changed_key_length_is_caught(self):
        low, high = Shared.image.exact_fde(tool.SERIALIZE_RMP)
        rows = tool.decode_range(Shared.image, low, high)
        row = next(item for item in rows if item.op == "jcc")
        patch = tool.edits_for(Shared.image, [row])[0][2]
        harness = tool.Harness(Shared.image, patch)
        harness.machine.step_limit = tool.MUTANT_STEP_LIMIT
        case = tool.Case("least", tool.least_state())
        hit = tool.first_failure(harness, [case], [tool.spec_run(case)])
        self.assertIsNotNone(hit)

    def test_edit_of_an_out_of_range_address_is_refused(self):
        with self.assertRaises(Exception):
            Shared.image.exact_fde(0x10)

    def test_corrupt_input_does_not_decode(self):
        data = tool.wire_input(tool.ROOT, tool.least_state())
        got = Shared.harness.decode_rmp(data[:40])
        self.assertNotEqual(got, ("ok",))


class Packet(unittest.TestCase):
    def test_evidence_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["state_bytes"], 0x298)
        self.assertGreater(data["named_scenarios"], 400)
        self.assertGreater(data["mutations"]["killed"], 0)

    def test_no_absolute_paths_in_evidence(self):
        marks = ("\x2ftmp", "\x2fhome", "\x2fsrv", "\x2fmnt")
        for path in FOLDER.iterdir():
            text = path.read_text()
            for mark in marks:
                self.assertNotIn(mark, text, path.name)


if __name__ == "__main__":
    unittest.main()
