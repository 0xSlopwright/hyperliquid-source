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
        for path in FOLDER.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text()
            for mark in marks:
                self.assertNotIn(mark, text, path.name)


class MultiplyOverflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def test_native_decimal_imul_drives_jo(self):
        # These instruction starts/bytes were checked against native objdump.
        for va in (0x1515000, 0x151A6FF):
            read = lambda at, size: self.image.blob[self.image.offset(at):self.image.offset(at) + size]
            imul = tool.decode(read, va)
            jump = tool.decode(read, imul.next)
            self.assertEqual((imul.op, imul.width), ("imul3" if va == 0x1515000 else "imul2", 8))
            self.assertEqual((jump.op, jump.cc), ("jcc", 0))
            for value in ((2**63 - 1) // 10, (2**63 - 1) // 10 + 1,
                          -(2**63 // 10), -(2**63 // 10) - 1):
                with self.subTest(va=hex(va), value=value):
                    machine = tool.Machine(self.image)
                    if imul.op == "imul3":
                        machine.regs[tool.RSI] = value & tool.MASK[8]
                    else:
                        machine.regs[tool.RAX] = value & tool.MASK[8]
                        machine.regs[tool.R8] = tool.STACK_TOP - 0x40
                        machine.regs[tool.RDX] = 0
                        machine.memory.write(tool.STACK_TOP - 0x40, 8, 10)
                    overflow = not -(2**63) <= value * 10 < 2**63
                    machine.cf = machine.of = not overflow
                    machine.step(imul)
                    self.assertEqual((machine.cf, machine.of), (overflow, overflow))
                    self.assertEqual(machine.step(jump), jump.target if overflow else jump.next)

    def test_signed_imul_operand_widths_and_flag_clearing(self):
        # Independently encoded instructions; only the Python model is run.
        for prefix, width in ((b"\x66", 2), (b"", 4), (b"\x48", 8)):
            for tail, op in ((bytes.fromhex("6bf60a"), "imul3"),
                             (bytes.fromhex("0faff7"), "imul2")):
                raw = prefix + tail + b"\x90" * 16
                ins = tool.decode(lambda va, count: raw[va:va + count], 0)
                self.assertEqual((ins.op, ins.width), (op, width))
                bound = 1 << (8 * width - 1)
                for a, b in ((0, 10), ((bound - 1) // 10, 10),
                             ((bound - 1) // 10 + 1, 10), (-bound, -1)):
                    if op == "imul3" and b != 10:
                        continue
                    with self.subTest(width=width, op=op, a=a, b=b):
                        machine = tool.Machine(self.image)
                        machine.regs[tool.RSI] = a & tool.MASK[width]
                        machine.regs[tool.RDI] = b & tool.MASK[width]
                        overflow = not -bound <= a * b < bound
                        machine.cf = machine.of = not overflow
                        machine.step(ins)
                        self.assertEqual(machine.regs[tool.RSI] & tool.MASK[width], a * b & tool.MASK[width])
                        self.assertEqual((machine.cf, machine.of), (overflow, overflow))

    def test_wrapping_year_is_rejected_by_every_reader(self):
        for form, entries in (("rmp", (tool.DECODE_RMP,) + tool.RMP_COPIES),
                              ("json", (tool.DECODE_JSON,) + tool.JSON_COPIES)):
            for entry in entries:
                for year in (2**64, 2**64 + 1, 2**64 + 2023):
                    state = tool.least_state()
                    state["jail_until"] = [[tool.address(1), f"+{year}-11-14T22:13:20"]]
                    harness = tool.Harness(self.image)
                    if form == "rmp":
                        got = harness.decode_rmp(tool.wire_input(tool.ROOT, state), entry)
                    else:
                        got = harness.decode_json(json.dumps(tool.json_input(tool.ROOT, state)), entry)
                    with self.subTest(form=form, entry=hex(entry), year=year):
                        self.assertEqual(got, ("error", "input is out of range"))

    def test_valid_explicit_year_retains_its_value(self):
        for form, entries in (("rmp", (tool.DECODE_RMP,) + tool.RMP_COPIES),
                              ("json", (tool.DECODE_JSON,) + tool.JSON_COPIES)):
            for entry in entries:
                state = tool.least_state()
                state["jail_until"] = [[tool.address(1), "+2023-11-14T22:13:20"]]
                harness = tool.Harness(self.image)
                if form == "rmp":
                    got = harness.decode_rmp(tool.wire_input(tool.ROOT, state), entry)
                else:
                    got = harness.decode_json(json.dumps(tool.json_input(tool.ROOT, state)), entry)
                with self.subTest(form=form, entry=hex(entry)):
                    self.assertEqual(got, ("ok",))
                    self.assertIn('"2023-11-14T22:13:20"', harness.text("  "))


if __name__ == "__main__":
    unittest.main()
