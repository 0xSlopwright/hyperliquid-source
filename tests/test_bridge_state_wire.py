import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_state_wire as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "bridge-state-wire-94"


def one(harness, state, named=1, mode=0):
    return harness.serialize(tool.Case("x", state, named, mode))


class Image(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(tool.BINARY.read_bytes()).hexdigest(), tool.SHA256)
        self.assertEqual(tool.SHA256, "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")

    def test_function_outside_any_body_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image().exact_fde(tool.ROOT_RMP + 1)


class Wire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def test_named_head_and_order(self):
        data = bytes.fromhex(one(self.harness, tool.State())[1])
        self.assertEqual(data[:9], b"\xa7bridge2\x8a")
        at = [data.index(name.encode()) for name in tool.FIELD_ORDER]
        self.assertEqual(at, sorted(at))

    def test_array_form_has_no_key(self):
        data = bytes.fromhex(one(self.harness, tool.State(), 0)[1])
        self.assertEqual(data[0], 0x9A)
        self.assertNotIn(b"bridge2", data)

    def test_full_state_matches_the_rule_list(self):
        for named in (1, 0):
            case = tool.Case("full", tool.full_state(), named)
            self.assertEqual(self.harness.serialize(case), tool.spec_run(case))

    def test_noop_policy_is_an_empty_array_even_named(self):
        data = bytes.fromhex(one(self.harness, tool.State())[1])
        self.assertIn(b"\xa3hsc\x90", data)

    def test_vote_row_of_a_set_is_a_pair_with_nil(self):
        data = bytes.fromhex(one(self.harness, tool.full_state())[1])
        self.assertIn(b"\xc0\xa3hvs", data)

    def test_time_text(self):
        self.assertEqual(tool.time_shape((2024, 60, 86399, 0)), "2024-02-29T23:59:59")
        self.assertEqual(tool.time_shape((2023, 4, 3599, 1500000000)), "2023-01-04T00:59:60.500")

    def test_no_voter_row_panics_with_the_type_name(self):
        state = tool.State(sig=[tool.sign_row(inner=[((1, tool.USER), [], "novoter")])])
        self.assertEqual(one(self.harness, state), ("panic", tool.NO_VOTER_TEXT))
        self.assertIn("hard_quorum_policy::NoVoter", tool.NO_VOTER_TEXT)

    def test_edited_status_byte_is_seen(self):
        at = 0x393C2BC
        row = tool.row_at(self.image, at)
        data = bytes(self.image.blob[self.image.offset(at):self.image.offset(at) + row.size])
        harness = tool.Harness(self.image, {at + row.imm_at: data[row.imm_at] ^ 1})
        case = tool.Case("x", tool.State(dep=[tool.deposit_row()]), 1)
        self.assertNotEqual(harness.serialize(case), tool.spec_run(case))

    def test_wrong_rule_is_caught(self):
        case = tool.Case("x", tool.State(), 1)
        bad = tool.De("x", b"\xc0", ("error", 6, "other text"))
        with self.assertRaises(tool.EvidenceError):
            tool.check_all(self.harness, [bad])
        self.assertTrue(tool.check_all(self.harness, [case]))


class Decode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def run_case(self, data):
        return self.harness.decode(tool.De("x", data, None))

    def test_round_trip_both_forms(self):
        state = tool.full_state()
        self.assertEqual(self.run_case(tool.wire(state)), tool.ok(state))
        self.assertEqual(self.run_case(tool.wire(state, 0)), tool.ok(state))

    def test_five_required_fields(self):
        self.assertEqual(self.run_case(b"\x80"), ("error", 6, "missing field `eth_id_to_deposit_votes`"))
        rows = [row for row in tool.field_rows(tool.State()) if row[0] != "validator_set_signatures"]
        self.assertEqual(self.run_case(tool.pack(tool.Pairs(*rows), 1)), ("error", 6, "missing field `validator_set_signatures`"))

    def test_short_array_names_the_next_required_index(self):
        rows = tool.field_rows(tool.State())
        self.assertEqual(self.run_case(tool.pack(tool.Pairs(*rows[:1]), 0)), ("error", 6, tool.ARRAY_TEXT % 2))
        self.assertEqual(self.run_case(tool.pack(tool.Pairs(*rows[:7]), 0))[0], "ok")

    def test_repeat_key_is_refused(self):
        key = (5, 9, 0, 1, tool.DIGEST)
        data = tool.wire(tool.State(dep=[tool.deposit_row(key), tool.deposit_row(key)]))
        self.assertEqual(self.run_case(data), ("error", 6, "duplicate key"))

    def test_rows_are_sorted_by_key_type(self):
        state = tool.State(times=[((9, tool.USER), tool.MOMENT), ((2, tool.USER), tool.MOMENT), ((1, tool.OTHER), tool.MOMENT)])
        self.assertEqual(self.run_case(tool.wire(state)), tool.ok(state))

    def test_negative_control_wrong_order_is_not_equal(self):
        state = tool.State(times=[((9, tool.USER), tool.MOMENT), ((2, tool.USER), tool.MOMENT)])
        self.assertNotEqual(self.run_case(tool.wire(state)), ("ok", tool.pack(tool.bridge_shape(state), 0).hex()))


class MultiplyOverflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def test_native_decimal_imul_drives_jo(self):
        # These instruction starts/bytes were checked against native objdump.
        for va in (0x1515000, 0x151A6FF):
            imul = tool.row_at(self.image, va)
            jump = tool.row_at(self.image, imul.next)
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

    def test_wrapping_year_is_rejected_by_all_decoder_copies(self):
        rows = tool.field_rows(tool.State())
        for entry in (tool.DECODE_ROOT,) + tool.DECODE_COPIES:
            for year in (2**64, 2**64 + 1, 2**64 + 2023):
                text = f"+{year}-11-14T22:13:20"
                fields = tool.tracker_edit(rows, "finished_withdrawal_to_time",
                                          lambda _: [[tool.un_shape((55, tool.USER)), text]])
                case = tool.De("wrapping_year", tool.pack(tool.Pairs(*fields), 1), None, entry)
                with self.subTest(entry=hex(entry), year=year):
                    self.assertEqual(tool.Harness(self.image).decode(case),
                                     ("error", 6, "input is out of range"))

    def test_valid_explicit_year_retains_its_value(self):
        state = tool.State(times=[((55, tool.USER), (2023, 318, 80000, 0))])
        fields = tool.tracker_edit(tool.field_rows(tool.State()), "finished_withdrawal_to_time",
                                  lambda _: [[tool.un_shape((55, tool.USER)), "+2023-11-14T22:13:20"]])
        case = tool.De("valid_year", tool.pack(tool.Pairs(*fields), 1), None)
        self.assertEqual(tool.Harness(self.image).decode(case), tool.ok(state))


class Stored(unittest.TestCase):
    def test_manifest_matches_files(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_regenerated_light_files_match(self):
        image = tool.load_image()
        for name, rows in (("fields.tsv", tool.field_table(image)), ("texts.tsv", tool.text_rows(image)), ("key-rows.tsv", tool.key_rows(image))):
            stored = (FOLDER / name).read_text().splitlines()[1:]
            self.assertEqual(stored, ["\t".join(str(cell) for cell in row) for row in rows], name)


if __name__ == "__main__":
    unittest.main()
