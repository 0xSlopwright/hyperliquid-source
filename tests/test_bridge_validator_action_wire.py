"""Tests for tools/bridge_validator_action_wire.py: rule list against real bytes, and negative controls."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bridge_validator_action_wire as tool  # noqa: E402


FOLDER = ROOT / "research" / "work-items" / "bridge-validator-action-wire-94"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)

    def decode(self, entry, item):
        return tool.run_case(self.harness, tool.De("t", entry, item))

    def encode(self, entry, action, named=1, capacity=0x1000):
        return bytes.fromhex(tool.run_case(self.harness, tool.Ser("t", entry, action, named, capacity))[1])

    def profile(self, text):
        return self.decode(tool.DE_SET_R, {"profiles": [text], "epoch": 1})


class Rules(Base):
    def test_generated_cases_match(self):
        self.assertEqual(len(tool.check_all(self.harness, tool.vector_cases(60))), 60)

    def test_sign_field_order(self):
        data = self.encode(tool.SIGN_JC, tool.Act("sign"))
        self.assertLess(data.index(b'"usd"'), data.index(b'"nonce"'))
        self.assertTrue(data.startswith(b'{"type":"ValidatorSignWithdrawalAction","user":'))

    def test_finalize_puts_nonce_before_usd(self):
        data = self.encode(tool.VF_JC, tool.Act("vf"))
        self.assertLess(data.index(b'"nonce"'), data.index(b'"usd"'))

    def test_compact_form_has_no_keys(self):
        data = self.encode(tool.VF_MA, tool.Act("vf"), named=0)
        self.assertEqual(data[0], 0x96)
        self.assertNotIn(b"ethTxHash", data)

    def test_profile_is_one_string(self):
        rows = [(5, bytes(20), b"\xff" * 20)]
        self.assertIn(b'"profiles":["5-0x' + b"00" * 20 + b"-0x" + b"ff" * 20 + b'"]', self.encode(tool.SET_JC, tool.Act("set", profiles=rows)))

    def test_signature_word_has_no_leading_zeros(self):
        self.assertIn(b'"r":"0xabc"', self.encode(tool.SIGN_JC, tool.Act("sign", signature=tool.Sig(0xABC, 1, 27))))

    def test_profile_status_texts(self):
        good = "5-%s-%s" % (tool.USER, tool.DEST)
        self.assertEqual(self.profile(good)[0], "ok")
        self.assertEqual(self.profile("5-" + tool.USER), ("error", "Invalid input"))
        self.assertEqual(self.profile("x-%s-%s" % (tool.USER, tool.DEST)), ("error", "Invalid input number"))
        self.assertEqual(self.profile("5-x-" + tool.DEST), ("error", "Failed to parse user address"))
        self.assertEqual(self.profile("%d-%s-%s" % (1 << 64, tool.USER, tool.DEST)), ("error", "Invalid input number"))

    def test_plus_sign_and_padding_pass(self):
        self.assertEqual(self.profile("+05-%s-%s" % (tool.USER, tool.DEST)), self.profile("5-%s-%s" % (tool.USER, tool.DEST)))

    def test_set_sorts_by_power_then_validator_and_drops_duplicates(self):
        low, high = "0x" + "00" * 20, "0x" + "ff" * 20
        rows = ["9-%s-%s" % (low, low), "1-%s-%s" % (high, low), "1-%s-%s" % (low, high), "1-%s-%s" % (low, high)]
        fields = self.decode(tool.DE_SET_R, {"profiles": rows, "epoch": 1})[1]
        self.assertEqual([(row[0], row[1][:2]) for row in fields], [(1, "00"), (1, "ff"), (9, "00")])

    def test_set_ignores_a_key_the_action_refuses(self):
        self.assertEqual(self.decode(tool.DE_SET_R, tool.changed(tool.GOOD_SET, z=1))[0], "ok")
        self.assertEqual(self.decode(tool.DE_VS_R, {"validatorSet": tool.GOOD_SET, "z": 1}), ("error", "unknown field `z`, expected `validatorSet`"))

    def test_unit_text_splits_the_two_error_types(self):
        unit = tool.Con(tool.UNIT)
        self.assertEqual(self.decode(tool.DE_VF_J, unit), ("error", "invalid type: null, expected struct VoteEthFinalizedWithdrawalAction"))
        self.assertEqual(self.decode(tool.DE_VF_R, unit), ("error", "invalid type: unit value, expected struct VoteEthFinalizedWithdrawalAction"))

    def test_round_trip_writes_the_sorted_set(self):
        case = tool.Trip("t", tool.DE_SET_R, tool.SET_JC, {"profiles": ["7-%s-%s" % (tool.USER, tool.DEST), "2-%s-%s" % (tool.USER, tool.DEST)], "epoch": 3})
        self.assertEqual(tool.run_case(self.harness, case), tool.spec_run(case))


class Negative(Base):
    def test_wrong_hash_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_function_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.SIGN_JC + 1)

    def patched(self, va, flip, case):
        offset = self.image.offset(va)
        harness = tool.Harness(self.image, {va: self.image.blob[offset] ^ flip})
        try:
            return tool.run_case(harness, case) != tool.spec_run(case)
        except (tool.Halt, tool.EvidenceError, tool.Panicked):
            return True

    def test_changed_part_count_is_caught(self):
        self.assertTrue(self.patched(0x37A1007, 1, tool.De("t", tool.DE_SET_R, tool.GOOD_SET)))

    def test_changed_separator_is_caught(self):
        self.assertTrue(self.patched(0x37A0FCD, 1, tool.De("t", tool.DE_SET_R, tool.GOOD_SET)))

    def test_changed_sign_user_offset_is_caught(self):
        self.assertTrue(self.patched(0x1E9E5F1, 8, tool.Ser("t", tool.SIGN_JC, tool.Act("sign"))))

    def test_rule_list_rejects_a_wrong_order(self):
        case = tool.De("t", tool.DE_SET_R, tool.GOOD_SET)
        rule = tool.spec_profiles
        tool.spec_profiles = lambda value, flavor: tuple(reversed(rule(value, flavor)))
        try:
            self.assertNotEqual(tool.run_case(self.harness, case), tool.spec_run(case))
        finally:
            tool.spec_profiles = rule

    def test_rule_list_rejects_a_wrong_field_order(self):
        case = tool.Ser("t", tool.VF_MP, tool.Act("vf"))
        rule = tool.shape
        tool.shape = lambda action: list(reversed(rule(action)))
        try:
            self.assertNotEqual(tool.run_case(self.harness, case), tool.spec_run(case))
        finally:
            tool.shape = rule

    def test_moved_key_row_fails(self):
        rows = tool.KEY_ROWS
        tool.KEY_ROWS = ((0x37A1002, "wrong operation", "mov"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.key_rows(self.image)
        finally:
            tool.KEY_ROWS = rows

    def test_moved_field_text_fails(self):
        rows = tool.FIELD_TEXT
        tool.FIELD_TEXT = ((0x3BF847, "nonce"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.text_rows(self.image)
        finally:
            tool.FIELD_TEXT = rows

    def test_moved_status_text_fails(self):
        rows = tool.STATUS_TEXT
        tool.STATUS_TEXT = ((0x13F, 0x59E416, "Invalid input number"),)
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.status_rows(self.image)
        finally:
            tool.STATUS_TEXT = rows

    def test_a_copy_with_the_wrong_primary_fails(self):
        rows = tool.SERIALIZER_COPIES
        tool.SERIALIZER_COPIES = ((0x3349870, tool.VF_MP),)
        decoders = tool.DECODER_COPIES
        tool.DECODER_COPIES = ()
        cases = [tool.Ser("t", tool.VF_MP, tool.Act("vf")) for _ in range(11)]
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.copy_rows(self.image, self.harness, cases)
        finally:
            tool.SERIALIZER_COPIES = rows
            tool.DECODER_COPIES = decoders
            tool.FORMS.pop(0x3349870, None)


class Output(Base):
    def test_files_match_the_tool_without_mutation_rows(self):
        files = tool.render(tool.analyse(self.image, mutate=False, vectors=200))
        for name, text in files.items():
            if name == "evidence.json":
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest_lists_every_file(self):
        listed = {line.split("  ", 1)[1] for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()}
        present = {path.name for path in FOLDER.iterdir() if path.name != "MANIFEST.sha256"}
        self.assertEqual(listed, present)


if __name__ == "__main__":
    unittest.main()
