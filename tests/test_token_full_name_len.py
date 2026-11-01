"""RE-036: token full-name length packet: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-036-token-full-name-len-94"
sys.path.insert(0, str(ROOT / "tools"))
import token_full_name_len as tool  # noqa: E402

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


@unittest.skipIf(DATA is None, "node #94 binary not present")
class TokenFullNameLenStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        digest = hashlib.sha256(text.encode()).hexdigest()
        pin = (PACKET / "token_full_name_len.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(digest, hashlib.sha256(pin.encode()).hexdigest())
        self.assertEqual(r["carve"]["len"], 206)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["direct_calls"], 1)
        self.assertEqual(r["direct_call_sites"], [hex(v) for v in tool.DIRECT_E8_SITES])
        self.assertIsNone(r["got_slot"])
        self.assertEqual(r["got_relative_to_entry"], [])
        self.assertEqual(r["ff15_inbound_via_got"], 0)
        self.assertEqual(r["abi"]["err_tag"], hex(tool.ERR_TAG))
        self.assertEqual(r["abi"]["ok_tag"], hex(tool.OK_TAG))
        self.assertIn("movw STORE", r["abi"]["ok_note"])
        self.assertTrue(r["extent"]["int3_padding_at_fde_end"])
        self.assertTrue(r["extent"]["next_fn_is_push_rbp"])
        for s in r["error_strings"]:
            self.assertTrue(s["match"], s["name"])
            self.assertEqual(s["occurrence_count"], 1)
            self.assertTrue(s["lea_in_carve"]["targets_string"], s["name"])

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "token_full_name_len.json").read_text())
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertIsNone(disk["got_slot"])
        self.assertEqual(disk["claim"], "token_full_name_len_and_already_set_rules_only")
        self.assertEqual(disk["component"], "RE-036")
        self.assertEqual(disk["adjacent_prior_work"]["component"], "RE-030")
        self.assertEqual(disk["adjacent_prior_work"]["entry"], "0x375f3d0")
        self.assertEqual(disk["adjacent_prior_work"]["inventory_only"]["pr"], 650)
        texts = {s["name"]: s["text"] for s in disk["error_strings"]}
        self.assertEqual(
            texts["token_full_name_len"],
            "token full name must be between 1 and 50 characters long",
        )
        self.assertEqual(texts["full_name_already_set"], "full name already set")
        claimed = {r["name"] for r in disk["rules"] if r["claimed"]}
        self.assertEqual(claimed, {"full_name_len_1_to_50", "full_name_already_set"})

    def test_error_string_bytes_verbatim(self):
        segs = tool.segments(bytes(DATA))
        for name, va, expected, _lea, strlen_imm in tool.ERROR_STRINGS:
            raw = tool.read_va(bytes(DATA), segs, va, len(expected))
            self.assertEqual(raw, expected, name)
            self.assertEqual(len(raw), len(expected), name)
            self.assertEqual(len(expected), strlen_imm, name)
            # No trailing junk beyond the pinned length for the primary length string.
            if name == "token_full_name_len":
                self.assertTrue(raw.endswith(b"long"), name)
                self.assertEqual(raw, b"token full name must be between 1 and 50 characters long")

    def test_negative_controls_per_rule(self):
        r = tool.analyse(bytes(DATA))
        # Rule A: length 1..=50
        self.assertTrue(r["negatives"]["len_add_imm_is_neg_0x33"])
        self.assertTrue(r["negatives"]["len_cmp_imm_is_neg_0x33"])
        self.assertTrue(r["negatives"]["len_ja_present"])
        self.assertTrue(r["negatives"]["range_rejects_0_and_ge_51"])
        self.assertTrue(r["negatives"]["range_accepts_1_through_50"])
        self.assertTrue(r["rules"][0]["match"])
        self.assertEqual(r["rules"][0]["immediate"], 0x33)
        self.assertIn("1..=50", r["rules"][0]["description"])
        # Rule B: already set
        self.assertTrue(r["negatives"]["option_cmp_match"])
        self.assertTrue(r["negatives"]["option_jno_match"])
        self.assertTrue(r["rules"][1]["match"])
        self.assertIn("already Some", r["rules"][1]["description"])
        self.assertTrue(r["negatives"]["err_tag_is_0xdf"])
        self.assertTrue(r["negatives"]["ok_tag_is_movw_0x186"])
        self.assertTrue(r["negatives"]["string_len_exact"])
        self.assertTrue(r["negatives"]["string_already_set_exact"])

    def test_range_gate_truth_table(self):
        self.assertFalse(tool.range_gate_accepts(0))
        for n in range(1, 51):
            self.assertTrue(tool.range_gate_accepts(n), n)
        for n in (51, 52, 100, 255, 1000):
            self.assertFalse(tool.range_gate_accepts(n), n)

    def test_mutation_tamper_len_imm(self):
        # Negative for Rule A: flip the -0x33 immediate on the cmp.
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.CMP_LEN_VA < base + filesz:
                file_off = off + (tool.CMP_LEN_VA - base)
                mutated[file_off + 3] ^= 0x01
                break
        else:
            self.fail("len cmp not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "len" in e or "rule" in e or "key" in e or "negative" in e or "range" in e
                for e in errs
            ),
            errs,
        )

    def test_mutation_tamper_option_jno(self):
        # Negative for Rule B: flip the jno opcode/offset.
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.OPT_JNO_VA < base + filesz:
                file_off = off + (tool.OPT_JNO_VA - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("option jno not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "already" in e
                or "option" in e
                or "rule" in e
                or "key" in e
                or "negative" in e
                for e in errs
            ),
            errs,
        )

    def test_mutation_tamper_carve(self):
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.FN < base + filesz:
                file_off = off + (tool.FN - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("fn not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any("carve" in e or "key" in e for e in errs),
            errs,
        )


if __name__ == "__main__":
    unittest.main()
