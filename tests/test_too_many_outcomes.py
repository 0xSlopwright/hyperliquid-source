"""RE-038: too-many-outcomes (0x31 arm) packet: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-038-too-many-outcomes-94"
sys.path.insert(0, str(ROOT / "tools"))
import too_many_outcomes as tool  # noqa: E402

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


@unittest.skipIf(DATA is None, "node #94 binary not present")
class TooManyOutcomesStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        digest = hashlib.sha256(text.encode()).hexdigest()
        pin = (PACKET / "too_many_outcomes.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(digest, hashlib.sha256(pin.encode()).hexdigest())
        self.assertEqual(r["carve"]["len"], 1173)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["direct_calls"], 0)
        self.assertEqual(r["direct_call_sites"], [])
        self.assertEqual(r["got_slot"], hex(tool.GOT_SLOT))
        self.assertTrue(r["got_addend_match"])
        self.assertEqual(r["ff15_inbound_via_got"], 3)
        self.assertEqual(r["ff15_sites"], [hex(v) for v in tool.FF15_SITES])
        self.assertEqual(r["abi"]["err_tag"], hex(tool.ERR_TAG))
        self.assertEqual(r["abi"]["err_tag_kind"], "movw_store")
        self.assertIn("movw STORE", r["abi"]["err_note"])
        self.assertTrue(r["extent"]["int3_padding_at_fde_end"])
        self.assertEqual(r["extent"]["int3_pad_len"], 11)
        self.assertTrue(r["extent"]["next_fn_is_push_rbp"])
        for s in r["error_strings"]:
            self.assertTrue(s["match"], s["name"])
            self.assertEqual(s["occurrence_count"], 1)
            self.assertTrue(s["lea_in_carve"]["targets_string"], s["name"])
            self.assertEqual(s["len"], 30)

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "too_many_outcomes.json").read_text())
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_slot"], hex(tool.GOT_SLOT))
        self.assertEqual(disk["claim"], "too_many_outcomes_0x31_arm_only")
        self.assertEqual(disk["component"], "RE-038")
        self.assertEqual(disk["adjacent_prior_work"]["sibling"]["pr"], 997)
        self.assertEqual(disk["adjacent_prior_work"]["inventory_only"], [])
        texts = {s["name"]: s["text"] for s in disk["error_strings"]}
        self.assertEqual(texts["too_many_outcomes"], "too many outcomes for question")
        claimed = {r["name"] for r in disk["rules"] if r["claimed"]}
        self.assertEqual(claimed, {"too_many_outcomes_count_le_0x31"})
        self.assertEqual(len(disk["neighbour_arms_not_claimed"]), 3)
        for arm in disk["neighbour_arms_not_claimed"]:
            self.assertFalse(arm["claimed"])

    def test_error_string_bytes_verbatim(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRING
        raw = tool.read_va(bytes(DATA), segs, va, len(expected))
        self.assertEqual(raw, expected, name)
        self.assertEqual(len(raw), len(expected), name)
        self.assertEqual(len(expected), tool.STR_LEN_IMM, name)
        self.assertEqual(raw, b"too many outcomes for question")
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "cffe7f247336dec13c90c834218d23ec2ab8ba54a527cc0eec9974713ba64899",
        )

    def test_negative_controls_per_rule(self):
        r = tool.analyse(bytes(DATA))
        self.assertTrue(r["negatives"]["cmp_bytes_match"])
        self.assertTrue(r["negatives"]["cmp_imm_is_0x31"])
        self.assertTrue(r["negatives"]["jbe_bytes_match"])
        self.assertTrue(r["negatives"]["jbe_targets_continue"])
        self.assertTrue(r["negatives"]["err_is_fallthrough_of_jbe"])
        self.assertTrue(r["negatives"]["err_17b_movw_store"])
        self.assertTrue(r["negatives"]["string_exact"])
        self.assertTrue(r["negatives"]["string_len_imm_0x1e"])
        self.assertTrue(r["negatives"]["lea_targets_string"])
        self.assertTrue(r["negatives"]["occurrence_count_is_1"])
        self.assertTrue(r["negatives"]["range_accepts_0_through_49"])
        self.assertTrue(r["negatives"]["range_rejects_ge_50"])
        self.assertTrue(r["rules"][0]["match"])
        self.assertEqual(r["rules"][0]["cmp_bytes"], "4a837c09e031")
        self.assertEqual(r["rules"][0]["jbe_bytes"], "761d")
        self.assertEqual(r["rules"][0]["jbe_target"], hex(tool.JBE_TARGET))
        self.assertEqual(r["rules"][0]["cmp_immediate"], 0x31)
        self.assertIn("0x31", r["rules"][0]["description"])
        self.assertIn("<= 0x31", r["rules"][0]["proof"]["count_le_0x31_continues"])
        self.assertIn("> 0x31", r["rules"][0]["proof"]["count_gt_0x31_takes_err"])

    def test_mutation_tamper_cmp_imm(self):
        # Negative for the claimed 0x31 arm: flip the cmp immediate.
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.CMP_VA < base + filesz:
                file_off = off + (tool.CMP_VA - base)
                # Last byte of cmpq is the imm8 0x31; flip it.
                mutated[file_off + 5] ^= 0x01
                break
        else:
            self.fail("cmp not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "rule" in e or "key" in e or "negative" in e or "cmp" in e
                for e in errs
            ),
            errs,
        )

    def test_mutation_tamper_jbe_branch(self):
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.JBE_VA < base + filesz:
                file_off = off + (tool.JBE_VA - base)
                # Flip the relative displacement.
                mutated[file_off + 1] ^= 0x01
                break
        else:
            self.fail("jbe not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "rule" in e or "key" in e or "negative" in e or "jbe" in e
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
