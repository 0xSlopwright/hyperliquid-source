"""RE-037: USDC-as-base guard packet: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-037-usdc-as-base-94"
sys.path.insert(0, str(ROOT / "tools"))
import usdc_as_base_guard as tool  # noqa: E402

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


@unittest.skipIf(DATA is None, "node #94 binary not present")
class UsdcAsBaseGuardStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        digest = hashlib.sha256(text.encode()).hexdigest()
        pin = (PACKET / "usdc_as_base_guard.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(digest, hashlib.sha256(pin.encode()).hexdigest())
        self.assertEqual(r["carve"]["len"], 308)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["direct_calls"], 1)
        self.assertEqual(r["direct_call_sites"], [hex(v) for v in tool.DIRECT_E8_SITES])
        self.assertIsNone(r["got_slot"])
        self.assertEqual(r["got_relative_to_entry"], [])
        self.assertEqual(r["ff15_inbound_via_got"], 0)
        self.assertEqual(r["abi"]["err_tag"], hex(tool.ERR_TAG))
        self.assertEqual(r["abi"]["ok_tag"], hex(tool.OK_TAG))
        self.assertEqual(r["abi"]["bounds_err_tag"], hex(tool.BOUNDS_ERR_TAG))
        self.assertIn("movw STORE", r["abi"]["ok_note"])
        self.assertTrue(r["extent"]["int3_padding_at_fde_end"])
        self.assertEqual(r["extent"]["int3_pad_len"], 12)
        self.assertTrue(r["extent"]["next_fn_is_push_r15"])
        for s in r["error_strings"]:
            self.assertTrue(s["match"], s["name"])
            self.assertEqual(s["occurrence_count"], 3)
            self.assertTrue(s["lea_in_carve"]["targets_string"], s["name"])
            self.assertEqual(s["len"], 29)

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "usdc_as_base_guard.json").read_text())
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertIsNone(disk["got_slot"])
        self.assertEqual(disk["claim"], "refuse_usdc_as_base_rule_only")
        self.assertEqual(disk["component"], "RE-037")
        inv = disk["adjacent_prior_work"]["inventory_only"]
        prs = {item["pr"] for item in inv}
        self.assertEqual(prs, {650, 389})
        texts = {s["name"]: s["text"] for s in disk["error_strings"]}
        self.assertEqual(texts["usdc_as_base"], "cannot use USDC as base token")
        claimed = {r["name"] for r in disk["rules"] if r["claimed"]}
        self.assertEqual(claimed, {"refuse_usdc_as_base"})
        not_claimed = disk["error_strings"][0]["not_claimed_leas_of_duplicates"]
        self.assertEqual(len(not_claimed), 2)

    def test_error_string_bytes_verbatim(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRING
        raw = tool.read_va(bytes(DATA), segs, va, len(expected))
        self.assertEqual(raw, expected, name)
        self.assertEqual(len(raw), len(expected), name)
        self.assertEqual(len(expected), tool.STR_LEN_IMM, name)
        self.assertEqual(raw, b"cannot use USDC as base token")
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "e4f0351fd1370a8f9035f0e19b4ed40255d600f52248c0852da99c2ee8a99d5b")

    def test_negative_controls_per_rule(self):
        r = tool.analyse(bytes(DATA))
        self.assertTrue(r["negatives"]["test_rdi_match"])
        self.assertTrue(r["negatives"]["je_bytes_match"])
        self.assertTrue(r["negatives"]["je_targets_err_df_block"])
        self.assertTrue(r["negatives"]["err_df_movw_store"])
        self.assertTrue(r["negatives"]["string_exact"])
        self.assertTrue(r["negatives"]["string_len_imm_0x1d"])
        self.assertTrue(r["negatives"]["lea_targets_string"])
        self.assertTrue(r["rules"][0]["match"])
        self.assertEqual(r["rules"][0]["test_bytes"], "4885ff")
        self.assertEqual(r["rules"][0]["je_bytes"], "0f84dc000000")
        self.assertEqual(r["rules"][0]["je_target"], hex(tool.JE_TARGET))
        self.assertIn("USDC", r["rules"][0]["description"])
        self.assertIn("rdi==0", r["rules"][0]["proof"]["rdi_eq_0_takes_refuse"])
        self.assertIn("rdi!=0", r["rules"][0]["proof"]["rdi_neq_0_continues"])

    def test_mutation_tamper_je_branch(self):
        # Negative for the claimed rule: flip the je opcode/rel.
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.JE_VA < base + filesz:
                file_off = off + (tool.JE_VA - base)
                # Flip the relative displacement low byte (immediate).
                mutated[file_off + 2] ^= 0x01
                break
        else:
            self.fail("je not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any(
                "rule" in e or "key" in e or "negative" in e or "je" in e
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
