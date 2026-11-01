"""RE-033: sub-deployer set guards packet: exact pins, negatives, mutation/tamper."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-033-sub-deployer-guards-94"
sys.path.insert(0, str(ROOT / "tools"))
import sub_deployer_guards as tool  # noqa: E402

OUTPUT_SHA256 = None  # filled after first deterministic run
DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None


@unittest.skipIf(DATA is None, "node #94 binary not present")
class SubDeployerGuardsStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA))
        self.assertEqual(tool.expectation_errors(r), [])
        text = tool.render(r)
        digest = hashlib.sha256(text.encode()).hexdigest()
        pin = (PACKET / "sub_deployer_guards.json").read_text()
        self.assertEqual(text, pin)
        self.assertEqual(digest, hashlib.sha256(pin.encode()).hexdigest())
        self.assertEqual(r["carve"]["len"], 1879)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["slot_ref_counts"], {"call": 3, "jmp": 0, "mov": 0})
        self.assertEqual(
            [x["va"] for x in r["slot_refs"]],
            [hex(v) for v in tool.FF15_SITES],
        )
        self.assertEqual(r["direct_calls"], 0)
        self.assertEqual(r["abi"]["err_tag"], hex(tool.ERR_TAG))
        self.assertEqual(r["abi"]["ok_tag"], hex(tool.OK_TAG))
        self.assertEqual(r["abi"]["early_err_tag"], hex(tool.EARLY_ERR_TAG))
        self.assertTrue(r["early_reject_rule"]["claimed"])
        self.assertTrue(r["early_reject_rule"]["match"])
        self.assertTrue(r["extent"]["int3_padding_at_fde_end"])
        self.assertTrue(r["extent"]["next_fn_is_push_r15"])
        self.assertTrue(r["sibling"]["carve_sha256_match"])
        self.assertTrue(r["sibling"]["call_target_match"])
        for s in r["error_strings"]:
            self.assertTrue(s["match"], s["name"])

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "sub_deployer_guards.json").read_text())
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_slot"], hex(tool.GOT_SLOT))
        self.assertEqual(disk["got_rela"]["r_addend"], hex(tool.FN))
        self.assertEqual(disk["claim"], "sub_deployer_set_guard_rules_only")
        self.assertEqual(disk["component"], "RE-033")
        self.assertEqual(disk["fallback_from"]["dropped"], "RE-032")
        texts = {s["name"]: s["text"] for s in disk["error_strings"]}
        self.assertEqual(texts["duplicate"], "duplicate sub-deployer")
        self.assertEqual(texts["cannot_set_deployer"], "cannot set deployer as sub-deployer")
        self.assertEqual(texts["too_many"], "too many sub-deployers")

    def test_error_string_bytes_verbatim(self):
        # One negative-per-rule check: each pinned string must match full length.
        segs = tool.segments(bytes(DATA))
        for name, va, expected in tool.ERROR_STRINGS:
            raw = tool.read_va(bytes(DATA), segs, va, len(expected))
            self.assertEqual(raw, expected, name)
            self.assertEqual(len(raw), len(expected), name)

    def test_negative_controls_per_rule(self):
        r = tool.analyse(bytes(DATA))
        # Rule 1: duplicate
        self.assertTrue(r["negatives"]["duplicate_string_exact"])
        # Rule 2: cannot set deployer as sub-deployer
        self.assertTrue(r["negatives"]["cannot_set_string_exact"])
        # Rule 3: early-reject network==3 -> 0xe3
        self.assertTrue(r["negatives"]["early_reject_imm_is_3"])
        self.assertTrue(r["negatives"]["early_err_tag_is_0xe3"])
        self.assertTrue(r["negatives"]["err_tag_is_0xe0"])
        self.assertTrue(r["negatives"]["ok_tag_is_0x186"])
        # Explicit negatives: wrong strings must not be claimed as primary.
        texts = {s["text"] for s in r["error_strings"]}
        self.assertNotIn("deployer trading fee share cannot be more than 100%", texts)
        self.assertNotIn("cannot reset legacy token fee share", texts)

    def test_mutation_tamper_duplicate_string(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRINGS[0]
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= va < base + filesz:
                file_off = off + (va - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("string not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(any("string duplicate" in e for e in errs), errs)

    def test_mutation_tamper_cannot_set_string(self):
        segs = tool.segments(bytes(DATA))
        name, va, expected = tool.ERROR_STRINGS[1]
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= va < base + filesz:
                file_off = off + (va - base)
                mutated[file_off] ^= 0x01
                break
        else:
            self.fail("string not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(any("string cannot_set" in e for e in errs), errs)

    def test_mutation_tamper_early_reject_imm(self):
        segs = tool.segments(bytes(DATA))
        mutated = bytearray(DATA)
        for base, off, filesz in segs:
            if base <= tool.EARLY_CMP_VA < base + filesz:
                file_off = off + (tool.EARLY_CMP_VA - base)
                # flip the immediate byte of cmpb $0x3 (last byte)
                mutated[file_off + 6] ^= 0x01
                break
        else:
            self.fail("early cmp not mapped")
        r = tool.analyse(bytes(mutated), check_sha=False)
        errs = tool.expectation_errors(r)
        self.assertTrue(
            any("early" in e or "key_insns" in e for e in errs), errs
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
            any(e in ("carve sha256", "key_insns") or "carve" in e or "key" in e for e in errs),
            errs,
        )


if __name__ == "__main__":
    unittest.main()
