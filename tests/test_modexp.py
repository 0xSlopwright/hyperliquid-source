"""RE-028: modexp packet: exact pins, gas checks, negative and mutation controls."""
import hashlib
import importlib.util
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-028-modexp-94"
sys.path.insert(0, str(ROOT / "tools"))
import modexp as tool  # noqa: E402

OUTPUT_SHA256 = "20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360"
NO_EMU_OUTPUT_SHA256 = "e7fb0730df145fa34bc18534712ec4b4b5fa1bcf8769540f4b2b6d8cfdf4eced"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA)) if DATA is not None else None
RELA = tool.rela_dyn(bytes(DATA)) if DATA is not None else None


def off(va):
    return tool.va_to_off(SEGS, va)


class Patched:
    def __init__(self, file_off, new):
        self.o, self.new = file_off, bytes(new)

    def __enter__(self):
        self.old = bytes(DATA[self.o : self.o + len(self.new)])
        DATA[self.o : self.o + len(self.new)] = self.new
        return DATA

    def __exit__(self, *exc):
        DATA[self.o : self.o + len(self.old)] = self.old


def flip(va, at=0):
    o = off(va) + at
    return Patched(o, [DATA[o] ^ 0x01])


@unittest.skipIf(DATA is None, "node #94 binary not present")
class ModexpStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(
            hashlib.sha256(tool.render(r).encode()).hexdigest(), NO_EMU_OUTPUT_SHA256
        )
        self.assertEqual(r["carve"]["len"], 356)
        self.assertEqual(r["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(r["slot_ref_counts"], {"call": 2, "jmp": 0, "mov": 0})
        self.assertEqual(
            [x["va"] for x in r["slot_refs"]],
            [hex(tool.BERLIN_CALL), hex(tool.BYZ_CALL)],
        )
        self.assertEqual(r["direct_calls"], 0)
        self.assertEqual(r["extent"]["primary_ret"], hex(tool.FN_RET))
        self.assertTrue(r["extent"]["padding_all_int3"])
        self.assertFalse(r["simd_any"])
        for w in r["wrappers"]:
            self.assertTrue(w["match"], w["fork"])
        for name, imm in r["gas_immediates"].items():
            self.assertTrue(imm["match"], name)

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "modexp.json").read_text())
        self.assertTrue(disk["emu"]["ran"])
        self.assertEqual(disk["carve"]["sha256"], tool.CARVED_SHA256)
        self.assertEqual(disk["got_slot"], hex(tool.GOT_SLOT))
        self.assertEqual(disk["got_rela"]["r_addend"], hex(tool.FN))
        for name in tool.VECTORS:
            v = disk["vectors"][name]
            self.assertTrue(v["berlin"]["output_match"], name)
            self.assertTrue(v["berlin"]["gas_match"], name)
            self.assertTrue(v["byzantium"]["output_match"], name)
            self.assertTrue(v["byzantium"]["gas_match"], name)
        for label, m in disk["mutations"].items():
            self.assertTrue(m["broke_expectation"], label)

    def test_gas_formulas_independent(self):
        # Independent gas vs EIP-2565 / EIP-198 on at least 3 inputs; exact, never >=.
        cases = ["eip198_ex1", "large", "even_modulus"]
        for name in cases:
            b, e, m = tool.VECTORS[name]
            self.assertEqual(tool.gas_eip2565(b, e, m), {
                "eip198_ex1": 1360, "large": 6677, "even_modulus": 200,
            }[name])
            self.assertEqual(tool.gas_eip198(b, e, m), {
                "eip198_ex1": 13056, "large": 64102, "even_modulus": 0,
            }[name])

    def test_negative_wrong_base_changes_output(self):
        good = tool.ref_modexp(*tool.VECTORS["small_3_5_7"])
        bad = tool.ref_modexp(*tool.VECTORS["neg_wrong_base"])
        self.assertEqual(good.hex(), "05")
        self.assertEqual(bad.hex(), "03")
        self.assertNotEqual(good, bad)

    def test_zero_modulus_empty(self):
        self.assertEqual(tool.ref_modexp(*tool.VECTORS["zero_modulus"]), b"")

    def test_tamper_carve_detected(self):
        with flip(tool.FN, 4):
            errs = tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
        self.assertTrue(any("carved" in e or "key_insn" in e for e in errs))

    def test_tamper_got_addend_detected(self):
        # Flip low byte of RELATIVE addend for GOT slot.
        e_shoff = struct.unpack_from("<Q", DATA, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", DATA, 58)
        so, ss = struct.unpack_from("<QQ", DATA, e_shoff + e_shstrndx * e_shentsize + 24)
        names = bytes(DATA[so : so + ss])
        base = None
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            n = struct.unpack_from("<I", DATA, o)[0]
            if names[n : names.find(b"\x00", n)] == b".rela.dyn":
                base = struct.unpack_from("<Q", DATA, o + 24)[0]
        idx = [k for k, r in enumerate(RELA) if r[0] == tool.GOT_SLOT][0]
        addend_off = base + idx * 24 + 16
        with Patched(addend_off, bytes([DATA[addend_off] ^ 0x01])):
            errs = tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
        self.assertTrue(any("GOT" in e for e in errs))

    def test_tamper_address05_detected(self):
        with flip(tool.BERLIN_TABLE + 0x10 + 19):
            errs = tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
        self.assertTrue(any("wrapper" in e for e in errs))

    def test_tamper_gas_imm_detected(self):
        with flip(tool.BERLIN_DIV3_IMM_VA, 4):  # the 0x3 immediate byte
            errs = tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
        self.assertTrue(any("gas immediate" in e for e in errs))

    def test_seed_determinism(self):
        a = tool.render(tool.analyse(bytes(DATA), run_emu=False))
        b = tool.render(tool.analyse(bytes(DATA), run_emu=False))
        self.assertEqual(a, b)
        self.assertEqual(hashlib.sha256(a.encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)


@unittest.skipIf(DATA is None, "node #94 binary not present")
@unittest.skipUnless(HAS_UNICORN, "unicorn not installed")
class ModexpEmuTests(unittest.TestCase):
    def test_emu_output_pin(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(
            hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256
        )

    def test_berlin_byz_vectors_exact(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        for name, v in r["vectors"].items():
            self.assertTrue(v["berlin"]["returned"], name)
            self.assertTrue(v["berlin"]["output_match"], name)
            self.assertTrue(v["berlin"]["gas_match"], name)
            self.assertEqual(v["berlin"]["gas_used"], v["expected_gas_eip2565"], name)
            self.assertTrue(v["byzantium"]["returned"], name)
            self.assertTrue(v["byzantium"]["output_match"], name)
            self.assertTrue(v["byzantium"]["gas_match"], name)
            self.assertEqual(v["byzantium"]["gas_used"], v["expected_gas_eip198"], name)

    def test_mutations_break_gas(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        for label, m in r["mutations"].items():
            self.assertTrue(m["broke_expectation"], label)
            self.assertTrue(m["returned"], label)

    def test_wrong_base_emulated_differs(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        a = r["vectors"]["small_3_5_7"]["berlin"]["output_hex"]
        b = r["vectors"]["neg_wrong_base"]["berlin"]["output_hex"]
        self.assertEqual(a, "05")
        self.assertEqual(b, "03")
        self.assertNotEqual(a, b)

    def test_zero_modulus_emulated_empty(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(r["vectors"]["zero_modulus"]["berlin"]["output_hex"], "")
        self.assertEqual(r["vectors"]["zero_modulus"]["berlin"]["gas_used"], 200)


if __name__ == "__main__":
    unittest.main()
