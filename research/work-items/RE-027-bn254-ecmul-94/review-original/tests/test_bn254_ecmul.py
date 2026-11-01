"""RE-027: bn254 ecMul packet: exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-027-bn254-ecmul-94"
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecmul as tool  # noqa: E402

OUTPUT_SHA256 = "ae212bc9791ccdd53cc48dff1446aec74f07693be008b62746d83a601af3b980"
NO_EMU_OUTPUT_SHA256 = "79149c497481d1f9daff231044ca8d2ca135af3907086a0f63393209208322f4"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None
TOOL = str(ROOT / "tools" / "bn254_ecmul.py")

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


def rela_entry_off(slot):
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", DATA, 58)
    e_shoff = struct.unpack_from("<Q", DATA, 40)[0]
    so, ss = struct.unpack_from("<QQ", DATA, e_shoff + shstrndx * shentsize + 24)
    names = bytes(DATA[so : so + ss])
    for i in range(shnum):
        o = e_shoff + i * shentsize
        n = struct.unpack_from("<I", DATA, o)[0]
        if names[n : names.find(b"\x00", n)] == b".rela.dyn":
            base = struct.unpack_from("<Q", DATA, o + 24)[0]
    idx = [k for k, r in enumerate(RELA) if r[0] == slot][0]
    return base + idx * 24


def static_errors():
    try:
        return tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
    except Exception as exc:  # parse failure counts as detection
        return [repr(exc)]


def emu(inp, gas=6000, limit=6000, stub=True):
    return tool.emulate(bytes(DATA), SEGS, tool.rela_dyn(bytes(DATA)), inp, gas, limit, stub=stub)


C1 = tool.VECTORS["geth_chfast1"]


@unittest.skipIf(DATA is None, "node #94 binary not present")
class Bn254EcMulStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        self.assertEqual(r["carved_len"], 1762)
        self.assertEqual(r["got_slot_refs"]["vas"], ["call@0x4e98a87", "call@0x4e98b17"])
        self.assertEqual(r["direct_e8_e9_to_fn"], 0)
        self.assertEqual([w["gas_imm"] for w in r["wrappers"]], [40000, 6000])
        self.assertEqual(r["extent"]["c3_offsets_in_carve"], ["0x4e973c1"])
        self.assertTrue(r["extent"]["padding_all_int3"])

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "bn254-ecmul.json").read_text())
        self.assertTrue(disk["emu_ran"])
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)
        for name, (_i, _g, _l, kind, expect) in tool.VECTORS.items():
            v = disk["vectors"][name]
            self.assertEqual(v["expected"], expect)
            self.assertTrue(v["emulated_match"], name)
            got = v["emu"]["output_hex"] if kind == "ok" else v["emu"]["err_payload_hex"]
            self.assertEqual(got, expect, name)

    def test_field_constants_independent(self):
        self.assertEqual(tool.P, 21888242871839275222246405745257275088696311157297823662689037894645226208583)
        self.assertEqual(tool.R_ORDER, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
        self.assertEqual(tool.INV128 & (2**64 - 1), 0x87D20782E4866389)
        self.assertEqual(tool.INV128_R & (2**64 - 1), 0xC2E1F593EFFFFFFF)
        self.assertEqual(tool.ref_mul(tool.G, tool.R_ORDER), (0, 0))
        x, y = tool.ref_mul(tool.G, 2)
        self.assertEqual((y * y - x * x * x - 3) % tool.P, 0)

    def test_seed_determinism_no_emu(self):
        digests = []
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = subprocess.check_output([sys.executable, "-B", TOOL, "--no-emu"], cwd=str(ROOT), env=env)
            digests.append(hashlib.sha256(out).hexdigest())
        self.assertEqual(digests, [NO_EMU_OUTPUT_SHA256] * 3)

    def test_optim_determinism_no_emu(self):
        env = dict(os.environ, PYTHONHASHSEED="0")
        out = subprocess.check_output([sys.executable, "-O", "-B", TOOL, "--no-emu"], cwd=str(ROOT), env=env)
        self.assertEqual(hashlib.sha256(out).hexdigest(), NO_EMU_OUTPUT_SHA256)

    def test_independent_verify_imports(self):
        src = (PACKET / "independent_verify.py").read_text()
        imports = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
        self.assertEqual(imports, ["import hashlib", "from pathlib import Path", "import struct"])
        self.assertNotIn("bn254_ecmul", src)

    def test_tamper_prologue_rejected(self):
        with flip(tool.FN):
            self.assertTrue(static_errors())

    def test_tamper_p_limb_rejected(self):
        with flip(0x4E9705D, at=2):
            self.assertIn("p_limbs_in_run_mul mismatch", static_errors())

    def test_tamper_fq_montgomery_inv_rejected(self):
        with flip(0x4E9708F, at=2):
            self.assertIn("inv_limbs_in_run_mul mismatch", static_errors())

    def test_tamper_fr_montgomery_inv_rejected(self):
        with flip(0x4E96F63, at=2):
            self.assertIn("inv_r_limbs_in_run_mul mismatch", static_errors())

    def test_tamper_r2_mod_r_rejected(self):
        with flip(0x4E96EE1, at=2):
            self.assertIn("r2_mod_r_limbs_in_run_mul mismatch", static_errors())

    def test_tamper_wrapper_gas_rejected(self):
        with flip(0x4E98A80):
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_wrapper_call_rejected(self):
        with flip(0x4E98B17, at=2):
            self.assertIn("GOT slot ref counts mismatch", static_errors())

    def test_tamper_malloc_call_rejected(self):
        with flip(tool.MALLOC_CALL, at=2):
            self.assertIn("branch target mismatch", static_errors())

    def test_tamper_scalar_mul_call_rejected(self):
        with flip(0x4E96FB8, at=1):
            self.assertIn("branch target mismatch", static_errors())

    def test_tamper_got_rela_rejected(self):
        o = rela_entry_off(tool.GOT_SLOT) + 16
        with Patched(o, [DATA[o] ^ 0x10]):
            self.assertIn("GOT RELA mismatch", static_errors())

    def test_tamper_table_rela_rejected(self):
        o = rela_entry_off(0x574F050) + 16
        with Patched(o, [DATA[o] ^ 0x10]):
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_table_address_rejected(self):
        with flip(0x574F050 + 0x10 + 19):  # Address 0x07 -> 0x06
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_padding_rejected(self):
        with flip(tool.PAD[0] + 3):
            self.assertTrue(static_errors())

    def test_negative_injected_cpuid_rejected(self):
        with Patched(off(0x4E96D80), b"\x0f\xa2"):
            self.assertIn("SIMD/feature pattern in run_mul", static_errors())

    def test_negative_unpinned_carve_byte_only_carve_differs(self):
        with flip(0x4E96D80):
            self.assertEqual(static_errors(), ["carved_sha256 mismatch"])

    def test_negative_wrong_binary_sha_raises(self):
        with flip(0x4E96D80):
            with self.assertRaises(ValueError):
                tool.analyse(bytes(DATA), check_sha=True, run_emu=False)


@unittest.skipIf(DATA is None or not HAS_UNICORN, "binary or unicorn missing")
class Bn254EcMulEmuTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "bn254-ecmul.json").read_text(), tool.render(r))

    def test_g_times_3_matches_reference(self):
        r = emu(tool.enc(1, 2, 3))
        self.assertEqual(r["output_hex"], tool.enc(*tool.ref_mul(tool.G, 3)).hex())

    def test_tamper_input_takes_error_path(self):
        inp = bytearray(C1[0])
        inp[63] ^= 1  # y no longer on the curve
        r = emu(bytes(inp))
        self.assertEqual((r["kind"], r["err_payload_hex"], r["allocs"]), ("err", tool.ERR_AFFINE, []))

    def test_tamper_carve_montgomery_inv_breaks_output(self):
        with flip(0x4E9708F, at=2):
            r = emu(C1[0])
            self.assertNotEqual(r.get("output_hex"), C1[4])

    def test_tamper_carve_len_store_breaks_len(self):
        with flip(0x4E97392, at=4):  # movq $0x40,0x10(%rbx) immediate
            self.assertEqual(emu(C1[0])["len"], 0x41)

    def test_tamper_stub_removed_does_not_reproduce(self):
        r = emu(C1[0], stub=False)
        self.assertEqual(r["allocs"], [])
        self.assertFalse(r["returned"] and r.get("output_hex") == C1[4])

    def test_tamper_stub_heap_moves_pointer_not_output(self):
        old = tool.HEAP
        tool.HEAP = 0x71000000
        try:
            r = emu(C1[0])
        finally:
            tool.HEAP = old
        self.assertEqual((r["data_ptr"], r["output_hex"]), ("0x71000000", C1[4]))

    def test_gas_one_below_cost_out_of_gas(self):
        r = emu(C1[0], gas=6000, limit=5999)
        self.assertEqual((r["kind"], r["err_payload_hex"]), ("err", tool.ERR_OOG))

    def test_byzantium_gas_cost_reported(self):
        r = emu(C1[0], gas=40000, limit=40000)
        self.assertEqual((r["kind"], r["gas_used"], r["output_hex"]), ("ok", 40000, C1[4]))

    def test_short_input_not_emulated(self):
        # input < 96 bytes goes through memcpy (GLOB_DAT, unresolved here): not covered.
        r = emu(C1[0][:64])
        self.assertFalse(r["returned"])


if __name__ == "__main__":
    unittest.main()
