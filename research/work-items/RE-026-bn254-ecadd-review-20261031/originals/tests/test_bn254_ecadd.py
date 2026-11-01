"""RE-026: bn254 ecAdd packet: exact pins, seed determinism, negative controls, tamper tests."""
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
PACKET = ROOT / "research" / "work-items" / "RE-026-bn254-ecadd-94"
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecadd as tool  # noqa: E402

OUTPUT_SHA256 = "0ece19222a62722e80d336bca990ba1113a9e3765a26aa0f858b46c7af335581"
NO_EMU_OUTPUT_SHA256 = "8832409f27af72886b0f2cf4c1355e142bf29f76ac6a1faf7dc1d35684df1716"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None
TOOL = str(ROOT / "tools" / "bn254_ecadd.py")

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


def emu(inp, gas=150, limit=1000, stub=True):
    return tool.emulate(bytes(DATA), SEGS, tool.rela_dyn(bytes(DATA)), inp, gas, limit, stub=stub)


GG = tool.VECTORS["g_plus_g"]


@unittest.skipIf(DATA is None, "node #94 binary not present")
class Bn254EcAddStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        self.assertEqual(r["carved_len"], 1758)
        self.assertEqual(r["got_slot_refs"]["vas"], ["call@0x4e98a57", "call@0x4e98ae7"])
        self.assertEqual(r["direct_e8_e9_to_fn"], 0)
        self.assertEqual([w["gas_imm"] for w in r["wrappers"]], [150, 500])

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "bn254-ecadd.json").read_text())
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
        self.assertEqual(tool.INV128 & (2**64 - 1), 0x87D20782E4866389)
        self.assertEqual(tool.ref_add(tool.G, tool.G), tool.TWO_G)
        x, y = tool.TWO_G
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
        self.assertNotIn("bn254_ecadd", src)

    def test_tamper_prologue_rejected(self):
        with flip(tool.FN):
            self.assertTrue(static_errors())

    def test_tamper_p_limb_rejected(self):
        with flip(0x4E9696B, at=2):
            self.assertIn("p limbs count in run_add mismatch", static_errors())

    def test_tamper_montgomery_inv_rejected(self):
        with flip(0x4E969A3, at=2):
            self.assertIn("Montgomery inv count mismatch", static_errors())

    def test_tamper_r2_in_decoder_rejected(self):
        with flip(0x4E9628C, at=2):
            self.assertIn("R^2 mod p limbs in decoder mismatch", static_errors())

    def test_tamper_wrapper_gas_rejected(self):
        with flip(0x4E98A50):
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_wrapper_call_rejected(self):
        with flip(0x4E98AE7, at=2):
            errs = static_errors()
            self.assertIn("GOT slot ref counts mismatch", errs)

    def test_tamper_malloc_call_rejected(self):
        with flip(tool.MALLOC_CALL, at=2):
            self.assertIn("branch target mismatch", static_errors())

    def test_tamper_got_rela_rejected(self):
        o = rela_entry_off(tool.GOT_SLOT) + 16
        with Patched(o, [DATA[o] ^ 0x10]):
            self.assertIn("GOT RELA mismatch", static_errors())

    def test_tamper_table_rela_rejected(self):
        o = rela_entry_off(0x574F0E0) + 16
        with Patched(o, [DATA[o] ^ 0x10]):
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_table_address_rejected(self):
        with flip(0x574F0E0 + 0x10 + 19):  # Address 0x06 -> 0x07
            self.assertTrue(any("wrapper mismatch" in e for e in static_errors()))

    def test_tamper_location_line_rejected(self):
        with flip(tool.LOCATION, at=16):
            self.assertIn("location mismatch", static_errors())

    def test_negative_injected_cpuid_rejected(self):
        with Patched(off(0x4E96700), b"\x0f\xa2"):
            errs = static_errors()
            self.assertIn("SIMD/feature pattern in run_add", errs)

    def test_negative_unpinned_carve_byte_only_carve_differs(self):
        with flip(0x4E96700):
            self.assertEqual(static_errors(), ["carved_sha256 mismatch"])

    def test_negative_wrong_binary_sha_raises(self):
        with flip(0x4E96700):
            with self.assertRaises(ValueError):
                tool.analyse(bytes(DATA), check_sha=True, run_emu=False)


@unittest.skipIf(DATA is None or not HAS_UNICORN, "binary or unicorn missing")
class Bn254EcAddEmuTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "bn254-ecadd.json").read_text(), tool.render(r))

    def test_g_plus_2g_matches_reference(self):
        three_g = tool.ref_add(tool.G, tool.TWO_G)
        r = emu(tool.enc(*tool.G, *tool.TWO_G))
        self.assertEqual(r["output_hex"], tool.enc(*three_g).hex())

    def test_tamper_input_takes_error_path(self):
        inp = bytearray(GG[0])
        inp[63] ^= 1  # y of point 1: 2 -> 3, off curve
        r = emu(bytes(inp))
        self.assertEqual((r["kind"], r["err_payload_hex"], r["allocs"]), ("err", tool.ERR_AFFINE, []))

    def test_tamper_carve_p_limb_breaks_output(self):
        with flip(0x4E9696B, at=2):
            r = emu(GG[0])
            self.assertNotEqual(r.get("output_hex"), GG[4])

    def test_tamper_carve_len_store_breaks_len(self):
        with flip(0x4E96CC2):  # movq $0x40,0x10(%rbx) immediate
            self.assertEqual(emu(GG[0])["len"], 0x41)

    def test_tamper_stub_removed_does_not_reproduce(self):
        r = emu(GG[0], stub=False)
        self.assertEqual(r["allocs"], [])
        self.assertFalse(r["returned"] and r.get("output_hex") == GG[4])

    def test_tamper_stub_heap_moves_pointer_not_output(self):
        old = tool.HEAP
        tool.HEAP = 0x71000000
        try:
            r = emu(GG[0])
        finally:
            tool.HEAP = old
        self.assertEqual((r["data_ptr"], r["output_hex"]), ("0x71000000", GG[4]))

    def test_gas_equal_limit_succeeds(self):
        r = emu(GG[0], gas=150, limit=150)
        self.assertEqual((r["kind"], r["gas_used"]), ("ok", 150))


if __name__ == "__main__":
    unittest.main()
