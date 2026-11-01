"""RE-026: bn254 ecAdd packet: exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-026-bn254-ecadd-94"
sys.path.insert(0, str(ROOT / "tools"))
import bn254_ecadd as tool  # noqa: E402

OUTPUT_SHA256 = "0ece19222a62722e80d336bca990ba1113a9e3765a26aa0f858b46c7af335581"
NO_EMU_OUTPUT_SHA256 = "8832409f27af72886b0f2cf4c1355e142bf29f76ac6a1faf7dc1d35684df1716"
HAS_UNICORN = importlib.util.find_spec("unicorn") is not None
ALLOW_EMULATION = os.environ.get("HL_ALLOW_BN254_ECADD_EMULATION") == "1"
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
    return tool.emulate(bytes(DATA), SEGS, tool.rela_dyn(bytes(DATA)), inp, gas, limit,
                        stub=stub, allow_execution=True)


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

    def test_out_of_gas_leaves_trailing_result_bytes_untouched(self):
        # Authenticate the branch/store footprint; this is static algebra only.
        self.assertEqual(tool.read_va(DATA, SEGS, 0x4e96627, 2).hex(), "7613")
        self.assertEqual(tool.read_va(DATA, SEGS, 0x4e96629, 19).hex(),
                         "48b8000000000000008048894310e995010000")
        self.assertEqual(tool.read_va(DATA, SEGS, 0x4e967d1, 9).hex(),
                         "0f57c00f11034889d8")
        result = bytearray([0xa5] * 40)
        result[16:24] = struct.pack("<Q", 1 << 63)
        result[:16] = bytes(16)
        self.assertEqual(result[24:], bytes([0xa5] * 16))
        self.assertNotEqual(result[16:].hex(), tool.ERR_OOG)


@unittest.skipUnless(ALLOW_EMULATION and DATA is not None and HAS_UNICORN,
                     "captured emulation requires explicit authorization and opt-in")
class Bn254EcAddEmuTests(unittest.TestCase):
    def assert_complete(self, result):
        self.assertTrue(result["returned"], result)
        self.assertIsNone(result["fault"], result)

    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "bn254-ecadd.json").read_text(), tool.render(r))

    def test_g_plus_2g_matches_reference(self):
        three_g = tool.ref_add(tool.G, tool.TWO_G)
        r = emu(tool.enc(*tool.G, *tool.TWO_G))
        self.assert_complete(r)
        self.assertEqual(r["output_hex"], tool.enc(*three_g).hex())

    def test_tamper_input_takes_error_path(self):
        inp = bytearray(GG[0])
        inp[63] ^= 1  # y of point 1: 2 -> 3, off curve
        r = emu(bytes(inp))
        self.assert_complete(r)
        self.assertEqual((r["kind"], r["err_payload_hex"], r["allocs"]), ("err", tool.ERR_AFFINE, []))

    def test_tamper_carve_p_limb_breaks_output(self):
        with flip(0x4E9696B, at=2):
            r = emu(GG[0])
            self.assertNotEqual(r.get("output_hex"), GG[4])

    def test_tamper_carve_len_store_breaks_len(self):
        with flip(0x4E96CC2):  # movq $0x40,0x10(%rbx) immediate
            r = emu(GG[0])
            self.assertEqual(r["len"], 0x41)
            self.assertFalse(r["returned"])
            self.assertIsNotNone(r["fault"])
            self.assertIsNone(r["output_hex"])

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
        self.assert_complete(r)
        self.assertEqual((r["data_ptr"], r["output_hex"]), ("0x71000000", GG[4]))

    def test_gas_equal_limit_succeeds(self):
        r = emu(GG[0], gas=150, limit=150)
        self.assert_complete(r)
        self.assertEqual((r["kind"], r["gas_used"]), ("ok", 150))


class Bn254EcAddHarnessControls(unittest.TestCase):
    def test_authentication_fails_before_backend_import(self):
        with patch.dict(sys.modules, {"unicorn": None, "crypto_emulation_guard": None}):
            with self.assertRaisesRegex(ValueError, "authenticated node94"):
                tool.emulate(b"not an ELF", [], [], bytes(128), 150, 1000,
                             allow_execution=True)

    @unittest.skipIf(DATA is None, "node #94 binary not present")
    def test_only_the_two_exact_original_mutations_are_authenticated(self):
        tool.validate_run(bytes(DATA), SEGS, RELA, GG[0], 150, 1000, True, True)
        for va in (0x4E9696D, 0x4E96CC2):
            with flip(va):
                tool.validate_run(bytes(DATA), SEGS, RELA, GG[0], 150, 1000, True, True)
        for va in (0, tool.FN, 0x4E9696E, 0x4E96CC3):
            # Offset zero is the ELF magic; all other cases are code mutations.
            mutation = Patched(0, bytes([DATA[0] ^ 1])) if va == 0 else flip(va)
            with mutation, self.assertRaisesRegex(ValueError, "authenticated node94"):
                tool.validate_run(bytes(DATA), SEGS, RELA, GG[0], 150, 1000, True, True)
        with flip(0x4E9696D), flip(0x4E96CC2):
            with self.assertRaisesRegex(ValueError, "authenticated node94"):
                tool.validate_run(bytes(DATA), SEGS, RELA, GG[0], 150, 1000, True, True)

    @unittest.skipIf(DATA is None, "node #94 binary not present")
    def test_mapping_metadata_is_bound_before_backend_import(self):
        with patch.dict(sys.modules, {"unicorn": None, "crypto_emulation_guard": None}):
            for segs, rela in (([], RELA), (SEGS, []), (SEGS, RELA[:-1])):
                with self.subTest(segs_empty=not segs, rela_count=len(rela)):
                    with self.assertRaisesRegex(ValueError, "metadata"):
                        tool.emulate(bytes(DATA), segs, rela, GG[0], 150, 1000,
                                     allow_execution=True)

    def test_gas_and_heap_scope_fail_before_backend_import(self):
        for value in (True, 1.5, -1, 1 << 64):
            for gas, limit in ((value, 1000), (150, value)):
                with self.assertRaisesRegex(ValueError, "u64 gas"):
                    tool.validate_run(b"", [], [], GG[0], gas, limit, True, True)
        for heap in (tool.FN, 0x60000000, 0x7FFF00000000, 0x70000001):
            with patch.object(tool, "HEAP", heap):
                with self.assertRaisesRegex(ValueError, "heap placements"):
                    tool.validate_run(b"", [], [], GG[0], 150, 1000, True, True)

    def test_complete_header_required_before_pointer_read(self):
        q = (0x5670AE8, tool.HEAP, 64, tool.HEAP | 1, 150)
        allocs = [{"ret": hex(tool.MALLOC_RET), "size": 64}]
        tool.validate_result(q, allocs, 150)
        for i in range(5):
            bad = list(q)
            bad[i] ^= 1
            with self.subTest(qword=i), self.assertRaises(ValueError):
                tool.validate_result(tuple(bad), allocs, 150)
        for bad_allocs in ([], allocs * 2, [{"ret": hex(tool.MALLOC_RET + 1), "size": 64}]):
            with self.assertRaises(ValueError):
                tool.validate_result(q, bad_allocs, 150)
        for tag in (0, 6, 7):
            tool.validate_result((0, 0, (1 << 63) | tag, 0xa5, 0xa5), [], 150)
        for bad in ((0, 1, 1 << 63, 0, 0), (0, 0, 0, 0, 0)):
            with self.assertRaises(ValueError):
                tool.validate_result(bad, [], 150)

    def fake_backend_result(self, *, header=None, stopped=False):
        """Pure host control: the fake runner never executes any instructions."""
        u = types.ModuleType("unicorn")
        x = types.ModuleType("unicorn.x86_const")
        guard = types.ModuleType("crypto_emulation_guard")
        for i, name in enumerate(("UC_ARCH_X86", "UC_HOOK_CODE", "UC_MODE_64", "UC_PROT_ALL")):
            setattr(u, name, i)
        for i, name in enumerate(("FS_BASE", "R8", "RAX", "RCX", "RDI", "RDX", "RIP", "RSI", "RSP")):
            setattr(x, "UC_X86_REG_" + name, i)
        u.UcError = type("FakeUcError", (Exception,), {})
        reads = []

        class Fake:
            def __init__(self, *args): self.mem, self.reg, self.hooks = {}, {}, []
            def mem_map(self, *args): pass
            def mem_write(self, address, data): self.mem.update((address+i, b) for i, b in enumerate(data))
            def mem_read(self, address, size):
                reads.append((address, size))
                return bytes(self.mem.get(address+i, 0) for i in range(size))
            def reg_write(self, reg, value): self.reg[reg] = value
            def reg_read(self, reg): return self.reg.get(reg, 0)
            def hook_add(self, kind, hook, **kwargs): self.hooks.append(hook); return len(self.hooks)
            def hook_del(self, hook): pass

        u.Uc = Fake
        q = header or (0x5670AE8, tool.HEAP, 64, tool.HEAP | 1, 150)
        expected = tool.enc(*tool.ref_add(tool.G, tool.TWO_G)).hex()

        def fake_run(mu, start, stop, **kwargs):
            self.assertEqual(kwargs["writable_ranges"][-1], (tool.HEAP, tool.HEAP + 64))
            sp = mu.reg_read(x.UC_X86_REG_RSP)
            mu.mem_write(sp, struct.pack("<Q", tool.MALLOC_RET))
            mu.reg_write(x.UC_X86_REG_RDI, 64)
            mu.hooks[0](mu, tool.MALLOC, 4, None)
            mu.mem_write(0x60000100, struct.pack("<5Q", *q))
            mu.mem_write(tool.HEAP, bytes.fromhex(expected))
            mu.reg_write(x.UC_X86_REG_RIP, start if stopped else stop)
            if stopped:
                raise ValueError("controlled incomplete return")

        guard.run_bounded = fake_run
        with patch.dict(sys.modules, {"unicorn": u, "unicorn.x86_const": x,
                                     "crypto_emulation_guard": guard}), \
             patch.object(tool, "validate_run"):
            result = tool.emulate(b"", [], [], GG[0], 150, 1000, allow_execution=True)
        return result, reads, expected

    def test_stopped_output_never_passes_positive_acceptance(self):
        result, reads, _ = self.fake_backend_result(stopped=True)
        self.assertFalse(result["returned"])
        self.assertEqual(result["fault"], "controlled incomplete return")
        self.assertIsNone(result["output_hex"])
        self.assertNotIn((tool.HEAP, 64), reads)
        with self.assertRaises(AssertionError):
            Bn254EcAddEmuTests().assert_complete(result)

    def test_invalid_header_never_reads_guest_output(self):
        for q in ((1, tool.HEAP, 64, tool.HEAP | 1, 150),
                  (0x5670AE8, tool.HEAP + 8, 64, tool.HEAP | 1, 150),
                  (0x5670AE8, tool.HEAP, 65, tool.HEAP | 1, 150),
                  (0x5670AE8, tool.HEAP, 64, 0, 150),
                  (0x5670AE8, tool.HEAP, 64, tool.HEAP | 1, 151)):
            result, reads, _ = self.fake_backend_result(header=q)
            self.assertFalse(result["returned"])
            self.assertIsNotNone(result["fault"])
            self.assertIsNone(result["output_hex"])
            self.assertNotIn((q[1], q[2]), reads)

    def test_valid_header_reads_exact_allocation_after_completion(self):
        result, reads, expected = self.fake_backend_result()
        self.assertTrue(result["returned"])
        self.assertIsNone(result["fault"])
        self.assertEqual(result["output_hex"], expected)
        self.assertEqual(reads[-1], (tool.HEAP, 64))

    def test_raw_reference_scans_include_final_fitting_offsets(self):
        target = tool.TEXT_LOAD_VA + 0x100
        for prefix,kind,size in [(b"\xff\x15","call",6),(b"\xff\x25","jmp",6),
                                 (b"\x48\x8b\x05","mov",7),(b"\x4c\x8b\x05","mov",7)]:
            for pad in [b"",b"\x90"]:
                candidate=prefix+struct.pack('<i',target-(tool.TEXT_LOAD_VA+len(pad)+size))
                self.assertEqual(tool.slot_refs(pad+candidate,target),[(kind,tool.TEXT_LOAD_VA+len(pad))])
                self.assertEqual(tool.slot_refs(pad+candidate[:-1],target),[])
        for prefix in [b"\xe8",b"\xe9"]:
            candidate=prefix+struct.pack('<i',target-(tool.TEXT_LOAD_VA+5))
            self.assertEqual(tool.direct_calls(candidate,target),1)
            self.assertEqual(tool.direct_calls(candidate[:-1],target),0)

    def test_default_cli_is_static_even_if_unicorn_is_available(self):
        with patch.object(tool, "analyse", return_value={}) as analyse, \
             patch.object(tool, "expectation_errors", return_value=[]), \
             patch.object(tool, "render", return_value=""), \
             patch.object(tool, "unicorn_available", return_value=True):
            self.assertEqual(tool.main([]), 0)
        self.assertFalse(analyse.call_args.kwargs["run_emu"])

    def test_emulation_requires_opt_in_before_loading_backend(self):
        with self.assertRaisesRegex(ValueError, "explicit authorization"):
            tool.emulate(b"", [], [], bytes(128), 150, 1000)
        with patch.object(tool, "unicorn_available", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                tool.analyse(b"", run_emu=True)

    def test_input_bounds_checked_before_loading_backend(self):
        for inp, gas, limit in [(b"",150,1000),(bytes(129),150,1000),(bytes(128),-1,1000),(bytes(128),150,2**64)]:
            with self.assertRaisesRegex(ValueError, "128-byte input"):
                tool.emulate(b"", [], [], inp, gas, limit, allow_execution=True)

    def test_malloc_callback_rejects_unreviewed_requests(self):
        stack=0x1000;heap=0x100000
        self.assertEqual(tool.malloc_request(stack,tool.MALLOC_RET,64,heap,stack,heap),heap+64)
        for sp,ret,n,bump in [(stack-1,tool.MALLOC_RET,64,heap),(stack+0x100000-7,tool.MALLOC_RET,64,heap),
                              (stack,tool.MALLOC_RET+1,64,heap),(stack,tool.MALLOC_RET,65,heap),
                              (stack,tool.MALLOC_RET,64,heap+0xfff0),(stack,tool.MALLOC_RET,64,heap+1)]:
            with self.assertRaises(ValueError):tool.malloc_request(sp,ret,n,bump,stack,heap)


if __name__ == "__main__":
    unittest.main()
