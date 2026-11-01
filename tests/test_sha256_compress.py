"""RE-025: SHA-256 compress packet: exact pins, seed determinism, negative controls, tamper tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-025-sha256-compress-94"
sys.path.insert(0, str(ROOT / "tools"))
import sha256_compress as tool  # noqa: E402

OUTPUT_SHA256 = "9dd7fda7ac294318790f69c971d3caaa1fef82abe09b0637897834692b0d9d27"
NO_EMU_OUTPUT_SHA256 = "9d931ebabf18dfaf49b329da7cb50f77d4d1303066480a01a4ca55a0942376cc"
HAS_UNICORN = (os.environ.get("HL_ALLOW_CAPTURED_CRYPTO_EMULATION") == "1"
               and importlib.util.find_spec("unicorn") is not None)
TOOL = str(ROOT / "tools" / "sha256_compress.py")

DATA = bytearray(tool.TARGET.read_bytes()) if tool.TARGET.exists() else None
SEGS = tool.segments(bytes(DATA)) if DATA is not None else None


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


def static_errors():
    try:
        return tool.expectation_errors(tool.analyse(bytes(DATA), check_sha=False, run_emu=False))
    except Exception as exc:  # parse failure counts as detection
        return [repr(exc)]


def emu(blocks, nblocks, state=tool.SHA256_IV_LE, flag=0):
    return tool.emulate_compress(bytes(DATA), SEGS, blocks, nblocks, state=state, flag=flag).hex()


ABC = tool.VECTORS["abc"]


@unittest.skipIf(DATA is None, "node #94 binary not present")
class Sha256CompressStaticTests(unittest.TestCase):
    def test_static_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=False)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), NO_EMU_OUTPUT_SHA256)
        self.assertEqual(r["carved_len"], 11419)
        self.assertEqual(r["got_slot_refs"]["total"], 33)
        self.assertEqual(r["shani_sha256rnds2_count"], 32)
        self.assertEqual(r["direct_e8_e9_to_fn"], 0)

    def test_committed_json_pins(self):
        disk = json.loads((PACKET / "sha256-compress.json").read_text())
        self.assertTrue(disk["emu_ran"])
        self.assertEqual(disk["carved_sha256"], tool.CARVED_SHA256)
        for name, (_m, _n, digest) in tool.VECTORS.items():
            self.assertEqual(disk["vectors"][name]["expected_digest_hex"], digest)
            self.assertEqual(disk["vectors"][name]["emulated_digest_hex"], digest)

    def test_fips_literals_agree_with_hashlib(self):
        for name, (msg, nblocks, digest) in tool.VECTORS.items():
            self.assertEqual(hashlib.sha256(msg).hexdigest(), digest, name)
            self.assertEqual(len(tool.pad(msg)), 64 * nblocks, name)

    def test_k_derivation_matches_fips_endpoints(self):
        self.assertEqual(tool.SHA256_K[0], 0x428A2F98)
        self.assertEqual(tool.SHA256_K[63], 0xC67178F2)
        self.assertEqual(len(set(tool.SHA256_K)), 64)

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
        self.assertNotIn("sha256_compress", src)

    def test_tamper_prologue_rejected(self):
        with flip(tool.FN):
            self.assertTrue(static_errors())

    def test_tamper_dispatch_cmp_rejected(self):
        with flip(0x4EC9258):  # cmp al,1 immediate
            self.assertTrue(static_errors())

    def test_tamper_shani_jmp_rejected(self):
        with flip(tool.SHANI_JMP, at=1):
            self.assertTrue(static_errors())

    def test_tamper_plain_k_imm_rejected(self):
        with flip(0x4EC93DA):  # first imm32 0x428a2f98 in the plain body
            self.assertTrue(static_errors())

    def test_tamper_shani_k_group_rejected(self):
        with flip(0x203380):  # K[4..7] group used by the SHA-NI body
            self.assertTrue(static_errors())

    def test_tamper_caller_call_rejected(self):
        with flip(tool.CALLER_CALL, at=2):
            self.assertTrue(static_errors())

    def test_tamper_got_rela_rejected(self):
        rela = tool.rela_dyn(bytes(DATA))
        idx = [k for k, r in enumerate(rela) if r[0] == tool.GOT_SLOT][0]
        e_shoff = int.from_bytes(DATA[40:48], "little")
        import struct

        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", DATA, 58)
        hdr = e_shoff + shstrndx * shentsize
        so, ss = struct.unpack_from("<QQ", DATA, hdr + 24)
        names = bytes(DATA[so : so + ss])
        for i in range(shnum):
            o = e_shoff + i * shentsize
            n = struct.unpack_from("<I", DATA, o)[0]
            if names[n : names.find(b"\x00", n)] == b".rela.dyn":
                base = struct.unpack_from("<Q", DATA, o + 24)[0]
        with Patched(base + idx * 24 + 16, [DATA[base + idx * 24 + 16] ^ 0x10]):
            self.assertIn("GOT RELA mismatch", static_errors())

    def test_tamper_location_line_rejected(self):
        with flip(0x566BFF0, at=16):
            self.assertTrue(any("location" in e for e in static_errors()))

    def test_negative_unpinned_plain_byte_static_ok_but_carve_differs(self):
        with flip(0x4EC9500):
            errs = static_errors()
            self.assertEqual(errs, ["carved_sha256 mismatch"])

    def test_negative_wrong_binary_sha_raises(self):
        with flip(0x4EC9500):
            with self.assertRaises(ValueError):
                tool.analyse(bytes(DATA), check_sha=True, run_emu=False)


@unittest.skipIf(DATA is None or not HAS_UNICORN, "binary missing or captured emulation not explicitly enabled")
class Sha256CompressEmuTests(unittest.TestCase):
    def test_output_pin_and_expectations(self):
        r = tool.analyse(bytes(DATA), run_emu=True)
        self.assertEqual(tool.expectation_errors(r), [])
        self.assertEqual(hashlib.sha256(tool.render(r).encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "sha256-compress.json").read_text(), tool.render(r))

    def test_tamper_state_breaks_digest(self):
        st = bytearray(tool.SHA256_IV_LE)
        st[0] ^= 1
        self.assertNotEqual(emu(tool.pad(ABC[0]), 1, state=bytes(st)), ABC[2])

    def test_tamper_block_breaks_digest(self):
        blk = bytearray(tool.pad(ABC[0]))
        blk[1] ^= 1
        self.assertNotEqual(emu(bytes(blk), 1), ABC[2])

    def test_tamper_carve_k_imm_breaks_digest(self):
        with flip(0x4EC93DA):
            self.assertNotEqual(emu(tool.pad(ABC[0]), 1), ABC[2])

    def test_negative_shani_region_flip_leaves_plain_digest(self):
        with flip(0x4ECC100):  # inside SHA-NI body; plain path never reaches it
            self.assertEqual(emu(tool.pad(ABC[0]), 1), ABC[2])

    def test_nblocks_zero_leaves_state(self):
        iv_be = b"".join(w.to_bytes(4, "big") for w in tool.SHA256_IV).hex()
        self.assertEqual(emu(bytes(64), 0), iv_be)

    def test_shani_branch_not_executable_under_unicorn(self):
        from unicorn import UcError

        with self.assertRaisesRegex(ValueError, "escaped allowed range"):
            emu(tool.pad(ABC[0]), 1, flag=1)


if __name__ == "__main__":
    unittest.main()
