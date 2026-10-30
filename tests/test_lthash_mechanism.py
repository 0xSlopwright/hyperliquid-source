import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-C-lthash-mechanism-94"
BIN = ROOT / "artifacts/node/94/hl-node"
OUTPUT_SHA256 = "9450c6225fbc78446bfd7813592ec7e9700006c1fa0bf9ad567216ddb703b12a"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = load("lthash_mechanism", ROOT / "tools/lthash_mechanism.py")
iv = load("re009c_independent_verify", PACKET / "independent_verify.py")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BIN.read_bytes()
        cls.extents = tool.leaf_extents(cls.data)
        t = next(s for s in tool.sections(cls.data) if s["name"] == ".text")
        cls.ta, cls.to = t["address"], t["offset"]

    def off(self, va):
        return va - self.ta + self.to


class PinnedOutput(Base):
    def test_exact_output_sha(self):
        text = tool.render(tool.analyse(self.data, extents=self.extents))
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), OUTPUT_SHA256)
        self.assertEqual((PACKET / "lthash-mechanism.json").read_text(), text)

    def test_exact_mechanism(self):
        r = tool.analyse(self.data, extents=self.extents)
        self.assertEqual(r["counts"], {"leaves": 3, "lattice_loops": 6, "count_blocks": 3})
        self.assertEqual([L["leaf"] for L in r["leaves"]], ["0x37f3f00", "0x37f4280", "0x37f4610"])
        for L in r["leaves"]:
            a, b = L["lattice_entry_add"], L["lattice_merge_add"]
            self.assertEqual((a["index_start"], a["index_bound"], a["index_step"], a["iterations"],
                              a["lanes_per_iteration"], a["u16_words_total"], a["rol16_8_swaps"]),
                             (1, "0x401", 2, 512, 2, 1024, 6))
            self.assertEqual((b["index_start"], b["index_bound"], b["index_step"], b["iterations"],
                              b["u16_words_total"], b["rol16_8_swaps"]),
                             (0, "0x400", 2, 512, 1024, 6))
            self.assertEqual(a["addend_minus_accumulator"], "0x1020")
            self.assertEqual(b["addend_minus_accumulator"], "0x810")
            for x in (a, b):
                self.assertEqual((x["byte_order"], x["overflow"], x["bytes_covered"]),
                                 ("big-endian", "wrapping-mod-2^16", 0x800))
            self.assertEqual(L["blake3_slots"], {"new": "0x57700c0", "update": "0x57700c8",
                                                 "finalize_xof": "0x57700b0"})
            self.assertEqual(L["count_add"]["u64_adds"], 2)
            self.assertEqual(L["count_add"]["overflow"], "saturating-u64")

    def test_independent_verify_clean(self):
        packet = json.loads((PACKET / "lthash-mechanism.json").read_text())
        self.assertEqual(iv.check(self.data, packet), [])
        self.assertEqual((len(iv.KEYS), len(iv.BLOBS)), (37, 9))

    def test_independent_verify_imports_nothing_from_tools(self):
        src = (PACKET / "independent_verify.py").read_text()
        self.assertNotIn("tools", [l.split()[1].split(".")[0] for l in src.splitlines()
                                   if l.startswith(("import ", "from "))])
        self.assertNotIn("sys.path", src)


class Determinism(unittest.TestCase):
    def test_hashseeds(self):
        outs = set()
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-O", "-B", str(ROOT / "tools/lthash_mechanism.py")],
                               capture_output=True, env=env, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})


class KeyVaTamper(Base):
    """Every pinned key VA and block must be caught on its own (sha gate off)."""

    def setUp(self):
        self.buf = bytearray(self.data)

    def flip(self, va):
        o = self.off(va)
        self.buf[o] ^= 0xFF
        return o

    def test_every_key_va_caught_by_independent_verify(self):
        for va, hx, _kind, _tgt, role in iv.KEYS:
            for i in range(len(hx) // 2):
                with self.subTest(va=hex(va), byte=i, role=role):
                    o = self.flip(va + i)
                    errs = iv.check(bytes(self.buf), require_sha=False)
                    self.buf[o] ^= 0xFF
                    self.assertTrue(any(f"{va:#x}" in e for e in errs), errs)

    def test_every_block_caught_by_independent_verify(self):
        for va, n, _sha, role in iv.BLOBS:
            for i in (0, n // 2, n - 1):
                with self.subTest(va=hex(va), byte=i, role=role):
                    o = self.flip(va + i)
                    errs = iv.check(bytes(self.buf), require_sha=False)
                    self.buf[o] ^= 0xFF
                    self.assertTrue(any(f"{va:#x}" in e for e in errs), errs)

    def test_every_key_va_caught_by_tool(self):
        for va, hx, _kind, _tgt, role in iv.KEYS:
            with self.subTest(va=hex(va), role=role):
                o = self.flip(va + len(hx) // 2 - 1)
                try:
                    out = tool.render(tool.analyse(bytes(self.buf), require_sha=False,
                                                   extents=self.extents))
                    changed = hashlib.sha256(out.encode()).hexdigest() != OUTPUT_SHA256
                except ValueError:
                    changed = True
                self.buf[o] ^= 0xFF
                self.assertTrue(changed)

    def test_byte_swap_removed_is_rejected(self):
        va = 0x37f40d8                     # rol cx,0x8 in leaf1 entry loop
        o = self.off(va)
        self.assertEqual(self.buf[o:o + 4], bytes.fromhex("66c1c108"))
        self.buf[o:o + 4] = b"\x90" * 4
        with self.assertRaises(ValueError):
            tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents)

    def test_bound_change_changes_output(self):
        o = self.off(0x37f4120 + 2)        # cmp rax,0x401 imm32
        self.assertEqual(struct.unpack_from("<I", self.buf, o)[0], 0x401)
        struct.pack_into("<I", self.buf, o, 0x403)
        out = tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents)
        self.assertEqual(out["leaves"][0]["lattice_entry_add"]["u16_words_total"], 1026)

    def test_xof_len_change_rejected(self):
        o = self.off(0x37f408a + 1)
        struct.pack_into("<I", self.buf, o, 0x801)
        with self.assertRaises(ValueError):
            tool.analyse(bytes(self.buf), require_sha=False, extents=self.extents)

    def test_sha_gate(self):
        with self.assertRaises(ValueError):
            tool.analyse(self.data[:-1] + bytes([self.data[-1] ^ 0xFF]), extents=self.extents)


if __name__ == "__main__":
    unittest.main()
