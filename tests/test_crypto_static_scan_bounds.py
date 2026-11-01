"""Synthetic raw-byte scanner boundaries; no captured code execution."""
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import blake2b_compress
import chacha12_guts
import ripemd160_compress
import sha256_compress
import sha512_compress

BASE = 0x1343c80


def reference(prefix, target):
    return prefix + struct.pack("<i", target - BASE - len(prefix) - 4)


class CryptoStaticScanBoundsTests(unittest.TestCase):
    def test_terminal_three_byte_rotate(self):
        with patch.object(blake2b_compress, "read_va", return_value=b"\x48\xd1\xc0"):
            self.assertEqual(blake2b_compress.count_rol_immediates(b"", []),
                             {"0x20": 0, "0x28": 0, "0x30": 0, "1": 1})

    def test_terminal_chacha_call(self):
        data = reference(b"\xff\x15", chacha12_guts.GOT_SLOT)
        self.assertEqual(chacha12_guts.count_got_callers(data, [(BASE, 0, len(data), len(data))]), 1)

    def test_terminal_sha512_extended_register_load(self):
        data = reference(b"\x4c\x8b\x25", sha512_compress.GOT_SLOT)
        self.assertEqual(sha512_compress.count_got_mov_callers(data, [(BASE, 0, len(data), len(data))]), 1)

    def test_ripemd_extended_register_and_terminal_call(self):
        for prefix, expected in ((b"\x4c\x8b\x25", (1, 0)), (b"\xff\x15", (0, 1))):
            with self.subTest(prefix=prefix.hex()):
                data = reference(prefix, ripemd160_compress.GOT_SLOT)
                self.assertEqual(ripemd160_compress.count_got_callers(data, [(BASE, 0, len(data), len(data))]), expected)

    def test_terminal_sha256_reference_lengths(self):
        for prefix, kind in ((b"\xff\x15", "call"), (b"\xff\x25", "jmp"), (b"\x4c\x8b\x25", "mov")):
            with self.subTest(kind=kind):
                data = reference(prefix, sha256_compress.GOT_SLOT)
                self.assertEqual(sha256_compress.slot_refs(data, [(BASE, 0, len(data), len(data))]), [(kind, BASE)])

    def test_truncated_and_wrong_target_refs_are_not_counted(self):
        for tool, fn in ((chacha12_guts, chacha12_guts.count_got_callers),
                         (ripemd160_compress, ripemd160_compress.count_got_callers),
                         (sha256_compress, sha256_compress.slot_refs)):
            for data in (b"\xff\x15\x00", reference(b"\xff\x15", tool.GOT_SLOT + 1)):
                result = fn(data, [(BASE, 0, len(data), len(data))])
                self.assertIn(result, (0, (0, 0), []))


if __name__ == "__main__":
    unittest.main()
