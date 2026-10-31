"""Real Node94 byte/relocation controls; local arithmetic is not binary execution."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT
from rate_lookup_result_static import (CONTROLS, RELOCATIONS, TARGET, TARGET_BYTES, TARGET_SHA256,
                                       Image, branch_targets, controls, relocations, verify_listing)


class RateLookupResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / TARGET).read_bytes()
        if len(cls.data) != TARGET_BYTES or hashlib.sha256(cls.data).hexdigest() != TARGET_SHA256:
            raise ValueError('Real Node94 identity mismatch')
        cls.image = Image(cls.data)

    def test_real_target_instruction_and_relocation_controls(self):
        controls(self.image)
        self.assertEqual(len(relocations(self.image)), 5)
        self.assertEqual(branch_targets(self.image), {
            'caller_to_lookup': '0x4956d50', 'opaque_helper': '0x4959020',
            'jno_target': '0x4956d78', 'callback_slot': '0x576efb0',
            'caller_data_address': '0x572e848'})

    def test_each_real_instruction_control_rejects_corruption(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = self.image.read(va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction changed'):
                    controls(Image(changed))

    def test_each_real_relocation_rejects_retarget(self):
        for row in relocations(self.image):
            with self.subTest(slot=row['slot_va']):
                changed = bytearray(self.data)
                changed[int(row['record_file_offset'], 16) + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relocations(Image(changed))

    def test_encoded_zero_minus_word_overflow_partition(self):
        self.assertEqual(self.image.read(0x4956d5a, 7)[1], bytes.fromhex('31c0483b077117'))
        maximum, sign = (1 << 64) - 1, 1 << 63
        # Architectural subtraction OF=((a^b)&(a^result)&sign)!=0, with a=0.
        # Signed negation has one unrepresentable input: -2**63.
        samples = [0, 1, 2, sign - 1, sign, sign + 1, maximum - 1, maximum]
        overflowing = [word for word in samples if (word & ((-word) & maximum) & sign) != 0]
        self.assertEqual(overflowing, [sign])

    def test_two_real_encoded_stride_and_base_operands(self):
        fast = self.image.read(0x4956d61, 12)[1]
        slow = self.image.read(0x4956e7a, 14)[1]
        self.assertEqual(fast[:4], bytes.fromhex('48694718'))
        self.assertEqual(slow[:5], bytes.fromhex('4869442468'))
        self.assertEqual(struct.unpack_from('<i', fast, 4)[0], 608)
        self.assertEqual(struct.unpack_from('<i', slow, 5)[0], 608)
        self.assertEqual(fast[8:], bytes.fromhex('48034708'))
        self.assertEqual(slow[9:], bytes.fromhex('4803442458'))
        # Independent multiply/add reduction examples, no memory dereference.
        modulus = 1 << 64
        for base, index, expected in [(0, 0, 0), (0x1000, 2, 0x14c0),
                                      (modulus - 1, 1, 607), (7, modulus - 1, modulus - 601)]:
            self.assertEqual((base + 608 * index) % modulus, expected)

    def test_listing_guard_rejects_truncation_address_and_byte_changes(self):
        start, end = 0x4714f49, 0x4714f4c
        exact = ' 4714f49:\t48 89 c7  \tmov %rax,%rdi\n'
        verify_listing(exact, self.image, start, end)
        for raw in ['', exact.replace('4714f49', '4714f4a'), exact.replace('c7', 'cf'),
                    ' 4714f49:\t48 89  \tmov\n']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                verify_listing(raw, self.image, start, end)

    def test_real_cli_preserves_existing_empty_and_populated_output(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temporary:
            output = Path(temporary) / 'retained'
            output.mkdir()
            for populated in (False, True):
                with self.subTest(populated=populated):
                    if populated:
                        (output / 'records.json').write_bytes(b'prior-evidence\r\n\x00')
                    before = {p.name: p.read_bytes() for p in output.iterdir()}
                    result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/rate_lookup_result_static.py'),
                                             '--binary', str(ROOT / TARGET), '--output', str(output)],
                                            capture_output=True, encoding='utf-8', check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Output already exists; preserve retained evidence', result.stderr)
                    self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)


if __name__ == '__main__':
    unittest.main()
