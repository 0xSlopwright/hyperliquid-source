"""Independent review checks for selected node94 observations."""
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import pxpriv_admission as px
import stake_requirement_static as stake
import sub_account_static as sub

class NxtReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / px.BINARY_REL).read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != px.EXPECTED_SHA256:
            raise ValueError('wrong baseline')

    def test_px_manifest_duplicate_path_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'provenance').mkdir()
            item = {'path': px.BINARY_REL, 'size': px.EXPECTED_SIZE, 'sha256': px.EXPECTED_SHA256}
            (root / 'provenance/artifacts.json').write_text(json.dumps({'files': [item, item]}))
            with self.assertRaises(px.EvidenceError):
                px.load_expected_artifact(root)

    def test_px_manifest_cannot_rebind_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'provenance').mkdir()
            item = {'path': px.BINARY_REL, 'size': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
            (root / 'provenance/artifacts.json').write_text(json.dumps({'files': [item]}))
            with self.assertRaises(px.EvidenceError):
                px.check_digest(b'', root)

    def test_px_integer_branches_and_distinct_carriers(self):
        # GNU-decoded instruction boundaries, not raw opcode-search hits.
        for base in [0x2812c00, 0x2813320, 0x2813af0, 0x35938d0, 0x3593fa0, 0x35947f0]:
            off = base - 0x1000
            self.assertEqual(self.data[off+0xe1:off+0xf4].hex(), '4d85f60f88a30100004c8934240f85bd010000')
            self.assertEqual(self.data[off+0x2a8:off+0x2b1].hex(), '4d85f60f84a9020000')
            self.assertEqual(self.data[off+0x556:off+0x55a].hex(), '31c0eb5a')
            self.assertEqual(self.data[off+0x5b4:off+0x5b7].hex(), '4c89f2')
        for base in [0x2e625e0, 0x2e957e0, 0x2ee1ec0]:
            off = base - 0x1000
            self.assertEqual(self.data[off+0x253:off+0x25c].hex(), '4885c00f88dbfeffff')
            self.assertEqual(self.data[off+0x261:off+0x266].hex(), '4885c07566')
            self.assertEqual(self.data[off+0x2bf:off+0x2d3].hex(), '4885c0480fc84889442420741048894708c60709')

    def test_staking_rejects_adjacent_start_as_extent(self):
        altered = [dict(row) for row in stake.FDES]
        altered[0]['end_va'] = 0x2512ad0
        with patch.object(stake, 'FDES', altered), self.assertRaises(stake.EvidenceError):
            stake.analyse(self.data)

    def test_staking_panic_record_mutation(self):
        bad = bytearray(self.data)
        bad[0x56b81b0 - 0x2000 + 16] ^= 1
        with patch.object(stake, 'check_digest'), self.assertRaisesRegex(stake.EvidenceError, 'panic location'):
            stake.analyse(bytes(bad))

    def test_staking_table_mutation(self):
        bad = bytearray(self.data)
        bad[0x20c2a0] ^= 1
        with patch.object(stake, 'check_digest'), self.assertRaisesRegex(stake.EvidenceError, 'Spot table'):
            stake.analyse(bytes(bad))

    def test_sub_account_rejects_adjacent_start_as_extent(self):
        altered = [dict(row) for row in sub.FDES]
        altered[0]['end'] = 0x36f3c20
        with patch.object(sub, 'FDES', altered), self.assertRaises(sub.EvidenceError):
            sub.analyse(self.data)

    def test_sub_account_magic_division_matches_unsigned_domain(self):
        # MUL high half; SHR33; unsigned MIN40; ADD10.
        rng = random.Random(615)
        values = [0, (1 << 64)-1] + [rng.randrange(1 << 64) for _ in range(1000)]
        values += [step*10_000_000_000+delta for step in range(1, 42) for delta in [-1,0,1]]
        for value in values:
            quotient = ((value * 0xdbe6fecebdedd5bf) >> 64) >> 33
            self.assertEqual(sub.max_sub_accounts_for_equity(value), 10 + min(quotient, 40))
        for value in [-1, 1 << 64, True]:
            with self.assertRaises(ValueError):
                sub.max_sub_accounts_for_equity(value)

    def test_sub_account_name_byte_boundary(self):
        self.assertEqual(sub.validate_sub_account_name('\u00e9'*8), sub.SUCCESS_CODE)
        self.assertEqual(sub.validate_sub_account_name('\u00e9'*9), sub.ERR_SUB_ACCOUNT_INVALID_NAME)
        for length in range(34):
            native = ((length-17) & ((1 << 64)-1)) > (1 << 64)-17
            self.assertEqual(sub.validate_sub_account_name('a'*length) == sub.SUCCESS_CODE, native)

if __name__ == '__main__':
    unittest.main()
