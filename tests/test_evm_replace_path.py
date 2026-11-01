import hashlib
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_replace_path as m


class ReplacePathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.checked_data()
        cls.sections = m.sections(cls.data)
        cls.record = m.generate(cls.data)

    def test_target_and_exact_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.DIGEST)
        self.assertEqual([(x['start'],x['end_exclusive']) for x in self.record['functions']], [
            ('0x326a6f0','0x326aa38'), ('0x326aa40','0x326abc1'),
            ('0x326abd0','0x326aebc'), ('0x3271680','0x3272188'),
            ('0x37ebb90','0x37ebda1')])

    def test_dispatch_and_constant(self):
        self.assertEqual(self.record['dispatch_table']['targets'], [
            '0x326aa67','0x326aa7a','0x326aa6d','0x326aa67','0x326ab08'])
        self.assertEqual(self.record['hash_constant'],
          'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')

    def test_old_value_branches_and_failure_branch(self):
        branches={x['site']:(x['condition'],x['target']) for x in self.record['branches']}
        self.assertEqual(branches['0x326a74f'],('equal','0x326a976'))
        self.assertEqual(branches['0x326ac2a'],('not_equal','0x326ae18'))
        self.assertEqual(branches['0x326aa85'],('unsigned_above','0x326ab92'))
        self.assertEqual(branches['0x326aa8e'],('equal','0x326ab08'))

    def test_dispatch_slots_resolve_to_both_writers(self):
        rel={r['slot']:r['addend'] for r in self.record['relocations']}
        calls={r['site']:r['target'] for r in self.record['calls']}
        self.assertEqual(rel[calls['0x326ab02']],'0x326a6f0')
        self.assertEqual(rel[calls['0x326ab73']],'0x326abd0')
        self.assertEqual(rel[calls['0x327199b']],'0x326a6f0')
        self.assertEqual(rel[calls['0x32719ac']],'0x326abd0')

    def test_wrong_digest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad'; p.write_bytes(b'ELF but not the target')
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                m.checked_data(p)

    def test_corrupt_instruction_rejected(self):
        # Override just the target window; avoids copying the full captured ELF.
        original=m.read_va
        def corrupt(data, va, size, sec=None):
            result=original(data,va,size,sec)
            return bytes([result[0]^1])+result[1:] if va == 0x326ac42 else result
        with patch.object(m,'read_va',side_effect=corrupt):
            with self.assertRaisesRegex(ValueError,'instruction mismatch'):
                m.check_pins(self.data,self.sections)

    def test_range_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            m.read_va(self.data,0xffffffffffffffff,8,self.sections)
        bss=next(s for s in self.sections if s['type']==8 and s['size'])
        with self.assertRaises(ValueError):
            m.read_va(self.data,bss['address'],1,[bss])

    def test_unknown_branch_and_call_rejected(self):
        with patch.object(m,'read_va',return_value=b'\x90'*6):
            with self.assertRaises(ValueError): m.decode_branch(self.data,0,self.sections)
            with self.assertRaises(ValueError): m.decode_call(self.data,0,self.sections)

    def test_corrupt_table_rejected(self):
        original=m.read_va
        def corrupt(data,va,size,sec=None):
            result=original(data,va,size,sec)
            return bytes([result[0]^1])+result[1:] if va == 0x581f44 else result
        with patch.object(m,'read_va',side_effect=corrupt):
            with self.assertRaisesRegex(ValueError,'dispatch table'):
                m.generate(self.data)

if __name__ == '__main__':
    unittest.main()
