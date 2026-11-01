"""Three captured admission prefixes against independent mathematical conditions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import snapshot_admission as tool

class SnapshotAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data

    def test_packet_matches_real_owners(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))

    def test_every_residue_in_two_periods_and_three_copies(self):
        for case in tool.CASES:
            for height in range(20001):
                for tag in (0,1,2,0xffffffff):
                    self.assertEqual(tool.replay(self.image,case,tag,height,tool.MASK),tool.expected(tag,height,tool.MASK))

    def test_exact_and_past_freeze_override_periodic(self):
        heights=(0,1,9999,10000,10001,20000,1<<63,tool.MASK)
        for case in tool.CASES:
            for height in heights:
                for frozen in {0,height,max(0,height-1),min(tool.MASK,height+1),tool.MASK}:
                    self.assertEqual(tool.replay(self.image,case,1,height,frozen),tool.expected(1,height,frozen))
            self.assertEqual(tool.replay(self.image,case,1,10000,9999),'panic')
            self.assertEqual(tool.replay(self.image,case,1,10000,10000),'freeze')

    def test_unsigned_high_words_and_divisibility_boundaries(self):
        heights={0,tool.MASK,1<<63,(1<<63)-1,(1<<63)+1}
        for multiple in (10000,10000*((1<<63)//10000),10000*(tool.MASK//10000)):
            heights.update(n for n in (multiple-1,multiple,multiple+1) if 0<=n<=tool.MASK)
        for case in tool.CASES:
            for height in heights:
                for tag in (0,1,2):
                    self.assertEqual(tool.replay(self.image,case,tag,height,tool.MASK),tool.expected(tag,height,tool.MASK))

    def test_actual_rotation_and_branch_mutations_change_outcomes(self):
        for case in tool.CASES:
            # Unfrozen-arm ROR immediate: 4 -> 3. Largest u64 multiple no longer passes.
            mutated=self.changed(case['start']+0x6b,b'\x03')
            self.assertNotEqual(tool.replay(tool.Image(mutated),case,0,10000*(tool.MASK//10000),0),'periodic')
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(mutated)
            # Frozen-arm unsigned below -> above/equal: reverses the past-target path.
            mutated=self.changed(case['start']+0x2a,b'\x83')
            self.assertNotEqual(tool.replay(tool.Image(mutated),case,1,10000,9999),'panic')
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(mutated)

    def test_identity_label_bounds_and_decoder_fail_closed(self):
        for case in tool.CASES:
            changed=self.changed(case['label'],b'X')
            with self.assertRaisesRegex(ValueError,'label changed'):tool.observe(changed)
            changed=self.changed(case['start']+0x16,b'\xcc')
            with self.assertRaisesRegex(ValueError,'unsupported'):tool.replay(tool.Image(changed),case,0,0,0)
            with self.assertRaises(ValueError):tool.replay(self.image,case,1,-1,0)
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])

if __name__=='__main__':unittest.main()
