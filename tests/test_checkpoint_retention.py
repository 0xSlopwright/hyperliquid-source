"""Captured unsigned retention gates and boundary/corruption controls."""
import itertools
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import checkpoint_retention as tool

class RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)
    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data
    def test_real_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))
    def test_all_small_and_unsigned_edge_bound_combinations(self):
        values=(0,1,2,3,4,(1<<63)-1,1<<63,tool.MASK)
        for args in itertools.product(values,repeat=4):
            self.assertEqual(tool.replay_unmarked(self.image,*args),tool.expected(*args))
    def test_interval_and_cap_each_have_different_endpoint_rules(self):
        for height in range(12):
            result=tool.replay_unmarked(self.image,height,3,9,7)
            self.assertEqual(result,dict(keep=3<=height<=7,diagnostic=height<3))
        self.assertFalse(tool.replay_unmarked(self.image,3,3,3,9)['keep'])
        self.assertFalse(tool.replay_unmarked(self.image,3,8,2,9)['keep'])
    def test_actual_upper_branch_and_cap_slot_mutations_change_answer(self):
        for va,raw,args in ((0x3308650,b'\x72',(9,3,9,20)),
                            (0x330865c+4,b'\x48',(5,0,10,4))):
            data=self.changed(va,raw)
            self.assertNotEqual(tool.replay_unmarked(tool.Image(data),*args),tool.expected(*args))
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_marker_copy_loop_and_identity_corruptions(self):
        for va,raw in ((0x33085ab,b'\x75'),(0x3308501+3,b'\x21'),(0x330852e+3,b'\x21'),
                       (0x3308664+1,b'\x82')):
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(self.changed(va,raw))
        with self.assertRaisesRegex(ValueError,'marker'):tool.observe(self.changed(0x1fe44c,b'X'))
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
    def test_raw_domain_and_decoder_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'raw u64'):tool.replay_unmarked(self.image,-1,0,0,0)
        data=self.changed(0x33085f2,b'\xcc')
        with self.assertRaisesRegex(ValueError,'unsupported'):tool.replay_unmarked(tool.Image(data),0,0,0,0)
        # Retarget each resolved but semantically unclosed helper independently.
        import struct
        _,off,size=self.image.section('.rela.dyn')
        for slot in tool.observe(self.data)['resolved_unclosed_slots']:
            rows=[pos for pos in range(off,off+size,24) if struct.unpack_from('<Q',self.data,pos)[0]==int(slot,16)]
            self.assertEqual(len(rows),1)
            changed=bytearray(self.data);changed[rows[0]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):tool.observe(changed)
if __name__=='__main__':unittest.main()
