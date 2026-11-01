"""Raw signed/unsigned metadata comparison and original control corruptions."""
import itertools
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import gossip_reload_gates as tool

class GossipReloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)
    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data
    def test_real_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))
    def test_signed_first_unsigned_remainder_all_boundary_pairs(self):
        edges=(0,1,0x7fffffff,0x80000000,0xffffffff)
        values=list(itertools.product(edges,repeat=3))
        for new,old in itertools.product(values,repeat=2):
            self.assertEqual(tool.replay_newer(self.image,new,old),tool.expected_newer(new,old))
    def test_actual_signedness_and_equality_mutations_change_answers(self):
        for va,raw,new,old in ((0x4741328,b'\x97',(0x80000000,0,0),(0,0,0)),
                               (0x4741334,b'\x9f',(0,0x80000000,0),(0,0,0)),
                               (0x474133f,b'\x73',(0,0,0),(0,0,0))):
            data=self.changed(va,raw)
            self.assertNotEqual(tool.replay_newer(tool.Image(data),new,old),tool.expected_newer(new,old))
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_throttle_conditional_ieee_classes(self):
        for result in (-float('inf'),-1.,-0.,0.,1.,float('inf'),float('nan')):
            self.assertEqual(tool.replay_throttle(self.image,0,result,float('nan')),'refresh then file predicate')
            expected='refresh then file predicate' if result>0 else 'release without refresh'
            self.assertEqual(tool.replay_throttle(self.image,1,result,0.),expected)
        self.assertEqual(tool.replay_throttle(self.image,1,1.,float('nan')),'release without refresh')
        changed=self.changed(0x47412c6,b'\x87')
        self.assertNotEqual(tool.replay_throttle(tool.Image(changed),1,0.,0.),tool.replay_throttle(self.image,1,0.,0.))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(changed)
    def test_refresh_parse_and_cached_store_controls(self):
        for va,raw in ((0x47412c6,b'\x87'),(0x47412d3,b'\x90'),(0x474136a,b'\x03'),
                       (0x47414e6,b'\x90'),(0x4741513,b'\x90'),(0x4741530,b'\x90')):
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(self.changed(va,raw))
    def test_input_identity_and_decoder_domain(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
        with self.assertRaisesRegex(ValueError,'raw dword'):tool.replay_newer(self.image,(-1,0,0),(0,0,0))
        with self.assertRaisesRegex(ValueError,'unsupported'):tool.replay_newer(tool.Image(self.changed(0x4741320,b'\xcc')),(0,0,0),(0,0,0))
        # Retarget each resolved but semantically unclosed helper independently.
        import struct
        _,off,size=self.image.section('.rela.dyn')
        for slot in tool.observe(self.data)['resolved_unclosed_slots']:
            rows=[pos for pos in range(off,off+size,24) if struct.unpack_from('<Q',self.data,pos)[0]==int(slot,16)]
            self.assertEqual(len(rows),1)
            changed=bytearray(self.data);changed[rows[0]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):tool.observe(changed)
if __name__=='__main__':unittest.main()
