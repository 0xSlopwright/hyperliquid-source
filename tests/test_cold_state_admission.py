"""Target-bound 32-byte SIMD comparison and conditional admission controls."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cold_state_admission as tool

class StateAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data

    def test_real_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))

    def test_each_digest_byte_value(self):
        baseline=bytes(range(32))
        for pos in range(32):
            for value in range(256):
                other=baseline[:pos]+bytes([value])+baseline[pos+1:]
                self.assertEqual(tool.digest_matches(self.image,baseline,other),baseline==other)
                self.assertEqual(tool.digest_matches(self.image,other,baseline),baseline==other)
        for digest in (bytes(32),b'\xff'*32,baseline):
            self.assertTrue(tool.digest_matches(self.image,digest,digest))

    def test_simd_pair_order_and_branch_corruptions_change_answer(self):
        equal=bytes(range(32))
        different=equal[:16]+equal[:16]
        for va,raw,a,b in ((0x23ece0d+3,b'\xd9',different,equal),
                           (0x23ece22+1,b'\x84',equal,equal),
                           (0x23ece1d+1,b'\xff\x7f\x00\x00',equal,equal)):
            data=self.changed(va,raw)
            self.assertNotEqual(tool.digest_matches(tool.Image(data),a,b),a==b)
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)

    def test_bound_scalar_control_changes_are_rejected(self):
        for va,raw in ((0x23ece39,b'\x75'),(0x23ece42,b'\x0f\x85'),
                       (0x23eceba+2,b'\x41'),(0x23ecec9+1,b'\x84'),
                       (0x23ecfce,b'\x90'),(0x23ecd9c,b'\x00')):
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(self.changed(va,raw))
        with self.assertRaisesRegex(ValueError,'diagnostic'):tool.observe(self.changed(0x1fc232,b'X'))

    def test_conditional_route_summary(self):
        success=0x8000000000000040
        for word in (0,1,(1<<64)-1):
            self.assertIn('mismatch',tool.selected_route(False,word,word,success))
            self.assertEqual(tool.selected_route(True,0,word,success),'return fetched prefix')
        self.assertEqual(tool.selected_route(True,1,0,success),'pre-helper assertion')
        self.assertEqual(tool.selected_route(True,1,1,success),'return fetched prefix')
        for tag in (0,1,success-1,success+1,(1<<64)-1):
            self.assertEqual(tool.selected_route(True,0,0,tag),'post-helper unwrap trap')

    def test_identity_and_decoder_domain_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
        with self.assertRaisesRegex(ValueError,'synthetic digests'):tool.digest_matches(self.image,b'',bytes(32))
        data=self.changed(0x23ece0d,b'\xcc')
        with self.assertRaisesRegex(ValueError,'unsupported'):tool.digest_matches(tool.Image(data),bytes(32),bytes(32))

        # Retarget each resolved but semantically unclosed helper independently.
        import struct
        _,off,size=self.image.section('.rela.dyn')
        for slot in tool.observe(self.data)['resolved_unclosed_slots']:
            rows=[pos for pos in range(off,off+size,24) if struct.unpack_from('<Q',self.data,pos)[0]==int(slot,16)]
            self.assertEqual(len(rows),1)
            changed=bytearray(self.data);changed[rows[0]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):tool.observe(changed)
if __name__=='__main__':unittest.main()
