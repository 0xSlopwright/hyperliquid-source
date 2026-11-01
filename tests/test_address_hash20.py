"""Captured arithmetic versus independent math; only public synthetic fixtures."""
import json
import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import address_hash20 as tool

class AddressHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.img=tool.Image(cls.data)
        cls.record=tool.build(cls.data)

    def changed(self,va,raw):
        data=bytearray(self.data);off=self.img.off(va,len(raw));data[off:off+len(raw)]=raw
        return data

    def test_packet_and_specialized_writer_domain(self):
        self.assertEqual(json.loads((tool.PACKET/'records.json').read_bytes()),self.record)
        self.assertEqual(self.record['specialized_write'],{'fresh_tail':0,'full_words':2,'tail_bytes':4})
        self.assertEqual(tool.target_hash(self.img,(0,0),bytes(range(20))),0x639e355ae68c0100)

    def test_actual_arithmetic_all_message_byte_classes_with_synthetic_seeds(self):
        seeds=((0,0),(tool.MASK,tool.MASK),(0x0706050403020100,0x0f0e0d0c0b0a0908),(1<<63,1))
        original=bytes(range(20))
        for seed in seeds:
            for pos in range(20):
                for value in range(256):
                    message=original[:pos]+bytes([value])+original[pos+1:]
                    self.assertEqual(tool.target_hash(self.img,seed,message),tool.reference_hash(seed,message))

    def test_zero_ff_and_tail_boundary_words(self):
        for message in (b'\0'*20,b'\xff'*20,bytes(range(20)),b'\0'*16+b'\xff'*4,b'\xff'*16+b'\0'*4):
            self.assertEqual(tool.target_hash(self.img,(0,1),message),tool.reference_hash((0,1),message))
        with self.assertRaises(ValueError):tool.target_hash(self.img,(0,0),b'x'*19)

    def test_real_compression_and_final_rotations_change_hash(self):
        message=bytes(range(20));expected=tool.reference_hash((0,0),message)
        for va in (0x288e3aa+3,0x2841067+3):
            changed=self.changed(va,b'\x0c')
            self.assertNotEqual(tool.target_hash(tool.Image(changed),(0,0),message),expected)
            with self.assertRaisesRegex(ValueError,'body changed'):tool.observe(changed)

    def test_real_constants_initialization_length_loop_and_tail(self):
        for va in (0x204ec0,0x203e70,0x2840fb8+4,0x2840fe7+5,0x2840ff9+1,
                   0x2841008+3,0x284105a+3,0x288e28c,0x288e37f+3,0x288e3da+3,0x288e3f8+3,0x288e44d+3):
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):
                tool.observe(self.changed(va,bytes([self.img.read(va,1)[0]^1])))

    def test_arithmetic_fail_closed_and_fde_identity(self):
        with self.assertRaises(ValueError):tool.arithmetic(b'\x48\x90\xc0',[None]*16,{})
        for owner in self.record['owners']:
            fde=int(owner['fde'],16);size=int(owner['end_exclusive'],16)-int(owner['start'],16)
            with self.assertRaisesRegex(ValueError,'FDE'):
                tool.observe(self.changed(fde+12,struct.pack('<i',size-1)))
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            tool.build(self.changed(tool.CASES[0][0],b'\x90'))
if __name__=='__main__':unittest.main()
