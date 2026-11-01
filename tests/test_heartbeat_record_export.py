"""Actual store operands, opaque floating bits and preserved padding controls."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import heartbeat_record_export as tool

class HeartbeatExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)
    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data
    def test_real_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))
    def test_each_key_byte_and_opaque_word_bits(self):
        words=(bytes(8),b'\xff'*8,struct.pack('<Q',0x7ff8000000000001),struct.pack('<Q',1<<63))
        baseline=bytes(range(20));initial=b'\xa5'*48
        for pos in range(20):
            for value in range(256):
                key=baseline[:pos]+bytes([value])+baseline[pos+1:]
                for index,word in enumerate(words):
                    args=(key,word,words[(index+1)%4],words[(index+2)%4],initial)
                    self.assertEqual(tool.pack_selected(self.image,*args),tool.expected_pack(*args))
    def test_four_padding_bytes_are_preserved_not_normalized(self):
        for byte in (0,1,0x55,0xa5,255):
            initial=bytes([byte])*48
            out=tool.pack_selected(self.image,bytes(20),bytes(8),bytes(8),bytes(8),initial)
            self.assertEqual(out[20:24],bytes([byte])*4)
            self.assertEqual(out[:20]+out[24:],bytes(44))
    def test_actual_destination_offset_changes_record(self):
        data=self.changed(0x488c715+4,b'\x14')
        args=(bytes(range(20)),b'\xff'*8,bytes(8),bytes(8),b'\xa5'*48)
        self.assertNotEqual(tool.pack_selected(tool.Image(data),*args),tool.expected_pack(*args))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_count_stride_key_source_helper_and_loop_corruptions(self):
        for va,raw in ((0x488c437+2,b'\xc7'),(0x488c429+3,b'\x48'),
                       (0x488c67d+3,b'\x60'),(0x488c709+4,b'\x90'),
                       (0x488c6d5+2,b'\xe4'),(0x488c726+2,b'\xc7')):
            with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(self.changed(va,raw))
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
        with self.assertRaisesRegex(ValueError,'source anchor'):tool.observe(self.changed(0x6fda03,b'X'))
    def test_decoder_and_ram_bounds_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'requires'):tool.pack_selected(self.image,bytes(19),bytes(8),bytes(8),bytes(8),bytes(48))
        data=self.changed(0x488c715+4,b'\xff')
        with self.assertRaisesRegex(ValueError,'escaped'):tool.pack_selected(tool.Image(data),bytes(20),bytes(8),bytes(8),bytes(8),bytes(48))
        # Retarget each resolved but semantically unclosed helper independently.
        import struct
        _,off,size=self.image.section('.rela.dyn')
        for slot in tool.observe(self.data)['resolved_unclosed_slots']:
            rows=[pos for pos in range(off,off+size,24) if struct.unpack_from('<Q',self.data,pos)[0]==int(slot,16)]
            self.assertEqual(len(rows),1)
            changed=bytearray(self.data);changed[rows[0]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):tool.observe(changed)
if __name__=='__main__':unittest.main()
