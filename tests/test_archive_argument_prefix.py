"""Captured constructor and row-load controls over synthetic pointer tuples."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import archive_argument_prefix as tool

class ArchivePrefixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=(tool.ROOT/tool.BINARY).read_bytes();cls.image=tool.Image(cls.data)
    def changed(self,va,raw):
        data=bytearray(self.data);off=self.image.off(va,len(raw));data[off:off+len(raw)]=raw;return data
    def test_packet(self):
        self.assertEqual(tool.build(self.data),json.loads((tool.PACKET/'records.json').read_bytes()))
    def test_actual_builder_fixed_order_and_dynamic_pairs(self):
        for count in (0,1,2,3,15,16,31,128,1024):
            for length in (0,1,15,16,255,65535):
                exclude=(0x300000,length);a=(0x400000,length+1);b=(0x500000,length+2)
                result=tool.replay_prefix(self.image,count,exclude,a,b)
                self.assertEqual(result['header'],(1,0,6))
                self.assertEqual(result['prefix'],[(0x59c095,3),exclude,(0x59c098,2),a,(0x59c09a,3),b])
                self.assertEqual(result['row_span'],(0x200000,0x200000+24*count))
    def test_rows_project_second_and_third_words(self):
        for count in range(65):
            values=[(0xabc000+i,0x300000+31*i,17*i) for i in range(count)]
            owned=b''.join(struct.pack('<QQQ',*row) for row in values)
            expected=b''.join(struct.pack('<QQ',row[1],row[2]) for row in values)
            self.assertEqual(tool.project_selected(self.image,owned),expected)
    def test_actual_length_and_projection_offset_change_results(self):
        pairs=((0x300000,27),(0x400000,11),(0x500000,17))
        data=self.changed(0x37e3183+8,b'\x02')
        self.assertNotEqual(tool.replay_prefix(tool.Image(data),1,*pairs),tool.replay_prefix(self.image,1,*pairs))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
        data=self.changed(0x3bae188+5,b'\x00')
        row=struct.pack('<QQQ',7,123,456)
        self.assertNotEqual(tool.project_selected(tool.Image(data),row),tool.project_selected(self.image,row))
        with self.assertRaisesRegex(ValueError,'owner changed'):tool.observe(data)
    def test_literal_relocation_and_identity_corruptions(self):
        for va in (0x59c095,0x59c089,0x1fe85b):
            with self.assertRaises(ValueError):tool.observe(self.changed(va,b'X'))
        _,off,size=self.image.section('.rela.dyn')
        for slot in tool.observe(self.data)['resolved_unclosed_slots']:
            rows=[p for p in range(off,off+size,24) if struct.unpack_from('<Q',self.data,p)[0]==int(slot,16)]
            self.assertEqual(len(rows),1);data=bytearray(self.data);data[rows[0]+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation'):tool.observe(data)
        with self.assertRaisesRegex(ValueError,'SHA-256'):tool.build(self.data[:-1])
    def test_domain_and_decoder_fail_closed(self):
        with self.assertRaises(ValueError):tool.replay_prefix(self.image,1025,(1,1),(2,2),(3,3))
        with self.assertRaises(ValueError):tool.project_selected(self.image,bytes(23))
        data=self.changed(0x37e30e2,b'\xcc')
        with self.assertRaisesRegex(ValueError,'unsupported'):tool.replay_prefix(tool.Image(data),0,(1,1),(2,2),(3,3))
if __name__=='__main__':unittest.main()
