"""Target-byte controls for a bounded file-tracker initialization packet."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from file_tracker_init_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class FileTrackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_target_obligations(self):
        controls(self.data)
        self.assertEqual(len(relocations(self.data)),5)

    def test_actual_initializer_and_predicate_instructions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_diagnostic_and_source_bytes(self):
        for va in LITERALS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_actual_helper_and_source_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_regular_mode_mask_all_low16_values(self):
        body=read_va(self.data,0x144A769,18)[1]
        self.assertEqual(body[:1],b'\xb8')
        mask=struct.unpack_from('<I',body,1)[0]
        self.assertEqual(body[9],0x3d)
        expected=struct.unpack_from('<I',body,10)[0]
        # Independent interval predicate for all low16 encodings. Higher bits
        # are discarded by the observed 0xf000 mask; syscall semantics unknown.
        for mode in range(65536):
            self.assertEqual((mode&mask)==expected,0x8000<=mode<0x9000)

    def test_dev_null_length_and_bytes_in_actual_immediates(self):
        body=read_va(self.data,0x144F05D,40)[1]
        self.assertEqual(body[:4],bytes.fromhex('4883fa09'))
        self.assertEqual(body[8:16],b'/dev/nul')
        self.assertEqual(read_va(self.data,0x144F075,4)[1],bytes.fromhex('4883f16c'))

if __name__=='__main__':unittest.main()
