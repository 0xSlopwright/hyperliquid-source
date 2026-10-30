"""Real node94 configuration/counter collector controls; no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from cguard_consistency_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class CGuardConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_instruction_data_and_global_bindings(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),7)

    def test_actual_branch_field_counter_and_unlock_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_source_location_and_global_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_actual_source_path_corruption(self):
        changed=bytearray(self.data);offset,_=read_va(changed,0x2019E9,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_four_scalar_field_offsets_and_shared_failure_target(self):
        for va,offset,width in [(0x1445830,0x4c,1),(0x1445839,0x4d,1),(0x1445842,0x48,4),(0x144584a,0x4e,1)]:
            with self.subTest(va=hex(va)):
                size=9 if width==1 else 8
                body=read_va(self.data,va,size)[1]
                expected=(b'\x0f\xb6\x47'+bytes([offset])+b'\x3a\x46'+bytes([offset]))if width==1 else (b'\x8b\x47'+bytes([offset])+b'\x3b\x46'+bytes([offset]))
                self.assertEqual(body[:-2],expected);self.assertEqual(body[-2],0x75)
                self.assertEqual(va+size+struct.unpack('b',body[-1:])[0],0x14458ab)

    def test_count_store_precedes_old_value_limit_check(self):
        body=read_va(self.data,0x143ab2b,28)[1]
        store=body.index(bytes.fromhex('49894558'))
        comparison=body.rfind(bytes.fromhex('4883f9'))
        self.assertLess(store,comparison)
        threshold=body[comparison+3];self.assertEqual(threshold,100)
        maximum=(1<<64)-1
        # Architectural local-route model only, not target execution or a
        # claim that every caller reaches this counter update.
        def local_route(old):
            if old==maximum:return old,'overflow'
            return old+1,('limit'if old>=threshold else'ok')
        for old,expected in [(0,(1,'ok')),(99,(100,'ok')),(100,(101,'limit')),(maximum-1,(maximum,'limit')),(maximum,(maximum,'overflow'))]:
            self.assertEqual(local_route(old),expected)

if __name__=='__main__':unittest.main()
