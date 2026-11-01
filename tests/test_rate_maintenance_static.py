"""Real-target guarded maintenance collector controls, not live rate-limit tests."""
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
import rate_maintenance_static as packet
from rate_maintenance_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class RateMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_target_controls(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),3)

    def test_actual_guard_reset_and_call_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_source_global_and_callback_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_actual_source_path(self):
        changed=bytearray(self.data);offset,_=read_va(changed,0x20252a,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_guard_byte_branch_all256_encodings(self):
        body=read_va(self.data,0x4714c21,15)[1]
        self.assertEqual(body[:9],bytes.fromhex('440fb677204180fe01'))
        self.assertEqual(body[9:11],bytes.fromhex('0f85'))
        self.assertEqual(0x4714c2a+6+struct.unpack_from('<i',body,11)[0],0x4714f63)
        self.assertEqual(read_va(self.data,0x4714f63,3)[1],bytes.fromhex('4489f0'))
        # Local comparison partitions input bytes; it is not an admission enum.
        self.assertEqual([b for b in range(256)if b==body[8]],[1])

    def test_three_identical_integer_reset_formulas(self):
        bodies=[read_va(self.data,va,28)[1]for va in (0x4c8b914,0x4c8b970,0x4c8b9e4)]
        self.assertEqual(bodies[0],bodies[1]);self.assertEqual(bodies[1],bodies[2])
        self.assertEqual(bodies[0],bytes.fromhex('498d46014889c148c1e9034883e0f84829c84983fe08490f42c6eb02'))
        # An architectural integer-fragment model for these selected masks.
        # No table object is allocated and no whole hash-table ABI is claimed.
        maximum=(1<<64)-1
        def local_formula(mask):
            word=(mask+1)&maximum
            return mask if mask<8 else ((word&~7)-(word>>3))&maximum
        for mask,expected in [(0,0),(1,1),(3,3),(7,7),(15,14),(31,28),(63,56),(1023,896)]:
            self.assertEqual(local_formula(mask),expected)

SHIM='''#!/usr/bin/env python3
import os,shutil,sys
marker={marker!r}
if not os.path.exists(marker):
    open(marker,'w').write('swapped\\n')
    staging={target!r}+'.staging'
    shutil.copyfile({mutated!r},staging)
    os.replace(staging,{target!r})
os.execv({readelf!r},['readelf']+sys.argv[1:])
'''

@unittest.skipUnless(shutil.which('readelf') and shutil.which('objdump'),'GNU binutils required')
@unittest.skipUnless((ROOT/'artifacts/node/94/hl-node').stat().st_size==91774280,'materialize the pinned node94 capture')
class DecoderBindingTests(unittest.TestCase):
    def test_packet_stays_bound_to_admitted_bytes(self):
        # generate() verifies the target once (artifacts.check) and analyses
        # the bytes it read; the readelf/objdump evidence must come from
        # those same bytes. Replacing the file after admission - at the
        # first decoder call - must not change the emitted packet.
        data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory);target=tmp/'hl-node';target.write_bytes(data)
            baseline=tmp/'baseline';packet.generate(target,baseline)
            changed=bytearray(data)
            offset,_=read_va(data,74533904,1);changed[offset]^=0xff
            slot,addend=next(iter(RELATIVE.items()))
            pos=changed.find(struct.pack('<QQq',slot,8,addend));self.assertGreaterEqual(pos,0)
            struct.pack_into('<q',changed,pos+16,addend+8)
            mutated=tmp/'mutated.elf';mutated.write_bytes(changed)
            shim_dir=tmp/'shim';shim_dir.mkdir();shim=shim_dir/'readelf'
            shim.write_text(SHIM.format(marker=str(tmp/'swapped.marker'),target=str(target),
                                        mutated=str(mutated),readelf=shutil.which('readelf')))
            shim.chmod(0o755)
            target.write_bytes(data)
            saved=os.environ['PATH']
            os.environ['PATH']=str(shim_dir)+os.pathsep+saved
            try:
                swapped=tmp/'swapped';packet.generate(target,swapped)
            finally:
                os.environ['PATH']=saved
            self.assertEqual(target.read_bytes(),bytes(changed))
            names=sorted(p.name for p in baseline.iterdir())
            self.assertEqual(names,sorted(p.name for p in swapped.iterdir()))
            for name in names:
                self.assertEqual((baseline/name).read_bytes(),(swapped/name).read_bytes(),name)

if __name__=='__main__':unittest.main()
