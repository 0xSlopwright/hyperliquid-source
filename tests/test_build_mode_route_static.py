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
import build_mode_route_static as packet
from build_mode_route_static import CONTROLS,LITERALS,RELATIVE,controls,read_va,relocations

class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']if i['path']=='artifacts/node/94/hl-node')
        check(target,identity);cls.data=target.read_bytes()

    def test_actual_control_baseline(self):
        controls(self.data);self.assertEqual(len(relocations(self.data)),len(RELATIVE))

    def test_actual_instruction_corruptions(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'instruction changed'):controls(changed)

    def test_actual_literal_corruptions(self):
        for va in LITERALS:
            with self.subTest(va=hex(va)):
                changed=bytearray(self.data);offset,_=read_va(changed,va,1);changed[offset]^=1
                with self.assertRaisesRegex(ValueError,'literal changed'):controls(changed)

    def test_actual_relocation_retargets(self):
        for slot,target in RELATIVE.items():
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data);offset=changed.find(struct.pack('<QQq',slot,8,target))
                self.assertGreaterEqual(offset,0);changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError,'relocation changed'):relocations(changed)

    def test_exact_client_literal_and_length_guard(self):
        self.assertEqual(read_va(self.data,0x13cd42f,6)[1],bytes.fromhex('4883fa0a7521'))
        literal=read_va(self.data,0x13cd437,8)[1]+read_va(self.data,0x13cd449,2)[1]
        self.assertEqual(literal,b'run-client')
        for text in (b'run-client',b'run-clients',b'Run-client',b'run-clien',b'xun-client'):
            selected=len(text)==10 and text[:8]==literal[:8] and text[8:]==literal[8:]
            self.assertEqual(selected,text==b'run-client')

    def test_mode_routes_and_result_tag_writes(self):
        self.assertEqual(read_va(self.data,0x13cd428,7)[1],bytes.fromhex('4489c008c8744f'))
        body=read_va(self.data,0x13cd45f,17)[1]
        self.assertEqual(body[:5],bytes.fromhex('80f901742e'))
        self.assertEqual(body[5:11],bytes.fromhex('0fb6c183f802'))
        self.assertEqual(0x13cd46a+6+struct.unpack_from('<i',body,13)[0],0x13cd636)
        self.assertEqual(read_va(self.data,0x2194d5,12)[1],b'debugrelease')
        self.assertEqual(read_va(self.data,0x13cd54d,4)[1],bytes.fromhex('c6431801'))
        self.assertEqual(read_va(self.data,0x13cd5f2,4)[1],bytes.fromhex('c6431800'))
        # Raw predicate, not a reconstruction of a complete Rust enum/API.
        self.assertEqual([mode for mode in range(256)if mode==body[2] or mode==body[10]],[1,2])

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
            offset,_=read_va(data,20763670,1);changed[offset]^=0xff
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
            for name in ('records.json','frames.txt','relocations.txt','name-route.objdump.txt'):
                self.assertEqual((baseline/name).read_bytes(),(swapped/name).read_bytes(),name)

if __name__=='__main__':unittest.main()
