"""Target-byte controls for a bounded file-tracker initialization packet."""
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
import file_tracker_init_static as packet
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
            offset,_=read_va(data,20760960,1);changed[offset]^=0xff
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
