"""Target-grounded guard controls; synthetic text is only a local branch model."""
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from artifacts import ROOT,check
from gnu_binutils import requires_gnu
import truncated_debug_static as packet
from truncated_debug_static import PROFILES,SLOTS,PATH_VA,read_va,source_bindings,profile,census,rejects_boundary_byte

@requires_gnu('readelf')
class TruncatedDebugTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target=ROOT/'artifacts/node/94/hl-node'
        identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
        check(target,identity)
        cls.data=target.read_bytes()
        frames=subprocess.check_output(['readelf','-wf',str(target)],text=True)
        cls.fdes=[(int(a,16),int(b,16)) for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
        cls.rows=census(cls.data,cls.fdes)

    def test_actual_family_and_source_bindings(self):
        self.assertEqual(len(source_bindings(self.data)),5)
        self.assertEqual(sum(r['bytes'] for r in self.rows),17952)
        self.assertEqual({k:sum(r['guard_profile']==k for r in self.rows) for k in PROFILES},{'bf-jle':27,'c0-jl':39})

    def test_actual_guard_and_prefix_corruptions(self):
        for kind in PROFILES:
            row=next(r for r in self.rows if r['guard_profile']==kind)
            body=bytes.fromhex(row['body_hex'])
            for offset in (0x3a,0x3e,0x4a,0x4c,0x5c,0xe0,0xec):
                with self.subTest(kind=kind,offset=offset):
                    changed=bytearray(body);changed[offset]^=1
                    with self.assertRaises(ValueError):profile(changed)

    def test_actual_source_retargets_and_path(self):
        for slot in SLOTS:
            changed=bytearray(self.data)
            offset=changed.find(struct.pack('<QQq',slot,8,PATH_VA))
            self.assertGreaterEqual(offset,0);changed[offset+16]^=1
            with self.assertRaisesRegex(ValueError,'relocation changed'):source_bindings(changed)
        changed=bytearray(self.data);offset,_=read_va(changed,PATH_VA,1);changed[offset]^=1
        with self.assertRaisesRegex(ValueError,'path changed'):source_bindings(changed)

    def test_both_decoded_signed_predicates_all256_bytes(self):
        for kind,body in PROFILES.items():
            # Decode actual immediate and signed Jcc, independent of the helper.
            immediate=body[20];immediate=immediate if immediate<128 else immediate-256
            jcc=body[22]
            self.assertIn(jcc,(0x8c,0x8e))
            rejected=[]
            for value in range(256):
                signed=value if value<128 else value-256
                actual=signed<immediate if jcc==0x8c else signed<=immediate
                self.assertEqual(actual,rejects_boundary_byte(value,kind))
                if actual:rejected.append(value)
            self.assertEqual(rejected,list(range(0x80,0xc0)))

    def test_length_and_fixed_cutpoint_branch_destinations(self):
        for row in self.rows:
            body=bytes.fromhex(row['body_hex'])
            cutoff=struct.unpack_from('<I',body,0x3a)[0]
            self.assertEqual(cutoff,10000)
            self.assertEqual(0x40+body[0x3f],0x8e)
            self.assertEqual(0x52+struct.unpack_from('<i',body,0x4e)[0],0xd8)
            self.assertEqual([length for length in (9999,10000,10001) if length>cutoff],[10001])

    def test_valid_utf8_boundary_examples_and_local_limit(self):
        for character in ('é','€','😀'):
            for offset in range(len(character.encode())):
                data=('a'*(10000-offset)+character+'z').encode()
                try:data[:10000].decode('utf-8');valid=True
                except UnicodeDecodeError:valid=False
                self.assertEqual(not rejects_boundary_byte(data[10000],'bf-jle'),valid)
        # This local guard is not a complete validator: invalid leader bytes pass.
        self.assertFalse(rejects_boundary_byte(0xc0,'bf-jle'))
        self.assertFalse(rejects_boundary_byte(0xff,'c0-jl'))

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

@requires_gnu('readelf', 'objdump')
@unittest.skipUnless((ROOT/'artifacts/node/94/hl-node').stat().st_size==91774280,'materialize the pinned node94 capture')
class DecoderBindingTests(unittest.TestCase):
    def test_packet_stays_bound_to_admitted_bytes(self):
        # generate() verifies the target once (artifacts.check) and analyses
        # the bytes it read; the readelf/objdump evidence must come from
        # those same bytes. Replacing the file after admission - at the
        # first decoder call - must not change the emitted packet. The
        # packet resolves its decoders through gnu_tool(), whose --version
        # probe is the first post-admission invocation the shim sees.
        data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory);target=tmp/'hl-node';target.write_bytes(data)
            baseline=tmp/'baseline';packet.generate(target,baseline)
            changed=bytearray(data)
            # First census family body +0x100, past the source LEA site
            # (+0xd8) that generate() re-checks in the disassembly.
            offset,_=read_va(data,0x1445d70,1);changed[offset]^=0xff
            slot,addend=SLOTS[0],PATH_VA
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
