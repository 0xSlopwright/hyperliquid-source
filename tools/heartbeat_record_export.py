"""RE-001: selected heartbeat export record stores, static synthetic RAM only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records
PACKET=ROOT/'research/work-items/RE-001-heartbeat-record-export-94'
CASES=[(0x488c410,0x488c7d6,'f227940ed7ceba72b20161c627b8b183232a5d35d54f47b863c82d546821207b')]
MASK=(1<<64)-1

def require(ok,message):
    if not ok:raise ValueError(message)

def pack_selected(image,key,word0,word1,helper_word,initial):
    """Replay only observed record store operands on bounded synthetic RAM.

    Preceding traversal/loads specialize key, two entry words, and opaque helper
    bits. This does not execute the B-tree walk, clock/duration helper or allocator.
    """
    require(len(key)==20 and len(initial)==48 and all(len(v)==8 for v in (word0,word1,helper_word)),'record specialization requires key20, three words8, RAM48')
    out=bytearray(initial)
    def write(offset,value):
        require(0<=offset and offset+len(value)<=48,'store escaped synthetic record');out[offset:offset+len(value)]=value
    raw=image.read(0x488c705,4)
    require(raw[:3]==b'\x89\x74\x07','unsupported key-tail store');write(raw[3],key[16:])
    require(image.read(0x488c709,8)==bytes.fromhex('0f10948d80040000'),'key vector load changed')
    require(image.read(0x488c711,4)==bytes.fromhex('0f111407'),'key vector store changed');write(0,key[:16])
    for va,value,prefix in ((0x488c715,word0,b'\x48\x89\x54\x07'),
                             (0x488c71a,word1,b'\xf2\x0f\x11\x4c\x07'),
                             (0x488c720,helper_word,b'\xf2\x0f\x11\x44\x07')):
        raw=image.read(va,len(prefix)+1);require(raw[:-1]==prefix,'unsupported record-word store');write(raw[-1],value)
    return bytes(out)

def expected_pack(key,word0,word1,helper_word,initial):
    return key+initial[20:24]+word0+word1+helper_word

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'heartbeat FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'heartbeat owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    controls={0x488c41e:'4c8b76404c89f048c1e0044c8d3c40',
      0x488c42d:'48b8aaaaaaaaaaaaaa024939c6760b',
      0x488c481:'b8080000004889042448c744240800000000',
      0x488c67d:'496bdc68',0x488c695:'8b441d6889442448488b441d604889442440',
      0x488c6a7:'48b8010000009a0000004889442450488d054613e7fb488944245848c744246044000000',
      0x488c6d5:'ff15e521ee00',
      0x488c6de:'488d042b4883c0084b8d0ca4488b10f20f1048084b8d047648c1e004',
      0x488c6fa:'8bb48d90040000488b3c24897407100f10948d800400000f1114074889540718f20f114c0720f20f11440728',
      0x488c726:'49ffc6b101b8000000004d85ed4c8b6424100f8592fdffff',
      0x488c752:'488b4c2420488b442408488901488b042448894108488b44241848894110'}
    for va,raw in controls.items():
        expected=bytes.fromhex(raw);require(image.read(va,len(expected))==expected,f'heartbeat control changed at {va:#x}')
    source=b'/home/ubuntu/hl/code_Mainnet/node/src/consensus/heartbeat_tracker.rs'
    require(image.read(0x6fda03,0x44)==source,'heartbeat source anchor changed')
    slots={91678912: 21262640, 91676632: 88868528, 91676600: 20209768}
    actual=image.relative_relocs()
    require(all(actual.get(slot)==target for slot,target in slots.items()),'unclosed helper relocation changed')
    return dict(target_sha256=SHA256,owners=owners,resolved_unclosed_slots={hex(k):hex(v) for k,v in slots.items()},controls={hex(k):v for k,v in controls.items()},
      source_anchor=dict(address='0x6fda03',length=0x44,path=source.decode(),raw_header='0x9a00000001',meaning='byte-bound path/stack-header anchor, no recovered ABI type'),
      record_stride=48,written_ranges=[[0,20],[24,48]],unwritten_range=[20,24],
      observations=['count at self+0x40; direct allocation path at most 0x2aaaaaaaaaaaaaa, otherwise size-error call first; wrapping span count*48',
        'selected entry stride 0x68, key stride 20; entry+8 and +16 stored as raw qword and movsd bits',
        'opaque helper result XMM0 stored at output+40',
        'record stores leave bytes +20..+23 unwritten; no zero/canonical wire-format claim'],
      limits='Only selected record stores replayed. Iterator validity/order, helper duration semantics, allocation contents, key identity, ownership, callers and serialization unclosed.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
