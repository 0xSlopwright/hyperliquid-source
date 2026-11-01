"""RE-001: bounded gossip configuration reload gates; no filesystem access."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-gossip-reload-gates-94'
CASES=[(0x4741210,0x4741694,'33eff4f0458c535e2cdd4cf397957e21c0a64d9165182c50b5e5cb807dffb29b')]

def require(ok,message):
    if not ok:raise ValueError(message)

def signed(x):return x-(1<<32) if x>>31 else x

def replay_newer(image,new,old):
    """Interpret actual CMP/SETcc/TEST/Jcc instructions over raw dword triples."""
    require(len(new)==len(old)==3 and all(type(v) is int and 0<=v<1<<32 for v in (*new,*old)),'raw dword triple required')
    pc=0x4741320;cf=zf=sg=al=None
    for _ in range(20):
        if pc==0x474134e:return True
        if pc==0x4741528:return False
        require(0x4741320<=pc<0x474134e,'newer gate escaped selected range')
        raw=image.read(pc,7)
        if raw[:3] in (b'\x41\x3b\xae',b'\x45\x3b\xbe',b'\x45\x3b\xa6'):
            offset=struct.unpack_from('<I',raw,3)[0];index=(offset-0x90)//4
            require(offset in (0x90,0x94,0x98),'unexpected cached field')
            a,b=new[index],old[index];cf=a<b;zf=a==b;sg=signed(a)>signed(b);pc+=7
        elif raw[:3] in (b'\x0f\x9f\xc0',b'\x0f\x97\xc0'):
            require(cf is not None,'unset flags');al=sg if raw[1]==0x9f else not cf and not zf;pc+=3
        elif raw[:2]==b'\x84\xc0':
            require(al is not None,'unset al');zf=not al;cf=False;pc+=2
        elif raw[0] in (0x73,0x75,0x77) or raw[:2]==b'\x0f\x84':
            require(cf is not None and zf is not None,'unset flags')
            wide=raw[0]==0x0f;size=6 if wide else 2
            condition=zf if wide else {0x73:not cf,0x75:not zf,0x77:not cf and not zf}[raw[0]]
            delta=int.from_bytes(raw[2:6] if wide else raw[1:2],'little',signed=True)
            pc+=size+(delta if condition else 0)
        elif raw[0]==0xe9:pc+=5+struct.unpack_from('<i',raw,1)[0]
        else:raise ValueError('unsupported newer-gate instruction')
    raise ValueError('newer gate instruction budget exhausted')

def expected_newer(new,old):return (signed(new[0]),*new[1:])>(signed(old[0]),*old[1:])

def replay_throttle(image,previous_word,xmm0,threshold):
    """Actual TEST/JE and UCOMISD/Jcc, specializing opaque helper normal return."""
    require(type(previous_word) is int and 0<=previous_word<1<<32,'raw previous dword required')
    first=image.read(0x4741253,4)
    require(first[:2]==b'\x85\xc0' and first[2] in (0x74,0x75),'unsupported previous-word gate')
    target=0x4741257+int.from_bytes(first[3:4],'little',signed=True)
    require(target==0x47412cb,'previous-word target changed')
    take=(previous_word==0) if first[2]==0x74 else (previous_word!=0)
    if take:return 'refresh then file predicate'
    raw=image.read(0x47412bf,12)
    require(raw[:6]==bytes.fromhex('660f2e442408'),'unsupported float comparison')
    require(raw[6:8] in (b'\x0f\x86',b'\x0f\x87'),'unsupported float branch')
    require(0x47412cb+struct.unpack_from('<i',raw,8)[0]==0x4741528,'float skip target changed')
    unordered=math.isnan(xmm0) or math.isnan(threshold)
    cf=unordered or xmm0<threshold;zf=unordered or xmm0==threshold
    take=(cf or zf) if raw[7]==0x86 else (not cf and not zf)
    return 'release without refresh' if take else 'refresh then file predicate'

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'reload FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'reload owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    controls={0x474124f:'418b467885c07474',0x47412bf:'660f2e4424080f865d020000',
      0x47412cb:'498d46788b4c2420894808488b4c2418488908',
      0x47412e6:'ff15fcd6020184c00f8434020000',0x4741301:'ff15e9d60201837c2438010f8456020000',
      0x4741320:'413bae900000000f9fc0751a453bbe940000000f97c0750e453ba698000000770de9e201000084c00f84da010000',
      0x474135e:'e8dd00feff83bc2480000000020f858e000000',
      0x47413f3:'4d89a688000000e929010000',
      0x47414d0:'410f115d30410f115520410f114d1066410f114500',
      0x47414e5:'4189ae900000008b442408418986940000008b44243441898698000000',
      0x4741513:'49c7868800000000000000',0x4741528:'31c9b808000000f0480fb10b7525'}
    for va,raw in controls.items():
        expected=bytes.fromhex(raw);require(image.read(va,len(expected))==expected,f'reload control changed at {va:#x}')
    slots={91678912: 21262640, 91679208: 21276432, 91679216: 21285168, 91679096: 21221392}
    actual=image.relative_relocs()
    require(all(actual.get(slot)==target for slot,target in slots.items()),'unclosed helper relocation changed')
    return dict(target_sha256=SHA256,owners=owners,resolved_unclosed_slots={hex(k):hex(v) for k,v in slots.items()},controls={hex(k):v for k,v in controls.items()},
      observations=['throttle previous first dword zero bypasses float comparison; otherwise UCOMISD/JBE gates refresh',
        'last-check raw time stored before file predicate and metadata helper',
        'new metadata triple uses signed first dword and unsigned second/third, strict lexicographic greater',
        'parse raw tag 2 logs/stores error carrier without updating cached triple',
        'other parse tags reach payload replacement before cached triple stores and error-carrier clearing'],
      limits='Selected throttle branches and raw triple gate interpreted; ordering is a byte-bound summary. Helper timing, filesystem metadata meaning, parse grammar, allocation and concurrent behavior unclosed.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
