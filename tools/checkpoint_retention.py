"""RE-001: checkpoint retention predicate, static synthetic bounds only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records
PACKET=ROOT/'research/work-items/RE-001-checkpoint-retention-94'
CASES=[(0x33084a0,0x33086f3,'77aa93933a93ddabe2993c106e2ffcd31ca117c65747212c450554799f4b1e45')]
MASK=(1<<64)-1

def require(ok,message):
    if not ok:raise ValueError(message)

def replay_unmarked(image,height,lower,upper,cap):
    """Actual unsigned CMP/Jcc window, conditional on diagnostic returning.

    The logging block is opaque: taking its entry records a requested diagnostic
    and resumes at its observed successor. No formatter/logger/filesystem runs.
    """
    require(all(type(x) is int and 0<=x<=MASK for x in (height,lower,upper,cap)),'raw u64 bounds required')
    pc=0x33085f2;bound=lower;cf=zf=None;diagnostic=False
    stack={0x10:lower,0x48:upper,0x40:cap}
    for _ in range(20):
        if pc==0x33084f0:return dict(keep=True,diagnostic=diagnostic)
        if pc==0x3308670:return dict(keep=False,diagnostic=diagnostic)
        if pc==0x33085f7:diagnostic=True;pc=0x3308648;continue
        require(0x33085f2<=pc<=0x33085f5 or 0x3308648<=pc<=0x330866a,'retention branch escaped selected range')
        raw=image.read(pc,6)
        if raw[:3]==b'\x4c\x3b\x20':cf=height<bound;zf=height==bound;pc+=3
        elif raw[:4]==b'\x48\x8b\x44\x24':
            require(raw[4] in stack,'unknown synthetic bound slot');bound=stack[raw[4]];pc+=5
        elif raw[0] in (0x72,0x73,0x76) or raw[:2]==b'\x0f\x86':
            require(cf is not None,'unset retention flags')
            wide=raw[0]==0x0f;op=0x76 if wide else raw[0]
            condition={0x72:cf,0x73:not cf,0x76:cf or zf}[op]
            size=6 if wide else 2;delta=int.from_bytes(raw[2:6] if wide else raw[1:2],'little',signed=True)
            pc+=size+(delta if condition else 0)
        elif raw[:6]==b'\x66\x0f\x1f\x44\x00\x00':pc+=6
        else:raise ValueError('unsupported retention instruction')
    raise ValueError('retention instruction budget exhausted')

def expected(height,lower,upper,cap):return dict(keep=lower<=height<upper and height<=cap,diagnostic=height<lower)

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'retention FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'retention owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    controls={0x33084f0:'410f104500410f104d100f114b100f11034883c320',
      0x330852e:'4883c52049896f08',0x33085a3:'ff153f64460284c07423',
      0x33085b5:'0f8435ffffff',0x33085c6:'e925ffffff',
      0x33085e5:'4c8ba42488000000488b4424104c3b207351',
      0x3308648:'488b4424484c3b20731e488b4424104c3b207214488b4424404c3b200f8686feffff',
      0x3308670:'488b7424704885f60f848ffeffff',0x330868b:'e97dfeffff',
      0x3308690:'488b4424084889da'}
    for va,raw in controls.items():
        expected=bytes.fromhex(raw);require(image.read(va,len(expected))==expected,f'retention control changed at {va:#x}')
    require(image.read(0x1fe44c,21)==b'/MARKED_FOR_DELETION\x00','marker suffix changed')
    slots={91679208: 21276432, 91676736: 20203360, 91679096: 21221392}
    actual=image.relative_relocs()
    require(all(actual.get(slot)==target for slot,target in slots.items()),'unclosed helper relocation changed')
    return dict(target_sha256=SHA256,owners=owners,resolved_unclosed_slots={hex(k):hex(v) for k,v in slots.items()},controls={hex(k):v for k,v in controls.items()},
      observations=['marker helper AL nonzero takes unconditional keep route, not the height predicates',
        'other records request diagnostic when height is unsigned below lower',
        'remaining keep predicate is lower <= height < upper and height <= cap',
        'kept 32-byte records copied unchanged to output cursor, advancing cursor by 32'],
      limits='Only unsigned height gate interpreted, logger normal-return successor specialized. Marker/file helper behavior, allocation, input validity, callers and filesystem deletion unclosed.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
