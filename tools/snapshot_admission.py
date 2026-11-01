"""RE-001: three snapshot admission prefixes; static, synthetic state only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT, BINARY, SHA256, Image
from fde_extents import eh_frame_records

MASK=(1<<64)-1
PACKET=ROOT/'research/work-items/RE-001-snapshot-admission-94'
# Full owners, prefix endpoints and distinct selected outcomes; ELF VAs.
CASES=[
    dict(start=0x220bed0,end=0x220c477,sha='5d012f851027ae4d6b1adedb7bd494d4de7301c0dcb8d115903d3c1ed02dd897',
         freeze=0x220bf56,periodic=0x220bf6c,skip=0x220c148,panic=0x220c352,tag=0xb90,label=0x3d74da),
    dict(start=0x42e73d0,end=0x42e797d,sha='65392f8ad976017d9d1d2f09f53732261e2e08319a466328023e14747714ed9a',
         freeze=0x42e7456,periodic=0x42e7464,skip=0x42e7640,panic=0x42e7858,tag=0x1610,label=0x6f0521),
    dict(start=0x42e7980,end=0x42e7f2d,sha='5d6f8fedb6a0ddbf77e648dd390776e77f4d639abca767c637de6ef9c6203656',
         freeze=0x42e7a06,periodic=0x42e7a14,skip=0x42e7bf0,panic=0x42e7e08,tag=0xb90,label=0x6f0521),
]

def require(value,message):
    if not value: raise ValueError(message)

def replay(image,case,tag,height,freeze_height):
    """Decode the actual bounded prefix, not native execution or full CFG replay.

    Prologue/current-height load are specialized inputs. Stops before labels,
    snapshot helpers, panic or housekeeping; no host/captured calls execute.
    """
    require(type(tag) is int and 0<=tag<1<<32,'tag is a raw u32')
    require(all(type(n) is int and 0<=n<=MASK for n in (height,freeze_height)),'height is a raw u64')
    pc=case['start']+0x16
    regs={0:None,1:None,2:None,14:height}; cf=zf=None
    stops={case[k]:k for k in ('freeze','periodic','skip','panic')}
    def register(n):
        require(regs.get(n) is not None,'unset synthetic register');return regs[n]
    def compare(a,b): return a<b,a==b
    for _ in range(40):
        if pc in stops:return stops[pc]
        require(case['start']+0x16<=pc<case['freeze'],'branch escaped selected prefix')
        raw=image.read(pc,10)
        if raw[:2]==b'\x83\xbf':
            offset=struct.unpack_from('<i',raw,2)[0]
            require(offset==case['tag'],'unexpected state offset')
            immediate=int.from_bytes(raw[6:7],'little',signed=True)&0xffffffff
            cf,zf=compare(tag,immediate);pc+=7
        elif raw[:3]==b'\x48\x8b\x83':
            require(struct.unpack_from('<i',raw,3)[0]==case['tag']+8,'unexpected freeze offset')
            regs[0]=freeze_height;pc+=7
        elif raw[:2] in (b'\x48\xb8',b'\x48\xb9',b'\x48\xba'):
            regs[raw[1]-0xb8]=struct.unpack_from('<Q',raw,2)[0];pc+=10
        elif raw[:3]==b'\x49\x0f\xaf':
            require(raw[3] in (0xc6,0xce),'unsupported multiply')
            n=(raw[3]>>3)&7;regs[n]=(register(n)*register(14))&MASK;pc+=4
        elif raw[:3]==b'\x48\xc1\xc8' or raw[:3]==b'\x48\xc1\xc9':
            n=raw[2]-0xc8;amount=raw[3]&63
            require(amount!=0,'unsupported zero rotate');v=register(n)
            regs[n]=((v>>amount)|(v<<(64-amount)))&MASK;pc+=4
        elif raw[:3]==b'\x4c\x39\xf0':cf,zf=compare(register(0),register(14));pc+=3
        elif raw[:3]==b'\x48\x39\xd1':cf,zf=compare(register(1),register(2));pc+=3
        elif raw[:3]==b'\x48\x39\xc8':cf,zf=compare(register(0),register(1));pc+=3
        elif raw[0] in (0xeb,0xe9):
            size=1 if raw[0]==0xeb else 4
            delta=int.from_bytes(raw[1:1+size],'little',signed=True);pc+=1+size+delta
        elif raw[0] in (0x72,0x73,0x74,0x75) or raw[:2] in (b'\x0f\x82',b'\x0f\x83',b'\x0f\x84',b'\x0f\x85'):
            require(cf is not None and zf is not None,'unset condition flags')
            wide=raw[0]==0x0f;op=raw[1]-0x10 if wide else raw[0];size=4 if wide else 1;prefix=2 if wide else 1
            take={0x72:cf,0x73:not cf,0x74:zf,0x75:not zf}[op]
            delta=int.from_bytes(raw[prefix:prefix+size],'little',signed=True)
            pc+=prefix+size+(delta if take else 0)
        else:raise ValueError(f'unsupported prefix instruction at {pc:#x}')
    raise ValueError('selected prefix instruction budget exhausted')

def expected(tag,height,freeze_height):
    if tag==1:
        if freeze_height<height:return 'panic'
        if freeze_height==height:return 'freeze'
    return 'periodic' if height%10000==0 else 'skip'

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for case in CASES:
        start,end=case['start'],case['end'];rows=[f for f in fdes if f['start']==start]
        require(len(rows)==1 and rows[0]['end']==end,'snapshot FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==case['sha'],'snapshot owner changed')
        require(image.read(case['label'],6)==b'freeze','freeze label changed')
        require(image.read(0x20a3e0,8)==b'periodic','periodic label changed')
        # Actual label constructor RIP addresses and length, not inferred names.
        for key,length in (('freeze',6),('periodic',8)):
            va=case[key];raw=image.read(va,7)
            require(raw[:3]==b'\x48\x8d\x15','label pointer construction changed')
            dest=va+7+struct.unpack_from('<i',raw,3)[0]
            require(dest==(case['label'] if key=='freeze' else 0x20a3e0),'label target changed')
            length_va=va+(15 if start==0x220bed0 else 7)
            require(image.read(length_va,5)==b'\xb9'+struct.pack('<I',length),'label length changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=case['sha'],fde=hex(rows[0]['fde']),cie=hex(rows[0]['cie']),
                           outcomes={k:hex(case[k]) for k in ('freeze','periodic','skip','panic')},tag_offset=hex(case['tag'])))
    return dict(target_sha256=SHA256,owners=owners,raw_state='u32 tag at lane-specific offset, u64 height +0x28, u64 freeze target tag+8',
                observations=['tag 1 and target below height reaches assertion path before periodic predicate',
                              'tag 1 and equal target chooses freeze even at a periodic height',
                              'other admissible states choose periodic exactly at multiples of 10000, including zero'],
                limits='Only selected admission prefixes and label construction. Helper effects, housekeeping, typed state reachability and native execution unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
