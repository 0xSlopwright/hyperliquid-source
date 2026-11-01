"""RE-001: prepared archive prefix and borrowed row projection; static only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records
PACKET=ROOT/'research/work-items/RE-001-archive-prefix-94'
CASES=[(0x37e2960,0x37e3a6b,'7fc7855c17899fc24fa9c0f37c2af2d23fe113666a91017f352eae2742aebe41'),
       (0x3bade80,0x3bae218,'f038248c0d836df1f85cde79fe28a33b852c0d38f1cc535141c2e641e3b6015d')]
MASK=(1<<64)-1
def require(ok,message):
    if not ok:raise ValueError(message)

def replay_prefix(image,count,exclude,slot_a,slot_b,row_base=0x200000):
    """Actual bounded MOV/LEA prefix builder, with opaque formatter outputs.

    Tuple arguments are synthetic (pointer,length), not host pointers. No call,
    allocator, string formatter, shell parser or captured function executes.
    """
    require(type(count) is int and 0<=count<=1024,'synthetic count outside bound')
    require(type(row_base) is int and 0<=row_base<=MASK-count*24,'synthetic row span outside bound')
    require(all(len(pair)==2 and all(type(v) is int and 0<=v<=MASK for v in pair) for pair in (exclude,slot_a,slot_b)),'raw pointer-length pairs required')
    regs={0:exclude[1],1:slot_a[1],3:count,4:0x100000,7:exclude[0],8:slot_a[0],12:row_base}
    ram=bytearray(0x300);struct.pack_into('<Q',ram,0x90,slot_b[0]);struct.pack_into('<Q',ram,0xe8,slot_b[1])
    def register(n):require(n in regs,'unset synthetic register');return regs[n]
    def store(offset,value):
        require(0<=offset<=len(ram)-8,'stack store escaped synthetic RAM');struct.pack_into('<Q',ram,offset,value&MASK)
    pc=0x37e30e2
    for _ in range(60):
        if pc==0x37e31bf:
            return dict(header=struct.unpack_from('<QQQ',ram,0x200),prefix=[struct.unpack_from('<QQ',ram,0x218+16*i) for i in range(6)],
                        row_span=struct.unpack_from('<QQ',ram,0x278))
        require(0x37e30e2<=pc<0x37e31bf,'prefix escaped bounded range');raw=image.read(pc,12)
        if raw[:3]==bytes.fromhex('488d14'):
            require(raw[3]==0x5b,'unsupported row-count scale');regs[2]=(register(3)*3)&MASK;pc+=4
        elif raw[:4]==bytes.fromhex('498d14d4'):regs[2]=(register(12)+register(2)*8)&MASK;pc+=4
        elif raw[:4]==bytes.fromhex('48c78424'):
            offset=struct.unpack_from('<i',raw,4)[0];value=struct.unpack_from('<i',raw,8)[0];store(offset,value);pc+=12
        elif raw[0] in (0x48,0x4c) and raw[1] in (0x89,0x8b) and raw[2]&0xc7==0x84 and raw[3]==0x24:
            reg=((raw[2]>>3)&7)+(8 if raw[0]&4 else 0);offset=struct.unpack_from('<i',raw,4)[0]
            require(0<=offset<=len(ram)-8,'stack load escaped synthetic RAM')
            if raw[1]==0x89:store(offset,register(reg))
            else:regs[reg]=struct.unpack_from('<Q',ram,offset)[0]
            pc+=8
        elif raw[:3] in (bytes.fromhex('488d35'),bytes.fromhex('488d05')):
            reg=(raw[2]>>3)&7;regs[reg]=pc+7+struct.unpack_from('<i',raw,3)[0];pc+=7
        else:raise ValueError(f'unsupported prefix instruction at {pc:#x}')
    raise ValueError('prefix instruction budget exhausted')

def project_selected(image,source_rows):
    """Specialized row projection from the actual tail load's displacement.

    It is a lowering of the selected row load, not full iterator replay.
    """
    require(len(source_rows)%24==0 and len(source_rows)<=24*1024,'synthetic 24-byte rows required')
    raw=image.read(0x3bae188,6)
    require(raw[:5]==bytes.fromhex('410f1044d4'),'unsupported row projection')
    offset=int.from_bytes(raw[5:6],'little',signed=True)
    require(0<=offset<=8,'row load escaped synthetic row')
    return b''.join(source_rows[pos+offset:pos+offset+16] for pos in range(0,len(source_rows),24))

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'archive owner FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'archive owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    require(image.read(0x59c095,8)==b'tar-C-cf','prefix literals changed')
    require(image.read(0x59c089,12)==b'TAR_COMPLETE','marker literal changed')
    require(image.read(0x1fe85b,18)==b'\x0e--exclude="**/\xc0\x01"','exclude format record changed')
    slots={0x576e040:0x1344760,0x576e9e8:0x144a710};actual=image.relative_relocs()
    require(all(actual.get(k)==v for k,v in slots.items()),'archive helper relocation changed')
    edges={0x37e31cc:0x3bade80,0x37e3207:0x1455c00}
    for site,target in edges.items():
        raw=image.read(site,5)
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,'archive direct call changed')
    sample=replay_prefix(image,3,(0x300000,27),(0x400000,11),(0x500000,17))
    require(sample['header']==(1,0,6),'prepared prefix header changed')
    require(sample['row_span']==(0x200000,0x200000+3*24),'row span changed')
    return dict(target_sha256=SHA256,owners=owners,
      prefix_literals=[dict(address='0x59c095',length=3,text='tar'),dict(address='0x59c098',length=2,text='-C'),dict(address='0x59c09a',length=3,text='-cf')],
      prepared_prefix=['tar','opaque exclusion formatter result','-C','tuple from stack+0xf8/+0x100','-cf','tuple from stack+0x90/+0xe8'],
      array_metadata=[1,0,6],tail_input_stride=24,tail_output_stride=16,tail_pair_offset=8,
      direct_call_edges={hex(k):hex(v) for k,v in edges.items()},
      resolved_unclosed_slots={hex(k):hex(v) for k,v in slots.items()},
      observations=['six fixed/dynamic pointer-length pairs precede the owned-row span',
        'row span end is row base plus count*24','tail projection loads 16 bytes at row+8, omitting the first qword'],
      limits='Prefix builder interpreted; tail row load specialized, full iterator and formatter/string consumer remain unclosed. No shell argv, process execution, escaping, archive contents, caller success or filesystem effects established.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
