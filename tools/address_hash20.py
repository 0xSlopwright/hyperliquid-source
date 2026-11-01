#!/usr/bin/env python3
"""RE-001: specialized 20-byte table hash, synthetic seed words only; static."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-address-hash20-94'
CASES=[(0x2840fb0,0x28410f5,'3fdd8618bbf0ec801f49ca7b9bf78b3d4719a2ec2d409a4e9d71a5af986837aa'),
       (0x288e280,0x288e457,'2de0e4e06f65af3f729cc6b2a4d12d7dcbbcb25902272a15c5f238c5096ed8b0')]
MASK=(1<<64)-1

def require(ok,message):
    if not ok:raise ValueError(message)

def rotate(x,n):return ((x<<n)|(x>>(64-n)))&MASK

def arithmetic(code,registers,memory):
    """Bounded subset: 64-bit ADD/XOR/MOV/OR, ROL/SHL, synthetic stack only."""
    r=list(registers);pc=0
    def reg(n):
        require(r[n] is not None,'Read of unset synthetic register');return r[n]
    for _ in range(150):
        if pc==len(code):return r
        require(pc+3<=len(code),'Truncated arithmetic instruction')
        rex,op,modrm=code[pc:pc+3];pc+=3
        require(0x48<=rex<=0x4f,'Unsupported arithmetic prefix')
        mode=modrm>>6;src=((modrm>>3)&7)+((rex&4)<<1);rm=(modrm&7)+((rex&1)<<3)
        address=None
        if mode!=3:
            require(rm==4 and code[pc]==0x24 and mode in (0,1,2),'Unsupported synthetic addressing');pc+=1
            size=0 if mode==0 else 1 if mode==1 else 4
            offset=int.from_bytes(code[pc:pc+size],'little',signed=True) if size else 0;pc+=size
            address=reg(4)+offset
        def get_rm():
            if address is None:return reg(rm)
            require(all(address+i in memory for i in range(8)),'Synthetic stack read escaped RAM')
            return int.from_bytes(bytes(memory[address+i] for i in range(8)),'little')
        def set_rm(value):
            value&=MASK
            if address is None:r[rm]=value
            else:
                require(all(address+i in memory for i in range(8)),'Synthetic stack write escaped RAM')
                memory.update((address+i,b) for i,b in enumerate(struct.pack('<Q',value)))
        if op==0x01:set_rm(get_rm()+reg(src))
        elif op==0x31:set_rm(get_rm()^reg(src))
        elif op==0x89:set_rm(reg(src))
        elif op==0x8b:r[src]=get_rm()
        elif op==0x0b:r[src]=reg(src)|get_rm()
        elif op==0xc1:
            n=code[pc]&63;pc+=1;group=(modrm>>3)&7;value=get_rm()
            require(group in (0,4) and n!=0,'Unsupported shift/rotate')
            set_rm(rotate(value,n) if group==0 else value<<n)
        elif op==0x81:
            require(((modrm>>3)&7)==6,'Unsupported immediate arithmetic')
            value=int.from_bytes(code[pc:pc+4],'little',signed=True)&MASK;pc+=4;set_rm(get_rm()^value)
        else:raise ValueError(f'Unmodelled arithmetic opcode {op:#x}')
    raise ValueError('Arithmetic step bound')

def target_hash(img,seed,message):
    require(len(seed)==2 and all(type(v) is int and 0<=v<=MASK for v in seed),'Synthetic seed word domain')
    require(type(message) is bytes and len(message)==20,'Specialized 20-byte message domain')
    a,c=struct.unpack('<QQ',img.read(0x204ec0,16));b,d=struct.unpack('<QQ',img.read(0x203e70,16))
    state=[a^seed[0],b^seed[1],c^seed[0],d^seed[1]]
    compression=img.read(0x288e3a4,0x288e3da-0x288e3a4)
    for offset in (0,8):
        r=[None]*16;r[0],r[10],r[1],r[11]=state;r[3]=int.from_bytes(message[offset:offset+8],'little')
        r=arithmetic(compression,r,{})
        state=[r[0],r[10],r[1],r[11]]
    # Specialized fresh-writer path: two full words, four-byte tail, length 20.
    stack=bytearray(72)
    struct.pack_into('<QQQQ',stack,0,state[0],state[2],state[1],state[3])
    struct.pack_into('<QQQ',stack,0x30,20,int.from_bytes(message[16:20],'little'),4)
    memory={0x100000+i:b for i,b in enumerate(stack)};r=[None]*16;r[4]=0x100000
    return arithmetic(img.read(0x2841003,0x28410f0-0x2841003),r,memory)[0]

def reference_hash(seed,message):
    """Independent SipHash-1-3 math for the same fixed 20-byte domain."""
    s=[seed[0]^0x736f6d6570736575,seed[1]^0x646f72616e646f6d,
       seed[0]^0x6c7967656e657261,seed[1]^0x7465646279746573]
    def mix(v):
        a,b,c,d=v;a=(a+b)&MASK;c=(c+d)&MASK;b=rotate(b,13)^a;d=rotate(d,16)^c;a=rotate(a,32)
        c=(c+b)&MASK;a=(a+d)&MASK;b=rotate(b,17)^c;d=rotate(d,21)^a;c=rotate(c,32)
        return [a,b,c,d]
    for word in (*struct.unpack('<QQ',message[:16]),(20<<56)|int.from_bytes(message[16:],'little')):
        s[3]^=word;s=mix(s);s[0]^=word
    s[2]^=255
    for _ in range(3):s=mix(s)
    return s[0]^s[1]^s[2]^s[3]

def observe(data):
    img=Image(data);read=img.read
    patterns={0x2840fb4:'f30f6f07660f70c844660fef0dfb3e9cfd',
      0x2840fca:'660f70c8ee660fef0d992e9cfd',0x2840fe3:'660fefc0660f7f44243048c744244000000000',
      0x2840ff9:'ba14000000e87dd20400',0x2841003:'488b7c243048c1e738480b7c2438',
      0x284105a:'4881f6ff000000',0x288e281:'480157304c8b4f404d85c9742f',
      0x288e375:'4c29c24189d14183e1074883e2f84939d0736a',
      0x288e3da:'4983c0084939d072bd',0x288e3f2:'4183f9047215428b1406b804000000',
      0x288e44d:'488957384c894f40',
      0x204ec0:'75657370656d6f736172656e6567796c',0x203e70:'6d6f646e61726f647365747962646574',
    }
    for va,raw in patterns.items():
        expected=bytes.fromhex(raw);require(read(va,len(expected))==expected,f'Hash initializer/path changed at {va:#x}')
    _,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        fs=[f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,'Hash owner FDE changed')
        require(hashlib.sha256(read(start,end-start)).hexdigest()==digest,'Hash owner body changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(fs[0]['fde']),cie=hex(fs[0]['cie'])))
    return dict(target_sha256=SHA256,owners=owners,message_bytes=20,seed_words=2,
                specialized_write={'fresh_tail':0,'full_words':2,'tail_bytes':4},identified_math='SipHash-1-3 on fixed 20-byte domain',
                limits='Fixed-length fresh-writer synthetic-seed math only; generic incremental writer, runtime seed selection, caller hash-table ownership and address derivation unproved.',
                captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/BINARY)
    p.add_argument('--out',type=Path,default=ROOT/'work/address-hash20.json');a=p.parse_args()
    result=build(a.binary.read_bytes());a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n')
    print('Verified specialized 20-byte table-hash paths')
if __name__=='__main__':main()
