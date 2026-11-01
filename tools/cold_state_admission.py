"""RE-001: bounded cold-state digest admission, static synthetic inputs only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from evm_amount_scale import ROOT,BINARY,SHA256,Image
from fde_extents import eh_frame_records

PACKET=ROOT/'research/work-items/RE-001-cold-state-admission-94'
CASES=[(0x23ecd70,0x23ed020,'c12748b24408bdba27a38f7ceab249f6f229ee86b512b86ef25f74e8eaa02a58'),
       (0x2209450,0x22095bd,'3f39caee97520c73b7d887d9d6a46adc8ab65c136d370b1b1d04cd8b14f2ff3d')]

def require(ok,message):
    if not ok:raise ValueError(message)

def digest_matches(image,incoming,local):
    """Interpret only the actual PCMPEQB/PAND/PMOVMSKB/CMP/Jcc window.

    XMM values specialize the surrounding four observed loads; no native code,
    hash helper, runtime state or user fixture is executed/accessed.
    """
    require(len(incoming)==len(local)==32,'two 32-byte synthetic digests required')
    xmm=[local[16:],local[:16],incoming[:16],incoming[16:]]
    pc=0x23ece0d
    for _ in range(4):
        raw=image.read(pc,4)
        require(raw[:2]==b'\x66\x0f' and raw[3]>>6==3,'unsupported SIMD instruction')
        dst=(raw[3]>>3)&7;src=raw[3]&7
        require(dst<4 and src<4,'SIMD register outside specialization')
        if raw[2]==0x74:xmm[dst]=bytes(255 if a==b else 0 for a,b in zip(xmm[dst],xmm[src]))
        elif raw[2]==0xdb:xmm[dst]=bytes(a&b for a,b in zip(xmm[dst],xmm[src]))
        elif raw[2]==0xd7:
            require(dst==0,'PMOVMSKB destination changed')
            mask=sum((v>>7)<<i for i,v in enumerate(xmm[src]))
        else:raise ValueError('unsupported SIMD operation')
        pc+=4
    raw=image.read(pc,5);require(raw[0]==0x3d,'unsupported mask compare')
    equal=mask==struct.unpack_from('<I',raw,1)[0];pc+=5
    branch=image.read(pc,6);require(branch[:2] in (b'\x0f\x84',b'\x0f\x85'),'unsupported digest branch')
    target=pc+6+struct.unpack_from('<i',branch,2)[0]
    require(target==0x23ecf0c,'digest rejection target changed')
    return not (equal if branch[1]==0x84 else not equal)

def selected_route(matches,optional_word,input_word,helper_result):
    """Byte-bound conditional summary, NOT replay of clone/validation helpers."""
    if not matches:return 'digest mismatch diagnostic then trap'
    if optional_word and input_word==0:return 'pre-helper assertion'
    return ('return fetched prefix' if helper_result==0x8000000000000040
            else 'post-helper unwrap trap')

def observe(data):
    image=Image(data);_,fdes=eh_frame_records(data);owners=[]
    for start,end,digest in CASES:
        matches=[f for f in fdes if f['start']==start]
        require(len(matches)==1 and matches[0]['end']==end,'state admission FDE changed')
        require(hashlib.sha256(image.read(start,end-start)).hexdigest()==digest,'state admission owner changed')
        owners.append(dict(start=hex(start),end_exclusive=hex(end),sha256=digest,fde=hex(matches[0]['fde']),cie=hex(matches[0]['cie'])))
    controls={
      0x23ecd8f:'440fb620',0x23ecd9b:'e8b0c6e1ff',
      0x23ecdc2:'0f10442438',0x23ecdcf:'f30f6f442458',0x23ecdd5:'660f7f8424f0000000',
      0x23ecde4:'660f7f8c24e0000000',0x23ece04:'f30f6f13f30f6f5b10660f74d8660f74d1660fdbd3660fd7c23dffff00000f85e4000000',
      0x23ece28:'488b6d2848837b3000',0x23ece39:'741d488b73204885f60f8479010000',
      0x23ece48:'488b5328488d7c2470e81a334b00',
      0x23ece58:'48c74424700000000048c784248000000000000000',
      0x23ecea3:'410fb6f4488d7c2470488d4c24104889eaff15fe6b3803',
      0x23eceba:'48b8400000000000008048394424700f8585000000',
      0x23ecf4a:'31ffff15ae6f3803eb7a',0x23ecfce:'0f0b',
    }
    for va,raw in controls.items():
        expected=bytes.fromhex(raw);require(image.read(va,len(expected))==expected,f'admission control changed at {va:#x}')
    require(image.read(0x1fc232,32)==b"'cold quorum l1 hash mismatch: c",'diagnostic bytes changed')
    slots={91699896: 74723072, 91700992: 78807824, 91676744: 22522384, 91699704: 60077072}
    actual=image.relative_relocs()
    require(all(actual.get(slot)==target for slot,target in slots.items()),'unclosed helper relocation changed')
    return dict(target_sha256=SHA256,owners=owners,resolved_unclosed_slots={hex(k):hex(v) for k,v in slots.items()},digest_bytes=32,
      controls={hex(k):v for k,v in controls.items()},
      observations=['32-byte fetched digest and incoming digest compared before optional helper preparation',
                    'mismatch diagnostic joins UD2, not the successful return',
                    'optional raw word +0x30 nonzero with +0x20 zero reaches a pre-helper assertion',
                    'outer helper result 0x8000000000000040 gates returning the fetched first 56 bytes'],
      limits='Only SIMD digest comparison is interpreted. Fetch/hash/clone/validation/logging helpers, cryptographic guarantees and typed state reachability remain unclosed.',
      captured_binaries_executed=False)

def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'wrong node94 SHA-256');return observe(data)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.write_text(json.dumps(build((ROOT/BINARY).read_bytes()),indent=2)+'\n',encoding='utf8',newline='\n')
