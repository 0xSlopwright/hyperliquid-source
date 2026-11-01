"""Independent explicit-route witnesses derived before reading any new Rust.

This is integer/address math for chosen cases, not a CPU interpreter. Refusal
phases/statuses are selected explicitly per case from native branch witnesses;
we never ask the implementation to generate its expected answer.
"""
import hashlib
import json
from pathlib import Path
import struct

OUT=Path('/tmp/huf-constructor-controls-20261031')
U64=(1<<64)-1
INITIAL=[0xd000000000000000+i*0x01010101010101 for i in range(19)]
BASE={'state':0x1000,'output':0x2000,'input':0x3000,'table':0x4000}
INPUTS=[];EXPECTED=[]

def input_bytes(n,a=8,b=8,c=8,blocks=None):
    data=bytearray(n)
    if n>=6:data[:6]=struct.pack('<HHH',a,b,c)
    if blocks is not None:
        ends=[6+a,6+a+b,6+a+b+c,n]
        for end,block in zip(ends,blocks):
            assert len(block)==8 and 8<=end<=n
            data[end-8:end]=block
    return bytes(data)


def add(label,L,data,phase,status=None,header=b'\xa5\x5a\x0b\xff',addresses=None,domain=False):
    addresses=dict(BASE if addresses is None else addresses)
    stimulus={'addresses':addresses,'output_length':L,'input_hex':data.hex(),
              'header_hex':header.hex(),'state':list(INITIAL)}
    result=list(INITIAL)
    if phase in ('starts','cursors','full'):
        a,b,c=struct.unpack_from('<HHH',data)
        I,O=addresses['input'],addresses['output']
        starts=[I+6,I+6+a,I+6+a+b,I+6+a+b+c]
        result[15:19]=[v&U64 for v in starts]
    if phase in ('cursors','full'):
        ends=[I+6+a,I+6+a+b,I+6+a+b+c,I+len(data)]
        result[0:4]=[v-8 for v in ends]
        k=(L+3)//4
        result[4:8]=[O+j*k for j in range(4)]
    if phase=='full':
        relative=[6+a,6+a+b,6+a+b+c,len(data)]
        bits=[]
        for end in relative:
            last=data[end-1]
            shift=0 if last==0 else 9-last.bit_length()
            bits.append(((int.from_bytes(data[end-8:end],'little')|1)<<shift)&U64)
        result[8:12]=bits
        result[12]=addresses['table']+4
        result[13]=I
        result[14]=O+L
    INPUTS.append(stimulus)
    EXPECTED.append({'label':label,'raw_status':status,'domain_error_expected':domain,
                     'state':result,'native_phase':phase,
                     'new_checked_API_boundary_only':domain})

# Guard-priority witnesses. Header bytes are always supplied as a fullDWORD.
add('L0-wins-empty-input-and-bad-table',0,b'','none',0,header=b'\x00'*4)
add('L0-wins-N9-and-bad-table',0,bytes(9),'none',0,header=b'\x00'*4)
add('positive-L-N9-error-wins-bad-table',4,bytes(9),'none',U64-19,header=b'\x00'*4)
add('positive-L-N10-bad-table-zero',4,input_bytes(10),'none',0,header=b'\x00'*4)
for lane,lengths in [('a',(7,8,8)),('b',(8,7,8)),('c',(8,8,7))]:
    add(lane+'7-wins-residual-underflow',4,input_bytes(10,*lengths),'starts',0)
add('residual-underflow-raw-minus20-after-four-writes',4,input_bytes(10),'starts',U64-19)
add('residual7-zero-after-four-writes',4,input_bytes(37),'starts',0)

# Independent exact arithmetic boundary: late output refusal is NOT L<4.
LATE={1,2,3,5,6,9}
for L in range(1,14):
    add('output-L'+str(L),L,input_bytes(38),'cursors' if L in LATE else 'full',0 if L in LATE else 1)

# Exact bit values/lanes, not merely a nonzero check.
add('lastbytes-0-1-128-255',4,input_bytes(38,blocks=[bytes(7)+bytes([b]) for b in [0,1,128,255]]),'full',1)
assert EXPECTED[-1]['state'][8:12]==[1,256,2,0xfe00000000000002]
add('lastbytes-3-127-2-64',4,input_bytes(38,blocks=[bytes(7)+bytes([b]) for b in [3,127,2,64]]),'full',1)
blocks=[bytes.fromhex(s) for s in ['0123456789abcdef','1032547698badc00','1122334455667701','deadbeef01020380']]
add('distinct-lane-LE64-lastwords',13,input_bytes(44,8,9,10,blocks),'full',1)
for lane,lengths in [('a',(256,8,8)),('b',(8,256,8)),('c',(8,8,256))]:
    add('WORD-not-BYTE-'+lane,4,input_bytes(6+sum(lengths)+8,*lengths),'full',1)
add('distinct-LE16-header-lengths',4,input_bytes(6+0x0102+0x0201+0x0304+8,0x0102,0x0201,0x0304),'full',1)
for label,header in [('byte0-only',b'\x0b\x00\x00\x00'),('byte1-only',b'\x00\x0b\x00\x00'),('byte3-only',b'\x00\x00\x00\x0b')]:
    add('table-'+label+'-not-byte2',4,input_bytes(38),'none',0,header=header)
add('table-other-bits-ignored',4,input_bytes(38),'full',1,header=b'\xff\xff\x0b\xff')

# Refused stored pointer VALUES can wrap without a stream dereference.
addr=dict(BASE,input=U64-38)
add('wrapped-failed-stream-start-values',4,input_bytes(38,65535,65535,65535),'starts',U64-19,addresses=addr)
assert EXPECTED[-1]['state'][15:19]==[U64-32,65502,131037,196572]
addr=dict(BASE,input=U64-10)
add('wrapped-start-values-first-size7-zero',4,input_bytes(10,7,65535,65535),'starts',0,addresses=addr)
assert EXPECTED[-1]['state'][15:19]==[U64-4,2,65537,131072]

# Exactly adjacent ranges are allowed; empty ranges have no overlap.
addr={'state':0x1000,'input':0x1098,'output':0x10be,'table':0x10c2}
add('adjacent-half-open-ranges',4,input_bytes(38),'full',1,addresses=addr)
addr={'state':0x1000,'input':0x1000,'output':0x1000,'table':0x4000}
add('empty-input-output-ranges-not-overlap',0,b'','none',0,addresses=addr)
addr={'state':0x9000000000000000,'input':0x9000000000001000,'table':0x9000000000002000,'output':0x1000}
add('largest-signed-L-symbolic-math-domain',(1<<63)-1,input_bytes(38),'full',1,addresses=addr)

# Unsupported checked-domain results are NOT target raw refusal codes.
for label,addr,L in [
 ('Q-plus152-overflow',dict(BASE,state=U64-151),4),
 ('I-plusN-overflow',dict(BASE,input=U64-37),4),
 ('O-plusL-overflow',dict(BASE,output=U64-3),4),
 ('T-plus4-overflow',dict(BASE,table=U64-3),4),
 ('O-plus3ceil-overflow-despite-output-end-fit',dict(BASE,output=U64-2),1),
 ('negative-signed-L-bit63',BASE,1<<63),('negative-signed-L-allones',BASE,U64),
 ('state-input-overlap',dict(BASE,input=BASE['state']),4),
 ('state-output-overlap',dict(BASE,output=BASE['state']),4),
 ('state-header-overlap',dict(BASE,table=BASE['state']),4),
 ('input-output-overlap',dict(BASE,output=BASE['input']),4),
 ('input-header-overlap',dict(BASE,table=BASE['input']),4),
 ('output-header-overlap',dict(BASE,table=BASE['output']),4),
]:
    add(label,L,input_bytes(38),'unsupported',None,addresses=addr,domain=True)
assert all(len(v['state'])==19 for v in INPUTS+EXPECTED)
for name,value in [('STIMULI.json',INPUTS),('EXPECTED.json',EXPECTED)]:
    (OUT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
manifest={'status':'INDEPENDENT_NATIVE_EXPECTATIONS_FROZEN_BEFORE_NEW_RUST_SOURCE_READ',
          'case_count':len(INPUTS),'expected_raw_success':sum(x['raw_status']==1 for x in EXPECTED),
          'expected_raw_zero':sum(x['raw_status']==0 for x in EXPECTED),'expected_raw_minus20':sum(x['raw_status']==U64-19 for x in EXPECTED),
          'expected_unsupported_domain':sum(x['domain_error_expected'] for x in EXPECTED),
          'target_body_sha256':'e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63',
          'proof_sha256':'1c8e097fd7fbf61b27501ebc898ab85580bc041685196d3764a5a26103d7a3a2',
          'files':{n:{'bytes':(OUT/n).stat().st_size,'sha256':hashlib.sha256((OUT/n).read_bytes()).hexdigest()} for n in ['STIMULI.json','EXPECTED.json','freeze_expectations.py']},
          'new_Rust_source_read':False,'compiler_or_target_execution':False,
          'method':'Explicit native guard phases/statuses chosen independently; complete expected state vectors from interval/bit equations, no implementation call or instruction interpreter.'}
(OUT/'EXPECTATIONS-FREEZE.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
