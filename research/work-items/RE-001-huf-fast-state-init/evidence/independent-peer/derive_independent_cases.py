"""Closed constructor equations derived from authenticated native rows, not CPU stepping.
No Rust implementation or author model is imported/read by this generator.
"""
from pathlib import Path
import json,hashlib
MASK=(1<<64)-1;MAXL=(1<<63)-1;P=Path('/tmp/huf-init-peer-bajf87p2')
def image(a=8,b=8,c=8,d=8,last=(0,1,128,255)):
 x=bytearray(a.to_bytes(2,'little')+b.to_bytes(2,'little')+c.to_bytes(2,'little')+bytes(a+b+c+d))
 end=6
 for j,n in enumerate((a,b,c,d)):
  end+=n
  if n:x[end-1]=last[j]
 return bytes(x)
def oracle(m,L,data,header,initial):
 # Checked API mathematical domain. Physicalnativeframe/code/mapping validities
 # remain explicit external assumptions and are not simulated here.
 if L>MAXL:return None,initial[:],'outside-signed-L'
 k=(L+3)//4
 regs=[(m['state'],152),(m['output'],L),(m['input'],len(data)),(m['table'],4)]
 if any(s+n>MASK for s,n in regs) or m['output']+3*k>MASK:return None,initial[:],'outside-nonwrap'
 for j,(s,n) in enumerate(regs):
  for t,z in regs[j+1:]:
   if n and z and max(s,t)<min(s+n,t+z):return None,initial[:],'outside-role-separation'
 out=initial[:]
 if L==0:return 0,out,'no-state-writes'
 N=len(data)
 if N<=9:return MASK-19,out,'no-state-writes'
 if header[2]!=11:return 0,out,'no-state-writes'
 a,b,c=[int.from_bytes(data[i:i+2],'little') for i in (0,2,4)]
 I=m['input'];O=m['output'];starts=[(I+v)&MASK for v in (6,6+a,6+a+b,6+a+b+c)];out[15:19]=starts
 if a<=7 or b<=7:return 0,out,'four-start-writes'
 d=(N-6-a-b-c)&MASK
 if c<=7 or d<=7:return 0,out,'four-start-writes'
 if d>N:return MASK-19,out,'four-start-writes'
 offsets=[6+a,6+a+b,6+a+b+c,N]
 out[0:4]=[I+e-8 for e in offsets];out[4:8]=[O+j*k for j in range(4)]
 if O+3*k>=O+L:return 0,out,'twelve-writes'
 for j,e in enumerate(offsets):
  b=data[e-1];w=int.from_bytes(data[e-8:e],'little');shift=0 if not b else 8-(b.bit_length()-1)
  out[8+j]=((w|1)<<shift)&MASK
 out[12:15]=[m['table']+4,I,O+L]
 return 1,out,'nineteen-writes'
cases=[]
def add(name,L=4,data=None,header=bytes([0x12,0x34,11,0x56]),m=None):
 if data is None:data=image()
 if m is None:m=dict(state=0x100000,output=0x300000,input=0x200000,table=0x400000)
 initial=[0xac00000000000000+len(cases)*256+j for j in range(19)]
 status,expected,phase=oracle(m,L,data,header,initial)
 cases.append(dict(name=name,addresses=m,output_length=L,input_hex=data.hex(),header_hex=header.hex(),initial_state=initial,expected_status=status,expected_state=expected,expected_phase=phase))
for L in range(14):add('ceil-partition-L'+str(L),L=L)
add('zero-L-empty-role-ranges-share-state',L=0,data=b'',m=dict(state=0x100000,output=0x100000,input=0x100000,table=0x400000))
add('positive-L-empty-input-wins-bad-header',data=b'',header=bytes(4))
add('N9-wins-bad-header',data=bytes(9),header=bytes(4))
for a,b,c in ((7,8,8),(8,7,8),(8,8,7),(8,8,8),(0,65535,65535)):
 data=a.to_bytes(2,'little')+b.to_bytes(2,'little')+c.to_bytes(2,'little')+bytes(4)
 add('N10-size-guards-%d-%d-%d'%(a,b,c),data=data)
add('residual-zero',data=image(d=0));add('residual-seven',data=image(d=7));add('residual-eight',data=image(d=8))
x=bytearray(image(9,10,11,12));end=6
for j,n in enumerate((9,10,11,12)):
 end+=n;x[end-8:end]=bytes([0x12+j,0x34+j,0x56+j,0x78+j,0x9a+j,0xbc+j,0xde+j,(1,3,128,255)[j]])
add('distinct-streams-distinct-qword-width-endian',data=bytes(x))
add('WORD-length-256-not-byte',data=image(256,8,8,8))
add('header-byte0-not-selected',header=bytes([0,0,11,0]))
add('header-byte0-cannot-substitute-for-byte2',header=bytes([11,0,0,0]))
add('wrapped-start-values-on-error',data=bytes([255]*6)+bytes(32),m=dict(state=0x100000,output=0x300000,input=MASK-38,table=0x400000))
for L in (MAXL-3,MAXL):add('signed-L-upper-'+str(L),L=L,m=dict(state=0x8000000000001000,output=0,input=0x8000000000010000,table=0x8000000000020000))
add('negative-signed-L-outside',L=1<<63)
add('output-cursor-wrap-even-when-end-fits',L=1,m=dict(state=0x100000,output=MASK-2,input=0x200000,table=0x400000))
add('output-cursor-max-nonwrap-refusal',L=1,m=dict(state=0x100000,output=MASK-3,input=0x200000,table=0x400000))
for key,value in [('state',MASK-151),('input',MASK-37),('table',MASK-3),('output',MASK-3)]:
 m=dict(state=0x100000,output=0x300000,input=0x200000,table=0x400000);m[key]=value;add('range-end-overflow-'+key,m=m)
for key,value in [('output',0x100008),('input',0x100008),('table',0x100094)]:
 m=dict(state=0x100000,output=0x300000,input=0x200000,table=0x400000);m[key]=value;add('role-overlap-'+key,m=m)
# Prove special expectations independently of using the generalcase generator.
assert cases[4]['expected_state'][8:12]==[1,256,2,0xfe00000000000002]
assert [x['output_length'] for x in cases[:14] if x['expected_phase']=='twelve-writes']==[1,2,3,5,6,9]
assert next(x for x in cases if x['name']=='wrapped-start-values-on-error')['expected_state'][15:19]==[MASK-32,65502,131037,196572]
record=dict(target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',primary_body_sha256='e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63',derivation='Independent closed arithmetic/partial-state equations from prior peer-authenticated native443B, before peer reads newRustimplementation orauthorbuildoutputs. Not concreteCPUstepping/emulation andnot targetexecution. SymbolicAPIaddress boundarycases do notassert actualhardwarememory mappings.',native_proof_receipt_sha256='1c6aac79e84e3741d732bec0efd295c5988c989ea577ce209a0069eac3c53bad',cases=cases)
f=P/'INDEPENDENT-CLIENT-EXPECTED-CASES.json';f.write_text(json.dumps(record,indent=2)+'\n');print('cases',len(cases),'sha',hashlib.sha256(f.read_bytes()).hexdigest())
