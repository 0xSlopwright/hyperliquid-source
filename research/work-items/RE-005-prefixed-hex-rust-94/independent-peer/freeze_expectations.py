"""Independent high-level normal-domain byte relation, before production Rust."""
from pathlib import Path
import json,hashlib
D=Path(__file__).resolve().parent
cases=[]
def add(input_bytes,mode,capacity,kind,label):
 i=len(cases)
 left=bytes([0xe3,i&255,0x19]) if i%3 else b'\0\xff'
 right=bytes([0x0f,0xa6,(i*7)&255,0x80])
 out_left=bytes([0x62,(i+17)&255,0xf1,0x05])
 out_right=bytes([0x17,0xde,(i*13)&255])
 output=bytes((0xa5+i*11+j*19)&255 for j in range(capacity))
 required=2*len(input_bytes)+2
 if not input_bytes or capacity<required:
  status='unsupported';length=0;expected=output
 else:
  # Python's byte hex rendering is independent of the new Rust producer;
  # the first-nibble operation follows the admitted byte-table/flag proof.
  digits=input_bytes.hex()
  if mode and input_bytes[0]<16:digits=digits[1:]
  prefix=('0x'+digits).encode('ascii');length=len(prefix)
  status='ok';expected=prefix+output[length:]
 ident='repeat' if i%7==0 else f'case_{97-i:03d}'
 cases.append({'id':ident,'mode':int(mode),'input_left':left.hex(),'input':input_bytes.hex(),'input_right':right.hex(),'output_left':out_left.hex(),'initial_output':output.hex(),'output_right':out_right.hex(),'domain':kind,'label':label,'expected_status':status,'expected_length':length,'expected_complete_output':expected.hex()})
lengths=[1,2,3,5,9,17,20,31,32,33,63]
for i,n in enumerate(lengths):
 for m in [False,True]:
  b=bytes([[0,15,16,255][(i+int(m))%4]])+bytes((i*37+int(m)*71+k*29+k*k*3)&255 for k in range(1,n))
  add(b,m,2*n+2+[0,1,7][(i+int(m))%3],'normal',f'variable_n{n}_mode{int(m)}')
for first in [0,1,15,16,255]:
 for m in [False,True]:
  for n,extra in [(3,0),(6,5)]:
   b=bytes([first])+bytes([0,15,240,1,16][:n-1])
   add(b,m,2*n+2+extra,'normal',f'first_nibble_{first}_n{n}_mode{int(m)}')
assert len(cases)==42
for cap in [0,1,2,5]:
 for m in [False,True]:add(b'',m,cap,'safe_api_policy','empty_input')
for n in [1,2,3,7]:
 for m in [False,True]:add(bytes([15])+bytes((j*47)&255 for j in range(1,n)),m,2*n+1,'safe_api_policy','one_short_even_if_trim_would_fit')
for cap in [0,1,2]:
 for m in [False,True]:add(bytes.fromhex('0f10ff'),m,cap,'safe_api_policy','short_prefix_or_body_capacity')
assert len(cases)==64
encode=lambda s:s or '-'
inputs=[' '.join([r['id'],str(r['mode']),*(encode(r[k]) for k in ['input_left','input','input_right','output_left','initial_output','output_right'])]) for r in cases]
expected=[' '.join([r['id'],r['expected_status'],str(r['expected_length']),encode(r['expected_complete_output'])]) for r in cases]
(D/'STIMULI-AND-EXPECTATIONS.json').write_text(json.dumps(cases,indent=2)+'\n')
(D/'INPUTS.txt').write_text('\n'.join(inputs)+'\n');(D/'EXPECTED.txt').write_text('\n'.join(expected)+'\n')
files={p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [D/'freeze_expectations.py',D/'STIMULI-AND-EXPECTATIONS.json',D/'INPUTS.txt',D/'EXPECTED.txt']}
v={'schema':'independent-prefixed-hex-pre-rust-oracle-v1','production_Rust_read':False,'author_oracle_inputs_or_answers_or_generator_read':False,'target_or_CPU_emulator_execution':False,'method':'Derived from97 admitted native rows and actual16-byte table; expected bytes use Python bytes.hex plus the proved single-first-nibble operation. No new Rust source or author oracle supplies answers.','cases':64,'normal_domain_cases':42,'safe_API_policy_cases':22,'all_cases_use_padded_disjoint_input_and_output_containers':True,'IDs_are_repeated_and_nonmonotone':True,'case_counts_are_not_claimed_unique_author_unseen_values':True,'policy_boundary':'Empty/short safe API returns Err without writes; this differs from unqualified target panic/partial-write behavior and is not target parity.','normal_required_capacity':'2*n+2 even when first high nibble is suppressed; actual written length2*n+2-trim','files':files}
(D/'EXPECTATIONS-FREEZE.json').write_text(json.dumps(v,indent=2)+'\n')
print(json.dumps({'cases':64,'normal':42,'policy':22,'freeze_sha256':hashlib.sha256((D/'EXPECTATIONS-FREEZE.json').read_bytes()).hexdigest()},indent=2))
