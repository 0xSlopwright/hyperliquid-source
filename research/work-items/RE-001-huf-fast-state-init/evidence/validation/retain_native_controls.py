"""Retain static tiny-span counterfactuals; never run captured code or a compiler."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess

CHECKOUT=Path('/dev/shm/hyperliquid-wave-ninth-20261031/huf_fast_state/checkout')
INTAKE=Path('/tmp/huf-caller-intake-SPk2Bt')
OUT=Path('/tmp/huf-constructor-controls-20261031/retained-native-controls')
TEST_SHA='c1ab312d3981501112092920a247016d9650745952bdf17d94d57f7214b97bc9'
TOOL_SHA='8c6aef2c81520dbae905d35512256fbe5f0ef58fc8819440f81b12a4d07edce4'

def sha(data):return hashlib.sha256(data).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def pin(path,expected):
    raw=path.read_bytes()
    if sha(raw)!=expected:raise ValueError('Pinned input changed: '+str(path))
    return raw

pin(CHECKOUT/'tests/test_huf_fast_state_init.py',TEST_SHA)
pin(CHECKOUT/'tools/huf_fast_state_init.py',TOOL_SHA)
spec=importlib.util.spec_from_file_location('owned_huf_control_tests',CHECKOUT/'tests/test_huf_fast_state_init.py')
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
subject=tests.subject
provider=Path(shutil.which('objdump')).resolve()
pin(provider,tests.OBJDUMP_SHA)
raw=pin(INTAKE/'94-55dc5e0-55dc79b.bin',tests.SPAN_SHA)
OUT.mkdir(mode=0o700)
records=[]

def native(label,data,start):
    folder=OUT/label;folder.mkdir(mode=0o700)
    span=folder/'span.bin';span.write_bytes(data);span.chmod(0o400)
    argv=[str(provider),'-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+hex(start),'span.bin']
    result=subprocess.run(argv,cwd=folder,stdin=subprocess.DEVNULL,capture_output=True,check=True,env={**os.environ,'LC_ALL':'C','LANG':'C'})
    (folder/'native.stdout').write_bytes(result.stdout);(folder/'native.stderr').write_bytes(result.stderr)
    dump(folder/'COMMAND.json',{'argv':argv,'exit_code':result.returncode,'captured_code_executed':False})
    if result.stderr or span.read_bytes()!=data:raise ValueError('Native copied-span changed')
    text=result.stdout.decode('ascii');rows=subject.parse_native_listing(text,start,data)
    return folder,rows,text

def reject(label,kind,call,needle=None,extra=None):
    try:call()
    except ValueError as error:
        reason=str(error)
        if needle is not None and needle not in reason:raise
        records.append({'control':label,'kind':kind,'accepted':False,'rejection':reason,**(extra or {})})
        return
    raise AssertionError('Counterfactual was accepted: '+label)

base,rows,listing=native('baseline-constructor',raw,tests.START)
subject.validate_constructor(raw,rows)
for label,address,before,after in tests.MUTATIONS:
    changed=bytearray(raw);at=address-tests.START
    if changed[at:at+len(bytes.fromhex(before))]!=bytes.fromhex(before):raise ValueError('Mutation anchor')
    changed[at:at+len(bytes.fromhex(before))]=bytes.fromhex(after)
    proposed=bytes(changed);folder,changed_rows,_=native(label,proposed,tests.START)
    reject(label,'actual constructor bytes',lambda:subject.validate_constructor(proposed,changed_rows),extra={'raw_sha256':sha(proposed),'address':address,'before':before,'after':after})

for label,source,start,end,expected,saved,called,reg,other in (
    ('wrapper-A','94-55dd2f0-55dd5bd.bin',0x55dd2f0,0x55dd35d,'47887cbe8583a3b291c5fdce681b313159d8d92a9f3f5f492a3db5c86a57f15e',0x55dd2f2,0x55dd35a,'r15','r14'),
    ('wrapper-B','94-55dceb0-55dd2f0.bin',0x55dceb0,0x55dcf1d,'59e356d00f002bf4076dde268b6222d9bd1984bd66803cf10d3f129945abcac8',0x55dceb4,0x55dcf1a,'r14','r15'),
):
    context=(INTAKE/source).read_bytes()[:end-start]
    if sha(context)!=expected:raise ValueError('Wrapper cut identity')
    _,context_rows,_=native(label+'-baseline',context,start)
    subject.validate_context(label,context,context_rows)
    for role,address in [('saved',saved),('called',called)]:
        changed=bytearray(context);at=address-start+2;changed[at]^=1
        _,changed_rows,_=native(label+'-'+role+'-raw-register',bytes(changed),start)
        reject(label+'-'+role+'-raw-register','actual context bytes',lambda:subject.validate_context(label,bytes(changed),changed_rows),'Selected context identity mismatch',{'raw_sha256':sha(changed)})
        changed_rows=copy.deepcopy(context_rows);row=next(r for r in changed_rows if r['address']==address)
        row['operands']=other+',r9' if role=='saved' else other
        folder=OUT/(label+'-'+role+'-rendered-register');folder.mkdir(mode=0o700);dump(folder/'rows.json',changed_rows)
        reject(label+'-'+role+'-rendered-register','authentic bytes, changed rendered operand',lambda:subject.validate_context(label,context,changed_rows),'Saved callback operand mismatch' if role=='saved' else 'Callback register mismatch')

first=re.search(r'(?m)^(\s*)(55dc5e0):(\s*)(48)(\s+89\s+d0)',listing)
corruptions={
    'listing-byte':listing[:first.start(4)]+'49'+listing[first.end(4):],
    'listing-address':listing[:first.start(2)]+'55dc5e1'+listing[first.end(2):],
    'listing-padding-gap':'\n'.join(line for line in listing.splitlines() if not re.match(r'^\s*55dc61b:',line)),
}
for label,text in corruptions.items():
    folder=OUT/label;folder.mkdir(mode=0o700);(folder/'native-mutated.stdout').write_text(text)
    reject(label,'changed listing only',lambda:subject.parse_native_listing(text,tests.START,raw))
lines=listing.splitlines();at=next(i for i,line in enumerate(lines) if re.match(r'^\s*55dc5f8:',line));lines[at]=lines[at].replace('0x55dc778','0x55dc779')
text='\n'.join(lines);folder=OUT/'listing-branch-target';folder.mkdir(mode=0o700);(folder/'native-mutated.stdout').write_text(text)
changed_rows=subject.parse_native_listing(text,tests.START,raw)
reject('listing-branch-target','authentic bytes, changed rendered target',lambda:subject.validate_constructor(raw,changed_rows),'raw displacement')
pin(CHECKOUT/'tests/test_huf_fast_state_init.py',TEST_SHA);pin(CHECKOUT/'tools/huf_fast_state_init.py',TOOL_SHA);pin(provider,tests.OBJDUMP_SHA)
if len(records)!=33:raise AssertionError('Complete independent control count')
report={'schema':'actual-static-constructor-control-ledger-v1','status':'PASS','controls':records,'count':len(records),'constructor_actual_byte_negatives':21,'wrapper_actual_byte_negatives':4,'wrapper_rendered_operand_negatives':4,'constructor_listing_negatives':4,'test_sha256':TEST_SHA,'tool_sha256':TOOL_SHA,'objdump_sha256':tests.OBJDUMP_SHA,'constructor_sha256':tests.SPAN_SHA,'input_admission':'previously authenticated intake span/cuts, exact independent SHA rechecked; no fresh full-image admission claimed','captured_or_compatible_assembly_executed':False,'compiler_executed':False,'new_rust_implementation_read':False,'callback_raw_controls_reject_at_context_admission':True,'callback_rendered_controls_exercise_used_consumer_checks':True,'actual_inputs_preserved':True}
dump(OUT/'CONTROL-LEDGER.json',report)
manifest={str(path.relative_to(OUT)):{'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())} for path in sorted(OUT.rglob('*')) if path.is_file()}
dump(OUT/'MANIFEST.json',manifest)
print(json.dumps({'output':str(OUT),'controls':len(records),'ledger_sha256':sha((OUT/'CONTROL-LEDGER.json').read_bytes()),'manifest_sha256':sha((OUT/'MANIFEST.json').read_bytes()),'files':len(manifest)},sort_keys=True))
