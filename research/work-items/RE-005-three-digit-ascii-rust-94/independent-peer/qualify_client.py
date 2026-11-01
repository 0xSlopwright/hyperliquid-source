from pathlib import Path
import json,hashlib,subprocess,os,time,datetime
P=Path(__file__).parent
A=Path('/tmp/hl-three-digit-ascii-rust-20261101/component-attempt-1')
R=Path('/tmp/hl-three-digit-ascii-rust-20261101/checkout')
O=P/'actual-client-run'
O.mkdir(mode=0o700)
(O/'tmp').mkdir(mode=0o700)
def h(p):
 value=hashlib.sha256()
 with Path(p).open('rb') as stream:
  for block in iter(lambda:stream.read(1<<20),b''): value.update(block)
 return value.hexdigest()
report=A/'RESULT.json'
assert h(report)=='349032293044d63811f7765c522bb8179252280ab1012682ce673400211d0ae8'
d=json.loads(report.read_text())
assert d['status']=='PASS' and d['before_after_equal'] and d['commands']==29 and d['raw_streams']==58
assert (A/'BEFORE.json').read_bytes()==(A/'AFTER.json').read_bytes()
profile=next(x for x in d['profiles'] if x['name']=='optimized')
lib=Path(profile['library'])
assert h(lib)==profile['library_sha256']=='90e6fef72a4db3e3b91bbfe79e2ca6492e8215290f59990b54cf1b57082388cc'
command=next(x for x in d['calls'] if x['label']=='optimized-client-build')['argv'][:]
old_driver=str(R/'src/node94-three-digit-ascii/input_only_driver.rs')
assert old_driver in command and '--test' not in command
command[command.index(old_driver)]=str(P/'client.rs')
command[command.index('--crate-name')+1]='independent_three_digit_peer'
program=O/'independent-client'
command[command.index('-o')+1]=str(program)
assert 'node94_three_digit_ascii='+str(lib) in command
rustc=Path(command[0])
linker=Path(d['linker']['path'])
assert h(rustc)==d['compiler']['sha256']=='ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
assert h(linker)==d['linker']['sha256']
watched=[P/'client.rs',P/'INPUTS.txt',P/'EXPECTED.txt',P/'EXPECTATIONS-FREEZE.json',P/'OWN-CLIENT-SOURCE-FREEZE.json',P/'SOURCE-AND-CLIENT-PROTOCOL-PEER.json',lib,rustc,linker,R/'src/node94-three-digit-ascii/lib.rs',R/'src/node94-three-digit-ascii/input_only_driver.rs']
before={str(p):{'bytes':p.stat().st_size,'sha256':h(p)} for p in watched}
assert before[str(P/'client.rs')]['sha256']=='c20644a35b1f6d23deb43902d62493c5f84ed629024d9273eee53ee1c87766ce'
assert before[str(R/'src/node94-three-digit-ascii/lib.rs')]['sha256']=='f74f7d0c2cb9a86deee5e7fc2976afb42d39b4b8829a018df8cc36ab27db05ed'
(O/'BEFORE.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
maximum=Path('/sys/fs/cgroup/memory.max').read_text().strip()
headroom=int(maximum)-int(Path('/sys/fs/cgroup/memory.current').read_text()) if maximum.isdigit() else None
assert headroom is None or headroom>256<<20
# Same concrete author driver flags; only client source/name/output differ.
environment=dict(d['environment'])
environment['TMPDIR']=str(O/'tmp')
calls=[]
def run(label,argv):
 start=time.monotonic()
 process=subprocess.run(argv,cwd=P,env=environment,stdin=subprocess.DEVNULL,capture_output=True)
 for name in ('stdout','stderr'): (O/(label+'.'+name)).write_bytes(getattr(process,name))
 row={'label':label,'argv':argv,'cwd':str(P),'exit':process.returncode,'seconds':time.monotonic()-start,'stdout_sha256':h(O/(label+'.stdout')),'stderr_sha256':h(O/(label+'.stderr'))}
 calls.append(row)
 (O/'CALLS.json').write_text(json.dumps(calls,indent=2,sort_keys=True)+'\n')
 assert process.returncode==0,(label,process.stderr.decode(errors='replace'))
 return process
run('compile-own-client',command)
actual=run('runtime-input-only',[str(program),str(P/'INPUTS.txt')]).stdout
wanted=(P/'EXPECTED.txt').read_bytes()
assert actual==wanted and len(actual.splitlines())==64
rows=actual.decode('ascii').splitlines()
inputs=json.loads((P/'STIMULI.json').read_text())
assert [line.split()[0] for line in rows]==[x['id'] for x in inputs]
assert len(rows)==64 and sum(int(line.split()[1])!=0 for line in rows)==21
assert len({int(line.split()[1]) for line in rows if int(line.split()[1])})==12
after={str(p):{'bytes':p.stat().st_size,'sha256':h(p)} for p in watched}
(O/'AFTER.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
assert before==after
result={'schema':'three-digit-independent-linked-client-run-v1','status':'PASS_ONE_SMALL_CLIENT_LINK_AND64_FROZEN_RUNTIME_INPUT_RECORDS','at_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'compiler':d['compiler'],'linker':d['linker'],'author_component_receipt_sha256':h(report),'matching_rlib':{'path':str(lib),'bytes':lib.stat().st_size,'sha256':h(lib)},'author107_or_103prefix_audit':'Reused exactauthor source/prefix/linker before/after records; independently rehashed invokedrustc/linker/library/source/data here. No freshwholeprefix hash or target read.','source_and_input_before_after_equal':True,'before_sha256':h(O/'BEFORE.json'),'after_sha256':h(O/'AFTER.json'),'executable_sha256':h(program),'environment':environment,'headroom_before_bytes':headroom,'actual_calls':calls,'new_library_builds':0,'new_client_compiles':1,'actual_client_runs':1,'records':64,'stdout_sha256':hashlib.sha256(actual).hexdigest(),'expected_sha256':hashlib.sha256(wanted).hexdigest(),'all_IDs_order_and_multiplicity_exact':True,'nonzero_rows':21,'distinct_valid_values':12,'all_valid_values_already_author_covered':True,'controls':'18malformed triples,16wronglength,18poisoned contexts and12already-coveredvalid rows; ownclient checksfullbacking bytes unchanged.','new_invalid_bytevectors_vs_author':28,'protocol_comparator_negatives':'7pureoutputmutations recorded separately inead4sourcepeer; notcompiledsemanticmutants.','native_relation_peer_sha256':h(P/'PRE-RUST-NATIVE-RELATION-PEER.json'),'pre_Rust_expectations_sha256':h(P/'EXPECTATIONS-FREEZE.json'),'client_pre_source_read_freeze_sha256':h(P/'OWN-CLIENT-SOURCE-FREEZE.json'),'postfreeze_input_overlap_sha256':h(P/'POSTFREEZE-INPUT-OVERLAP.json'),'no_target_original_compatible_object_emulator_or_newfamily_execution':True,'limits':['Safe slice value projection only; no native fault/invalidpointer/readtrace/ABI/originalcompiler/fullcaller/gate claim.','Compiled only thisindependentclient againstexistingownlibrary; no duplicate library or flaggrid.','Source/tool audits are observedbefore/after understablehost assumption, notatomic hostile-host guarantees.']}
p=O/'INDEPENDENT-CLIENT-RESULT.json'
p.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({'status':result['status'],'receipt':str(p),'sha256':h(p),'rows':64,'rlib_sha256':h(lib),'stdout_sha256':result['stdout_sha256'],'client_sha256':h(program),'headroom_before':headroom},indent=2))
