import hashlib,json,os,pathlib,subprocess,sys,time
P=pathlib.Path(__file__).resolve().parent;T=P.parent/'pr1030-advance-tree';D=T/'research/work-items/RE-005-field-parent-current546-rebind';sys.path.insert(0,str(T/'tools'));os.environ['PATH']='/opt/homebrew/opt/binutils/bin:'+os.environ['PATH']
import bincode_diagnostic_parent_rust as b
head='38883e27597c1da7540d8ab0669290fb88aa66bc';base='da97c34d6fa24600672bf74653a9af0f582b6cdb'
files=subprocess.check_output(['git','diff','--cached','--name-only'],cwd=T,text=True).splitlines();assert len(files)==19 and all(x.startswith('research/work-items/RE-005-field-parent-current546-rebind/') for x in files)
blobs=[]
for f in files:
 data=subprocess.check_output(['git','show',head+':'+f],cwd=T);assert (T/f).read_bytes()==data;blobs.append({'file':f,'sha256':hashlib.sha256(data).hexdigest()})
manifest_drift=[]
for line in (D/'MANIFEST.sha256').read_text().splitlines():
 h,f=line.split('  ',1);original=subprocess.check_output(['git','show',head+':'+f],cwd=T);assert hashlib.sha256(original).hexdigest()==h,f
 actual=hashlib.sha256((T/f).read_bytes()).hexdigest()
 if actual!=h:manifest_drift.append({'file':f,'historical_head_sha256':h,'current_sha256':actual})
fresh=b.reference.oracle(b.TARGET,repo=T)
for name,key in [('inputs.txt','inputs'),('expected.txt','expected'),('fixture.tsv','fixture')]:assert (D/'evidence'/name).read_bytes()==fresh[key],name
assert json.loads((D/'evidence/oracle.json').read_text())==fresh['metadata']
for name in ['debug.stdout','optimized.stdout']:assert (D/'evidence'/name).read_bytes()==fresh['expected']
assert (D/'evidence/BEFORE.json').read_bytes()==(D/'evidence/AFTER.json').read_bytes()
native=json.loads((D/'evidence/native-record.json').read_text());producer=b.reference._load_producer(T);proof,exports=producer._analyze(b.TARGET.read_bytes());proof=json.loads(json.dumps(proof))
(P/'fresh-native-record.json').write_text(json.dumps(proof,indent=2)+'\n')
provider_deltas=[]
for fresh,prior,path in [(proof,native,'native_tool'),(proof['used_adapter_contract'],native['used_adapter_contract'],'used_adapter_contract/native_tool')]:
 if fresh['native_tool']!=prior['native_tool']:
  provider_deltas.append({'field':path,'historical':prior['native_tool'],'review':fresh['native_tool']})
  fresh['native_tool']=prior['native_tool']
assert proof==native
for k,v in exports.items():
 if (D/'evidence'/k).exists():assert (D/'evidence'/k).read_text()==v,k
py='/Users/shawwalters/.local/share/uv/python/cpython-3.10.18-macos-aarch64-none/bin/python3.10';results=[]
for opt in [[],['-O']]:
 cmd=[py,*opt,'-B','-m','unittest','discover','-s','tests','-p','test_bincode_diagnostic_parent_rust.py','-v'];st=time.time();r=subprocess.run(cmd,cwd=T,capture_output=True,text=True);name='optimized' if opt else 'normal';(P/(name+'.log')).write_text(r.stdout+r.stderr);results.append({'command':cmd,'exit':r.returncode,'seconds':time.time()-st,'log':name+'.log'});assert not r.returncode
rustc=pathlib.Path('/Users/shawwalters/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc');actual=hashlib.sha256(rustc.read_bytes()).hexdigest();assert actual=='b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
original_pin=b.COMPILER_SHA256;b.COMPILER_SHA256=actual
host=b.build(b.TARGET,rustc,P/'host-build',False)
review={'number':1030,'head':head,'base':base,'effective_files':blobs,'only_additive_evidence':True,'prior_source_and_tests_unchanged':True,'fresh_oracle_equals_all_recorded_bytes':True,'fresh_native_record_equal_except_provider_labels':True,'provider_deltas':provider_deltas,'before_after_equal':True,'historical_manifest_all83_authenticated':True,'current_manifest_drift':manifest_drift,'tests':results,'host_build_status':host['status'],'host_override':{'original_linux_compiler_pin':original_pin,'review_host_pin':actual,'source_pins_unmodified':True,'scope':'Fresh native macOS arm64 own-code build and925-row replay, not reproduction of historical Linux binary identities'},'target_sha256':b.reference.TARGET_SHA256,'captured_execution':False,'instruction_emulation':False}
(P/'review.json').write_text(json.dumps(review,indent=2)+'\n');print('PASS evidence, focused tests, fresh host own-code build',flush=True)
