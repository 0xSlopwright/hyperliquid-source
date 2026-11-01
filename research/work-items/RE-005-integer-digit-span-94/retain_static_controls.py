"""Retain actual bounded native controls only; no target instruction evaluator."""
from pathlib import Path
import hashlib,importlib.util,json,re,shutil,sys
ROOT=Path('/tmp/hl-integer-digit-span-20261101/checkout')
HERE=Path(__file__).resolve().parent
INTAKE=Path('/tmp/hl-primitive-value-intake-20261031/actual-selected-metadata')
OUT=HERE/'retained-static-controls'
TOOL_SHA='52fc43e05b1d0c9fa0f733437e687b5c4be666768c512975c7a4dc76e6020e85'
TEST_SHA='52cc90daf7122aea962b212c7cd6eee672a696e709639be8a6f6ec0fc29eb9a5'
DESIGN_SHA='7546391eadbcacd7387f7492f992181663071d718d861db36dc8c1e215d0e097'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path,expected):
 b=path.read_bytes()
 if sha(b)!=expected:raise ValueError('Pinned dependency changed: '+str(path))
 return b
def emit(path,obj):path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')
pin(ROOT/'tools/integer_digit_span_static.py',TOOL_SHA);pin(ROOT/'tests/test_integer_digit_span_static.py',TEST_SHA)
design=json.loads(pin(HERE/'NATIVE-CONTROL-DESIGN.json',DESIGN_SHA))
primary=pin(INTAKE/'0x1570470.bin','bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f')
selector=pin(INTAKE/'0x14f7660.bin','a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf')
tables=json.loads(pin(Path('/tmp/hl-primitive-value-intake-20261031/SELECTED-TABLES-AND-HELPERS.json'),'6a68407a3ca89994c5416032c3052e25aba52326a644e9357b75eb14b8d3ca86'))['tables']
pairs,lower,upper,prefix=[bytes.fromhex(tables[k]['raw']) for k in ('decimal-pairs','nibble-table-25','nibble-table-26','base16-prefix')]
sys.path.insert(0,str(ROOT/'tools'))
import integer_digit_span_static as subject
OUT.mkdir(mode=0o700)
records=[]

def native(label,raw,base):
 folder=OUT/label;folder.mkdir(mode=0o700)
 p=folder/'span.bin';p.write_bytes(raw);p.chmod(0o400)
 rows,text,provider=subject.decode_span(raw,base)
 (folder/'native.stdout').write_text(text);emit(folder/'native-rows.json',rows);emit(folder/'provider.json',provider)
 if p.read_bytes()!=raw:raise ValueError('Retained static input changed')
 return folder,rows,text

def reject(label,kind,call,extra=None):
 try:call()
 except subject.EvidenceError as error:
  records.append({'control':label,'kind':kind,'accepted':False,'rejection':str(error),**(extra or {})})
  return
 raise AssertionError('Unexpected counterfactual acceptance: '+label)

_,rows,listing=native('baseline-primary',primary,subject.PRIMARY_BASE)
proof=subject.prove_primary(primary,pairs,listing=listing)
_,_,context_listing=native('baseline-selector',selector,subject.SELECTOR_BASE)
subject.prove_selector(selector,lower,upper,prefix,listing=context_listing)
for control in design['controls']:
 base=control['body_start'];before=primary if base==subject.PRIMARY_BASE else selector
 proposed=bytearray(before);at=control['address']-base;old,new=bytes.fromhex(control['before']),bytes.fromhex(control['after'])
 if proposed[at:at+len(old)]!=old or len(old)!=len(new):raise ValueError('Frozen actual anchor changed')
 proposed[at:at+len(old)]=new;proposed=bytes(proposed)
 _,_,native_listing=native(control['label'],proposed,base)
 if base==subject.PRIMARY_BASE:call=lambda:subject.prove_primary(proposed,pairs,listing=native_listing)
 else:call=lambda:subject.prove_selector(proposed,lower,upper,prefix,listing=native_listing)
 reject(control['label'],'actual changed native bytes',call,{'address':control['address'],'before':control['before'],'after':control['after'],'changed_span_sha256':sha(proposed),'witness':control['witness']})

bad_pairs=bytearray(pairs);bad_pairs[1]=ord('1')
folder=OUT/'decimal-table-zero-second-byte';folder.mkdir(mode=0o700);(folder/'table.bin').write_bytes(bad_pairs)
reject(folder.name,'actual changed observed table',lambda:subject.prove_primary(primary,bytes(bad_pairs),listing=listing))
for name in ('lower','upper','prefix'):
 lo,up,pre=bytearray(lower),bytearray(upper),bytearray(prefix)
 if name=='lower':lo[10]=ord('A');changed=lo
 elif name=='upper':up[10]=ord('a');changed=up
 else:pre[1]=ord('X');changed=pre
 folder=OUT/(name+'-table');folder.mkdir(mode=0o700);(folder/'table.bin').write_bytes(changed)
 reject(folder.name,'actual changed observed table/prefix',lambda:subject.prove_selector(selector,bytes(lo),bytes(up),bytes(pre),listing=context_listing))

first=re.search(r'(?m)^([ \t]*)(0*1570470):([ \t]+)(55)(?=[ \t])',listing)
views={'listing-byte':listing[:first.start(4)]+'54'+listing[first.end(4):],
       'listing-address':listing[:first.start(2)]+'1570471'+listing[first.end(2):],
       'listing-padding-gap':'\n'.join(line for line in listing.splitlines() if not re.match(r'^\s*0*15704ac:',line))}
for name,text in views.items():
 folder=OUT/name;folder.mkdir(mode=0o700);(folder/'changed-listing.stdout').write_text(text)
 reject(name,'changed listing raw binding',lambda:subject.verify_listing(text,primary,subject.PRIMARY_BASE))
lines=listing.splitlines();index=next(i for i,line in enumerate(lines) if re.match(r'^\s*0*157048b:',line));lines[index]=lines[index].replace('0x1570567','0x1570568');text='\n'.join(lines)
folder=OUT/'rendered-target-nonauthoritative';folder.mkdir(mode=0o700);(folder/'changed-listing.stdout').write_text(text)
changed_proof=subject.prove_primary(primary,pairs,listing=text)
for key in ('parameters','cfg','store_sites','mathematics'):
 if changed_proof[key]!=proof[key]:raise ValueError('Rendered prose redirected raw proof')
records.append({'control':'rendered-target-nonauthoritative','kind':'unchanged authentic bytes; altered optional rendered branch prose','accepted':True,'semantic_parameters_CFG_stores_math_unchanged':True,'independent_disassembler_prose_rejection_claimed':False})
if len(records)!=37 or sum(r['accepted'] is False for r in records)!=36:raise ValueError('Actual control denominator')
pin(ROOT/'tools/integer_digit_span_static.py',TOOL_SHA);pin(ROOT/'tests/test_integer_digit_span_static.py',TEST_SHA);pin(HERE/'NATIVE-CONTROL-DESIGN.json',DESIGN_SHA)
provider=Path(shutil.which('objdump')).resolve()
report={'schema':'actual-digit-bounded-static-controls-v1','status':'PASS','controls':records,'total_observations':37,'rejected_negatives':36,'actual_byte_controls':29,'table_prefix_controls':4,'listing_byte_address_coverage_negatives':3,'nonauthoritative_prose_invariance_observations':1,'tool_sha256':TOOL_SHA,'test_sha256':TEST_SHA,'control_design_sha256':DESIGN_SHA,'observed_provider':{'path':str(provider),'sha256':sha(provider.read_bytes()),'scope':'Measured installed host provider; not atomic child-execution provenance'},'target_admission':'Previously full-digest-admitted intake tiny spans/tables, exact SHA rebound here; no fresh full-image admission by this retention script','source_and_control_inputs_unchanged':True,'actions':{'new_target_image_copy':False,'captured_code_or_instruction_interpreter':False,'compiler':False,'new_rust_read':False,'repository_edits_git_or_public_actions':False}}
emit(OUT/'CONTROL-LEDGER.json',report)
manifest={str(p.relative_to(OUT)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(OUT.rglob('*')) if p.is_file()};emit(OUT/'MANIFEST.json',manifest)
print(json.dumps({'output':str(OUT),'ledger_sha256':sha((OUT/'CONTROL-LEDGER.json').read_bytes()),'manifest_sha256':sha((OUT/'MANIFEST.json').read_bytes()),'payload_files':len(manifest),'payload_bytes':sum(v['bytes'] for v in manifest.values()),'rejections':36,'prose_invariance':1},sort_keys=True))
