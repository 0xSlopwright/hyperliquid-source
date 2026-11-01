import csv,hashlib,importlib,json,pathlib,re,struct,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import elf_index,fde_extents,asset_row_scale as asset,perp_order_price_scale as price,evm_replace_path as evm
binary=r/'artifacts/node/94/hl-node';data=binary.read_bytes();assert hashlib.sha256(data).hexdigest()==asset.SHA;secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);out=b/'native';out.mkdir(exist_ok=True);cache={}
def native(start,end):
 if (start,end)not in cache:
  text=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(binary)],text=True);(out/f'{start:x}-{end:x}.txt').write_text(text);rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)};assert b''.join(rows.values())==asset.read_va(data,secs,start,end-start)
  cache[start,end]=(rows,hashlib.sha256(text.encode()).hexdigest())
 return cache[start,end]
def body(start,end,digest):
 actual=[f for f in fdes if f['start']==start and f['end']==end];assert len(actual)==1
 rows,export=native(start,end);assert hashlib.sha256(b''.join(rows.values())).hexdigest()==digest
 return {'start':hex(start),'end':hex(end),'bytes':end-start,'instruction_rows':len(rows),'exact_fde_extent':True,'sha256':digest,'native_export_sha256':export},rows
foundation=[]
for name in ['foundation_round_up_division','foundation_indexed_store_and_clear']:
 t=importlib.import_module(name);packet=r/'research/work-items'/(name.replace('_','-')+'-94');x=json.loads((packet/'evidence.json').read_text());items=[]
 for key in ['function','callee']:
  w=x[key];m,rows=body(int(w['start_va'],16),int(w['end_va_exclusive'],16),w['sha256']);m['kind']=key
  if key=='function':assert rows=={a:bytes.fromhex(v)for a,v in t.INSTR.items()}
  items.append(m)
 callers=[]
 for c in x['incoming']['direct_e8_callers']:
  site=int(c['site'],16);owners=[f for f in fdes if f['start']<=site<f['end']];assert len(owners)==1;f=owners[0];rows,export=native(f['start'],f['end']);raw=rows[site];assert raw[0]==0xe8 and site+5+struct.unpack('<i',raw[1:])[0]==int(x['function']['start_va'],16);callers.append(dict(site=hex(site),fde_start=hex(f['start']),fde_end=hex(f['end']),native_export_sha256=export))
 foundation.append({'tool':name,'bodies':items,'native_callers':callers})
x=json.loads((r/'research/work-items/RE-004-perp-price-option-scale-94/evidence.json').read_text());scaling=[]
for w in x['functions']+[x['display_function']]:
 m,rows=body(int(w['start'],16),int(w['end'],16),w['sha256']);branches=w['branches']
 for br in branches:
  va=br['va'];raw=bytes.fromhex(br['bytes']);assert rows[va]==raw
  size=len(raw);disp=struct.unpack('<b'if size==2 else '<i',raw[-1:]if size==2 else raw[-4:])[0];assert va+size+disp==br['taken']and va+size==br['fallthrough']
 m['native_branch_sites']=len(branches);scaling.append(m)
for start,digest in price.COPIES.items():assert any(w['start']==hex(start)and w['sha256']==digest for w in scaling)
e=json.loads((r/'research/work-items/RE-009-evm-replace-path-94/evidence.json').read_text());replacement=[];allrows={}
for w in e['functions']:
 m,rows=body(int(w['start'],16),int(w['end_exclusive'],16),w['sha256']);replacement.append(m);allrows.update(rows)
for va,pattern in evm.PINS.items():assert va in allrows and asset.read_va(data,secs,va,len(bytes.fromhex(pattern)))==bytes.fromhex(pattern)
for va in evm.CALLS+evm.BRANCHES:assert va in allrows
result={'target_sha256':asset.SHA,'foundation':foundation,'price_scaling':scaling,'overlap':'PRs 1276 and 1279 cover the same two 318-byte option helpers; counted once here. PR1279 additionally binds the display function and control walker.','evm_replacement':replacement,'evm_pins_at_native_instruction_starts':len(evm.PINS),'evm_edge_sites_at_native_instruction_starts':len(evm.CALLS)+len(evm.BRANCHES),'limits':'Native partitions, selected branch destinations, actual FDE extents and pinned bytes; not a complete CFG, source/ABI identity or all-input equivalence.'};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('native checks passed; unique bodies',len(cache))
