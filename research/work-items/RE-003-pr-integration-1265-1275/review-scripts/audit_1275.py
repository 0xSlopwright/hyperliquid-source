import hashlib,json,os,pathlib,re,struct,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import state_wrapper_read as t,asset_row_scale as asset,elf_index,fde_extents
out=b/'late-1275';out.mkdir(exist_ok=True);fresh=out/'generated';env=dict(os.environ,PYTHONHASHSEED='17',TZ='UTC')
p=subprocess.run([sys.executable,'tools/state_wrapper_read.py','--out',str(fresh)],cwd=r,env=env,capture_output=True);(out/'generator.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0
packet=r/'research/work-items/RE-009-state-wrapper-read-94';assert (fresh/'records.json').read_bytes()==(packet/'records.json').read_bytes();record=json.loads((fresh/'records.json').read_text());data=t.BINARY.read_bytes();assert hashlib.sha256(data).hexdigest()==t.DIGEST;secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);allrows={};bodies=[]
for f in record['functions']:
 start,end=int(f['start'],16),int(f['end'],16);actual=[x for x in fdes if x['start']==start and x['end']==end and x['fde']==int(f['fde'],16)];assert len(actual)==1
 native=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(t.BINARY)],text=True);(out/f'{start:x}.txt').write_text(native)
 rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',native,re.M)};raw=b''.join(rows.values());assert raw==asset.read_va(data,secs,start,end-start)and hashlib.sha256(raw).hexdigest()==f['sha256'];allrows.update(rows)
 bodies.append({**f,'exact_fde_extent':True,'instruction_rows':len(rows),'native_export_sha256':hashlib.sha256(native.encode()).hexdigest()})
for pin in record['pins']+record['loader_pins']:
 site=int(pin['site'],16);raw=bytes.fromhex(pin['bytes']);assert site in allrows and t.at(data,site,len(raw))==raw,pin
for edge in record['edges']+record['entry_edges']:
 site=int(edge['site'],16);raw=allrows[site];assert raw[0]==0xe8 or raw[:2]in (b'\x0f\x84',b'\x0f\x85');target=site+len(raw)+struct.unpack('<i',raw[-4:])[0];assert target==int(edge['target'],16),edge
matched=[];missing=[]
for table in record['tables']:
 for side,base in [('left',t.PARSERS[0]),('right',t.PARSERS[1])]:
  addr=int(table[side],16);targets=[addr+n[0]for n in struct.iter_unpack('<i',t.at(data,addr,table['entries']*4))]
  for target in targets:
   (matched if target in allrows else missing).append({'table':hex(addr),'target':hex(target)})
for line in (packet/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split(maxsplit=1);assert hashlib.sha256((packet/name).read_bytes()).hexdigest()==digest
result={'pr':1275,'head':'85c9a4cf9aa972a042b8fddb2a1fdb7b1250ef80','target_sha256':t.DIGEST,'reproduced_files':1,'records_sha256':hashlib.sha256((fresh/'records.json').read_bytes()).hexdigest(),'manifest_entries_verified':2,'bodies':bodies,'pins_at_native_instruction_starts':len(record['pins'])+len(record['loader_pins']),'native_branch_and_call_sites':len(record['edges'])+len(record['entry_edges']),'paired_table_offsets':518,'table_targets_at_native_instruction_starts':len(matched),'table_targets_not_at_native_instruction_starts':missing,'limits':['Byte partitions and selected target starts are static checks, not reachable-tag, complete CFG or runtime equivalence.','Nested child decoder and unknown-key helper remain opaque.','Incoming table-corruption test rejects at the digest guard, not an independent table-structure control.']};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
