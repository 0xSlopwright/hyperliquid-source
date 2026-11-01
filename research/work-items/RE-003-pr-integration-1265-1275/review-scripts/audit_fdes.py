import hashlib,json,pathlib,re,struct,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import asset_row_scale as asset,elf_index,fde_extents
data=(r/'artifacts/node/94/hl-node').read_bytes();assert hashlib.sha256(data).hexdigest()==asset.SHA
secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);obj='/opt/homebrew/Cellar/binutils/2.47/bin/objdump';out=b/'fde-native';out.mkdir(exist_ok=True);cache={}
def native(start,end):
 key=(start,end)
 if key not in cache:
  text=subprocess.check_output([obj,'-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')],text=True)
  (out/f'{start:x}-{end:x}.txt').write_text(text)
  rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)}
  assert b''.join(rows.values())==asset.read_va(data,secs,start,end-start),(hex(start),hex(end))
  cache[key]=(rows,hashlib.sha256(text.encode()).hexdigest())
 return cache[key]
foundation=[]
for w in json.loads((b/'foundation-native/result.json').read_text())['windows']:
 start,end=int(w['start'],16),int(w['end'],16);exact=[f for f in fdes if f['start']==start and f['end']==end];assert len(exact)==1,w
 packet=w['tool'].replace('_','-')+'-94';e=json.loads((r/'research/work-items'/packet/'evidence.json').read_text());callers=[]
 for c in e.get('incoming',{}).get('direct_e8_callers',[]):
  site=int(c['site'] if isinstance(c,dict)else c,16);owners=[f for f in fdes if f['start']<=site<f['end']];assert len(owners)==1,hex(site)
  f=owners[0];rows,digest=native(f['start'],f['end']);insn=rows[site];assert len(insn)==5 and insn[0]==0xe8 and site+5+struct.unpack('<i',insn[1:])[0]==start
  callers.append({'site':hex(site),'fde_start':hex(f['start']),'fde_end':hex(f['end']),'native_export_sha256':digest,'target':hex(start),'instruction_start_verified':True})
 foundation.append(dict(w,exact_fde_extent=True,callers=callers))
assetrows=[]
for start,(end,digest)in asset.FUNCTIONS.items():
 assert len([f for f in fdes if f['start']==start and f['end']==end])==1
 rows,export=native(start,end);raw=b''.join(rows.values());assert hashlib.sha256(raw).hexdigest()==digest
 anchors=[]
 for va,pattern in asset.ANCHORS.items():
  if start<=va<end:
   assert va in rows and asset.read_va(data,secs,va,len(bytes.fromhex(pattern)))==bytes.fromhex(pattern)
   anchors.append(hex(va))
 assetrows.append({'start':hex(start),'end':hex(end),'bytes':len(raw),'instruction_rows':len(rows),'exact_fde_extent':True,'anchors_at_instruction_starts':anchors,'body_sha256':digest,'native_export_sha256':export})
report={'target_sha256':asset.SHA,'provider_sha256':hashlib.sha256(pathlib.Path(obj).read_bytes()).hexdigest(),'foundation':foundation,'asset':assetrows,'scope':'Native static instruction starts, bytes, direct call destinations and .eh_frame FDE extents; not original-source or runtime equivalence.'}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print('foundation exact FDEs',len(foundation),'native callers',sum(len(w['callers'])for w in foundation),'asset FDEs',len(assetrows),'asset instruction rows',sum(w['instruction_rows']for w in assetrows))
