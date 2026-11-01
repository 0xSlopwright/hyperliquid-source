import hashlib,json,pathlib,re,struct,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import foundation_devirtualized_getter as t,asset_row_scale as asset,elf_index,fde_extents
out=b/'late-1274';out.mkdir(exist_ok=True);data=(r/'artifacts/node/94/hl-node').read_bytes();assert hashlib.sha256(data).hexdigest()==asset.SHA;secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);eh=next(s for s in secs if s['name']=='.eh_frame');packet=r/'research/work-items/foundation-devirtualized-getter-94';ev=json.loads((packet/'evidence.json').read_text());bodies=[]
for key,table in [('function',t.INSTR),('getter',t.GETTER_INSTR)]:
 field=ev[key];start=int(field['start_va'],16);end=int(field['end_va_exclusive'],16);f=[x for x in fdes if x['start']==start];assert len(f)==1 and f[0]['end']==end and f[0]['fde']-eh['address']==int(field['fde_section_offset'],16) and f[0]['cie']-eh['address']==int(field['fde_cie'],16)
 nxt=[x for x in fdes if x['start']==int(field['next_fde_start'],16)];assert len(nxt)==1 and nxt[0]['fde']-eh['address']==int(field['next_fde_section_offset'],16) and nxt[0]['cie']-eh['address']==int(field['next_fde_cie'],16)
 native=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')],text=True);(out/(key+'.txt')).write_text(native)
 rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',native,re.M)};assert rows=={a:bytes.fromhex(s)for a,s in table.items()};raw=b''.join(rows.values());assert raw==asset.read_va(data,secs,start,end-start)
 bodies.append({'label':key,'start':hex(start),'end':hex(end),'bytes':len(raw),'instruction_rows':len(rows),'exact_fde_extent':True,'native_export_sha256':hashlib.sha256(native.encode()).hexdigest()})
rela=next(s for s in secs if s['name']=='.rela.dyn');relocs=[]
for off in range(rela['offset'],rela['offset']+rela['size'],24):
 slot,info,addend=struct.unpack_from('<QQq',data,off)
 if slot==t.GLOBAL_SLOT:relocs.append({'slot':hex(slot),'type':info&0xffffffff,'symbol':info>>32,'addend':hex(addend)})
assert relocs==[{'slot':'0x5778020','type':8,'symbol':0,'addend':'0x4fa7e80'}]
for line in (packet/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split(maxsplit=1);assert hashlib.sha256((packet/name).read_bytes()).hexdigest()==digest
report={'pr':1274,'head':'83a906ec267f2f2abae8fe3cf7b225ee9e1172cb','target_sha256':asset.SHA,'bodies':bodies,'relocations':relocs,'manifest_entries_verified':4,'limits':['No virtual-fallback callee behavior or type/caller identity established.','Original frame checker matches retained text; this review independently checks actual .eh_frame FDE and CIE records.','Whole-corpus similarity and mnemonic singleton claims were not rerun; no census or completion credit assigned.']}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
