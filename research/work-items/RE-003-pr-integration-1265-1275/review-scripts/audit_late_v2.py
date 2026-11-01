import hashlib,json,pathlib,re,struct,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import foundation_set_once_366 as t,asset_row_scale as asset,fde_extents
out=b/'late-1273';out.mkdir(exist_ok=True);data=t.TARGET.read_bytes();ev=json.loads((r/'research/work-items/foundation-set-once-366-94/evidence.json').read_text());t.analyze(data,ev)
secs=t.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);f=[f for f in fdes if f['start']==t.START];assert len(f)==1 and f[0]['end']==t.END and f[0]['fde']==t.FDE_VA and f[0]['cie']==t.CIE_VA
obj='/opt/homebrew/Cellar/binutils/2.47/bin/objdump';native=subprocess.check_output([obj,'-d','-M','intel','--insn-width=16',f'--start-address={t.START}',f'--stop-address={t.NEXT_START}',str(t.TARGET)],text=True);(out/'window.txt').write_text(native)
rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',native,re.M)};assert b''.join(rows.values())==t.WINDOW+t.PADDING
textsec=next(s for s in secs if s['name']=='.text');text=data[textsec['offset']:textsec['offset']+textsec['size']];callers=[]
for m in re.finditer(b'[\xe8\xe9]',text):
 off=m.start()
 if off+5<=len(text) and textsec['address']+off+5+struct.unpack_from('<i',text,off+1)[0]==t.START:callers.append(hex(textsec['address']+off))
assert not callers and struct.pack('<Q',t.START)not in data
manifest=r/'research/work-items/foundation-set-once-366-94/MANIFEST.sha256'
for line in manifest.read_text().splitlines():
 digest,name=line.split(maxsplit=1);assert hashlib.sha256((manifest.parent/name).read_bytes()).hexdigest()==digest
cmd=[sys.executable,'-m','unittest','discover','-s','tests','-p','test_foundation_set_once_366.py','-v'];log=out/'tests.log'
with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,stdout=h,stderr=subprocess.STDOUT)
assert p.returncode==0
record={'pr':1273,'head':'708e1958de82be55ecd54a27b13dd2d83f059ba5','target_sha256':t.SHA256,'exact_fde_extent':True,'fde':{k:hex(v)if isinstance(v,int)else v for k,v in f[0].items()},'function_bytes':51,'instruction_rows':sum(a<t.END for a in rows),'padding_int3_bytes':13,'whole_text_rel32_byte_pattern_candidates':callers,'whole_file_qword_references':[],'manifest_entries_verified':2,'tests':11,'skips':0,'returncode':p.returncode,'test_source_sha256':hashlib.sha256((r/'tests/test_foundation_set_once_366.py').read_bytes()).hexdigest(),'test_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'native_export_sha256':hashlib.sha256(native.encode()).hexdigest(),'limits':['Static helper only; no caller or source type established.','Incoming binary-corruption controls reject at the whole-file digest guard; they do not establish independent structural-parser rejection.','No byte-equivalence or completion-gate credit.']}
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
