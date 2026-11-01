import hashlib,importlib,json,re,subprocess,sys
from pathlib import Path
base=Path(__file__).resolve().parent;root=base.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(root/'tools'))
changes=json.loads((base/'full-file-changes.json').read_text());provider=Path('/opt/homebrew/Cellar/binutils/2.47/bin/objdump');target=root/'artifacts/node/94/hl-node';out=base/'foundation-native';out.mkdir(exist_ok=True)
records=[]
for toolpath in [Path(x.split('\t',1)[1])for rows in changes.values()for x in rows if '\ttools/foundation_'in x]:
 t=importlib.import_module(toolpath.stem)
 if hasattr(t,'BODY'):start,end,raw=t.START,t.END,t.BODY
 else:start=min(t.INSTR);raw=b''.join(bytes.fromhex(t.INSTR[a])for a in sorted(t.INSTR));end=start+len(raw)
 native=subprocess.check_output([str(provider),'-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(target)],text=True)
 (out/(toolpath.stem+'.txt')).write_text(native)
 rows={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',native,re.M)}
 assert b''.join(rows.values())==raw
 if hasattr(t,'INSTR'):assert rows=={a:bytes.fromhex(v)for a,v in t.INSTR.items()}
 records.append(dict(tool=toolpath.stem,start=hex(start),end=hex(end),instruction_rows=len(rows),body_sha256=hashlib.sha256(raw).hexdigest(),export_sha256=hashlib.sha256(native.encode()).hexdigest()))
(out/'result.json').write_text(json.dumps(dict(provider_sha256=hashlib.sha256(provider.read_bytes()).hexdigest(),windows=records,limit='Native byte partitions and pinned static contract only; no complete component equivalence.'),indent=2)+'\n');print('native foundation windows:',len(records))
