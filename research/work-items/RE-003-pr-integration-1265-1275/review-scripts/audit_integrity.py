import hashlib,json,pathlib,re,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
changes=json.loads((b/'full-file-changes.json').read_text()); records=[]
for pr,changeset in changes.items():
 for c in changeset:
  p=r/c.split('\t',1)[1]
  if p.name=='MANIFEST.sha256':
   matches=[]
   for line in p.read_text().splitlines():
    if not line.strip():continue
    digest,name=line.split(maxsplit=1);name=name.lstrip('*');candidates=list(dict.fromkeys([p.parent/name,r/name]));valid=[q for q in candidates if q.is_file() and sha(q)==digest]
    assert len(valid)==1,(p,name)
    matches.append({'file':str(valid[0].relative_to(r)),'sha256':digest})
   records.append({'pr':int(pr),'manifest':str(p.relative_to(r)),'files':matches})
p=r/'research/work-items/RE-013-visor-shell-command';v=json.loads((p/'VALIDATION.json').read_text());m=v['manifestExcludingThisFile']
for name,digest in m.items():assert sha(p/name)==digest,name
records.append({'pr':1266,'manifest':str((p/'VALIDATION.json').relative_to(r)),'files':[{'file':str((p/n).relative_to(r)),'sha256':d}for n,d in m.items()]})
old=json.loads((p/'observed/summary.json').read_text());new=json.loads((b/'visor-host/observed/summary.json').read_text());different={k for k in old if old[k]!=new.get(k)}
assert different=={'versions'},different
assert (b/'visor-host/verification.json').read_bytes()==(b/'visor-host/verification-optimized.json').read_bytes()
fresh=b/'regenerated/asset_row_scale_cli';oldasset=r/'research/work-items/RE-004-asset-row-scale-94';asset=[]
for f in sorted(fresh.iterdir()):
 assert f.read_bytes()==(oldasset/f.name).read_bytes(),f
 asset.append({'file':f.name,'sha256':sha(f),'equal':True})
assert len(asset)==2
report={'manifests':records,'visor':{'target_facts_unchanged':True,'summary_differences':sorted(different),'normal_and_optimized_receipts_equal':True,'host_provider_override':'GNU 2.47.20260726 / LLVM 22.1.4; original pin GNU 2.42 / LLVM 18.1.3 retained.'},'asset_cli':{'exit_code':0,'command':'python3 tools/asset_row_scale.py --out work/review/asset_row_scale','files':asset,'note':'Documented CLI invocation. Initial generic review adapter used main(argv), which this CLI does not accept; retained as review-adapter failure, not a repository defect.'}}
(b/'integrity.json').write_text(json.dumps(report,indent=2)+'\n');print('manifests',len(records),'entries',sum(len(x['files'])for x in records),'visor host facts equal; asset CLI reproduced exactly')
