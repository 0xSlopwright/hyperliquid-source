import concurrent.futures,hashlib,json,os,subprocess,time
from pathlib import Path
base=Path(__file__).resolve().parent;root=base.parent/'merge-latest-1153-1160/integration'
changes=json.loads((base/'full-file-changes.json').read_text());records=[]
prs={'staking_core_writer':1268,'bridge_evm_block_step':1269,'set_global_oracle':1271,'asset_row_scale':1272}
child=base.parent/'merge-latest-1153-1160/packet_child.py'
env=dict(os.environ,PYTHONHASHSEED='17',TZ='UTC',PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH'])
def run(item):
 name,pr=item;out=base/'regenerated'/name;out.parent.mkdir(exist_ok=True);log=base/(name+'.log');start=time.monotonic()
 with log.open('w') as f:
  p=subprocess.run(['/opt/miniconda3/bin/python3',str(child),name,str(out)],cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=1200)
 files=[x.split('\t',1)[1]for x in changes[str(pr)] if '\tresearch/work-items/'in x];packet=root/Path(files[0]).parent
 results=[]
 if p.returncode==0:
  for fresh in sorted(out.rglob('*')):
   if fresh.is_file():
    rel=fresh.relative_to(out);old=packet/rel
    results.append(dict(file=str(rel),retained=old.is_file(),equal=old.is_file()and fresh.read_bytes()==old.read_bytes(),fresh_sha256=hashlib.sha256(fresh.read_bytes()).hexdigest()))
 return dict(tool=name,pr=pr,packet=str(packet.relative_to(root)),exit_code=p.returncode,seconds=round(time.monotonic()-start,2),files=results)
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:
 for r in pool.map(run,prs.items()):
  records.append(r);(base/'packet-reproduction.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({**{k:v for k,v in r.items()if k!='files'},'files':len(r['files']),'differences':[x['file']for x in r['files']if not x['equal']]}),flush=True)
raise SystemExit(any(r['exit_code']for r in records))
