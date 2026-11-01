import concurrent.futures,hashlib,json,os,subprocess
from pathlib import Path
base=Path(__file__).resolve().parent;root=base.parent/'merge-latest-1153-1160/integration';out=base/'static';out.mkdir(exist_ok=True)
changes=json.loads((base/'full-file-changes.json').read_text());env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH'])
jobs=[]
for pr,rows in changes.items():
 paths=[Path(r.split('\t',1)[1])for r in rows]
 for tool in [p for p in paths if p.parent==Path('tools')and p.stem.startswith('foundation_')]:
  evidence=next(p for p in paths if p.name=='evidence.json');jobs.append((tool.stem,[tool,'--check',evidence],None))
 if int(pr)in(1191,1192,1198,1200):
  for p in paths:
   if p.name in ('verify.py','independent_verify.py'):jobs.append((pr+'-'+p.stem,[p],None))

def run(job):
 label,args,compare=job;p=subprocess.run(['/opt/miniconda3/bin/python3',*map(str,args)],cwd=root,env=env,capture_output=True,timeout=300)
 (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
 r=dict(label=label,argv=list(map(str,args)),exit_code=p.returncode,stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),stderr_sha256=hashlib.sha256(p.stderr).hexdigest())
 if compare and p.returncode==0:r['json_equal']=json.loads(p.stdout)==json.loads((root/compare).read_text())
 return r
results=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:
 for r in pool.map(run,jobs):
  results.append(r);(base/'static-checks.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(r),flush=True)
raise SystemExit(any(r['exit_code'] or r.get('json_equal') is False for r in results))
