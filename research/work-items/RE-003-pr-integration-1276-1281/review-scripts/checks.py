import concurrent.futures,hashlib,json,os,pathlib,re,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';changes=json.loads((b/'full-file-changes.json').read_text());tests=[pathlib.Path(s.split('\t')[1]).name for rows in changes.values()for s in rows if '\ttests/test_'in s];jobs=[(n,[sys.executable,'-m','unittest','discover','-s','tests','-p',n,'-v'])for n in tests];jobs += [('repository',['make','doctor','verify','catalogue-check'])];results=[]
def run(job):
 name,cmd=job;start=time.monotonic();log=b/(name+'.log');env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH'])
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,env=env,stdout=h,stderr=subprocess.STDOUT)
 raw=log.read_bytes();counts=re.findall(rb'^Ran (\d+) tests? in ',raw,re.M);x={'name':name,'command':cmd,'returncode':p.returncode,'seconds':round(time.monotonic()-start,2),'tests':int(counts[-1])if counts else None,'log_sha256':hashlib.sha256(raw).hexdigest()}
 if name in tests:x['source_sha256']=hashlib.sha256((r/'tests'/name).read_bytes()).hexdigest()
 return x
with concurrent.futures.ThreadPoolExecutor(max_workers=6)as ex:
 for x in ex.map(run,jobs):results.append(x);(b/'checks.json').write_text(json.dumps(results,indent=2)+'\n');print(x['name'],x['returncode'],x['tests'],flush=True)
raise SystemExit(any(x['returncode']for x in results))
