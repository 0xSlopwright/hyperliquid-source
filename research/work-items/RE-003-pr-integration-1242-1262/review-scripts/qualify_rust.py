import concurrent.futures,json,os,subprocess,time
from pathlib import Path
root=Path.cwd(); out=Path(__file__).resolve().parent/'rust';out.mkdir(exist_ok=True)
def qualify(name):
 manifest='src/'+name+'/Cargo.toml'; results=[]
 env=os.environ|{'CARGO_BUILD_JOBS':'2','RUST_TEST_THREADS':'2','CARGO_TARGET_DIR':str(out/name)}
 commands=[['fmt','--manifest-path',manifest,'--','--check'],['build','--offline','--locked','--manifest-path',manifest],['test','--offline','--locked','--manifest-path',manifest],['test','--offline','--locked','--release','--manifest-path',manifest],['clippy','--offline','--locked','--manifest-path',manifest,'--all-targets','--','-D','warnings'],['build','--offline','--locked','--release','--target','x86_64-unknown-linux-gnu','--manifest-path',manifest]]
 for i,args in enumerate(commands):
  cmd=['cargo','+1.94.1',*args];log=out/f'{name}-{i}.log';t=time.monotonic()
  with log.open('wb') as handle:r=subprocess.run(cmd,cwd=root,env=env,stdout=handle,stderr=subprocess.STDOUT)
  results.append({'command':cmd,'exit_code':r.returncode,'seconds':round(time.monotonic()-t,3),'log':log.name})
 print(name,json.dumps(results),flush=True);return {'component':name,'results':results}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
 results=list(pool.map(qualify,['node94-tcp-frame','node94-orderbook','node94-margin-risk']))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
