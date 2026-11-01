import hashlib,json,pathlib,subprocess,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';manifest='src/node94-consensus-admission/Cargo.toml';commands=[['cargo','+1.94.1','fmt','--manifest-path',manifest,'--check'],['cargo','+1.94.1','test','--manifest-path',manifest,'--offline','--locked'],['cargo','+1.94.1','test','--manifest-path',manifest,'--offline','--locked','--release'],['cargo','+1.94.1','clippy','--manifest-path',manifest,'--offline','--locked','--all-targets','--','-D','warnings']];results=[]
for i,cmd in enumerate(commands):
 log=b/f'rust-{i}.log';start=time.monotonic()
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,stdout=h,stderr=subprocess.STDOUT)
 x={'command':cmd,'returncode':p.returncode,'seconds':round(time.monotonic()-start,2),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()};results.append(x);(b/'rust-checks.json').write_text(json.dumps(results,indent=2)+'\n');print(i,p.returncode,flush=True)
raise SystemExit(any(x['returncode']for x in results))
