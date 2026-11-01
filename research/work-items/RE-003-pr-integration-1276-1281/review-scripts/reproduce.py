import concurrent.futures,hashlib,json,os,pathlib,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';tasks=[('perp_order_price_scale','RE-004-perp-order-price-scale-94'),('evm_replace_path','RE-009-evm-replace-path-94'),('perp_price_option_scale','RE-004-perp-price-option-scale-94')];results=[]
def run(job):
 tool,packet=job;out=b/'generated'/tool;log=b/(tool+'.log');start=time.monotonic();env=dict(os.environ,PYTHONHASHSEED='17',TZ='UTC')
 with log.open('wb')as h:p=subprocess.run([sys.executable,f'tools/{tool}.py','--out',str(out)],cwd=r,env=env,stdout=h,stderr=subprocess.STDOUT)
 files=[]
 if p.returncode==0:
  for f in sorted(out.rglob('*')):
   if f.is_file():
    relative=f.relative_to(out);old=r/'research/work-items'/packet/relative;files.append({'file':str(relative),'equal':old.is_file()and old.read_bytes()==f.read_bytes(),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
 return {'tool':tool,'packet':packet,'returncode':p.returncode,'seconds':round(time.monotonic()-start,2),'files':files}
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as ex:
 for x in ex.map(run,tasks):results.append(x);(b/'reproduction.json').write_text(json.dumps(results,indent=2)+'\n');print(x['tool'],x['returncode'],len(x['files']),[f['file']for f in x['files']if not f['equal']],flush=True)
raise SystemExit(any(x['returncode']or any(not f['equal']for f in x['files'])for x in results))
