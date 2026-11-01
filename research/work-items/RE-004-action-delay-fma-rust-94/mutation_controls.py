import os,subprocess,tempfile,shutil,json,hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[3];crate=root/'src/node94-action-delay';results=[]
mutations=[('mode1', 'if raw_mode < 2','if raw_mode < 1'),('unfused','input.mul_add(10_000.0, bias)','(input * 10_000.0) + bias'),('signed_tail','raw >= 100_000_000 || raw.wrapping_sub(10_000) < 100_000','raw_action >= 100_000_000 || (10_000..110_000).contains(&raw_action)'),('clamp_infinity','if !value.is_finite() {','if value.is_nan() {')]
with tempfile.TemporaryDirectory(prefix='hype-delay-mutants-') as td:
 for label,old,new in mutations:
  dest=Path(td)/label;shutil.copytree(crate,dest);p=dest/'src/lib.rs';s=p.read_text();assert s.count(old)==1;p.write_text(s.replace(old,new))
  env=dict(os.environ,CARGO_TARGET_DIR=td+'/build')
  r=subprocess.run(['cargo','test','--offline','--locked','--manifest-path',str(dest/'Cargo.toml'),'--test','target'],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  assert r.returncode!=0 and 'test result: FAILED' in r.stdout,(label,r.stdout)
  fails=[l.strip() for l in r.stdout.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
  results.append(dict(mutation=label,replacement=new,returncode=r.returncode,failed_tests=fails))
(root/'research/work-items/RE-004-action-delay-fma-rust-94/mutations.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
