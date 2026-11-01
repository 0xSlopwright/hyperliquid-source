import hashlib,json,shutil,subprocess
from pathlib import Path

root=Path.cwd();base=Path(__file__).resolve().parent;out=base/'hex-rust';out.mkdir(exist_ok=True)
component=root/'src/node94-prefixed-hex';peer=root/'research/work-items/RE-005-prefixed-hex-rust-94/independent-peer'
compiler=Path(subprocess.check_output(['rustup','which','--toolchain','1.94.1','rustc'],text=True).strip())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
calls=[]
def run(label,args,expected=0):
    r=subprocess.run([str(x) for x in args],capture_output=True)
    (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
    calls.append(dict(label=label,argv=[str(x).replace(str(root),'<repo>').replace(str(base),'<review-output>')for x in args],exit_code=r.returncode,stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest()))
    assert r.returncode==expected,(label,r.stderr.decode())
    return r.stdout
flags=['--edition=2021','-C','debuginfo=0']
expected=(component/'target-expected.txt').read_bytes()
for opt in ['0','3']:
    unit=out/('unit-'+opt)
    run('compile-unit-'+opt,[compiler,*flags,'-C','opt-level='+opt,'--test',component/'lib.rs','-o',unit])
    run('unit-'+opt,[unit])
    lib=out/('libnode94_prefixed_hex_'+opt+'.rlib')
    run('compile-library-'+opt,[compiler,*flags,'-C','opt-level='+opt,'--crate-type=rlib','--crate-name=node94_prefixed_hex',component/'lib.rs','-o',lib])
    driver=out/('driver-'+opt)
    run('compile-driver-'+opt,[compiler,*flags,'-C','opt-level='+opt,component/'input_only_driver.rs','--extern','node94_prefixed_hex='+str(lib),'-o',driver])
    assert run('driver-'+opt,[driver,component/'target-inputs.txt'])==expected
client=out/'independent-client'
run('compile-independent-client',[compiler,*flags,peer/'client.rs','--extern','node94_prefixed_hex='+str(lib),'-o',client])
assert run('independent-client',[client,peer/'INPUTS.txt'])==(peer/'EXPECTED.txt').read_bytes()
run('linux-library',[compiler,*flags,'--target=x86_64-unknown-linux-gnu','-C','opt-level=3','--crate-type=rlib','--crate-name=node94_prefixed_hex',component/'lib.rs','-o',out/'libhex_linux.rlib'])
text=(component/'lib.rs').read_text();mutants=[]
for name,needle,replacement in [
    ('uppercase-digits',"b'a' + (nibble - 10)","b'A' + (nibble - 10)"),
    ('omit-whole-first-byte','for (index, &byte) in input.iter().enumerate() {','for (index, &byte) in input.iter().enumerate() {\n        if index == 0 && trim_first_nibble && byte < 16 { continue; }'),
    ('trim-every-small-byte','index == 0 && trim_first_nibble && byte < 16','index < input.len() && trim_first_nibble && byte < 16')]:
    assert text.count(needle)==1
    directory=out/name;directory.mkdir(exist_ok=True);source=directory/'lib.rs';source.write_text(text.replace(needle,replacement));shutil.copyfile(component/'target-vectors.txt',directory/'target-vectors.txt')
    library=directory/'libnode94_prefixed_hex.rlib';driver=directory/'driver';unit=directory/'unit'
    run(name+'-compile-library',[compiler,*flags,'--crate-type=rlib','--crate-name=node94_prefixed_hex',source,'-o',library])
    run(name+'-compile-driver',[compiler,*flags,component/'input_only_driver.rs','--extern','node94_prefixed_hex='+str(library),'-o',driver])
    actual=run(name+'-driver',[driver,component/'target-inputs.txt'])
    mismatches=[(a,b) for a,b in zip(actual.splitlines(),expected.splitlines()) if a!=b]
    assert mismatches and all(a.split()[1]==b.split()[1]==b'ok' for a,b in mismatches)
    run(name+'-compile-unit',[compiler,*flags,'--test',source,'-o',unit]);run(name+'-unit',[unit],101)
    mutants.append(dict(name=name,normal_result_mismatches=len(mismatches),policy_result_mismatches=0))
record=dict(compiler={'sha256':sha(compiler),'version':subprocess.check_output([compiler,'-vV'],text=True)},scope='Explicit macOS Rust 1.94.1 provider override; not the contributor Linux compiler or its 103-payload recipe. Own reconstructed Rust only, no captured execution.',vectors_per_profile=2664,profiles=['debug','optimized'],independent_client_records=64,linux_x86_64_library_build=True,mutants=mutants,calls=calls)
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:v for k,v in record.items() if k!='calls'}))
