#!/usr/bin/env python3
"""Qualify the independently authored capacity20 decimal suffix implementation.

The authenticated static producer supplies grouped arithmetic/pair expectations;
only our Rust library, input-only client and ordinary unit tests execute.
Captured target code and instruction emulators never execute here.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,time
import integer_digit_span_reference as reference

CRATE='node94_integer_digit_span'
COMPILER_SHA256='ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def file_digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb')as f:
        for raw in iter(lambda:f.read(1<<20),b''):h.update(raw)
    return h.hexdigest()

def mismatch_ids(actual,wanted):
    rows,expected=actual.splitlines(),wanted.splitlines()
    need(len(rows)==len(expected),'Production row count differs, not a normal semantic control')
    mismatches=[]
    for row,answer in zip(rows,expected):
        identifier=answer.split(b' ',1)[0]
        need(row.split(b' ',1)[0]==identifier,'Production case identities/order differ')
        if row!=answer:mismatches.append(identifier.decode('ascii'))
    return mismatches

def qualify(root,expected,source,fixture,rustc,output,harness,mutations,additional_sources=()):
    root,source,fixture,rustc,output=(Path(p).absolute()for p in(root,source,fixture,rustc,output))
    need(not output.exists(),'Output directory must be new; preserve previous evidence')
    need(fixture.read_bytes()==expected['fixture'],'Checked fixture differs from fresh static expectations')
    compiler_before=file_digest(rustc)
    need(compiler_before==COMPILER_SHA256,'Compiler differs from authenticated research1.94.1')
    linker=shutil.which('cc');need(linker is not None,'C linker driver cc is required')
    linker_before=file_digest(linker)
    inputs=tuple(sorted(p for p in source.parent.iterdir()if p.is_file() and p.suffix in {'.rs','.txt','.tsv'}))+tuple(map(Path,additional_sources))
    before={str(p):file_digest(p)for p in inputs}
    output.mkdir(parents=True,exist_ok=False)
    (output/'inputs.txt').write_bytes(expected['inputs']);(output/'expected.txt').write_bytes(expected['expected'])
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n')
    (output/'native-proof.json').write_text(json.dumps(expected['native_proof'],indent=2)+'\n')
    (output/'comparison-main.rs').write_text(harness)
    calls=[];environment=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    def execute(label,argv,required_exit=0):
        start=time.monotonic();p=subprocess.run([str(v)for v in argv],cwd=root,env=environment,stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+kind;(output/name).write_bytes(raw);logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(v)for v in argv],'exit_code':p.returncode,'seconds':round(time.monotonic()-start,3),'logs':logs})
        (output/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
        need(p.returncode==required_exit,label+' failed; exact raw streams retained')
        return p
    try:
        version=execute('rustc-identity',[rustc,'-vV']).stdout.decode()
        need(version.startswith('rustc 1.94.1 ')and'e408947bfd200af42db322daf0fadfe7e26d3bd1'in version,'Actual compiler full identity differs')
        linker_version=execute('linker-identity',[linker,'--version']).stdout.decode()
        def flags(opt):return ['--edition=2021','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','linker='+linker,'--remap-path-prefix',str(root)+'=/reconstruction']
        def library(label,src,opt,directory):
            directory.mkdir(parents=True,exist_ok=False);lib=directory/('lib'+CRATE+'.rlib')
            execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',src,'-o',lib,'-C','metadata=node94-integer-digit-span',*flags(opt)])
            return lib
        def production(label,lib,opt,directory):
            program=directory/'production'
            execute(label+'-link',[rustc,'--crate-name','digit_span_comparison',output/'comparison-main.rs','--extern',CRATE+'='+str(lib),'-o',program,*flags(opt)])
            raw=execute(label+'-run',[program,output/'inputs.txt']).stdout
            return program,raw
        def ordinary_tests(label,src,opt,directory,failed=False):
            program=directory/'ordinary-tests'
            execute(label+'-build',[rustc,'--crate-name',CRATE,'--test',src,'-o',program,*flags(opt)])
            p=execute(label+'-run',[program,'--nocapture','--test-threads=1'],101 if failed else 0)
            raw=p.stdout+p.stderr
            if failed:
                need(b'FAILED'in raw and b'panicked at'in raw,'No retained semantic unit assertion failure')
                return {'program':str(program),'expected_exit':101,'semantic_failure_observed':True}
            m=re.search(rb'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',raw)
            need(m is not None and int(m[1])>0,'Actual ordinary Rust tests did not run')
            return {'program':str(program),'actual_tests':int(m[1]),'expected_exit':0}
        profiles=[]
        for name,opt in [('debug',0),('optimized',3)]:
            directory=output/name;lib=library(name+'-library',source,opt,directory)
            tests=ordinary_tests(name+'-ordinary',source,opt,directory)
            program,raw=production(name+'-production',lib,opt,directory)
            need(not mismatch_ids(raw,expected['expected']),name+' fresh native expectation mismatch')
            profiles.append({'name':name,'opt_level':opt,'ordinary_tests':tests,'production':str(program),'production_sha256':file_digest(program),'production_cases':len(raw.splitlines()),'actual_sha256':sha(raw),'expected_sha256':sha(expected['expected']),'library_sha256':file_digest(lib)})
        a=library('repro-a',source,3,output/'repro-a');b=library('repro-b',source,3,output/'repro-b')
        rebuild={'a_bytes':a.stat().st_size,'b_bytes':b.stat().st_size,'a_sha256':file_digest(a),'b_sha256':file_digest(b),'raw_equal':a.read_bytes()==b.read_bytes(),'normalization':'none','original_target_match_claimed':False}
        need(rebuild['raw_equal'],'Own rebuilds differ')
        results=[];text=source.read_text()
        for item in mutations:
            name=item['name'];need(text.count(item['needle'])==1,name+' no longer uniquely matches source')
            folder=output/('mutant-'+name);folder.mkdir()
            # All copied inputs are our component source/tests/fixtures, not a
            # captured image/provider. Expected fixture bytes stay unchanged.
            for p in source.parent.iterdir():
                if p.is_file():
                    need(p.stat().st_size<1<<20,'Unexpected large component input')
                    shutil.copy2(p,folder/p.name)
            altered=folder/source.name;altered.write_text(text.replace(item['needle'],item['replacement']))
            lib=library('mutant-'+name+'-library',altered,0,folder/'library')
            _,raw=production('mutant-'+name+'-production',lib,0,folder)
            mismatches=mismatch_ids(raw,expected['expected']);need(mismatches,name+' did not fail semantic observations')
            if item.get('witness_stimulus_id'):need(item['witness_stimulus_id']in mismatches,name+' selected witness did not fail')
            tests=ordinary_tests('mutant-'+name+'-ordinary',altered,0,folder,True)
            results.append({'name':name,'relation':item['relation'],'source_sha256':file_digest(altered),'production_exit':0,'production_cases':len(raw.splitlines()),'different_transcripts':len(mismatches),'sample_mismatch_ids':mismatches[:8],'ordinary_tests':tests})
        after={str(p):file_digest(p)for p in inputs}
        need(before==after and file_digest(rustc)==compiler_before and file_digest(linker)==linker_before,'Source/compiler/linker bytes changed')
        result={'status':'PASS','compiler':{'path':str(rustc),'sha256':compiler_before,'identity':version,'research_toolchain_not_original':True},'linker':{'path':linker,'sha256':linker_before,'identity':linker_version},'oracle':expected['metadata'],'source_before':before,'source_after':after,'profiles':profiles,'own_reproducibility':rebuild,'semantic_mutants':results,'calls':calls,'limits':['Decimal-only chosen safe-array API, not selector/hex/flags or downstream formatter behavior.','Input-only production data flow, not a filesystem sandbox.','Finite vectors corroborate the separately proved all-u64 native math/store relation.','Only independently authored Rust executes; captured target or CPU emulator never executes.','Own raw rebuild equality, no original compiler/ABI/byte identity/runtime/gate claim.']}
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls,'source_before':before},indent=2)+'\n');raise


ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/94/hl-node'
COMPONENT=ROOT/'src/node94-integer-digit-span'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
FIXTURE=COMPONENT/'target-vectors.tsv'


def verify_fixture(expected,path=FIXTURE):
    need(Path(path).read_bytes()==expected['fixture'],
         'Checked fixture differs from fresh static expectations')


def semantic_mutations(source):
    """Five independent native contract relations, not random byte changes."""
    changes=[
        {'name':'zero-empty','needle':'    let mut start = 20;',
         'replacement':'    if value == 0 { return 20; }\n    let mut start = 20;',
         'relation':'Native zero writes one digit and returns19, never an empty suffix.'},
        {'name':'quotient-base-eleven','needle':'        value /= 10;',
         'replacement':'        value /= 11;',
         'relation':'Decimal quotient/progress must retain conventional decimal digits.'},
        {'name':'wrong-digit-encoding','needle':"b'0' + (value % 10) as u8",
         'replacement':"b'1' + (value % 10) as u8",
         'relation':'Actual native pair-table digits are ASCII0 through9.'},
        {'name':'returned-start-plus-one','needle':'    start\n}',
         'replacement':'    start + 1\n}',
         'relation':'Return is the first written index20-D(n), observed independently of bytes.'},
        {'name':'overwrite-prefix','needle':'    start\n}',
         'replacement':'    buffer[..start].fill(0);\n    start\n}',
         'relation':'Every byte before the returned start remains the arbitrary initial byte.'}]
    for row in changes:
        need(source.count(row['needle'])==1,row['name']+' no longer uniquely matches actual source')
    return changes


def build(binary,rustc,output,controls=False):
    output=Path(output).absolute()
    need(not output.exists(),'Output directory must be new; preserve previous evidence')
    expected=reference.oracle(Path(binary),repo=ROOT)
    verify_fixture(expected)
    changes=semantic_mutations(SOURCE.read_text())if controls else[]
    additional=[Path(__file__),Path(reference.__file__),ROOT/'tools/integer_digit_span_static.py',
                ROOT/'tools/bincode_varint.py']
    return qualify(ROOT,expected,SOURCE,FIXTURE,Path(rustc),output,
                   DRIVER.read_text(),changes,additional)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args();result=build(args.binary,args.rustc,args.output,args.controls)
    print(json.dumps({'status':result['status'],'cases':result['oracle']['case_count'],
                      'commands':len(result['calls']),'mutants':len(result['semantic_mutants'])}))


if __name__=='__main__':main()
