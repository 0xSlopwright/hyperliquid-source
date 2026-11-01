#!/usr/bin/env python3
"""Build and qualify the independently authored nonzero-u128 quotient implementation.

The complete198-byte static proof and independently frozen native equations supply expectations;
only our Rust library, input-only client and ordinary unit tests execute.
Captured target code and instruction emulators never execute here.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,time
import u128_division_reference as reference
from libcore_fmt_correspondence import Elf, ar_members
import u128_division_contract as native

CRATE='node94_u128_division'
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
    for row in rows:
        parts=row.split(b'|')
        need(len(parts)==2 and re.fullmatch(rb'[0-9a-f]{32}',parts[1])is not None,
             'Production row is not a complete normal128-bit quotient')
    mismatches=[]
    for row,answer in zip(rows,expected):
        identifier=answer.split(b'|',1)[0]
        need(row.split(b'|',1)[0]==identifier,'Production case identities/order differ')
        if row!=answer:mismatches.append(identifier.decode('ascii'))
    return mismatches

def qualify(root,expected,source,fixture,rustc,output,harness,mutations,additional_sources=()):
    root,source,fixture,rustc,output=(Path(p).absolute()for p in(root,source,fixture,rustc,output))
    need(not os.path.lexists(output),'Output directory must be new; preserve previous evidence')
    need(fixture.read_bytes()==expected['fixture'],'Checked fixture differs from fresh static expectations')
    compiler_before=file_digest(rustc)
    need(compiler_before==COMPILER_SHA256,'Compiler differs from authenticated research1.94.1')
    linker=shutil.which('cc');need(linker is not None,'C linker driver cc is required')
    linker_before=file_digest(linker)
    inputs=tuple(sorted(p for p in source.parent.iterdir()if p.is_file() and p.suffix in {'.rs','.txt','.tsv'}))+tuple(map(Path,additional_sources))
    before={str(p):file_digest(p)for p in inputs}
    output.mkdir(parents=True,exist_ok=False)
    (output/'tmp').mkdir()
    (output/'inputs.txt').write_bytes(expected['inputs']);(output/'expected.txt').write_bytes(expected['expected'])
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n',encoding='utf-8',newline='\n')
    (output/'native-proof.json').write_text(json.dumps(expected['native_proof'],indent=2)+'\n',encoding='utf-8',newline='\n')
    (output/'comparison-main.rs').write_text(harness,encoding='utf-8',newline='\n')
    calls=[];environment=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',TZ='UTC',TMPDIR=str(output/'tmp'))
    def execute(label,argv,required_exit=0):
        memory=Path('/sys/fs/cgroup/memory.max')
        if memory.exists() and memory.read_text(encoding='utf-8').strip().isdigit():
            need(int(memory.read_text(encoding='utf-8'))-int(Path('/sys/fs/cgroup/memory.current').read_text(encoding='utf-8'))>256*1024*1024,
                 'Pause own Rust commands: cgroup headroom below256MiB')
        start=time.monotonic();p=subprocess.run([str(v)for v in argv],cwd=root,env=environment,stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+kind;(output/name).write_bytes(raw);logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(v)for v in argv],'exit_code':p.returncode,'seconds':round(time.monotonic()-start,3),'logs':logs})
        (output/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n',encoding='utf-8',newline='\n')
        need(p.returncode==required_exit,label+' failed; exact raw streams retained')
        return p
    try:
        version=execute('rustc-identity',[rustc,'-vV']).stdout.decode('utf-8')
        need(version.startswith('rustc 1.94.1 ')and'e408947bfd200af42db322daf0fadfe7e26d3bd1'in version,'Actual compiler full identity differs')
        linker_version=execute('linker-identity',[linker,'--version']).stdout.decode('utf-8')
        objdump=shutil.which('objdump');need(objdump is not None,'GNU objdump is required for own object inspection')
        objdump_before=file_digest(objdump)
        objdump_version=execute('objdump-identity',[objdump,'--version']).stdout.decode('utf-8')
        library_checks=[]
        def flags(opt):return ['--edition=2021','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','linker='+linker,'--remap-path-prefix',str(root)+'=/reconstruction']
        def library(label,src,opt,directory,delegation_control=False):
            directory.mkdir(parents=True,exist_ok=False);lib=directory/('lib'+CRATE+'.rlib')
            execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',src,
                           '--emit=link,obj,llvm-ir','--out-dir',directory,
                           '-C','metadata=node94-u128-quotient',*flags(opt)])
            observation=inspect_own_artifacts(directory,execute,label,objdump)
            try:
                reject_delegation(observation)
            except ValueError as error:
                need(delegation_control,'Production division delegation guard rejected: '+str(error))
                need(observation['forbidden_symbols'] and observation['IR_division_operations'],
                     'Build-only wrapper did not exercise both actual object and IR guard')
                observation.update(verdict='REJECTED_BEFORE_CLIENT_LINK_OR_EXECUTION',refusal=str(error))
            else:
                need(not delegation_control,'Build-only delegation wrapper was incorrectly admitted')
                observation['verdict']='PRODUCTION_NO_DIVISION_DELEGATION'
            library_checks.append({'label':label,**observation})
            return lib
        def production(label,lib,opt,directory):
            program=directory/'production'
            execute(label+'-link',[rustc,'--crate-name','u128_quotient_comparison',output/'comparison-main.rs','--extern',CRATE+'='+str(lib),'-o',program,*flags(opt)])
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
        control_source=output/'delegation-wrapper.rs'
        control_source.write_text('#![no_std]\nuse core::num::NonZeroU128;\n#[inline(never)]\npub fn quotient(n:u128,d:NonZeroU128)->u128{ n / d.get() }\n',encoding='utf-8',newline='\n')
        library('build-only-delegation-wrapper',control_source,0,output/'delegation-wrapper',True)
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
        results=[];text=source.read_text(encoding='utf-8')
        for item in mutations:
            name=item['name'];need(text.count(item['needle'])==1,name+' no longer uniquely matches source')
            folder=output/('mutant-'+name);folder.mkdir()
            # All copied inputs are our component source/tests/fixtures, not a
            # captured image/provider. Expected fixture bytes stay unchanged.
            for p in source.parent.iterdir():
                if p.is_file():
                    need(p.stat().st_size<1<<20,'Unexpected large component input')
                    shutil.copy2(p,folder/p.name)
            altered=folder/source.name;altered.write_text(text.replace(item['needle'],item['replacement']),encoding='utf-8',newline='\n')
            lib=library('mutant-'+name+'-library',altered,0,folder/'library')
            _,raw=production('mutant-'+name+'-production',lib,0,folder)
            mismatches=mismatch_ids(raw,expected['expected']);need(mismatches,name+' did not fail semantic observations')
            if item.get('witness_stimulus_id'):need(item['witness_stimulus_id']in mismatches,name+' selected witness did not fail')
            tests=ordinary_tests('mutant-'+name+'-ordinary',altered,0,folder,True)
            results.append({'name':name,'relation':item['relation'],'source_sha256':file_digest(altered),'production_exit':0,'production_cases':len(raw.splitlines()),'different_transcripts':len(mismatches),'sample_mismatch_ids':mismatches[:8],'ordinary_tests':tests})
        after={str(p):file_digest(p)for p in inputs}
        need(before==after and file_digest(rustc)==compiler_before and file_digest(linker)==linker_before and file_digest(objdump)==objdump_before,'Source/compiler/linker/analysis-tool bytes changed')
        result={'status':'PASS','compiler':{'path':str(rustc),'sha256':compiler_before,'identity':version,'research_toolchain_not_original':True},'linker':{'path':linker,'sha256':linker_before,'identity':linker_version},'oracle':expected['metadata'],'child_environment':environment,'source_before':before,'source_after':after,'profiles':profiles,'own_reproducibility':rebuild,'semantic_mutants':results,'own_library_static_checks':library_checks,'analysis_provider':{'path':objdump,'sha256':objdump_before,'identity':objdump_version},'calls':calls,'limits':['All u128 numerators/nonzero divisors as a numerical projection under the explicit native ordinary-call/frame domain.','Input-only production data flow, not a filesystem sandbox.','Finite7587 vectors support the separately complete native and restoring-loop proofs.','Only independently authored Rust executes; captured code and instruction interpreters never execute.','No original ABI/type/compiler/runtime/byte identity, caller-wide or recovery gate claim.']}
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls,'source_before':before},indent=2)+'\n',encoding='utf-8',newline='\n');raise



def inspect_own_artifacts(directory, execute, label, objdump):
    """Static own-output check; no supplied or captured object is loaded/run."""
    lib=directory/('lib'+CRATE+'.rlib');obj=directory/(CRATE+'.o');ir=directory/(CRATE+'.ll')
    need(all(p.is_file() for p in (lib,obj,ir)), 'Fixed library recipe omitted an output')
    undefined=set();definitions=[]
    for name,raw in ar_members(lib.read_bytes()).items():
        if raw[:4]!=b'\x7fELF':continue
        image=Elf(raw,1)
        for table in image.sections:
            if table['type']!=2:continue
            for symbol in image.symbols(table['index']):
                if symbol['section']==0 and symbol['name']:undefined.add(symbol['name'])
                if symbol['section'] and symbol['info']&15==2 and CRATE in symbol['name'] and 'quotient' in symbol['name']:
                    function=image.function(symbol['section'],symbol['name'])
                    body=image.section_bytes(function['section'])
                    definitions.append({'member':name,'symbol':function,'body_bytes':len(body),
                                        'body_sha256':sha(body),'code_relocations':image.relocations(function['section'])})
    need(len(definitions)==1,'Own quotient function definition is missing or ambiguous')
    forbidden=sorted(s for s in undefined if re.search(r'__(?:u?div|u?mod|u?rem|sdiv|smod)',s))
    ir_text=ir.read_text(encoding='utf-8')
    ir_ops=sorted(set(re.findall(r'\b(?:udiv|urem|sdiv|srem)\b',ir_text)))
    machine_ops=[]
    if not forbidden and not ir_ops:
        raw=execute(label+'-own-object-disassembly',[objdump,'-dr','-Mintel',obj]).stdout
        for line in raw.decode('utf-8').splitlines():
            parts=line.split('\t')
            if len(parts)>=3:
                words=parts[-1].strip().split()
                if words and words[0]in('div','idiv'):machine_ops.append(line)
    return {'files':{p.name:{'bytes':p.stat().st_size,'sha256':file_digest(p)}for p in(lib,obj,ir)},
            'undefined_symbols':sorted(undefined),'forbidden_symbols':forbidden,
            'IR_division_operations':ir_ops,'machine_division_instructions':machine_ops,
            'quotient_definitions':definitions,
            'scope':'Actual production rlib/object/IR only, not the std-linked I/O client or unit harness'}


def reject_delegation(observation):
    need(not observation['forbidden_symbols'] and not observation['IR_division_operations']
         and not observation['machine_division_instructions'],
         'Production division/remainder delegation or machine DIV is forbidden')


ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/94/hl-node'
COMPONENT=ROOT/'src/node94-u128-division'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
FIXTURE=COMPONENT/'target-vectors.tsv'
PACKET=ROOT/'research/work-items/RE-004-u128-division-94'


def semantic_mutations(text):
    changes=[
        {'name':'strict-subtraction-boundary','needle':'if remainder >= divisor {',
         'replacement':'if remainder > divisor {','relation':'Incorrect exact-multiple quotient boundary.','witness_stimulus_id':'u00455'},
        {'name':'skip-top-input-bit','needle':'let mut bit = 128_usize;',
         'replacement':'let mut bit = 127_usize;','relation':'Drop the most-significant numerator bit.','witness_stimulus_id':'u07132'},
        {'name':'omit-remainder-update','needle':'            remainder -= divisor;',
         'replacement':'            // Deliberately omit the conditional remainder subtraction.',
         'relation':'Keep the full input prefix instead of the required division residue.','witness_stimulus_id':'u00836'},
        {'name':'wrong-quotient-shift','needle':'        result <<= 1;',
         'replacement':'        result <<= 2;','relation':'Place consumed quotient bits at the wrong positions.','witness_stimulus_id':'u00836'}]
    for row in changes:need(text.count(row['needle'])==1,row['name']+' no longer matches source uniquely')
    return changes


def build(binary,rustc,output,controls=False):
    output=Path(output).absolute()
    need(not os.path.lexists(output),'Output directory must be new; preserve evidence')
    expected=reference.fresh(Path(binary))
    expected['metadata'].update(primary_qualified_case_count=len(expected['cases']),
                              primary_expected_sha256=sha(expected['expected']),
                              fixture_sha256=sha(expected['fixture']),
                              pre_Rust_oracle_freeze_sha256=file_digest(PACKET/'preparation/ORACLE-FREEZE.json'))
    additional=[Path(__file__),Path(native.__file__),Path(reference.__file__),
                ROOT/'tools/libcore_fmt_correspondence.py',ROOT/'tools/elf_index.py',
                ROOT/'tools/fde_extents.py',ROOT/'tools/node115_field_adapter_drift.py',
                ROOT/'tools/build_provenance.py',ROOT/'tools/artifacts.py',
                PACKET/'native/rows.json',PACKET/'PROOF.md',PACKET/'preparation/ORACLE-FREEZE.json']
    return qualify(ROOT,expected,SOURCE,FIXTURE,Path(rustc),output,
                   DRIVER.read_text(encoding='utf-8'),semantic_mutations(SOURCE.read_text(encoding='utf-8'))if controls else[],additional)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args();result=build(args.binary,args.rustc,args.output,args.controls)
    print(json.dumps({'status':result['status'],'primary_qualified_cases':result['oracle']['primary_qualified_case_count'],
                      'commands':len(result['calls']),'valued_mutants':len(result['semantic_mutants']),
                      'build_only_delegation_control':'REJECTED_BEFORE_CLIENT_LINK_OR_EXECUTION'}))


if __name__=='__main__':main()
