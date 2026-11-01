#!/usr/bin/env python3
"""Qualify the independently authored qualified normalized-weight table implementation.

The authenticated static producer supplies decoded 771-byte table facts and independent pre-Rust equations;
only our Rust library, input-only client and ordinary unit tests execute.
Captured target code and instruction emulators never execute here.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,time
import fse_weight_table_reference as reference
import fse_weight_table as native

CRATE='node94_fse_weight_table'
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
        parts=row.split(b' ')
        need(len(parts)==4 and parts[1] in (b'ok',b'unsupported') and parts[2].isdigit()
             and re.fullmatch(rb'[0-9a-f]{520}',parts[3]) is not None,
             'Production row is not a complete normal four-field value')
    mismatches=[]
    for row,answer in zip(rows,expected):
        identifier=answer.split(b' ',1)[0]
        need(row.split(b' ',1)[0]==identifier,'Production case identities/order differ')
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
    (output/'supplemental-inputs.txt').write_bytes(expected['supplemental_inputs'])
    (output/'supplemental-expected.txt').write_bytes(expected['supplemental_expected'])
    calls=[];environment=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',TZ='UTC',TMPDIR=str(output/'tmp'))
    def execute(label,argv,required_exit=0):
        memory=Path('/sys/fs/cgroup/memory.max')
        if memory.exists() and memory.read_text(encoding='utf-8').strip().isdigit():
            need(int(memory.read_text(encoding='utf-8'))-int(Path('/sys/fs/cgroup/memory.current').read_text(encoding='utf-8'))>1<<30,
                 'Pause own Rust commands: cgroup headroom below1GiB')
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
        def flags(opt):return ['--edition=2021','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','linker='+linker,'--remap-path-prefix',str(root)+'=/reconstruction']
        def library(label,src,opt,directory):
            directory.mkdir(parents=True,exist_ok=False);lib=directory/('lib'+CRATE+'.rlib')
            execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',src,'-o',lib,'-C','metadata=node94-fse-weight-table',*flags(opt)])
            return lib
        def production(label,lib,opt,directory):
            program=directory/'production'
            execute(label+'-link',[rustc,'--crate-name','fse_table_comparison',output/'comparison-main.rs','--extern',CRATE+'='+str(lib),'-o',program,*flags(opt)])
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
            extra=execute(name+'-supplemental-run',[program,output/'supplemental-inputs.txt']).stdout
            need(not mismatch_ids(extra,expected['supplemental_expected']),name+' supplemental safe-API observation mismatch')
            profiles[-1]['supplemental_separate_cases']=len(extra.splitlines())
            profiles[-1]['supplemental_actual_sha256']=sha(extra)
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
        need(before==after and file_digest(rustc)==compiler_before and file_digest(linker)==linker_before,'Source/compiler/linker bytes changed')
        result={'status':'PASS','compiler':{'path':str(rustc),'sha256':compiler_before,'identity':version,'research_toolchain_not_original':True},'linker':{'path':linker,'sha256':linker_before,'identity':linker_version},'oracle':expected['metadata'],'child_environment':environment,'source_before':before,'source_after':after,'profiles':profiles,'own_reproducibility':rebuild,'semantic_mutants':results,'calls':calls,'limits':['Primary39 actual876-caller normalized-weight tables; supplemental30 observations remain separate.','Input-only production data flow, not a filesystem sandbox.','Finite vectors support the separately closed conditional771-byte normal table relation, not full decoder/scratch/error parity.','Only independently authored Rust executes; captured target or CPU emulator never executes.','Chosen safe API length/error and workspace; no original ABI/type/compiler/runtime/byte identity or gate claim.']}
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls,'source_before':before},indent=2)+'\n',encoding='utf-8',newline='\n');raise


ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/94/hl-node'
COMPONENT=ROOT/'src/node94-fse-weight-table'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
FIXTURE=COMPONENT/'target-vectors.tsv'
PACKET=ROOT/'research/work-items/RE-001-fse-weight-table-94'
PRIMARY_INPUT_SHA256='6869fbf399c1ce7e2b8aa3254fed3ff030b236051cc6f287280acb3572a733d5'
SUPPLEMENT_INPUT=PACKET/'independent-controls/OWN-API-STIMULI.json'
SUPPLEMENT_EXPECTED=PACKET/'independent-controls/OWN-API-EXPECTED.json'
ORACLE_FREEZE=PACKET/'independent-oracle/ORACLE-FREEZE.json'


def stimulus(line):
    fields=line.split(' ')
    need(len(fields)==5 and re.fullmatch(r'[A-Za-z0-9_-]+',fields[0])is not None,
         'Expected five input-only stimulus fields')
    identifier,log,maximum,coefficients,initial=fields
    need(log.isdigit() and maximum.isdigit(),'Invalid unsigned stimulus')
    values=coefficients.split(',')
    need(len(values)==256 and all(re.fullmatch(r'-?[0-9]+',word)is not None for word in values),
         'Expected256 signed coefficient words')
    normalized=[int(word)for word in values]
    need(0<=int(log)<=255 and 0<=int(maximum)<=255 and
         all(-32768<=word<=32767 for word in normalized),'Typed stimulus outside Rust input range')
    need(re.fullmatch(r'[0-9a-f]{520}',initial)is not None,'Expected complete260-byte initial image')
    return identifier,int(log),int(maximum),normalized,bytes.fromhex(initial)


def answer(line):
    identifier,log,maximum,normalized,initial=stimulus(line)
    result=reference.serialize_case(log,maximum,normalized,initial)
    need(result['status']in('ok','unsupported')and len(result['output'])==260,
         'Independent reference did not produce complete chosen-API observation')
    return (f"{identifier} {result['status']} {result['length']} {result['output'].hex()}").encode(),result


def fresh_expectations(binary):
    """Admit actual native facts first; the fixed scalar oracle reads no Rust.

    The comparison oracle is not parameter-generic. Require all freshly decoded
    operand/layout and separately bound caller facts to match its proved scope;
    defaults or a historical report alone cannot admit expectations.
    """
    data=native.load_target(binary)
    record=native.analyze(data)
    del data
    parameters={'final_base_field':4,'final_bits_field':7,'final_symbol_field':6,
                'half_log_adjustment':-1,'log_guard':12,'low_high_decrement':1,
                'low_next_initial':1,'low_symbol_field':2,'max_symbol_guard':255,
                'padded_list_base':10,'scratch_extra':8,'stride_bias':3,
                'table_header_bytes':4,'table_mask_adjustment':-1}
    need(record['proof']['parameters']==parameters and record['metadata']['bytes']==771
         and record['proof']['native_rows']==213,'Fresh native facts do not admit fixed scalar oracle')
    domains=record['proof']['domains']
    observed=[(d['log'],d['T'],d['stride'],d['caller876_max_symbol'],d['table_bytes'])for d in domains]
    need(observed==[(5,32,23,91,132),(6,64,43,11,260)],'Fresh caller/domain facts differ')
    need(file_digest(ORACLE_FREEZE)==reference.FROZEN_ORACLE_SHA256,
         'Independent pre-Rust table authority receipt differs')
    inputs=(COMPONENT/'target-inputs.txt').read_bytes()
    need(sha(inputs)==PRIMARY_INPUT_SHA256,'Frozen39 stimulus serialization differs')
    lines=inputs.decode('ascii').splitlines();need(len(lines)==39,'Expected39 qualified primary cases')
    expected=[]
    for line in lines:
        value,meaning=answer(line)
        need(meaning['status']=='ok','Primary corpus includes a safe-API refusal')
        expected.append(value)
    wanted=b'\n'.join(expected)+b'\n'
    fixture=b''.join(line.encode()+b'\t'+value+b'\n'for line,value in zip(lines,expected))
    need((COMPONENT/'target-expected.txt').read_bytes()==wanted,
         'Retained39 expected rows differ from fresh independent equations')
    need(FIXTURE.read_bytes()==fixture,'Retained39 fixture differs from fresh independent equations')

    # This separate30-case corpus includes14 valid-domain supports and16 chosen
    # API refusals. None of its refusals is claimed as a native error observation.
    extra=json.loads(SUPPLEMENT_INPUT.read_text(encoding='utf-8'));frozen=json.loads(SUPPLEMENT_EXPECTED.read_text(encoding='utf-8'))
    need(len(extra)==len(frozen)==30,'Supplemental corpus count differs')
    supplemental_inputs=[];supplemental_expected=[];supported=0;refused=0
    for item,witness in zip(extra,frozen):
        line=item['input_line'];identifier,log,maximum,normalized,initial=stimulus(line)
        need((identifier,log,maximum,normalized,initial.hex())==
             (item['id'],item['log'],item['max_symbol'],item['normalized'],item['initial260_hex']),
             'Supplemental input fields and serialization differ')
        value,meaning=answer(line)
        need(value.decode()==witness['expected_line']and identifier==witness['id'],
             'Fresh supplemental equations differ from independently frozen observations')
        supported+=meaning['status']=='ok';refused+=meaning['status']=='unsupported'
        supplemental_inputs.append(line.encode());supplemental_expected.append(value)
    need((supported,refused)==(14,16),'Supplemental policy classification differs')
    metadata={'primary_qualified_case_count':39,'primary_expected_sha256':sha(wanted),
              'frozen_primary_inputs_sha256':sha(inputs),'primary_fixture_sha256':sha(fixture),
              'supplemental_separate_cases':30,'supplemental_valid_domain_supports':supported,
              'supplemental_chosen_API_refusals_not_native_errors':refused,
              'target':record['target'],'primary_native_bytes':771,'primary_native_rows':213,
              'separate_caller_context_bytes':sum(x['bytes']for x in record['metadata']['caller_context']),
              'independent_pre_Rust_table_authority':reference.FROZEN_ORACLE_SHA256,
              'reference_wrapper_scope':'Checked safe-API wrapper prepared later; only frozen table equations predate Rust.',
              'native_success_RAX':0,'chosen_success_return':'132 or260 byte length; not original RAX',
              'no_whole_decoder_private_ABI_scratch_error_or_byte_identity_claim':True}
    return {'inputs':inputs,'expected':wanted,'fixture':fixture,'metadata':metadata,
            'native_proof':record,'supplemental_inputs':b'\n'.join(supplemental_inputs)+b'\n',
            'supplemental_expected':b'\n'.join(supplemental_expected)+b'\n'}


def semantic_mutations(text):
    changes=[
        {'name':'odd-stride-bias','needle':'let stride = table_size / 2 + table_size / 8 + 3;',
         'replacement':'let stride = table_size / 2 + table_size / 8 + 5;',
         'relation':'Change the proved odd permutation while keeping both strides odd and terminating.',
         'witness_stimulus_id':'l5-threshold-below'},
        {'name':'low-next-counter','needle':'next[symbol] = 1;',
         'replacement':'next[symbol] = 2;',
         'relation':'Low-probability row bits/base use the wrong nonzero initial counter.',
         'witness_stimulus_id':'l5-all32-low'},
        {'name':'half-threshold-flag','needle':'coefficient as usize >= table_size / 2',
         'replacement':'coefficient as usize > table_size / 2',
         'relation':'Change the exact half-table high flag boundary.',
         'witness_stimulus_id':'l5-threshold-equal'},
        {'name':'serialized-base-bit','needle':'let base = ((value << bits) - table_size as u32) as u16;',
         'replacement':'let base = (((value << bits) - table_size as u32) as u16) ^ 1;',
         'relation':'Change the serialized row base without changing loops or memory extents.',
         'witness_stimulus_id':'l5-single-positive'},
        {'name':'log5-suffix-preservation','needle':'    Ok(4 + 4 * table_size)',
         'replacement':'    if table_size == 32 {\n        output[132..].fill(0);\n    }\n    Ok(4 + 4 * table_size)',
         'relation':'Change only the untouched suffix in the chosen API, not native scratch parity.',
         'witness_stimulus_id':'l5-single-positive'}]
    for row in changes:need(text.count(row['needle'])==1,row['name']+' no longer uniquely matches source')
    return changes


def build(binary,rustc,output,controls=False):
    output=Path(output).absolute()
    need(not os.path.lexists(output),'Output directory must be new; preserve previous evidence')
    expected=fresh_expectations(Path(binary))
    changes=semantic_mutations(SOURCE.read_text(encoding='utf-8'))if controls else[]
    additional=[Path(__file__),Path(native.__file__),Path(reference.__file__),
                ROOT/'tools/elf_index.py',ROOT/'tools/fde_extents.py',
                ORACLE_FREEZE,SUPPLEMENT_INPUT,SUPPLEMENT_EXPECTED]
    return qualify(ROOT,expected,SOURCE,FIXTURE,Path(rustc),output,
                   DRIVER.read_text(encoding='utf-8'),changes,additional)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args();result=build(args.binary,args.rustc,args.output,args.controls)
    print(json.dumps({'status':result['status'],'primary_qualified_cases':result['oracle']['primary_qualified_case_count'],
                      'separate_supplemental_cases':result['oracle']['supplemental_separate_cases'],
                      'commands':len(result['calls']),'mutants':len(result['semantic_mutants'])}))


if __name__=='__main__':main()
