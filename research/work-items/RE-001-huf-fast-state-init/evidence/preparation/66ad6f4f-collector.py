#!/usr/bin/env python3
"""Static node #94 constructor evidence and an optional independent Rust client.

No captured executable, licensed assembly object, emulator or network is run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-huf-fast-state-init'
COMPONENT = ROOT / 'src/node94-huf-fast-state'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_BYTES = 91774280
START, END = 0x55dc5e0, 0x55dc79b
SPAN_SHA = 'e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63'
LEDGER_SHA = '891da8ee5a0c63cdb64479bb96c1dfa2e4af442af3434f04b1efa062e4d8992d'
OBJDUMP_SHA = '96afb8521834982d0e711b5d6e9785252bf82129fb0106b93a6bd54d83fae11f'
RUSTC = Path('/tmp/hl-rem-rust-1.94.1-20261031/prefix/bin/rustc')
RUSTC_SHA = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
STATE_ORDER = [120,128,136,144,32,0,8,40,48,16,24,56,64,72,80,104,112,96,88]
CONTEXTS = [
    ('wrapper-A', 0x55dd2f0, 0x55dd35d, 0x55dd5bd),
    ('wrapper-B', 0x55dceb0, 0x55dcf1d, 0x55dd2f0),
    ('selected-dispatcher', 0x55ec060, 0x55ec199, 0x55ec199),
]
ROW = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S+)(?:\s+(.*))?$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def admit_file(path, expected_size, expected_sha):
    data = Path(path).read_bytes()
    if len(data) != expected_size or sha(data) != expected_sha:
        raise ValueError('Input identity mismatch: ' + str(path))
    return data


def _slice(data, secs, start, end):
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4
               and s['address'] <= start < end <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('One executable section is required')
    s = matches[0]
    off = s['offset'] + start - s['address']
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    segments = []
    for index in range(count):
        typ, flags, fo, va, _, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, phoff + index * entsize)
        if typ == 1 and flags & 1 and va <= start < end <= va + fs:
            segments.append({'index': index, 'file_offset': fo + start - va, 'va': va,
                             'filesz': fs, 'memsz': ms, 'flags': flags, 'align': align})
    if len(segments) != 1 or segments[0]['file_offset'] != off:
        raise ValueError('Section / PT_LOAD coordinate mismatch')
    return data[off:off + end - start], {'start':start,'end':end,'bytes':end-start,
             'file_offset':off,'section':s,'load':segments[0]}


def admit_target(path=None):
    """Derive every fact from one full, digest-admitted immutable bytes object."""
    data = admit_file(path or ROOT/'artifacts/node/94/hl-node', TARGET_BYTES, TARGET_SHA)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    raw, info = _slice(data, secs, START, END)
    if sha(raw) != SPAN_SHA:
        raise ValueError('Selected constructor identity mismatch')
    found = [f for f in fdes if f['start'] == START and f['end'] == END]
    if len(found) != 1:
        raise ValueError('Exact constructor FDE required')
    info['fde'] = found[0]
    info['sha256'] = sha(raw)
    contexts = {}
    for label, start, end, fde_end in CONTEXTS:
        matches = [f for f in fdes if f['start'] == start and f['end'] == fde_end]
        if len(matches) != 1:
            raise ValueError('Context FDE mismatch: ' + label)
        view, facts = _slice(data, secs, start, end)
        facts.update(fde=matches[0], sha256=sha(view), raw=view)
        contexts[label] = facts
    return {'target_sha256': TARGET_SHA, 'target_bytes': len(data),
            'raw':raw, 'constructor':info, 'contexts':contexts}


def parse_native_listing(text, start, raw):
    rows = []
    for line in text.splitlines():
        match = ROW.match(line)
        if match:
            rows.append({'address':int(match[1],16), 'raw':bytes.fromhex(match[2]).hex(),
                         'mnemonic':match[3], 'operands':match[4] or ''})
    cursor = start
    emitted = bytearray()
    for row in rows:
        code = bytes.fromhex(row['raw'])
        if row['address'] != cursor or not code or row['mnemonic'] in ('(bad)', '.byte'):
            raise ValueError('Native instruction coordinate/decoding mismatch')
        emitted.extend(code)
        cursor += len(code)
    if bytes(emitted) != raw or cursor != start + len(raw):
        raise ValueError('Native listing bytes do not bind the admitted span')
    return rows


def _branch(row):
    raw = bytes.fromhex(row['raw'])
    if not row['mnemonic'].startswith('j'):
        return None
    if len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
        displacement = struct.unpack('<b', raw[-1:])[0]
    elif len(raw) == 5 and raw[0] == 0xe9:
        displacement = struct.unpack('<i', raw[-4:])[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack('<i', raw[-4:])[0]
    else:
        raise ValueError('Unexpected encoded branch form')
    target = row['address'] + len(raw) + displacement
    if target != int(row['operands'], 16):
        raise ValueError('Native branch rendering disagrees with raw displacement')
    return target


def validate_constructor(raw, rows):
    """Bind reviewed finite transfer facts below full-image identity admission.

    This is a static proof-data checker, not a CPU model or general interpreter.
    The complete reviewed ledger preserves every instruction, including padding.
    """
    ledger_data = admit_file(PACKET/'TRANSFER-LEDGER.json',
                            (PACKET/'TRANSFER-LEDGER.json').stat().st_size, LEDGER_SHA)
    expected = json.loads(ledger_data)['complete_native_rows']
    if len(raw) != END-START or len(rows) != len(expected):
        raise ValueError('Complete constructor instruction denominator required')
    # Validate raw/listing coordinates before reviewed operand/transfer matching.
    cursor = START
    for row in rows:
        code = bytes.fromhex(row['raw'])
        if row['address'] != cursor or raw[cursor-START:cursor-START+len(code)] != code:
            raise ValueError('Constructor row does not bind the proposed bytes')
        cursor += len(code)
    if cursor != END:
        raise ValueError('Constructor coverage is incomplete')
    by = {r['address']:r for r in rows}
    edges = {}
    branches = []
    for row in rows:
        address = row['address']; after = address + len(bytes.fromhex(row['raw']))
        target = _branch(row)
        if target is not None:
            if target not in by:
                raise ValueError('Branch target is not an instruction boundary')
            edges[address] = [target] if row['mnemonic']=='jmp' else [target,after]
            branches.append({'address':address,'target':target,'raw':row['raw']})
        elif row['mnemonic']=='ret': edges[address] = []
        else: edges[address] = [after] if after in by else []
    stores = []
    for row in rows:
        if row['mnemonic']=='mov' and row['operands'].startswith('QWORD PTR [rdi'):
            code=bytes.fromhex(row['raw'])
            # Actual REX.W + MOV r64->r/m64, base RDI, disp0/8/32.
            if not (0x48<=code[0]<=0x4f and code[0]&8 and code[1]==0x89 and code[2]&7==7):
                raise ValueError('State write is not the required QWORD encoding')
            mod=code[2]>>6
            if mod==0: offset=0
            elif mod==1: offset=struct.unpack('<b',code[3:4])[0]
            elif mod==2: offset=struct.unpack('<i',code[3:7])[0]
            else: raise ValueError('State store is not memory')
            stores.append({'address':row['address'],'offset':offset,'raw':row['raw']})
    if [x['offset'] for x in stores] != STATE_ORDER:
        raise ValueError('Ordered partial state writes differ from the transfer proof')
    for actual, reviewed in zip(rows,expected):
        for field in ('address','raw','mnemonic','operands'):
            if actual[field] != reviewed[field]:
                raise ValueError('Reviewed '+reviewed['phase']+' transfer differs: '+field)
    seen=set(); pending=[START]
    while pending:
        address=pending.pop()
        if address not in seen:
            seen.add(address);pending.extend(edges[address])
    if len(seen)!=128 or len(branches)!=16 or any(r['mnemonic'].startswith('call') for r in rows):
        raise ValueError('Reviewed local CFG differs')
    return {'semantic_bytes':len(raw),'instruction_rows':len(rows),'reachable_rows':len(seen),
            'unreachable_padding':[r for r in rows if r['address'] not in seen],
            'raw_verified_branches':branches,'ordered_state_stores':stores,
            'state_words_on_success':19,'raw_statuses':[0,0xffffffffffffffec,1],
            'initial_nonzero_bit_cells':'conditional static proof in PROOF.md, not runtime result',
            'late_output_refusal_positive_lengths':[1,2,3,5,6,9],
            'table_payload_qualified':False,'runtime_dispatch_qualified':False,
            'whole_loop_or_decoder_qualified':False,'progress_gate_changed':False}


def validate_context(label, raw, rows):
    expected_sha={
        'wrapper-A':'47887cbe8583a3b291c5fdce681b313159d8d92a9f3f5f492a3db5c86a57f15e',
        'wrapper-B':'59e356d00f002bf4076dde268b6222d9bd1984bd66803cf10d3f129945abcac8',
        'selected-dispatcher':'1d890160203e2f8d70c421008bf398e9ca992858667c4919cfe2b29bca02a06d'}
    if sha(raw)!=expected_sha[label]:raise ValueError('Selected context identity mismatch')
    by={r['address']:r for r in rows}
    def require(address, encoding, mnemonic):
        row=by.get(address)
        if row is None or row['raw']!=encoding or row['mnemonic']!=mnemonic:
            raise ValueError('Selected context transfer differs')
        return row
    if label.startswith('wrapper'):
        is_a=label=='wrapper-A'
        saved=require(0x55dd2f2 if is_a else 0x55dceb4,'4d89cf' if is_a else '4d89ce','mov')
        if saved['operands']!=('r15,r9' if is_a else 'r14,r9'):
            raise ValueError('Saved callback operand mismatch')
        address=0x55dd342 if is_a else 0x55dcf02;row=by[address];code=bytes.fromhex(row['raw'])
        if row['mnemonic']!='call' or code[0]!=0xe8 or address+5+struct.unpack('<i',code[1:])[0]!=START or int(row['operands'],16)!=START:
            raise ValueError('Constructor call destination mismatch')
        callback=require(0x55dd35a if is_a else 0x55dcf1a,'41ffd7' if is_a else '41ffd6','call')
        if callback['operands']!=('r15' if is_a else 'r14'):raise ValueError('Callback register mismatch')
        return {'context_bytes':len(raw),'constructor_call':address,'constructor_target':START,
                'indirect_call':callback['address'],'callback_register':callback['operands'],
                'argument':'RDI=workingRSP+16, preserved by complete initializer transfer',
                'callback_condition':'normal-domain constructor status1 only; 0/-20 bypass it',
                'complete_wrapper_implemented':False}
    pointers=[]
    for address,target in [(0x55ec09e,0x56319fd),(0x55ec0f3,0x5631580)]:
        row=by[address];code=bytes.fromhex(row['raw'])
        if code[:3]!=bytes.fromhex('4c8d0d') or row['mnemonic']!='lea' or address+7+struct.unpack('<i',code[3:])[0]!=target or not row['operands'].endswith('# '+hex(target)):
            raise ValueError('Selected raw RIP pointer destination mismatch')
        pointers.append({'address':address,'target':target})
    return {'context_bytes':len(raw),'selected_entry_leas':pointers,
            'assembly_pointer_condition':'opaque incoming bit0=1,bit0x10=0; bit0x20=0 permits wrapper attempt',
            'selection_byte':'incoming R8+1: zero selects A, nonzero B',
            'runtime_CPUID_or_CPU_support_proved':False,'complete_caller_reach_proved':False}


def _native(raw, start, work):
    provider=Path(shutil.which('objdump') or '/missing-objdump').resolve()
    if sha(provider.read_bytes()) != OBJDUMP_SHA:
        raise ValueError('Unsupported GNU objdump identity')
    path=work/'span.bin';path.write_bytes(raw);path.chmod(0o400)
    argv=[str(provider),'-D','-b','binary','-m','i386:x86-64','-M','intel',
          '--insn-width=16',f'--adjust-vma={start}','span.bin']
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          env={**os.environ,'LC_ALL':'C','LANG':'C'},cwd=work,check=True)
    if sha(provider.read_bytes()) != OBJDUMP_SHA:
        raise ValueError('Native provider changed during collection')
    rows=parse_native_listing(result.stdout.decode(),start,raw)
    return rows, result.stdout, result.stderr, argv


def _json(value):
    return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def _write_outputs(output_dir, artifacts):
    output=Path(output_dir)
    output.mkdir(parents=False,exist_ok=False)
    for name,data in sorted(artifacts.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
    manifest={name:{'bytes':len(data),'sha256':sha(data)} for name,data in sorted(artifacts.items())}
    with (output/'OUTPUT-MANIFEST.json').open('xb') as stream:stream.write(_json(manifest))


def collect(output_dir, target_path=None):
    if Path(output_dir).exists():raise FileExistsError(output_dir)
    admitted=admit_target(target_path)
    artifacts={};context_facts={}
    with tempfile.TemporaryDirectory(prefix='hufs-native-',dir='/tmp') as tmp:
        work=Path(tmp);raw=admitted.pop('raw')
        rows,stdout,stderr,argv=_native(raw,START,work)
        facts=validate_constructor(raw,rows)
        artifacts.update({'constructor.bin':raw,'native.stdout':stdout,'native.stderr':stderr,
                          'native-rows.json':_json(rows)})
        for label,context in admitted['contexts'].items():
            view=context.pop('raw')
            context_work=work/label;context_work.mkdir()
            context_rows,cstdout,cstderr,cargv=_native(view,context['start'],context_work)
            context['selected_transfer']=validate_context(label,view,context_rows)
            context['native_argv']=cargv
            context_facts[label]=context
            # The context cuts are raw provenance and selected pointer flow,
            # not a claim to implement their entire larger FDE bodies.
            artifacts['contexts/'+label+'.bin']=view
            artifacts['contexts/'+label+'.native.stdout']=cstdout
            artifacts['contexts/'+label+'.native.stderr']=cstderr
            artifacts['contexts/'+label+'.native-rows.json']=_json(context_rows)
        bindings={name:sha((ROOT/name).read_bytes()) for name in
                  ['tools/huf_fast_state_init.py','tools/elf_index.py','tools/fde_extents.py',
                   'src/node94-huf-fast-state/lib.rs','src/node94-huf-fast-state/driver.rs',
                   'research/work-items/RE-001-huf-fast-state-init/PROOF.md',
                   'research/work-items/RE-001-huf-fast-state-init/TRANSFER-LEDGER.json']}
        report={'question':'Conditional normal-state constructor and selected pre-call interface',
                'target':{'sha256':TARGET_SHA,'bytes':TARGET_BYTES},'constructor':admitted['constructor'],
                'transfer':facts,'selected_contexts':context_facts,'selected_context_bytes':531,
                'primary_semantic_bytes':443,'source_bindings':bindings,
                'native':{'provider_sha256':OBJDUMP_SHA,'argv':argv,
                          'environment_overrides':{'LC_ALL':'C','LANG':'C'},
                          'inherited_environment_trusted_unrecorded':True,
                          'trusted_stable_host_not_atomic_execution_provenance':True},
                'compiler_or_target_executed':False,'rust_component_validation':'separate actual driver record',
                'limits':'PROOF.md normal domain and external image/stack/return assumptions; no table payload, later refill, decoder or runtime CPU qualification'}
        artifacts['REPORT.json']=_json(report)
        _write_outputs(output_dir,artifacts)
    return report


def driver_request(case):
    a=case['addresses'];state=case['state'];header=bytes.fromhex(case['header_hex']);source=bytes.fromhex(case['input_hex'])
    if set(a)!={'state','output','input','table'} or len(state)!=19 or len(header)!=4:
        raise ValueError('Invalid component stimulus shape')
    numbers=[a[k] for k in ('state','output','input','table')]+[case['output_length']]+state
    if any(type(x) is not int or not 0<=x<1<<64 for x in numbers):
        raise ValueError('Component stimulus integer outside u64')
    return ' '.join([*(format(a[k],'x') for k in ('state','output','input','table')),
                     format(case['output_length'],'x'),header.hex(),source.hex() or '-',
                     ','.join(format(x,'x') for x in state)])


def parse_driver_output(text, count):
    lines=text.splitlines()
    if len(lines)!=count:raise ValueError('Wrong component response count')
    result=[]
    for line in lines:
        status,words=line.split('\t');state=[int(x,16) for x in words.split(',')]
        if len(state)!=19 or any(not 0<=x<1<<64 for x in state):raise ValueError('Wrong component state width or value')
        if status.startswith('status '): row={'raw_status':int(status[7:],16),'domain_error':None,'state':state}
        elif status.startswith('domain '):row={'raw_status':None,'domain_error':status[7:],'state':state}
        else:raise ValueError('Unknown component result protocol')
        result.append(row)
    return result


def _bind_toolchain(rustc):
    lock_path=PACKET/'TOOLCHAIN.json'
    lock_data=admit_file(lock_path,lock_path.stat().st_size,
        '781089d80c0e6a86ac54e0b8f27cc32611b76750fa2569992dae50c942e52cbd')
    lock=json.loads(lock_data);prefix=rustc.parent.parent;bound={}
    for relative,expected in lock['prefix_files'].items():
        data=admit_file(prefix/relative,expected['bytes'],expected['sha256'])
        bound['prefix/'+relative]={'bytes':len(data),'sha256':sha(data)}
    for path,expected in lock['native_linker_host'].items():
        data=admit_file(path,expected['bytes'],expected['sha256'])
        bound[path]={'bytes':len(data),'sha256':sha(data)}
    return bound


def run_rust_cases(cases, output_dir, rustc_path=RUSTC, source_root=COMPONENT, retain_library=False):
    """Build and execute only the independently authored component/real client.

    The driver receives stimuli only. Any test-side expected fields are ignored.
    This function reports actual responses, not a captured-code equivalence claim.
    """
    output=Path(output_dir)
    if output.exists():raise FileExistsError(output)
    rustc=Path(rustc_path).resolve()
    if sha(rustc.read_bytes())!=RUSTC_SHA:raise ValueError('Unsupported rustc identity')
    toolchain_before=_bind_toolchain(rustc)
    sources={name:(Path(source_root)/name).read_bytes() for name in ('lib.rs','driver.rs')}
    requests=('\n'.join(driver_request(case) for case in cases)+'\n').encode()
    artifacts={};commands=[]
    with tempfile.TemporaryDirectory(prefix='hufs-rust-',dir='/tmp') as tmp:
        work=Path(tmp)
        for name,data in sources.items():(work/name).write_bytes(data)
        (work/'tmp').mkdir()
        env={**os.environ,'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TMPDIR':'tmp'}
        argv_list=[
            [str(rustc),'--edition=2021','--crate-name','node94_huf_fast_state','--crate-type','rlib',
             '--target','x86_64-unknown-linux-gnu','-C','opt-level=0','lib.rs','-o','libnode94_huf_fast_state.rlib'],
            [str(rustc),'--edition=2021','--crate-name','node94_huf_fast_state_driver',
             '--target','x86_64-unknown-linux-gnu','-C','opt-level=0',
             '-C','linker=/usr/bin/x86_64-linux-gnu-gcc-14','driver.rs',
             '--extern','node94_huf_fast_state=libnode94_huf_fast_state.rlib','-o','driver'],
        ]
        for index,argv in enumerate(argv_list):
            r=subprocess.run(argv,cwd=work,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            commands.append({'argv':argv,'cwd':'private owned temporary directory','exit_code':r.returncode})
            artifacts[f'compile{index}.stdout']=r.stdout;artifacts[f'compile{index}.stderr']=r.stderr
            if r.returncode:raise ValueError('Independent Rust build failed: '+r.stderr.decode(errors='replace'))
        r=subprocess.run(['./driver'],cwd=work,env=env,input=requests,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if r.returncode:raise ValueError('Independent Rust client failed: '+r.stderr.decode(errors='replace'))
        if sha(rustc.read_bytes())!=RUSTC_SHA:raise ValueError('rustc changed during component build')
        toolchain_after=_bind_toolchain(rustc)
        if toolchain_before!=toolchain_after:raise ValueError('Toolchain inputs changed')
        responses=parse_driver_output(r.stdout.decode(),len(cases))
        artifacts.update({'driver.stdin':requests,'driver.stdout':r.stdout,'driver.stderr':r.stderr,
                          'stimuli.json':_json(cases),'responses.json':_json(responses)})
        report={'rustc':str(rustc),'rustc_sha256':RUSTC_SHA,'target':'x86_64-unknown-linux-gnu',
                'source_bindings':{name:sha(data) for name,data in sources.items()},'commands':commands,
                'toolchain_inputs':toolchain_before,'toolchain_inputs_unchanged':True,
                'analysis_source_bindings':{'tools/huf_fast_state_init.py':sha(Path(__file__).read_bytes()),
                    'research/work-items/RE-001-huf-fast-state-init/TOOLCHAIN.json':sha((PACKET/'TOOLCHAIN.json').read_bytes())},
                'driver_executed':True,'driver_argv':['./driver'],'driver_cwd':'private owned temporary directory',
                'environment_overrides':{'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TMPDIR':'tmp'},
                'inherited_environment_trusted_unrecorded':True,'driver_receives_expected_results':False,
                'captured_or_compatible_assembly_executed':False,'responses':responses,
                'artifact_hashes':{name:sha((work/name).read_bytes()) for name in ('libnode94_huf_fast_state.rlib','driver')},
                'trusted_toolchain_not_original_capture_compiler':True}
        if retain_library:
            artifacts['libnode94_huf_fast_state.rlib']=(work/'libnode94_huf_fast_state.rlib').read_bytes()
            report['retained_library']='libnode94_huf_fast_state.rlib'
        artifacts['RUST-REPORT.json']=_json(report)
        _write_outputs(output,artifacts)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',required=True,type=Path)
    parser.add_argument('--rust-cases',type=Path)
    parser.add_argument('--rustc',type=Path,default=RUSTC)
    args=parser.parse_args()
    report=collect(args.output_dir)
    if args.rust_cases is not None:
        cases=json.loads(args.rust_cases.read_bytes())
        run_rust_cases(cases,args.output_dir/'rust-client',args.rustc)
    print(json.dumps({'primary_semantic_bytes':report['primary_semantic_bytes'],
                      'progress_gate_changed':False}))


if __name__=='__main__':main()
