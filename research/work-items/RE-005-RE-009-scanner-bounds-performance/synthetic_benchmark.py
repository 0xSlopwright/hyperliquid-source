"""Small synthetic-only differential benchmark; no repository mutation or target scan."""
import ast, hashlib, json, random, statistics, struct, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE/'original'
REPO=HERE.parents[2]

def extract(file, name, extra=None):
    node=next(n for n in ast.parse((ROOT/file).read_text()).body if isinstance(n,ast.FunctionDef) and n.name==name)
    # A complete-offset brute-force oracle: only the former loop endpoint is fixed.
    for item in ast.walk(node):
        if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Sub) and isinstance(item.left, ast.Call) and isinstance(item.left.func, ast.Name) and item.left.func.id=='len' and item.left.args and isinstance(item.left.args[0],ast.Name) and item.left.args[0].id=='tb' and isinstance(item.right,ast.Constant):
            item.right.value -= 1
    scope={'struct':struct, **(extra or {})}
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(file),'exec'),scope)
    return scope[name],scope

old_call,call_scope=extract(Path('tools/bincode_varint_slow.py'),'_call_got_sites',{'READER_CALL_COUNTS':{},'EvidenceError':ValueError})
old_refs,_=extract(Path('research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py'),'scan_refs')
BASE=0x100000

def candidates(text, needle, stop):
    i=text.find(needle)
    while 0 <= i < stop:
        yield i
        i=text.find(needle,i+1)

def current_function(path, name, extra):
    node=next(n for n in ast.parse((REPO/path).read_text()).body if isinstance(n,ast.FunctionDef) and n.name==name)
    scope={'struct':struct,**extra}
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),scope)
    return scope[name],scope
actual_call,actual_call_scope=current_function(Path('tools/bincode_varint_slow.py'),'_call_got_sites',{'READER_CALL_COUNTS':{},'EvidenceError':ValueError})
actual_counts,actual_counts_scope=current_function(Path('research/work-items/RE-005-bincode-slow-widths/independent_verify.py'),'reader_call_counts',{'CALL_COUNTS':{},'i32':lambda b,k:struct.unpack_from('<i',b,k)[0]})
new_refs,_=current_function(Path('research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py'),'scan_refs',{})
def new_call(*args):
    actual_call_scope['READER_CALL_COUNTS']=call_scope['READER_CALL_COUNTS']
    actual_counts_scope['CALL_COUNTS']=call_scope['READER_CALL_COUNTS']
    result=actual_call(*args)
    data,secs,relocs=args
    counts=actual_counts(data,secs['.text']['addr'],relocs)
    if counts!={int(k,16):len(v) for k,v in result.items()}:raise AssertionError('independent call-count mismatch')
    return result

def fixture(text):
    offsets=[i for i in range(max(0,len(text)-5)) if text[i:i+2]==b'\xff\x15']
    relocs={BASE+i+6+struct.unpack_from('<i',text,i+2)[0]:1234 for i in offsets}
    call_scope['READER_CALL_COUNTS']={1234:len(offsets)}
    sc={'.text':{'offset':0,'size':len(text),'addr':BASE}}
    targets=set()
    for i in range(len(text)):
        if text[i] in (0xe8,0xe9) and i+5<=len(text):targets.add(BASE+i+5+struct.unpack_from('<i',text,i+1)[0])
        if text[i]==0x8d and i+6<=len(text) and text[i+1]&0xc7==5:targets.add(BASE+i+6+struct.unpack_from('<i',text,i+2)[0])
    # Also exercise the unchanged relocation stream and duplicate additions.
    record=struct.pack('<QQq',17,8,next(iter(sorted(targets)),5))
    data=text+record;sr={'.text':(BASE,0,len(text)),'.rela.dyn':(0,len(text),24)}
    return (text,sc,relocs),(data,sr,tuple(sorted(targets)))

cases=[]
for n in range(34):
    for pat in (b'\xff\x15\x00\x00\x00\x00',b'\xe8\x00\x00\x00\x00',b'\xe9\xff\xff\xff\xff',b'\x8d\x05\x00\x00\x00\x00'):
        for at in range(n+1):
            buf=bytearray(b'\x90'*n);tail=pat[:n-at];buf[at:at+len(tail)]=tail;cases.append(bytes(buf))
for modrm in range(256):cases.append(bytes([0x8d,modrm])+b'\xff\xff\xff\xff\x90')
for disp in (-2**31, -1, 0, 2**31-1):
    for prefix in (b'\xff\x15', b'\xe8', b'\xe9', b'\x8d\x05'):
        for suffix in (b'', b'\x90\x90'):
            cases.append(prefix+struct.pack('<i',disp)+suffix)
# Candidate opcodes inside a different candidate's displacement must remain visible.
for pat in (b'\xff\x15\xff\x15\x00\x00\x00\x00\x90',b'\xe8\xe9\xe8\xe9\xe8\x00\x00\x00\x00\x90',b'\x8d\x05\x8d\x05\x00\x00\x00\x00\x90'):
    cases.append(pat)
for text in cases:
    ca,ra=fixture(text)
    if old_call(*ca)!=new_call(*ca):raise AssertionError(('call',text.hex()))
    if old_refs(*ra)!=new_refs(*ra):raise AssertionError(('refs',text.hex()))

rng=random.Random(20261031)
benches={'sparse_1MiB':b'\x90'*(1<<20),'uniform_1MiB':rng.randbytes(1<<20),'overlapping_dense_32KiB':(b'\xff\x15\xff\x15\xe8\xe9\x8d\x05'*4096)}
results=[]
for name,text in benches.items():
    ca,ra=fixture(text)
    actual_call_scope['READER_CALL_COUNTS']=call_scope['READER_CALL_COUNTS']
    for label,old,new,args in [('bincode_call_got',old_call,actual_call,ca),('lthash_independent_refs',old_refs,new_refs,ra)]:
        expected=old(*args)
        if expected!=new(*args):raise AssertionError(name)
        timings={}
        for kind,fn in [('old',old),('candidate_find',new)]:
            ts=[]
            for _ in range(3):
                t=time.perf_counter();fn(*args);ts.append(time.perf_counter()-t)
            timings[kind]=statistics.median(ts)
        results.append({'fixture':name,'bytes':len(text),'scanner':label,'complete_bruteforce_seconds':timings['old'],'candidate_seconds':timings['candidate_find'],'speedup':timings['old']/timings['candidate_find'],'exact_output_equal':True})
report={'source_commit':'da97c34d6fa24600672bf74653a9af0f582b6cdb','python':sys.version,'synthetic_cases':len(cases),'equivalent_scanner_results':3*len(cases),'domain':'Complete fitting-offset brute-force reference derived from archived original loops by fixing only the endpoint; compares all three actual corrected functions. Preserves overlaps, interior opcodes, signed displacements, relocation records, sorting. No instruction-boundary filtering added.','benchmarks':results,'source_sha256':{str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [REPO/'tools/bincode_varint_slow.py',REPO/'research/work-items/RE-005-bincode-slow-widths/independent_verify.py',REPO/'research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py']}}
(HERE/'benchmark.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,indent=2,sort_keys=True))
