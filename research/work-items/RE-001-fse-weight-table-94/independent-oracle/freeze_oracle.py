"""Independent repeat-list / filtered permutation equations; not a CPU model.

Derived from the authenticated771-byte operands before any new Rust is read.
No source build, target execution, public C source or instruction interpreter.
"""
from pathlib import Path
import hashlib,json,math,struct

D=Path(__file__).resolve().parent
H=lambda b:hashlib.sha256(b).hexdigest()

def sizes(log,m):
    t=1<<log;n=m+1
    need=t+2*n+8
    outer=4*(t+((t+2*n+11)//4)+0x83)
    passed=876-(4*t+0x204)
    return {'T':t,'symbols':n,'constructor_scratch_required_bytes':need,
            'outer_workspace_required_bytes':outer,'actual_outer_workspace_bytes':876,
            'scratch_passed_by876caller_bytes':passed,'caller876_admitted':outer<=876}

def oracle(coeff,log,domain):
    t=1<<log;m=len(coeff)-1
    assert log in (5,6) and 0<=m<=255 and coeff[-1]!=0
    assert all(c==-1 or 0<=c<=t for c in coeff) and sum(abs(c)for c in coeff)==t
    capacity=sizes(log,m)
    if domain=='caller876':assert capacity['caller876_admitted']
    else:assert domain=='standalone_constructor_not_reached876' and not capacity['caller876_admitted']
    if domain!='caller876':capacity['standalone_scratch_supplied_bytes']=capacity['constructor_scratch_required_bytes']
    step=(t//2)+(t//8)+3
    cycle=[(j*step)%t for j in range(t)]
    assert math.gcd(step,t)==1 and sorted(cycle)==list(range(t))
    lows=[s for s,c in enumerate(coeff)if c==-1];nlow=len(lows)
    symbols=[None]*t
    for i,s in enumerate(lows):symbols[t-1-i]=s
    positive_list=[s for s,c in enumerate(coeff)for unused in range(max(c,0))]
    allowed=[p for p in cycle if p<t-nlow]
    assert len(positive_list)==len(allowed)==t-nlow
    for p,s in zip(allowed,positive_list):assert symbols[p]is None;symbols[p]=s
    assert all(s is not None and 0<=s<=m for s in symbols)
    flag=int(not any(c>=t//2 for c in coeff))
    header=log|(flag<<16)
    initial=[1 if c==-1 else c for c in coeff]
    rowbytes=[];rows=[];seen=[0]*len(coeff)
    for state,s in enumerate(symbols):
        v=initial[s]+seen[s];seen[s]+=1
        assert v>0
        bits=log-(v.bit_length()-1)
        base=(v<<bits)-t
        assert 0<=bits<=log and 0<=base and base+(1<<bits)<=t
        rowbytes.append(struct.pack('<HBB',base,s,bits))
        rows.append({'state':state,'symbol':s,'read_counter':v,'bits':bits,'new_state_base':base})
    image=struct.pack('<I',header)+b''.join(rowbytes)
    assert len(image)==4+4*t
    return {'table_hex':image.hex(),'table_sha256':H(image),'bytes':len(image),
            'header_DWORD':header,'high_flag':flag,'low_probability_symbols':lows,
            'permutation_step':step,'full_cycle':cycle,'positive_list':positive_list,
            'filtered_positions':allowed,'rows':rows,'capacity':capacity,
            'domain':domain,'broader_than_actual876caller':domain!='caller876'}

stimuli=[];expected=[];keys=set()
def add(label,coeff,log,domain):
    key=(tuple(coeff),log,domain)
    if key in keys:return
    keys.add(key);case={'id':label,'log':log,'coefficients':coeff,'domain':domain}
    stimuli.append(case);expected.append({'id':label,**oracle(coeff,log,domain)})

for log,limit in [(5,91),(6,11)]:
    t=1<<log
    add(f'l{log}-single-positive',[t],log,'caller876')
    add(f'l{log}-threshold-equal',[t//2,t//2-1,1],log,'caller876')
    add(f'l{log}-threshold-below',[t//2-1,t//2-1,2],log,'caller876')
    for m in sorted({0,1,2,limit//2,limit}):
        n=m+1
        for low in sorted({0,min(1,n-1),min(t-1,n-1)}):
            c=[-1]*low+[0]*(n-low);c[-1]=t-low
            add(f'l{log}-m{m}-N{low}-one-positive',c,log,'caller876')
            slots=list(range(low,n));mass=t-low
            if mass>=len(slots):
                balanced=[-1]*low+[0]*(n-low)
                for i in range(mass):balanced[slots[i%len(slots)]]+=1
                add(f'l{log}-m{m}-N{low}-balanced',balanced,log,'caller876')
    if t-1<=limit:add('l5-all32-low',[-1]*t,log,'caller876')
    if log==6:add('l6-standalone-all-low',[-1]*t,log,'standalone_constructor_not_reached876')
    broad=[0]*256;broad[-1]=t
    add(f'l{log}-standalone-symbol255',broad,log,'standalone_constructor_not_reached876')

units=[]
for log in [5,6]:
    records=[sizes(log,m)for m in range(256)]
    caller=[r['symbols']-1 for r in records if r['caller876_admitted']]
    direct=[r['symbols']-1 for r in records if r['constructor_scratch_required_bytes']<=r['scratch_passed_by876caller_bytes']]
    assert max(caller)==(91 if log==5 else 11) and max(direct)==(95 if log==5 else 15)
    for r in records:
        if r['caller876_admitted']:assert r['scratch_passed_by876caller_bytes']>=r['constructor_scratch_required_bytes']+8
    units.append({'log':log,'caller_m_max':max(caller),'direct_constructor_m_max_with_same_residual':max(direct),
                  'boundary_admitted':sizes(log,max(caller)),'next_rejected':sizes(log,max(caller)+1)})

for name,data in [('STIMULI.json',stimuli),('EXPECTED.json',expected),('WORKSPACE-UNITS.json',units)]:
    (D/name).write_text(json.dumps(data,indent=2)+'\n')
freeze={'scope':'Independent equations before Rust; no target execution or instruction model',
        'code_sha256':'8d7636d905df5188c3a5d0d495cf337bf1eca14949a373cc7e5393f5ae94484e',
        'native_rows':213,'case_count':len(stimuli),
        'caller876_cases':sum(c['domain']=='caller876'for c in stimuli),
        'standalone_only_cases':sum(c['domain']!='caller876'for c in stimuli),
        'actual_units':units,'bindings':{n:H((D/n).read_bytes())for n in ['freeze_oracle.py','STIMULI.json','EXPECTED.json','WORKSPACE-UNITS.json','INDEPENDENT-ADMISSION.json']},
        'no_Rust_source_or_publicC_implementation_read':True,'no_repository_or_public_action':True,
        'not_a_whole_decoder_or_runtime_equivalence_claim':True}
(D/'ORACLE-FREEZE.json').write_text(json.dumps(freeze,indent=2)+'\n')
print(json.dumps({'cases':len(stimuli),'caller876':freeze['caller876_cases'],'standalone':freeze['standalone_only_cases'],'freeze_sha256':H((D/'ORACLE-FREEZE.json').read_bytes())}))
