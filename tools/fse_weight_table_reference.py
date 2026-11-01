"""Independent scalar oracle from the pre-Rust frozen native equations.

This module performs no file, Rust, provider or expected-answer reads. A runner
must authenticate the native provider separately before making a target-bound
claim. Serialized suffix/domain policy follows the explicitly chosen safe API;
it is not native scratch/error parity. No instruction interpreter is present.
"""
import hashlib
import math
import struct

FROZEN_ORACLE_SHA256 = "eb57a5e1ea71e483b5fc9f9113f871f63f0696cefc95145921167f664befd3bd"
H = lambda data: hashlib.sha256(data).hexdigest()

def sizes(log,m):
    t=1<<log;n=m+1
    need=t+2*n+8
    outer=4*(t+((t+2*n+11)//4)+0x83)
    passed=876-(4*t+0x204)
    return {'T':t,'symbols':n,'constructor_scratch_required_bytes':need,
            'outer_workspace_required_bytes':outer,'actual_outer_workspace_bytes':876,
            'scratch_passed_by876caller_bytes':passed,'caller876_admitted':outer<=876}

def _frozen_table(coeff,log,domain):
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

def _qualified(log, max_symbol, normalized):
    if log not in (5, 6) or max_symbol > (91 if log == 5 else 11):
        return False
    t = 1 << log
    if normalized[max_symbol] == 0 or any(normalized[max_symbol + 1:]):
        return False
    prefix = normalized[:max_symbol + 1]
    return all(c == -1 or 0 <= c <= t for c in prefix) and sum(abs(c) for c in prefix) == t


def table_details(log, coefficients):
    """Qualified mathematical table relation; fresh native admission is separate."""
    if type(log) is not int or log not in (5, 6):
        raise ValueError("Unsupported qualified log")
    if not 1 <= len(coefficients) <= 256 or not all(type(c) is int for c in coefficients):
        raise ValueError("Invalid coefficient vector")
    maximum = len(coefficients) - 1
    normalized = list(coefficients) + [0] * (256 - len(coefficients))
    if not _qualified(log, maximum, normalized):
        raise ValueError("Outside actual876 caller domain")
    return _frozen_table(list(coefficients), log, "caller876")


def table_bytes(log, coefficients):
    return bytes.fromhex(table_details(log, coefficients)["table_hex"])


def serialize_case(log, max_symbol, normalized, initial):
    """Pure safe-API policy, returning complete260 bytes including untouched tail.

    Type/shape failures are protocol errors. A typed but nonqualified domain
    yields unsupported and the initial image, without a native error claim.
    """
    if type(log) is not int or not 0 <= log <= 255 or type(max_symbol) is not int or not 0 <= max_symbol <= 255:
        raise ValueError("Invalid u8 stimulus")
    if len(normalized) != 256 or not all(type(c) is int and -32768 <= c <= 32767 for c in normalized):
        raise ValueError("Invalid typed256 coefficient stimulus")
    if type(initial) is not bytes or len(initial) != 260:
        raise ValueError("Invalid initial260 stimulus")
    if not _qualified(log, max_symbol, normalized):
        return {"status": "unsupported", "length": 0, "output": initial}
    prefix = table_bytes(log, list(normalized[:max_symbol + 1]))
    return {"status": "ok", "length": len(prefix), "output": prefix + initial[len(prefix):]}
