"""Independent mathematical cases from admitted native facts; no target evaluator.

Only Python integer/string mathematics is used. No repository/Rust implementation
is read/imported; no compiler, disassembler, captured code or emulator is run.
"""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent
INTAKE=Path('/tmp/hl-primitive-value-intake-20261031')
U64=(1<<64)-1
FLAG_LOWER=1<<25
FLAG_UPPER=1<<26

def sha(raw):return hashlib.sha256(raw).hexdigest()
def emit(name,value):
    raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();(OUT/name).write_bytes(raw)
    return {'bytes':len(raw),'sha256':sha(raw)}

def pin(path,digest):
    raw=path.read_bytes()
    if sha(raw)!=digest:raise ValueError('Independent native fact input changed')
    return raw

core=pin(INTAKE/'actual-selected-metadata/0x1570470.bin','bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f')
context=pin(INTAKE/'actual-selected-metadata/0x14f7660.bin','a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf')
tables_raw=pin(INTAKE/'SELECTED-TABLES-AND-HELPERS.json','6a68407a3ca89994c5416032c3052e25aba52326a644e9357b75eb14b8d3ca86')
tables=json.loads(tables_raw)['tables']
assert bytes.fromhex(tables['decimal-pairs']['raw'])==''.join(f'{n:02d}' for n in range(100)).encode()
assert bytes.fromhex(tables['nibble-table-25']['raw'])==b'0123456789abcdef'
assert bytes.fromhex(tables['nibble-table-26']['raw'])==b'0123456789ABCDEF'
assert bytes.fromhex(tables['base16-prefix']['raw'])==b'0x'

M=int.from_bytes(core[0x157049a-0x1570470:0x157049a-0x1570470+8],'little')
assert M==0x346dc5d63886594b
assert 10000*M-(1<<75)==432 and 432*U64<(1<<75)
assert 5243*100-(1<<19)==12 and 12*9999<(1<<19)
assert 5243*25-(1<<17)==3 and 3*(999//4)<(1<<17)
assert all((x*5243)>>19==x//100 for x in range(10000))
assert all((((x//4)*5243)>>17)==x//100 for x in range(1000))

values=set(range(129))|set(range(990,1011))|set(range(9990,10012))
for k in range(20):
    values.update(n for n in range(10**k-2,10**k+3) if 0<=n<=U64)
for k in range(64):values.update(n for n in ((1<<k)-1,1<<k,(1<<k)+1) if 0<=n<=U64)
for pair in range(100):
    values.add(10000+101*pair)
    values.add(100000000+100010001*pair)
values.update([9999998,9999999,10000000,10000001,(1<<63)-1,1<<63,(1<<63)+1,U64-1,U64,0x0102030405060708,0x8080808080808080,0xaaaaaaaaaaaaaaaa,0x5555555555555555,0x123456789abcdef0])
values=sorted(values)

def marker(index):return bytes(0x80+((index*11+i*37)%128) for i in range(20))
def native_decimal_store_offsets(digits):
    # Mathematical chunk/tail partition proved from the actual repeat threshold;
    # not a PC/register/instruction interpreter. g=floor(digit_count/4).
    groups,tail=divmod(len(digits),4)
    offsets=[]
    for group in range(groups):offsets.extend(range(20-4*(group+1),20-4*group))
    end=20-4*groups
    if tail==1:offsets.append(end-1)
    elif tail==2:offsets.extend([end-2,end-1])
    elif tail==3:offsets.extend([end-2,end-1,end-3])
    assert len(offsets)==len(digits) and len(set(offsets))==len(offsets)
    assert set(offsets)==set(range(20-len(digits),20))
    return offsets

stimuli=[];expected=[]
for index,value in enumerate(values):
    before=marker(index);digits=str(value).encode('ascii');start=20-len(digits);after=before[:start]+digits
    stimuli.append({'value':value,'buffer_hex':before.hex()})
    expected.append({'case_label':'decimal-'+str(value),'value':value,'start':start,'end':20,'length':len(digits),'digits_ascii':digits.decode(),'buffer_hex':after.hex(),'native_store_offsets':native_decimal_store_offsets(digits),'physical_generated_rust_store_order_claimed':False})
    assert 0<=start<=19 and len(after)==20
    assert (value*M)>>75==value//10000

selector_values=sorted({0,1,7,9,10,15,16,31,99,100,255,256,4095,4096,0xabcdef,0xdeadbeef,1<<63,U64})
selector_pairs={(n,f) for n in selector_values for f in (0,FLAG_LOWER,FLAG_UPPER,FLAG_LOWER|FLAG_UPPER,(1<<32)-1)}
selector_pairs.update((0xabcdef,1<<bit) for bit in range(32))
selector_pairs.update((n,f) for n in range(16) for f in (FLAG_LOWER,FLAG_UPPER))
selector_stimuli=[];selector_expected=[]
for index,(value,flags) in enumerate(sorted(selector_pairs)):
    before=marker(index+len(values));mode='lowerhex' if flags&FLAG_LOWER else 'upperhex' if flags&FLAG_UPPER else 'decimal'
    digits=(format(value,'x') if mode=='lowerhex' else format(value,'X') if mode=='upperhex' else str(value)).encode('ascii')
    end=20 if mode=='decimal' else 16;start=end-len(digits);after=before[:start]+digits+before[end:]
    selector_stimuli.append({'value':value,'flags_low_dword':flags,'buffer_hex':before.hex()})
    selector_expected.append({'case_label':f'selector-{value}-{flags:08x}','mode':mode,'digits_ascii':digits.decode(),'native_digits_start_relative_B':start,'native_digits_end_relative_B':end,'digits_length':len(digits),'native_buffer_B_equals_selector_SP_plus':4,'native_buffer_hex':after.hex(),'prefix_bytes_hex':'' if mode=='decimal' else '3078','native_prefix_pointer_word':1 if mode=='decimal' else 0x252bed,'native_prefix_length':0 if mode=='decimal' else 2,'native_RSI_word':1,'qualified_original_return_or_rendered_output':False,'checked_by_future_rust_component':False})
    assert 0<=start<end<=20 and len(after)==20
    if mode!='decimal':assert after[16:]==before[16:]

files={}
files['DECIMAL-STIMULI.json']=emit('DECIMAL-STIMULI.json',stimuli)
files['DECIMAL-EXPECTED.json']=emit('DECIMAL-EXPECTED.json',expected)
files['SELECTOR-CONTEXT-STIMULI.json']=emit('SELECTOR-CONTEXT-STIMULI.json',selector_stimuli)
files['SELECTOR-CONTEXT-EXPECTED.json']=emit('SELECTOR-CONTEXT-EXPECTED.json',selector_expected)
math={'reciprocal10000':{'M':M,'shift':75,'error_numerator':432,'u64_bound':432*U64,'denominator':1<<75,'minus_one_counterexample':{'n':10000,'wrong_q':(10000*(M-1))>>75,'required_q':1}},'reciprocal100':{'M':5243,'shift':19,'domain':[0,9999],'error_numerator':12,'checked_inputs':10000,'minus_one_counterexample':{'n':100,'wrong_q':(100*5242)>>19,'required_q':1}},'tail_hundreds':{'M':5243,'pre_shift':2,'post_shift':17,'domain':[0,999],'error_numerator25':3,'checked_inputs':1000,'minus_one_counterexample':{'n':100,'wrong_q':((100//4)*5242)>>17,'required_q':1}},'all_u64_decimal_digits':{'minimum':1,'maximum':20,'minimum_four_digit_groups':0,'maximum_four_digit_groups':5,'tail_digits':[0,1,2,3],'loop_repeat_old_quotient_above':9999999},'decimal_table_sha256':tables['decimal-pairs']['sha256'],'prefix_and_table_ownership':'Target byte evidence; no upstream source implementation copied.'}
files['MATHEMATICAL-BOUNDARIES.json']=emit('MATHEMATICAL-BOUNDARIES.json',math)
freeze={'schema':'independent-digit-span-preimplementation-freeze-v1','status':'FROZEN before new Rust exists/is read','input_native_core':{'bytes':len(core),'sha256':sha(core),'scope':'444-byte primary capacity20 converter'},'input_selector':{'bytes':len(context),'sha256':sha(context),'scope':'235-byte separate conditional selector/native forwarding context'},'input_tables_sha256':sha(tables_raw),'files':files,'decimal_cases':len(stimuli),'decimal_length_set':sorted({e['length'] for e in expected}),'selector_context_cases':len(selector_stimuli),'selector_flags_literal_bit_count':32,'selector_context_mode_counts':{mode:sum(v['mode']==mode for v in selector_expected) for mode in ('decimal','lowerhex','upperhex')},'expected_generation':'Independent Python integer/str/format mathematics plus observed native chunk/store coordinate facts; never generated by a proposed Rust answer or target instruction model.','future_rust_API_agreed':'write_decimal_suffix(value:u64, buffer:&mut[u8;20])->usize; decimal only, preserves arbitrary prefix and returns start offset','selector_hex_or_downstream_rust_stub_added':False,'expected_answers_enter_runtime_driver':False,'no_original_G_ABI_render_or_gate_claim':True,'actions':{'new_rust_source_read':False,'new_rust_exists_at_author_confirmation':False,'repository_modules_imported':False,'target_or_instruction_emulator_execution':False,'native_tools_or_compiler':False,'full_image_file_or_new_target_copies':False,'repository_edits_git_or_public_actions':False}}
emit('EXPECTATIONS-FREEZE.json',freeze)
print(json.dumps({'decimal_cases':len(stimuli),'selector_context_cases':len(selector_stimuli),'freeze_sha256':sha((OUT/'EXPECTATIONS-FREEZE.json').read_bytes()),'decimal_stimuli_sha256':files['DECIMAL-STIMULI.json']['sha256'],'decimal_expected_sha256':files['DECIMAL-EXPECTED.json']['sha256']},sort_keys=True))
