from pathlib import Path
import hashlib,json,datetime
P=Path(__file__).parent;N=Path('/tmp/hl-three-digit-rust-intake-20261101/native-admission-1')
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert h(N/'ADMISSION.json')=='5f52e8e8180a3706a0009635f367a806a6953e0a6a665c28959d02ba8a20f41f'
raw=(N/'primary.bin').read_bytes();rows=json.loads((N/'primary.rows.json').read_text());assert len(raw)==85
# These are closed integer predicate checks, not instruction stepping.
for b in range(256):
 assert (((b-58)&255)>=247)==(49<=b<=57)
 assert (((b-48)&255)<10)==(48<=b<=57)
def expected(data):
 if len(data)!=3:return 0
 a,b,c=data
 if not (49<=a<=57 and 48<=b<=57 and 48<=c<=57):return 0
 return 100*(a-48)+10*(b-48)+(c-48)
records=[]
def add(category,core,left=b'',right=b''):
 i=len(records);identifier='repeat'if i in (0,12,30,46,63)else ('P'+str(1000-i))
 value=expected(core);assert value==0 or 100<=value<=999
 records.append({'id':identifier,'category':category,'left_hex':left.hex(),'slice_hex':core.hex(),'right_hex':right.hex(),'expected':value})
for text in ['100','101','109','110','199','500','909','990','998','999','202','707']:add('valid_already_author_covered',text.encode())
for data in [b'\x00\x00\x00',b'\xff\xff\xff',b'\xb1\xb2\xb3',b'1\xb0\xb9',b'\xb1\xb09',b'/0/',b':\xff9',b'9:\x00',b' \t9',b'+1-',b'-+2',b'099',b'000',b'1\x00\xff',b'9\xff\x00',b'\x7f12',b'12\n',b'1\r\t']:add('malformed_three_byte',data)
for data in [b'',b'1',b'12',b'1234',b'123\0',b'0123',b'99999',b'100000',b'1234567',b'0123456789',b'9'*16,b'9'*31,b'\xff'*4,b'\0'*2,b'\xff',b'\0'*8]:add('wrong_length_with_digit_neighbors',data,b'100',b'999')
for core in [b'100',b'999',b'099',b'1/9',b'\xff00',b'500']:
 for left,right in [(b'\xff\0:9',b'123\0'),(b'999999',b'000'),(b'',b'\xff'*8)]:add('neighbor_poisoned_slice',core,left,right)
assert len(records)==64
(P/'STIMULI.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
(P/'INPUTS.txt').write_text(''.join(f"{r['id']} {r['left_hex']or'-'} {r['slice_hex']or'-'} {r['right_hex']or'-'}\n"for r in records))
(P/'EXPECTED.txt').write_text(''.join(f"{r['id']} {r['expected']}\n"for r in records))
(P/'DERIVATION.md').write_text('''# Independent pre-Rust parser derivation

Target node94 SHA3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
The admitted primary is85 bytes at0x1683670..0x16836c5; no helper or loop.
I derived the returned-value expectations from the30 primary instruction rows;
the31-byte caller relation is separate. The admission also contains1301B caller
boundary metadata, whose prefix was displayed during the intake read; it is not
used to infer fullcaller semantics. I did not read the author's oracle/generator
or future Rust implementation.

The first CMP compares the full RSI length against3. Its JNE reaches XOR EAX,EAX
and RET before any data read. For length3, the primary loads exactly BYTE[rdi],
BYTE[rdi+1], BYTE[rdi+2] before validity flags are calculated. Later DIL clobber
therefore cannot affect those reads. This is a returned-value projection under
valid readable3B input, ordinary return/frame and immutable/separated-input
conditions, not a Rust/private ABI or a physical read-order equivalence claim.

For first byte a, the low byte of(a-58) is compared unsigned against247;
SETB is an error exactly outside ASCII1..9. The accepted wrapped interval
247..255 corresponds to a49..57. For the other two bytes, the low byte of
(b-48)/(c-48) must be below10, exactly ASCII0..9. All256 values for each
independent predicate were checked as closed integer equations. OR combines
three one-bit error flags; success requires all three in range. This proves
rejection for every malformed length3 byte combination without CPU emulation.

On success, zero-extension and IMUL100 give100*(a-48). The double/LEA sequence
makes10*(b-48), at most90, so its later AL zero-extension loses no bits.
Adding the final digit yields100..999, no overflow or truncation. Error returns
zero. No source type/result arity, original compiler or machine-byte identity
is inferred. A safe &[u8] API covers valid references; it does not claim invalid
native pointers are representable in Rust even when a wrong length avoids loads.

The separate31-byte selected context loads RDI/RSI from physical+8/+16 slots,
calls this entry, tests AX, branches away if zero, otherwise stores AX as WORD
then7 as BYTE at destination+64. This is only the observed local relation if
that context executes normally, not private object types or fullcaller closure.

64 independent records comprise12 valid values already covered by the author's
all900 corpus,18 malformed triples,16 wrong-length slices with digit neighbors,
and18 neighbor-poison contexts. Their numerical values are not claimed novel;
useful controls are malformed combinations, exactlength and slicecontext.
Repeated/non-sorted IDs require output multiplicity and original order; they
are an own-client protocol check, not native metadata. The runtime input file
contains no expected answers. Neighbor invariance checks defined returned
values; it does not instrument machine memory access or establish a no-read
hardware boundary. No target execution, CPU interpreter, compiler or network
was used to construct these expectations.
''')
d={'schema':'three-digit-independent-pre-Rust-expectations-v1','at_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','admission_sha256':h(N/'ADMISSION.json'),'primary_bytes':85,'primary_sha256':h(N/'primary.bin'),'primary_listing_sha256':h(N/'primary.objdump.txt'),'caller_context_bytes':31,'caller_context_sha256':h(N/'selected-caller-context.bin'),'records':64,'categories':{c:sum(r['category']==c for r in records)for c in sorted({r['category']for r in records})},'valid_values_already_author_covered_no_unseen_valid_claim':True,'expected_domain':'0 or100..999 fromclosedbytepredicates/weighteddecimalexpression','input_ids_nonsorted_and_repeated':True,'runtime_inputs_have_no_expected_answers':True,'author_generator_answers_or_production_Rust_read':False,'new_image_admission_or_target_execution_or_compiler':False,'files':{n:{'bytes':(P/n).stat().st_size,'sha256':h(P/n)}for n in ['STIMULI.json','INPUTS.txt','EXPECTED.txt','DERIVATION.md','freeze_expectations.py']}}
(P/'EXPECTATIONS-FREEZE.json').write_text(json.dumps(d,indent=2,sort_keys=True)+'\n');print(json.dumps({'status':'INDEPENDENT_EXPECTATIONS_FROZEN_BEFORE_RUST','sha256':h(P/'EXPECTATIONS-FREEZE.json'),'records':64,'categories':d['categories'],'primary_sha256':h(N/'primary.bin')},indent=2))
