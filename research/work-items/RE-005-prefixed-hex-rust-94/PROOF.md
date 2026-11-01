# Node94 414-byte prefixed-hex normal-return relation

This proof was written before any proposed Rust implementation. It uses the
97 complete GNU rows in authenticated-native/primary.rows.json, the matching
414 bytes, actual FDE/CIE, 16-byte table and two separately labelled caller
cuts. Admission receipt 682850d3 authenticates all those contents against one
complete expected-SHA stream without a full-image memory/fixture copy.

## Scope, values and domain

At entry let O=RDI, c=RSI, P=RDX, n=RCX, and f=R8 bit 0. Values are unsigned
64-bit except the explicitly decoded byte/dword operations. Require:

* n>=1 and 2*n+2 representable without u64 overflow;
* c>=2*n+2 and nonwrapping readable P[0,n), writable O[0,c);
* input and output do not overlap, and neither writes nor mutable source
  alias the immutable captured code/table or the active save/return slots;
* the push slot [entrySP-8,entrySP) is writable, the normal return slot
  [entrySP,entrySP+8) and ordinary call/return state are valid, and these
  protected slots do not overlap O or P.

The relevant caller-local output buffers are allowed to be on the caller's
stack. They need only be separate from the callee's active save/return slots,
not from the entire caller-allocated frame. This distinction matters for both
actual callers. No original source-level signature, type or ABI is recovered.

The chosen safe API will take immutable input and a disjoint mutable output
slice, returning the written length; unsupported input/capacity will be a
separate API policy which preserves output. That policy is not parity with
native panic/error states. The safe API will use bool mode, corresponding to
entry low bit 0 or 1. The target tests only that low bit, not arbitrary R8
nonzeroness. Neither R8's runtime provenance nor an original bool type is known.

## I1. Entry size guard and prefix

29ed381 LEA computes (2*n+1) modulo 2^64. Under the domain it equals 2*n+1.
29ed389/38c unsigned CMP/JBE calls the out-of-domain helper when c<=2*n+1.
The admitted branch therefore continues. 29ed392 stores little-endian WORD
0x7830, exactly bytes '0x' at O[0,2). No NUL is stored. 29ed397/39a tests
n and branches to a bounds call for zero; our n>=1 excludes it. The initial
capacity requirement is 2*n+2 even if the later mode omits one nibble.

## I2. First byte and optional one-nibble omission

29ed3a0 reads the first byte to zero-extended R9D. 29ed3a4/3a8 computes
R10B=(byte<16). 29ed3b1 tests R8B AND R10B, so define delta=1 iff f=1 and
byte<16. Let a=3-delta: EAX is 2 on the omission branch and 3 otherwise.
When delta=0, SHR4 selects the byte's high nibble, the RIP LEA resolves to
0x208620, and table[index] is written at O+2. All table indices are 0..15;
the independently admitted bytes are '0123456789abcdef'. When delta=1 the
high nibble is omitted, even when the whole first byte is zero. No later
zero byte receives this treatment.

29ed3d0/3d3 checks a<c. Since a<=3 and c>=4, it cannot take the panic edge.
AND15 selects the low nibble, the second independently resolved LEA names
the same table, and its digit is written at O+a. R9 becomes a+1. Therefore
the first byte's contribution is exactly one or two lowercase digits and
the written prefix length is a+1=4-delta.

## I3. n=1 and n=2 exits

If n=1, 29ed3f1/3f5 reaches the common end with length a+1=2*n+2-delta.
Otherwise R9=a+1<c because n>=2 implies c>=6, so 29ed3fe cannot panic.
29ed404 reads P+1 once, its high digit is written at O+a+1, and
29ed41e/421 checks a+2<c. a+2<=5 and c>=6 close this bound. Its low digit
is written at O+a+2. If n=2, 29ed43b adds 3 to a and uses that as length,
giving a+3=6-delta=2*n+2-delta. Reads and writes are within the stated slices.

## I4. Remaining loop and finite progress

For n>=3, 29ed444 sets RAX=a OR4. a is 2 or 3 with bit2 clear, so this is
a+4. 29ed448 initializes R11=2; 29ed44e sets R8=a+4. At the loop head
with input index i=R11, maintain i in [2,n), and R8=2*i+3-delta.

* The high store index R8-1=2*i+2-delta is at most 2*n-delta<c, so the
  unsigned JAE at29ed467 is not taken.
* 29ed469 reads exactly P+i, within the input. Its SHR4 table digit is
  stored at O+R8-1. No second source read is needed for the low digit.
* R8=2*i+3-delta is at most 2*n+1-delta<c, excluding 29ed482's call edge.
  The AND15 table digit is then stored at O+R8.
* R8+=2 and R11+=1 establish the invariant for i+1. At i+1=n the JNE
  falls through. There are exactly n-2 iterations. The input index never
  wraps, and no source read occurs at i=n.

The largest transient R8 is 2*n+3-delta. Because 2*n+2 is even and fits
u64, it is at most 2^64-2; therefore even this transient is at most 2^64-1.
No cursor increment or index arithmetic wraps in the proof domain.

## I5. Common end, stores and return

The loop decrements R8 once and moves it to R9, giving 2*n+2-delta. Both
short exits already have this same value. The unsigned JA at29ed4a5 cannot
take its helper edge because length<=2*n+2<=c. 29ed4a7 returns original O
in RAX and 29ed4aa copies the length to RDX. POP/RET use only the protected
slots; arrival at local RET is proved, while actual hardware return assumes
the declared ordinary call/return state.

Apart from the explicit callee save slot, the only writes are the prefix and
successive digit bytes, covering exactly O[0,length). Every remaining byte
O[length,c) retains its entry value. All input bytes and the digit table are
read-only. No helper is called on this domain. Exact output is '0x' followed
by the lowercase bytewise hexadecimal form, with only its first high '0'
omitted when delta=1. This is a safe-slice result/mutation projection, not a
claim of an original Rust layout, physical fault/load timing or whole-node ABI.

## I6. Refusal and context limits

All six static call sites are retained, not erased from the denominator:
29ed4be -> slot576e2e0; 29ed4d7 -> slot576e108; and29ed4e7/4f7/508/518
-> slot576dfc8. They are excluded because our inequalities prove their edges
unreachable, not because their bodies or noreturn behavior were assumed.
Empty input with c>=2 writes the prefix before its bounds call; short output
reaches the initial helper before the prefix. We do not claim a resulting
error value, output preservation or behavior after a helper returns.

The separately admitted69-byte bridge cut at32479e1..3247a26 sets n=32,
c=66, R8=0, calls through the actual unique RELATIVE slot5773120, then
passes RAX as the string pointer and leaves RDX as the length to3599a40.
The separately admitted169-byte proposer FDE at4670030..46700d9 contains
the analogous n=20,c=42,R8=0 call at4670095 and subsequent string-writer
call4aeb170. These calls establish concrete uses, not their complete parent
semantics, legal field values, signing/hash behavior or end-to-end encoding.
Primary semantic denominator remains414 bytes/97 instructions; those238
context bytes, table16 and FDE/RELA metadata are not added as recovered code.

No target, compatible assembly object or instruction evaluator is executed.
No unlicensed inferred implementation has been read or copied. New source
will be independently authored MIT; captured evidence retains original rights.
