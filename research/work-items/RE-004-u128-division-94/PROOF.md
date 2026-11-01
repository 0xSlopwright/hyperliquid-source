# Complete nonzero-divisor contract of node94's 198-byte leaf

Read-only design intake. No new target read, native execution, interpreter,
compiler, public source edit or worktree. The proof uses the retained complete
71-row GNU listing and 198 bytes from the independently authenticated node94
FDE `[0x565f5a0,0x565f666)`, body SHA256
45f632dd0c1fc0915e680ad7ad98cabda1fcf34ba7835c2e73e3569b570a288d.
The #1161 named-artifact correspondence is corroboration, not a premise that the
helper performs division. Below, DIV means the specified unsigned x86 instruction.

## Contract and execution domain

Let B=2^64. At entry define n = RDI + B*RSI and d = RDX + B*RCX,
where each register is interpreted as an unsigned 64-bit bitvector. Write
n=a+B*b and d=l+B*h. The numerical theorem is for all 0<=n<B^2 and 0<d<B^2.
On a normal local RET, RAX+B*RDX = floor(n/d).

Ordinary x86-64 instruction semantics are assumed, with immutable complete code,
no asynchronous register/code mutation, executable mapped instructions and a
valid ordinary call/return state. For entry RSP=S, [S,S+8) contains a usable return
address; on h>0, [S-8,S) is writable/readable storage for saving RBX. The relevant
stack address operations do not wrap or corrupt the immutable code/return word.
A uniform safe bridge may require this entire frame even when h=0 does not push.
This does not recover an original Rust ABI or arbitrary fault/alias/unwind state.

There are no calls, loops or static-data references in these 71 rows. The only
non-register memory operations are PUSH/POP RBX on h>0 and RET. RBX is restored;
RBP/R12-R15 are never written. Stack-save bytes may be overwritten on the h>0
path. A numerical Rust API does not reproduce physical clobbers/store timing.
The four RET addresses are 0x565f61d, 0x565f631, 0x565f652 and 0x565f665.

## Complete partition

0x565f5a0 copies incoming l to R8. TEST RCX/JE at 0x565f5a3..5a6 selects
h=0 versus h>0. Those disjoint cases exhaust every d!=0.

### 1. h=0 and b<l: 0x565f61e..0x565f631

Because d!=0 and h=0, l>0. CMP RSI,R8 followed by unsigned JAE selects b>=l;
its fallthrough therefore has b<l. MOV RAX,RDI; MOV RDX,RSI forms n=b*B+a.
The 64-bit DIV R8 at 0x565f629 is safe: divisor l>0 and high numerator b<l,
so n/l < B. It returns floor(n/l) in RAX. XOR ECX,ECX and MOV RDX,RCX
set the returned high quotient word to zero. This is the required 128-bit q.
The hardware remainder is deliberately overwritten; no remainder API is claimed.

### 2. h=0 and b>=l: 0x565f632..0x565f665

MOV RAX,RSI; OR RAX,R8; SHR RAX,32; JE at 0x565f632..63c chooses whether
both b and l are below 2^32. These are the only two remaining branches.

2a. If either word has a nonzero high32, 0x565f63e..652 performs a first
64-bit DIV of the numerator b. Its pair is RDX:RAX = 0:b; the high word is zero. XOR EDX,EDX zeros the entire RDX. Since b<B and l>0,
this division fits, yielding b=qh*l+rh, 0<=rh<l and qh<B. It saves qh in
RCX, loads a into RAX, and divides the pair rh:a at 0x565f64c. The second
DIV is safe because rh<l; it yields ql=floor((rh*B+a)/l)<B. Hence
n=(qh*B)*l+(rh*B+a) and floor(n/l)=qh*B+ql. MOV RDX,RCX returns qh.

2b. If (b|l)>>32 == 0, both b,l<2^32 and still l>0. At 0x565f653,
MOV EAX,ESI reproduces b exactly and zero-extends it; XOR EDX,EDX zeros RDX.
The first DIV R8D at 0x565f657 is a 32-bit division of b by l. Its quotient
fits32 because b<2^32 and l>=1. Its quotient/remainder writes zero-extend
EAX/EDX. MOV ECX,EAX saves qh without upper-word garbage. The second 64-bit
DIV at 0x565f65f again uses rh:a with rh<l and is safe. The same digit identity
from 2a proves the returned qh:ql. The b>=l condition does not invalidate either
first division; their numerator high word is explicitly zero, not b.

### 3. h>0: normalization, estimate and correction, 0x565f5a8..0x565f61d

BSR R9,RCX at 0x565f5a9 is defined because h!=0. Let s=floor(log2(h)),
0<=s<=63, and e=s+1 in [1,64]. MOV EDX,R9D; XOR EDX,63 produces 63-s:
s occupies only six bits, so six-bit complement equals subtraction from63.
MOV AL,64; SUB AL,DL produces e exactly in AL. Other incoming EAX bits are
irrelevant: only CL's low count bits and TEST AL,64 are used until full RAX
is replaced by b before DIV.

At 0x565f5b7..5cb, SHRD RDX,R11,CL and SHR R10,CL construct
M=floor(d/2^e). For e<64, TEST AL,64 has ZF=1 and CMOVE selects
(l>>e)|(h<<(64-e)), the low word of d>>e. It fits64. For e=64 (s=63),
x86 masks shift counts to zero; TEST AL,64 has ZF=0 and CMOVE does NOT select
the unchanged l. R10 stays h, exactly d>>64. Thus the endpoint is handled,
not a Rust shift-by64 assumption. In every case 2^63<=M<B.

MOV RAX,RSI; SHLD RAX,RDI,63; MOV RDX,RSI; SHR RDX,1 at 0x565f5cf..5da
form exactly floor(n/2) in RDX:RAX: lowword=(b<<63 mod B)|(a>>1), highword=b>>1.
DIV R10 at 0x565f5dd is always safe: M>=2^63>0 and its high numerator
b>>1<2^63<=M. Its quotient t=floor(floor(n/2)/M)=floor(n/(2M)) is below B.
MOV ECX,R9D; SHR R10,CL then computes
Qhat=floor(t/2^s)=floor(n/(M*2^(s+1))). Its count s is always0..63,
including s=0; the prior e=64 case does not leak into this count.

Put D'=M*2^e and delta=d-D'. Since d has highest bit64+s,
D'>=2^(64+s), 0<=delta<=2^(s+1)-1, and D'<=d. Consequently

    0 <= n/D' - n/d = n*delta/(D'*d)
       < (2^(s+1)-1)/2^(2s) <= 1.

The last inequality holds for s=0 (1=1), and for s>=1 because s+1<=2s.
The strict inequality uses n<2^128; when delta=0 the difference is0 directly.
Taking floors proves Qhat is either q=floor(n/d) or q+1. This is a complete
input-domain error bound, not a finite-vector inference.

XOR ECX,ECX makes all64 bits of RCX zero. SUB R10,1 followed by CMOVB R10,RCX
at 0x565f5e9..5ef therefore gives q0=max(Qhat-1,0). Thus
0<=q0<=q<=q0+1. In particular q0*d<=n<B^2, so the next product has no
128-bit overflow. Also h>0 implies d>=B and therefore q<B.

0x565f5f3..606 computes q0*d as a two-word product: MUL supplies the low product
l*q0 and its highword; low64 IMUL supplies h*q0; ADD forms the high product word.
Signed IMUL has the same low64 product bits, and its overflow flags are unused.
The true product fits128 as proved above, so this reconstruction loses no needed
high bits. SUB RDI,R9; SBB RSI,RDX at 0x565f609..60c computes exact
r=n-q0*d>=0 as a two-word value. Since q-q0 is0 or1, 0<=r<2*d; r also fits128
because r<=n<B^2, even if 2*d itself needs129 mathematical bits.

CMP RDI,R8; SBB RSI,R11 at 0x565f60f..612 sets CF exactly when r<d, using
lowword borrow then highword subtraction. SBB RAX,-1 at 0x565f615 uses the
sign-extended immediate all-ones and returns q0+1-CF. This is q0 when r<d,
or q0+1 otherwise, hence exactly q. Its increment cannot overflow64: an increment
means q0<q<B. POP restores RBX, and MOV RDX,RCX sets returned highword0.
No later instruction changes RAX. This proves the fourth numerical return path.

## Caller connection and excluded inputs

The exact mapped slot 0x576e1a8 resolves to this leaf, as already retained in1161.
The accepted L1-transfer-fee symbolic call witness reads dividend low/high from
RDI/RSI and divisor low/high from RDX/RCX, then expects quotient low/high in
RAX/RDX (`tools/l1_evm_transfer_fee.py`, do_call). It explicitly refuses a zero
single-word divisor and requires a nonzero OR-test fact for a two-word divisor.
Our result would discharge only this known unsigned-division primitive on those
nonzero call inputs; no new claim about the entire caller follows. Other callers
must separately establish the entry registers/nonzero guard and environment.
The primitive theorem admits arbitrary n, including0 and2^128-1; no caller-specific
product-range, units, rounding, fee or overflow policy is smuggled into it.

d=0 is outside the numerical theorem. Native h=0,l=0 reaches a DIV-byzero site;
this does not define the process's signal/exception behavior. A new safe Rust
API can exclude zero with core::num::NonZeroU128 without emulating this runtime
fault or claiming zero-input parity. No private ABI or original Rust type is needed.

## Independently chosen Rust implementation design

Proposed API (no source materialized yet):

    pub fn quotient(n: u128, divisor: core::num::NonZeroU128) -> u128

Use a standard128-step restoring algorithm, not u128 `/` or `%`, and not the
native quotient-estimate algorithm. Maintain the already-consumed high-bit prefix
p=q*d+r with0<=r<d. Read the next input bit from127 down to0, replace q by2*q,
and form w=2*r+bit; if w>=d, subtract d and set the new low quotient bit.
Because r<d, w<2*d, so at most one subtraction restores0<=r<d and preserves
p=q*d+r. Start with the empty prefix p=q=r=0 and perform exactly128 steps.
At the end p=n and Euclidean uniqueness gives q=floor(n/d).

For this exact fixed-width input, no129th-bit machinery is needed. Before reading
any bit, the consumed prefix has at most127bits and r<=p<2^127. Thus2*r+bit
is always below2^128; neither shift/OR loses a required bit. Also q<=p because
d>=1, so shifting the partial q for the next prefix cannot overflow128 either.
The conditional subtraction is nonnegative and fits128. This stronger prefix
bound means an explicit saved carry would always be zero here; it must not be
advertised as a testable extra behavior. The earlier carry/wrapping design was
correct but unnecessarily general and is retained privately as preparation.
No upstream specialized_div_rem implementation has been read or copied;
licensed source declarations are corroboration only.

Later qualification must statically inspect actual produced own-library objects
for division/remainder builtin dependencies, including __udivti3/__umodti3/
__udivmodti4, rather than assuming an optimizer cannot reintroduce one. Builds
are two fixed pinned-rustc profiles only; all produced programs are our own code.
A separately authored oracle should derive native branch/normalization/correction
expressions from admitted actual operands, not reuse this restoring implementation.
Finite corpus/semantic mutants support the two proofs; they do not replace them.
