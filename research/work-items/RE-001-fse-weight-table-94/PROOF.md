# Actual771-byte table constructor under the admitted header invariant

This is a finite static proof, not an implementation, instruction evaluator,
runtime test, original-source attribution or whole-decoder qualification.
Node #94 identity is91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact FDE `[556fb60,556fe63)` is771 bytes, SHA-256
`8d7636d905df5188c3a5d0d495cf337bf1eca14949a373cc7e5393f5ae94484e`.
The complete byte-checked GNU listing has213 rows,24 encoded direct branches,
one RET (`556fd38`), no CALL and no RIP-relative data references.

## Actual caller and input premises

The selected decoder calls at556ff55 with O=RDI=A+0x200, C=RSI=A,
EDX=m, ECX=l, Q=R8=A+(4*T+0x204), and scratch capacity R9 equal to the
remaining advertised workspace after that Q offset, where T=2^l.
The preceding header proof and actual outer limit establish l5 or6, m in
0..255 and the initialized physical WORD invariant in
`UPSTREAM-NORMALIZED-INVARIANT.md`: a_i=-1 or0..T, sum|a_i|=T,
a_i=0 beyond m, and a_m nonzero. Here T is32 or64. Let B=m+1.
No public C function name or inferred reference label supplies these facts.

Require normal accessible nonwrapping and separated regions for the
read-only count area C[0..512), output O[0..4+4*T), scratch
Q[0..2*B+T+8), and own saved/red-zone frame/return/code. The caller's
source/other used cells must not alias these writes. The actual relative
caller coordinates make the count area, output and scratch adjacent and
nonoverlapping; their total advertised-size condition is checked below.
Architectural integer/BSR/SSE operations and ordinary memory are assumed,
not runtime CPU/provider/original ABI claims. There are no opaque helpers
in this body, so no hidden callee postcondition is used.

## Entry guards and workspace implication

The body forms T+2*B+8 and rejects if R9 is smaller or m>255
(`556fb7c..556fb9e`), returning raw-46. It then rejects l>12 as raw-44.
The actual header/caller l5/6 and m bounds satisfy the latter guards.

The decoder's earlier workspace check requires total advertised size at
least `4*(T+floor((T+2*B+11)/4)+0x83)`. Since T is a multiple of4 and
2*B is even, this is `5*T+2*B+532` for even B or `5*T+2*B+534` for odd B.
The actual Q offset plus this constructor's required scratch is
`(4*T+516)+(2*B+T+8)=5*T+2*B+524`, at least8 bytes smaller. Thus a passed
outer workspace check implies this exact constructor scratch check, with
no wrap under the small admitted scalar bounds. For the measured actual
workspace size876 this is a conditional admission, not a claim that all
possible header m/l pairs fit that workspace.

## First loop: low-probability symbols and next counters

The loop `556fc24..556fc4f` visits exactly i=0..m. It reads one initialized
WORD C[i]. A cell with bits0xffff is handled separately: it writes symbol
byte i to table slot h=T-1,T-2,... (`556fc39`) and sets scratch next_i=1
(`556fc43`). Otherwise it sets scratch next_i=a_i (`556fc0c`). Every
scratch WORD i is initialized once. Every symbol i fits one byte.

Let N be the number of-1 cells. The input identity gives0<=N<=T and
sum_{a_i>0}a_i=T-N. The low writes therefore cover exactly the N reserved
slots T-N..T-1, once each; no write uses a negative index. If N=T, the
last valid store is slot0, and only afterward does h wrap to0xffffffff.
There is no further low store in that case. This edge is preserved.

The low16 header is l. Its high16 is a Boolean F, initially1 and set to0
if any nonnegative coefficient is at least T/2, via the signed-WORD
comparison and CMOVGE (`556fc08..556fc17`). Negative-1 cells bypass that
comparison. The R12 flag only chooses how the same final header is formed;
the all-1 case retains the initial F=1. The DWORD at O (`556fc85`) is
exactly l|(F<<16), with no inferred nominal header type.

## Coverage when at least one low cell exists

The code uses stride s=T/2+T/8+3:23 for T32 and43 for T64. Both are odd,
so gcd(s,T)=1. Repeated `(p+s)&(T-1)` visits every table index exactly once
per full cycle. For0<N<T, the loop skips indices above h=T-N-1 and thus
visits every unreserved index0..h exactly once before repeating0.

For each positive coefficient a_i, `556fcb3` writes symbol i at the current
unreserved index and repeats exactly a_i times (`556fccb..556fcd1`). The
advance/skip loop is `556fcc0..556fcc9`. The total number of positive
writes is T-N, precisely the number of unreserved slots. These writes are
therefore disjoint from the N reserved low slots and cover every remaining
slot once. The final p is0, so the raw-1 refusal at556fce0..556fcea is
unreachable under this premise. Skipping terminates: every full odd-stride
cycle contains an unreserved index. Arithmetic p+s is at most106 here,
then the actual mask restores0..T-1.

If N=T, there are no positive coefficients. The positive-write loops are
skipped, p remains0 and all T symbols were already written by the first
loop. This does not enter an infinite skip loop or assume a positive cell.

## Separate optimized coverage when N=0

Equality of the final h and T-1 branches at556fc8a to556fd39. All a_i are
then nonnegative and sum a_i=T. Let U=Q+2*B. The code prepares a repeated
byte pattern for each symbol i and writes a padded symbol sequence at U.
Its cumulative offset b_i is the sum of preceding a_j.

The unconditional QWORD store `556fd68` begins at U+b_i, even for a_i=0.
For a_i>8, the scalar/SIMD groups write contiguous eight-byte multiples
after that first QWORD. With k=floor((a_i-1)/8), they write k additional
QWORDs: the XMM loop handles pairs and the odd-tail QWORD handles the last.
The actual sites are556fdad,556fdc0,556fdc7 and556fde5, with the small
9..16 special branch at556fe59. Thus for a_i>0 the union covers exactly
the rounded-up-eight interval containing its a_i logical bytes, with at
most7 extra bytes. For a_i=0 the initial eight-byte store may overwrite
future padding, never a preceding logical byte.

All stores lie inside U[0..T+8). Later symbols begin at nondecreasing b_i
and overwrite any earlier padding at or beyond that offset. Consequently
the final logical prefix U[0..T) is exactly symbol i repeated a_i times,
in index order. The repeated-byte increment is0x0101010101010101; for
i0..255 it is exactly the symbol byte in all eight lanes. The possible
unused increment after i255 is not read.

`556fe21..556fe52` then consumes exactly T logical bytes, two at a time;
T32/64 is even. It writes their symbol bytes to indices `(j*s)&(T-1)`.
The same odd-stride permutation initializes every table symbol slot once.
It reads no padded byte beyond U[T-1]. This optimized branch is proved
separately rather than assumed equivalent from its name or vector shape.

## Final rows: all fields, state bounds and fast-mode condition

After either coverage branch, `556fcf8..556fd2a` visits table rows j0..T-1.
Every loaded symbol byte is initialized and at most m. For a positive
coefficient c, that symbol appears exactly c times. Its scratch next value
before each occurrence is n=c,c+1,...,2*c-1. For a low-1 symbol it appears
once with n=1. Zero coefficients do not appear. All these n are nonzero
and at most2*T-1<=127. The subsequent WORD increment cannot wrap.

BSR at556fd0c is therefore defined. Let k=floor(log2 n). The actual row
code computes b=l-k, stores b to byte+3 (`556fd18`), and stores the low
WORD v=(n<<b)-T to row+0 (`556fd1f`). Because1<=n<2*T,0<=k<=l and
0<=b<=l<=6. The exact inequalities

`T <= n*2^b < 2*T` and `(n+1)*2^b <= 2*T`

give `0<=v<=T-1` and `v+(2^b-1)<=T-1`. Thus every extracted b-bit
quantity added to this v stays within the same T-entry table. No state
index, row field or undefined BSR input is assumed from a source typedef.

Together with the prior symbol write, these WORD/byte stores initialize
all four bytes of every row, plus the complete4-byte header. The exact
output extent is O[0..4+4*T). Scratch next_i is updated only for i<=m;
the optional U fill lies in its separately reserved T+8 bytes.

If F=1, every positive c<T/2, so every n<=2*c-1<T. Low symbols also use
n=1<T. Then k<=l-1 and every row has b>=1. If F=0, b=0 is allowed.
This supplies the actual flag/positive-bit relation needed by the selected
decoder's two bit-extraction branches, without claiming their whole behavior.

## Ordinary return and write/read footprint

Under these admitted premises both entry guards pass and the general
spread's p==0 check passes. The final row loop is exactly T iterations,
and success returns raw RAX0 (`556fd2c`). The one epilogue restores all six
saved registers and original stack before its sole RET. There are no opaque
calls, runtime imports or unresolved instruction transfers in this body.

Its read-only count accesses stay in C[0..2*B), final symbol reads stay in
the initialized T rows, and scratch reads stay in the initialized next-word
area or the proved U prefix. Writes are only the complete output extent,
scratch Q[0..2*B+T+8), and own saved/red-zone stack cells. No source,
caller-output or protected-return overwrite follows in the declared separated
domain. The larger checked scratch size is an upper bound, not a claim that
every byte is changed on every branch.

Outside the admitted count invariant the function can return-46,-44 or-1;
some symbol/header/scratch writes precede the late-1 refusal. It does not
transactionally validate arbitrary malformed counts. Those broader inputs,
other table logs/capacities/aliases, physical generated Rust stores, original
types/compiler and whole decompression semantics remain unqualified.

## Finite result

The actual header invariant, not a guessed public-source interface, supplies
the normalized counts needed to prove complete FSE table coverage and row
state/bit bounds here. This closes this771-byte constructor prerequisite
conditionally on the exact stated normal domains. It supplies the missing
table premises for a subsequent explicit composition review of the selected
2,835-byte decoder's read/write/count contract. It does not automatically
qualify its bitstream-format semantics or the later12,390-byte HUF builder's
symbol/advance table coverage. No implementation, stub, repository edit,
progress gate or census-only PR is created by this intake.
