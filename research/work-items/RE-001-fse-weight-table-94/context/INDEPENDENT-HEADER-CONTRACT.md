# Independent selected header contract review

Target: node94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This is a static proof review of the actual 21-byte selector and the complete
895/908-byte header bodies. It is not an implementation, runtime experiment,
source-type attribution or whole decoder proof. No public C implementation or
postcondition was used to derive the relations below.

## Independently admitted evidence

One immutable 91,774,280-byte snapshot supplies a separate direct ELF section /
PT_LOAD reader, all three 1,824 selected code bytes and their raw selected FDE
records. Fresh pinned GNU decoding reproduces all 494 cached rows exactly.
The FDE check corroborates the selected raw pcrel start/range/CIE records; this
peer does not claim its small checker independently audits global uniqueness.
The retained FDE hex is a32-byte prefix, not a complete CFI dump (the selector
record is20 bytes, so its prefix also includes adjacent context). The actual
24-byte CIE decodes as version1, zR, code alignment1, data alignment-8, return
register16 and one-byte R encoding0x1b. Only the selected start/range/CIE
relationship is corroborated here; no full unwind-behavior claim is made.
The tiny PLT stubs, actual JUMP_SLOT records and dynsym names independently bind
the three static import edges to memcpy, memset and __stack_chk_fail. Names do
not establish the currently loaded providers or their runtime behavior.

The actual selector tests R9D; zero tails to 556f010, nonzero to 556f3a0. The
selected caller sets R9D=1 before its call. In both bodies the physical roles
are A=RDI, Mptr=RSI, Lptr=RDX, S=RCX and V=R8. The max DWORD is read before the
short-input branch. This review uses initial max255 and 0<=V<=127. The separate
outer caller's limit6 is an explicit contextual premise; its local comparison
against the returned log is independently visible at556feef/556fef2.

## Conditional memory, calls and architectural domain

A[0,512), both distinct four-byte output cells, S[0,V), and protected code /
stack / return / FS state must have the specified nonwrapping accessibility
and separation. The pointers must be valid for the assumed imports, including
zero-length cases. Own saved frames and the private eight-byte padding cell
must remain protected. The ordinary architectural shifts, LZCNT/TZCNT/BMI2
instructions and nonvolatile-register/return discipline are premises, not CPU
feature or hardware-return results measured here.

The two external data calls are conditional standard-C contracts: memcpy
copies exactly n bytes and returns its destination; memset zeroes exactly n
bytes; their ABI and non-target regions are preserved as required. No dynamic
resolution or loaded-provider identity is qualified. FS mismatch actually
calls the third import and falls outside each local FDE if it returns. No
noreturn or diagnostic/error behavior is assumed for that edge.

## Long-input setup and mass invariant

For V>=8, the actual memset size is twice the zero-extended32-bit value
(initial max+1), hence512. Then the low source nibble produces l=nibble+5.
l>15 returns raw-44 after count zeroing and before writing Lptr. Otherwise
Lptr receives l, T=2^l, remaining R=T+1, threshold P=T and width w=l+1.

At each count decode with R>=2, P is a power of two and P<=R<2P; w is its
bit length. This holds initially since T>=32. Define b=2P-1-R, so0<=b<P.
Let z be the unsigned current bit window and u=z&(P-1).

- If u<b, decoded d=u and w-1 bits are consumed.
- Otherwise a=z&(2P-1), and d=a-b if a>=P, else d=a; w bits are consumed.

In the second case u>=b means that if a>=P then a>=P+b. Therefore0<=d<=R
in both cases. The actual subtract1 makes c=d-1 in[-1,R-1]. The CMOVNS at
556f4e1 chooses R-c for c>=0, whereas the preceding ADD gives R-1 for c=-1.
Consequently R'=R-|c| is in[1,R]. Arithmetic fits the actual positive32-bit
domain (R<=32769, a<=65535). If R'>=P the old threshold remains valid. If
1<R'<P, the checked nonzero LZCNT/BSR path sets P'=2^floor(log2 R'), with
P'<=R'<2P'. R'=1 leaves before another decode.

Each direct WORD store is at the prior index n. An ordinary store advances
that index by1; zero runs skip only already-zero cells. Thus, throughout the
loop, R + sum(abs(c_i)) = T+1 over the cells written so far. The only accepted
finish requires R=1, giving sum(abs(c_i))=T. The bounds check prevents another
WORD store when the next index reaches256. Final accepted n<=256 sets m=n-1,
so0<=m<=255. All cells above m remain zero. The final coefficient is nonzero:
a zero store cannot change R, and its zero-run continuation occurs only with
R>1, so it cannot supply a successful R=1 finish.

For the actual outer log<=6, l is5 or6 and T is32 or64. Logical c therefore
has exact physical WORD representation as -1 or0..T. If N is the number of
-1 cells, then0<=N<=T and sum(positive cells)=T-N. Both N=T and one positive
cell T are allowed by the proof; neither is silently excluded.

The signed-WORD interpretation must not be extended to the entire generic
log range: l15 permits logical c32768 and physical WORD0x8000. A static
arithmetic witness is input prefix fa ff 0f 00 with8 readable bytes: R32769,
P32768, b32766, a65535 yields d32769,c32768,R'=1 and bitcount20. The separate
outer limit6 rejects that log. This is a domain limit, not a target defect or
an executed vector.

## Source bounds, finite zero runs and count indices

For the long branch E=S+V, cap=E-4, edge=E-7. The initial four-byte read is
inside S[0,V). At ordinary reload, the old base<=edge and bitcount<=23 imply
base+floor(bitcount/8)<=E-5; otherwise the code checks the candidate against
cap, clamps it to cap if necessary and adjusts the low32-bit shift count.
Every physical DWORD read is between S and cap inclusive. The zero-run fast
reload uses base+3 only while base<=edge, again at most cap. Its final decode
uses the same candidate/cap check. On the fast eligible base<=edge path, the
prior residual is at most7 and the stop pair count at most11, so the new
bitcount is at most31. At a clamped base, residuals can reach31 and the
zero-run terminator may advance the bitcount to33 or34; the explicit cap
check and architectural shift masking handle that path. No universal
pre-reload bitcount<=31 claim is made.

When zero-run scanning reaches the end window, clamping reads the last DWORD
and adjusts its shift. The NOT|0x80000000 operand is always nonzero, so TZCNT
is defined. For the worst all-ones word, at cap a residual s>8 already gives
at most23 trailing ones and stops. Residual0..8 advances through
(s+24)&31; even s8 reaches0 then24, so at most two repeated clamped scans are
needed. Other words stop no later. Earlier repeats move the byte base by3.
Thus a safe bound is ceil(V/3)+4 full-group repeats. With V<=127, the skipped
index is below256+36*47+36<2^31; no32-bit index/bitcount wrap can evade the
unsigned capacity comparison. This argument is scalar/interval reasoning,
not instruction execution.

Accepted finish checks the final bitcount<=32. It is nonnegative by setup,
decode increments and the masked clamp paths. Its cursor is in[S,E-4], so
h=(cursor-S)+ceil(bitcount/8) lies in[0,V]. Padding/refill reasoning does not
claim a complete wire format or runtime safety outside the stated domain.

## Short input, partial effects and errors

For V<=7, the function zeroes a private eight-byte cell and copies exactly V
bytes into it, then calls generic556f010 with V=8. That call necessarily takes
its long branch: recursion is at most one level. Its private padded reads
compose without new original-source reads. If a non-error inner h exceeds
original V, the wrapper converts it to raw-20. Actual near-top negative error
values are preserved by the unsigned threshold comparison. The inner count,
log and possibly max writes are not rolled back by this conversion.

The observed normal-return raw constants are-44,-20,-48. This is a safe return
set, not a statement that every constant is reachable under initial max255.
In particular, with R=1 obtained only by an ordinary final count and the
pre-store capacity guard, n<=256 already holds; the-48 guard is defensive in
this bounded mathematical domain. Errors can leave zeroed512 counts, partial
WORDs/log, and (on the short wrapper) a completed max before rejecting h>V.
No transactional-unchanged-output promise follows.

## Review decision

The normalized-count and512-byte initialized-footprint premises needed by the
separate771-byte table constructor are conditionally established for actual
max255, source V<=127 and outer accepted log5/6. Table writes, symbol coverage,
state transitions, full decoder behavior, runtime imports and original source
types remain open and are not borrowed from any public C implementation.
Fresh complete live ownership/main reconciliation is a separate pending
administrative prerequisite after the maintainer closure batch; no producer,
repository edit, PR, compiler, captured code or emulator is authorized here.
