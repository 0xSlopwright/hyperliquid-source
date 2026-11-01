# Selected compressed-weight caller: bounded normal memory/count contract

This composes only previously admitted node94 bytes and proved algebra. All
facts remain pinned to SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Upstream main advanced from308 to546 during this work; this document executes
no new upstream code, hooks or tests and does not treat old-base validation as
current-main validation. No captured instructions, compatible assembly,
emulator or PC/register evaluator is executed.

## Boundary and necessary conditions

The measured statistics caller at556ef55 supplies W, destination capacity255,
source S=I+1, source length V<=127, limit6, secondary workspace A and size876,
plus selector1. The21-byte wrapper selects the895-byte header reader, with
the908-byte generic reader used only for its private padded short-input case.
The3,184-byte decoder entry selects the2,835-byte decoder. Its771-byte table
constructor has no helper calls. Exact scopes, hashes and data/control
witnesses remain in the separate intake receipts.

Require the stated normal CPU/ordinary memory domain; valid nonwrapping and
separated W[0..256), secondary A[0..876), source I[0..original_size),
statistics outputs/histogram, and protected call/return/code regions; normal
saved-frame/register preservation; stable saved/currentFS words; and the
explicit actual-import memcpy/memset contracts. These are meaningful domain
conditions, not claims about arbitrary aliases, hostile runtime symbol
interposition or unsupported hardware. Designated count/log/max outputs may
change. The normal-domain composition does not assume that opaque helpers
initialize arbitrary tables: the actual header and constructor proofs now
supply those prerequisites.

## Header, workspace and table facts used

The header gives a non-error h in[0,V], max index m in[0,255], initialized512
count bytes and log l in[5,15]. The decoder requires l<=6, so l5/6 and
T=2^l32/64. Its successful normalized physical WORDs are-1 or0..T,
zero beyond m, with sum of absolute values T. The actual workspace guard is

`5*T+2*(m+1)+532` for even m+1, or two bytes more for odd m+1.

At the measured size876 this further admits m<=91 for l5 and m<=11 for l6.
The broader header bound m<=255 is not silently substituted for this later
caller admission. A larger m can be a real header result and still cause
the decoder's raw-44 refusal before table construction.

When the guard passes, the constructor's output O=A+512 occupies exactly
4+4*T bytes. Its scratch begins Q=A+516+4*T and fits the remaining workspace:
the exact needed total5*T+2*(m+1)+524 is smaller than the outer guard by8 or10.
The constructor returns0, initializes the header and every one of T rows,
and produces symbol<=m, row bit count b in[0,l], row base v with

`0<=v` and `v+(2^b-1)<T`.

If the actual header flag selects the fast extraction loop, every b>=1.
All normalized-count, table and scratch writes/reads are inside A[0..876)
under these admitted actual caller coordinates. This supplies concrete
region and field guarantees, not a table-name or shape assumption.

## Initial states and bounded table reads

Let payload S'=S+h, length M=V-h. Header h<=V eliminates the earlier
underflow counterfactual: M is in[0,127]. M0 returns raw-72 before any payload
byte read or direct W store. Otherwise the last payload byte is read. Zero
last-byte errors are raw-20 for M<=7 and raw-1 for M>7, with no direct W store.

For a nonzero marker, LZCNT32(marker)-23 is in[1,8]. A long payload uses
one QWORD at S'+M-8. A short payload assembles exactly M bytes through the
actual bounded switches and adds8*(8-M) to its initial consumed-bit count;
it does not read an eight-byte original-source object. The initial two
states are masked by T-1, so each is in0..T-1, including the short-input
overconsumption branches with hardware-masked shifts.

For every later table access, the state points at one initialized4-byte row.
The normal loop masks extraction to b bits using its actual BZHI/AND form,
including b0. The fast loop's SHLX/SHRX form produces a b-bit quantity only
because its proven flag guarantees b>=1. The constructor bound on
v+(2^b-1) consequently preserves state<T after each transition. There is
no unsupported table read outside the initialized T rows and no invented
zero-bit fast-mode premise.

##64-bit payload/refill read bound

For M>=8 maintain a payload QWORD cursor C in[S',S'+M-8]. Every actual
refill decreases C. When C>=S'+8, the bounded pre-refill consumed-bit count
is<=64, so subtracting floor(count/8) subtracts at most8 bytes and stays
at or above S'. The reload's upper end never increases. When C<S'+8 but
C>S', the code subtracts the smaller of floor(count/8) and C-S'; this
explicit clamp again preserves C>=S'. At C==S' it does not fetch another
QWORD. Therefore all real payload QWORD reads stay in S'[0..M).

For M<=7 the cursor starts at S'. Each C==S' branch skips QWORD reload;
the only payload reads were the bounded byte assembly and marker. The same
observation covers the initial/refill variants in both extraction modes,
including the cold init blocks at557090a/557092d/5570945/5570950.

Initial short consumed counts can exceed64, and the four-byte output loops
may accumulate up to64+4*6=88 before their post-block check. These cases
route to the guarded final-pair region. The apparent static-zero pointer
at802380 is a cursor sentinel, not an extra source buffer read in this
normal domain: the consumed count is already>64, the next row adds a
nonnegative value<=6, and the first final-pair branch exits before any
cursor refill. The maximum transient count is at most94, so no32-bit wrap
can turn that condition false. If capacity cannot admit a pair, raw-70
is returned before the pair and before any such reload.

On paths that do reload, the preceding consumed-count check is<=64. The
ordinary decrement/mask/clamp operations preserve a nonnegative bounded
count. This is an explicit raw-refill composition argument, not a general
claim that all pointers are magically valid. It uses the now-proved header
length and table field/state bounds.

## Output, returns and partial effects

The existing selected-decoder cutset proof establishes all16 destination
byte-store sites and all11 ordinary epilogue predecessors. Its four-byte
blocks admit only P<W+255-3. Its final-pair regions admit P<=W+255-2,
and the parity/capacity guards bound all final two/three-byte returns.
Thus every non-error local return has **2<=q<=255**, and exactly the
contiguous W[0..q) prefix has been directly initialized. All direct W
stores are inside W[0..255), including on ordinary decode refusal.
The table symbols additionally establish each stored byte<=m; no particular
decompressed weight sequence or accepted compressed-language identity is
claimed by this memory/count theorem.

The actual normal caller can receive header raw-20/-44/-48, the caller's
workspace/log raw-44, payload marker raw-1/-20, empty remaining raw-72 or
capacity raw-70. All lie in its top119 u64 error predicate. The constructor's
-46/-44/-1 branches are real outside its admitted conditions but unreachable
when the proved header plus passed workspace premises hold. The decoder's
remaining-in-top119 branches are likewise unreachable once h<=V is supplied.
Saved-FS mismatch still takes the separate actual external guard CALL; no
noreturn/provider behavior is inferred and that route is outside this normal
contract.

Refusals are not transactional. Count512 bytes can be cleared, count/log/max
outputs or table/scratch fields can be changed, and a bounded W prefix can
be written before error. Success and error paths do not write the caller's
histogram/count/depth or original source under the actual separated-region
domain. There is no rollback or all-error-unchanged promise.

The prior selected statistics proof can use these explicit q/prefix/source/
workspace facts in the same normal domain. Its final inferred weight at
W[q] fits the reserved256th cell, its finite histogram counts remain exact,
and its own weight<=12/power-residual/rank checks still decide acceptance.
The normal domain is conditional on actual imports/hardware/memory, not an
unconditional runtime safety/format-equivalence declaration. The later
12,390-byte HUF builder's complete DTable coverage/symbol/advance1..2 proof
is still open. No new Rust, source gate or whole-decoder claim follows.
