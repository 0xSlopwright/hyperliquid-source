# Conditional transfer proof: node #94 fast-state constructor

This is a complete static transfer argument for the selected constructor,
not a machine-execution experiment or an all-input decoder theorem. Target:
node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Its actual FDE `0xfb5e54` (CIE `0xce1518`) covers
`[0x55dc5e0,0x55dc79b)`: 443 bytes, SHA-256
`e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63`.
All 130 decoded rows are bound to raw bytes, including two unreachable NOP
rows. There are 128 reachable rows, 16 directly encoded branches, two RETs
and no CALL. Thus no unknown helper transfer occurs inside this denominator.

## Domain and entry roles

Let `Q=RDI`, `O=RSI`, `L=RDX`, `I=RCX`, `N=R8`, `T=R9` at entry. These
are symbolic roles inferred from actual loads/stores, not original private
Rust/C types or an exported ABI. Q denotes a 152-byte existing state image;
the four-byte header at T and the N input bytes at I are immutable snapshots.
The normal domain is `0 <= L <= 2^63-1`. Logical ranges Q..Q+152, I..I+N,
O..O+L and T..T+4 must be nonwrapping and pairwise disjoint (empty ranges
have no overlap). In addition O+3*k must be nonwrapping, where
`k=(L+3)>>2`; this matters even when that cursor lies beyond O+L on a
refused path. L+3 and 3*k cannot themselves overflow in this signed-L domain.

For correspondence to the native routine, the state/input/header/output
roles must also be disjoint from the live save/return stack and immutable
code. Stack slots and return state must be valid for ordinary local call/RET;
the calling convention alone is not a proof of hardware return validity.
The detached checked Rust API can validate its symbolic ranges and slice
lengths; native stack/code separation and the image interpretation are
explicit external assumptions, not checks that the Rust API pretends to do.

The computed stream-start *values* may wrap or lie outside the input on an
early refused path. They are stored before stream-length validation and are
not dereferenced there. Preserve these modulo-64 values; do not silently
claim that I+N nonwrap proves every failed-path intermediate nonwrapping.
After the successful size checks they are inside the admitted input range.
The table payload is never read by this constructor: only its header is.
No payload, symbol, advance, ownership or CPU feature validity follows.

## Initial state, guard order and refusal phases

All arithmetic below is unsigned 64-bit modular arithmetic except the
explicit first signed L test and the 32-bit operations used to compute a
byte's shift. Typed little-endian loads have their actual widths.

1. `0x55dc5e0..0x55dc5f8`: save L in RAX, I in RDX, compute O+L, and
   **load a DWORD at T before testing L**. The save stack is five qwords.
   L=0 reaches `0x55dc778` and returns raw status 0 without state writes.
   Negative signed L is outside this contract; its separate native path is
   retained in the complete ledger and is not called zero-length behavior.
2. For L>0, N<=9 returns raw `0xffffffffffffffec` (-20), without state
   writes. Otherwise shift the DWORD header by16 and compare its low byte
   to11: only byte T+2 matters. An unequal byte returns0 without state writes.
   Therefore L0 takes priority over bad N/header, while positive L with N9
   returns-20 even if the header byte is not11. T still had to be readable.
3. `0x55dc620..0x55dc656`: load three zero-extended little-endian WORDs
   a,b,c from I+0,+2,+4. Write stream starts, in this exact order:
   `Q[15]=I+6`, `Q[16]=I+6+a`, `Q[17]=I+6+a+b`,
   `Q[18]=I+6+a+b+c`, modulo2^64. No table/input aliases are admitted.
4. Check a>7, then b>7. Compute `d=N-6-a-b-c mod2^64`; check c>7,
   then d>7. Any failed check returns0 with exactly those four state writes.
   Finally d>N returns-20 with the same four writes. This last comparison
   rejects a residual subtraction underflow on the normal domain: the
   subtraction sum is at most196611, and an underflow result exceeds N.
   It is not a signed residual test. The three header WORDs remain distinct.
5. `0x55dc684..0x55dc6ce`: compute k=(L+3)>>2, four input cursors and
   output cursors. Additional state writes are exactly:
   `Q[4]=O`, `Q[0]=I+6+a-8`, `Q[1]=I+6+a+b-8`,
   `Q[5]=O+k`, `Q[6]=O+2*k`, `Q[2]=I+6+a+b+c-8`,
   `Q[3]=I+N-8`, `Q[7]=O+3*k`.
   If O+3*k >= O+L, return0. There have now been twelve writes; all seven
   not-yet-written cells keep their entry values. The guard is unsigned.
   Nonwrapping O+3*k makes this equivalent to 3*ceil(L/4)>=L. For positive
   L, the exact failing set is {1,2,3,5,6,9}: write L=4*m+r to verify each
   r in0..3. Merely testing L<4 would miss valid refusal paths.

The constructor's only normal-domain raw statuses are0, -20 and1.
Unsupported Rust API domains are separate errors, never silently relabeled
as one of these target refusals. Its initial state remains unchanged on an
unsupported-domain result; this is an API boundary, not a native status.

## Successful bit cells and all nineteen writes

After the above guards, a,b,c,d>=8 and sum to N-6; hence all four final
8-byte windows are readable inside I..I+N. Let the four ends be
`E0=I+6+a`, `E1=I+6+a+b`, `E2=I+6+a+b+c`, `E3=I+N`.
For each lane read its final byte b and its final little-endian qword w.

The actual byte is zero-extended to EAX and tested before BSR. If b=0,
ECX remains zero. Otherwise BSR EAX,EAX computes floor(log2 b); the
32-bit XOR31 and LEA-23 produce `s=8-floor(log2 b)` in ECX. Thus s=0
for b0 and s in1..8 otherwise. There is no BSR-on-zero premise here.
The qword result is `(w|1)<<s mod2^64`, with x86's count mask inactive
because s<=8. OR1 fixes bit0 before the shift, so bit s is1 afterward:
**all four initial bit cells are nonzero**, including last-byte0. Examples
b0→s0, b1→s8, b128/255→s1 are consequences, not the general proof.

After the first twelve writes, the exact remaining order is:
`Q[8]=bits0`, `Q[9]=bits1`, `Q[10]=bits2`, `Q[13]=I`,
`Q[14]=O+L`, `Q[12]=T+4`, `Q[11]=bits3`; EAX is then1 and control
joins the shared restore/RET. All19 qwords are now written exactly once.
The entry value of RDI/Q is never changed; its address is used only by the
nineteen stores. RBX,RBP,R12,R13,R14 are restored from their saved slots,
R15 is untouched, and the two normal RET paths consume the original return
slot under the stated valid call/return state. No flags contract is claimed.

On success the input cursors are ordered, separated by b,c,d>=8; each points
at its lane's final readable qword. Output cursors are ordered and op3<oend.
This resolves only the **initial** cursor/bit/state premises of the earlier
loop contracts. Subsequent table contents, symbol widths/advances, refill
states, loop progress, termination and decompression validity remain open.
In particular, the X2 table advance1..2 condition is not established here.

## Selected caller context, kept outside the 443-byte denominator

Two actual wrapper FDEs are `[0x55dd2f0,0x55dd5bd)` (717 bytes) and
`[0x55dceb0,0x55dd2f0)` (1088 bytes). Only their109-byte pre-call cuts
are proposed: `[0x55dd2f0,0x55dd35d)` and
`[0x55dceb0,0x55dcf1d)`. They save incoming R9 as the loop pointer in
R15 or R14, reserve a real stack frame, pass Q=workingRSP+16 to this
initializer and then test its raw status. The error-above-(-120) branch and
zero branch exclude -20 and0; in the proved domain the indirect CALL
therefore occurs iff status1. The actual initializer preserves RDI and the
saved callback register, so the constructed Q is the loop argument.
The call boundary, later decoder/fallback and canary failure are not a
whole-wrapper implementation or ordinary-return proof for arbitrary input.

A separate313-byte actual dispatcher FDE
`[0x55ec060,0x55ec199)` supplies instruction-aligned RIP LEAs to the two
licensed assembly entries. The header byte at incoming R8+1 selects which
pair; opaque incoming flag bits choose the assembly or another pointer,
permit/skip the fast wrapper, or take fallbacks. This gives selected
argument/pointer-flow context only. It neither derives those flag values
from CPUID nor proves runtime CPU dispatch, complete caller reachability,
original private types or ABI names. The 313+109+109=531 selected context
bytes are reported separately, never added to443 semantic constructor bytes.

## Source rights, checks and remaining scope

The proof follows admitted target instructions and typed memory transfers.
Compatible licensed upstream assembly in #1065 supplied hypotheses about
roles, not original native/Rust source. No unlicensed inferred implementation
is read or copied; no assembly or target bytes are transplanted into Rust.
The dependency-free Rust component implements only this documented checked
constructor and its refused-state effects, using the authenticated direct
rustc toolchain. It is neither a decoder stub nor a root Cargo workspace.

Actual byte/provider controls must attack header-byte selection, signed/zero
and residual guard order, state-store offsets/order, byte/WORD/qword widths,
shift and OR1 bindings, native addresses/bytes, and callback argument flow.
Independent concrete expectations must cover all refusal phases and input
boundaries, not just mirror a Rust implementation. Rust execution is limited
to this independently authored component and its own driver; captured code,
compatible assembly objects and CPU emulators are not executed. Target
behavior remains a static conditional result, not runtime differential proof.
No global census, original-source identity, caller/table closure or progress
gate changes are claimed.
