# Conditional scalar contract of the 85-byte parser

Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The independently admitted FDE is `0x1683670..0x16836c5`: 85 bytes,
30 complete GNU-decoded instructions, two conditional forward edges, two RETs,
zero CALLs, zero RIP-relative data references and zero explicit stores.
Eleven following INT3 padding bytes are outside the primary denominator.
All facts below refer to the actual admitted bytes, not the nearby symbol
annotation, the inferred source tree or an original Rust name/type.

The chosen implementation contract is
`parse_three_digits(input: &[u8]) -> u16`. It returns zero unless the slice
contains exactly three bytes with first byte in ASCII `1..9` and the other
two in ASCII `0..9`; otherwise it returns the corresponding value 100..999.
This interface is chosen independently. It is not a recovered machine ABI.

## Native domain and endpoints

At the selected native entry, let n be the initial 64-bit RSI and P be RDI.
For n=3 require the nonwrapping three-byte readable immutable region P..P+3.
For n!=3 no input dereference occurs. Require immutable admitted code and an
ordinary valid architectural call/return state. The local proof endpoint is
arrival at either actual RET with RAX equal to the stated scalar; actual
return additionally assumes that ordinary call/return state. It asserts no
unwind/fault/concurrent-mutation behavior, register-clobber compatibility or
physical read-timing parity. A safe Rust slice supplies the narrower valid
object domain; arbitrary invalid raw pointers are not part of its API.

No helper or static table assumption is needed. Source/compiler/function
identity, the meaning of this value and full caller behavior remain unknown.

## Complete local transfers

1. `1683670` compares full RSI with three; `1683674` branches to `16836a6`
   on inequality. That block zeroes EAX and reaches RET at `16836a8`.
   Therefore every other native length returns zero without reading P.
2. For equal length, the MOVZX instructions at `1683676`, `1683679` and
   `168367f` read exactly P, P+1 and P+2 into ECX, EAX and EDX. All three
   reads precede the later write to DIL, so that low-byte register clobber
   cannot alter a remaining input address. There are no further input reads.
3. ADD AL/ADD DL at `168367d`/`1683683` form middle/last biased bytes
   d1=(b1+208) mod256 and d2=(b2+208) mod256. LEA ESI at `1683686` followed
   by the SIL compare/SETB forms flag0=(((b0-58) mod256)<247).
   The two CMP/SETAE pairs form flag1=(d1>=10), flag2=(d2>=10).
4. The two byte OR instructions at `168369e`/`16836a1` set ZF from exactly
   flag0 OR flag1 OR flag2. Earlier or upper-register flags cannot affect
   the JE at `16836a4`. Nonzero reaches the same zero-return block; zero
   reaches `16836a9`. These account for every branch and normal path.
5. On that compute path, MOVZX DL and the biased CL/MOVZX establish d2 and
   d0=(b0+208) mod256 as nonnegative values. IMUL ECX by100 gives the
   hundreds term. MOVZX AL, ADD EAX,EAX and LEA EAX,[RAX+RAX*4] give
   ten*d1. The following MOVZX AL retains its low byte. Finally ADD ECX
   and ADD EDX into EAX produce 100*d0+10*d1+d2, followed by RET16836c4.
   All writes to EAX zero its high RAX half.

## Predicate and payload proof

The first flag is zero exactly on b0=49..57: subtracting58 modulo256 gives
247..255 there, and every other byte gives0..246. The other biased bytes are
below10 exactly for b1/b2=48..57. `BYTE-PREDICATES.json` checks each equivalence
over all256 byte values separately (768 scalar checks). Composition is an OR
of these complete predicates, not a conclusion drawn from a few examples.
Exactly9*10*10=900 three-byte strings pass; every other length-three string
returns zero. No 16-million-case target execution is asserted.

On the passing path d0 is1..9 and d1/d2 are0..9. The tens term is0..90, so
its low-byte truncation is exact. Hundreds are100..900 and the complete sum
is100..999; all 32-bit arithmetic and the final u16 projection are exact.
The zero return is therefore an unambiguous invalid sentinel. No native
zero-valued valid string exists: notably `000` and `012` are invalid.

All finite local paths reach one of the two RETs. The lack of stores means
the caller's input memory remains unchanged in the stated normal domain.
The implementation may use a different read order under safe readable
slices; exact memory traces and fault timing are not reconstructed.

## Separate used-result context

The actual selected context is `16825fe..168261d`: 31 bytes/seven rows.
Its boundaries are independently corroborated by linear native decoding of
the separate `1682220..1682735` 1,301-byte caller FDE. That larger decode is
boundary evidence only and is not added to the 85-byte semantic denominator.

Actual `49 8b 7f 08` at16825fe loads QWORD[R15+8] into RDI, the following
load takes RSI from[R15+16], and the direct CALL1682606 reaches this parser.
TEST AX branches to an unresolved caller path on zero. On nonzero the
selected prefix stores AX at[R14] and byte7 at[R14+0x40]. This witnesses use
of the numeric result/sentinel; it does not identify the source fields,
original return type, tag interpretation, wider parser or caller reachability.
PR627's prose names the first load/address incorrectly; its retained native
bytes are the authority, and the old packet is preserved rather than edited.

## Pre-Rust expected observations and remaining work

`pre-Rust-oracle/ORACLE-FREEZE.json` binds the native-derived closed scalar
equation, all900 valid values,739 distinct single-invalid-byte triples and
24 additional length/multiple-invalid boundaries:1,663 distinct stimuli.
Expected answers and runtime inputs are separate. IDs are opaque deterministic
hash labels and the input wire contains no expected value or classification.
There is no PC/register/opcode execution or new Rust source in this freeze.

An independent peer will freeze additional malformed/slice-boundary/order/ID
expectations before reading the production source. Because all900 valid
triples are already included, such controls must not be called new distinct
valid values. Actual own-Rust builds, units, input-only clients and compiling
valued counterfactuals are still pending. No component gate, source build,
machine-byte equality, whole caller or whole node claim follows.
