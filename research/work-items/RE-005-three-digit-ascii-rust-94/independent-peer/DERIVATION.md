# Independent pre-Rust parser derivation

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
