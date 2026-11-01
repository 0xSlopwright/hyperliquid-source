# Independent capacity20 decimal-span proof

This is a mathematical relation over the independently authenticated node94
body `1570470..157062c` (444 bytes,114 GNU rows). Its SHA256 is
`bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f`.
The separate235-byte selector is context only. No new Rust was read before
the expectation freeze, no captured instructions execute, and this is not a
PC/register/memory interpreter.

Let n be the incoming unsigned64 value, B the writable output base, C=20,
and T the actual200-byte sequence of pairs00 through99. B's20-byte interval,
T, immutable code and live save/return slots are valid, nonwrapping and suitably
separated. Saved scalar/frame roles are preserved; faults/unwind/concurrent
mutation and arbitrary raw aliasing are outside this qualified domain.
The safe array API narrows raw invalid pointer states. No original type or ABI
is inferred from that choice.

## Exact quotients from observed constants

The MUL-high64 followed by SHR11 at15704bb/15704c7 computes
floor(n*M/2^75), where M=0x346dc5d63886594b. Direct integer calculation gives
10000*M=2^75+432 and432*(2^64-1)<2^75. Write n=10000q+r,0<=r<10000.
Then n*M/2^75=q+(r+432*n/2^75)/10000. Its fractional term is strictly below1
and nonnegative, so the quotient is exactly floor(n/10000) for EVERY u64.

The observed32-bit low subtraction is also exact for this purpose:
(low32(n)-low32(10000*q)) modulo2^32 equals r modulo2^32, and r<10000.
No unproved equality of truncated high words is needed.

For x in0..9999,100*5243=2^19+12 and12*9999<2^19. The same remainder argument
proves floor(5243*x/2^19)=floor(x/100). This product cannot overflow32 bits.
The high and low pair indices are therefore0..99; the actual16-bit zero
extensions do not change them, and their table-byte indices lie0..199.

For t in0..999, let y=floor(t/4),0<=y<=249. Since25*5243=2^17+3 and3*249<2^17,
floor(5243*y/2^17)=floor(y/25)=floor(t/100). The observed16-bit extension of y
is inert. This establishes the different tail-quarter reciprocal, rather than
mistaking it for the full remainder reciprocal.

## Four-byte groups and their exact limit

The initial branch at1570484 compares n with1000, NOT10000. For an admitted
group, let current n_j=floor(n/10000^j), quotient n_(j+1)=floor(n_j/10000),
and remainder r_j=n_j-10000*n_(j+1). The stores at15704eb,1570507,157052d,
1570548 write T's two pairs for r_j at offsets
[20-4(j+1),20-4j). The negative four-byte continuation and B-1 carrier make
these exact offsets, not an assumed conventional buffer layout.

At1570554, JA compares the OLD n_j with9999999. It repeats iff
n_j>=10000000, equivalently n_(j+1)>=1000. Thus the abstract decomposition
repeats while current>=1000 and exits with0<=t<=999.

There can be five groups, not four: entering group j requires
n>=1000*10000^j. For j=5 this exceeds2^64-1; j=4 is possible for n>=10^19.
So g<=5 and every group writes within0..19. If g=5 then the high quotient is0,
because n<10^20. The maximum u64 therefore writes five4-byte groups, no high
tail, returns start0 and spells18446744073709551615. A final group whose
current value is1000..9999 has a nonzero leading digit and is not a spurious
zero group.

## Tail, zero, return and untouched prefix

Let u=20-4g. For t>=10 the source writes the actual pair for t modulo100 at
[u-2,u), then writes one additional high digit at u-3 iff floor(t/100)>0.
For t in1..9 it writes one digit at u-1. For t=0 it writes no high digit when
original n is nonzero; original n=0 instead writes one zero at19.

Accordingly the tail is0..3 bytes (zero itself has one), and its length h plus4g
is the conventional decimal digit count D(n), with D(0)=1. D(n)<=20, so u-h>=0.
Every tail guard index is also strictly below20. All three out-of-domain guard
CALL blocks are unreachable under C20; their unknown61-byte callee semantics
are not used to prove this domain.

The returned RAX is start=20-D(n), not D(n). Group and tail intervals partition
[start,20), with no repeated store and no write below start. Thus arbitrary
initial prefix bytes [0,start) remain unchanged, and the suffix equals n's
ordinary unsigned decimal spelling. This is a symbolic all-input argument;
1697 frozen concrete values with varying raw marker buffers corroborate it.

## Separate selector facts, not additional Rust behavior

The235-byte method `14f7660..14f774b` loads DWORD(F+16), tests bit25 before26,
and uses decimal only if both are clear. Bits outside these masks do not change
this selection. It reads the supplied QWORD value. Decimal passes B=selectorSP+4
and C20, then forwards digit pointer B+start and length20-start.

The hexadecimal loops each execute1..16 nibble stores, including one for zero.
Relative to that SAME B=selectorSP+4, their span is[16-k,16), NOT[20-k,20):
the first store is selectorSP+19=B+15; the last store moves backward by k-1.
Their observed alphabets are the actual lower/upper16-byte tables. They forward
prefix pointer to the literal0x with length2. Decimal forwards raw pointer word1
with prefix length0. Those are argument projections, not rendered output.

No new Rust hex/flags component, G stub, type/vtable/layout claim or downstream
formatting/padding/fill/AL behavior follows. The slot576e2d8 binds the opaque
1295-byte15723b0 body; only its FDE/RELA metadata is admitted. All full formatter,
physical rendering, original compiler/bytes/runtime and component gates remain
unqualified.
