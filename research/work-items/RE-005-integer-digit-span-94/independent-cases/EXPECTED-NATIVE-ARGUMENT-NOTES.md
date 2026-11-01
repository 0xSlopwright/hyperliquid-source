# Independent digit-span expectation boundary

These cases were frozen before any new Rust existed or was read. The expected
ASCII digits use Python's independent integer `str`/`format` implementation;
they never come from a proposed Rust answer, a PC/register interpreter, an
original executable or an inferred upstream source. The actual raw operands,
fixed tables and the mathematical argument below justify that oracle.

The primary theorem is only the 444-byte converter at capacity 20. Its scalar
input is unsigned 64-bit, including values above i64::MAX. Its writable region is
one separated 20-byte buffer B. The result RAX is a **start offset**, not a digit
count. For d ordinary decimal digits, the required output is B[20-d..20] and
RAX=20-d; B[0..20-d] remains unchanged. The marked buffers contain non-ASCII,
distinct initial bytes so an implementation cannot silently clear that prefix.

The native quotient uses high64(n*M) shifted 11, equivalently floor(n*M/2^75),
where M=0x346dc5d63886594b. Since 10000*M=2^75+432 and
432*(2^64-1)<2^75, its error above n/10000 is strictly less than1/10000;
therefore it produces exactly floor(n/10000). The low 32-bit subtraction recovers
the actual remainder because that remainder is 0..9999. The remainder*5243
product fits 32 bits, and the analogous error bound proves its shift19 quotient
is floor(remainder/100). The resulting byte-pair indices stay 0..99.

The initial n < 1000 route has no four-digit group. Otherwise the observed
repeat comparison uses the OLD quotient>9,999,999. For a d-digit input this
stores g=floor(d/4) four-digit groups, rightmost group first, at ascending
positions inside each group. There are at most five groups. The remaining
0..3 digits use the actual tail branches. The tail's
5243*floor(x/4)>>17 expression is floor(x/100) for x in 0..999. For a three-digit
tail its lower pair is written first and the leading byte last. For zero,
the original-input-zero branch forces one final byte 0. A nonzero original
input with no remaining quotient does not add a leading zero.

The fixture's native_store_offsets is this mathematical group/tail consequence,
not a measured physical store order of generated Rust. Tests of the new
component compare returned offsets, every final buffer byte and unchanged
prefixes. They do not claim generated instruction order or an original ABI.
The 621 decimal inputs cover every digit length 1..20, both sides of powers of 10/2,
0/9/10/99/100/999/1000/9999/10000 and the9,999,999 repeat boundary, all 100 pair
entries in selected group positions, high-bit/max-u64 values and varying markers.

The separate 235-byte selector context is not part of the Rust component API.
Its actual low DWORD flag sample gives bit 25 priority over bit 26. The 140
context records cover every literal flag bit, both flags together, case-specific
nibbles and the raw forwarded prefix arguments. B is selectorSP+4: decimal
endsB+20, whereas both hex loops endB+16 and preserve B[16..20]. Hex stores run
backward and include one digit for zero. Those facts do not imply downstream
prefix rendering, padding, alignment, complete G or original private types.

The real Rust API is decimal-only write_decimal_suffix(value, &mut[u8;20])
returning the start. It contains no fake hex path, formatter, writer callback or
opaque downstream implementation. Original short capacities and three guard
calls remain outside the theorem. Memory/frame/return/table preservation and
separation are native external premises, stronger safe references are a chosen
implementation domain, and no whole-target execution, compiler identity,
byte-equality or component gate follows from these cases.
