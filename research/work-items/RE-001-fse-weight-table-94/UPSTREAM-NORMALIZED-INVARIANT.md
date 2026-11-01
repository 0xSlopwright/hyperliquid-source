# Actual header invariant supplied to the table-constructor question

This records a proved input premise, not a guessed FSE source type. The
preceding header receipt51c5631c and detailed HEADER-CONTRACT-PROOF.md derive
it from actual selected895-byte plus908-byte fallback bodies. The caller's
physical conditions are initial max DWORD255, source length V<=127 and outer
limit6. Normal separated memory/import/CPU/frame conditions remain explicit.

On a non-error header return, its local log l is in[5,15]. The actual outer
decoder compares that DWORD with6 and rejects larger values before calling
the771-byte constructor. Therefore its admitted l is5 or6, and T=2^l is32
or64. The returned maximum index m is in[0,255]. All256 two-byte cells at
A[0..512) are initialized: a normal imported memset zeros them before
parsing, ordinary count stores address only indices0..255, and zero-run
skips write no cells and leave their pre-zeroed contents intact.

Interpret a cell with bits0xffff as coefficient-1, and a cell with bits0..64
as that nonnegative coefficient. No other cell bits arise on the outer
admitted l5/6 path. This interpretation is unambiguous in a16-bit field; it
does not infer a recovered C/Rust typedef. Define a_i by those coefficients.

The native scalar argument starts remaining R=T+1. At each actual count
decode, power P and width w satisfy P<=R<2P, P a power of two and w its bit
length. The native cutoff a=2P-1-R is in[0,P). The two masked decode cases
produce exactly a coefficient c in[-1,R-1], then update R to R-|c|.
Thus R remains positive, arithmetic does not wrap, and the only successful
finish requires R=1. Ordinary stores advance the next symbol index; zero
runs advance it over coefficients already zero. The source-length bound and
the native three-byte/final-window run progression prevent that index from
wrapping32 bits before its unsigned capacity comparison.

Consequently, for the actual constructor inputs:

- a_i is-1 or in[0,T] for0<=i<=255;
- a_i=0 for every i>m;
- the last used coefficient a_m is nonzero: a zero coefficient does not
  change R, and a zero-run path is entered only while R>1, so it cannot
  produce the accepted R=1 finish;
- sum_{i=0..m}|a_i|=T, by telescoping remaining from T+1 to1;
- if N is the number of-1 cells,0<=N<=T and
  sum_{a_i>0}a_i=T-N.

These include the edge N=T (all low-probability-1 cells), and a single
positive coefficient T. Neither edge is silently excluded. They are useful
algebraic premises for complete table-write and state/bit bounds; they do
not establish those constructor results by themselves. Its actual771 bytes,
workspace checks, counter widths, loops and helper effects must supply the
rest. No new native/CPU/model execution is performed by this document.
