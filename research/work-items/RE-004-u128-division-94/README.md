# RE-004: complete nonzero-u128 quotient contract and independent Rust

Target: captured Linux x86-64 node94, SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Source baseline `4179e174f58ea877cb803abece4a3842c614daf3`.
Addresses below are ELF virtual addresses before load bias. Component: RE-004
quantities/rounding, supporting the shared wide-integer arithmetic primitive.

This contribution proves the complete nonzero-divisor numerical contract of the
198-byte leaf `[0x565f5a0,0x565f666)` and implements it in independently authored
core-only Rust. It preserves the separate #1161 published-artifact correspondence;
that identification is corroboration, not a premise that the leaf divides.

## Gap and closed numerical boundary

The accepted spot-wei-scale, L1-EVM-transfer-fee and priority-native-cost packets
used or assumed this shared helper through slot `0x576e1a8`. The L1 symbolic
call witness reads numerator low/high from RDI/RSI, divisor low/high from RDX/RCX,
and expects quotient low/high in RAX/RDX; it explicitly requires a nonzero divisor.
That primitive assumption is now discharged by the complete native proof.
The caller's other guards, units, overflow/rounding policy and side effects are
not newly reconstructed here.

For all unsigned128-bit n and nonzero unsigned128-bit d, define the entry values
n=RDI+2^64*RSI and d=RDX+2^64*RCX. Under the explicit ordinary x86 call/frame domain,
the returned numerical value is RAX+2^64*RDX=floor(n/d). Every local return is covered:

- high divisor word zero, numerator high word below divisor low word: safe one64-bit DIV;
- high divisor word zero, remaining large-word branch: safe two64-bit digit DIVs;
- high divisor word zero, both selected words below2^32: safe32-bit then64-bit digit DIVs;
- high divisor word nonzero: safe normalized DIV, bounded estimate, predecessor,
  exact multiply-back and borrow correction.

The high-word proof derives s=floorlog2(d_high), e=s+1, M=floor(d/2^e) and
D'=M*2^e. M>=2^63 guarantees the hardware DIV cannot overflow; the actual e=64
masked-shift/CMOVE endpoint is handled explicitly. Since
`0 <= n/D' - n/d < 1`, the estimate is q or q+1. Its saturated predecessor is
q or q-1; its product fits128, and the final CMP/SBB pair and SBB−1 return q.
The partial-AL/unknown-upper-EAX case, sign-extended immediate, low/high borrows,
32-bit zero extensions and all four returned high words are addressed explicitly.

[PROOF.md](PROOF.md) is the unchanged reviewed proof frozen before Rust authoring.
Its intake/proposed/future-tense labels are preserved as historical evidence;
actual implementation and qualification follow below. All71 instruction rows and
198 bytes are retained in [native/rows.json](native/rows.json), with raw GNU output.
There are no native calls or static-data references. Ordinary valid call/return,
immutable code and a permitted conditional RBX save/restore stack region remain
explicit premises; arbitrary raw aliases, asynchronous changes and faults are
outside this numeric projection. Stack-save bytes and physical register clobbers
are not represented by the new Rust API.

The static admission hashes one immutable complete target object. It binds the
selected indexed FDE/local neighbors and full CIE, unique mapped code coordinates,
the complete eight-byte dependency slot and its global typed RELA uniqueness.
It does not allocate or claim a new global unwind census. The complete fixed
71-row encoding and its actual arithmetic operands must satisfy the proof;
changed encodings fail instead of being assigned speculative semantics.

## Independently authored implementation

[The library](../../../src/node94-u128-division/lib.rs) exposes
`quotient(u128, NonZeroU128) -> u128`. It uses128-step bit-prefix restoring division,
structurally different from the native normalized-estimate/digit algorithm.
At each step, the consumed prefix p=q*d+r with0<=r<d is extended by one bit;
one guarded subtraction restores the invariant. The prior prefix has at most127
bits, so the remainder and quotient shifts fit128 without a hidden carry or
wrapping assumption. After128 steps the returned quotient is uniquely floor(n/d).
There is no `/`, `%`, native-byte transplant, fake callee or forwarding wrapper.

`NonZeroU128` is a newly chosen safe value domain. Native zero-divisor process
exception/signaling behavior is unimplemented, not mapped to a fabricated error.
The Rust signature/layout and physical operation order are not the original ABI.
Build scope is a real standalone `rustc` library/client/test pipeline, with no
root Cargo workspace or registry dependencies. The documented research compiler
is official Rust1.94.1 commit e408947bfd200af42db322daf0fadfe7e26d3bd1,
not a recovered original node compiler.

## Independent oracle and actual qualification

Before any new Rust source existed, a separate reviewer derived native branch,
digit, normalization/product/borrow equations from the71 actual rows and froze
7,587 stimuli/outputs, crosschecking each with exact integer divmod. All four RET
paths, e=1..64, estimate q/q+1, correction0/1 and both borrow classes occur.
The proof also checked384 partial-register/count cases. This finite corpus
supports the complete proofs; it is not exhaustive testing of the128-bit domain.

The original [freeze](preparation/ORACLE-FREEZE.json) and
[review](preparation/PRE-RUST-INDEPENDENT-REVIEW.json) are retained. The later
portable pure-core extraction and admission/serialization wrapper preserve those
native equations exactly; their preparation is explicitly separated in
[REFERENCE-WRAPPER-PROVENANCE.json](preparation/REFERENCE-WRAPPER-PROVENANCE.json).
Standalone model use is UNQUALIFIED. Fresh admitted native facts must precede
qualified expectation generation. Stored expected/TSV files are checked against
fresh equations, not used to create their answers.

Actual first-run results are retained in [observed/RESULT.json](observed/RESULT.json):

- 44 recorded processes and88 exact raw stdout/stderr streams;
- debug and O3 ordinary production libraries each match all7,587 fresh quotients;
- one actual Rust unit test per profile checks all7,587 fixture rows;
- four compiled, normal-returning semantic mutants differ on2312/3126/3089/3928
  quotients respectively, with successful full7587-row clients and actual
  assertion-failing unit exit101;
- two independent O3 rlibs are raw-equal,6,898 bytes each, SHA256
  `f52f0b39b1c257a96ea37aa5074120a98f835805ac28ed038298bafe2ba803ec`;
- all eight production/mutant/rebuild libraries have no forbidden division or
  remainder builtin, DIV/REM IR operation or machine DIV. The ordinary quotient
  bodies are470 bytes debug and126 bytes O3, not claimed to match target bytes;
- the separately labeled own `n/d.get()` wrapper is compiled once. Its actual
  `udiv i128` IR and `__udivti3` object reference make the same production guard
  reject it **before client linking or execution**. It is not an implementation
  or oracle and was never run.

The separately linked actual production client receives only id/n/d stimuli and
prints its full actual128-bit quotient. It never receives an expected value or
branch/path tag. This is reviewed data flow, not filesystem capability isolation.
The ordinary library excludes the cfg(test) fixture. Standard Rust I/O/test
runtime remains distinct from the guarded production-library arithmetic.

[OUTER-AUDIT.json](observed/OUTER-AUDIT.json) binds unchanged23 source/input files,
all103 authenticated compiler-prefix payloads, target and seven actual pins before
and after the run. No captured target, original compatible artifact or instruction
interpreter was invoked as an oracle. A later independent replay of both retained
production programs passed70 separate cases, including64 novel pairs and reordered
duplicates; those controls are kept separate in [independent-controls](independent-controls).

The setup mkdir omission and later evidence-packaging glob error are preserved
under preparation. Both were corrected without a compiler/scientific rerun or
altering previous results. The actual component pipeline passed on its first run.

## Reproduction and limits

```sh
python3 -B tools/u128_division_rust.py \
  --binary artifacts/node/94/hl-node \
  --rustc /path/to/verified/rustc \
  --output /tmp/new-u128-qualification --controls
python3 -B -m unittest discover -s tests -p test_u128_division_contract.py -v
```

The fixed own-library recipes emit rlib/ELF/LLVM IR at opt0 and O3; they do not run
captured bytes. Exact command arguments/environment and the lossless88-stream
[pack](observed/RAW-LOGS.json) are retained. Full generated libraries/objects and
compiler payloads stay local; no source-built compiler/runtime claim is made.
Newly authored Rust, Python and documentation use the repository MIT license.
The corresponding published compiler-builtins artifact excerpt retains its exact
`MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)` terms; the full
unmodified upstream license is retained under `third_party/`. Captured node bytes
and derived native listings retain their original ownership; this does not
relicense the capture as MIT. Only this bounded198-byte instruction evidence is
retained here, and no unlicensed can1357 implementation is copied.

All project recovery gates remain false. This is one complete numerical primitive
under stated native execution premises and a real independent Rust implementation.
It does not recover caller-wide fee arithmetic, rounding/units/state, original
private types/ABI/compiler, zero-fault behavior, physical clobbers, full component
or whole-ELF binary identity. The final exact-commit repository check results are
reported externally and in the PR; no green full-suite/CI result is inferred here.
