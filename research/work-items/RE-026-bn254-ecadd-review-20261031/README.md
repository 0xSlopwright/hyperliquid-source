# RE-026: review of PR #1142 bn254 ecAdd evidence

Exact original head: `37edf82353c6e00459e4e9280b53e403c2763ea9`.
Target node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `a4e4302fb0743238cfd7ac21bc0823ee2f91345a`.

**Held for behavioral acceptance.** Static evidence and safe harness controls
were reviewed; no captured instruction, emulator or public download ran here.
The original acceptance includes eight emulator tests that need separate user
authorization. Authorization for other crypto packets does not cover this one.
The original eight changed Git blobs are archived byte-for-byte in `originals/`.
The original emulator JSON is unchanged and remains author-reported evidence.
Exact hashes, commands, results, fixes, gaps and the future bounded execution
command are recorded in `review.json`.

Native GNU objdump/readelf 2.47.20260726 and independent FDE parsing authenticate
the nine originally claimed/context FDEs: 15,478 bytes and 2,852 instructions.
The main body `0x4e96610..0x4e96cee` is exactly 1,758 bytes with SHA-256
`89f39d1b63955c1db57a998837ca6f826d190682a1c6ad8db722e37f707bad39`.
The 29 original byte pins, selected direct/RIP transfers, six slot bindings,
20-byte table Address 0x06 fields, gas150/500 immediates, source Location and
field/Montgomery constants agree with native bytes. Constant occurrence counts
were separately checked as native MOVABS immediates, not just byte substrings.
The independent affine doubling equation gives the retained 2G vector, without
claiming that the captured body was executed or proved equivalent.

Four further arithmetic FDEs resolve through the native call graph:
`0x4f1dea0..0x4f1e70c`, `0x4f1f8e0..0x4f1f9b1`,
`0x4f20020..0x4f200e3`, `0x4f200f0..0x4f206ea`.
The resulting ten-body execution allowlist contains 13,773 authenticated bytes.
It is a conservative bounded allowlist, not complete semantic or path coverage.
Error/panic/import paths are excluded and must fail the bounded runner.

Original defaults automatically requested emulation; a mock-only reproduction
retains that negative finding without loading an emulator. Corrected CLI/API,
packet verifier and unit tests are static by default even with Unicorn present.
Only explicit opt-in enables the future comparison. The shared guard requires
in-range instructions and synthetic writes, a positive time/count limit and
the exact return sentinel. The malloc callback validates its stack read, exact
64-byte request from return0x4e96c62, heap bounds/alignment and synthetic output
reads. The allocator entry admits only its four-byte hook site; disabling the
stub therefore fails before executing the allocator body.

Two semantic qualifications matter. `run_add` contains 100 XMM instructions
(e.g. `xorps xmm0,xmm0` at0x4e96659), so a limited opcode scan is not a no-SIMD
or complete feature-dispatch proof. The out-of-gas branch writes only the tag
at output+0x10 and clears output0..0x10; output+0x18..0x28 remains unchanged.
A static nonzero-memory counterexample preserves that distinction from the
historical zero-initialized harness snapshot. Rust enum/type names remain
inferences, not recovered source contracts.

Original raw scans omitted final fitting encodings. Six synthetic terminal
cases reproduce those omissions; corrected producer and independent scans cover
them without claiming instruction-aligned global xref closure. The producer's
candidate search preserves the exact static JSON digest while avoiding repeated
bytewise Python scans of the whole text load.

Validation: original20 static tests pass normal and optimized actual Python3.10;
both original independent-verifier modes pass. Corrected suites each run39 tests:
31 safe tests pass and eight captured-code tests are explicitly skipped. Both
corrected packet verifiers pass normal and optimized in static scope. Verify,
catalogue-check and reproduce pass. All six changed/shared Python files compile
under actual Python3.10. A preoptimization integration run was stopped and is
excluded, with its available receipts retained in the ignored review ledger.

Short inputs/memcpy, allocator internals, panic/unwind behavior, other callers
and forks, wrapper execution, source recovery and binary identity remain open.
No progress gate is changed. Do not merge this branch as behaviorally accepted
until the separately authorized eight-test command completes with zero skips.
