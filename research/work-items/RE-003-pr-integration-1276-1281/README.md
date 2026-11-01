# RE-003: integration review of PRs #1276–#1281

- Question: do these six heads reproduce their bounded node #94 evidence, and
  does the new consensus Rust component agree with the retained admission cases?
- Base: `b7fa6899`; exact contributor heads are in `reviewed-heads.json`.
- Components: foundation, perp quantities, EVM storage replacement, consensus.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: static observations and bounded reconstruction validation;
  source types, caller identities and original packet limitations remain qualified.
- Included: the six additive PRs and the dividend-wrap correction below.
  Excluded: captured execution, live cryptography/networking, complete node build,
  compiled-byte equivalence and full component acceptance gates.

## Evidence

The three new generators reproduce 15 retained files byte for byte. All five
current packet manifests verify, covering 27 file hashes. Native GNU disassembly
agrees with 51 instruction rows in four foundation bodies, 244 rows in three
price-scaling bodies and 996 rows in five EVM replacement ranges. Actual
`.eh_frame` records confirm those extents; the recorded division caller is also
verified at its native instruction start. EVM pins and selected edge sites align
with native instructions. The large contextual EVM caller is not fully analysed.

PRs #1276 and #1279 overlap at the two 318-byte option helpers. They are counted
once in this review. PR #1279 additionally supplies the display helper and
concrete control walker. Their four 4-byte RIP fields compare two target copies;
this is not a rebuilt-byte measurement. Display rounding mode, tag-2 meaning,
caller provenance, database failure propagation and durable state-root behavior
remain unresolved.

## Dividend-wrap correction in PR #1277

The submitted model claims `x = u64::MAX`, divisor 2 causes quotient overflow.
The pinned sequence instead clears `edx`, computes the 32-bit divisor bias in
`eax`, then executes `add rbx, rax` at `0x4f9eea4` before `div rcx`. The carry
is not propagated into `rdx`. The correct dividend is
`(x + ((t - 1) mod 2^32)) mod 2^64`, with high half zero. For that input both
quotient and remainder are zero. With divisor 10 the same input yields quotient
zero and remainder eight. A nonzero divisor cannot overflow the quotient when
the high dividend half is zero; divisor zero still faults.

Three regressions fail against the incoming evaluator: two wrapped numerators
are rejected and a false divide-overflow claim is accepted. The corrected
evaluator, retained boundary record, test expectations and README agree with the
instruction sequence. All 28 focused tests then pass. `original-division/`
preserves all five changed incoming files, and both failing and passing logs are
retained. The packet manifest is refreshed; raw disassembly and frame exports
are unchanged. No captured code was executed to establish this correction.

## Consensus implementation and comparison

`src/node94-consensus-admission/` is a real standalone MIT Rust crate. Offline
debug and release tests each pass 36 unit and nine evidence-contract tests.
Formatting and clippy with warnings denied pass. Authentication, digest
construction and proposer scheduling remain explicit external boundaries;
stable ordering among simultaneous TC signature failures is an unresolved-case
choice documented by the crate. Target panics become typed fatal results.

A separate generated Rust client compares all 456 retained named/seeded cases
in both debug and optimized profiles. It checks result class/tag, block and
transaction keys, request removal, ordered unknown hashes, placeholder time,
forwarding/wake counts and failure atomicity. It supplies the retained fixtures'
recovered identities through the authentication trait. This does not test real
signatures, error payloads, logging, pointer layouts, allocation, or channel
internals. The generated client emits unused-variable warnings; the crate's own
clippy check is clean. Client source/fixture hashes and results are retained,
and `review-scripts/qualify_consensus.py` regenerates the client.

The existing target-row evaluator is independently rerun on all 456 cases with
its documented stubs. Thirteen output files reproduce byte for byte; summary
fields also agree after excluding the old mutation statistics. The mutation
sweep is not repeated. Native disassembly agrees with all 3,642 instruction
partitions in the 15 declared FDE ranges, with no unsupported tail. These checks
support the bounded packet contract, not native execution or whole-node
equivalence. The Rust evidence-contract tests alone inspect retained text;
the additional evaluator/client comparisons provide the behavioral check here.

## Reproduce and validation

Host: Python 3.13.2, GNU binutils 2.47, Rust 1.94.1, macOS arm64. Run from the
repository root. `review-scripts/` retains exact commands and options; substitute
the `<repo>` and `<review-output>` placeholders and restore its ignored review
directory layout. `checks.json`, `rust-checks.json`, `reproduction.json` and the
consensus receipts record the executed checks. Native exports are under `native/`;
only local filename prefixes are replaced, with original/published hashes kept.
Published Rust test logs omit trailing blank lines; original log hashes and
unaltered transient logs remain available. Transient outputs remain under ignored `work/merge-open-1276-1281/`.

The immediately preceding integration completed all 901 baseline test files in
this same session. These six PRs add files without changing baseline tracked
code. All five new Python modules pass, including the corrected division suite:
90 new tests. The combined current inventory is 906 files and 14,618 reported
tests: 14,558 passed, 60 explicit baseline skips, no failures. Per-file hashes and
the baseline record link are in `regression-validation.json`. A second full
baseline run is not claimed. Repository integrity and catalogue checks pass
again after the correction. Captured-execution and Unicorn opt-ins remain off.

## Results and limitations

No progress gate is requested. README module and byte-window completion figures
remain unchanged. Native partition agreement, target-copy normalization and a
bounded Rust component do not establish complete helper/data/relocation closure
or a full node build. Hosted CI is separate from these local results.

Next question: bind an unclaimed consensus authentication boundary to its exact
signing fields and recovered identity semantics before closing the Rust
component's cryptographic assumptions.
