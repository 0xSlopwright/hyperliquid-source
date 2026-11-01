# RE-003: integration review of PRs #1242–#1264

- Question: do the 23 recorded PR heads preserve the baseline evidence and pass
  their declared bounded checks when integrated together?
- Base: `391fe838467760eefc04072c0ea762a7a1155c78`; exact heads are in
  `reviewed-heads.json`. Contributor commits and original evidence are preserved.
- Components: foundation, transport, orderbook, risk, assets, action-wire,
  action-dispatch, bridge, staking and the separate Visor artifact.
- Claim status: local integration observations, with original packet-specific
  inferences and unresolved scope retained. No completion gate is requested.

Targets, authenticated as static inputs:

- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115 comparison only: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Visor: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

## Evidence and implementation

The batch adds five independent, explicitly partial Rust components: TCP frame
codec, order-book lifecycle, margin risk, prefixed-hex encoding and action
preimage/payload construction. They have real standalone build scopes; none is
a full node build. The action component constructs bytes and does not sign or
submit transactions. Helper stubs, safe-API differences, incomplete caller/data
closure and packet-specific ABI gaps remain unresolved.

The `c_signer_jail` change rejects a truncated RELA section before iterating
24-byte records. It repairs evidence ingestion for that existing research task;
the regression covers valid target data and malformed inputs.

Eight small foundation collectors pass their evidence checks. Seven larger packets
regenerate 79 files byte for byte: bridge admission, send-to-EVM, update leverage,
isolated margin, staking action wire, staking vote quorum and Hyperliquidity
registration. Independent GNU objdump checks agree with 68,328 instruction byte partitions across their 190
declared FDE bodies, plus 233 rows in the eight foundation windows. Counts are
checks of declared bodies, not a deduplicated node-function denominator, and
instruction partition agreement does not prove evaluator semantics.
All 21 incoming manifests verify, including 403 recorded file hashes, after the
two corrections below. Original raw target exports are unchanged.

### Capacity-helper correction in PR #1262

The incoming model reverses the meaning of `cmp rsi, rcx; cmovbe rsi, rcx` at
`0x4f050b8`/`0x4f050bb`: when the incremented request is below or equal to the
doubled capacity, the source register replaces it. This selects the unsigned
maximum. The correct expression is `max(4, (requested+1) mod 2^64,
(2*oldcap) mod 2^64)`. With old capacity 10 and request 5, the original model
returns 6 although the target sequence selects 20.

The added regression fails against the submitted model; all 23 focused tests
pass after correcting the model, boundary expectations, derived edge records,
caller reduction and prose. The caller sets oldcap=requested, which still does
not reduce the expression to requested+1. The original five modified files and
the first failing regression are retained in `original-capacity-clamp/` and
`capacity-correction/`. The packet manifest is refreshed for the corrected
derived evidence. No raw disassembly/frame record or completion gate changes.

### Retry-loop instruction-table correction in PR #1264

The table at `0x3cbefe1` retains only seven bytes of a 15-byte NOP, mistaking
GNU's default display wrapping for an instruction boundary. The existing full
body hash correctly pins all 115 bytes, but the instruction table covers only
107. The full encoding is restored and the checker rejects table gaps and
overlap. Two regressions fail against the original table/checker; all 21
focused tests then pass. `original-retry-loop/` and `retry-correction/` retain
the submitted files and failing logs. The retry semantics and raw target exports
are unchanged.

The three draft PRs receive focused qualification here. The status-controller
collector reproduces its retained output. The prefixed-hex Rust reconstruction
passes 2,664 frozen responses in both debug and optimized profiles, 64 independent
client cases, and compiled mutation controls. Native inspection admits its
414-byte target body and caller contexts. The Visor packet reproduces all target
facts with the installed providers, passes ten corruption controls, and has
GNU/LLVM byte-partition agreement over four FDE bodies, 2,560 bytes and 640 rows.

## Reproduce and validation

Machine-readable commands, source identities and results are retained alongside
this file. Full transient logs, regenerated packets and native exports remain
under ignored `work/merge-open-1242-1259/`. Original PR packets retain their raw
target evidence and reproduction procedures. Local roots in published records
are replaced with `<repo>`, `<review-output>` and `<user-home>`. Trailing blank
lines are removed from published Rust logs; the original logs remain in ignored work.
`review-scripts/` records the executed review scripts; reuse requires restoring
the transient directory layout and substituting these local path placeholders.

The host uses Python 3.13.2, GNU binutils 2.47, LLVM 22.1.4 and Rust 1.94.1.
For native checks, prepend installed GNU binutils and LLVM to `PATH`.
`make doctor verify catalogue-check reproduce` uses the pinned repository inputs.
The full `tools/run_tests.py` inventory is scheduled with the same isolated
unittest command per file, eight subprocesses concurrently; the late quorum
and corrected capacity-helper test files, plus Hyperliquidity registration and
the corrected retry-loop checker,
run separately. Final per-file results are in
`regression-validation.json`. Captured execution and Unicorn opt-ins remain off.
The final current inventory contains 891 test files: all pass, with 14,275
reported tests and 60 explicit skips. Per-file source hashes and skip reasons
are retained. Repository integrity, catalogue consistency and inventory/literal
reproduction checks also pass.

All four new Cargo crates receive formatting checks, offline locked builds,
debug/release tests, Clippy with warnings denied and Linux x86-64 release library
builds. Per profile, TCP has 53 tests, orderbook 27, margin risk 40 and action
payloads 14. Prefixed hex uses its documented direct-rustc build and also builds
a Linux x86-64 library. Initial missing Cargo cache entries and Linux standard
library failures are retained; installation of the locked dependencies and
target resolves them, and every affected command is rerun successfully.

Provider differences are explicit. Prefixed hex uses the macOS build of Rust
1.94.1, not the contributor's Linux compiler or its 103-payload recipe. Its native
wrapper uses installed GNU 2.47; Linux cgroup admission is unavailable on this
host. Visor checks use GNU 2.47 and LLVM 22.1.4 instead of the original 2.42 and
18.1.3. Ignored host copies change provider admission only, preserving submitted
scripts and evidence. These are fresh host qualifications, not claims to have
reproduced the original Linux provider environments.

## Results and remaining gaps

No module or compiled-byte registry entry is added. Regenerating the catalogue
leaves 0/24 complete modules and 0/96 accepted full-scope gates. Node #94 retains
4,386/4,478 raw matching bytes (97.95%), 3/8 raw-equal windows (37.50%) and 8/8
raw-or-relocation-qualified windows (100%). Those windows cover only 0.00636%
of node #94's `.text`; whole-module byte correctness remains unmeasured.
Node #115 remains a separate comparison and is excluded from those totals.

No captured executable is launched, no chain action or target networking occurs,
and no source submodule or artifact pin advances. Hosted CI is queued at review;
local validation does not establish hosted success. A full node build, complete
component behavior and code/data/call identity remain open.

Next question: which bounded uncovered caller or helper can close one of the
new Rust components' explicitly documented target-evidence gaps?
