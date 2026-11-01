# RE-003: integration review of PRs #1170–#1184

The requested merge batch begins at main
`de089f488ddb7d381a2e0aaccde7a4a2e9ad9bac`. `reviewed-heads.json` records
the exact incoming heads retained as merge ancestors. PR #1181 arrived during
review; #1180 added a retained verification log and clarified its execution
scope while its producer and record bytes remained unchanged.

The node observations bind node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The Visor observations bind the separate capture SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
No captured executable, live signing, chain operation or target network service
was started. Imported artifacts, reference pins and all completion gates remain
unchanged. These are bounded research results, not complete component recovery.

## Research reproduction

Both foundation collectors reproduce their submitted JSON. Their tests cover
corrupted instruction, FDE, relocation and caller controls. An independent GNU
disassembly audit confirms the complete 38-byte divide-by-million and 49-byte
scaled-count bodies and the three incoming scaled-count call boundaries from
their actual FDE starts. Full native listings remain in the ignored review
directory; `foundation-native-audit.json` binds their digests. Callee behavior
and the contributors' whole-corpus twin searches are not independently closed.

The divide-by-million result is exact, but the contributor's loose `2**-18`
error estimate alone does not establish that result. The tighter independent
argument is retained in the audit: `MAGIC * 1000000 - 2**82 = 175296 < 2**18`,
so for every u64 input the excess is less than `1/1000000`, below the smallest
distance from a nonintegral quotient to the next integer. The original packet
is preserved without editing its evidence.

The heartbeat generator reproduces all 16 generated files, including 412 cases
and all 560 sampled mutation results. The signing/bundle generator reproduces
all eight generated files, including 1,273 cases and its killed, surviving and
unreached mutation records. These are one fresh reproduction per packet, with
`PYTHONHASHSEED=17`, `TZ=UTC` and two signing mutation workers. They preserve
the submitted crypto, allocator, clock and state-update stub limitations.
All four packet manifests verify; hashes are in `packet-audits.json`.

Independent GNU decoding matches the custom decoders' byte partitions for
21,295 rows over 74 heartbeat FDEs and 6,275 rows over 57 signing FDEs. One
heartbeat helper, `0x48c4470`, has an unsupported decoder tail beginning at
`0x48c4534`; only its matched prefix is credited by this check. All other
listed bodies decode to their ends. This tests instruction boundaries and
bytes, not instruction semantics or all-input behavior. The exact per-body
scope and export digests are in `decoder-native-audit.json`.

## Visor provider difference and controls

The original exact-recipe verifier correctly refuses this host's record because
the submitted recipe records GNU 2.42 while this host has GNU 2.47.20260726.
The only differing JSON field is `versions`; all seven raw GNU disassembly
exports and every other record field are byte-identical. No raw annotation,
address or instruction mask was applied. `visor-provider-difference.json` and
`visor-host-record.json` retain the distinction. This is not an exact pass of
the original Ubuntu tool recipe.

Unchanged copies of the submitted producer/verifier were run against a separate
host-specific record under ignored `work/`. Both normal and optimized Python
verification pass, each with two regenerations and all eight corruption
controls refused. LLVM independently matches all 324 instruction partitions
(1,574 bytes) in the readiness and OS-clock extents. No existing packet was
rewritten. Calendar/helper completeness, timestamp production and whole
readiness-policy behavior remain open as stated by the contributor.

## Parser integration and regression scope

The seven parser changes reject duplicate section names, non-increasing FDE
starts, duplicate RELATIVE slots or truncated relocation sections at their
actual evidence-ingestion boundaries. Synthetic corruption controls and the
affected collectors on authenticated retained captures are checked together.
The changes remain minimal; no surrounding tool architecture is replaced.

`regression-validation.json` reports fresh affected-module results separately
from the completed 805-module parent validation. New tests and a conservative
transitive reference search through tools/tests select the reruns, including
dependent action-dispatch, database, state-hasher and subaccount collectors.
Every selected source is hashed in `test-selection.json`. The resulting combined
inventory is checked against repository discovery, without counting reruns as
additional unique modules. A new full sequential `make test` run is not claimed.

`make doctor verify catalogue-check reproduce` passes with Python 3.13.2 and
installed native tools. Final artifact/pin and catalogue checks are repeated
before publication. Hosted CI success is not claimed. Raw test logs, native
exports and the original Visor version-mismatch failure remain under ignored
`work/merge-latest-1170-1180/`; the new regression controls and compact validation
records are retained here.

## Final two arrivals (#1182–#1183)

After the first publication at `8e80259254c57d0834b34e738c6a3bc9fd18aa30`,
the compact-string relocation reader receives the same minimal partial-record
rejection. Both affected modules pass all 12 tests on authenticated node #94.
The new action-delay static collector passes five tests, including original
instruction, constant and relocation corruption controls. These reruns extend
the fresh scope to 52 unittest modules / 672 tests, zero skips or failures.

The independently authored action-delay Rust crate passes three integration
tests on macOS aarch64 with actual Rust 1.94.1. Its release driver matches all
332 statically grounded vectors at every retained stage. All four deliberate
Rust mutants fail real tests. Original evidence and mutation records are
preserved; fresh outputs and full failure logs remain under ignored work/.

The locked, offline Linux x86-64 library build also passes using the already
retained Linux standard library. Two fresh optimized object builds both hash
to `985248f18d58430c3efd7d452153649e0aa95d6216883123756f8aaa4c28c4f6`, matching
the submitted own-build record. Fresh GNU decoding matches all 147 instruction
partitions across the five declared FDEs (665 bytes). Compiler/provider and
standard-library hashes are recorded in `action-delay-rust-review.json`.
This is own-build reproducibility and qualified logical arithmetic evidence;
it is not captured-byte, original ABI or whole-node equality. The original
FMA3/environment qualification, software fallback and caller gaps remain open.
Only newly authored Rust executes; captured bytes are read statically.

PR #1184 adds the same truncated-relocation guard to the separate Visor
reader. Both affected modules pass on the authenticated Visor capture. The
final fresh regression scope is 54 unittest modules / 684 tests,
with zero skips or failures; the incremental combined inventory is 819 modules.
