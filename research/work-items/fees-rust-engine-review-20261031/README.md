# PR #1150: bounded fee-engine review and input-error repair

Component: `fees`. Original source head:
`7b33a43b17c2ef0c5618ef4cfa08a8957e8a9943`, preserved as an ancestor.
Review base: `f5aca6234857c00cb62322274cf394e1c4da159d`.
Target: Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Disposition: accept the standalone offline component with the structural-input
repair described below. This is independently authored MIT Rust, with a real
dependency-free Cargo package and lockfile. No reference-tree code, invented
workspace, dependency stub, progress promotion, or target build identity is
introduced. The original packet and its author-reported failures and coverage
remain unchanged; coverage percentages were not independently reproduced.

## Original failure and repair

`FeeLedger::apply` originally credited the payer's trial-extra field before
resolving an enabled referrer address. A missing builder address was detected
even later, after payer and referrer credits. Thus an `Err` could leave state
changed, and retrying corrected input would credit part of a fill twice.

The retained original negative control starts with `TrialExtra=5`, submits a
record with `extra=7` and a missing enabled recipient, and observes state changed
to `TrialExtra=12` despite `MissingLedgerRecipient`. Both the missing-referrer
and missing-builder tests fail on the original implementation; an inactive-field
control passes. See `raw/original-unresolved-both.log` and the original source
snapshots. The earlier single-recipient failure is also retained verbatim.

The repair resolves both required addresses before any mutation. It retains the
target's exact low-dword referrer-tag check and low-byte/nonzero-amount builder
check. Unused addresses remain unused. Three new tests prove unchanged state on
each error, one application after a corrected retry, and inactive-field behavior.
This error contract belongs to the offline typed API: an absent Rust `Option`
address is not a recovered target-memory representation or new native transition.

Only the crate's ledger implementation and README change; a new boundary test and
this review packet are added. Original PR file hashes are in
`original-file-pins.json`; all reproduction inputs are in `source-pins.json`.

## Native binding and reviewed semantics

`native/audit.json` and the eleven GNU disassemblies bind 3,796 instructions to
the authenticated artifact, exact full FDE ranges, per-range byte hashes, and
the existing retained decoder boundaries/bytes. No broad decompiler labels were
used as function evidence. GNU objdump version is retained in the audit.

Specific reviewed controls include:

- Perp negative-rate share uses division then `MINSD` at `0x37131d4` and
  `0x37131d8`; the trial/asset multiplications precede the discount comparisons
  at `0x3713275`/`0x371327b`. The Rust operand ordering preserves these branches.
- Perp conversion sequences at `0x371345b..0x3713495` and
  `0x37134b7..0x371350d` clamp/truncate rather than using an ordinary unchecked
  cast. Builder base divides by 100,000 before multiplying notional at
  `0x3713561`/`0x3713569`; the Rust implementation uses that order.
- The ledger tests the referrer tag as a dword (`0x3745b52`, `0x3745ba6`),
  subtracts rebate before extra (`0x3745bc8`, `0x3745bd2`), and checks the
  builder low byte and amount (`0x3745ef8`, `0x3745f1b`). State updates retain
  target order, including aliased owners and saturating/floor recorder events.
- The scale setter's `UCOMISD`/`JA` pairs at `0x3718e3f..0x3718e4d` reject
  ordered values outside [0,3]. Unordered NaN sets carry and does not take
  either `JA`; the bounded Rust range predicate preserves that fact without
  claiming that a public action parser accepts NaN.
- Full supporting rate, discount, volume-window, conversion and rate-grid
  ranges are enumerated in the native audit. Their retained synthetic cases
  exercise branch boundaries, nonfinite conversions and arithmetic recorder
  paths; imported table/allocator/hash helper contracts remain explicit limits.

## Fresh evaluation and Rust comparison

The five existing Python suites pass all 207 tests. After reviewing their
interpreters and host hooks, fresh bounded evaluation regenerated the exact
retained TSVs byte-for-byte: 2,840 trade-fee, 1,015 fill-ledger, 3,613 fee-scale,
2,749 rate-grid point and 3,436 unit-conversion vectors. Their evaluators compare
decoded-instruction execution with the separate packet models and fail on
disagreement. Raw commands, source/target/vector hashes, memory observations and
limits are retained in `raw/` and `safety-review.json`.

The wrapper caps each arena at 16 MiB, aggregate arenas at 64 MiB per machine,
nested interpreter calls at 32 and process time at 900 seconds. Existing finite
step budgets remain unchanged. The largest observed arena was 1,490,232 bytes;
the maximum observed call depth was four. No captured native process, public
download, socket, private state or chain action was used. Original exhaustive
mutation surveys and rate-grid caller-chain variants were not regenerated by
this vector command; the 207 existing tests ran separately.

An independently authored Rust stdin driver calls the actual crate API on
11,832 representable cases, with zero mismatches before and after the repair:

| API | Compared cases | Explicitly excluded packet cases |
| --- | ---: | --- |
| Trade producers | 2,686 | 48 asset-admission panics, 96 negative-notional panics, 10 malformed-tree panics |
| Ledger | 863 | 152 cases with pre-existing empty buckets, which the public seeding API cannot represent |
| Rate-grid point | 2,749 | None |
| Unit conversion | 3,432 | 4 asset-admission cases outside this API |
| Scale range | 2,102 | 1,511 other packet behaviors, such as time/cooldown/parser paths |

Negative notionals are separately covered by the Rust error tests. Trade
comparisons include all output amounts/recipients and ordered arithmetic-event
kinds; ledger comparisons include final seeded/reachable values, collected
builder fees, event count and creation count. Ledger event/creation detail and
alias order also have focused Rust tests. Corpus input, expected and actual
text are retained as deterministic gzip files, including the original actual
output. These comparisons are bounded source/API validation, not a claim of
full helper implementation, machine ABI, live map layout or whole-node identity.

## Terminal checks and reproduction

Original Rust: all 16 tests pass on 1.94.1 and 1.95.0; locked offline release
build, format check and clippy with warnings denied pass. After repair, all 19
tests pass on 1.94.1 debug/release and 1.95.0 debug. Format, clippy and build pass.
The five Python suites pass 207 tests. `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` pass with installed GNU binutils.
The parent integration lane owns the full combined `make test` gate; no full
repository success is claimed by this packet. The original author's full-suite
failures remain in its unchanged packet and raw PR metadata.

Run from the repository root, with the authenticated artifact and already
installed Rust 1.94.1 and GNU objdump available:

```sh
python3 -I -S -B research/work-items/fees-rust-engine-review-20261031/scripts/reproduce.py
cargo +1.94.1 test --offline --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 test --release --offline --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 clippy --offline --locked --manifest-path src/node94-fees/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path src/node94-fees/Cargo.toml -- --check
```

The reproduction driver authenticates its inputs before evaluation, uses the
recorded macOS GNU path, builds only local Rust source with networking disabled,
and writes under ignored `work/fees-engine-1150-reproduction`. It has also been
run with actual Python 3.10.18. Python optimization must be disabled because
the retained evaluators use assertions. Original review scripts are preserved
under `original/`; runnable copies add explicit output paths and a failing
status on any corpus mismatch.

Remaining scope is unchanged: full schedule/rollover, settlement/collection,
live persistence, node #115, target ABI, and build/binary identity are not
implemented or certified. No `fees` progress gate is advanced.
