# fees-rust-engine-94: offline per-fill fee and ledger component

- Component ID: `fees`.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: repository `546081f30a3ebe6af1dadb6f90869f01bd08e1e4`;
  reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23` was not used as
  implementation source.
- Claim status: implementation of the bounded behaviors in the five retained
  packets listed below; no whole-fees-component, production-ledger, ABI, or
  binary-identity claim.
- Scope included: independently authored Rust in `src/node94-fees/`, per-fill
  fee output, supporting unit/rate calculations, and the six-word ledger.
  Scope excluded: schedule writers/rollover, live state layout, collection and
  exchange settlement, node #115, and full target build identity.

## Reproduce

Working directory: repository root. The Rust crate has no third-party
dependencies and does not run the captured node.

```sh
python3 tools/artifacts.py verify
(cd research/work-items/fees-trade-fee-94 && sha256sum -c MANIFEST.sha256)
(cd research/work-items/fees-fill-ledger-94 && sha256sum -c MANIFEST.sha256)
(cd research/work-items/fees-fee-scale-94 && sha256sum -c MANIFEST.sha256)
(cd research/work-items/fees-rate-grid-94 && sha256sum -c MANIFEST.sha256)
(cd research/work-items/fees-unit-conversion-94 && sha256sum -c MANIFEST.sha256)
cargo +1.94.1 build --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 test --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 clippy --locked --manifest-path src/node94-fees/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path src/node94-fees/Cargo.toml -- --check
```

Repository verification remains:

```sh
make verify test catalogue-check
make reproduce
```

`make doctor` is expected to remain non-zero on the authoring macOS shell when
GNU binutils and the optional local Java/Ghidra installation are unavailable;
the component consumes already-reviewed packets and does not require native
analysis to build.

## Evidence

This implementation depends on these authenticated, binary-backed packets and
does not reinterpret the unlicensed reference source as evidence:

- `research/work-items/fees-trade-fee-94/`: full perp and spot producer
  functions plus rate, discount and window helpers; 2,840 evaluated vectors.
- `research/work-items/fees-fill-ledger-94/`: full six-word fill-ledger path;
  1,015 evaluated vectors.
- `research/work-items/fees-unit-conversion-94/`: full conversion/accumulation
  function; 3,436 evaluated vectors.
- `research/work-items/fees-rate-grid-94/`: complete grid point and bounded
  caller chain; 2,749 point vectors.
- `research/work-items/fees-fee-scale-94/`: complete scale setter and its
  observed `[0, 3]` comparison, including NaN comparison behavior; 3,613
  evaluated vectors.

Original ranges, addresses, decoding options, mutations and limitations remain
in those immutable packets. Their manifests are rechecked rather than copied
here.

## Implementation and comparison

The crate is a standalone Rust 2024 library with a pinned `Cargo.lock`, no
dependencies and a documented build scope. Public types distinguish rates,
profiles, perp/spot fills, recipients, arithmetic events, errors, the six
ledger words, and builder collections.

The named trade-fee examples are transcribed as Rust integration tests. The
supporting tests exercise the exact strict boundaries and exceptional paths.
Passing those tests establishes agreement for the retained examples and tested
boundaries, not target-wide equivalence. No normalization mask, machine-code
body comparison, Linux two-build identity result, or target ABI comparison is
claimed.

## Results and limitations

The standalone crate contains 1,463 lines of library Rust and 786 lines of
Rust integration tests. Its 16 Rust test functions pass with both the target's
Rust 1.94.1 toolchain and repository Rust 1.95.0 toolchain. The five retained
packet suites contribute 207 passing Python tests. A fresh run regenerated
every stored oracle datum byte-for-byte: 2,840 trade-fee, 1,015 fill-ledger,
3,613 fee-scale, 2,749 rate-grid, and 3,436 unit-conversion vectors.

LLVM source coverage for the seven library modules is 711/835 executable lines
(85.15%) and 927/1,107 regions (83.74%). Coverage including integration tests
is 1,352/1,476 lines (91.60%). Rust format, clippy with warnings denied,
locked release build, artifact verification, catalogue check, and repository
reproduction all pass.

The repository-wide `make test` run is not clean on the authoring macOS host:
GNU-binutils-dependent native tests fail because `objdump`/`readelf` are not
available, several pre-existing static-evaluator tests fail independently of
this standalone crate, and the run was eventually terminated by signal 9 in
`test_node_port_static`. This component's target-bound Rust and Python suites
are therefore the qualified comparison surface. The implementation
intentionally leaves the `fees` progress gates unchanged because it covers
neither the full 14-day rollover nor the full production
settlement/collection state machine.

Unresolved dependencies:

- the accepted semantics of the still-open spot/perp settlement and collection
  packets;
- full fee-schedule and volume-window writers, including rollover;
- live hash-table/B-tree layouts and persistence;
- node #115 drift and any target build/ABI identity comparison.

Next question: once the open settlement packets are reviewed, which bounded
typed transition can be added without conflating the six-word fee ledger with
the exchange balance and collection ledgers?
