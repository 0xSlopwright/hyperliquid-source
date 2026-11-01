# RE-007 node94-margin-risk Rust implementation

- Component: bounded margin-tier, position-margin, and liquidation-eligibility
  path.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Implementation: `src/node94-margin-risk/`.
- Evidence dependency: `research/work-items/RE-007-margin-path-94/`, merged as
  PR #50.
- Claim: independent source implementation of the authenticated bounded
  behaviors only; no source, ABI, binary, or complete-risk-engine equivalence.

## Evidence-to-code mapping

| Retained evidence | Rust implementation |
| --- | --- |
| ordered tier admission and contribution arithmetic, `0x3335590..0x3335c40` | `src/tiers.rs`, `src/types.rs` |
| unsigned lookup and initial/maintenance formulas, `0x33331a0..0x3333915` | `src/requirements.rs` |
| signed notional, raw modes 0 through 4, cross/isolated output, `0x3717480..0x37179c5` | `src/position.rs` |
| signed saturating surplus and negative-only admission, `0x37d7360..0x37d79e0` | `src/liquidation.rs` |
| authenticated boundary table and independently transcribed mode vectors | `tests/fixtures/`, `tests/evidence_vectors.rs` |
| malformed and high-range input controls | unit tests and `tests/adversarial.rs` |

The library is dependency-free and never executes the captured node. The
fixed-point crate was reviewed but is not linked because it does not expose the
exact raw signed multiplication and record contract required by this path.

## Reproduce

From the repository root:

```sh
python3 tools/artifacts.py verify
(cd research/work-items/RE-007-margin-path-94 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_margin_path_static -v
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --offline --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --offline --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo clippy --offline --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-margin-risk/Cargo.toml -- --check
```

## Limits

Unresolved behavior is intentionally explicit: external custom-table lookup,
cross-account aggregation, decimal exponents, owned target layouts, candidate
record fields and ordering, liquidation sizing, transfers, execution, and
persistent state mutation. Requirement values outside signed-i64 range reach a
target recorder/failure path and are returned as typed errors. Zero divisors
are never normalized.

The implementation does not advance the risk component gates. It establishes
a testable source base for the proved path while preserving the remaining
reconstruction work.
