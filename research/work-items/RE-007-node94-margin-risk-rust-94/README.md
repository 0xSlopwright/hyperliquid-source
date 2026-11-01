# RE-007 node94-margin-risk Rust implementation

- Component: bounded margin-tier, position-margin, and liquidation-eligibility
  path.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Implementation: `src/node94-margin-risk/`.
- Evidence dependency: `research/work-items/RE-007-margin-path-94/`, merged as
  PR #50.
- Implementation base: `391fe838467760eefc04072c0ea762a7a1155c78`.
- Claim: independent source implementation of the authenticated bounded
  behaviors only; no source, ABI, binary, or complete-risk-engine equivalence.

## Evidence-to-code mapping

| Retained evidence | Rust implementation |
| --- | --- |
| ordered tier admission and contribution arithmetic, `0x3335590..0x3335c40` | `src/tiers.rs`, `src/types.rs` |
| unsigned lookup and initial/maintenance formulas, `0x33331a0..0x3333915` | `src/requirements.rs` |
| signed notional, raw modes 0 through 4, cross/isolated output, `0x3717480..0x37179c5` | `src/position.rs` |
| signed saturating surplus and aggregate pair, `0x37d77e0..0x37d7f0c` | `src/surplus.rs` |
| negative-only admission and bounded record fields, `0x37d7360..0x37d77d8` | `src/candidate.rs` |
| authenticated boundary table and independently transcribed mode vectors | `tests/fixtures/`, `tests/evidence_vectors.rs` |
| all maintained packet boundaries | `tests/boundary_contract.rs` |
| malformed, high-range, formula and admission mutants | `tests/adversarial.rs`, `tests/negative_controls.rs` |

The library is dependency-free and never executes the captured node. The
fixed-point crate was reviewed but is not linked because it does not expose the
exact raw signed multiplication and record contract required by this path.

## Candidate record boundary

The following are direct observations in the candidate collector. Record
addressing at `0x37d73fd..0x37d7405` and `0x37d7475..0x37d7484` multiplies the
index by 48. The cross append writes tag zero at `0x37d7405`, signed surplus at
`0x37d740d`, and 20 input bytes at `0x37d7417..0x37d7422`. The isolated append
writes tag one at `0x37d7484`, its context word at `0x37d748c`, signed surplus
at `0x37d7491`, and the same 20-byte input at `0x37d749b..0x37d74a6`.
`0x37d73dc..0x37d73df` and `0x37d76c2..0x37d76c5` admit only negative surplus.

`CandidateScope`, `CandidateSubject`, and `LiquidationCandidate` represent
those bounded values without `repr(C)` or byte serialization. Calling the
20-byte value a subject, and the aggregate words signed equity and maintenance
requirement, are target-supported labels rather than recovered source names.
The final four bytes of the 48-byte record, the isolated context word's owned
type, candidate ordering, and all post-admission mutation remain unresolved.

## Reproduce

From the repository root:

```sh
python3 tools/artifacts.py verify
(cd research/work-items/RE-007-margin-path-94 && sha256sum -c MANIFEST.sha256)
python3 -m unittest tests.test_margin_path_static -v
CARGO_BUILD_JOBS=2 cargo +1.94.1 build --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo +1.94.1 test --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo +1.94.1 test --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo +1.94.1 clippy --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path src/node94-margin-risk/Cargo.toml -- --check
```

## Limits

Unresolved behavior is intentionally explicit: external custom-table lookup,
the account-state source of starting equity, decimal exponents, owned target
layouts, candidate ordering, liquidation sizing, transfers, execution, and
persistent state mutation. Requirement values outside signed-i64 range reach a
target recorder/failure path and are returned as typed errors. Zero divisors
are never normalized.

The implementation does not advance the risk component gates. It establishes
a testable source base for the proved path while preserving the remaining
reconstruction work.
