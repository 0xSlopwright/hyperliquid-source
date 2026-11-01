# Node #94 margin and risk component

This directory contains an independently authored, offline Rust library for
the bounded margin path established for Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It does not execute the captured node or use the unlicensed reference tree as
implementation source.

The crate is standalone, dependency-free, and deliberately absent from a root
Cargo workspace because the repository does not yet have a recovered workspace
contract. The API uses raw integer units: the evidence establishes widths and
operations inside this path, but not the external decimal exponents.

## Public contract

`MarginTable::try_from(RawMarginTable)` preserves the observed constructor
order. It admits a UTF-8 description of at most 250 bytes and one through three
tiers. The first lower bound must be zero. Every lower bound is below
`0x0ccccccccccccccc`; later lower bounds are also at most
`1_000_000_000_000_000`. Leverage is at most 50, strictly decreases, and lower
bounds strictly increase. The constructor retains the target's exact
prevalidation order, including checking the next lower bound before comparing
the current lower bound with its predecessor.

For a tier boundary `B`, current leverage `Lc`, previous leverage `Lp`, and
accumulated prior contribution `P`, the stored value is:

```text
P = P.saturating_add(B / (2 * Lc))
     .saturating_sub(B / (2 * Lp))
```

A single tier with zero leverage is admitted, as in the target. Any later
calculation that reaches its divisor returns a typed fault; the library does
not silently choose a value or panic.

Tier selection uses the last lower bound less than or equal to unsigned
notional. The two requirement functions preserve target u64 operation order:

```text
initial = floor(notional / (2 * leverage))
          .saturating_sub(prior_contribution)

maintenance_numerator = notional.saturating_mul(2).saturating_sub(
    prior_contribution.saturating_mul(4 * leverage)
)
maintenance = floor(maintenance_numerator / (6 * leverage))
```

`calculate_position_margin` implements the five verified raw modes:

| Mode | Requirement |
| ---: | --- |
| 0 | zero |
| 1 | absolute notional divided by the position's u32 divisor |
| 2 | tiered initial requirement |
| 3 | tiered maintenance requirement |
| 4 | absolute notional divided by `min(position divisor, u8 cap)` |

The function rejects negative signed-i64 prices, checks signed-i64
`size * price`, and converts the result to unsigned magnitude. Consequently,
`i64::MIN` has magnitude `2^63`. For modes 2 and 3, selectors below 50 form the
observed single tier; selectors at least 50 require a caller-supplied,
already-resolved custom table. The surrounding lookup map is not invented.

The record's raw accounting byte is represented by `AccountingMode`: zero is
cross and every nonzero value is isolated. Cross output retains signed
notional, requirement, and unsigned magnitude. Isolated output saturating-adds
signed notional to prior margin, clamps effective margin at zero, and retains
the prior margin and computed requirement.

Liquidation support ends at eligibility. Cross callers must supply the
already-aggregated signed equity and unsigned maintenance requirement. Isolated
callers use the position result directly. The requirement must fit the signed
comparison path; surplus uses signed saturating subtraction and eligibility is
exactly `surplus < 0`. Zero surplus is ineligible.

## Evidence map

The implementation is grounded in
`research/work-items/RE-007-margin-path-94/`, merged in PR #50. The retained
packet authenticates every admitted target range, instruction control, call
edge, source-location record, and arithmetic vector.

| Module | Established target range or record |
| --- | --- |
| `src/tiers.rs` | tier admission `0x3335590..0x3335c40` |
| `src/requirements.rs` | lookup `0x33331a0..0x3333276`, maintenance `0x3333670..0x33337f9`, initial `0x3333800..0x3333915` |
| `src/position.rs` | position margin by mode `0x3717480..0x37179c5` |
| `src/liquidation.rs` | candidate collection `0x37d7360..0x37d77d8`, surplus `0x37d77e0..0x37d79e0` |
| `tests/fixtures/*.tsv` | packet `boundaries.tsv` plus the five mode branches |
| `tests/adversarial.rs` | bounded deterministic mutation controls over admitted public inputs |

The relevant RE-004 packets and `src/node94-fixed-point/` were reviewed for
type compatibility. This path needs checked signed price-size multiplication,
unsigned `i64::MIN` magnitude, and raw-width margin records not exposed by that
crate, so no artificial dependency was introduced.

## Validation

Run from the repository root with at most two build jobs and test threads:

```sh
CARGO_BUILD_JOBS=2 cargo build --offline --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo build --offline --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --offline --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2 cargo test --offline --release --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml
CARGO_BUILD_JOBS=2 cargo clippy --offline --locked \
  --manifest-path src/node94-margin-risk/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-margin-risk/Cargo.toml -- --check
python3 -m unittest tests.test_margin_path_static -v
```

Authenticate the target and retained packet before interpreting these tests.
Repository-level verification remains `make verify`, `make test`,
`make catalogue-check`, and `make reproduce`; it must not overlap another
full-suite run.

## Deliberate limits

This component does not claim a complete risk engine, account aggregation,
custom-table storage lookup, oracle conversion, decimal scaling, serialization,
ABI or owned-layout equivalence, candidate record field ordering, candidate
sorting, liquidation sizing, transfers, execution, persistence, or live node
behavior. The 48-byte candidate append is established, but its fields are not,
so this crate does not serialize a speculative candidate record.

Target panic and recorder paths are exposed as typed errors rather than
reproducing abort payloads. No socket, signing, production state, or networking
code is present. No completion gate is advanced by this bounded component.
