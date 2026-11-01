# Node #94 offline fee engine

This standalone, dependency-free Rust crate implements the bounded fee behavior
established for Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It is independently authored from binary-backed evidence. The unlicensed
reference tree was used only as a lead by the retained research packets and was
not used as implementation source.

## Implemented contract

- Per-fill perp and spot fee calculation with explicit maker/taker selection.
- Target row semantics: a low-byte row tag selects current rates, a non-zero
  previous-rate tag selects the second rate set, and an exact row tag of 1
  selects the user's volume anchor and carried weight.
- Target spot category branches, including the different current/previous
  handling for categories 1, 2, and all other non-zero bytes.
- The 2,500,000,000 discount boundary, 100,000,000,000 referrer boundary,
  volume-tier scan, fixed flagged referral share, builder base fee and builder
  tier gain.
- Perp deployer/protocol split, rebates, trial extra, and the target behavior of
  the two all-`0xfe`/all-`0xff` exempt addresses.
- Target f64-to-i64 conversion: non-finite values become zero; finite values
  truncate toward zero and saturate.
- The unit/rate conversion path from `fees-unit-conversion-94`, including the
  exact `/ 10000`, pre-rate bypass and product clamp.
- The single-point schedule check from `fees-rate-grid-94`, with all four
  target reject classes.
- The six-word `V U C r F T` per-token ledger and collected-builder-fee map,
  including deterministic payer/referrer/builder aliasing and creation order.

All saturating or floor-at-zero operations that have a proven target recorder
path return an `ArithmeticEvent`. Structurally unresolved inputs return a
`FeeError`; they are never silently assigned a conventional finance meaning.
Perp-to-ledger conversion checks every target multiplication by 100.

## API shape

`FeeEngine` owns a `FeeSchedule` and offline `FeeProfile` map. Callers provide a
typed `PerpFill` or `SpotFill` and receive `Computation<...>`, which contains the
fee output and arithmetic events. `FeeLedger::apply` mutates the typed ledger
and reports record creation plus arithmetic events. `volume_conversion` and
`validate_rate_grid_point` expose the two bounded supporting calculations.

The conservative field names `multiplier_90`, `multiplier_98`, `row_tag`, and
`previous_tag` preserve target offsets/branch roles where the packets did not
establish a production name.

## Evidence map

| Behavior | Retained packet | Target ranges (ELF virtual addresses) |
| --- | --- | --- |
| Perp/spot fee and rate helpers | `fees-trade-fee-94` | `0x37130b0..0x3713dac`, `0x3742460..0x374301c`, `0x3742070`, `0x3743020`, `0x3743df0` |
| Six-word ledger | `fees-fill-ledger-94` | `0x3745a60..0x37463e7`, `0x3596da0`, `0x379a610` |
| Unit/rate conversion | `fees-unit-conversion-94` | `0x37153f0..0x3715e8b` |
| Schedule rate-grid point | `fees-rate-grid-94` | `0x36e2d90..0x36e3586` |
| Deployer scale range | `fees-fee-scale-94` | `0x3718e30..0x3719023` |

`tests/target_vectors.rs` transcribes all 13 named producer examples from the
trade-fee packet. `tests/adversarial.rs` covers strict discount boundaries,
builder/referrer precedence, missing previous rates, spot previous-rate routing,
self-referral and three-way aliasing, zero-credit creation rules, ledger
underflow/overflow, checked 100x conversion, non-finite conversion, every
rate-grid rejection, fee-scale NaN behavior, and gross saturation.

## Build and verify

From the repository root:

```sh
cargo +1.94.1 build --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 test --locked --manifest-path src/node94-fees/Cargo.toml
cargo +1.94.1 clippy --locked --manifest-path src/node94-fees/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path src/node94-fees/Cargo.toml -- --check
```

## Deliberate limits

This is not a full fee schedule, fee-schedule writer, 14-day volume rollover,
hash-table/B-tree implementation, or production exchange ledger. It does not
implement the still-open spot/perp settlement packets, fee collection sweeps,
trial rollover, live state loading, node #115, or target ABI/layout identity.
The profile maps are typed offline inputs, not recovered persistence formats.

The fee packets establish binary64 instruction order, so this implementation
uses Rust `f64` only for those observed steps. It does not replace any target
step with decimal/fixed-point arithmetic, nor does it promise cross-target
bit identity beyond Rust's ordinary IEEE-754 operations. No progress gate or
whole-component identity claim is requested.
