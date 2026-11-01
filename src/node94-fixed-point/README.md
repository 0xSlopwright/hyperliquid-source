# Node #94 fixed-point component

This directory contains an independently authored Rust library for the bounded
quantity and price arithmetic established by the retained RE-004 evidence. It
targets Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The unlicensed reference tree was not used as implementation source.

The crate is standalone and dependency-free. It deliberately is not added to a
root Cargo workspace because this repository does not yet have a recovered
workspace contract.

## Evidence-backed contract

The public surface combines eight independently verified packets:

| Packet | Implemented behavior |
| --- | --- |
| `RE-004-qty-newtype-sign-guards-94` | Nonnegative i64 admission for `Notional`, `BigNotional`, and `Size`; u64-to-i64 range checks for `SignedNotional` and `SignedSize` |
| `RE-004-wei-saturating-ops-94` | `Wei` addition saturates at `u64::MAX`; subtraction saturates at zero |
| `RE-004-sz-saturating-sites-94` | Unsigned `Size` and signed `SignedSize` add/subtract with boundary saturation |
| `RE-004-spot-wei-scale-family-94` | Checked `10^k` for `k = 0..=19`, decimal subtraction, checked size-to-wei multiplication, floor and exact wei-to-size division |
| `RE-004-spot-token-decimals-94` | Separate general-range (`sz <= wei <= 10`) and deploy (`sz <= 5`, then `wei >= sz + 5`) validators with preserved guard order |
| `RE-004-spot-wire-scale-94` | Eight-decimal wire price/size conversion with exact divisibility, nonzero price, and zero-size behavior |
| `RE-004-px-tick-ladder-94` | Five-significant-digit tick ladder, perp and spot caps, divisibility, floor, and always-advance next-tick rounding |
| `RE-004-evm-amount-scale-94` | Four-limb U256 division/multiplication for exponents `-19..=19` and the strict internal amount cap |

Every saturating operation returns both its value and
`ArithmeticStatus::{Exact, Overflow, Underflow}`. Operations that the target
rejects or reaches through a panic path instead return typed errors. The
library does not intentionally panic for input-domain failures.

## Conversion rules

For a base token with `b` size decimals and a quote token with `q` wei
decimals, `TokenDecimals` exposes the independently observed general-range and
deploy validators. They are not implicitly combined because the evidence does
not establish that one request traverses both paths. Scaling uses `10^(q-b)`.
A borrow (`q < b`), an exponent above 19, or a u64 multiplication overflow is
rejected. The API keeps flooring and exact wei-to-size conversion distinct so
a caller cannot silently choose one policy for the other.

Spot wire values have eight decimals. A price uses `k = q-b` raw decimals and
must be a nonzero exact multiple of `10^(8-k)` with `0 <= k <= 8`. A size must
be an exact multiple of `10^(8-b)` with `0 <= b <= 8`; zero size is admitted.
Neither operation rounds.

The significant-price tick is:

```text
10^max(0, decimal_digits(raw_price) - 5)
```

Perpetual ticks require size decimals `0..=6` and cap that result at
`10^(6-size_decimals)`. Ordinary spot ticks cap it at `10^(q-b)`; the verified
fixed branch returns 1000. Price divisibility is exact. Floor rounding clamps a
zero result to one, while next-tick rounding advances even an exact multiple
and saturates at `u64::MAX`.

EVM conversion accepts a U256 as four little-endian u64 limbs. A nonnegative
exponent divides by `10^e` and discards the remainder. A negative exponent
performs checked 256-bit multiplication by `10^abs(e)`. The result must fit in
one limb and be strictly less than `922337203685477580`.

## Validation

The unit tests exercise each API invariant. `tests/evidence_vectors.rs`
separately transcribes packet tables and boundaries, including all 20 admitted
u64 powers of ten, all 16 tick intervals, every admitted spot wire decimal
case, every perp cap, and all 39 supported EVM exponents. This separation keeps
the main regression oracle independent of the implementation's internal test
helpers.

Build and verify with the repository-pinned toolchain:

```sh
cargo build --locked --manifest-path src/node94-fixed-point/Cargo.toml
cargo build --release --locked --manifest-path src/node94-fixed-point/Cargo.toml
cargo test --locked --manifest-path src/node94-fixed-point/Cargo.toml
cargo clippy --locked --manifest-path src/node94-fixed-point/Cargo.toml \
  --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-fixed-point/Cargo.toml -- --check
```

Before interpreting the Rust tests, authenticate the target and regenerate the
source packets with the repository verification and reproduction commands.

## Deliberate limits

This component does not implement order books, notional ratio helpers, fee
calculation, asset lookup, serialization, wire string parsing, caller-specific
status words, or target panic payloads. It does not claim source identity,
binary identity, a recovered root workspace, or complete RE-004 coverage. The
fixed spot-tick selector is a caller-supplied boolean because the upstream
predicate behind that selector is outside the retained packet.

The deploy decimal guard's surrounding metadata-presence gate is also left to
the caller: the packet proves the predicate when reached but does not resolve
when that outer gate skips it.

The raw `BigNotional` storage type provides a stable wide wrapper, but only its
i64 nonnegative admission rule is claimed from the sign-guard packet. Likewise,
`InternalAmount` names the U256 helper's bounded result without asserting which
higher-level balance type owns every caller.

No completion gate in `research/progress.json` is advanced by this component.
