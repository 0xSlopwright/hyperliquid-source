use core::fmt;

use crate::{Price, checked_pow10};

const MAX_SIGNIFICANT_TICK: u64 = 1_000_000_000_000_000;
const FIXED_SPOT_TICK: u64 = 1_000;

/// A nonzero raw price tick.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tick(u64);

impl Tick {
    /// Creates a tick while rejecting the invalid zero divisor.
    pub const fn new(raw: u64) -> Result<Self, TickError> {
        if raw == 0 {
            Err(TickError::ZeroTick)
        } else {
            Ok(Self(raw))
        }
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    const fn established(raw: u64) -> Self {
        debug_assert!(raw != 0);
        Self(raw)
    }
}

/// Rejections associated with tick selection and validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickError {
    ZeroTick,
    PerpSizeDecimalsOutOfRange {
        size_decimals: u8,
    },
    SpotDecimalUnderflow {
        quote_wei_decimals: u8,
        base_size_decimals: u8,
    },
    PriceNotDivisible {
        price: Price,
        tick: Tick,
    },
}

impl fmt::Display for TickError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTick => formatter.write_str("tick must be nonzero"),
            Self::PerpSizeDecimalsOutOfRange { size_decimals } => write!(
                formatter,
                "perpetual size decimals {size_decimals} exceed the established range 0..=6"
            ),
            Self::SpotDecimalUnderflow {
                quote_wei_decimals,
                base_size_decimals,
            } => write!(
                formatter,
                "quote wei decimals {quote_wei_decimals} are below base size decimals {base_size_decimals}"
            ),
            Self::PriceNotDivisible { .. } => {
                formatter.write_str("price must be divisible by tick size")
            }
        }
    }
}

impl std::error::Error for TickError {}

/// Returns 10^max(0, digits(price) - 5) for every raw u64 price.
#[must_use]
pub fn significant_tick(price: Price) -> Tick {
    let mut digits = 1_u8;
    let mut remaining = price.raw();
    while remaining >= 10 {
        remaining /= 10;
        digits += 1;
    }
    let exponent = digits.saturating_sub(5);
    let raw = checked_pow10(exponent).expect("a u64 price produces a tick exponent at most 15");
    debug_assert!(raw <= MAX_SIGNIFICANT_TICK);
    Tick::established(raw)
}

/// Applies the node #94 perpetual tick cap for size decimals 0..=6.
pub fn perp_tick(price: Price, size_decimals: u8) -> Result<Tick, TickError> {
    let Some(exponent) = 6_u8.checked_sub(size_decimals) else {
        return Err(TickError::PerpSizeDecimalsOutOfRange { size_decimals });
    };
    let cap = checked_pow10(exponent).expect("perpetual tick exponent is at most 6");
    Ok(Tick::established(significant_tick(price).raw().min(cap)))
}

/// Applies the node #94 spot tick rule.
///
/// The fixed-tick branch ignores the price and decimal metadata. Otherwise
/// the tick is capped by 10^(quote wei decimals - base size decimals).
pub fn spot_tick(
    price: Price,
    base_size_decimals: u8,
    quote_wei_decimals: u8,
    fixed_tick: bool,
) -> Result<Tick, TickError> {
    if fixed_tick {
        return Ok(Tick::established(FIXED_SPOT_TICK));
    }

    let Some(exponent) = quote_wei_decimals.checked_sub(base_size_decimals) else {
        return Err(TickError::SpotDecimalUnderflow {
            quote_wei_decimals,
            base_size_decimals,
        });
    };
    let significant = significant_tick(price);
    if exponent >= 20 {
        return Ok(significant);
    }
    let cap = checked_pow10(exponent).expect("spot exponent below 20 fits u64");
    Ok(Tick::established(significant.raw().min(cap)))
}

/// Returns whether a price is an exact multiple of its tick.
#[must_use]
pub const fn is_tick_divisible(price: Price, tick: Tick) -> bool {
    price.raw().is_multiple_of(tick.raw())
}

/// Rejects a price that is not an exact multiple of its tick.
pub const fn require_tick_divisible(price: Price, tick: Tick) -> Result<(), TickError> {
    if is_tick_divisible(price, tick) {
        Ok(())
    } else {
        Err(TickError::PriceNotDivisible { price, tick })
    }
}

/// Floors to a tick and clamps the zero result to one raw price unit.
#[must_use]
pub fn round_down_to_tick(price: Price, tick: Tick) -> Price {
    let quotient = price.raw() / tick.raw();
    Price::from_raw(quotient.saturating_mul(tick.raw()).max(1))
}

/// Advances to the next tick, even from an exact multiple, with u64 saturation.
#[must_use]
pub fn next_tick(price: Price, tick: Tick) -> Price {
    let quotient = price.raw() / tick.raw();
    Price::from_raw(quotient.saturating_add(1).saturating_mul(tick.raw()).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn significant_tick_changes_at_each_decimal_boundary() {
        let cases = [
            (0, 1),
            (99_999, 1),
            (100_000, 10),
            (999_999, 10),
            (1_000_000, 100),
            (99_999_999_999, 1_000_000),
            (100_000_000_000, 10_000_000),
            (9_999_999_999_999_999_999, 100_000_000_000_000),
            (10_000_000_000_000_000_000, MAX_SIGNIFICANT_TICK),
            (u64::MAX, MAX_SIGNIFICANT_TICK),
        ];
        for (price, expected) in cases {
            assert_eq!(significant_tick(Price::from_raw(price)).raw(), expected);
        }
    }

    #[test]
    fn perpetual_tick_caps_and_rejects_unestablished_decimals() {
        let price = Price::from_raw(u64::MAX);
        for (size_decimals, expected) in [
            (0, 1_000_000),
            (1, 100_000),
            (2, 10_000),
            (3, 1_000),
            (4, 100),
            (5, 10),
            (6, 1),
        ] {
            assert_eq!(perp_tick(price, size_decimals).map(Tick::raw), Ok(expected));
        }
        assert_eq!(
            perp_tick(price, 7),
            Err(TickError::PerpSizeDecimalsOutOfRange { size_decimals: 7 })
        );
    }

    #[test]
    fn spot_tick_handles_fixed_branch_caps_and_underflow() {
        let price = Price::from_raw(u64::MAX);
        assert_eq!(spot_tick(price, 255, 0, true).map(Tick::raw), Ok(1_000));
        assert_eq!(spot_tick(price, 8, 8, false).map(Tick::raw), Ok(1));
        assert_eq!(
            spot_tick(price, 0, 15, false).map(Tick::raw),
            Ok(MAX_SIGNIFICANT_TICK)
        );
        assert_eq!(
            spot_tick(price, 0, 255, false).map(Tick::raw),
            Ok(MAX_SIGNIFICANT_TICK)
        );
        assert_eq!(
            spot_tick(price, 9, 8, false),
            Err(TickError::SpotDecimalUnderflow {
                quote_wei_decimals: 8,
                base_size_decimals: 9,
            })
        );
    }

    #[test]
    fn divisibility_is_exact_and_zero_tick_is_unrepresentable() {
        let tick = Tick::new(10).unwrap();
        assert_eq!(require_tick_divisible(Price::from_raw(1_000), tick), Ok(()));
        assert_eq!(
            require_tick_divisible(Price::from_raw(1_005), tick),
            Err(TickError::PriceNotDivisible {
                price: Price::from_raw(1_005),
                tick,
            })
        );
        assert_eq!(Tick::new(0), Err(TickError::ZeroTick));
    }

    #[test]
    fn rounding_matches_observed_next_and_floor_tails() {
        let tick = Tick::new(10).unwrap();
        assert_eq!(
            round_down_to_tick(Price::from_raw(1_005), tick),
            Price::from_raw(1_000)
        );
        assert_eq!(
            next_tick(Price::from_raw(1_005), tick),
            Price::from_raw(1_010)
        );
        assert_eq!(
            next_tick(Price::from_raw(1_000), tick),
            Price::from_raw(1_010)
        );
        assert_eq!(
            round_down_to_tick(Price::from_raw(0), tick),
            Price::from_raw(1)
        );
        assert_eq!(next_tick(Price::from_raw(0), tick), Price::from_raw(10));
        let unit = Tick::new(1).unwrap();
        assert_eq!(
            next_tick(Price::from_raw(u64::MAX), unit),
            Price::from_raw(u64::MAX)
        );
    }
}
