use core::fmt;

use crate::{Price, ScaleError, Size, checked_pow10};

const WIRE_DECIMALS: u8 = 8;

/// Fail-closed outcomes for the established spot wire conversions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotWireError {
    PriceScaleUnderflow {
        quote_wei_decimals: u8,
        base_size_decimals: u8,
    },
    PriceScaleExceedsWire {
        raw_price_decimals: u8,
    },
    InvalidPrice {
        wire_value: u64,
        divisor: u64,
    },
    SizeScaleExceedsWire {
        base_size_decimals: u8,
    },
    InvalidSize {
        wire_value: u64,
        divisor: u64,
    },
}

impl fmt::Display for SpotWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PriceScaleUnderflow {
                quote_wei_decimals,
                base_size_decimals,
            } => write!(
                formatter,
                "quote wei decimals {quote_wei_decimals} are below base size decimals {base_size_decimals}"
            ),
            Self::PriceScaleExceedsWire { raw_price_decimals } => write!(
                formatter,
                "raw price decimals {raw_price_decimals} exceed the 8-decimal wire scale"
            ),
            Self::InvalidPrice { .. } => formatter.write_str("order has invalid price"),
            Self::SizeScaleExceedsWire { base_size_decimals } => write!(
                formatter,
                "base size decimals {base_size_decimals} exceed the 8-decimal wire scale"
            ),
            Self::InvalidSize { .. } => formatter.write_str("order has invalid size"),
        }
    }
}

impl std::error::Error for SpotWireError {}

/// Converts an eight-decimal spot wire price to its raw pair price.
pub fn parse_spot_wire_price(
    wire_value: u64,
    base_size_decimals: u8,
    quote_wei_decimals: u8,
) -> Result<Price, SpotWireError> {
    let Some(raw_price_decimals) = quote_wei_decimals.checked_sub(base_size_decimals) else {
        return Err(SpotWireError::PriceScaleUnderflow {
            quote_wei_decimals,
            base_size_decimals,
        });
    };
    let Some(divisor_exponent) = WIRE_DECIMALS.checked_sub(raw_price_decimals) else {
        return Err(SpotWireError::PriceScaleExceedsWire { raw_price_decimals });
    };
    let divisor = pow10_wire(divisor_exponent);
    if wire_value < divisor || !wire_value.is_multiple_of(divisor) {
        return Err(SpotWireError::InvalidPrice {
            wire_value,
            divisor,
        });
    }
    Ok(Price::from_raw(wire_value / divisor))
}

/// Converts an eight-decimal spot wire size to raw base size units.
pub fn parse_spot_wire_size(
    wire_value: u64,
    base_size_decimals: u8,
) -> Result<Size, SpotWireError> {
    let Some(divisor_exponent) = WIRE_DECIMALS.checked_sub(base_size_decimals) else {
        return Err(SpotWireError::SizeScaleExceedsWire { base_size_decimals });
    };
    let divisor = pow10_wire(divisor_exponent);
    if !wire_value.is_multiple_of(divisor) {
        return Err(SpotWireError::InvalidSize {
            wire_value,
            divisor,
        });
    }
    Ok(Size::from_raw(wire_value / divisor))
}

fn pow10_wire(exponent: u8) -> u64 {
    match checked_pow10(exponent) {
        Ok(value) => value,
        Err(ScaleError::ExponentOutOfRange { .. }) => unreachable!(),
        Err(_) => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_requires_a_nonzero_exact_wire_multiple() {
        assert_eq!(
            parse_spot_wire_price(100_000, 3, 8),
            Ok(Price::from_raw(100))
        );
        assert_eq!(
            parse_spot_wire_price(100_001, 3, 8),
            Err(SpotWireError::InvalidPrice {
                wire_value: 100_001,
                divisor: 1_000,
            })
        );
        assert_eq!(
            parse_spot_wire_price(0, 8, 8),
            Err(SpotWireError::InvalidPrice {
                wire_value: 0,
                divisor: 100_000_000,
            })
        );
    }

    #[test]
    fn size_accepts_zero_but_still_requires_exact_divisibility() {
        assert_eq!(parse_spot_wire_size(0, 0), Ok(Size::from_raw(0)));
        assert_eq!(parse_spot_wire_size(100, 6), Ok(Size::from_raw(1)));
        assert_eq!(
            parse_spot_wire_size(99, 6),
            Err(SpotWireError::InvalidSize {
                wire_value: 99,
                divisor: 100,
            })
        );
    }

    #[test]
    fn invalid_decimal_relationships_fail_before_conversion() {
        assert_eq!(
            parse_spot_wire_price(1, 9, 8),
            Err(SpotWireError::PriceScaleUnderflow {
                quote_wei_decimals: 8,
                base_size_decimals: 9,
            })
        );
        assert_eq!(
            parse_spot_wire_price(1, 0, 9),
            Err(SpotWireError::PriceScaleExceedsWire {
                raw_price_decimals: 9,
            })
        );
        assert_eq!(
            parse_spot_wire_size(0, 9),
            Err(SpotWireError::SizeScaleExceedsWire {
                base_size_decimals: 9,
            })
        );
    }
}
