use core::fmt;

use crate::{Size, Wei};

/// Decimal-scale failures established by the spot quantity family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScaleError {
    WeiDecimalsBelowSize { wei_decimals: u8, size_decimals: u8 },
    ExponentOutOfRange { exponent: u8 },
    MultiplicationOverflow,
    InexactDivision { remainder: u64 },
}

impl fmt::Display for ScaleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeiDecimalsBelowSize {
                wei_decimals,
                size_decimals,
            } => write!(
                formatter,
                "wei decimals {wei_decimals} are below size decimals {size_decimals}"
            ),
            Self::ExponentOutOfRange { exponent } => {
                write!(formatter, "decimal exponent {exponent} does not fit u64")
            }
            Self::MultiplicationOverflow => {
                formatter.write_str("scaled quantity exceeds the u64 range")
            }
            Self::InexactDivision { remainder } => {
                write!(
                    formatter,
                    "quantity is not exactly divisible; remainder {remainder}"
                )
            }
        }
    }
}

impl std::error::Error for ScaleError {}

/// Computes 10^exponent when the result fits in u64.
pub const fn checked_pow10(exponent: u8) -> Result<u64, ScaleError> {
    if exponent > 19 {
        return Err(ScaleError::ExponentOutOfRange { exponent });
    }

    let mut value = 1_u64;
    let mut index = 0_u8;
    while index < exponent {
        value *= 10;
        index += 1;
    }
    Ok(value)
}

/// Base size and quote wei decimal metadata for one spot pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenDecimals {
    pub size_decimals: u8,
    pub wei_decimals: u8,
}

impl TokenDecimals {
    #[must_use]
    pub const fn new(size_decimals: u8, wei_decimals: u8) -> Self {
        Self {
            size_decimals,
            wei_decimals,
        }
    }

    /// Returns 10^(wei_decimals - size_decimals), or an explicit rejection.
    pub const fn scale_factor(self) -> Result<u64, ScaleError> {
        let Some(exponent) = self.wei_decimals.checked_sub(self.size_decimals) else {
            return Err(ScaleError::WeiDecimalsBelowSize {
                wei_decimals: self.wei_decimals,
                size_decimals: self.size_decimals,
            });
        };
        checked_pow10(exponent)
    }

    /// Converts raw size units to raw wei units without saturation.
    pub fn size_to_wei(self, size: Size) -> Result<Wei, ScaleError> {
        let factor = self.scale_factor()?;
        match size.raw().checked_mul(factor) {
            Some(value) => Ok(Wei::from_raw(value)),
            None => Err(ScaleError::MultiplicationOverflow),
        }
    }

    /// Floors raw wei units to the corresponding raw size units.
    pub fn wei_to_size_floor(self, wei: Wei) -> Result<Size, ScaleError> {
        let factor = self.scale_factor()?;
        Ok(Size::from_raw(wei.raw() / factor))
    }

    /// Converts only when no raw wei units would be discarded.
    pub fn wei_to_size_exact(self, wei: Wei) -> Result<Size, ScaleError> {
        let factor = self.scale_factor()?;
        let remainder = wei.raw() % factor;
        if remainder != 0 {
            return Err(ScaleError::InexactDivision { remainder });
        }
        Ok(Size::from_raw(wei.raw() / factor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powers_of_ten_cover_the_complete_u64_range() {
        assert_eq!(checked_pow10(0), Ok(1));
        assert_eq!(checked_pow10(8), Ok(100_000_000));
        assert_eq!(checked_pow10(19), Ok(10_000_000_000_000_000_000));
        assert_eq!(
            checked_pow10(20),
            Err(ScaleError::ExponentOutOfRange { exponent: 20 })
        );
    }

    #[test]
    fn token_scale_rejects_decimal_subtraction_underflow() {
        assert_eq!(
            TokenDecimals::new(9, 8).scale_factor(),
            Err(ScaleError::WeiDecimalsBelowSize {
                wei_decimals: 8,
                size_decimals: 9,
            })
        );
    }

    #[test]
    fn size_and_wei_conversions_distinguish_floor_from_exact() {
        let decimals = TokenDecimals::new(2, 5);
        assert_eq!(
            decimals.size_to_wei(Size::from_raw(7)),
            Ok(Wei::from_raw(7_000))
        );
        assert_eq!(
            decimals.wei_to_size_floor(Wei::from_raw(7_999)),
            Ok(Size::from_raw(7))
        );
        assert_eq!(
            decimals.wei_to_size_exact(Wei::from_raw(7_999)),
            Err(ScaleError::InexactDivision { remainder: 999 })
        );
        assert_eq!(
            decimals.wei_to_size_exact(Wei::from_raw(8_000)),
            Ok(Size::from_raw(8))
        );
    }

    #[test]
    fn size_to_wei_reports_overflow_instead_of_saturating() {
        assert_eq!(
            TokenDecimals::new(0, 1).size_to_wei(Size::from_raw(u64::MAX)),
            Err(ScaleError::MultiplicationOverflow)
        );
    }
}
