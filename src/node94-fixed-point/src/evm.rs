use core::fmt;

use crate::{InternalAmount, checked_pow10};

/// Node #94 admits only results strictly below this value.
pub const INTERNAL_AMOUNT_EXCLUSIVE_MAX: u64 = 922_337_203_685_477_580;

/// A dependency-free 256-bit unsigned integer stored as little-endian limbs.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct U256 {
    limbs: [u64; 4],
}

impl U256 {
    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self::from_limbs([value, 0, 0, 0])
    }

    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self::from_limbs([value as u64, (value >> 64) as u64, 0, 0])
    }

    #[must_use]
    pub const fn limbs(self) -> [u64; 4] {
        self.limbs
    }

    fn checked_mul_u64(self, multiplier: u64) -> Option<Self> {
        let mut product = [0_u64; 4];
        let mut carry = 0_u128;
        let mut index = 0;
        while index < product.len() {
            let wide = u128::from(self.limbs[index]) * u128::from(multiplier) + carry;
            product[index] = wide as u64;
            carry = wide >> 64;
            index += 1;
        }
        if carry == 0 {
            Some(Self::from_limbs(product))
        } else {
            None
        }
    }

    fn div_u64(self, divisor: u64) -> (Self, u64) {
        debug_assert_ne!(divisor, 0);
        let mut quotient = [0_u64; 4];
        let mut remainder = 0_u128;
        let mut index = quotient.len();
        while index > 0 {
            index -= 1;
            let dividend = (remainder << 64) | u128::from(self.limbs[index]);
            quotient[index] = (dividend / u128::from(divisor)) as u64;
            remainder = dividend % u128::from(divisor);
        }
        (Self::from_limbs(quotient), remainder as u64)
    }

    const fn admitted_low_limb(self) -> Option<u64> {
        if self.limbs[1] != 0 || self.limbs[2] != 0 || self.limbs[3] != 0 {
            return None;
        }
        let value = self.limbs[0];
        if value < INTERNAL_AMOUNT_EXCLUSIVE_MAX {
            Some(value)
        } else {
            None
        }
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

/// Explicit rejection paths for the established EVM amount scaling helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmAmountError {
    ExponentOutOfRange { exponent: i8 },
    MultiplicationOverflow,
    InternalAmountOutOfRange,
}

impl fmt::Display for EvmAmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExponentOutOfRange { exponent } => write!(
                formatter,
                "EVM amount exponent {exponent} is outside the established range -19..=19"
            ),
            Self::MultiplicationOverflow => {
                formatter.write_str("scaled EVM amount exceeds the U256 range")
            }
            Self::InternalAmountOutOfRange => formatter
                .write_str("scaled EVM amount is outside the established internal amount range"),
        }
    }
}

impl std::error::Error for EvmAmountError {}

/// Scales an EVM U256 amount into the bounded internal u64 amount.
///
/// Nonnegative exponents divide and discard the remainder. Negative
/// exponents multiply with checked U256 arithmetic. Both paths then require
/// a result strictly below [`INTERNAL_AMOUNT_EXCLUSIVE_MAX`].
pub fn evm_amount_to_internal(
    amount: U256,
    exponent: i8,
) -> Result<InternalAmount, EvmAmountError> {
    let magnitude = exponent.unsigned_abs();
    let scale =
        checked_pow10(magnitude).map_err(|_| EvmAmountError::ExponentOutOfRange { exponent })?;
    let scaled = if exponent >= 0 {
        amount.div_u64(scale).0
    } else {
        amount
            .checked_mul_u64(scale)
            .ok_or(EvmAmountError::MultiplicationOverflow)?
    };
    scaled
        .admitted_low_limb()
        .map(InternalAmount::from_raw)
        .ok_or(EvmAmountError::InternalAmountOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonnegative_exponents_floor_the_u256_quotient() {
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(1_234), 2),
            Ok(InternalAmount::from_raw(12))
        );
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(99), 2),
            Ok(InternalAmount::from_raw(0))
        );
    }

    #[test]
    fn negative_exponents_multiply_with_checked_u256_arithmetic() {
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(7), -2),
            Ok(InternalAmount::from_raw(700))
        );
        assert_eq!(
            evm_amount_to_internal(U256::from_limbs([u64::MAX; 4]), -1),
            Err(EvmAmountError::MultiplicationOverflow)
        );
    }

    #[test]
    fn result_cap_is_strict_on_both_sides_of_the_boundary() {
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1), 0),
            Ok(InternalAmount::from_raw(INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1))
        );
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(INTERNAL_AMOUNT_EXCLUSIVE_MAX), 0),
            Err(EvmAmountError::InternalAmountOutOfRange)
        );
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(1), -19),
            Err(EvmAmountError::InternalAmountOutOfRange)
        );
    }

    #[test]
    fn exponent_domain_is_exact_and_handles_i8_min() {
        for exponent in [-128, -20, 20, 127] {
            assert_eq!(
                evm_amount_to_internal(U256::from_u64(0), exponent),
                Err(EvmAmountError::ExponentOutOfRange { exponent })
            );
        }
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(0), -19),
            Ok(InternalAmount::from_raw(0))
        );
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(0), 19),
            Ok(InternalAmount::from_raw(0))
        );
    }

    #[test]
    fn positive_exponent_boundary_uses_all_256_input_bits() {
        let scale = 10_000_000_000_000_000_000_u128;
        let largest = u128::from(INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1) * scale + scale - 1;
        assert_eq!(
            evm_amount_to_internal(U256::from_u128(largest), 19),
            Ok(InternalAmount::from_raw(INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1))
        );
        let first_rejected = u128::from(INTERNAL_AMOUNT_EXCLUSIVE_MAX) * scale;
        assert_eq!(
            evm_amount_to_internal(U256::from_u128(first_rejected), 19),
            Err(EvmAmountError::InternalAmountOutOfRange)
        );
    }
}
