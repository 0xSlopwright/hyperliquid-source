use core::fmt;

use crate::{
    MarginTable, MarginTier, RequirementError, initial_requirement, maintenance_requirement,
    select_tier,
};

/// The accounting branch selected by the position record's byte at offset zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingMode {
    Cross,
    Isolated,
}

impl AccountingMode {
    /// The target treats zero as cross and every nonzero byte as isolated.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        if raw == 0 {
            Self::Cross
        } else {
            Self::Isolated
        }
    }
}

/// The five entries established for the target's byte-indexed jump table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MarginMode {
    Zero = 0,
    PositionDivisor = 1,
    TieredInitial = 2,
    TieredMaintenance = 3,
    CappedPositionDivisor = 4,
}

impl TryFrom<u8> for MarginMode {
    type Error = PositionCalculationError;

    fn try_from(raw: u8) -> Result<Self, Self::Error> {
        match raw {
            0 => Ok(Self::Zero),
            1 => Ok(Self::PositionDivisor),
            2 => Ok(Self::TieredInitial),
            3 => Ok(Self::TieredMaintenance),
            4 => Ok(Self::CappedPositionDivisor),
            _ => Err(PositionCalculationError::UnsupportedMode { raw }),
        }
    }
}

/// The fields proved to be consumed from the bounded position record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositionInput {
    /// Raw byte at record offset `+0x00`: zero is cross, nonzero is isolated.
    pub accounting: AccountingMode,
    /// Unsigned divisor at record offset `+0x04`, used by modes 1 and 4.
    pub leverage_divisor: u32,
    /// Signed isolated margin at record offset `+0x08`.
    pub margin: i64,
    /// Signed position size at record offset `+0x10`.
    pub size: i64,
    /// Selector at record offset `+0x38`, used by modes 2 and 3.
    pub tier_selector: u32,
}

/// The two established output layouts, represented without speculative fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionMargin {
    Cross {
        signed_notional: i64,
        effective_margin: u64,
        absolute_notional: u64,
    },
    Isolated {
        margin_after: i64,
        effective_margin: u64,
        absolute_notional: u64,
        previous_margin: i64,
        computed_requirement: u64,
    },
}

impl PositionMargin {
    #[must_use]
    pub const fn absolute_notional(self) -> u64 {
        match self {
            Self::Cross {
                absolute_notional, ..
            }
            | Self::Isolated {
                absolute_notional, ..
            } => absolute_notional,
        }
    }

    #[must_use]
    pub const fn computed_requirement(self) -> u64 {
        match self {
            Self::Cross {
                effective_margin, ..
            } => effective_margin,
            Self::Isolated {
                computed_requirement,
                ..
            } => computed_requirement,
        }
    }
}

/// A verified rejection, arithmetic fault, or unresolved external lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionCalculationError {
    UnsupportedMode { raw: u8 },
    NegativePrice { price: i64 },
    SignedNotionalOverflow { size: i64, price: i64 },
    ZeroPositionDivisor { mode: MarginMode },
    MissingCustomMarginTable { selector: u32 },
    Requirement(RequirementError),
}

impl fmt::Display for PositionCalculationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMode { raw } => {
                write!(formatter, "raw margin mode {raw} is outside 0 through 4")
            }
            Self::NegativePrice { price } => write!(formatter, "raw price {price} is negative"),
            Self::SignedNotionalOverflow { size, price } => {
                write!(formatter, "signed notional overflows: {size} * {price}")
            }
            Self::ZeroPositionDivisor { mode } => {
                write!(formatter, "mode {} reaches a zero divisor", *mode as u8)
            }
            Self::MissingCustomMarginTable { selector } => write!(
                formatter,
                "tier selector {selector} requires an externally resolved custom margin table"
            ),
            Self::Requirement(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PositionCalculationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Requirement(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RequirementError> for PositionCalculationError {
    fn from(error: RequirementError) -> Self {
        Self::Requirement(error)
    }
}

fn tier_requirement(
    input: PositionInput,
    notional: u64,
    mode: MarginMode,
    custom_margin_table: Option<&MarginTable>,
) -> Result<u64, PositionCalculationError> {
    let tier = if input.tier_selector < 50 {
        MarginTier::new(0, 0, input.tier_selector as u8)
    } else {
        let table =
            custom_margin_table.ok_or(PositionCalculationError::MissingCustomMarginTable {
                selector: input.tier_selector,
            })?;
        *select_tier(table, notional)
    };

    match mode {
        MarginMode::TieredInitial => Ok(initial_requirement(notional, tier)?),
        MarginMode::TieredMaintenance => Ok(maintenance_requirement(notional, tier)?),
        _ => unreachable!("tier_requirement is called only for modes 2 and 3"),
    }
}

/// Calculate the bounded position-margin output established at `0x3717480`.
///
/// `custom_margin_table` represents the already-resolved external lookup used
/// only when a mode-2/3 selector is at least 50. This crate does not invent the
/// surrounding state map. `cap` is consumed only by mode 4.
pub fn calculate_position_margin(
    input: PositionInput,
    price: i64,
    raw_mode: u8,
    cap: u8,
    custom_margin_table: Option<&MarginTable>,
) -> Result<PositionMargin, PositionCalculationError> {
    if price < 0 {
        return Err(PositionCalculationError::NegativePrice { price });
    }
    let signed_notional =
        input
            .size
            .checked_mul(price)
            .ok_or(PositionCalculationError::SignedNotionalOverflow {
                size: input.size,
                price,
            })?;
    let absolute_notional = signed_notional.unsigned_abs();
    let mode = MarginMode::try_from(raw_mode)?;

    let requirement = match mode {
        MarginMode::Zero => 0,
        MarginMode::PositionDivisor => {
            let divisor = u64::from(input.leverage_divisor);
            if divisor == 0 {
                return Err(PositionCalculationError::ZeroPositionDivisor { mode });
            }
            absolute_notional / divisor
        }
        MarginMode::TieredInitial | MarginMode::TieredMaintenance => {
            tier_requirement(input, absolute_notional, mode, custom_margin_table)?
        }
        MarginMode::CappedPositionDivisor => {
            let divisor = u64::from(input.leverage_divisor.min(u32::from(cap)));
            if divisor == 0 {
                return Err(PositionCalculationError::ZeroPositionDivisor { mode });
            }
            absolute_notional / divisor
        }
    };

    Ok(match input.accounting {
        AccountingMode::Cross => PositionMargin::Cross {
            signed_notional,
            effective_margin: requirement,
            absolute_notional,
        },
        AccountingMode::Isolated => {
            let margin_after = input.margin.saturating_add(signed_notional);
            PositionMargin::Isolated {
                margin_after,
                effective_margin: margin_after.max(0) as u64,
                absolute_notional,
                previous_margin: input.margin,
                computed_requirement: requirement,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawMarginTable, RawMarginTier};

    fn table() -> MarginTable {
        MarginTable::try_from(RawMarginTable {
            description: "fixture".to_owned(),
            tiers: vec![
                RawMarginTier {
                    lower_bound: 0,
                    max_leverage: 50,
                },
                RawMarginTier {
                    lower_bound: 1_000,
                    max_leverage: 20,
                },
                RawMarginTier {
                    lower_bound: 1_000_000,
                    max_leverage: 10,
                },
            ],
        })
        .unwrap()
    }

    fn cross() -> PositionInput {
        PositionInput {
            accounting: AccountingMode::Cross,
            leverage_divisor: 20,
            margin: 0,
            size: 100,
            tier_selector: 50,
        }
    }

    #[test]
    fn all_five_raw_modes_match_established_requirements() {
        let table = table();
        for (mode, cap, expected) in [(0, 0, 0), (1, 0, 50), (2, 0, 10), (3, 0, 6), (4, 8, 125)] {
            let result = calculate_position_margin(cross(), 10, mode, cap, Some(&table)).unwrap();
            assert_eq!(result.computed_requirement(), expected, "mode {mode}");
        }
    }

    #[test]
    fn negative_price_precedes_multiplication_and_mode_dispatch() {
        let mut input = cross();
        input.size = i64::MAX;
        assert_eq!(
            calculate_position_margin(input, -1, 255, 0, None),
            Err(PositionCalculationError::NegativePrice { price: -1 })
        );
    }

    #[test]
    fn signed_multiply_is_checked_and_i64_minimum_has_unsigned_magnitude() {
        let mut input = cross();
        input.size = i64::MAX;
        assert_eq!(
            calculate_position_margin(input, 2, 0, 0, None),
            Err(PositionCalculationError::SignedNotionalOverflow {
                size: i64::MAX,
                price: 2,
            })
        );

        input.size = i64::MIN;
        let result = calculate_position_margin(input, 1, 0, 0, None).unwrap();
        assert_eq!(result.absolute_notional(), 1_u64 << 63);
        assert_eq!(
            result,
            PositionMargin::Cross {
                signed_notional: i64::MIN,
                effective_margin: 0,
                absolute_notional: 1_u64 << 63,
            }
        );
    }

    #[test]
    fn unsupported_mode_is_explicit_after_notional_calculation() {
        assert_eq!(
            calculate_position_margin(cross(), 1, 5, 0, None),
            Err(PositionCalculationError::UnsupportedMode { raw: 5 })
        );
        assert_eq!(
            calculate_position_margin(cross(), 1, u8::MAX, 0, None),
            Err(PositionCalculationError::UnsupportedMode { raw: u8::MAX })
        );
    }

    #[test]
    fn direct_and_capped_zero_divisors_are_not_normalized() {
        let mut input = cross();
        input.leverage_divisor = 0;
        assert_eq!(
            calculate_position_margin(input, 1, 1, 50, None),
            Err(PositionCalculationError::ZeroPositionDivisor {
                mode: MarginMode::PositionDivisor,
            })
        );
        input.leverage_divisor = 20;
        assert_eq!(
            calculate_position_margin(input, 1, 4, 0, None),
            Err(PositionCalculationError::ZeroPositionDivisor {
                mode: MarginMode::CappedPositionDivisor,
            })
        );
    }

    #[test]
    fn selector_below_fifty_builds_a_single_tier() {
        let mut input = cross();
        input.tier_selector = 20;
        assert_eq!(
            calculate_position_margin(input, 10, 2, 0, None)
                .unwrap()
                .computed_requirement(),
            25
        );
        assert_eq!(
            calculate_position_margin(input, 10, 3, 0, None)
                .unwrap()
                .computed_requirement(),
            16
        );
    }

    #[test]
    fn selector_zero_reaches_requirement_fault_and_fifty_needs_lookup() {
        let mut input = cross();
        input.tier_selector = 0;
        assert_eq!(
            calculate_position_margin(input, 1, 2, 0, None),
            Err(PositionCalculationError::Requirement(
                RequirementError::ZeroLeverage {
                    tier_lower_bound: 0,
                }
            ))
        );

        input.tier_selector = 50;
        assert_eq!(
            calculate_position_margin(input, 1, 3, 0, None),
            Err(PositionCalculationError::MissingCustomMarginTable { selector: 50 })
        );
    }

    #[test]
    fn cross_and_isolated_outputs_match_established_fixture() {
        let table = table();
        assert_eq!(
            calculate_position_margin(cross(), 10, 3, 0, Some(&table)),
            Ok(PositionMargin::Cross {
                signed_notional: 1_000,
                effective_margin: 6,
                absolute_notional: 1_000,
            })
        );

        let isolated = PositionInput {
            accounting: AccountingMode::from_raw(7),
            leverage_divisor: 20,
            margin: 90,
            size: -100,
            tier_selector: 50,
        };
        assert_eq!(
            calculate_position_margin(isolated, 10, 3, 0, Some(&table)),
            Ok(PositionMargin::Isolated {
                margin_after: -910,
                effective_margin: 0,
                absolute_notional: 1_000,
                previous_margin: 90,
                computed_requirement: 6,
            })
        );
    }

    #[test]
    fn isolated_margin_addition_saturates() {
        let input = PositionInput {
            accounting: AccountingMode::Isolated,
            leverage_divisor: 1,
            margin: i64::MAX,
            size: 1,
            tier_selector: 1,
        };
        assert_eq!(
            calculate_position_margin(input, 1, 0, 0, None),
            Ok(PositionMargin::Isolated {
                margin_after: i64::MAX,
                effective_margin: i64::MAX as u64,
                absolute_notional: 1,
                previous_margin: i64::MAX,
                computed_requirement: 0,
            })
        );
    }
}
