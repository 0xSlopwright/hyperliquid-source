use core::fmt;

use crate::types::{
    LATER_TIER_LOWER_INCLUSIVE_MAX, MAX_DESCRIPTION_BYTES, MAX_LEVERAGE, MAX_TIERS, MarginTable,
    MarginTier, RawMarginTable, WIRE_NOTIONAL_EXCLUSIVE_MAX,
};

/// A returned rejection or an arithmetic fault reached during tier construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TierConstructionError {
    DescriptionTooLong {
        bytes: usize,
    },
    TooManyTiers {
        count: usize,
    },
    EmptyTiers,
    WireNotionalTooLarge {
        index: usize,
        lower_bound: u64,
    },
    FirstLowerBoundNotZero {
        lower_bound: u64,
    },
    MaxLeverageTooLarge {
        index: usize,
        max_leverage: u8,
    },
    LaterLowerBoundTooLarge {
        index: usize,
        lower_bound: u64,
    },
    LeverageNotStrictlyDecreasing {
        index: usize,
        previous: u8,
        current: u8,
    },
    /// The target performs unsigned division here without a visible zero guard.
    ZeroDivisorReached {
        index: usize,
        previous_leverage: u8,
        current_leverage: u8,
    },
    LowerBoundNotStrictlyIncreasing {
        index: usize,
        previous: u64,
        current: u64,
    },
}

impl fmt::Display for TierConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptionTooLong { bytes } => {
                write!(formatter, "description has {bytes} bytes; maximum is 250")
            }
            Self::TooManyTiers { count } => {
                write!(formatter, "margin table has {count} tiers; maximum is 3")
            }
            Self::EmptyTiers => formatter.write_str("empty tiers"),
            Self::WireNotionalTooLarge { index, lower_bound } => write!(
                formatter,
                "tier {index} lower bound {lower_bound} is outside the verified wire range"
            ),
            Self::FirstLowerBoundNotZero { lower_bound } => {
                write!(formatter, "first lower bound is {lower_bound}, not zero")
            }
            Self::MaxLeverageTooLarge {
                index,
                max_leverage,
            } => write!(
                formatter,
                "tier {index} maximum leverage {max_leverage} exceeds 50"
            ),
            Self::LaterLowerBoundTooLarge { index, lower_bound } => write!(
                formatter,
                "tier {index} lower bound {lower_bound} exceeds 1000000000000000"
            ),
            Self::LeverageNotStrictlyDecreasing {
                index,
                previous,
                current,
            } => write!(
                formatter,
                "tier {index} leverage {current} does not decrease from {previous}"
            ),
            Self::ZeroDivisorReached {
                index,
                previous_leverage,
                current_leverage,
            } => write!(
                formatter,
                "tier {index} construction reaches a zero divisor with leverages {previous_leverage} and {current_leverage}"
            ),
            Self::LowerBoundNotStrictlyIncreasing {
                index,
                previous,
                current,
            } => write!(
                formatter,
                "tier {index} lower bound {current} does not increase from {previous}"
            ),
        }
    }
}

impl std::error::Error for TierConstructionError {}

fn admit_later_lower(index: usize, lower_bound: u64) -> Result<(), TierConstructionError> {
    if lower_bound >= WIRE_NOTIONAL_EXCLUSIVE_MAX {
        return Err(TierConstructionError::WireNotionalTooLarge { index, lower_bound });
    }
    if lower_bound > LATER_TIER_LOWER_INCLUSIVE_MAX {
        return Err(TierConstructionError::LaterLowerBoundTooLarge { index, lower_bound });
    }
    Ok(())
}

impl TryFrom<RawMarginTable> for MarginTable {
    type Error = TierConstructionError;

    fn try_from(raw: RawMarginTable) -> Result<Self, Self::Error> {
        let description_bytes = raw.description.len();
        if description_bytes > MAX_DESCRIPTION_BYTES {
            return Err(TierConstructionError::DescriptionTooLong {
                bytes: description_bytes,
            });
        }

        let tier_count = raw.tiers.len();
        if tier_count > MAX_TIERS {
            return Err(TierConstructionError::TooManyTiers { count: tier_count });
        }
        let first = *raw.tiers.first().ok_or(TierConstructionError::EmptyTiers)?;
        if first.lower_bound >= WIRE_NOTIONAL_EXCLUSIVE_MAX {
            return Err(TierConstructionError::WireNotionalTooLarge {
                index: 0,
                lower_bound: first.lower_bound,
            });
        }
        if first.lower_bound != 0 {
            return Err(TierConstructionError::FirstLowerBoundNotZero {
                lower_bound: first.lower_bound,
            });
        }
        if first.max_leverage > MAX_LEVERAGE {
            return Err(TierConstructionError::MaxLeverageTooLarge {
                index: 0,
                max_leverage: first.max_leverage,
            });
        }

        let mut tiers = Vec::with_capacity(tier_count);
        tiers.push(MarginTier::new(0, 0, first.max_leverage));
        if tier_count == 1 {
            return Ok(MarginTable::from_validated_parts(raw.description, tiers));
        }

        // The target prechecks the second lower bound before entering the loop.
        admit_later_lower(1, raw.tiers[1].lower_bound)?;

        let mut previous_lower = first.lower_bound;
        let mut previous_leverage = first.max_leverage;
        let mut prior_contribution = 0_u64;

        for index in 1..tier_count {
            let current = raw.tiers[index];
            if current.max_leverage > MAX_LEVERAGE {
                return Err(TierConstructionError::MaxLeverageTooLarge {
                    index,
                    max_leverage: current.max_leverage,
                });
            }
            if current.max_leverage >= previous_leverage {
                return Err(TierConstructionError::LeverageNotStrictlyDecreasing {
                    index,
                    previous: previous_leverage,
                    current: current.max_leverage,
                });
            }
            if current.max_leverage == 0 || previous_leverage == 0 {
                return Err(TierConstructionError::ZeroDivisorReached {
                    index,
                    previous_leverage,
                    current_leverage: current.max_leverage,
                });
            }

            let current_share = current.lower_bound / (2 * u64::from(current.max_leverage));
            let previous_share = current.lower_bound / (2 * u64::from(previous_leverage));
            prior_contribution = prior_contribution
                .saturating_add(current_share)
                .saturating_sub(previous_share);

            // This precheck happens before the current lower bound ordering test.
            if index + 1 < tier_count {
                admit_later_lower(index + 1, raw.tiers[index + 1].lower_bound)?;
            }
            if previous_lower >= current.lower_bound {
                return Err(TierConstructionError::LowerBoundNotStrictlyIncreasing {
                    index,
                    previous: previous_lower,
                    current: current.lower_bound,
                });
            }

            tiers.push(MarginTier::new(
                current.lower_bound,
                prior_contribution,
                current.max_leverage,
            ));
            previous_lower = current.lower_bound;
            previous_leverage = current.max_leverage;
        }

        Ok(MarginTable::from_validated_parts(raw.description, tiers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawMarginTier;

    fn raw(description: &str, tiers: &[(u64, u8)]) -> RawMarginTable {
        RawMarginTable {
            description: description.to_owned(),
            tiers: tiers
                .iter()
                .map(|&(lower_bound, max_leverage)| RawMarginTier {
                    lower_bound,
                    max_leverage,
                })
                .collect(),
        }
    }

    #[test]
    fn established_fixture_builds_exact_prior_contributions() {
        let table =
            MarginTable::try_from(raw("verified", &[(0, 50), (1_000, 20), (1_000_000, 10)]))
                .unwrap();
        assert_eq!(
            table.tiers(),
            &[
                MarginTier::new(0, 0, 50),
                MarginTier::new(1_000, 15, 20),
                MarginTier::new(1_000_000, 25_015, 10),
            ]
        );
    }

    #[test]
    fn description_precedes_count_and_count_precedes_empty() {
        assert_eq!(
            MarginTable::try_from(raw(&"x".repeat(251), &[(0, 50); 4])),
            Err(TierConstructionError::DescriptionTooLong { bytes: 251 })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 50); 4])),
            Err(TierConstructionError::TooManyTiers { count: 4 })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[])),
            Err(TierConstructionError::EmptyTiers)
        );
    }

    #[test]
    fn next_bound_precheck_precedes_current_ordering() {
        assert_eq!(
            MarginTable::try_from(raw(
                "",
                &[(0, 50), (0, 40), (LATER_TIER_LOWER_INCLUSIVE_MAX + 1, 30)],
            )),
            Err(TierConstructionError::LaterLowerBoundTooLarge {
                index: 2,
                lower_bound: LATER_TIER_LOWER_INCLUSIVE_MAX + 1,
            })
        );
    }

    #[test]
    fn single_zero_leverage_is_admitted_but_later_zero_reaches_division() {
        assert!(MarginTable::try_from(raw("", &[(0, 0)])).is_ok());
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 1), (1, 0)])),
            Err(TierConstructionError::ZeroDivisorReached {
                index: 1,
                previous_leverage: 1,
                current_leverage: 0,
            })
        );
    }

    #[test]
    fn description_limit_is_measured_in_utf8_bytes() {
        assert!(MarginTable::try_from(raw(&"x".repeat(250), &[(0, 50)])).is_ok());
        assert_eq!(
            MarginTable::try_from(raw(&format!("{}é", "x".repeat(249)), &[(0, 50)])),
            Err(TierConstructionError::DescriptionTooLong { bytes: 251 })
        );
    }

    #[test]
    fn one_through_three_tiers_are_admitted() {
        for tiers in [
            &[(0, 50)][..],
            &[(0, 50), (1, 40)][..],
            &[(0, 50), (1, 40), (2, 30)][..],
        ] {
            assert!(MarginTable::try_from(raw("", tiers)).is_ok());
        }
    }

    #[test]
    fn first_bound_checks_wire_range_before_zero() {
        assert_eq!(
            MarginTable::try_from(raw("", &[(WIRE_NOTIONAL_EXCLUSIVE_MAX, 50)])),
            Err(TierConstructionError::WireNotionalTooLarge {
                index: 0,
                lower_bound: WIRE_NOTIONAL_EXCLUSIVE_MAX,
            })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[(1, 50)])),
            Err(TierConstructionError::FirstLowerBoundNotZero { lower_bound: 1 })
        );
    }

    #[test]
    fn leverage_maximum_and_decreasing_order_are_exact() {
        assert!(MarginTable::try_from(raw("", &[(0, MAX_LEVERAGE)])).is_ok());
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, MAX_LEVERAGE + 1)])),
            Err(TierConstructionError::MaxLeverageTooLarge {
                index: 0,
                max_leverage: MAX_LEVERAGE + 1,
            })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 50), (1, 51)])),
            Err(TierConstructionError::MaxLeverageTooLarge {
                index: 1,
                max_leverage: 51,
            })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 50), (1, 50)])),
            Err(TierConstructionError::LeverageNotStrictlyDecreasing {
                index: 1,
                previous: 50,
                current: 50,
            })
        );
    }

    #[test]
    fn later_bound_maximum_is_inclusive() {
        assert!(
            MarginTable::try_from(raw("", &[(0, 50), (LATER_TIER_LOWER_INCLUSIVE_MAX, 25)],))
                .is_ok()
        );
        assert_eq!(
            MarginTable::try_from(raw(
                "",
                &[(0, 50), (LATER_TIER_LOWER_INCLUSIVE_MAX + 1, 25)],
            )),
            Err(TierConstructionError::LaterLowerBoundTooLarge {
                index: 1,
                lower_bound: LATER_TIER_LOWER_INCLUSIVE_MAX + 1,
            })
        );
    }

    #[test]
    fn lower_bounds_must_strictly_increase() {
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 50), (0, 40)])),
            Err(TierConstructionError::LowerBoundNotStrictlyIncreasing {
                index: 1,
                previous: 0,
                current: 0,
            })
        );
        assert_eq!(
            MarginTable::try_from(raw("", &[(0, 50), (2, 40), (1, 30)])),
            Err(TierConstructionError::LowerBoundNotStrictlyIncreasing {
                index: 2,
                previous: 2,
                current: 1,
            })
        );
    }
}
