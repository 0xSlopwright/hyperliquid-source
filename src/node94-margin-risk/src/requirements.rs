use core::fmt;

use crate::{MarginTable, MarginTier};

/// A target arithmetic fault reached while calculating a requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirementError {
    /// The observed target divides by a leverage-derived divisor without a
    /// visible zero check. This API reports that state instead of panicking.
    ZeroLeverage { tier_lower_bound: u64 },
}

impl fmt::Display for RequirementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLeverage { tier_lower_bound } => write!(
                formatter,
                "tier at lower bound {tier_lower_bound} reaches a zero leverage divisor"
            ),
        }
    }
}

impl std::error::Error for RequirementError {}

/// Select the last tier whose lower bound is at most the unsigned notional.
///
/// A validated table is always nonempty, and its first lower bound is zero, so
/// this function always returns a tier.
#[must_use]
pub fn select_tier(table: &MarginTable, notional: u64) -> &MarginTier {
    table
        .tiers()
        .iter()
        .rev()
        .find(|tier| tier.lower_bound() <= notional)
        .expect("validated margin table contains a zero lower bound")
}

/// Compute `floor(notional / (2 * leverage)) - prior`, saturating at zero.
///
/// The operation ordering matches the verified node #94 path.
pub fn initial_requirement(notional: u64, tier: MarginTier) -> Result<u64, RequirementError> {
    let leverage = u64::from(tier.max_leverage());
    if leverage == 0 {
        return Err(RequirementError::ZeroLeverage {
            tier_lower_bound: tier.lower_bound(),
        });
    }
    Ok((notional / (2 * leverage)).saturating_sub(tier.prior_contribution()))
}

/// Compute the verified maintenance requirement with target operation order.
///
/// The numerator is
/// `notional.saturating_mul(2).saturating_sub(prior.saturating_mul(4 * leverage))`,
/// followed by floor division by `6 * leverage`.
pub fn maintenance_requirement(notional: u64, tier: MarginTier) -> Result<u64, RequirementError> {
    let leverage = u64::from(tier.max_leverage());
    if leverage == 0 {
        return Err(RequirementError::ZeroLeverage {
            tier_lower_bound: tier.lower_bound(),
        });
    }
    let numerator = notional
        .saturating_mul(2)
        .saturating_sub(tier.prior_contribution().saturating_mul(4 * leverage));
    Ok(numerator / (6 * leverage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawMarginTable, RawMarginTier};

    fn established_table() -> MarginTable {
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

    #[test]
    fn selection_uses_unsigned_last_lower_bound_at_or_below_notional() {
        let table = established_table();
        for (notional, expected_lower) in [
            (0, 0),
            (999, 0),
            (1_000, 1_000),
            (999_999, 1_000),
            (1_000_000, 1_000_000),
            (u64::MAX, 1_000_000),
        ] {
            assert_eq!(select_tier(&table, notional).lower_bound(), expected_lower);
        }
    }

    #[test]
    fn established_transition_vectors_match() {
        let table = established_table();
        for (notional, expected_initial, expected_maintenance) in [
            (999, 9, 6),
            (1_000, 10, 6),
            (999_999, 24_984, 16_656),
            (1_000_000, 24_985, 16_656),
        ] {
            let tier = *select_tier(&table, notional);
            assert_eq!(initial_requirement(notional, tier), Ok(expected_initial));
            assert_eq!(
                maintenance_requirement(notional, tier),
                Ok(expected_maintenance)
            );
        }
    }

    #[test]
    fn initial_subtraction_saturates_after_division() {
        let tier = MarginTier::new(0, 10, 5);
        assert_eq!(initial_requirement(99, tier), Ok(0));
        assert_eq!(initial_requirement(100, tier), Ok(0));
        assert_eq!(initial_requirement(110, tier), Ok(1));
    }

    #[test]
    fn maintenance_multiplications_and_subtraction_saturate_in_order() {
        let no_prior = MarginTier::new(0, 0, 1);
        assert_eq!(
            maintenance_requirement(u64::MAX, no_prior),
            Ok(u64::MAX / 6)
        );

        let maximal_prior = MarginTier::new(0, u64::MAX, 50);
        assert_eq!(maintenance_requirement(u64::MAX, maximal_prior), Ok(0));
    }

    #[test]
    fn zero_leverage_is_an_explicit_target_fault() {
        let tier = MarginTier::new(0, 0, 0);
        let expected = Err(RequirementError::ZeroLeverage {
            tier_lower_bound: 0,
        });
        assert_eq!(initial_requirement(1, tier), expected);
        assert_eq!(maintenance_requirement(1, tier), expected);
    }
}
