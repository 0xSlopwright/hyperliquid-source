use core::fmt;

use crate::PositionMargin;

/// One pair accumulated by the observed cross-account margin helper.
///
/// The target also accumulates two further output words whose ownership is not
/// established by the bounded packet. This type deliberately exposes only the
/// signed-equity and maintenance-requirement pair consumed by candidate
/// admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossMarginContribution {
    pub signed_equity_delta: i64,
    pub maintenance_requirement: u64,
}

/// The two aggregate values consumed by the verified cross-margin branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossMarginSummary {
    pub signed_equity: i64,
    pub maintenance_requirement: u64,
}

/// The bounded result of subtracting maintenance requirement from margin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiquidationAssessment {
    pub surplus: i64,
    pub eligible: bool,
}

/// A verified failure or a rejected mismatch between accounting branches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiquidationError {
    RequirementExceedsSignedRange { requirement: u64 },
    CrossPositionRequiresAggregate,
}

impl fmt::Display for LiquidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequirementExceedsSignedRange { requirement } => write!(
                formatter,
                "maintenance requirement {requirement} does not fit the signed comparison path"
            ),
            Self::CrossPositionRequiresAggregate => formatter.write_str(
                "cross liquidation eligibility requires an externally aggregated margin summary",
            ),
        }
    }
}

impl std::error::Error for LiquidationError {}

/// Aggregate the proved cross-account pair with target saturation order.
///
/// Node #94 adds signed equity with signed saturation and maintenance
/// requirement with unsigned saturation. The caller supplies the account's
/// established starting equity because its construction is outside this
/// component.
#[must_use]
pub fn aggregate_cross_margin(
    starting_equity: i64,
    contributions: &[CrossMarginContribution],
) -> CrossMarginSummary {
    contributions.iter().fold(
        CrossMarginSummary {
            signed_equity: starting_equity,
            maintenance_requirement: 0,
        },
        |summary, contribution| CrossMarginSummary {
            signed_equity: summary
                .signed_equity
                .saturating_add(contribution.signed_equity_delta),
            maintenance_requirement: summary
                .maintenance_requirement
                .saturating_add(contribution.maintenance_requirement),
        },
    )
}

fn assess(
    signed_margin: i64,
    maintenance_requirement: u64,
) -> Result<LiquidationAssessment, LiquidationError> {
    let signed_requirement = i64::try_from(maintenance_requirement).map_err(|_| {
        LiquidationError::RequirementExceedsSignedRange {
            requirement: maintenance_requirement,
        }
    })?;
    let surplus = signed_margin.saturating_sub(signed_requirement);
    Ok(LiquidationAssessment {
        surplus,
        eligible: surplus < 0,
    })
}

/// Apply the proved signed-surplus predicate to aggregated cross values.
pub fn assess_cross_liquidation(
    summary: CrossMarginSummary,
) -> Result<LiquidationAssessment, LiquidationError> {
    assess(summary.signed_equity, summary.maintenance_requirement)
}

/// Apply the proved signed-surplus predicate to an isolated position output.
///
/// A cross output is rejected because the target first runs its separate
/// aggregate-margin helper. Treating one cross position as an account aggregate
/// would be an unsupported assumption.
pub fn assess_isolated_liquidation(
    position: PositionMargin,
) -> Result<LiquidationAssessment, LiquidationError> {
    match position {
        PositionMargin::Isolated {
            margin_after,
            computed_requirement,
            ..
        } => assess(margin_after, computed_requirement),
        PositionMargin::Cross { .. } => Err(LiquidationError::CrossPositionRequiresAggregate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_aggregation_saturates_each_proved_field_independently() {
        assert_eq!(
            aggregate_cross_margin(
                i64::MAX - 1,
                &[
                    CrossMarginContribution {
                        signed_equity_delta: 10,
                        maintenance_requirement: u64::MAX - 1,
                    },
                    CrossMarginContribution {
                        signed_equity_delta: -4,
                        maintenance_requirement: 10,
                    },
                ],
            ),
            CrossMarginSummary {
                signed_equity: i64::MAX - 4,
                maintenance_requirement: u64::MAX,
            }
        );
    }

    #[test]
    fn negative_only_predicate_excludes_zero() {
        for (signed_equity, requirement, surplus, eligible) in
            [(-1, 0, -1, true), (6, 6, 0, false), (7, 6, 1, false)]
        {
            assert_eq!(
                assess_cross_liquidation(CrossMarginSummary {
                    signed_equity,
                    maintenance_requirement: requirement,
                }),
                Ok(LiquidationAssessment { surplus, eligible })
            );
        }
    }

    #[test]
    fn signed_subtraction_saturates_at_i64_minimum() {
        assert_eq!(
            assess_cross_liquidation(CrossMarginSummary {
                signed_equity: i64::MIN,
                maintenance_requirement: 1,
            }),
            Ok(LiquidationAssessment {
                surplus: i64::MIN,
                eligible: true,
            })
        );
    }

    #[test]
    fn requirement_must_fit_signed_comparison_path() {
        let requirement = i64::MAX as u64 + 1;
        assert_eq!(
            assess_cross_liquidation(CrossMarginSummary {
                signed_equity: i64::MAX,
                maintenance_requirement: requirement,
            }),
            Err(LiquidationError::RequirementExceedsSignedRange { requirement })
        );
    }

    #[test]
    fn isolated_uses_margin_after_and_computed_requirement() {
        let position = PositionMargin::Isolated {
            margin_after: -910,
            effective_margin: 0,
            absolute_notional: 1_000,
            previous_margin: 90,
            computed_requirement: 6,
        };
        assert_eq!(
            assess_isolated_liquidation(position),
            Ok(LiquidationAssessment {
                surplus: -916,
                eligible: true,
            })
        );
    }

    #[test]
    fn cross_position_is_not_mistaken_for_account_aggregate() {
        let position = PositionMargin::Cross {
            signed_notional: 1_000,
            effective_margin: 6,
            absolute_notional: 1_000,
        };
        assert_eq!(
            assess_isolated_liquidation(position),
            Err(LiquidationError::CrossPositionRequiresAggregate)
        );
    }
}
