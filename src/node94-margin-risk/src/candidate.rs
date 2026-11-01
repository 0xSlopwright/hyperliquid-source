use crate::{
    CrossMarginSummary, LiquidationAssessment, LiquidationError, PositionMargin,
    assess_cross_liquidation, assess_isolated_liquidation,
};

/// Observed byte stride of one appended target candidate record.
///
/// This is evidence about node #94's internal vector element. It is not the
/// size of [`LiquidationCandidate`] and does not establish a stable ABI.
pub const TARGET_CANDIDATE_RECORD_BYTES: usize = 48;

/// The fixed 20-byte value copied into each admitted target record.
///
/// The bounded instructions prove its width and copy position. Its higher-level
/// account ownership is inferred, so this API deliberately names it only as a
/// candidate subject.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateSubject([u8; 20]);

impl CandidateSubject {
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 20] {
        self.0
    }
}

/// The target-observed candidate scope and isolated-only context word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateScope {
    Cross,
    /// Node #94 writes this target-owned word at record offset `+0x08`.
    /// Its pointed-to/owned layout is unresolved and is not dereferenced here.
    Isolated {
        context_word: u64,
    },
}

/// The evidence-backed logical fields of an admitted candidate.
///
/// This safe Rust value intentionally omits the target record's unresolved
/// padding and makes no layout or serialization claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiquidationCandidate {
    pub scope: CandidateScope,
    pub surplus: i64,
    pub subject: CandidateSubject,
}

/// Admission distinguishes a checked non-candidate from an appended candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAdmission {
    Admitted(LiquidationCandidate),
    Rejected { surplus: i64 },
}

fn admission(
    assessment: LiquidationAssessment,
    scope: CandidateScope,
    subject: CandidateSubject,
) -> CandidateAdmission {
    if assessment.eligible {
        CandidateAdmission::Admitted(LiquidationCandidate {
            scope,
            surplus: assessment.surplus,
            subject,
        })
    } else {
        CandidateAdmission::Rejected {
            surplus: assessment.surplus,
        }
    }
}

/// Admit a cross-account candidate only when aggregate surplus is negative.
pub fn admit_cross_candidate(
    summary: CrossMarginSummary,
    subject: CandidateSubject,
) -> Result<CandidateAdmission, LiquidationError> {
    Ok(admission(
        assess_cross_liquidation(summary)?,
        CandidateScope::Cross,
        subject,
    ))
}

/// Admit an isolated candidate only when the isolated position surplus is negative.
pub fn admit_isolated_candidate(
    position: PositionMargin,
    subject: CandidateSubject,
    context_word: u64,
) -> Result<CandidateAdmission, LiquidationError> {
    Ok(admission(
        assess_isolated_liquidation(position)?,
        CandidateScope::Isolated { context_word },
        subject,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT: CandidateSubject = CandidateSubject::new([0x94; 20]);

    #[test]
    fn cross_admission_returns_a_record_only_for_negative_surplus() {
        assert_eq!(
            admit_cross_candidate(
                CrossMarginSummary {
                    signed_equity: 5,
                    maintenance_requirement: 6,
                },
                SUBJECT,
            ),
            Ok(CandidateAdmission::Admitted(LiquidationCandidate {
                scope: CandidateScope::Cross,
                surplus: -1,
                subject: SUBJECT,
            }))
        );
        assert_eq!(
            admit_cross_candidate(
                CrossMarginSummary {
                    signed_equity: 6,
                    maintenance_requirement: 6,
                },
                SUBJECT,
            ),
            Ok(CandidateAdmission::Rejected { surplus: 0 })
        );
    }

    #[test]
    fn isolated_admission_retains_the_observed_context_word() {
        let position = PositionMargin::Isolated {
            margin_after: 5,
            effective_margin: 5,
            absolute_notional: 100,
            previous_margin: 10,
            computed_requirement: 7,
        };
        assert_eq!(
            admit_isolated_candidate(position, SUBJECT, 0x1234),
            Ok(CandidateAdmission::Admitted(LiquidationCandidate {
                scope: CandidateScope::Isolated {
                    context_word: 0x1234,
                },
                surplus: -2,
                subject: SUBJECT,
            }))
        );
    }
}
