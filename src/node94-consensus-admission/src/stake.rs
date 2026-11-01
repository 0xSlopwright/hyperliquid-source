use std::collections::{BTreeMap, BTreeSet};

use crate::{AdmissionError, FatalAdmissionError, Hardfork, Round, ValidatorAddress};

pub const RECENT_ROUND_SPAN: u64 = 2_000;
pub const STAKE_LAG_ROUNDS: u64 = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakeSnapshot {
    pub stakes: BTreeMap<ValidatorAddress, u64>,
}

impl StakeSnapshot {
    pub fn eligible_validators(&self) -> Vec<ValidatorAddress> {
        self.stakes.keys().copied().collect()
    }
}

/// The target stake-table fields used by the recovered verifier paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakeHistory {
    pub base_round: Round,
    pub hardfork: Hardfork,
    pub estimated_valid_until: Round,
    pub snapshots: BTreeMap<Round, StakeSnapshot>,
}

impl StakeHistory {
    /// Select the last snapshot key at or below the target-observed bound.
    pub fn snapshot_for(&self, round: Round) -> Result<&StakeSnapshot, AdmissionError> {
        let limit = self.base_round.0.saturating_add(RECENT_ROUND_SPAN);
        let bound = if round.0 < limit {
            self.base_round
        } else {
            Round(
                self.base_round
                    .0
                    .max(round.0.wrapping_sub(STAKE_LAG_ROUNDS)),
            )
        };

        self.snapshots
            .range(..=bound)
            .next_back()
            .map(|(_, snapshot)| snapshot)
            .ok_or(AdmissionError::MissingValidatorSetRound(round))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quorum {
    pub signed_stake: u64,
    pub total_stake: u64,
    pub reached: bool,
}

pub fn quorum(
    snapshot: &StakeSnapshot,
    signers: impl IntoIterator<Item = ValidatorAddress>,
) -> Result<Quorum, FatalAdmissionError> {
    let unique: BTreeSet<_> = signers.into_iter().collect();
    let signed_stake = checked_sum(
        unique
            .iter()
            .filter_map(|address| snapshot.stakes.get(address).copied()),
    )?;
    let total_stake = checked_sum(snapshot.stakes.values().copied())?;
    Ok(Quorum {
        signed_stake,
        total_stake,
        reached: has_strict_two_thirds(signed_stake, total_stake),
    })
}

/// The target compares full 128-bit products and requires a strict majority.
pub fn has_strict_two_thirds(signed_stake: u64, total_stake: u64) -> bool {
    3_u128 * u128::from(signed_stake) > 2_u128 * u128::from(total_stake)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, FatalAdmissionError> {
    values.into_iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value)
            .ok_or(FatalAdmissionError::StakeOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(value: u8) -> ValidatorAddress {
        ValidatorAddress([value; 20])
    }

    fn snapshot(entries: &[(u8, u64)]) -> StakeSnapshot {
        StakeSnapshot {
            stakes: entries
                .iter()
                .map(|(address, stake)| (validator(*address), *stake))
                .collect(),
        }
    }

    fn history(base: u64, entries: &[(u64, StakeSnapshot)]) -> StakeHistory {
        StakeHistory {
            base_round: Round(base),
            hardfork: Hardfork {
                version: 2,
                start_round: Round(100),
            },
            estimated_valid_until: Round(u64::MAX),
            snapshots: entries
                .iter()
                .cloned()
                .map(|(r, s)| (Round(r), s))
                .collect(),
        }
    }

    #[test]
    fn recent_rounds_use_the_base_bound() {
        let old = snapshot(&[(1, 10)]);
        let newer = snapshot(&[(2, 10)]);
        let history = history(500, &[(500, old.clone()), (501, newer)]);

        assert_eq!(history.snapshot_for(Round(2_499)), Ok(&old));
    }

    #[test]
    fn first_lagged_round_uses_round_minus_two_hundred() {
        let base = snapshot(&[(1, 10)]);
        let edge = snapshot(&[(2, 10)]);
        let history = history(500, &[(500, base), (2_300, edge.clone())]);

        assert_eq!(history.snapshot_for(Round(2_500)), Ok(&edge));
    }

    #[test]
    fn base_plus_span_saturates() {
        let selected = snapshot(&[(1, 10)]);
        let history = history(u64::MAX - 5, &[(u64::MAX - 5, selected.clone())]);
        assert_eq!(history.snapshot_for(Round(u64::MAX)), Ok(&selected));
    }

    #[test]
    fn no_key_at_or_below_bound_reports_the_requested_round() {
        let history = history(500, &[(501, snapshot(&[(1, 10)]))]);
        assert_eq!(
            history.snapshot_for(Round(600)),
            Err(AdmissionError::MissingValidatorSetRound(Round(600)))
        );
    }

    #[test]
    fn exactly_two_thirds_is_not_quorum() {
        assert!(!has_strict_two_thirds(2, 3));
        assert!(has_strict_two_thirds(3, 4));
    }

    #[test]
    fn duplicate_and_unknown_signers_do_not_add_weight() {
        let snapshot = snapshot(&[(1, 7), (2, 3)]);
        assert_eq!(
            quorum(&snapshot, [validator(1), validator(1), validator(99)]),
            Ok(Quorum {
                signed_stake: 7,
                total_stake: 10,
                reached: true,
            })
        );
    }

    #[test]
    fn stake_sums_are_checked_before_the_wide_compare() {
        let snapshot = snapshot(&[(1, u64::MAX), (2, 1)]);
        assert_eq!(
            quorum(&snapshot, [validator(1)]),
            Err(FatalAdmissionError::StakeOverflow)
        );
    }

    #[test]
    fn u128_products_preserve_large_comparisons() {
        assert!(has_strict_two_thirds(u64::MAX, u64::MAX));
        assert!(!has_strict_two_thirds(u64::MAX / 2, u64::MAX));
    }
}
