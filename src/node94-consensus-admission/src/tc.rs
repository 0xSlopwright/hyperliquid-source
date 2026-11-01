use crate::stake::quorum;
use crate::{
    verify_qc, AdmissionAuthenticator, AdmissionError, StakeHistory, Tc, TimeoutVote,
    VerificationFailure,
};

/// Verify a timeout certificate in the observed gate order.
pub fn verify_tc<A: AdmissionAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    tc: &Tc,
) -> Result<(), VerificationFailure> {
    let tc_snapshot = history.snapshot_for(tc.round)?;
    if tc.votes.is_empty() {
        return Err(AdmissionError::TcNoTimeout.into());
    }
    for vote in &tc.votes {
        if vote.round != tc.round {
            return Err(AdmissionError::TimeoutRoundMismatch {
                supplied: vote.round,
                expected: tc.round,
            }
            .into());
        }
    }

    let highest = tc
        .votes
        .iter()
        .reduce(|current, vote| {
            if vote.qc.round >= current.qc.round {
                vote
            } else {
                current
            }
        })
        .expect("nonempty checked above");
    verify_timeout_vote(history, authenticator, highest, true)?;

    // The native helper dispatches these checks through a parallel-loop
    // helper.  The retained fixtures establish each check and a single-error
    // result, but not ordering among several simultaneous failures.  This
    // bounded reconstruction uses stable input order for determinism.
    for vote in &tc.votes {
        verify_timeout_vote(history, authenticator, vote, false)?;
    }

    let result = quorum(tc_snapshot, tc.votes.iter().map(|vote| vote.signer))?;
    if result.reached {
        Ok(())
    } else {
        Err(AdmissionError::TcNoQuorum.into())
    }
}

fn verify_timeout_vote<A: AdmissionAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    vote: &TimeoutVote,
    with_qc: bool,
) -> Result<(), VerificationFailure> {
    let snapshot = history.snapshot_for(vote.round)?;
    if with_qc {
        verify_qc(history, authenticator, &vote.qc)?;
    }
    if !snapshot.stakes.contains_key(&vote.signer)
        || authenticator.verify_timeout_vote(vote).is_err()
    {
        return Err(AdmissionError::Signature.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        AuthenticationError, BlockHash, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock,
        StakeSnapshot, ValidatorAddress,
    };

    struct CountingAuth {
        timeout_checks: Cell<usize>,
    }

    impl AdmissionAuthenticator for CountingAuth {
        fn expected_proposer(
            &self,
            _round: Round,
            eligible: &[ValidatorAddress],
        ) -> Result<ValidatorAddress, AuthenticationError> {
            eligible
                .first()
                .copied()
                .ok_or(AuthenticationError::ProposerSelection)
        }

        fn verify_qc_vote(&self, _qc: &Qc, vote: &QcVote) -> Result<(), AuthenticationError> {
            if vote.signature.0[0] == vote.signer.0[0] {
                Ok(())
            } else {
                Err(AuthenticationError::QcVoteSignature)
            }
        }

        fn verify_timeout_vote(&self, vote: &TimeoutVote) -> Result<(), AuthenticationError> {
            self.timeout_checks.set(self.timeout_checks.get() + 1);
            if vote.signature.0[0] == vote.signer.0[0] {
                Ok(())
            } else {
                Err(AuthenticationError::TimeoutVoteSignature)
            }
        }

        fn verify_block_signature(&self, _block: &SignedBlock) -> Result<(), AuthenticationError> {
            Ok(())
        }
    }

    fn address(value: u8) -> ValidatorAddress {
        ValidatorAddress([value; 20])
    }

    fn signature(value: u8) -> SignatureBytes {
        let mut bytes = [0; 0x48];
        bytes[0] = value;
        SignatureBytes(bytes)
    }

    fn history() -> StakeHistory {
        StakeHistory {
            base_round: Round(0),
            hardfork: Hardfork {
                version: 2,
                start_round: Round(100),
            },
            estimated_valid_until: Round(10_000),
            snapshots: BTreeMap::from([(
                Round(0),
                StakeSnapshot {
                    stakes: [1_u8, 2, 3, 4]
                        .into_iter()
                        .map(|value| (address(value), 10))
                        .collect(),
                },
            )]),
        }
    }

    fn qc(round: u64, valid: bool) -> Qc {
        Qc {
            votes: [1_u8, 2, 3]
                .into_iter()
                .map(|value| QcVote {
                    signer: address(value),
                    signature: signature(if valid { value } else { 99 }),
                })
                .collect(),
            hardfork: Hardfork {
                version: 2,
                start_round: Round(100),
            },
            round: Round(round),
            block_hash: BlockHash([7; 32]),
        }
    }

    fn timeout(signer: u8, qc_round: u64, valid_qc: bool) -> TimeoutVote {
        TimeoutVote {
            qc: qc(qc_round, valid_qc),
            round: Round(999),
            signer: address(signer),
            signature: signature(signer),
        }
    }

    fn auth() -> CountingAuth {
        CountingAuth {
            timeout_checks: Cell::new(0),
        }
    }

    #[test]
    fn empty_and_mismatched_votes_precede_crypto() {
        let auth = auth();
        assert_eq!(
            verify_tc(
                &history(),
                &auth,
                &Tc {
                    votes: Vec::new(),
                    round: Round(999)
                }
            ),
            Err(VerificationFailure::Rejected(AdmissionError::TcNoTimeout))
        );
        assert_eq!(auth.timeout_checks.get(), 0);

        let mut vote = timeout(1, 998, true);
        vote.round = Round(998);
        assert_eq!(
            verify_tc(
                &history(),
                &auth,
                &Tc {
                    votes: vec![vote],
                    round: Round(999)
                }
            ),
            Err(VerificationFailure::Rejected(
                AdmissionError::TimeoutRoundMismatch {
                    supplied: Round(998),
                    expected: Round(999)
                }
            ))
        );
        assert_eq!(auth.timeout_checks.get(), 0);
    }

    #[test]
    fn highest_qc_is_verified_and_later_vote_wins_a_tie() {
        let auth = auth();
        let certificate = Tc {
            votes: vec![
                timeout(1, 990, false),
                timeout(2, 995, false),
                timeout(3, 995, true),
            ],
            round: Round(999),
        };
        assert_eq!(verify_tc(&history(), &auth, &certificate), Ok(()));
    }

    #[test]
    fn an_invalid_later_tie_is_the_qc_failure() {
        let auth = auth();
        let certificate = Tc {
            votes: vec![
                timeout(1, 995, true),
                timeout(2, 990, true),
                timeout(3, 995, false),
            ],
            round: Round(999),
        };
        assert_eq!(
            verify_tc(&history(), &auth, &certificate),
            Err(VerificationFailure::Rejected(
                AdmissionError::QcVoteSignature
            ))
        );
    }

    #[test]
    fn selected_timeout_signature_is_checked_twice() {
        let auth = auth();
        let certificate = Tc {
            votes: vec![
                timeout(1, 990, true),
                timeout(2, 991, true),
                timeout(3, 992, true),
            ],
            round: Round(999),
        };
        assert_eq!(verify_tc(&history(), &auth, &certificate), Ok(()));
        assert_eq!(auth.timeout_checks.get(), 4);
    }

    #[test]
    fn duplicate_voters_count_once_for_strict_quorum() {
        let auth = auth();
        let certificate = Tc {
            votes: vec![
                timeout(1, 990, true),
                timeout(2, 991, true),
                timeout(1, 992, true),
            ],
            round: Round(999),
        };
        assert_eq!(
            verify_tc(&history(), &auth, &certificate),
            Err(VerificationFailure::Rejected(AdmissionError::TcNoQuorum))
        );
    }
}
