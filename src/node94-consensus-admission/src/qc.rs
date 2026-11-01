use crate::stake::quorum;
use crate::{
    AdmissionAuthenticator, AdmissionError, FatalAdmissionError, Qc, StakeHistory,
    VerificationFailure,
};

/// Verify a QC in the target-observed order.
///
/// A held stake/signature/quorum result is superseded by hardfork and genesis
/// checks exactly where the native rows do so.  Target panics are represented
/// by [`VerificationFailure::Fatal`].
pub fn verify_qc<A: AdmissionAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    qc: &Qc,
) -> Result<(), VerificationFailure> {
    let mut quorum_passed = false;
    let held = match history.snapshot_for(qc.round) {
        Err(error) => Err(error.into()),
        Ok(snapshot) => {
            let mut vote_error = None;
            for vote in &qc.votes {
                if !snapshot.stakes.contains_key(&vote.signer) {
                    vote_error = Some(AdmissionError::QcVoteSignature);
                    break;
                }
                if authenticator
                    .recover_qc_vote_signer(qc, &vote.signature)
                    .as_ref()
                    != Ok(&vote.signer)
                {
                    vote_error = Some(AdmissionError::QcVoteSignature);
                    break;
                }
            }

            if let Some(error) = vote_error {
                Err(error.into())
            } else {
                let result = quorum(snapshot, qc.votes.iter().map(|vote| vote.signer))?;
                quorum_passed = result.reached;
                if quorum_passed {
                    Ok(())
                } else {
                    Err(AdmissionError::QcNoQuorum.into())
                }
            }
        }
    };

    if qc.hardfork != history.hardfork {
        if qc.hardfork.version > history.hardfork.version && quorum_passed {
            return Err(FatalAdmissionError::NewerHardforkWithQuorum.into());
        }
        return Err(AdmissionError::Hardfork {
            qc: qc.hardfork,
            node: history.hardfork,
        }
        .into());
    }

    if qc.round < history.hardfork.start_round {
        return Err(AdmissionError::QcRoundBeforeHardfork.into());
    }
    if qc.round == history.hardfork.start_round {
        return if qc.block_hash.0 == [0; 32] && qc.votes.is_empty() {
            Ok(())
        } else {
            Err(AdmissionError::QcGenesisInvalid.into())
        };
    }

    held
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        AuthenticationError, BlockHash, Hardfork, QcVote, Round, SignatureBytes, SignedBlock,
        StakeSnapshot, ValidatorAddress,
    };

    struct DeterministicAuth;

    impl AdmissionAuthenticator for DeterministicAuth {
        fn expected_proposer(
            &self,
            _round: Round,
            eligible: &[ValidatorAddress],
        ) -> Result<ValidatorAddress, AuthenticationError> {
            eligible
                .first()
                .copied()
                .ok_or(AuthenticationError::proposer(None))
        }

        fn recover_qc_vote_signer(
            &self,
            _qc: &Qc,
            signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            if signature.0[0] == 0xff {
                Err(AuthenticationError::QcVoteSignature)
            } else {
                Ok(address(signature.0[0]))
            }
        }

        fn recover_timeout_vote_signer(
            &self,
            _qc: &Qc,
            _round: Round,
            _signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            unreachable!()
        }

        fn recover_block_signer(
            &self,
            _block: &SignedBlock,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            unreachable!()
        }
    }

    fn address(value: u8) -> ValidatorAddress {
        ValidatorAddress([value; 20])
    }

    fn vote(value: u8) -> QcVote {
        let mut signature = [0; 0x48];
        signature[0] = value;
        QcVote {
            signer: address(value),
            signature: SignatureBytes(signature),
        }
    }

    fn history(stakes: &[(u8, u64)]) -> StakeHistory {
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
                    stakes: stakes
                        .iter()
                        .map(|(key, value)| (address(*key), *value))
                        .collect(),
                },
            )]),
        }
    }

    fn qc(votes: Vec<QcVote>) -> Qc {
        Qc {
            votes,
            hardfork: Hardfork {
                version: 2,
                start_round: Round(100),
            },
            round: Round(999),
            block_hash: BlockHash([7; 32]),
        }
    }

    #[test]
    fn strict_quorum_accepts_and_exact_two_thirds_rejects() {
        let auth = DeterministicAuth;
        assert_eq!(
            verify_qc(
                &history(&[(1, 4), (2, 3), (3, 3)]),
                &auth,
                &qc(vec![vote(1), vote(2)])
            ),
            Ok(())
        );
        assert_eq!(
            verify_qc(
                &history(&[(1, 1), (2, 1), (3, 1)]),
                &auth,
                &qc(vec![vote(1), vote(2)])
            ),
            Err(VerificationFailure::Rejected(AdmissionError::QcNoQuorum))
        );
    }

    #[test]
    fn duplicate_signers_are_authenticated_but_count_once() {
        let auth = DeterministicAuth;
        assert_eq!(
            verify_qc(
                &history(&[(1, 2), (2, 1)]),
                &auth,
                &qc(vec![vote(1), vote(1)])
            ),
            Err(VerificationFailure::Rejected(AdmissionError::QcNoQuorum))
        );
    }

    #[test]
    fn recovered_address_must_equal_the_claimed_qc_signer() {
        let auth = DeterministicAuth;
        let mut substituted = vote(1);
        substituted.signature.0[0] = 2;
        assert_eq!(
            verify_qc(&history(&[(1, 10)]), &auth, &qc(vec![substituted])),
            Err(VerificationFailure::Rejected(
                AdmissionError::QcVoteSignature
            ))
        );
    }

    #[test]
    fn genesis_overrides_a_missing_snapshot_but_requires_empty_zero_qc() {
        let auth = DeterministicAuth;
        let mut no_snapshots = history(&[]);
        no_snapshots.snapshots.clear();
        let mut genesis = qc(Vec::new());
        genesis.round = Round(100);
        genesis.block_hash = BlockHash([0; 32]);
        assert_eq!(verify_qc(&no_snapshots, &auth, &genesis), Ok(()));

        genesis.block_hash = BlockHash([1; 32]);
        assert_eq!(
            verify_qc(&no_snapshots, &auth, &genesis),
            Err(VerificationFailure::Rejected(
                AdmissionError::QcGenesisInvalid
            ))
        );
    }

    #[test]
    fn hardfork_mismatch_supersedes_a_held_signature_error() {
        let auth = DeterministicAuth;
        let mut bad_vote = vote(1);
        bad_vote.signature.0[0] = 9;
        let mut candidate = qc(vec![bad_vote]);
        candidate.hardfork.version = 1;
        assert!(matches!(
            verify_qc(&history(&[(1, 10)]), &auth, &candidate),
            Err(VerificationFailure::Rejected(
                AdmissionError::Hardfork { .. }
            ))
        ));
    }

    #[test]
    fn newer_version_is_fatal_only_after_quorum() {
        let auth = DeterministicAuth;
        let mut candidate = qc(vec![vote(1)]);
        candidate.hardfork.version = 3;
        assert_eq!(
            verify_qc(&history(&[(1, 10)]), &auth, &candidate),
            Err(VerificationFailure::Fatal(
                FatalAdmissionError::NewerHardforkWithQuorum
            ))
        );

        assert!(matches!(
            verify_qc(&history(&[(1, 1), (2, 1)]), &auth, &candidate),
            Err(VerificationFailure::Rejected(
                AdmissionError::Hardfork { .. }
            ))
        ));
    }

    #[test]
    fn pre_start_round_has_its_own_precedence() {
        let auth = DeterministicAuth;
        let mut candidate = qc(vec![vote(1)]);
        candidate.round = Round(99);
        assert_eq!(
            verify_qc(&history(&[(1, 10)]), &auth, &candidate),
            Err(VerificationFailure::Rejected(
                AdmissionError::QcRoundBeforeHardfork
            ))
        );
    }
}
