use crate::{
    verify_qc, verify_tc, AdmissionAuthenticator, AdmissionError, Round, SignedBlock, StakeHistory,
    VerificationFailure,
};

/// A block that passed the recovered certificate and proposer gates.
///
/// Construction is private so registration cannot accidentally accept an
/// unverified `SignedBlock`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlock {
    block: SignedBlock,
}

impl VerifiedBlock {
    pub fn block(&self) -> &SignedBlock {
        &self.block
    }

    pub(crate) fn into_block(self) -> SignedBlock {
        self.block
    }
}

/// Verify the signed block path through native helpers `0x454b700`,
/// `0x47b01b0`, `0x4758d70`, and optionally `0x47594f0`.
pub fn verify_block<A: AdmissionAuthenticator>(
    history: &StakeHistory,
    authenticator: &A,
    block: &SignedBlock,
) -> Result<VerifiedBlock, VerificationFailure> {
    // The outer signed-block verifier selects the block-round stake set before
    // invoking proposer selection or either certificate verifier.
    let block_snapshot = history.snapshot_for(block.round)?;
    let eligible = block_snapshot.eligible_validators();
    let expected = authenticator
        .expected_proposer(block.round, &eligible)
        .map_err(AdmissionError::Authentication)?;
    if block.proposer != expected {
        return Err(AdmissionError::BadBlockProposer {
            proposed: block.proposer,
            expected,
        }
        .into());
    }

    verify_qc(history, authenticator, &block.qc)?;
    if block.qc.round >= block.round {
        return Err(AdmissionError::BadQcRound.into());
    }

    if let Some(tc) = &block.tc {
        let expected_tc_round = Round(block.round.0.wrapping_sub(1));
        if tc.round != expected_tc_round {
            return Err(AdmissionError::BadTcRound.into());
        }
        verify_tc(history, authenticator, tc)?;
    }

    if !block_snapshot.stakes.contains_key(&block.proposer) {
        return Err(AdmissionError::Signature.into());
    }
    if authenticator.recover_block_signer(block).as_ref() != Ok(&block.proposer) {
        return Err(AdmissionError::Signature.into());
    }

    Ok(VerifiedBlock {
        block: block.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        AuthenticationError, BlockHash, Hardfork, Qc, QcVote, SignatureBytes, StakeSnapshot, Tc,
        TransactionHash, ValidatorAddress,
    };

    struct TracingAuth {
        proposer: Result<ValidatorAddress, AuthenticationError>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl AdmissionAuthenticator for TracingAuth {
        fn expected_proposer(
            &self,
            _round: Round,
            _eligible: &[ValidatorAddress],
        ) -> Result<ValidatorAddress, AuthenticationError> {
            self.calls.borrow_mut().push("proposer");
            self.proposer
        }

        fn recover_qc_vote_signer(
            &self,
            _qc: &Qc,
            signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            self.calls.borrow_mut().push("qc");
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
            signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            self.calls.borrow_mut().push("timeout");
            if signature.0[0] == 0xff {
                Err(AuthenticationError::TimeoutVoteSignature)
            } else {
                Ok(address(signature.0[0]))
            }
        }

        fn recover_block_signer(
            &self,
            block: &SignedBlock,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            self.calls.borrow_mut().push("block");
            if block.signature.0[0] == 0xff {
                Err(AuthenticationError::BlockSignature)
            } else {
                Ok(address(block.signature.0[0]))
            }
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
            estimated_valid_until: Round(2_000),
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

    fn qc(round: u64) -> Qc {
        Qc {
            votes: [1_u8, 2, 3]
                .into_iter()
                .map(|value| QcVote {
                    signer: address(value),
                    signature: signature(value),
                })
                .collect(),
            hardfork: Hardfork {
                version: 2,
                start_round: Round(100),
            },
            round: Round(round),
            block_hash: BlockHash([9; 32]),
        }
    }

    fn block() -> SignedBlock {
        SignedBlock {
            transaction_hashes: vec![TransactionHash([5; 32])],
            qc: qc(999),
            tc: None,
            round: Round(1_000),
            proposer: address(1),
            signature: signature(1),
        }
    }

    fn auth() -> TracingAuth {
        TracingAuth {
            proposer: Ok(address(1)),
            calls: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn qc_gap_needs_no_tc() {
        let auth = auth();
        let mut candidate = block();
        candidate.qc.round = Round(700);
        assert!(verify_block(&history(), &auth, &candidate).is_ok());
    }

    #[test]
    fn proposer_selection_and_identity_precede_qc() {
        let mut auth = auth();
        auth.proposer = Ok(address(2));
        assert!(matches!(
            verify_block(&history(), &auth, &block()),
            Err(VerificationFailure::Rejected(
                AdmissionError::BadBlockProposer { .. }
            ))
        ));
        assert_eq!(&*auth.calls.borrow(), &["proposer"]);
    }

    #[test]
    fn certificate_errors_precede_block_signature() {
        let auth = auth();
        let mut candidate = block();
        candidate.qc.round = candidate.round;
        candidate.signature = signature(99);
        assert_eq!(
            verify_block(&history(), &auth, &candidate),
            Err(VerificationFailure::Rejected(AdmissionError::BadQcRound))
        );
        assert!(!auth.calls.borrow().contains(&"block"));
    }

    #[test]
    fn tc_must_be_from_the_wrapping_previous_round() {
        let auth = auth();
        let mut candidate = block();
        candidate.tc = Some(Tc {
            votes: Vec::new(),
            round: Round(998),
        });
        assert_eq!(
            verify_block(&history(), &auth, &candidate),
            Err(VerificationFailure::Rejected(AdmissionError::BadTcRound))
        );
    }

    #[test]
    fn proposer_membership_is_checked_after_certificates() {
        let mut auth = auth();
        auth.proposer = Ok(address(9));
        let mut candidate = block();
        candidate.proposer = address(9);
        candidate.signature = signature(9);
        assert_eq!(
            verify_block(&history(), &auth, &candidate),
            Err(VerificationFailure::Rejected(AdmissionError::Signature))
        );
        assert_eq!(auth.calls.borrow().last(), Some(&"qc"));
    }

    #[test]
    fn missing_block_round_snapshot_is_first() {
        let auth = auth();
        let mut empty = history();
        empty.snapshots.clear();
        assert_eq!(
            verify_block(&empty, &auth, &block()),
            Err(VerificationFailure::Rejected(
                AdmissionError::MissingValidatorSetRound(Round(1_000))
            ))
        );
        assert!(auth.calls.borrow().is_empty());
    }

    #[test]
    fn recovered_address_must_equal_the_claimed_block_proposer() {
        let auth = auth();
        let mut substituted = block();
        substituted.signature = signature(2);
        assert_eq!(
            verify_block(&history(), &auth, &substituted),
            Err(VerificationFailure::Rejected(AdmissionError::Signature))
        );
    }

    #[test]
    fn proposer_rule_errors_preserve_an_authenticated_target_tag() {
        let auth = TracingAuth {
            proposer: Err(AuthenticationError::proposer(Some(0x10))),
            calls: RefCell::new(Vec::new()),
        };
        let error = verify_block(&history(), &auth, &block()).unwrap_err();
        assert_eq!(
            error,
            VerificationFailure::Rejected(AdmissionError::Authentication(
                AuthenticationError::proposer(Some(0x10))
            ))
        );
        let VerificationFailure::Rejected(error) = error else {
            unreachable!()
        };
        assert_eq!(error.target_tag(), Some(0x10));
    }
}
