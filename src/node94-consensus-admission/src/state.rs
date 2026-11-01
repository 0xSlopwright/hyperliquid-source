use std::collections::{BTreeMap, BTreeSet};

use crate::{
    verify_block, AdmissionAuthenticator, AdmissionError, BlockHash, EventTime, Round, SignedBlock,
    StakeHistory, TransactionHash, VerificationFailure, VerifiedBlock,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionRecord {
    Known,
    UnknownPlaceholder { observed_at: EventTime },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredBlock {
    pub block: SignedBlock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundBlock {
    pub block_hash: BlockHash,
    pub block: SignedBlock,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ForwardChannel {
    pub closed: bool,
    pub waker_registered: bool,
    pub wake_count: u64,
    pub records: Vec<OutboundBlock>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusState {
    pub committed_round: Round,
    pub transactions: BTreeMap<TransactionHash, TransactionRecord>,
    pub blocks: BTreeMap<BlockHash, RegisteredBlock>,
    pub requested_blocks: BTreeSet<BlockHash>,
    pub forwarding_disabled: bool,
    pub forward_channel: ForwardChannel,
}

impl ConsensusState {
    pub fn new(committed_round: Round) -> Self {
        Self {
            committed_round,
            transactions: BTreeMap::new(),
            blocks: BTreeMap::new(),
            requested_blocks: BTreeSet::new(),
            forwarding_disabled: false,
            forward_channel: ForwardChannel::default(),
        }
    }
}

/// A verified block that has also passed state-dependent admission gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedBlock {
    block_hash: BlockHash,
    verified: VerifiedBlock,
}

impl AdmittedBlock {
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    pub fn block(&self) -> &SignedBlock {
        self.verified.block()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardDisposition {
    Disabled,
    Closed,
    Queued,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationOutcome {
    pub block_hash: BlockHash,
    pub request_removed: bool,
    /// Preserves block order and repeats, matching the target's collected row.
    pub unknown_transactions: Vec<TransactionHash>,
    pub forward: ForwardDisposition,
}

/// Apply only the committed-round and duplicate gates to an already verified block.
pub fn admit_verified_block(
    state: &ConsensusState,
    block_hash: BlockHash,
    verified: VerifiedBlock,
) -> Result<AdmittedBlock, AdmissionError> {
    check_state_gates(state, block_hash, verified.block())?;
    Ok(AdmittedBlock {
        block_hash,
        verified,
    })
}

/// Register an admitted block and all target-observed side effects.
///
/// State gates are checked again to prevent a stale admission token from
/// overwriting state changed between admission and registration.
pub fn register_admitted_block(
    state: &mut ConsensusState,
    admitted: AdmittedBlock,
    event_time: EventTime,
) -> Result<RegistrationOutcome, AdmissionError> {
    check_state_gates(state, admitted.block_hash, admitted.block())?;
    let block_hash = admitted.block_hash;
    let block = admitted.verified.into_block();

    let request_removed = state.requested_blocks.remove(&block_hash);
    let unknown_transactions: Vec<_> = block
        .transaction_hashes
        .iter()
        .copied()
        .filter(|hash| !state.transactions.contains_key(hash))
        .collect();
    for hash in &unknown_transactions {
        state.transactions.insert(
            *hash,
            TransactionRecord::UnknownPlaceholder {
                observed_at: event_time,
            },
        );
    }

    let forward = if state.forwarding_disabled {
        ForwardDisposition::Disabled
    } else if state.forward_channel.closed {
        ForwardDisposition::Closed
    } else {
        state.forward_channel.records.push(OutboundBlock {
            block_hash,
            block: block.clone(),
        });
        if state.forward_channel.waker_registered {
            state.forward_channel.wake_count = state.forward_channel.wake_count.saturating_add(1);
        }
        ForwardDisposition::Queued
    };

    let old = state.blocks.insert(block_hash, RegisteredBlock { block });
    debug_assert!(old.is_none(), "state gates reject replacement");
    Ok(RegistrationOutcome {
        block_hash,
        request_removed,
        unknown_transactions,
        forward,
    })
}

/// Execute verification, admission, and registration without mutating state on failure.
pub fn admit_and_register<A: AdmissionAuthenticator>(
    state: &mut ConsensusState,
    history: &StakeHistory,
    authenticator: &A,
    block_hash: BlockHash,
    block: &SignedBlock,
    event_time: EventTime,
) -> Result<RegistrationOutcome, VerificationFailure> {
    let verified = verify_block(history, authenticator, block)?;
    let admitted = admit_verified_block(state, block_hash, verified)?;
    Ok(register_admitted_block(state, admitted, event_time)?)
}

fn check_state_gates(
    state: &ConsensusState,
    block_hash: BlockHash,
    block: &SignedBlock,
) -> Result<(), AdmissionError> {
    if block.round < state.committed_round {
        return Err(AdmissionError::BlockRound {
            block: block.round,
            committed: state.committed_round,
        });
    }
    if state.blocks.contains_key(&block_hash) {
        return Err(AdmissionError::BlockAlreadyRegistered(block_hash));
    }
    if let Some((known, _)) = state
        .blocks
        .iter()
        .find(|(_, record)| record.block.round == block.round)
    {
        return Err(AdmissionError::DuplicateBlockRound {
            known: *known,
            new: block_hash,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        AuthenticationError, Hardfork, Qc, QcVote, SignatureBytes, StakeSnapshot, Tc,
        ValidatorAddress,
    };

    struct Auth;

    impl AdmissionAuthenticator for Auth {
        fn expected_proposer(
            &self,
            _round: Round,
            _eligible: &[ValidatorAddress],
        ) -> Result<ValidatorAddress, AuthenticationError> {
            Ok(address(1))
        }

        fn recover_qc_vote_signer(
            &self,
            _qc: &Qc,
            signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            Ok(address(signature.0[0]))
        }

        fn recover_timeout_vote_signer(
            &self,
            _qc: &Qc,
            _round: Round,
            signature: &SignatureBytes,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            Ok(address(signature.0[0]))
        }

        fn recover_block_signer(
            &self,
            block: &SignedBlock,
        ) -> Result<ValidatorAddress, AuthenticationError> {
            Ok(address(block.signature.0[0]))
        }
    }

    fn address(value: u8) -> ValidatorAddress {
        ValidatorAddress([value; 20])
    }

    fn hash(value: u8) -> BlockHash {
        BlockHash([value; 32])
    }

    fn tx(value: u8) -> TransactionHash {
        TransactionHash([value; 32])
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

    fn block(round: u64, transactions: Vec<TransactionHash>) -> SignedBlock {
        SignedBlock {
            transaction_hashes: transactions,
            qc: Qc {
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
                round: Round(round - 1),
                block_hash: hash(90),
            },
            tc: None::<Tc>,
            round: Round(round),
            proposer: address(1),
            signature: signature(1),
        }
    }

    fn now() -> EventTime {
        EventTime {
            date: 20_000,
            seconds: 7,
            nanoseconds: 8,
        }
    }

    #[test]
    fn successful_registration_removes_request_and_inserts_placeholders() {
        let mut state = ConsensusState::new(Round(500));
        state.requested_blocks.insert(hash(10));
        state.transactions.insert(tx(1), TransactionRecord::Known);
        let candidate = block(1_000, vec![tx(1), tx(2), tx(2)]);

        let outcome =
            admit_and_register(&mut state, &history(), &Auth, hash(10), &candidate, now()).unwrap();
        assert!(outcome.request_removed);
        assert_eq!(outcome.unknown_transactions, vec![tx(2), tx(2)]);
        assert_eq!(
            state.transactions.get(&tx(2)),
            Some(&TransactionRecord::UnknownPlaceholder { observed_at: now() })
        );
        assert_eq!(
            state.transactions.get(&tx(1)),
            Some(&TransactionRecord::Known)
        );
        assert!(state.blocks.contains_key(&hash(10)));
    }

    #[test]
    fn closed_channel_drops_only_the_outbound_record() {
        let mut state = ConsensusState::new(Round(500));
        state.forward_channel.closed = true;
        let outcome = admit_and_register(
            &mut state,
            &history(),
            &Auth,
            hash(10),
            &block(1_000, Vec::new()),
            now(),
        )
        .unwrap();
        assert_eq!(outcome.forward, ForwardDisposition::Closed);
        assert!(state.forward_channel.records.is_empty());
        assert!(state.blocks.contains_key(&hash(10)));
    }

    #[test]
    fn open_channel_queues_and_wakes_once() {
        let mut state = ConsensusState::new(Round(500));
        state.forward_channel.waker_registered = true;
        let outcome = admit_and_register(
            &mut state,
            &history(),
            &Auth,
            hash(10),
            &block(1_000, Vec::new()),
            now(),
        )
        .unwrap();
        assert_eq!(outcome.forward, ForwardDisposition::Queued);
        assert_eq!(state.forward_channel.records.len(), 1);
        assert_eq!(state.forward_channel.wake_count, 1);
    }

    #[test]
    fn committed_duplicate_hash_and_duplicate_round_are_ordered() {
        let mut state = ConsensusState::new(Round(1_001));
        state.blocks.insert(
            hash(10),
            RegisteredBlock {
                block: block(1_000, Vec::new()),
            },
        );
        let verified = verify_block(&history(), &Auth, &block(1_000, Vec::new())).unwrap();
        assert!(matches!(
            admit_verified_block(&state, hash(10), verified.clone()),
            Err(AdmissionError::BlockRound { .. })
        ));

        state.committed_round = Round(500);
        assert_eq!(
            admit_verified_block(&state, hash(10), verified.clone()),
            Err(AdmissionError::BlockAlreadyRegistered(hash(10)))
        );
        assert!(matches!(
            admit_verified_block(&state, hash(11), verified),
            Err(AdmissionError::DuplicateBlockRound { known, new })
                if known == hash(10) && new == hash(11)
        ));
    }

    #[test]
    fn first_same_round_block_is_selected_in_hash_order() {
        let mut state = ConsensusState::new(Round(500));
        state.blocks.insert(
            hash(20),
            RegisteredBlock {
                block: block(1_000, Vec::new()),
            },
        );
        state.blocks.insert(
            hash(10),
            RegisteredBlock {
                block: block(1_000, Vec::new()),
            },
        );
        let verified = verify_block(&history(), &Auth, &block(1_000, Vec::new())).unwrap();
        assert!(matches!(
            admit_verified_block(&state, hash(30), verified),
            Err(AdmissionError::DuplicateBlockRound { known, .. }) if known == hash(10)
        ));
    }

    #[test]
    fn every_rejection_preserves_state() {
        let mut state = ConsensusState::new(Round(1_001));
        state.requested_blocks.insert(hash(10));
        let before = state.clone();
        let result = admit_and_register(
            &mut state,
            &history(),
            &Auth,
            hash(10),
            &block(1_000, vec![tx(1)]),
            now(),
        );
        assert!(matches!(
            result,
            Err(VerificationFailure::Rejected(
                AdmissionError::BlockRound { .. }
            ))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn stale_admission_token_cannot_overwrite_new_state() {
        let mut state = ConsensusState::new(Round(500));
        let verified = verify_block(&history(), &Auth, &block(1_000, Vec::new())).unwrap();
        let admitted = admit_verified_block(&state, hash(10), verified).unwrap();
        state.blocks.insert(
            hash(10),
            RegisteredBlock {
                block: block(999, Vec::new()),
            },
        );
        let before = state.clone();
        assert_eq!(
            register_admitted_block(&mut state, admitted, now()),
            Err(AdmissionError::BlockAlreadyRegistered(hash(10)))
        );
        assert_eq!(state, before);
    }
}
