use crate::{Qc, QcVote, Round, SignedBlock, TimeoutVote, ValidatorAddress};

/// Failure returned by the still-external cryptographic/proposer boundary.
///
/// The detail is deliberately typed and bounded.  It does not pretend to be
/// one of the target's recovered consensus tags when that mapping is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    ProposerSelection,
    QcVoteSignature,
    TimeoutVoteSignature,
    BlockSignature,
}

/// Explicit boundary for behavior not yet recovered from node #94.
///
/// Implementations must derive the expected proposer and verify signatures
/// from their signed message fields.  Admission code calls these methods in
/// the target-observed order.  The interface accepts no caller-supplied
/// `is_valid` value and therefore cannot accidentally promote a boolean into
/// cryptographic evidence.
pub trait AdmissionAuthenticator {
    fn expected_proposer(
        &self,
        round: Round,
        eligible: &[ValidatorAddress],
    ) -> Result<ValidatorAddress, AuthenticationError>;

    fn verify_qc_vote(&self, qc: &Qc, vote: &QcVote) -> Result<(), AuthenticationError>;

    fn verify_timeout_vote(&self, vote: &TimeoutVote) -> Result<(), AuthenticationError>;

    fn verify_block_signature(&self, block: &SignedBlock) -> Result<(), AuthenticationError>;
}
