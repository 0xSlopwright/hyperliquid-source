use crate::{Qc, Round, SignatureBytes, SignedBlock, ValidatorAddress};

/// Failure returned by the still-external cryptographic/proposer boundary.
///
/// The detail is deliberately typed and bounded.  It does not pretend to be
/// one of the target's recovered consensus tags when that mapping is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    ProposerSelection { target_tag: Option<u8> },
    QcVoteSignature,
    TimeoutVoteSignature,
    BlockSignature,
}

impl AuthenticationError {
    pub const fn proposer(target_tag: Option<u8>) -> Self {
        Self::ProposerSelection { target_tag }
    }

    pub const fn target_tag(self) -> Option<u8> {
        match self {
            Self::ProposerSelection { target_tag } => target_tag,
            Self::QcVoteSignature | Self::TimeoutVoteSignature | Self::BlockSignature => None,
        }
    }
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

    /// Recover an address from the QC signing fields and opaque signature.
    /// Admission separately checks membership and claimed-address equality.
    fn recover_qc_vote_signer(
        &self,
        qc: &Qc,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError>;

    /// Recover an address from digest variant 2's QC/round fields.
    fn recover_timeout_vote_signer(
        &self,
        qc: &Qc,
        round: Round,
        signature: &SignatureBytes,
    ) -> Result<ValidatorAddress, AuthenticationError>;

    fn recover_block_signer(
        &self,
        block: &SignedBlock,
    ) -> Result<ValidatorAddress, AuthenticationError>;
}
