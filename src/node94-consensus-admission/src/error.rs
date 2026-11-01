use crate::{AuthenticationError, BlockHash, Hardfork, Round, ValidatorAddress};

/// Recoverable admission errors and their target niche tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Hardfork {
        qc: Hardfork,
        node: Hardfork,
    },
    Signature,
    QcVoteSignature,
    BlockRound {
        block: Round,
        committed: Round,
    },
    BadQcRound,
    BadTcRound,
    BlockAlreadyRegistered(BlockHash),
    QcRoundBeforeHardfork,
    QcGenesisInvalid,
    QcNoQuorum,
    TcNoQuorum,
    TcNoTimeout,
    BadBlockProposer {
        proposed: ValidatorAddress,
        expected: ValidatorAddress,
    },
    DuplicateBlockRound {
        known: BlockHash,
        new: BlockHash,
    },
    TimeoutRoundMismatch {
        supplied: Round,
        expected: Round,
    },
    MissingValidatorSetRound(Round),
    Authentication(AuthenticationError),
}

impl AdmissionError {
    /// Return the recovered low-byte niche tag, when the target mapping is known.
    pub fn target_tag(&self) -> Option<u8> {
        match self {
            Self::Hardfork { .. } => Some(0x00),
            Self::Signature => Some(0x01),
            Self::QcVoteSignature => Some(0x02),
            Self::BlockRound { .. } => Some(0x03),
            Self::BadQcRound => Some(0x04),
            Self::BadTcRound => Some(0x05),
            Self::BlockAlreadyRegistered(_) => Some(0x06),
            Self::QcRoundBeforeHardfork => Some(0x07),
            Self::QcGenesisInvalid => Some(0x08),
            Self::QcNoQuorum => Some(0x09),
            Self::TcNoQuorum => Some(0x0a),
            Self::TcNoTimeout => Some(0x0b),
            Self::BadBlockProposer { .. } => Some(0x0c),
            Self::DuplicateBlockRound { .. } => Some(0x0e),
            Self::TimeoutRoundMismatch { .. } => Some(0x0f),
            Self::MissingValidatorSetRound(_) => Some(0x28),
            Self::Authentication(error) => error.target_tag(),
        }
    }
}

/// Target paths that panic are surfaced explicitly instead of crashing a host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatalAdmissionError {
    StakeOverflow,
    NewerHardforkWithQuorum,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationFailure {
    Rejected(AdmissionError),
    Fatal(FatalAdmissionError),
}

impl From<AdmissionError> for VerificationFailure {
    fn from(error: AdmissionError) -> Self {
        Self::Rejected(error)
    }
}

impl From<FatalAdmissionError> for VerificationFailure {
    fn from(error: FatalAdmissionError) -> Self {
        Self::Fatal(error)
    }
}
