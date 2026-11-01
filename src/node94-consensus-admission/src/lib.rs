//! Evidence-bounded reconstruction of node #94 consensus block admission.
//!
//! This crate reconstructs the stake-snapshot, QC, TC, ordered admission, and
//! registration behavior pinned by `RE-008-block-admission-94`.  Proposer
//! scheduling, digest construction, and signature recovery remain outside the
//! recovered native contract.  Callers supply those operations through
//! [`AdmissionAuthenticator`]; a bare boolean cannot cross that boundary.
//!
//! This is not a network service or a complete consensus implementation.

mod auth;
mod error;
mod qc;
mod stake;
mod types;

pub use auth::{AdmissionAuthenticator, AuthenticationError};
pub use error::{AdmissionError, FatalAdmissionError, VerificationFailure};
pub use qc::verify_qc;
pub use stake::{
    has_strict_two_thirds, Quorum, StakeHistory, StakeSnapshot, RECENT_ROUND_SPAN, STAKE_LAG_ROUNDS,
};
pub use types::{
    BlockHash, EventTime, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock, Tc,
    TimeoutVote, TransactionHash, ValidatorAddress,
};
