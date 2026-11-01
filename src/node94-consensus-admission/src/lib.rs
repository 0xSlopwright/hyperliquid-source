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
mod types;

pub use auth::{AdmissionAuthenticator, AuthenticationError};
pub use error::{AdmissionError, FatalAdmissionError};
pub use types::{
    BlockHash, EventTime, Hardfork, Qc, QcVote, Round, SignatureBytes, SignedBlock, Tc,
    TimeoutVote, TransactionHash, ValidatorAddress,
};
