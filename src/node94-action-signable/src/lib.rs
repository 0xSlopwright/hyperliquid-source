//! Offline reconstruction of the bounded node #94 action-signable path.
//!
//! The caller supplies already-serialized action bytes. This crate does not
//! implement MessagePack serialization, EIP-712, signatures, keys, or network
//! operations.

#![forbid(unsafe_code)]

mod context;
mod keccak;
mod layout;
mod payload;
mod preimage;

pub use context::{
    ChainSelector, ConnectionId, EncodedAction, FixedBytesError, FixedBytesField, SignableContext,
    SignatureChainId, VaultAddress,
};
pub use keccak::{KECCAK_DELIMITER, KECCAK_OUTPUT_LENGTH, KECCAK_RATE, keccak256};
pub use layout::{TARGET_SHA256, TargetContextLayout, TargetFunction};
pub use payload::{
    ACTION_CHAIN_ID, AgentPayload, AgentSource, EmbeddedPayload, ZeroVerifyingContract,
    build_agent_payload, build_embedded_payload, connection_id,
};
pub use preimage::{BuildError, build_preimage, preimage_len, signing_suffix_len};

#[cfg(test)]
mod tests;
