//! Offline reconstruction of the bounded node #94 action-signable path.
//!
//! The caller supplies already-serialized action bytes. This crate does not
//! implement MessagePack serialization, EIP-712, signatures, keys, or network
//! operations.

#![forbid(unsafe_code)]

mod context;
mod layout;
mod preimage;

pub use context::{
    ChainSelector, ConnectionId, EncodedAction, FixedBytesError, FixedBytesField, SignableContext,
    SignatureChainId, VaultAddress,
};
pub use layout::{TARGET_SHA256, TargetContextLayout, TargetFunction};
pub use preimage::{BuildError, build_preimage, preimage_len, signing_suffix_len};

#[cfg(test)]
mod tests;
