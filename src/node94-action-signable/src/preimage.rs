use core::fmt;

use crate::{EncodedAction, SignableContext};

const NONCE_LENGTH: usize = 8;
const ABSENT_VAULT_LENGTH: usize = 1;
const PRESENT_VAULT_LENGTH: usize = 1 + 20;
const PRESENT_EXPIRY_LENGTH: usize = 1 + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    LengthOverflow,
    AllocationFailed { requested: usize },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => formatter.write_str("action-signable preimage length overflow"),
            Self::AllocationFailed { requested } => {
                write!(formatter, "could not allocate {requested} preimage bytes")
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[must_use]
pub const fn signing_suffix_len(context: &SignableContext) -> usize {
    NONCE_LENGTH
        + if context.vault_address.is_some() {
            PRESENT_VAULT_LENGTH
        } else {
            ABSENT_VAULT_LENGTH
        }
        + if context.expires_after.is_some() {
            PRESENT_EXPIRY_LENGTH
        } else {
            0
        }
}

pub const fn preimage_len(
    action: EncodedAction<'_>,
    context: &SignableContext,
) -> Result<usize, BuildError> {
    match action.len().checked_add(signing_suffix_len(context)) {
        Some(length) => Ok(length),
        None => Err(BuildError::LengthOverflow),
    }
}

/// Builds the established byte sequence without interpreting `action`.
pub fn build_preimage(
    action: EncodedAction<'_>,
    context: &SignableContext,
) -> Result<Vec<u8>, BuildError> {
    let length = preimage_len(action, context)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| BuildError::AllocationFailed { requested: length })?;
    output.extend_from_slice(action.as_bytes());
    output.extend_from_slice(&context.nonce.to_be_bytes());
    match context.vault_address {
        Some(vault) => {
            output.push(1);
            output.extend_from_slice(vault.as_bytes());
        }
        None => output.push(0),
    }
    if let Some(expires_after) = context.expires_after {
        output.push(0);
        output.extend_from_slice(&expires_after.to_be_bytes());
    }
    debug_assert_eq!(output.len(), length);
    Ok(output)
}
