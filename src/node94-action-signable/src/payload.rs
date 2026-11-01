use crate::{
    BuildError, ChainSelector, ConnectionId, EncodedAction, SignableContext, SignatureChainId,
    build_preimage, keccak256,
};

pub const ACTION_CHAIN_ID: u64 = 1337;
const SOURCE_A_SELECTOR: u8 = 3;

/// One-byte source selected by the observed `selector == 3` branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentSource {
    A,
    B,
}

impl AgentSource {
    #[must_use]
    pub const fn from_selector(selector: ChainSelector) -> Self {
        if selector.value() == SOURCE_A_SELECTOR {
            Self::A
        } else {
            Self::B
        }
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::A => b'a',
            Self::B => b'b',
        }
    }
}

/// Marker for the established all-zero verifying-contract output.
///
/// The target clears a 24-byte output region, but this safe semantic type does
/// not infer an EIP-712 address width or claim target ABI compatibility.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZeroVerifyingContract;

impl ZeroVerifyingContract {
    pub const OBSERVED_ZERO_REGION_LENGTH: usize = 24;

    #[must_use]
    pub const fn observed_zero_region(self) -> [u8; Self::OBSERVED_ZERO_REGION_LENGTH] {
        [0; Self::OBSERVED_ZERO_REGION_LENGTH]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentPayload {
    pub source: AgentSource,
    pub connection_id: ConnectionId,
    pub chain_id: u64,
    pub verifying_contract: ZeroVerifyingContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedPayload {
    pub signature_chain_id: SignatureChainId,
    pub connection_id: ConnectionId,
    pub nonce: u64,
    pub chain_selector: ChainSelector,
}

pub fn connection_id(
    action: EncodedAction<'_>,
    context: &SignableContext,
) -> Result<ConnectionId, BuildError> {
    Ok(keccak256(&build_preimage(action, context)?))
}

pub fn build_agent_payload(
    action: EncodedAction<'_>,
    context: &SignableContext,
    chain_selector: ChainSelector,
) -> Result<AgentPayload, BuildError> {
    Ok(AgentPayload {
        source: AgentSource::from_selector(chain_selector),
        connection_id: connection_id(action, context)?,
        chain_id: ACTION_CHAIN_ID,
        verifying_contract: ZeroVerifyingContract,
    })
}

pub fn build_embedded_payload(
    action: EncodedAction<'_>,
    context: &SignableContext,
    chain_selector: ChainSelector,
    signature_chain_id: SignatureChainId,
) -> Result<EmbeddedPayload, BuildError> {
    Ok(EmbeddedPayload {
        signature_chain_id,
        connection_id: connection_id(action, context)?,
        nonce: context.nonce,
        chain_selector,
    })
}
