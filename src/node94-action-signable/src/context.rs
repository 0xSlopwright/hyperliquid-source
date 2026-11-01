use core::fmt;

/// Action bytes produced by an external serializer.
///
/// No action wire format is inferred or validated by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedAction<'a> {
    bytes: &'a [u8],
}

impl<'a> EncodedAction<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn len(self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
}

/// Exact 20-byte vault address copied by the observed present branch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VaultAddress([u8; Self::LENGTH]);

impl VaultAddress {
    pub const LENGTH: usize = 20;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedBytesError> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes).map_err(|_| FixedBytesError {
            field: FixedBytesField::VaultAddress,
            expected: Self::LENGTH,
            actual: bytes.len(),
        })?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Exact 32-byte value copied into the embedded payload's first field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureChainId([u8; Self::LENGTH]);

impl SignatureChainId {
    pub const LENGTH: usize = 32;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedBytesError> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes).map_err(|_| FixedBytesError {
            field: FixedBytesField::SignatureChainId,
            expected: Self::LENGTH,
            actual: bytes.len(),
        })?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Keccak-256 connection digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId([u8; Self::LENGTH]);

impl ConnectionId {
    pub const LENGTH: usize = 32;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedBytesError> {
        let bytes = <[u8; Self::LENGTH]>::try_from(bytes).map_err(|_| FixedBytesError {
            field: FixedBytesField::ConnectionId,
            expected: Self::LENGTH,
            actual: bytes.len(),
        })?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// The one-byte selector passed separately to the bounded target functions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainSelector(u8);

impl ChainSelector {
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl From<u8> for ChainSelector {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

/// Established inputs read from the target context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignableContext {
    pub nonce: u64,
    pub vault_address: Option<VaultAddress>,
    pub expires_after: Option<u64>,
}

impl SignableContext {
    #[must_use]
    pub const fn new(
        nonce: u64,
        vault_address: Option<VaultAddress>,
        expires_after: Option<u64>,
    ) -> Self {
        Self {
            nonce,
            vault_address,
            expires_after,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedBytesField {
    VaultAddress,
    SignatureChainId,
    ConnectionId,
}

impl fmt::Display for FixedBytesField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VaultAddress => "vault address",
            Self::SignatureChainId => "signature chain id",
            Self::ConnectionId => "connection id",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedBytesError {
    pub field: FixedBytesField,
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for FixedBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must contain exactly {} bytes; got {}",
            self.field, self.expected, self.actual
        )
    }
}

impl std::error::Error for FixedBytesError {}
