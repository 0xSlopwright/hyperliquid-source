use std::fmt;

/// A validator key is compared as exactly 20 bytes by the recovered paths.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidatorAddress(pub [u8; 20]);

impl fmt::Debug for ValidatorAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatorAddress(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

/// A block identity is a 32-byte digest supplied by the authenticated boundary.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockHash(pub [u8; 32]);

impl fmt::Debug for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockHash(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

/// Transaction identities use the same recovered 32-byte key width.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionHash(pub [u8; 32]);

impl fmt::Debug for TransactionHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionHash(")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

/// Consensus rounds are unsigned 64-bit words in the target layouts.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Round(pub u64);

/// The two-word hardfork pair compared by the QC verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hardfork {
    pub version: u64,
    pub start_round: Round,
}

/// The recovered signature rows are 0x48 bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SignatureBytes(pub [u8; 0x48]);

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SignatureBytes")
            .field(&"<72 bytes>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QcVote {
    pub signer: ValidatorAddress,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Qc {
    pub votes: Vec<QcVote>,
    pub hardfork: Hardfork,
    pub round: Round,
    pub block_hash: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutVote {
    pub qc: Qc,
    pub round: Round,
    pub signer: ValidatorAddress,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tc {
    pub votes: Vec<TimeoutVote>,
    pub round: Round,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedBlock {
    pub transaction_hashes: Vec<TransactionHash>,
    pub qc: Qc,
    pub tc: Option<Tc>,
    pub round: Round,
    pub proposer: ValidatorAddress,
    pub signature: SignatureBytes,
}

/// The target stores three words for the event time copied into placeholders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventTime {
    pub date: u64,
    pub seconds: u64,
    pub nanoseconds: u64,
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
