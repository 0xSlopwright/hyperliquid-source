use core::fmt;

use crate::{
    ChunkPlan, CompressionSizeError, Header, HeaderError, compressed_allocation_len,
    should_compress,
};

/// A complete offline-encoded frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    /// Header emitted by the writer.
    pub header: Header,
    bytes: Vec<u8>,
}

impl EncodedFrame {
    /// Returns the complete `[header][payload]` wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers ownership of the complete wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Plans the writer's 4,000,000-byte chunks over the complete frame.
    #[must_use]
    pub fn chunks(&self) -> ChunkPlan {
        ChunkPlan::new(self.bytes.len() as u64)
    }
}

/// Failures from the evidence-bounded offline writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The final raw or compressed payload does not fit the wire u32 length.
    Header(HeaderError),
    /// The verified compression capacity arithmetic overflowed.
    CompressionSize(CompressionSizeError),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(error) => error.fmt(formatter),
            Self::CompressionSize(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Header(error) => Some(error),
            Self::CompressionSize(error) => Some(error),
        }
    }
}

impl From<HeaderError> for EncodeError {
    fn from(error: HeaderError) -> Self {
        Self::Header(error)
    }
}

impl From<CompressionSizeError> for EncodeError {
    fn from(error: CompressionSizeError) -> Self {
        Self::CompressionSize(error)
    }
}

/// Encodes one complete frame using the verified threshold and port policy.
///
/// This function performs no I/O. It always emits flag 0 for raw payloads and
/// flag 1 for LZ4 payloads.
pub fn encode_frame(payload: &[u8], port: u16) -> Result<EncodedFrame, EncodeError> {
    let compressed = should_compress(payload.len() as u64, port);
    let wire_payload = if compressed {
        // Preserve the target's checked sizing failure before asking the pinned
        // crate to allocate its output vector.
        compressed_allocation_len(payload.len() as u64)?;
        lz4_flex::block::compress_prepend_size(payload)
    } else {
        payload.to_vec()
    };

    let header = Header::from_payload_len(wire_payload.len(), u8::from(compressed))?;
    let mut bytes = Vec::with_capacity(5 + wire_payload.len());
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&wire_payload);

    Ok(EncodedFrame { header, bytes })
}
