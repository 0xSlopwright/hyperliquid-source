use core::fmt;

use crate::Header;

/// Verified payload chunk cap used by both frame readers and writers.
pub const CHUNK_LEN: u64 = 4_000_000;

/// Configured frame/decompression limit passed through the verified read path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimits {
    max_len: u64,
}

impl FrameLimits {
    /// Constructs an inclusive maximum length.
    #[must_use]
    pub const fn new(max_len: u64) -> Self {
        Self { max_len }
    }

    /// Returns the configured inclusive maximum.
    #[must_use]
    pub const fn max_len(self) -> u64 {
        self.max_len
    }

    /// Applies the target's inclusive frame-payload admission predicate.
    pub const fn admit(self, header: Header) -> Result<(), LengthError> {
        let declared = header.payload_len as u64;
        if declared <= self.max_len {
            Ok(())
        } else {
            Err(LengthError::FrameTooLarge {
                declared: header.payload_len,
                max: self.max_len,
            })
        }
    }

    /// Applies the same inclusive limit to the LZ4 uncompressed-size prefix.
    pub const fn admit_uncompressed_size(
        self,
        compressed_payload_len: u32,
        uncompressed_size: u32,
    ) -> Result<(), LengthError> {
        if uncompressed_size as u64 <= self.max_len {
            Ok(())
        } else {
            Err(LengthError::DecompressedTooLarge {
                compressed_payload_len,
                uncompressed_size,
                max: self.max_len,
            })
        }
    }
}

/// Explicit rejections from the two verified inclusive length gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthError {
    /// The big-endian frame payload length exceeds the configured limit.
    FrameTooLarge { declared: u32, max: u64 },
    /// The little-endian LZ4 size prefix exceeds the same configured limit.
    DecompressedTooLarge {
        compressed_payload_len: u32,
        uncompressed_size: u32,
        max: u64,
    },
}

impl fmt::Display for LengthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { declared, max } => {
                write!(
                    formatter,
                    "frame payload length {declared} exceeds configured limit {max}"
                )
            }
            Self::DecompressedTooLarge {
                compressed_payload_len,
                uncompressed_size,
                max,
            } => write!(
                formatter,
                "lz4 bytes over limit: payload length {compressed_payload_len}, uncompressed size {uncompressed_size}, configured limit {max}"
            ),
        }
    }
}

impl std::error::Error for LengthError {}

/// One contiguous range selected by the verified chunk calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunk {
    /// Byte offset from the start of the chunked region.
    pub offset: u64,
    /// Number of bytes in this chunk, never greater than [`CHUNK_LEN`].
    pub len: u64,
}

/// Allocation-free iterator over `min(remaining, 4_000_000)` chunks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkPlan {
    total: u64,
    offset: u64,
}

impl ChunkPlan {
    /// Plans chunks for a payload (reader) or complete frame (writer).
    #[must_use]
    pub const fn new(total: u64) -> Self {
        Self { total, offset: 0 }
    }

    /// Number of chunks remaining, including a possible partial tail.
    #[must_use]
    pub const fn remaining_chunks(self) -> u64 {
        let remaining = self.total - self.offset;
        remaining / CHUNK_LEN + (!remaining.is_multiple_of(CHUNK_LEN)) as u64
    }
}

impl Iterator for ChunkPlan {
    type Item = Chunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.total {
            return None;
        }
        let remaining = self.total - self.offset;
        let len = remaining.min(CHUNK_LEN);
        let chunk = Chunk {
            offset: self.offset,
            len,
        };
        self.offset = self.offset.saturating_add(len);
        Some(chunk)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match usize::try_from(self.remaining_chunks()) {
            Ok(count) => (count, Some(count)),
            Err(_) => (usize::MAX, None),
        }
    }
}
