use core::fmt;

/// Number of bytes in the verified node #94 frame header.
pub const HEADER_LEN: usize = 5;

/// The complete five-byte wire header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Number of payload bytes following the header.
    pub payload_len: u32,
    /// Wire flag byte. Exactly `1` selects LZ4 decoding.
    pub compression_flag: u8,
}

impl Header {
    /// Constructs a header after checking that the payload length fits the wire u32.
    pub fn from_payload_len(payload_len: usize, compression_flag: u8) -> Result<Self, HeaderError> {
        let payload_len =
            u32::try_from(payload_len).map_err(|_| HeaderError::LengthNotRepresentable {
                payload_len: payload_len as u64,
            })?;
        Ok(Self {
            payload_len,
            compression_flag,
        })
    }

    /// Decodes the verified `[u32 big-endian length][u8 flag]` layout.
    pub fn decode(input: &[u8]) -> Result<Self, HeaderError> {
        let bytes = input.get(..HEADER_LEN).ok_or(HeaderError::UnexpectedEof {
            expected: HEADER_LEN,
            actual: input.len(),
        })?;
        Ok(Self {
            payload_len: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            compression_flag: bytes[4],
        })
    }

    /// Encodes the complete header without interpreting or normalizing its flag.
    #[must_use]
    pub const fn encode(self) -> [u8; HEADER_LEN] {
        let length = self.payload_len.to_be_bytes();
        [
            length[0],
            length[1],
            length[2],
            length[3],
            self.compression_flag,
        ]
    }

    /// Returns whether the reader selects the verified compressed path.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.compression_flag == 1
    }
}

/// Header construction and decoding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    /// Fewer than five bytes were available for the target's read-exact operation.
    UnexpectedEof { expected: usize, actual: usize },
    /// A writer payload cannot be represented by the wire u32 length.
    LengthNotRepresentable { payload_len: u64 },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { expected, actual } => write!(
                formatter,
                "unexpected EOF while reading frame header: expected {expected} bytes, got {actual}"
            ),
            Self::LengthNotRepresentable { payload_len } => write!(
                formatter,
                "frame payload length {payload_len} does not fit the wire u32"
            ),
        }
    }
}

impl std::error::Error for HeaderError {}
