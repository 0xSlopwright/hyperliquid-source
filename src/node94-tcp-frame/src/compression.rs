use core::fmt;

/// Smallest input length that reaches the verified writer compression path.
pub const COMPRESSION_THRESHOLD: u64 = 1_025;

const EXCLUDED_PORT_MASKED: u16 = 3_998;
const CAPACITY_PERCENT: u64 = 110;
const OUTPUT_OVERHEAD: u64 = 20;
const ALLOCATION_OVERHEAD: u64 = 24;

/// Hash-table entry width selected by the pinned LZ4 writer path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashTableWidth {
    /// 4,096 u16 entries (8 KiB), used below `u16::MAX` bytes.
    U16,
    /// 4,096 u32 entries (16 KiB), used at and above `u16::MAX` bytes.
    U32,
}

/// Returns whether the verified writer selects compression.
///
/// The masked comparison excludes exactly ports 3998 and 3999.
#[must_use]
pub const fn should_compress(input_len: u64, port: u16) -> bool {
    input_len >= COMPRESSION_THRESHOLD && (port & !1) != EXCLUDED_PORT_MASKED
}

/// Returns the observed LZ4 hash-table width boundary.
#[must_use]
pub const fn hash_table_width(input_len: u64) -> HashTableWidth {
    if input_len < u16::MAX as u64 {
        HashTableWidth::U16
    } else {
        HashTableWidth::U32
    }
}

/// Returns the verified output window after the four-byte size prefix.
pub fn compressed_output_capacity(input_len: u64) -> Result<u64, CompressionSizeError> {
    let scaled =
        input_len
            .checked_mul(CAPACITY_PERCENT)
            .ok_or(CompressionSizeError::CapacityOverflow {
                input_len,
                operation: "input_len * 110",
            })?
            / 100;
    scaled
        .checked_add(OUTPUT_OVERHEAD)
        .ok_or(CompressionSizeError::CapacityOverflow {
            input_len,
            operation: "scaled_len + 20",
        })
}

/// Returns the verified zeroed allocation length, including prefix and vector overhead.
pub fn compressed_allocation_len(input_len: u64) -> Result<u64, CompressionSizeError> {
    let scaled =
        input_len
            .checked_mul(CAPACITY_PERCENT)
            .ok_or(CompressionSizeError::CapacityOverflow {
                input_len,
                operation: "input_len * 110",
            })?
            / 100;
    scaled
        .checked_add(ALLOCATION_OVERHEAD)
        .ok_or(CompressionSizeError::CapacityOverflow {
            input_len,
            operation: "scaled_len + 24",
        })
}

/// Returns the writer's truncating little-endian uncompressed-size prefix.
///
/// The cast intentionally preserves the target's low 32 bits. The complete
/// frame writer separately rejects a final payload length that does not fit a
/// wire u32.
#[must_use]
pub const fn compression_size_prefix(input_len: u64) -> [u8; 4] {
    (input_len as u32).to_le_bytes()
}

/// Checked-size failures corresponding to the target's overflow-checked math.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionSizeError {
    /// The observed capacity arithmetic cannot be represented in u64.
    CapacityOverflow {
        input_len: u64,
        operation: &'static str,
    },
}

impl fmt::Display for CompressionSizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityOverflow {
                input_len,
                operation,
            } => write!(
                formatter,
                "compression capacity overflow for input length {input_len} during {operation}"
            ),
        }
    }
}

impl std::error::Error for CompressionSizeError {}
