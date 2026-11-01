use node94_tcp_frame::{
    COMPRESSION_THRESHOLD, CompressionSizeError, HashTableWidth, compressed_allocation_len,
    compressed_output_capacity, compression_size_prefix, hash_table_width, should_compress,
};

#[test]
fn threshold_is_inclusive() {
    assert!(!should_compress(COMPRESSION_THRESHOLD - 1, 4001));
    assert!(should_compress(COMPRESSION_THRESHOLD, 4001));
}

#[test]
fn masked_stream_field_rule_excludes_exactly_3998_and_3999_nearby() {
    let selected: Vec<_> = (3996_u16..=4001)
        .filter(|stream_field| should_compress(COMPRESSION_THRESHOLD, *stream_field))
        .collect();
    assert_eq!(selected, [3996, 3997, 4000, 4001]);
}

#[test]
fn output_and_allocation_sizes_match_verified_formula() {
    let cases = [0, 1, 100, 1_025, 65_534, 65_535, 4_000_000];
    for input_len in cases {
        let scaled = input_len * 110 / 100;
        assert_eq!(compressed_output_capacity(input_len), Ok(scaled + 20));
        assert_eq!(compressed_allocation_len(input_len), Ok(scaled + 24));
    }
}

#[test]
fn hash_table_width_switches_at_u16_max() {
    assert_eq!(hash_table_width(u16::MAX as u64 - 1), HashTableWidth::U16);
    assert_eq!(hash_table_width(u16::MAX as u64), HashTableWidth::U32);
}

#[test]
fn size_prefix_is_little_endian_and_truncating() {
    assert_eq!(compression_size_prefix(0x0102_0304), [4, 3, 2, 1]);
    assert_eq!(compression_size_prefix((1_u64 << 32) + 5), [5, 0, 0, 0]);
}

#[test]
fn capacity_multiplication_overflow_is_explicit() {
    assert_eq!(
        compressed_output_capacity(u64::MAX),
        Err(CompressionSizeError::CapacityOverflow {
            input_len: u64::MAX,
            operation: "input_len * 110",
        })
    );
    assert_eq!(
        compressed_allocation_len(u64::MAX),
        Err(CompressionSizeError::CapacityOverflow {
            input_len: u64::MAX,
            operation: "input_len * 110",
        })
    );
}

#[test]
fn negative_control_saturating_prefix_would_not_match() {
    let input_len = (1_u64 << 32) + 5;
    assert_eq!(compression_size_prefix(input_len), [5, 0, 0, 0]);
    assert_ne!(compression_size_prefix(input_len), u32::MAX.to_le_bytes());
}
