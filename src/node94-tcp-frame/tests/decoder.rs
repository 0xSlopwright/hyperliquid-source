use node94_tcp_frame::{
    DecodeError, FrameLimits, Header, HeaderError, LengthError, Lz4DecodeError, decode_frame,
};

fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let header = Header::from_payload_len(payload.len(), flag).unwrap();
    let mut wire = Vec::from(header.encode());
    wire.extend_from_slice(payload);
    wire
}

fn lz4_payload(prefix: u32, block: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(prefix.to_le_bytes());
    payload.extend_from_slice(block);
    payload
}

#[test]
fn raw_empty_frame_decodes() {
    let decoded = decode_frame(&[0; 5], FrameLimits::new(0)).unwrap();
    assert_eq!(decoded.header.payload_len, 0);
    assert_eq!(decoded.payload, []);
    assert_eq!(decoded.consumed, 5);
}

#[test]
fn non_one_flag_is_raw_and_preserved() {
    let wire = frame(2, b"raw");
    let decoded = decode_frame(&wire, FrameLimits::new(3)).unwrap();
    assert_eq!(decoded.header.compression_flag, 2);
    assert_eq!(decoded.payload, b"raw");
}

#[test]
fn independently_authored_literal_only_lz4_fixture_decodes() {
    // LZ4 token 0x50: five literal bytes and no match because input ends.
    let payload = lz4_payload(5, b"\x50hello");
    let decoded = decode_frame(&frame(1, &payload), FrameLimits::new(10)).unwrap();
    assert_eq!(decoded.payload, b"hello");
}

#[test]
fn decoded_length_is_not_required_to_equal_prefix() {
    // The target allocates prefix bytes but stores min(write_position, prefix).
    let payload = lz4_payload(8, b"\x50hello");
    let decoded = decode_frame(&frame(1, &payload), FrameLimits::new(10)).unwrap();
    assert_eq!(decoded.payload, b"hello");
}

#[test]
fn trailing_bytes_are_not_consumed_as_part_of_the_frame() {
    let mut wire = frame(0, b"abc");
    wire.extend_from_slice(b"next");
    let decoded = decode_frame(&wire, FrameLimits::new(3)).unwrap();
    assert_eq!(decoded.payload, b"abc");
    assert_eq!(decoded.consumed, 8);
    assert_eq!(&wire[decoded.consumed..], b"next");
}

#[test]
fn frame_limit_is_checked_before_payload_eof() {
    let wire = [0, 0, 0, 10, 0];
    assert_eq!(
        decode_frame(&wire, FrameLimits::new(9)),
        Err(DecodeError::Length(LengthError::FrameTooLarge {
            declared: 10,
            max: 9,
        }))
    );
}

#[test]
fn every_truncated_header_and_payload_is_explicit() {
    let wire = frame(0, b"abc");
    for available in 0..5 {
        assert_eq!(
            decode_frame(&wire[..available], FrameLimits::new(3)),
            Err(DecodeError::Header(HeaderError::UnexpectedEof {
                expected: 5,
                actual: available,
            }))
        );
    }
    for payload_bytes in 0..3 {
        let available = 5 + payload_bytes;
        assert_eq!(
            decode_frame(&wire[..available], FrameLimits::new(3)),
            Err(DecodeError::UnexpectedPayloadEof {
                declared: 3,
                actual: payload_bytes,
            })
        );
    }
}

#[test]
fn compressed_payloads_shorter_than_prefix_are_expected_another_byte() {
    for payload_len in 0..=3 {
        let payload = vec![0; payload_len];
        assert_eq!(
            decode_frame(&frame(1, &payload), FrameLimits::new(16)),
            Err(DecodeError::Lz4(Lz4DecodeError::ExpectedAnotherByte))
        );
    }
}

#[test]
fn malformed_big_endian_size_prefix_hits_limit_before_decode() {
    let payload = lz4_payload(0x0100_0000, b"\x00");
    assert_eq!(
        decode_frame(&frame(1, &payload), FrameLimits::new(1_000)),
        Err(DecodeError::Length(LengthError::DecompressedTooLarge {
            compressed_payload_len: 5,
            uncompressed_size: 0x0100_0000,
            max: 1_000,
        }))
    );
}

#[test]
fn prefix_equal_to_limit_is_admitted_before_malformed_block() {
    let payload = lz4_payload(16, b"");
    assert_eq!(
        decode_frame(&frame(1, &payload), FrameLimits::new(16)),
        Err(DecodeError::Lz4(Lz4DecodeError::ExpectedAnotherByte))
    );
}

#[test]
fn pinned_lz4_error_classes_remain_distinct() {
    let cases: &[(u32, &[u8], Lz4DecodeError)] = &[
        (
            1,
            b"\x20ab",
            Lz4DecodeError::OutputTooSmall {
                expected: 2,
                actual: 1,
            },
        ),
        (1, b"\x10", Lz4DecodeError::LiteralOutOfBounds),
        (1, b"", Lz4DecodeError::ExpectedAnotherByte),
        (4, b"\x00\x00\x00", Lz4DecodeError::OffsetZero),
        (4, b"\x00\x01\x00", Lz4DecodeError::OffsetOutOfBounds),
    ];

    for &(prefix, block, ref expected) in cases {
        let payload = lz4_payload(prefix, block);
        let max_len = u64::from(prefix).max(payload.len() as u64);
        assert_eq!(
            decode_frame(&frame(1, &payload), FrameLimits::new(max_len)),
            Err(DecodeError::Lz4(expected.clone())),
            "prefix={prefix}, block={block:02x?}"
        );
    }
}
