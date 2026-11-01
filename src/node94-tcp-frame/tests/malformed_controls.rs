use node94_tcp_frame::{
    DecodeError, FrameLimits, Header, LengthError, Lz4DecodeError, decode_frame, encode_frame,
};

fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let header = Header::from_payload_len(payload.len(), flag).unwrap();
    let mut wire = Vec::from(header.encode());
    wire.extend_from_slice(payload);
    wire
}

#[test]
fn truncating_each_byte_of_a_complete_raw_frame_never_succeeds() {
    let wire = frame(0, b"negative-control");
    for available in 0..wire.len() {
        assert!(
            decode_frame(&wire[..available], FrameLimits::new(64)).is_err(),
            "truncation at {available} bytes was admitted"
        );
    }
}

#[test]
fn mutating_raw_flag_to_one_changes_the_interpretation() {
    let mut wire = frame(0, b"hello");
    assert_eq!(
        decode_frame(&wire, FrameLimits::new(5)).unwrap().payload,
        b"hello"
    );

    wire[4] = 1;
    assert_eq!(
        decode_frame(&wire, FrameLimits::new(5)),
        Err(DecodeError::Length(LengthError::DecompressedTooLarge {
            compressed_payload_len: 5,
            uncompressed_size: u32::from_le_bytes(*b"hell"),
            max: 5,
        }))
    );
}

#[test]
fn mutating_compressed_flag_to_two_prevents_decompression() {
    let payload = b"compress-me".repeat(200);
    let encoded = encode_frame(&payload, 4001).unwrap();
    assert_eq!(encoded.header.compression_flag, 1);

    let mut wire = encoded.into_bytes();
    wire[4] = 2;
    let decoded = decode_frame(&wire, FrameLimits::new(wire.len() as u64)).unwrap();
    assert_ne!(decoded.payload, payload);
    assert_eq!(decoded.payload, wire[5..]);
}

#[test]
fn corrupting_prefix_endianness_is_caught_by_the_decoded_limit() {
    let block = b"\x50hello";
    let mut payload = Vec::from(5_u32.to_le_bytes());
    payload.extend_from_slice(block);
    let mut wire = frame(1, &payload);
    wire[5..9].copy_from_slice(&5_u32.to_be_bytes());

    assert_eq!(
        decode_frame(&wire, FrameLimits::new(1_000)),
        Err(DecodeError::Length(LengthError::DecompressedTooLarge {
            compressed_payload_len: 10,
            uncompressed_size: 0x0500_0000,
            max: 1_000,
        }))
    );
}

#[test]
fn zero_and_out_of_range_offsets_have_distinct_errors() {
    let cases: &[(&[u8], Lz4DecodeError)] = &[
        (b"\x00\x00\x00", Lz4DecodeError::OffsetZero),
        (b"\x00\x01\x00", Lz4DecodeError::OffsetOutOfBounds),
    ];
    for &(block, ref expected) in cases {
        let mut payload = Vec::from(4_u32.to_le_bytes());
        payload.extend_from_slice(block);
        assert_eq!(
            decode_frame(&frame(1, &payload), FrameLimits::new(7)),
            Err(DecodeError::Lz4(expected.clone()))
        );
    }
}

#[test]
fn declared_length_mutation_cannot_hide_payload_eof() {
    let mut wire = frame(0, b"abc");
    wire[..4].copy_from_slice(&4_u32.to_be_bytes());
    assert_eq!(
        decode_frame(&wire, FrameLimits::new(4)),
        Err(DecodeError::UnexpectedPayloadEof {
            declared: 4,
            actual: 3,
        })
    );
}
