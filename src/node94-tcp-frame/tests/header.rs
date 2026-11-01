use node94_tcp_frame::{HEADER_LEN, Header, HeaderError};

#[test]
fn header_vector_matches_verified_big_endian_layout() {
    let header = Header {
        payload_len: 0x0102_0304,
        compression_flag: 1,
    };
    assert_eq!(header.encode(), [1, 2, 3, 4, 1]);
    assert_eq!(Header::decode(&header.encode()), Ok(header));
}

#[test]
fn empty_raw_header_is_supported() {
    let header = Header::from_payload_len(0, 0).unwrap();
    assert_eq!(header.encode(), [0; HEADER_LEN]);
    assert!(!header.is_compressed());
}

#[test]
fn only_flag_one_selects_compression() {
    let compressed_flags: Vec<_> = (0_u8..=u8::MAX)
        .filter(|flag| {
            Header {
                payload_len: 0,
                compression_flag: *flag,
            }
            .is_compressed()
        })
        .collect();
    assert_eq!(compressed_flags, [1]);
}

#[test]
fn every_truncated_header_is_an_explicit_eof() {
    let complete = [0, 0, 0, 1, 0];
    for available in 0..HEADER_LEN {
        assert_eq!(
            Header::decode(&complete[..available]),
            Err(HeaderError::UnexpectedEof {
                expected: HEADER_LEN,
                actual: available,
            })
        );
    }
}

#[test]
fn decode_uses_only_the_header_prefix() {
    let input = [0, 0, 0, 2, 7, 0xaa, 0xbb];
    assert_eq!(
        Header::decode(&input),
        Ok(Header {
            payload_len: 2,
            compression_flag: 7,
        })
    );
}

#[test]
fn maximum_wire_length_roundtrips() {
    let header = Header {
        payload_len: u32::MAX,
        compression_flag: u8::MAX,
    };
    assert_eq!(Header::decode(&header.encode()), Ok(header));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn payload_above_u32_is_rejected_without_allocation() {
    let payload_len = u32::MAX as usize + 1;
    assert_eq!(
        Header::from_payload_len(payload_len, 0),
        Err(HeaderError::LengthNotRepresentable {
            payload_len: 1_u64 << 32,
        })
    );
}

#[test]
fn negative_control_little_endian_length_changes_the_value() {
    let corrupted = [4, 3, 2, 1, 1];
    assert_eq!(Header::decode(&corrupted).unwrap().payload_len, 0x0403_0201);
    assert_ne!(Header::decode(&corrupted).unwrap().payload_len, 0x0102_0304);
}
