use node94_tcp_frame::{CHUNK_LEN, COMPRESSION_THRESHOLD, Header, encode_frame};

#[test]
fn empty_payload_is_a_five_byte_raw_frame() {
    let encoded = encode_frame(&[], 4001).unwrap();
    assert_eq!(encoded.as_bytes(), &[0; 5]);
    assert_eq!(encoded.header.payload_len, 0);
    assert_eq!(encoded.header.compression_flag, 0);
}

#[test]
fn raw_frame_has_big_endian_length_and_exact_payload() {
    let encoded = encode_frame(b"abc", 4001).unwrap();
    assert_eq!(encoded.as_bytes(), b"\0\0\0\x03\0abc");
    assert_eq!(Header::decode(encoded.as_bytes()).unwrap(), encoded.header);
}

#[test]
fn threshold_boundary_switches_flag_and_size_prefix() {
    let below = vec![b'x'; COMPRESSION_THRESHOLD as usize - 1];
    let at = vec![b'x'; COMPRESSION_THRESHOLD as usize];

    let raw = encode_frame(&below, 4001).unwrap();
    assert_eq!(raw.header.compression_flag, 0);
    assert_eq!(raw.header.payload_len as usize, below.len());

    let compressed = encode_frame(&at, 4001).unwrap();
    assert_eq!(compressed.header.compression_flag, 1);
    assert_eq!(
        &compressed.as_bytes()[5..9],
        &(COMPRESSION_THRESHOLD as u32).to_le_bytes()
    );
}

#[test]
fn excluded_stream_field_values_keep_large_payload_raw() {
    let payload = vec![0x5a; COMPRESSION_THRESHOLD as usize];
    for stream_field in [3998, 3999] {
        let encoded = encode_frame(&payload, stream_field).unwrap();
        assert_eq!(
            encoded.header.compression_flag, 0,
            "stream field {stream_field}"
        );
        assert_eq!(
            &encoded.as_bytes()[5..],
            payload,
            "stream field {stream_field}"
        );
    }
}

#[test]
fn adjacent_stream_field_values_compress_large_payload() {
    let payload = vec![0x5a; COMPRESSION_THRESHOLD as usize];
    for stream_field in [3997, 4000] {
        assert_eq!(
            encode_frame(&payload, stream_field)
                .unwrap()
                .header
                .compression_flag,
            1,
            "stream field {stream_field}"
        );
    }
}

#[test]
fn writer_chunk_plan_covers_header_and_payload() {
    let payload = vec![0_u8; CHUNK_LEN as usize];
    let encoded = encode_frame(&payload, 3998).unwrap();
    let chunks = encoded.chunks().collect::<Vec<_>>();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len, CHUNK_LEN);
    assert_eq!(chunks[1].offset, CHUNK_LEN);
    assert_eq!(chunks[1].len, 5);
}

#[test]
fn repeated_compression_is_deterministic_within_the_pinned_crate() {
    let payload = b"node94-offline-codec".repeat(128);
    let first = encode_frame(&payload, 4001).unwrap();
    let second = encode_frame(&payload, 4001).unwrap();
    assert_eq!(first, second);
}
