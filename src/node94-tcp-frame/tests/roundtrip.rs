use node94_tcp_frame::{
    CHUNK_LEN, FrameLimits, HashTableWidth, decode_frame, encode_frame, hash_table_width,
};

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index.wrapping_mul(31).wrapping_add(7)) % 251) as u8)
        .collect()
}

fn assert_complete_roundtrip(payload: &[u8], port: u16) {
    let encoded = encode_frame(payload, port).unwrap();
    let max_len = (payload.len() as u64).max(u64::from(encoded.header.payload_len));
    let decoded = decode_frame(encoded.as_bytes(), FrameLimits::new(max_len)).unwrap();
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.consumed, encoded.as_bytes().len());
    assert_eq!(decoded.header, encoded.header);
}

#[test]
fn complete_roundtrips_span_the_compression_threshold() {
    for len in [0, 1, 1_023, 1_024, 1_025, 1_026] {
        let payload = deterministic_payload(len);
        assert_complete_roundtrip(&payload, 4001);
    }
}

#[test]
fn complete_roundtrips_span_the_hash_table_boundary() {
    let cases = [
        (65_534, HashTableWidth::U16),
        (65_535, HashTableWidth::U32),
        (65_536, HashTableWidth::U32),
    ];
    for (len, expected_width) in cases {
        assert_eq!(hash_table_width(len), expected_width);
        let payload = deterministic_payload(len as usize);
        assert_complete_roundtrip(&payload, 4001);
    }
}

#[test]
fn complete_raw_roundtrips_span_the_reader_chunk_boundary() {
    for len in [CHUNK_LEN - 1, CHUNK_LEN, CHUNK_LEN + 1] {
        let payload = deterministic_payload(len as usize);
        assert_complete_roundtrip(&payload, 3998);
    }
}

#[test]
fn writer_chunk_boundary_includes_the_five_byte_header() {
    let cases = [
        (CHUNK_LEN - 6, vec![CHUNK_LEN - 1]),
        (CHUNK_LEN - 5, vec![CHUNK_LEN]),
        (CHUNK_LEN - 4, vec![CHUNK_LEN, 1]),
    ];
    for (payload_len, expected_chunks) in cases {
        let payload = vec![0; payload_len as usize];
        let encoded = encode_frame(&payload, 3998).unwrap();
        assert_eq!(
            encoded.chunks().map(|chunk| chunk.len).collect::<Vec<_>>(),
            expected_chunks
        );
    }
}
