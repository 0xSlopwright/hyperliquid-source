use std::panic::{AssertUnwindSafe, catch_unwind};

use node94_tcp_frame::{DecodeError, FrameLimits, Header, LengthError, decode_frame, encode_frame};

fn next_u64(state: &mut u64) -> u64 {
    // Fixed xorshift64* sequence: deterministic, bounded, and dependency-free.
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[test]
fn deterministic_short_input_corpus_is_panic_free_and_stable() {
    let mut state = 0x3b71_79cd_967d_1b13;

    for case in 0..2_048 {
        let len = (next_u64(&mut state) % 97) as usize;
        let mut input = vec![0_u8; len];
        for byte in &mut input {
            *byte = next_u64(&mut state) as u8;
        }

        let decode = || decode_frame(&input, FrameLimits::new(64));
        let first = catch_unwind(AssertUnwindSafe(decode))
            .unwrap_or_else(|_| panic!("decoder panicked for deterministic case {case}"));
        let second = decode();
        assert_eq!(first, second, "unstable result for case {case}");

        if let Ok(frame) = first {
            assert!(frame.consumed <= input.len());
            assert_eq!(frame.consumed, 5 + frame.header.payload_len as usize);
            if !frame.header.is_compressed() {
                assert_eq!(frame.payload, input[5..frame.consumed]);
            }
        }
    }
}

#[test]
fn every_truncation_of_a_valid_compressed_frame_is_rejected() {
    let plain = b"bounded-compressed-truncation".repeat(96);
    let encoded = encode_frame(&plain, 4001).unwrap();
    assert!(encoded.header.is_compressed());
    let wire = encoded.as_bytes();

    for available in 0..wire.len() {
        let result = decode_frame(&wire[..available], FrameLimits::new(plain.len() as u64));
        assert!(result.is_err(), "truncation at {available} bytes succeeded");
    }
    assert_eq!(
        decode_frame(wire, FrameLimits::new(plain.len() as u64))
            .unwrap()
            .payload,
        plain
    );
}

#[test]
fn maximum_declared_frame_is_refused_before_payload_or_allocation() {
    let header = Header {
        payload_len: u32::MAX,
        compression_flag: 0,
    };
    assert_eq!(
        decode_frame(&header.encode(), FrameLimits::new(1_024)),
        Err(DecodeError::Length(LengthError::FrameTooLarge {
            declared: u32::MAX,
            max: 1_024,
        }))
    );
}

#[test]
fn maximum_lz4_prefix_is_refused_before_block_decode_or_allocation() {
    let payload = u32::MAX.to_le_bytes();
    let header = Header::from_payload_len(payload.len(), 1).unwrap();
    let mut wire = Vec::from(header.encode());
    wire.extend_from_slice(&payload);

    assert_eq!(
        decode_frame(&wire, FrameLimits::new(1_024)),
        Err(DecodeError::Length(LengthError::DecompressedTooLarge {
            compressed_payload_len: 4,
            uncompressed_size: u32::MAX,
            max: 1_024,
        }))
    );
}
