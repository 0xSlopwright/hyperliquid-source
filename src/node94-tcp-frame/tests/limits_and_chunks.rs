use node94_tcp_frame::{CHUNK_LEN, Chunk, ChunkPlan, FrameLimits, Header, LengthError};

fn raw_header(payload_len: u32) -> Header {
    Header {
        payload_len,
        compression_flag: 0,
    }
}

#[test]
fn frame_admission_is_inclusive_at_zero_and_configured_limit() {
    let limits = FrameLimits::new(100);
    assert_eq!(limits.admit(raw_header(0)), Ok(()));
    assert_eq!(limits.admit(raw_header(99)), Ok(()));
    assert_eq!(limits.admit(raw_header(100)), Ok(()));
    assert_eq!(
        limits.admit(raw_header(101)),
        Err(LengthError::FrameTooLarge {
            declared: 101,
            max: 100,
        })
    );
}

#[test]
fn maximum_wire_length_is_admitted_by_a_matching_limit() {
    assert_eq!(
        FrameLimits::new(u32::MAX as u64).admit(raw_header(u32::MAX)),
        Ok(())
    );
    assert_eq!(
        FrameLimits::new(u32::MAX as u64 - 1).admit(raw_header(u32::MAX)),
        Err(LengthError::FrameTooLarge {
            declared: u32::MAX,
            max: u32::MAX as u64 - 1,
        })
    );
}

#[test]
fn lz4_prefix_uses_the_same_inclusive_limit() {
    let limits = FrameLimits::new(4_000_000);
    assert_eq!(limits.admit_uncompressed_size(1234, 4_000_000), Ok(()));
    assert_eq!(
        limits.admit_uncompressed_size(1234, 4_000_001),
        Err(LengthError::DecompressedTooLarge {
            compressed_payload_len: 1234,
            uncompressed_size: 4_000_001,
            max: 4_000_000,
        })
    );
}

#[test]
fn chunk_boundaries_cover_empty_exact_and_partial_lengths() {
    let cases: &[(u64, &[Chunk])] = &[
        (0, &[]),
        (1, &[Chunk { offset: 0, len: 1 }]),
        (
            CHUNK_LEN - 1,
            &[Chunk {
                offset: 0,
                len: CHUNK_LEN - 1,
            }],
        ),
        (
            CHUNK_LEN,
            &[Chunk {
                offset: 0,
                len: CHUNK_LEN,
            }],
        ),
        (
            CHUNK_LEN + 1,
            &[
                Chunk {
                    offset: 0,
                    len: CHUNK_LEN,
                },
                Chunk {
                    offset: CHUNK_LEN,
                    len: 1,
                },
            ],
        ),
    ];

    for &(total, expected) in cases {
        assert_eq!(ChunkPlan::new(total).collect::<Vec<_>>(), expected);
    }
}

#[test]
fn chunk_plan_handles_the_maximum_declared_payload_without_allocation() {
    let mut plan = ChunkPlan::new(u32::MAX as u64);
    assert_eq!(plan.remaining_chunks(), 1074);
    assert_eq!(
        plan.next(),
        Some(Chunk {
            offset: 0,
            len: CHUNK_LEN,
        })
    );
    let last = plan.last().unwrap();
    assert_eq!(last.offset + last.len, u32::MAX as u64);
    assert!(last.len < CHUNK_LEN);
}

#[test]
fn negative_control_using_decimal_four_megabytes_matters() {
    let chunks = ChunkPlan::new(CHUNK_LEN + 1).collect::<Vec<_>>();
    assert_eq!(chunks[0].len, 4_000_000);
    assert_ne!(chunks[0].len, 4 * 1024 * 1024);
}
