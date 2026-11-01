use crate::*;

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16).unwrap();
    }
    output
}

#[test]
fn context_layout_constants_are_retained_without_an_abi_claim() {
    assert_eq!(TargetContextLayout::EXPIRES_TAG, 0x00);
    assert_eq!(TargetContextLayout::EXPIRES_VALUE, 0x08);
    assert_eq!(TargetContextLayout::NONCE, 0x10);
    assert_eq!(TargetContextLayout::VAULT_TAG, 0x18);
    assert_eq!(TargetContextLayout::VAULT_BYTES, 0x19);
    assert_eq!(TargetFunction::AGENT_INLINE.start, 0x333f240);
    assert_eq!(TargetFunction::EMBEDDED_INLINE.end_exclusive, 0x39853ec);
    assert_eq!(TARGET_SHA256.len(), 64);
}

#[test]
fn preimage_without_optional_fields_matches_the_observed_order() {
    let context = SignableContext::new(0x0102_0304_0506_0708, None, None);
    let actual = build_preimage(EncodedAction::new(&[0x81, 0xa1, b'k', 0x2a]), &context).unwrap();
    assert_eq!(actual, [0x81, 0xa1, b'k', 0x2a, 1, 2, 3, 4, 5, 6, 7, 8, 0,]);
    assert_eq!(
        preimage_len(EncodedAction::new(&actual[..4]), &context),
        Ok(13)
    );
}

#[test]
fn present_vault_and_expiry_use_exact_tags_and_big_endian_values() {
    let vault = VaultAddress::from_bytes([0x5a; 20]);
    let context = SignableContext::new(u64::MAX, Some(vault), Some(0x0102_0304_0506_0708));
    let actual = build_preimage(EncodedAction::new(&[]), &context).unwrap();
    assert_eq!(&actual[..8], &u64::MAX.to_be_bytes());
    assert_eq!(actual[8], 1);
    assert_eq!(&actual[9..29], &[0x5a; 20]);
    assert_eq!(actual[29], 0);
    assert_eq!(&actual[30..], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(actual.len(), 38);
}

#[test]
fn zero_expiry_is_present_and_distinct_from_absent() {
    let absent = SignableContext::new(0, None, None);
    let present = SignableContext::new(0, None, Some(0));
    let absent = build_preimage(EncodedAction::new(&[]), &absent).unwrap();
    let present = build_preimage(EncodedAction::new(&[]), &present).unwrap();
    assert_eq!(absent, [0; 9]);
    assert_eq!(present, [0; 18]);
}

#[test]
fn fixed_width_inputs_reject_short_and_long_slices() {
    assert!(VaultAddress::try_from_slice(&[0; 19]).is_err());
    assert!(VaultAddress::try_from_slice(&[0; 21]).is_err());
    assert!(SignatureChainId::try_from_slice(&[0; 31]).is_err());
    assert!(SignatureChainId::try_from_slice(&[0; 33]).is_err());
    assert!(ConnectionId::try_from_slice(&[0; 31]).is_err());
    assert!(ConnectionId::try_from_slice(&[0; 33]).is_err());
    assert!(VaultAddress::try_from_slice(&[0; 20]).is_ok());
    assert!(SignatureChainId::try_from_slice(&[0; 32]).is_ok());
    assert!(ConnectionId::try_from_slice(&[0; 32]).is_ok());
}

#[test]
fn keccak_known_answers_cover_empty_and_sha3_distinction() {
    let empty = keccak256(&[]);
    assert_eq!(
        *empty.as_bytes(),
        hex_32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    );
    assert_ne!(
        *empty.as_bytes(),
        hex_32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    );
    assert_eq!(
        *keccak256(b"abc").as_bytes(),
        hex_32("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    );
}

#[test]
fn keccak_absorb_boundaries_match_independent_expected_digests() {
    let cases = [
        (
            1,
            "69c322e3248a5dfc29d73c5b0553b0185a35cd5bb6386747517ef7e53b15e287",
        ),
        (
            135,
            "67ac26d3e79a18e88f212385a7bad88e6f9cfd25b5bfadbc2c4d0cf95457e613",
        ),
        (
            136,
            "e0ab45aba084eb3ddec8f785b6993a3555833dd941733756a685525a84fe012c",
        ),
        (
            137,
            "54e8f24f3543727f3825a7e1dd0e9c4d01b5254f5af2ae0fa3644212495d92b2",
        ),
        (
            271,
            "c3a61fb7e80b9a02d3af37c72e9f362c362e38b9711d6b20b6e1db17e94a50b2",
        ),
        (
            272,
            "57e0d7506f2c4eb5f09f7318721fbd04852849690c86ced13e7642fb17035478",
        ),
        (
            273,
            "21cdfe1022deefc98568fe3b6fa178e231ea59b445b5118d162f018dac5610be",
        ),
        (
            512,
            "60119b3bbdeef7e4b1afc02585cae1da1dd0025362ab01fb4107a8e8963ec154",
        ),
    ];
    for (length, expected) in cases {
        let input: Vec<_> = (0..length).map(|index| (index * 17 + 3) as u8).collect();
        assert_eq!(
            *keccak256(&input).as_bytes(),
            hex_32(expected),
            "length {length}"
        );
    }
}
