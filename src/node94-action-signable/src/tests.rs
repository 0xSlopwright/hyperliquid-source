use crate::*;
use std::collections::BTreeMap;

const EVALUATED_VECTORS: &str =
    include_str!("../../../research/work-items/RE-005-action-signable-94/vectors.tsv");
const ENCODED_INPUTS: &str = include_str!("../tests/encoded-inputs.tsv");

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

#[test]
fn public_sdk_connection_digest_matches_the_independent_golden_vector() {
    let encoded = hex_bytes(
        "83a474797065a56f72646572a66f72646572739186a16104a162c3a170a6313637302e31a173a6302e30313437a172c2a17481a56c696d697481a3746966a3496f63a867726f7570696e67a26e61",
    );
    let context = SignableContext::new(1_677_777_606_040, None, None);
    let actual = connection_id(EncodedAction::new(&encoded), &context).unwrap();
    assert_eq!(
        *actual.as_bytes(),
        hex_32("0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908")
    );
}

#[test]
fn agent_payload_source_covers_all_observed_selector_classes() {
    let context = SignableContext::new(7, None, None);
    for selector in [0, 1, 2, 3, 4, 0x7f, 0x80, 0xff] {
        let payload = build_agent_payload(
            EncodedAction::new(&[0x90]),
            &context,
            ChainSelector::new(selector),
        )
        .unwrap();
        assert_eq!(
            payload.source,
            if selector == 3 {
                AgentSource::A
            } else {
                AgentSource::B
            }
        );
        assert_eq!(
            payload.source.as_byte(),
            if selector == 3 { b'a' } else { b'b' }
        );
        assert_eq!(payload.chain_id, ACTION_CHAIN_ID);
        assert_eq!(
            payload.verifying_contract.observed_zero_region(),
            [0; ZeroVerifyingContract::OBSERVED_ZERO_REGION_LENGTH]
        );
    }
}

#[test]
fn embedded_payload_preserves_copied_fields_separately() {
    let signature_chain_id = SignatureChainId::from_bytes([0xa5; 32]);
    let context = SignableContext::new(u64::MAX, None, Some(0));
    let payload = build_embedded_payload(
        EncodedAction::new(&[0x80]),
        &context,
        ChainSelector::new(0xff),
        signature_chain_id,
    )
    .unwrap();
    assert_eq!(payload.signature_chain_id, signature_chain_id);
    assert_eq!(payload.nonce, u64::MAX);
    assert_eq!(payload.chain_selector.value(), 0xff);
    assert_eq!(
        payload.connection_id,
        connection_id(EncodedAction::new(&[0x80]), &context).unwrap()
    );
}

#[test]
fn selector_changes_payload_metadata_but_not_connection_digest() {
    let context = SignableContext::new(9, Some(VaultAddress::from_bytes([7; 20])), Some(11));
    let a = build_agent_payload(
        EncodedAction::new(&[1, 2, 3]),
        &context,
        ChainSelector::new(3),
    )
    .unwrap();
    let b = build_agent_payload(
        EncodedAction::new(&[1, 2, 3]),
        &context,
        ChainSelector::new(4),
    )
    .unwrap();
    assert_eq!(a.connection_id, b.connection_id);
    assert_ne!(a.source, b.source);
}

#[test]
fn each_preimage_field_changes_the_connection_digest() {
    let vault = VaultAddress::from_bytes([0x11; 20]);
    let base = SignableContext::new(1, None, None);
    let baseline = connection_id(EncodedAction::new(&[0x90]), &base).unwrap();
    for (action, context) in [
        (
            EncodedAction::new(&[0x91]),
            SignableContext::new(1, None, None),
        ),
        (
            EncodedAction::new(&[0x90]),
            SignableContext::new(2, None, None),
        ),
        (
            EncodedAction::new(&[0x90]),
            SignableContext::new(1, Some(vault), None),
        ),
        (
            EncodedAction::new(&[0x90]),
            SignableContext::new(1, None, Some(0)),
        ),
    ] {
        assert_ne!(connection_id(action, &context).unwrap(), baseline);
    }
}

#[test]
fn all_1008_retained_evaluator_vectors_match() {
    let inputs = encoded_inputs();
    let mut function_counts = BTreeMap::new();
    let mut count = 0usize;
    for (line_number, line) in EVALUATED_VECTORS.lines().enumerate().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 9, "evidence line {}", line_number + 1);
        let function = columns[0];
        let encoded_len: usize = columns[1].parse().unwrap();
        let nonce: u64 = columns[2].parse().unwrap();
        let input_key = if encoded_len == 40 {
            ("nonce", nonce)
        } else {
            ("length", encoded_len as u64)
        };
        let encoded = inputs
            .get(&input_key)
            .unwrap_or_else(|| panic!("missing encoded input {input_key:?}"));
        assert_eq!(encoded.len(), encoded_len);

        let vault_address = if columns[3] == "-" {
            None
        } else {
            Some(VaultAddress::try_from_slice(&hex_bytes(columns[3])).unwrap())
        };
        let expires_after = (columns[4] != "-").then(|| columns[4].parse().unwrap());
        let selector = ChainSelector::new(columns[5].parse().unwrap());
        let context = SignableContext::new(nonce, vault_address, expires_after);
        let expected = hex_32(columns[7]);
        assert_eq!(columns[8], "-");
        assert_eq!(
            *connection_id(EncodedAction::new(encoded), &context)
                .unwrap()
                .as_bytes(),
            expected,
            "evidence line {}",
            line_number + 1
        );

        match function {
            "0x333f240" | "0x37eb2d0" => {
                let payload =
                    build_agent_payload(EncodedAction::new(encoded), &context, selector).unwrap();
                assert_eq!(*payload.connection_id.as_bytes(), expected);
                assert_eq!(
                    payload.source,
                    if selector.value() == 3 {
                        AgentSource::A
                    } else {
                        AgentSource::B
                    }
                );
            }
            "0x3984fe0" => {
                let copied = SignatureChainId::from_bytes([count as u8; 32]);
                let payload =
                    build_embedded_payload(EncodedAction::new(encoded), &context, selector, copied)
                        .unwrap();
                assert_eq!(*payload.connection_id.as_bytes(), expected);
                assert_eq!(payload.signature_chain_id, copied);
                assert_eq!(payload.nonce, nonce);
                assert_eq!(payload.chain_selector, selector);
            }
            _ => panic!("unsupported retained function {function}"),
        }
        *function_counts.entry(function).or_insert(0usize) += 1;
        count += 1;
    }
    assert_eq!(count, 1008);
    assert_eq!(function_counts.get("0x333f240"), Some(&336));
    assert_eq!(function_counts.get("0x37eb2d0"), Some(&336));
    assert_eq!(function_counts.get("0x3984fe0"), Some(&336));
}

fn encoded_inputs() -> BTreeMap<(&'static str, u64), Vec<u8>> {
    ENCODED_INPUTS
        .lines()
        .skip(1)
        .map(|line| {
            let columns: Vec<_> = line.split('\t').collect();
            assert_eq!(columns.len(), 3);
            (
                (columns[0], columns[1].parse().unwrap()),
                if columns[2] == "-" {
                    Vec::new()
                } else {
                    hex_bytes(columns[2])
                },
            )
        })
        .collect()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
