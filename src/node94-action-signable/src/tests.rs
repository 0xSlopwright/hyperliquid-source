use crate::*;

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
