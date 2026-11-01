use node94_fixed_point::{
    AdmissionError, ArithmeticOutcome, ArithmeticStatus, EvmAmountError,
    INTERNAL_AMOUNT_EXCLUSIVE_MAX, InternalAmount, Notional, Price, QuantityKind, ScaleError,
    SignedSize, Size, SpotWireError, Tick, TickError, TokenDecimals, U256, Wei, checked_pow10,
    evm_amount_to_internal, next_tick, parse_spot_wire_price, parse_spot_wire_size, perp_tick,
    require_tick_divisible, round_down_to_tick, significant_tick, spot_tick,
};

#[test]
fn quantity_guard_vectors_match_the_retained_sign_packet() {
    // RE-004-qty-newtype-sign-guards-94: unsigned guards reject negative
    // i64 values; signed guards reject u64 values above i64::MAX.
    assert_eq!(Size::try_from(0), Ok(Size::from_raw(0)));
    assert_eq!(
        Notional::try_from(i64::MAX),
        Ok(Notional::from_raw(i64::MAX as u64))
    );
    assert_eq!(
        Size::try_from(-1),
        Err(AdmissionError::NegativeUnsigned {
            kind: QuantityKind::Size,
            value: -1,
        })
    );
    assert_eq!(
        SignedSize::try_from(i64::MAX as u64),
        Ok(SignedSize::from_raw(i64::MAX))
    );
    assert_eq!(
        SignedSize::try_from(i64::MAX as u64 + 1),
        Err(AdmissionError::SignedOutOfRange {
            kind: QuantityKind::SignedSize,
            value: i64::MAX as u64 + 1,
        })
    );
}

#[test]
fn saturation_vectors_match_wei_and_size_packets() {
    // RE-004-wei-saturating-ops-94 and RE-004-sz-saturating-sites-94.
    assert_eq!(
        Wei::from_raw(u64::MAX).saturating_add_status(Wei::from_raw(1)),
        ArithmeticOutcome {
            value: Wei::from_raw(u64::MAX),
            status: ArithmeticStatus::Overflow,
        }
    );
    assert_eq!(
        Size::from_raw(0).saturating_sub_status(Size::from_raw(1)),
        ArithmeticOutcome {
            value: Size::from_raw(0),
            status: ArithmeticStatus::Underflow,
        }
    );
    assert_eq!(
        SignedSize::from_raw(i64::MIN).saturating_sub_status(SignedSize::from_raw(1)),
        ArithmeticOutcome {
            value: SignedSize::from_raw(i64::MIN),
            status: ArithmeticStatus::Underflow,
        }
    );
}

#[test]
fn decimal_power_table_matches_all_admitted_packet_rows() {
    // RE-004-spot-wei-scale-family-94/pow10-exponents.tsv.
    let powers = [
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_000_000_000_000_000_000,
    ];
    for (exponent, expected) in powers.into_iter().enumerate() {
        assert_eq!(checked_pow10(exponent as u8), Ok(expected));
    }
    for exponent in [20, 21, 127, 255] {
        assert_eq!(
            checked_pow10(exponent),
            Err(ScaleError::ExponentOutOfRange { exponent })
        );
    }
}

#[test]
fn scale_family_boundaries_preserve_floor_exact_and_overflow_distinctions() {
    let unit = TokenDecimals::new(8, 8);
    assert_eq!(unit.scale_factor(), Ok(1));
    assert_eq!(
        unit.size_to_wei(Size::from_raw(u64::MAX)),
        Ok(Wei::from_raw(u64::MAX))
    );

    let max_scale = TokenDecimals::new(0, 19);
    assert_eq!(max_scale.scale_factor(), Ok(10_000_000_000_000_000_000));
    assert_eq!(
        max_scale.size_to_wei(Size::from_raw(1)),
        Ok(Wei::from_raw(10_000_000_000_000_000_000))
    );
    assert_eq!(
        max_scale.size_to_wei(Size::from_raw(2)),
        Err(ScaleError::MultiplicationOverflow)
    );
    assert_eq!(
        max_scale.wei_to_size_floor(Wei::from_raw(u64::MAX)),
        Ok(Size::from_raw(1))
    );
    assert_eq!(
        max_scale.wei_to_size_exact(Wei::from_raw(u64::MAX)),
        Err(ScaleError::InexactDivision {
            remainder: 8_446_744_073_709_551_615,
        })
    );
}

#[test]
fn spot_wire_price_vectors_cover_every_admitted_decimal_difference() {
    // RE-004-spot-wire-scale-94/scale-table.tsv, k=0..=8.
    for raw_price_decimals in 0..=8 {
        let divisor = checked_pow10(8 - raw_price_decimals).unwrap();
        assert_eq!(
            parse_spot_wire_price(divisor, 0, raw_price_decimals),
            Ok(Price::from_raw(1))
        );
        assert_eq!(
            parse_spot_wire_price(0, 0, raw_price_decimals),
            Err(SpotWireError::InvalidPrice {
                wire_value: 0,
                divisor,
            })
        );
        if divisor > 1 {
            assert_eq!(
                parse_spot_wire_price(divisor + 1, 0, raw_price_decimals),
                Err(SpotWireError::InvalidPrice {
                    wire_value: divisor + 1,
                    divisor,
                })
            );
        }
    }
}

#[test]
fn spot_wire_size_vectors_cover_every_admitted_base_scale() {
    // RE-004-spot-wire-scale-94/scale-table.tsv, b=0..=8.
    for base_size_decimals in 0..=8 {
        let divisor = checked_pow10(8 - base_size_decimals).unwrap();
        assert_eq!(
            parse_spot_wire_size(0, base_size_decimals),
            Ok(Size::from_raw(0))
        );
        assert_eq!(
            parse_spot_wire_size(divisor, base_size_decimals),
            Ok(Size::from_raw(1))
        );
        if divisor > 1 {
            assert_eq!(
                parse_spot_wire_size(divisor - 1, base_size_decimals),
                Err(SpotWireError::InvalidSize {
                    wire_value: divisor - 1,
                    divisor,
                })
            );
        }
    }
}

#[test]
fn significant_tick_vectors_cover_all_packet_intervals() {
    // RE-004-px-tick-ladder-94/step-intervals.tsv.
    let intervals = [
        (0, 99_999, 1),
        (100_000, 999_999, 10),
        (1_000_000, 9_999_999, 100),
        (10_000_000, 99_999_999, 1_000),
        (100_000_000, 999_999_999, 10_000),
        (1_000_000_000, 9_999_999_999, 100_000),
        (10_000_000_000, 99_999_999_999, 1_000_000),
        (100_000_000_000, 999_999_999_999, 10_000_000),
        (1_000_000_000_000, 9_999_999_999_999, 100_000_000),
        (10_000_000_000_000, 99_999_999_999_999, 1_000_000_000),
        (100_000_000_000_000, 999_999_999_999_999, 10_000_000_000),
        (
            1_000_000_000_000_000,
            9_999_999_999_999_999,
            100_000_000_000,
        ),
        (
            10_000_000_000_000_000,
            99_999_999_999_999_999,
            1_000_000_000_000,
        ),
        (
            100_000_000_000_000_000,
            999_999_999_999_999_999,
            10_000_000_000_000,
        ),
        (
            1_000_000_000_000_000_000,
            9_999_999_999_999_999_999,
            100_000_000_000_000,
        ),
        (10_000_000_000_000_000_000, u64::MAX, 1_000_000_000_000_000),
    ];
    for (low, high, expected) in intervals {
        assert_eq!(significant_tick(Price::from_raw(low)).raw(), expected);
        assert_eq!(significant_tick(Price::from_raw(high)).raw(), expected);
    }
}

#[test]
fn tick_caps_and_rounding_match_packet_tables() {
    let maximum = Price::from_raw(u64::MAX);
    let perp_caps = [1_000_000, 100_000, 10_000, 1_000, 100, 10, 1];
    for (size_decimals, expected) in perp_caps.into_iter().enumerate() {
        assert_eq!(
            perp_tick(maximum, size_decimals as u8).map(Tick::raw),
            Ok(expected)
        );
    }
    assert_eq!(
        perp_tick(maximum, 7),
        Err(TickError::PerpSizeDecimalsOutOfRange { size_decimals: 7 })
    );
    for exponent in 0..=19 {
        let expected = significant_tick(maximum)
            .raw()
            .min(checked_pow10(exponent).unwrap());
        assert_eq!(
            spot_tick(maximum, 0, exponent, false).map(Tick::raw),
            Ok(expected)
        );
    }
    assert_eq!(
        spot_tick(maximum, 0, 20, false).map(Tick::raw),
        Ok(1_000_000_000_000_000)
    );

    let tick = Tick::new(10).unwrap();
    assert_eq!(require_tick_divisible(Price::from_raw(1_000), tick), Ok(()));
    assert_eq!(
        round_down_to_tick(Price::from_raw(1_005), tick),
        Price::from_raw(1_000)
    );
    assert_eq!(
        next_tick(Price::from_raw(1_000), tick),
        Price::from_raw(1_010)
    );
}

#[test]
fn evm_boundary_vectors_cover_all_supported_exponents() {
    // RE-004-evm-amount-scale-94/boundaries.tsv.
    for exponent in 0_i8..=19 {
        let power = 10_u128.pow(exponent as u32);
        let largest = u128::from(INTERNAL_AMOUNT_EXCLUSIVE_MAX) * power - 1;
        assert_eq!(
            evm_amount_to_internal(U256::from_u128(largest), exponent),
            Ok(InternalAmount::from_raw(INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1))
        );
        let first_rejected = u128::from(INTERNAL_AMOUNT_EXCLUSIVE_MAX) * power;
        assert_eq!(
            evm_amount_to_internal(U256::from_u128(first_rejected), exponent),
            Err(EvmAmountError::InternalAmountOutOfRange)
        );
    }

    for magnitude in 1_i8..=19 {
        let power = checked_pow10(magnitude as u8).unwrap();
        let largest_input = (INTERNAL_AMOUNT_EXCLUSIVE_MAX - 1) / power;
        assert!(evm_amount_to_internal(U256::from_u64(largest_input), -magnitude).is_ok());
        assert_eq!(
            evm_amount_to_internal(U256::from_u64(largest_input + 1), -magnitude),
            Err(EvmAmountError::InternalAmountOutOfRange)
        );
    }
}

#[test]
fn invalid_scale_controls_fail_closed() {
    assert_eq!(
        TokenDecimals::new(1, 0).scale_factor(),
        Err(ScaleError::WeiDecimalsBelowSize {
            wei_decimals: 0,
            size_decimals: 1,
        })
    );
    assert_eq!(
        parse_spot_wire_price(1, 0, 9),
        Err(SpotWireError::PriceScaleExceedsWire {
            raw_price_decimals: 9,
        })
    );
    assert_eq!(
        evm_amount_to_internal(U256::from_u64(0), 20),
        Err(EvmAmountError::ExponentOutOfRange { exponent: 20 })
    );
}
