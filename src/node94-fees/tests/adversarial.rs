use node94_fees::{
    Address, ArithmeticEvent, AssetFeeScale, BuilderFee, FeeEngine, FeeError, FeeLedger,
    FeeProfile, FeeRates, FeeRecipient, FeeSchedule, FillFeeRecord, LedgerCredit, LedgerField,
    LiquidityRole, MarketRates, PerpFeeOutput, PerpFill, RateGridInput, RateGridOutcome, RateRow,
    SpotCategory, SpotFill, SubtractionStage, VolumeConversionInput, VolumeTier,
    deployer_scale_in_target_range, validate_rate_grid_point, volume_conversion,
};

const PAYER: Address = Address::new([11; 20]);
const OTHER: Address = Address::new([22; 20]);
const TOKEN: u64 = 360;

fn schedule() -> FeeSchedule {
    FeeSchedule {
        default_rates: FeeRates::new(
            MarketRates::new(1e-4, 3.5e-4),
            MarketRates::new(2.5e-4, 7e-4),
        ),
        volume_tiers: vec![
            VolumeTier {
                minimum_anchor: 0.0,
                share: 0.05,
            },
            VolumeTier {
                minimum_anchor: 10.0,
                share: 0.1,
            },
            VolumeTier {
                minimum_anchor: 100.0,
                share: 0.2,
            },
        ],
        low_volume_discount: 0.04,
        flagged_referrer_share: 0.1,
        multiplier_90: 0.5,
        multiplier_98: 2.0,
    }
}

fn perp() -> PerpFill {
    PerpFill {
        payer: PAYER,
        notional: 1_000_000_000_000,
        role: LiquidityRole::Taker,
        asset_scale: AssetFeeScale::Full,
        deployer_scale: 0.0,
        deployer_deleted: false,
        trial: false,
        flagged: false,
        builder: None,
    }
}

fn row(anchor: f64) -> RateRow {
    RateRow {
        current: schedule().default_rates,
        volume_anchor: anchor,
        carried_weight: 1.0,
        ..RateRow::default()
    }
}

#[test]
fn discount_bound_is_strict() {
    let mut below = FeeEngine::new(schedule()).unwrap();
    below.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: row(0.0),
            binding_flags: 1,
            referrer: Some(OTHER),
            volume_words: vec![2_499_999_999],
        },
    );
    assert_eq!(below.compute_perp(perp()).unwrap().value.gross, 336_000_000);

    let mut at = FeeEngine::new(schedule()).unwrap();
    at.insert_profile(
        PAYER,
        FeeProfile {
            volume_words: vec![2_500_000_000],
            ..below.profile(PAYER).unwrap().clone()
        },
    );
    assert_eq!(at.compute_perp(perp()).unwrap().value.gross, 350_000_000);
}

#[test]
fn builder_tier_preempts_referrer() {
    let mut engine = FeeEngine::new(schedule()).unwrap();
    engine.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: row(0.0),
            binding_flags: 3,
            referrer: Some(Address::new([33; 20])),
            volume_words: vec![1],
        },
    );
    engine.insert_profile(
        OTHER,
        FeeProfile {
            row_tag: 1,
            row: row(100.0),
            ..FeeProfile::default()
        },
    );
    let output = engine
        .compute_perp(PerpFill {
            builder: Some(BuilderFee {
                address: OTHER,
                rate_units: 0,
            }),
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(output.builder.unwrap().amount, 52_500_000);
    assert!(output.referrer.is_none());
    assert_eq!(output.protocol, 297_500_000);
}

#[test]
fn referrer_window_bound_keeps_tag_but_zeroes_amount() {
    let mut engine = FeeEngine::new(schedule()).unwrap();
    engine.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: row(0.0),
            binding_flags: 3,
            referrer: Some(OTHER),
            volume_words: vec![100_000_000_000],
        },
    );
    engine.insert_profile(
        OTHER,
        FeeProfile {
            row_tag: 1,
            row: row(100.0),
            ..FeeProfile::default()
        },
    );
    let output = engine.compute_perp(perp()).unwrap().value;
    assert_eq!(output.referrer.unwrap().amount, 0);
}

#[test]
fn malformed_rows_and_negative_notionals_are_explicit_errors() {
    assert!(matches!(
        FeeEngine::new(FeeSchedule {
            volume_tiers: vec![
                VolumeTier {
                    minimum_anchor: 2.0,
                    share: 0.1
                },
                VolumeTier {
                    minimum_anchor: 1.0,
                    share: 0.2
                },
            ],
            ..schedule()
        }),
        Err(FeeError::InvalidTierTable)
    ));
    let engine = FeeEngine::new(schedule()).unwrap();
    assert_eq!(
        engine.compute_perp(PerpFill {
            notional: -1,
            ..perp()
        }),
        Err(FeeError::NegativeNotional)
    );

    let mut missing = FeeEngine::new(schedule()).unwrap();
    missing.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: RateRow {
                previous_tag: 1,
                previous: None,
                ..row(0.0)
            },
            ..FeeProfile::default()
        },
    );
    assert_eq!(
        missing.compute_perp(perp()),
        Err(FeeError::MissingPreviousRates { owner: PAYER })
    );
}

#[test]
fn spot_no_quote_leg_uses_previous_rate_and_suppresses_splits() {
    let mut engine = FeeEngine::new(schedule()).unwrap();
    engine.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: RateRow {
                current: FeeRates::new(MarketRates::default(), MarketRates::new(5e-4, 5e-4)),
                previous: Some(FeeRates::new(
                    MarketRates::default(),
                    MarketRates::new(1e-3, 1e-3),
                )),
                previous_tag: 1,
                volume_anchor: 0.0,
                carried_weight: 1.0,
            },
            binding_flags: 1,
            referrer: Some(OTHER),
            volume_words: vec![],
        },
    );
    let output = engine
        .compute_spot(SpotFill {
            payer: PAYER,
            notional: 1_000_000,
            role: LiquidityRole::Maker,
            category: SpotCategory(0),
            category_weight: 1.0,
            aligned_quote: false,
            quote_leg: false,
            flagged: true,
            builder: Some(BuilderFee {
                address: OTHER,
                rate_units: 100,
            }),
        })
        .unwrap()
        .value;
    assert_eq!(output.gross, 960);
    assert!(output.referrer.is_none() && output.builder.is_none());
}

#[test]
fn ledger_aliasing_is_sequential_and_deterministic() {
    let mut ledger = FeeLedger::default();
    let result = ledger
        .apply(
            PAYER,
            TOKEN,
            FillFeeRecord {
                referrer: LedgerCredit {
                    tag: 1,
                    amount: 100,
                    address: Some(PAYER),
                },
                builder: LedgerCredit {
                    tag: 1,
                    amount: 25,
                    address: Some(PAYER),
                },
                gross: 1_000,
                rebate: 50,
                extra: 30,
            },
        )
        .unwrap();
    let state = ledger.token_state(PAYER, TOKEN).unwrap();
    assert_eq!(
        (
            state.unclaimed,
            state.rewarded_to_referrer,
            state.rewarded_fees,
            state.trial_extra
        ),
        (125, 100, 920, 30)
    );
    assert_eq!(ledger.collected_builder_fee(PAYER, TOKEN), Some(25));
    assert_eq!(
        result
            .value
            .creations
            .iter()
            .filter(|item| item.kind == node94_fees::LedgerRecordKind::OwnerBucket)
            .count(),
        1
    );
}

#[test]
fn ledger_creation_zero_rules_and_underflow_events_match_target() {
    let mut ledger = FeeLedger::default();
    let result = ledger
        .apply(
            PAYER,
            TOKEN,
            FillFeeRecord {
                referrer: LedgerCredit {
                    tag: 1,
                    amount: 0,
                    address: Some(OTHER),
                },
                builder: LedgerCredit {
                    tag: 1,
                    amount: 0,
                    address: Some(Address::new([44; 20])),
                },
                gross: 10,
                rebate: 20,
                extra: 5,
            },
        )
        .unwrap();
    assert!(ledger.token_state(OTHER, TOKEN).is_some());
    assert_eq!(ledger.owner_bucket_count(), 2);
    assert_eq!(
        result.events,
        vec![
            ArithmeticEvent::LedgerSubtractionFloored {
                stage: SubtractionStage::GrossLessRebate
            },
            ArithmeticEvent::LedgerSubtractionFloored {
                stage: SubtractionStage::NetLessExtra
            },
        ]
    );
}

#[test]
fn ledger_additions_saturate_and_perp_scaling_is_checked() {
    let mut ledger = FeeLedger::default();
    ledger
        .apply(
            PAYER,
            TOKEN,
            FillFeeRecord {
                referrer: LedgerCredit {
                    tag: 1,
                    amount: u64::MAX,
                    address: Some(PAYER),
                },
                builder: LedgerCredit::NONE,
                gross: 0,
                rebate: 0,
                extra: 0,
            },
        )
        .unwrap();
    let result = ledger
        .apply(
            PAYER,
            TOKEN,
            FillFeeRecord {
                referrer: LedgerCredit::NONE,
                builder: LedgerCredit {
                    tag: 1,
                    amount: 1,
                    address: Some(PAYER),
                },
                gross: 0,
                rebate: 0,
                extra: 0,
            },
        )
        .unwrap();
    assert!(
        result
            .events
            .contains(&ArithmeticEvent::LedgerAdditionSaturated {
                owner: PAYER,
                token: TOKEN,
                field: LedgerField::Unclaimed,
            })
    );

    let output = PerpFeeOutput {
        referrer: None,
        builder: None,
        gross: u64::MAX,
        rebate: 0,
        extra: 0,
        deployer: 0,
        protocol: 0,
    };
    assert_eq!(
        FillFeeRecord::from_perp(&output),
        Err(FeeError::LedgerScaleOverflow("gross"))
    );
}

#[test]
fn volume_conversion_covers_rate_limit_nonfinite_and_abs_error() {
    let ordinary = volume_conversion(VolumeConversionInput {
        notional: 1_000_000_000,
        rate: 1.0,
        trial: false,
        trial_multiplier: 1.0,
        tenth_scale: false,
    })
    .unwrap()
    .value;
    assert_eq!((ordinary.scaled, ordinary.unscaled), (100_000, 100_000));

    let nonfinite = volume_conversion(VolumeConversionInput {
        notional: 1_000,
        rate: f64::INFINITY,
        trial: true,
        trial_multiplier: f64::NAN,
        tenth_scale: false,
    })
    .unwrap()
    .value;
    assert_eq!((nonfinite.scaled, nonfinite.unscaled), (0, 0));

    assert_eq!(
        volume_conversion(VolumeConversionInput {
            notional: 1,
            rate: -1e300,
            trial: false,
            trial_multiplier: 1.0,
            tenth_scale: false,
        }),
        Err(FeeError::RateProductAbsoluteOverflow)
    );
}

#[test]
fn rate_grid_reports_all_four_rejections() {
    let base = RateGridInput {
        lowest_cross_rate: 0.0001,
        referral_share: 0.04,
        max_keep: 0.1,
        lowest_add_rate: 0.00001,
        first_cross_rate: 0.00035,
        scale: 1.0,
        notional: 1_000_000,
    };
    assert!(matches!(
        validate_rate_grid_point(base).unwrap().value,
        RateGridOutcome::Pass(_)
    ));
    assert!(matches!(
        validate_rate_grid_point(RateGridInput {
            lowest_cross_rate: -1.0,
            notional: 100,
            ..base
        })
        .unwrap()
        .value,
        RateGridOutcome::RejectDiscountedFee(_)
    ));
    assert!(matches!(
        validate_rate_grid_point(RateGridInput {
            lowest_cross_rate: 0.0,
            lowest_add_rate: -1.0,
            notional: 10,
            ..base
        })
        .unwrap()
        .value,
        RateGridOutcome::RejectNet(_)
    ));
    assert!(matches!(
        validate_rate_grid_point(RateGridInput {
            first_cross_rate: -1.0,
            notional: 10,
            ..base
        })
        .unwrap()
        .value,
        RateGridOutcome::RejectMaximumFee(_)
    ));
    assert!(matches!(
        validate_rate_grid_point(RateGridInput {
            lowest_cross_rate: 0.0,
            lowest_add_rate: 0.0,
            first_cross_rate: 1.0,
            max_keep: 0.0,
            notional: 1,
            ..base
        })
        .unwrap()
        .value,
        RateGridOutcome::RejectRounding(_)
    ));
}

#[test]
fn fee_scale_comparison_preserves_nan_behavior() {
    assert!(deployer_scale_in_target_range(0.0));
    assert!(deployer_scale_in_target_range(3.0));
    assert!(!deployer_scale_in_target_range(-f64::EPSILON));
    assert!(!deployer_scale_in_target_range(3.000_000_1));
    assert!(deployer_scale_in_target_range(f64::NAN));
}

#[test]
fn gross_saturation_is_observable() {
    let huge = FeeRates::new(MarketRates::new(1e300, 1e300), MarketRates::default());
    let mut engine = FeeEngine::new(FeeSchedule {
        default_rates: huge,
        ..schedule()
    })
    .unwrap();
    engine.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: RateRow {
                current: huge,
                previous: Some(FeeRates::new(
                    MarketRates::new(2e300, 2e300),
                    MarketRates::default(),
                )),
                previous_tag: 1,
                carried_weight: 1.0,
                ..RateRow::default()
            },
            ..FeeProfile::default()
        },
    );
    let result = engine
        .compute_perp(PerpFill {
            notional: 1_000_000,
            builder: Some(BuilderFee {
                address: OTHER,
                rate_units: 1,
            }),
            ..perp()
        })
        .unwrap();
    assert_eq!(result.value.gross, u64::MAX);
    assert!(
        result
            .events
            .contains(&ArithmeticEvent::GrossWithBuilderSaturated)
    );
}

#[test]
fn recipient_scaling_keeps_addresses() {
    let output = PerpFeeOutput {
        referrer: Some(FeeRecipient {
            address: OTHER,
            amount: 3,
        }),
        builder: Some(FeeRecipient {
            address: PAYER,
            amount: 4,
        }),
        gross: 5,
        rebate: 6,
        extra: 7,
        deployer: 0,
        protocol: 0,
    };
    let record = FillFeeRecord::from_perp(&output).unwrap();
    assert_eq!(
        (
            record.referrer.amount,
            record.builder.amount,
            record.gross,
            record.rebate,
            record.extra
        ),
        (300, 400, 500, 600, 700)
    );
    assert_eq!(record.referrer.address, Some(OTHER));
}
