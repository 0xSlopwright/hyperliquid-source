use node94_fees::{
    Address, AssetFeeScale, BuilderFee, FeeEngine, FeeProfile, FeeRates, FeeSchedule,
    LiquidityRole, MarketRates, PerpFill, RateRow, SpotCategory, SpotFill,
};

const PAYER: Address = Address::new([1; 20]);
const REFERRER: Address = Address::new([2; 20]);
const BUILDER: Address = Address::new([3; 20]);

fn rates() -> FeeRates {
    FeeRates::new(
        MarketRates::new(1e-4, 3.5e-4),
        MarketRates::new(2.5e-4, 7e-4),
    )
}

fn engine() -> FeeEngine {
    FeeEngine::new(FeeSchedule {
        default_rates: rates(),
        volume_tiers: vec![],
        low_volume_discount: 0.04,
        flagged_referrer_share: 0.1,
        multiplier_90: 1.0,
        multiplier_98: 1.0,
    })
    .unwrap()
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

fn spot() -> SpotFill {
    SpotFill {
        payer: PAYER,
        notional: 1_000_000_000_000,
        role: LiquidityRole::Taker,
        category: SpotCategory(0),
        category_weight: 1.0,
        aligned_quote: false,
        quote_leg: true,
        flagged: false,
        builder: None,
    }
}

#[test]
fn evidence_perp_examples() {
    let engine = engine();

    let taker = engine.compute_perp(perp()).unwrap().value;
    assert_eq!(
        (taker.gross, taker.rebate, taker.deployer, taker.protocol),
        (350_000_000, 0, 0, 350_000_000)
    );

    let maker = engine
        .compute_perp(PerpFill {
            role: LiquidityRole::Maker,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!((maker.gross, maker.protocol), (100_000_000, 100_000_000));

    let tenth = engine
        .compute_perp(PerpFill {
            asset_scale: AssetFeeScale::Tenth,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!((tenth.gross, tenth.protocol), (35_000_000, 35_000_000));

    let half = engine
        .compute_perp(PerpFill {
            deployer_scale: 0.5,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(
        (half.gross, half.deployer, half.protocol),
        (524_999_999, 174_999_999, 350_000_000)
    );

    let double = engine
        .compute_perp(PerpFill {
            deployer_scale: 2.0,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(
        (double.gross, double.deployer, double.protocol),
        (1_400_000_000, 700_000_000, 700_000_000)
    );

    let builder = engine
        .compute_perp(PerpFill {
            builder: Some(BuilderFee {
                address: BUILDER,
                rate_units: 10,
            }),
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(builder.gross, 450_000_000);
    assert_eq!(builder.builder.unwrap().amount, 100_000_000);

    let exempt = engine
        .compute_perp(PerpFill {
            payer: Address::EXEMPT_FE,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!((exempt.gross, exempt.protocol), (0, 0));
}

#[test]
fn evidence_negative_and_referred_examples() {
    let negative_engine = FeeEngine::new(FeeSchedule {
        default_rates: FeeRates::new(MarketRates::new(-2e-5, 3.5e-4), MarketRates::default()),
        volume_tiers: vec![],
        low_volume_discount: 0.04,
        flagged_referrer_share: 0.1,
        multiplier_90: 1.0,
        multiplier_98: 1.0,
    })
    .unwrap();
    let negative = negative_engine
        .compute_perp(PerpFill {
            role: LiquidityRole::Maker,
            deployer_scale: 1.0,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(
        (
            negative.gross,
            negative.rebate,
            negative.deployer,
            negative.protocol
        ),
        (0, 20_000_000, -10_000_000, -10_000_000)
    );

    let mut referred_engine = engine();
    referred_engine.insert_profile(
        PAYER,
        FeeProfile {
            row_tag: 1,
            row: RateRow {
                current: rates(),
                carried_weight: 1.0,
                ..RateRow::default()
            },
            binding_flags: 1,
            referrer: Some(REFERRER),
            volume_words: vec![1000],
        },
    );
    let referred = referred_engine
        .compute_perp(PerpFill {
            flagged: true,
            ..perp()
        })
        .unwrap()
        .value;
    assert_eq!(referred.gross, 336_000_000);
    assert_eq!(referred.referrer.unwrap().amount, 33_600_000);
    assert_eq!(referred.protocol, 302_400_000);
}

#[test]
fn evidence_spot_examples() {
    let engine = engine();
    let taker = engine.compute_spot(spot()).unwrap().value;
    assert_eq!((taker.gross, taker.rebate), (700_000_000, 0));

    let category_one = engine
        .compute_spot(SpotFill {
            category: SpotCategory(1),
            ..spot()
        })
        .unwrap()
        .value;
    assert_eq!(category_one.gross, 140_000_000);

    let weighted = engine
        .compute_spot(SpotFill {
            category: SpotCategory(2),
            category_weight: 0.25,
            ..spot()
        })
        .unwrap()
        .value;
    assert_eq!(weighted.gross, 175_000_000);

    let no_quote_leg = engine
        .compute_spot(SpotFill {
            quote_leg: false,
            ..spot()
        })
        .unwrap()
        .value;
    assert_eq!(no_quote_leg.gross, 700_000_000);
    assert!(no_quote_leg.builder.is_none() && no_quote_leg.referrer.is_none());
}
