use node94_margin_risk::{
    AccountingMode, LATER_TIER_LOWER_INCLUSIVE_MAX, MarginTable, PositionInput, PositionMargin,
    RawMarginTable, RawMarginTier, calculate_position_margin, initial_requirement,
    maintenance_requirement, select_tier,
};

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn known_table() -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: String::new(),
        tiers: vec![
            RawMarginTier {
                lower_bound: 0,
                max_leverage: 50,
            },
            RawMarginTier {
                lower_bound: 1_000,
                max_leverage: 20,
            },
            RawMarginTier {
                lower_bound: 1_000_000,
                max_leverage: 10,
            },
        ],
    })
    .unwrap()
}

#[test]
fn deterministic_tier_mutations_are_either_rejected_or_invariant_preserving() {
    let mut state = 0x94_3b71_79cd_967d_u64;
    for case in 0..512 {
        let count = (next(&mut state) % 5) as usize;
        let description_len = (next(&mut state) % 253) as usize;
        let mut tiers = Vec::with_capacity(count);
        for index in 0..count {
            let random = next(&mut state);
            let lower_bound = match random & 7 {
                0 => 0,
                1 => LATER_TIER_LOWER_INCLUSIVE_MAX,
                2 => LATER_TIER_LOWER_INCLUSIVE_MAX + 1,
                _ => random % (LATER_TIER_LOWER_INCLUSIVE_MAX + 2),
            };
            tiers.push(RawMarginTier {
                lower_bound: if index == 0 && random & 1 == 0 {
                    0
                } else {
                    lower_bound
                },
                max_leverage: (next(&mut state) % 53) as u8,
            });
        }
        let raw = RawMarginTable {
            description: "x".repeat(description_len),
            tiers,
        };

        if let Ok(table) = MarginTable::try_from(raw) {
            assert!((1..=3).contains(&table.tiers().len()), "case {case}");
            assert_eq!(table.tiers()[0].lower_bound(), 0, "case {case}");
            for pair in table.tiers().windows(2) {
                assert!(pair[0].lower_bound() < pair[1].lower_bound(), "case {case}");
                assert!(
                    pair[0].max_leverage() > pair[1].max_leverage(),
                    "case {case}"
                );
            }

            let notional = next(&mut state);
            let tier = *select_tier(&table, notional);
            let initial = initial_requirement(notional, tier);
            let maintenance = maintenance_requirement(notional, tier);
            assert_eq!(initial.is_err(), tier.max_leverage() == 0, "case {case}");
            assert_eq!(
                maintenance.is_err(),
                tier.max_leverage() == 0,
                "case {case}"
            );
        }
    }
}

#[test]
fn deterministic_position_mutations_preserve_success_invariants() {
    let table = known_table();
    let mut state = 0x007d_3717_4800_0094_u64;
    let prices = [-1, 0, 1, 2, i64::MAX];
    let sizes = [i64::MIN, -1, 0, 1, i64::MAX];

    for case in 0..512 {
        let input = PositionInput {
            accounting: AccountingMode::from_raw(next(&mut state) as u8),
            leverage_divisor: next(&mut state) as u32,
            margin: next(&mut state) as i64,
            size: sizes[(next(&mut state) as usize) % sizes.len()],
            tier_selector: (next(&mut state) % 53) as u32,
        };
        let price = prices[(next(&mut state) as usize) % prices.len()];
        let raw_mode = (next(&mut state) % 8) as u8;
        let cap = next(&mut state) as u8;

        if let Ok(output) = calculate_position_margin(input, price, raw_mode, cap, Some(&table)) {
            match output {
                PositionMargin::Cross {
                    signed_notional,
                    absolute_notional,
                    ..
                } => {
                    assert_eq!(input.accounting, AccountingMode::Cross, "case {case}");
                    assert_eq!(
                        absolute_notional,
                        signed_notional.unsigned_abs(),
                        "case {case}"
                    );
                }
                PositionMargin::Isolated {
                    margin_after,
                    effective_margin,
                    absolute_notional,
                    previous_margin,
                    ..
                } => {
                    assert_eq!(input.accounting, AccountingMode::Isolated, "case {case}");
                    assert_eq!(previous_margin, input.margin, "case {case}");
                    assert_eq!(effective_margin, margin_after.max(0) as u64, "case {case}");
                    assert!(absolute_notional <= 1_u64 << 63, "case {case}");
                }
            }
        }
    }
}
