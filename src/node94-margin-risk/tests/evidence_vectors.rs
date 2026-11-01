use node94_margin_risk::{
    AccountingMode, MarginTable, PositionInput, PositionMargin, RawMarginTable, RawMarginTier,
    calculate_position_margin, initial_requirement, maintenance_requirement, select_tier,
};

fn table() -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: "RE-007 established fixture".to_owned(),
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
fn requirement_fixture_matches_authenticated_packet_boundaries() {
    let table = table();
    let fixture = include_str!("fixtures/requirement-vectors.tsv");
    for (line_number, line) in fixture.lines().enumerate().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "fixture line {}", line_number + 1);
        let notional = fields[0].parse::<u64>().unwrap();
        let selected_lower = fields[1].parse::<u64>().unwrap();
        let expected_initial = fields[2].parse::<u64>().unwrap();
        let expected_maintenance = fields[3].parse::<u64>().unwrap();
        let tier = *select_tier(&table, notional);
        assert_eq!(tier.lower_bound(), selected_lower, "notional {notional}");
        assert_eq!(
            initial_requirement(notional, tier),
            Ok(expected_initial),
            "notional {notional}"
        );
        assert_eq!(
            maintenance_requirement(notional, tier),
            Ok(expected_maintenance),
            "notional {notional}"
        );
    }
}

#[test]
fn position_fixture_exercises_public_api_and_all_modes() {
    let table = table();
    let fixture = include_str!("fixtures/position-vectors.tsv");
    for (line_number, line) in fixture.lines().enumerate().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 12, "fixture line {}", line_number + 1);
        let accounting = match fields[0] {
            "cross" => AccountingMode::Cross,
            "isolated" => AccountingMode::Isolated,
            value => panic!("unknown accounting fixture value {value}"),
        };
        let input = PositionInput {
            accounting,
            size: fields[1].parse().unwrap(),
            leverage_divisor: fields[4].parse().unwrap(),
            margin: fields[5].parse().unwrap(),
            tier_selector: fields[6].parse().unwrap(),
        };
        let price = fields[2].parse().unwrap();
        let mode = fields[3].parse().unwrap();
        let cap = fields[7].parse().unwrap();
        let expected_signed = fields[8].parse::<i64>().unwrap();
        let expected_effective = fields[9].parse::<u64>().unwrap();
        let expected_notional = fields[10].parse::<u64>().unwrap();
        let expected_computed = fields[11].parse::<u64>().unwrap();

        let result = calculate_position_margin(input, price, mode, cap, Some(&table)).unwrap();
        match result {
            PositionMargin::Cross {
                signed_notional,
                effective_margin,
                absolute_notional,
            } => {
                assert_eq!(accounting, AccountingMode::Cross);
                assert_eq!(signed_notional, expected_signed);
                assert_eq!(effective_margin, expected_effective);
                assert_eq!(absolute_notional, expected_notional);
                assert_eq!(effective_margin, expected_computed);
            }
            PositionMargin::Isolated {
                margin_after,
                effective_margin,
                absolute_notional,
                computed_requirement,
                ..
            } => {
                assert_eq!(accounting, AccountingMode::Isolated);
                assert_eq!(margin_after, expected_signed);
                assert_eq!(effective_margin, expected_effective);
                assert_eq!(absolute_notional, expected_notional);
                assert_eq!(computed_requirement, expected_computed);
            }
        }
    }
}
