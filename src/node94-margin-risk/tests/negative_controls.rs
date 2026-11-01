use node94_margin_risk::{
    CandidateAdmission, CandidateSubject, CrossMarginSummary, MarginTable, RawMarginTable,
    RawMarginTier, admit_cross_candidate, initial_requirement, maintenance_requirement,
    select_tier,
};

fn table() -> MarginTable {
    MarginTable::try_from(RawMarginTable {
        description: "mutation controls".to_owned(),
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
fn boundary_vectors_kill_requirement_formula_mutants() {
    let table = table();

    let initial_notional = 1_000_000;
    let tier = *select_tier(&table, initial_notional);
    let target_initial = initial_requirement(initial_notional, tier).unwrap();
    let subtract_before_divide = initial_notional.saturating_sub(tier.prior_contribution())
        / (2 * u64::from(tier.max_leverage()));
    assert_ne!(target_initial, subtract_before_divide);

    let maintenance_notional = 1_u64 << 63;
    let tier = *select_tier(&table, maintenance_notional);
    let target_maintenance = maintenance_requirement(maintenance_notional, tier).unwrap();
    let wrapping_numerator = maintenance_notional.wrapping_mul(2).saturating_sub(
        tier.prior_contribution()
            .saturating_mul(4 * u64::from(tier.max_leverage())),
    );
    let wrapping_maintenance = wrapping_numerator / (6 * u64::from(tier.max_leverage()));
    assert_ne!(target_maintenance, wrapping_maintenance);
}

#[test]
fn zero_surplus_kills_the_less_than_or_equal_admission_mutant() {
    let admission = admit_cross_candidate(
        CrossMarginSummary {
            signed_equity: 7,
            maintenance_requirement: 7,
        },
        CandidateSubject::new([0; 20]),
    )
    .unwrap();

    assert_eq!(admission, CandidateAdmission::Rejected { surplus: 0 });
    let mutated_eligible = 0_i64 <= 0;
    assert!(mutated_eligible);
    assert!(!matches!(admission, CandidateAdmission::Admitted(_)));
}
