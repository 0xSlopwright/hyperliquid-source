use node94_margin_risk::{
    CandidateAdmission, CandidateSubject, CrossMarginSummary, MarginTable, RawMarginTable,
    RawMarginTier, TierConstructionError, admit_cross_candidate, initial_requirement,
    maintenance_requirement, select_tier,
};

const BOUNDARIES: &str =
    include_str!("../../../research/work-items/RE-007-margin-path-94/boundaries.tsv");
const SUBJECT: CandidateSubject = CandidateSubject::new([0x07; 20]);

fn raw(tiers: &[(u64, u8)]) -> RawMarginTable {
    RawMarginTable {
        description: String::new(),
        tiers: tiers
            .iter()
            .map(|&(lower_bound, max_leverage)| RawMarginTier {
                lower_bound,
                max_leverage,
            })
            .collect(),
    }
}

fn established_table() -> MarginTable {
    MarginTable::try_from(raw(&[(0, 50), (1_000, 20), (1_000_000, 10)])).unwrap()
}

#[test]
fn maintained_boundary_fixture_drives_the_public_contract() {
    let table = established_table();
    let mut rows = 0;

    for (line_index, line) in BOUNDARIES.lines().enumerate().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5, "fixture line {}", line_index + 1);
        rows += 1;

        match fields[0] {
            "requirement" => {
                let notional = fields[1].parse::<u64>().unwrap();
                let tier = *select_tier(&table, notional);
                assert_eq!(
                    initial_requirement(notional, tier),
                    Ok(fields[2].parse().unwrap()),
                    "fixture line {}",
                    line_index + 1
                );
                assert_eq!(
                    maintenance_requirement(notional, tier),
                    Ok(fields[3].parse().unwrap()),
                    "fixture line {}",
                    line_index + 1
                );
            }
            "admission:empty" => {
                assert_eq!(
                    MarginTable::try_from(raw(&[])),
                    Err(TierConstructionError::EmptyTiers)
                );
            }
            "admission:first-nonzero" => {
                assert_eq!(
                    MarginTable::try_from(raw(&[(1, 50)])),
                    Err(TierConstructionError::FirstLowerBoundNotZero { lower_bound: 1 })
                );
            }
            "admission:wire-limit" => {
                let lower_bound = 0x0ccc_cccc_cccc_cccc;
                assert_eq!(
                    MarginTable::try_from(raw(&[(lower_bound, 50)])),
                    Err(TierConstructionError::WireNotionalTooLarge {
                        index: 0,
                        lower_bound,
                    })
                );
            }
            "admission:too-many" => {
                assert!(matches!(
                    MarginTable::try_from(raw(&[(0, 50), (1, 40), (2, 30), (3, 20)])),
                    Err(TierConstructionError::TooManyTiers { count: 4 })
                ));
            }
            "admission:description-251-precedes-too-many" => {
                let mut input = raw(&[(0, 50), (0, 50), (0, 50), (0, 50)]);
                input.description = "x".repeat(251);
                assert_eq!(
                    MarginTable::try_from(input),
                    Err(TierConstructionError::DescriptionTooLong { bytes: 251 })
                );
            }
            "admission:leverage-51" => {
                assert_eq!(
                    MarginTable::try_from(raw(&[(0, 51)])),
                    Err(TierConstructionError::MaxLeverageTooLarge {
                        index: 0,
                        max_leverage: 51,
                    })
                );
            }
            "admission:equal-leverage" => {
                assert!(matches!(
                    MarginTable::try_from(raw(&[(0, 50), (1, 50)])),
                    Err(TierConstructionError::LeverageNotStrictlyDecreasing { index: 1, .. })
                ));
            }
            "admission:decreasing-lower" => {
                assert!(matches!(
                    MarginTable::try_from(raw(&[(0, 50), (2, 40), (1, 30)])),
                    Err(TierConstructionError::LowerBoundNotStrictlyIncreasing { index: 2, .. })
                ));
            }
            "admission:single-zero-leverage" => {
                assert!(MarginTable::try_from(raw(&[(0, 0)])).is_ok());
            }
            "admission:multi-zero-leverage" => {
                assert!(matches!(
                    MarginTable::try_from(raw(&[(0, 1), (1, 0)])),
                    Err(TierConstructionError::ZeroDivisorReached { index: 1, .. })
                ));
            }
            "eligibility" => {
                let surplus = fields[1].parse::<i64>().unwrap();
                let admission = admit_cross_candidate(
                    CrossMarginSummary {
                        signed_equity: surplus,
                        maintenance_requirement: 0,
                    },
                    SUBJECT,
                )
                .unwrap();
                assert_eq!(
                    matches!(admission, CandidateAdmission::Admitted(_)),
                    fields[4] == "eligible",
                    "fixture line {}",
                    line_index + 1
                );
            }
            kind => panic!("unhandled maintained boundary row {kind}"),
        }
    }

    assert_eq!(rows, 24);
}

#[test]
fn malformed_input_is_rejected_without_a_partial_table() {
    let invalid = raw(&[(0, 50), (1_000, 20), (999, 10)]);
    assert!(matches!(
        MarginTable::try_from(invalid),
        Err(TierConstructionError::LowerBoundNotStrictlyIncreasing { index: 2, .. })
    ));
}
