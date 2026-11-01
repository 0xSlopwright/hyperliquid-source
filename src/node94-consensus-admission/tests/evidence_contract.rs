use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use node94_consensus_admission::{
    AdmissionError, BlockHash, Hardfork, Round, ValidatorAddress, OUTBOUND_BLOCK_TAG,
    UNKNOWN_TRANSACTION_TAG,
};

const TARGET_SHA256: &str = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f";

fn packet() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/work-items/RE-008-block-admission-94")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(name: &str) -> String {
    fs::read_to_string(packet().join(name)).expect("retained RE-008 packet")
}

fn data_rows(text: &str) -> usize {
    text.lines().skip(1).filter(|line| !line.is_empty()).count()
}

fn assert_gate_contract(gates: &str, qc_tc: &str) -> Result<(), &'static str> {
    let required = [
        "stake set lookup for the block round",
        "proposer rule for the block round succeeds",
        "QC at block +0x18 verifies",
        "QC round is strictly under block round",
        "TC round == block round - 1",
        "proposer found in the stake set",
        "block round >= state +0x198",
        "block hash not in the block map",
        "no stored block has this round",
        "request row (tag byte 0, block hash) leaves",
        "each unknown hash gets a tx row",
        "block goes into the map",
    ];
    if required.iter().all(|needle| gates.contains(needle))
        && qc_tc.contains("3 * signed > 2 * total on 128 bit values, strict")
        && qc_tc.contains("the later vote wins a tie")
        && qc_tc.contains("QC hash all zero and 0 votes")
    {
        Ok(())
    } else {
        Err("ordered admission contract changed")
    }
}

#[test]
fn retained_packet_has_the_qualified_target_identity_and_counts() {
    let evidence = read("evidence.json");
    for field in [
        format!("\"sha256\": \"{TARGET_SHA256}\""),
        "\"cases\": 456".to_owned(),
        "\"functions_run\": 15".to_owned(),
        "\"function_bytes\": 17099".to_owned(),
        "\"reached_bytes\": 13559".to_owned(),
        "\"pins\": 99".to_owned(),
        "\"killed\": 497".to_owned(),
        "\"survived\": 183".to_owned(),
    ] {
        assert!(evidence.contains(&field), "missing {field}");
    }
    assert_eq!(data_rows(&read("cases.tsv")), 456);
    assert_eq!(data_rows(&read("functions.tsv")), 15);
    assert_eq!(data_rows(&read("gates.tsv")), 22);
    assert_eq!(data_rows(&read("qc-tc-gates.tsv")), 29);
}

#[test]
fn captured_executable_matches_the_packet_digest() {
    let target = repository_root().join("artifacts/node/94/hl-node");
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&target)
        .output()
        .expect("shasum is required by repository verification policy");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("shasum output is UTF-8");
    assert_eq!(stdout.split_whitespace().next(), Some(TARGET_SHA256));
}

#[test]
fn native_function_boundaries_are_pinned() {
    let functions = read("functions.tsv");
    for row in [
        "0x44b8410\t0x44b95a0\t4496\t3746",
        "0x4758d70\t0x47593a0\t1584\t1517",
        "0x47594f0\t0x4759963\t1139\t1072",
        "0x4ad90d0\t0x4ad9847\t1911\t973",
        "0x42c9930\t0x42c9a21\t241\t211",
        "0x454aa10\t0x454ad45\t821\t770",
    ] {
        assert!(functions.contains(row), "missing function row {row}");
    }
}

#[test]
fn ordered_gate_text_matches_the_implemented_contract() {
    assert_eq!(
        assert_gate_contract(&read("gates.tsv"), &read("qc-tc-gates.tsv")),
        Ok(())
    );
}

#[test]
fn negative_formula_and_order_mutations_are_rejected() {
    let gates = read("gates.tsv");
    let qc_tc = read("qc-tc-gates.tsv");

    let non_strict_round = gates.replace(
        "QC round is strictly under block round",
        "QC round is at or under block round",
    );
    assert!(assert_gate_contract(&non_strict_round, &qc_tc).is_err());

    let non_strict_quorum = qc_tc.replace(
        "3 * signed > 2 * total on 128 bit values, strict",
        "3 * signed >= 2 * total on 64 bit values",
    );
    assert!(assert_gate_contract(&gates, &non_strict_quorum).is_err());

    let first_tie = qc_tc.replace("the later vote wins a tie", "the first vote wins a tie");
    assert!(assert_gate_contract(&gates, &first_tie).is_err());
}

#[test]
fn target_case_table_contains_each_required_boundary_family() {
    let cases = read("cases.tsv");
    for name in [
        "register plain",
        "below committed by one",
        "duplicate hash",
        "same round other hash",
        "no stake table",
        "lag edge exact",
        "base saturated span",
        "genesis qc",
        "genesis qc with hash",
        "qc exact two thirds",
        "qc one over two thirds",
        "qc repeated signer counts once",
        "tc round not previous",
        "tc empty",
        "tc repeated voter counts once",
        "tc tie takes the later vote",
        "register closed channel",
        "register drops request row",
        "register unknown repeated",
    ] {
        assert!(
            cases.lines().any(|line| line.starts_with(name)),
            "missing {name}"
        );
    }
}

#[test]
fn rust_error_tags_match_the_retained_error_table() {
    let address = ValidatorAddress([1; 20]);
    let hash = BlockHash([2; 32]);
    let hardfork = Hardfork {
        version: 2,
        start_round: Round(100),
    };
    let variants = [
        (
            AdmissionError::Hardfork {
                qc: hardfork,
                node: hardfork,
            },
            0x00,
        ),
        (AdmissionError::Signature, 0x01),
        (AdmissionError::QcVoteSignature, 0x02),
        (
            AdmissionError::BlockRound {
                block: Round(1),
                committed: Round(2),
            },
            0x03,
        ),
        (AdmissionError::BadQcRound, 0x04),
        (AdmissionError::BadTcRound, 0x05),
        (AdmissionError::BlockAlreadyRegistered(hash), 0x06),
        (AdmissionError::QcRoundBeforeHardfork, 0x07),
        (AdmissionError::QcGenesisInvalid, 0x08),
        (AdmissionError::QcNoQuorum, 0x09),
        (AdmissionError::TcNoQuorum, 0x0a),
        (AdmissionError::TcNoTimeout, 0x0b),
        (
            AdmissionError::BadBlockProposer {
                proposed: address,
                expected: address,
            },
            0x0c,
        ),
        (
            AdmissionError::DuplicateBlockRound {
                known: hash,
                new: hash,
            },
            0x0e,
        ),
        (
            AdmissionError::TimeoutRoundMismatch {
                supplied: Round(1),
                expected: Round(2),
            },
            0x0f,
        ),
        (AdmissionError::MissingValidatorSetRound(Round(1)), 0x28),
    ];
    let table = read("error-tags.tsv");
    for (error, tag) in variants {
        assert_eq!(error.target_tag(), Some(tag));
        assert!(table
            .lines()
            .any(|line| line.starts_with(&format!("0x{tag:x}\t"))));
    }
}

#[test]
fn unresolved_crypto_edges_remain_explicit_in_the_packet() {
    let stubs = read("stubs.tsv");
    assert!(stubs.contains("0x454c050\tdirect call\tsigning digest:"));
    assert!(stubs.contains("0x576fe58\tdata slot\tsignature recover:"));
    assert!(stubs.contains("0x5773628\tdata slot\tproposer rule:"));
}

#[test]
fn registration_tags_match_the_native_rows() {
    assert_eq!(OUTBOUND_BLOCK_TAG, 0x8000_0000_0000_0000);
    assert_eq!(UNKNOWN_TRANSACTION_TAG, 0x8000_0000_0000_0001);
    let gates = read("gates.tsv");
    assert!(gates.contains("tag 0x8000000000000001"));
    assert!(gates.contains("word 0x8000000000000000"));
}
