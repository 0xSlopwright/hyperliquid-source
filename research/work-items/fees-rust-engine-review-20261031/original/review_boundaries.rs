use node94_fees::{Address, FeeError, FeeLedger, FillFeeRecord, LedgerCredit, TokenFeeState};

const PAYER: Address = Address::new([11; 20]);
const REFERRER: Address = Address::new([22; 20]);

fn record() -> FillFeeRecord {
    FillFeeRecord {
        referrer: LedgerCredit {
            tag: 1,
            amount: 10,
            address: Some(REFERRER),
        },
        builder: LedgerCredit {
            tag: 1,
            amount: 2,
            address: Some(PAYER),
        },
        gross: 100,
        rebate: 0,
        extra: 7,
    }
}

fn check_unresolved_recipient(missing: &'static str) {
    let mut ledger = FeeLedger::default();
    ledger.insert_token_state(
        PAYER,
        360,
        TokenFeeState {
            trial_extra: 5,
            ..TokenFeeState::default()
        },
    );
    let before = ledger.clone();
    let mut invalid = record();
    if missing == "referrer" {
        invalid.referrer.address = None;
    } else {
        invalid.builder.address = None;
    }
    assert_eq!(
        ledger.apply(PAYER, 360, invalid),
        Err(FeeError::MissingLedgerRecipient(missing))
    );
    assert_eq!(
        ledger, before,
        "{missing} input error changed state before a retry"
    );
    let mut expected = before;
    expected.apply(PAYER, 360, record()).unwrap();
    ledger.apply(PAYER, 360, record()).unwrap();
    assert_eq!(ledger, expected);
}

#[test]
fn unresolved_referrer_does_not_change_state() {
    check_unresolved_recipient("referrer");
}

#[test]
fn unresolved_builder_does_not_change_state() {
    check_unresolved_recipient("builder");
}

#[test]
fn inactive_recipient_fields_remain_unused() {
    let mut ledger = FeeLedger::default();
    let r = FillFeeRecord {
        referrer: LedgerCredit {
            tag: 2,
            amount: 10,
            address: None,
        },
        builder: LedgerCredit {
            tag: 1,
            amount: 0,
            address: None,
        },
        ..record()
    };
    ledger.apply(PAYER, 360, r).unwrap();
    assert_eq!(ledger.owner_bucket_count(), 1);
    assert_eq!(ledger.token_state(PAYER, 360).unwrap().trial_extra, 7);
}
