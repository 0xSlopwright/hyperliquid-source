use crate::{Address, ArithmeticEvent, LedgerField, SubtractionStage};

pub(crate) const DISCOUNT_VOLUME_LIMIT: u64 = 2_500_000_000;
pub(crate) const REFERRER_VOLUME_LIMIT: u64 = 100_000_000_000;

/// The repeated SSE conversion established in the fee packets.
///
/// NaN and infinities become zero. Finite values truncate toward zero and
/// saturate at the signed 64-bit endpoints.
pub(crate) fn target_i64(value: f64) -> i64 {
    if !value.is_finite() {
        0
    } else if value <= -(2.0_f64.powi(63)) {
        i64::MIN
    } else if value >= 2.0_f64.powi(63) {
        i64::MAX
    } else {
        value.trunc() as i64
    }
}

/// `maxsd a, b`: choose the second operand unless `a > b`.
pub(crate) fn target_max(a: f64, b: f64) -> f64 {
    if a > b { a } else { b }
}

/// `minsd a, b`: choose the second operand unless `a < b`.
pub(crate) fn target_min(a: f64, b: f64) -> f64 {
    if a < b { a } else { b }
}

pub(crate) fn saturating_u64_add(
    left: u64,
    right: u64,
    event: ArithmeticEvent,
    events: &mut Vec<ArithmeticEvent>,
) -> u64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => {
            events.push(event);
            u64::MAX
        }
    }
}

pub(crate) fn saturating_i64_sub(left: i64, right: i64, events: &mut Vec<ArithmeticEvent>) -> i64 {
    match left.checked_sub(right) {
        Some(value) => value,
        None => {
            events.push(ArithmeticEvent::ProtocolSplitSaturated);
            if right.is_negative() {
                i64::MAX
            } else {
                i64::MIN
            }
        }
    }
}

pub(crate) fn floor_sub(
    left: u64,
    right: u64,
    stage: SubtractionStage,
    events: &mut Vec<ArithmeticEvent>,
) -> u64 {
    match left.checked_sub(right) {
        Some(value) => value,
        None => {
            events.push(ArithmeticEvent::LedgerSubtractionFloored { stage });
            0
        }
    }
}

pub(crate) fn ledger_add_event(owner: Address, token: u64, field: LedgerField) -> ArithmeticEvent {
    ArithmeticEvent::LedgerAdditionSaturated {
        owner,
        token,
        field,
    }
}
