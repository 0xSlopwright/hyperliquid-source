use crate::arithmetic::target_i64;
use crate::{ArithmeticEvent, Computation, FeeError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateGridInput {
    pub lowest_cross_rate: f64,
    pub referral_share: f64,
    pub max_keep: f64,
    pub lowest_add_rate: f64,
    pub first_cross_rate: f64,
    pub scale: f64,
    pub notional: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RateGridValues {
    pub discounted_fee: i64,
    pub keep: i64,
    pub add: Option<i64>,
    pub net: Option<i64>,
    pub maximum_fee: Option<i64>,
    pub maximum_keep: Option<i64>,
    pub whole: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateGridOutcome {
    Pass(RateGridValues),
    RejectDiscountedFee(RateGridValues),
    RejectNet(RateGridValues),
    RejectMaximumFee(RateGridValues),
    RejectRounding(RateGridValues),
}

pub fn validate_rate_grid_point(
    input: RateGridInput,
) -> Result<Computation<RateGridOutcome>, FeeError> {
    if input.notional > i64::MAX as u64 {
        return Err(FeeError::RateGridNotionalOutOfRange);
    }
    let mut events = Vec::new();
    let notional = input.notional as f64;
    let discounted_fee =
        target_i64((1.0 - input.referral_share) * input.lowest_cross_rate * input.scale * notional);
    let keep = target_i64(discounted_fee as f64 * input.max_keep);
    let mut values = RateGridValues {
        discounted_fee,
        keep,
        ..RateGridValues::default()
    };
    if keep < 0 {
        return Ok(Computation::new(
            RateGridOutcome::RejectDiscountedFee(values),
            events,
        ));
    }

    let add = target_i64(input.lowest_add_rate * input.scale * notional);
    values.add = Some(add);
    let without_add = saturating_signed_sub(discounted_fee, keep, &mut events);
    let net = saturating_signed_add(without_add, add, &mut events);
    values.net = Some(net);
    if net < 0 {
        return Ok(Computation::new(RateGridOutcome::RejectNet(values), events));
    }

    let maximum_fee = target_i64(input.scale * input.first_cross_rate * notional);
    let maximum_keep = target_i64(maximum_fee as f64 * input.max_keep);
    values.maximum_fee = Some(maximum_fee);
    values.maximum_keep = Some(maximum_keep);
    if maximum_keep < 0 {
        return Ok(Computation::new(
            RateGridOutcome::RejectMaximumFee(values),
            events,
        ));
    }

    let partial = maximum_keep as u64 + maximum_fee.max(0) as u64;
    let whole = match partial.checked_add(add.unsigned_abs()) {
        Some(value) => value,
        None => {
            events.push(ArithmeticEvent::RateGridUnsignedSaturated);
            u64::MAX
        }
    };
    values.whole = Some(whole);
    let outcome = if whole >= input.notional {
        RateGridOutcome::RejectRounding(values)
    } else {
        RateGridOutcome::Pass(values)
    };
    Ok(Computation::new(outcome, events))
}

fn saturating_signed_sub(left: i64, right: i64, events: &mut Vec<ArithmeticEvent>) -> i64 {
    match left.checked_sub(right) {
        Some(value) => value,
        None => {
            events.push(ArithmeticEvent::RateGridSignedSaturated);
            if right.is_negative() {
                i64::MAX
            } else {
                i64::MIN
            }
        }
    }
}

fn saturating_signed_add(left: i64, right: i64, events: &mut Vec<ArithmeticEvent>) -> i64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => {
            events.push(ArithmeticEvent::RateGridSignedSaturated);
            if right.is_negative() {
                i64::MIN
            } else {
                i64::MAX
            }
        }
    }
}
