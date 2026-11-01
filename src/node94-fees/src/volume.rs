use crate::arithmetic::target_i64;
use crate::{Computation, FeeError};

pub const RATE_APPLICATION_LIMIT: u64 = u64::MAX / 100;
pub const RATE_PRODUCT_CLAMP: i64 = i64::MAX / 100;
pub const MAX_DEPLOYER_FEE_SCALE: f64 = 3.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VolumeConversionInput {
    pub notional: i64,
    pub rate: f64,
    pub trial: bool,
    pub trial_multiplier: f64,
    pub tenth_scale: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeConversionOutput {
    pub scaled: u64,
    pub unscaled: u64,
}

/// Range comparison used by the established deployer-fee-scale setter.
///
/// This intentionally returns true for NaN: both target `ucomisd` rejection
/// branches are false for NaN. The public action parser was not part of that
/// packet and may prevent NaN from reaching the setter.
pub fn deployer_scale_in_target_range(scale: f64) -> bool {
    // A Rust range would reject NaN, unlike the target's two ordered compares.
    #[allow(clippy::manual_range_contains)]
    !(0.0 > scale || scale > MAX_DEPLOYER_FEE_SCALE)
}

pub fn volume_conversion(
    input: VolumeConversionInput,
) -> Result<Computation<VolumeConversionOutput>, FeeError> {
    if input.notional < 0 {
        return Err(FeeError::NegativeNotional);
    }
    let mut multiplier = if input.trial {
        input.trial_multiplier
    } else {
        1.0
    };
    if input.tenth_scale {
        multiplier *= 0.1;
    }

    let converted = target_i64(multiplier * input.notional as f64).max(0) as u64;
    let rated = if converted > RATE_APPLICATION_LIMIT {
        converted
    } else {
        rate_step(converted, input.rate)?
    };
    let notional = input.notional as u64;
    let unrated = if notional > RATE_APPLICATION_LIMIT {
        notional
    } else {
        rate_step(notional, input.rate)?
    };

    Ok(Computation::new(
        VolumeConversionOutput {
            scaled: rated / 10_000,
            unscaled: unrated / 10_000,
        },
        Vec::new(),
    ))
}

fn rate_step(value: u64, rate: f64) -> Result<u64, FeeError> {
    let product = target_i64(value as f64 * rate);
    if product == i64::MIN {
        return Err(FeeError::RateProductAbsoluteOverflow);
    }
    let clamped = product.clamp(-RATE_PRODUCT_CLAMP, RATE_PRODUCT_CLAMP);
    Ok(clamped.max(0) as u64)
}
