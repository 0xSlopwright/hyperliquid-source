//! Offline reconstruction of the fee behavior established for node #94.
//!
//! The crate deliberately stops at the retained evidence boundary. It does not
//! implement fee-schedule rollover, live state lookup, or full spot/perp
//! settlement.

mod arithmetic;
mod engine;
mod ledger;
mod rate_grid;
mod types;
mod volume;

pub use engine::FeeEngine;
pub use ledger::{
    FeeLedger, FillFeeRecord, LedgerApplication, LedgerCreation, LedgerCredit, LedgerField,
    LedgerRecordKind, SubtractionStage, TokenFeeState,
};
pub use rate_grid::{RateGridInput, RateGridOutcome, RateGridValues, validate_rate_grid_point};
pub use types::{
    Address, ArithmeticEvent, AssetFeeScale, BuilderFee, Computation, FeeError, FeeProfile,
    FeeRates, FeeRecipient, FeeSchedule, LiquidityRole, MarketRates, PerpFeeOutput, PerpFill,
    RateRow, SpotCategory, SpotFeeOutput, SpotFill, VolumeTier,
};
pub use volume::{
    MAX_DEPLOYER_FEE_SCALE, RATE_APPLICATION_LIMIT, RATE_PRODUCT_CLAMP, VolumeConversionInput,
    VolumeConversionOutput, deployer_scale_in_target_range, volume_conversion,
};

/// SHA-256 of the only captured binary this component targets.
pub const TARGET_SHA256: &str = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f";
