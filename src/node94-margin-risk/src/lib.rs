//! Independently authored, offline margin calculations established for node #94.
//!
//! This crate deliberately excludes live state, networking, order execution,
//! liquidation sizing, and balance transfers.

#![forbid(unsafe_code)]

mod requirements;
mod tiers;
mod types;

pub use requirements::{
    RequirementError, initial_requirement, maintenance_requirement, select_tier,
};
pub use tiers::TierConstructionError;
pub use types::{
    LATER_TIER_LOWER_INCLUSIVE_MAX, MAX_DESCRIPTION_BYTES, MAX_LEVERAGE, MAX_TIERS, MarginTable,
    MarginTier, RawMarginTable, RawMarginTier, WIRE_NOTIONAL_EXCLUSIVE_MAX,
};
