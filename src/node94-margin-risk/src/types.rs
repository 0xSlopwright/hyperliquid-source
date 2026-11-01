/// Maximum admitted UTF-8 byte length of a margin-table description.
pub const MAX_DESCRIPTION_BYTES: usize = 250;

/// Maximum number of tiers admitted by the verified constructor.
pub const MAX_TIERS: usize = 3;

/// Maximum leverage admitted by the verified constructor.
pub const MAX_LEVERAGE: u8 = 50;

/// Exclusive wire-level notional bound checked for every tier lower bound.
pub const WIRE_NOTIONAL_EXCLUSIVE_MAX: u64 = 0x0ccc_cccc_cccc_cccc;

/// Inclusive additional bound checked for every tier after the first.
pub const LATER_TIER_LOWER_INCLUSIVE_MAX: u64 = 1_000_000_000_000_000;

/// One unvalidated tier supplied to the target-established constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawMarginTier {
    pub lower_bound: u64,
    pub max_leverage: u8,
}

/// Unvalidated description and tier records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMarginTable {
    pub description: String,
    pub tiers: Vec<RawMarginTier>,
}

/// One validated tier and its target-established accumulated contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarginTier {
    lower_bound: u64,
    prior_contribution: u64,
    max_leverage: u8,
}

impl MarginTier {
    pub(crate) const fn new(lower_bound: u64, prior_contribution: u64, max_leverage: u8) -> Self {
        Self {
            lower_bound,
            prior_contribution,
            max_leverage,
        }
    }

    #[must_use]
    pub const fn lower_bound(self) -> u64 {
        self.lower_bound
    }

    #[must_use]
    pub const fn prior_contribution(self) -> u64 {
        self.prior_contribution
    }

    #[must_use]
    pub const fn max_leverage(self) -> u8 {
        self.max_leverage
    }
}

/// A margin table admitted and constructed in the observed target order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTable {
    description: String,
    tiers: Vec<MarginTier>,
}

impl MarginTable {
    pub(crate) fn from_validated_parts(description: String, tiers: Vec<MarginTier>) -> Self {
        Self { description, tiers }
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub fn tiers(&self) -> &[MarginTier] {
        &self.tiers
    }
}
