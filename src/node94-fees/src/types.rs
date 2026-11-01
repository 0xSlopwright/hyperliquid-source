use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::{LedgerField, SubtractionStage};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub const EXEMPT_FE: Self = Self([0xfe; 20]);
    pub const EXEMPT_FF: Self = Self([0xff; 20]);

    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn is_fee_exempt(self) -> bool {
        self.0 == Self::EXEMPT_FE.0 || self.0 == Self::EXEMPT_FF.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiquidityRole {
    Maker,
    Taker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetFeeScale {
    Full,
    Tenth,
}

impl AssetFeeScale {
    pub(crate) const fn factor(self) -> f64 {
        match self {
            Self::Full => 1.0,
            Self::Tenth => 0.1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MarketRates {
    pub maker: f64,
    pub taker: f64,
}

impl MarketRates {
    pub const fn new(maker: f64, taker: f64) -> Self {
        Self { maker, taker }
    }

    pub(crate) const fn select(self, role: LiquidityRole) -> f64 {
        match role {
            LiquidityRole::Maker => self.maker,
            LiquidityRole::Taker => self.taker,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FeeRates {
    pub perp: MarketRates,
    pub spot: MarketRates,
}

impl FeeRates {
    pub const ZERO: Self = Self {
        perp: MarketRates::new(0.0, 0.0),
        spot: MarketRates::new(0.0, 0.0),
    };

    pub const fn new(perp: MarketRates, spot: MarketRates) -> Self {
        Self { perp, spot }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RateRow {
    pub current: FeeRates,
    /// Present when `previous_tag` is non-zero.
    pub previous: Option<FeeRates>,
    pub previous_tag: u32,
    pub volume_anchor: f64,
    pub carried_weight: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FeeProfile {
    /// Low byte non-zero selects `row`; exact value 1 enables its window anchor.
    pub row_tag: u32,
    pub row: RateRow,
    /// Exact value 1 enables the low-volume discount; bit 0 enables referral.
    pub binding_flags: u8,
    pub referrer: Option<Address>,
    /// Per-token volume words summed in key order by the target.
    pub volume_words: Vec<u64>,
}

impl Default for FeeProfile {
    fn default() -> Self {
        Self {
            row_tag: 0,
            row: RateRow {
                carried_weight: 1.0,
                ..RateRow::default()
            },
            binding_flags: 0,
            referrer: None,
            volume_words: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VolumeTier {
    pub minimum_anchor: f64,
    pub share: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FeeSchedule {
    pub default_rates: FeeRates,
    pub volume_tiers: Vec<VolumeTier>,
    pub low_volume_discount: f64,
    pub flagged_referrer_share: f64,
    /// Target context word at `+0x90`.
    pub multiplier_90: f64,
    /// Target context word at `+0x98`.
    pub multiplier_98: f64,
}

impl FeeSchedule {
    pub fn validate(&self) -> Result<(), FeeError> {
        let mut previous = None;
        for tier in &self.volume_tiers {
            if tier.minimum_anchor.is_nan()
                || previous.is_some_and(|value| tier.minimum_anchor < value)
            {
                return Err(FeeError::InvalidTierTable);
            }
            previous = Some(tier.minimum_anchor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuilderFee {
    pub address: Address,
    /// Integer units used by the target as `units / 100000 * notional`.
    pub rate_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PerpFill {
    pub payer: Address,
    pub notional: i64,
    pub role: LiquidityRole,
    pub asset_scale: AssetFeeScale,
    pub deployer_scale: f64,
    pub deployer_deleted: bool,
    pub trial: bool,
    /// Selects the fixed referral share and suppresses builder tier gain.
    pub flagged: bool,
    pub builder: Option<BuilderFee>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpotCategory(pub u8);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SpotFill {
    pub payer: Address,
    pub notional: i64,
    pub role: LiquidityRole,
    pub category: SpotCategory,
    pub category_weight: f64,
    pub aligned_quote: bool,
    pub quote_leg: bool,
    pub flagged: bool,
    pub builder: Option<BuilderFee>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeRecipient {
    pub address: Address,
    pub amount: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerpFeeOutput {
    pub referrer: Option<FeeRecipient>,
    pub builder: Option<FeeRecipient>,
    pub gross: u64,
    pub rebate: u64,
    pub extra: u64,
    pub deployer: i64,
    pub protocol: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpotFeeOutput {
    pub referrer: Option<FeeRecipient>,
    pub builder: Option<FeeRecipient>,
    pub gross: u64,
    pub rebate: u64,
    pub extra: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArithmeticEvent {
    WindowSumSaturated {
        owner: Address,
    },
    GrossWithBuilderSaturated,
    ProtocolSplitSaturated,
    LedgerAdditionSaturated {
        owner: Address,
        token: u64,
        field: LedgerField,
    },
    LedgerSubtractionFloored {
        stage: SubtractionStage,
    },
    RateGridSignedSaturated,
    RateGridUnsignedSaturated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Computation<T> {
    pub value: T,
    pub events: Vec<ArithmeticEvent>,
}

impl<T> Computation<T> {
    pub(crate) fn new(value: T, events: Vec<ArithmeticEvent>) -> Self {
        Self { value, events }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeError {
    NegativeNotional,
    InvalidTierTable,
    MissingPreviousRates { owner: Address },
    MissingReferrerAddress { owner: Address },
    MissingLedgerRecipient(&'static str),
    LedgerScaleOverflow(&'static str),
    RateProductAbsoluteOverflow,
    RateGridNotionalOutOfRange,
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeNotional => {
                formatter.write_str("negative notional is rejected by node #94")
            }
            Self::InvalidTierTable => {
                formatter.write_str("volume tiers must have non-NaN, nondecreasing anchors")
            }
            Self::MissingPreviousRates { owner } => write!(
                formatter,
                "profile {owner:?} enables previous rates but supplies none"
            ),
            Self::MissingReferrerAddress { owner } => write!(
                formatter,
                "profile {owner:?} enables referral but supplies no address"
            ),
            Self::MissingLedgerRecipient(kind) => {
                write!(formatter, "{kind} ledger tag requires a recipient address")
            }
            Self::LedgerScaleOverflow(field) => {
                write!(formatter, "perp ledger scaling overflowed for {field}")
            }
            Self::RateProductAbsoluteOverflow => {
                formatter.write_str("rate product reached i64::MIN before absolute-value handling")
            }
            Self::RateGridNotionalOutOfRange => {
                formatter.write_str("rate-grid notional exceeds i64::MAX")
            }
        }
    }
}

impl Error for FeeError {}

pub(crate) type Profiles = BTreeMap<Address, FeeProfile>;
