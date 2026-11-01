use crate::book::Book;
use crate::types::{BookError, CancelReason, OrderId, Side, SlotId, UserId};

/// Inclusive target ceiling observed before the fill-record notional write.
pub const MAX_SUPPORTED_NOTIONAL: u64 = 0x7fff_ffff_ffff_fffe;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchStatus {
    None,
    InsufficientMargin,
    MaxPosition,
}

impl MatchStatus {
    pub const fn target_word(self) -> u64 {
        match self {
            Self::None => 0x8000_0000_0000_0018,
            Self::InsufficientMargin => 0x8000_0000_0000_0003,
            Self::MaxPosition => 0x8000_0000_0000_0004,
        }
    }
}

/// The verified result byte. Names beyond the observed exits remain unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchReason(pub u8);

impl MatchReason {
    pub const LIMIT_OR_MASK: Self = Self(0);
    pub const REDUCE_ONLY_BLOCK: Self = Self(1);
    pub const SELF_CROSS: Self = Self(2);
    pub const CONTINUE: Self = Self(3);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetFillMask(pub u16);

impl TargetFillMask {
    pub const BOTH: Self = Self(0x101);

    fn low(self) -> bool {
        self.0 & 0x001 != 0
    }

    fn high(self) -> bool {
        self.0 & 0x100 != 0
    }

    fn maker_allowed(self, taker_side: Side) -> bool {
        match taker_side {
            Side::Bid => self.high(),
            Side::Ask => self.low(),
        }
    }

    fn taker_allowed(self, taker_side: Side) -> bool {
        match taker_side {
            Side::Bid => self.low(),
            Side::Ask => self.high(),
        }
    }
}

/// Results of external helpers observed by the bounded match body.
///
/// This crate intentionally does not calculate margin, leverage, positions,
/// or the fill mask. Supplying these values does not claim those subsystems.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchLimits {
    pub maker_cap: u64,
    pub taker_cap: u64,
    pub taker_other_cap: u64,
    pub fill_mask: TargetFillMask,
}

impl MatchLimits {
    pub const PERMISSIVE: Self = Self {
        maker_cap: u64::MAX,
        taker_cap: u64::MAX,
        taker_other_cap: u64::MAX,
        fill_mask: TargetFillMask::BOTH,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TakerOrder {
    pub order_id: OrderId,
    pub user: UserId,
    pub side: Side,
    /// Execution price already selected by the caller's bounded book walk.
    pub price: u64,
    pub asset: u64,
    pub budget: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fill {
    pub maker_slot: SlotId,
    pub maker_order_id: OrderId,
    pub taker_order_id: OrderId,
    pub maker_user: UserId,
    pub taker_user: UserId,
    pub taker_side: Side,
    pub price: u64,
    pub asset: u64,
    pub quantity: u64,
    pub notional: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatchOutcome {
    NoFill {
        status: MatchStatus,
        reported_budget: u64,
        reason: MatchReason,
    },
    Fill {
        fill: Fill,
        status: MatchStatus,
        reported_budget: u64,
        reason: MatchReason,
        maker_remaining: u64,
        maker_removed: bool,
    },
}

impl Book {
    /// Runs the verified single-resting-slot transition against the FIFO head
    /// of the best opposing level.
    ///
    /// Price crossing and the surrounding insertion/matching loop are outside
    /// the established body. The caller must have already selected a valid
    /// execution price and supplied results from external limit helpers.
    pub fn match_best_once(
        &mut self,
        taker: TakerOrder,
        limits: MatchLimits,
    ) -> Result<MatchOutcome, BookError> {
        let maker = self
            .best(taker.side.opposite())?
            .ok_or(BookError::CorruptState("no opposing resting order"))?;
        self.match_slot_once(maker.slot, taker, limits)
    }

    /// Same bounded transition with an explicitly selected resting slot.
    pub fn match_slot_once(
        &mut self,
        maker_slot: SlotId,
        taker: TakerOrder,
        limits: MatchLimits,
    ) -> Result<MatchOutcome, BookError> {
        let maker = self.occupied(maker_slot)?.clone();
        if maker.side != taker.side.opposite() {
            return Err(BookError::WrongMakerSide);
        }
        if maker.reduce_only {
            return Err(BookError::UnsupportedReduceOnlyMatch(maker.order_id));
        }
        if taker.budget == 0 {
            return Ok(no_fill(MatchStatus::None, 0, MatchReason::CONTINUE));
        }
        if maker.user == taker.user {
            return Ok(no_fill(
                MatchStatus::None,
                taker.budget,
                MatchReason::SELF_CROSS,
            ));
        }
        if maker.quantity == 0 {
            return Ok(no_fill(
                MatchStatus::None,
                taker.budget,
                MatchReason::CONTINUE,
            ));
        }

        let mut amount = maker.quantity.min(taker.budget);
        let mut reason = MatchReason::CONTINUE;
        if limits.maker_cap < amount {
            if limits.maker_cap == 0 {
                return Ok(no_fill(
                    MatchStatus::None,
                    taker.budget,
                    MatchReason::LIMIT_OR_MASK,
                ));
            }
            amount = limits.maker_cap;
            reason = MatchReason::LIMIT_OR_MASK;
        }

        let mut status = MatchStatus::None;
        let mut reported_budget = taker.budget;
        if limits.taker_cap < amount {
            status = if limits.taker_other_cap < amount {
                MatchStatus::InsufficientMargin
            } else {
                MatchStatus::MaxPosition
            };
            if limits.taker_cap == 0 {
                return Ok(no_fill(status, 0, reason));
            }
            amount = limits.taker_cap;
            reported_budget = limits.taker_cap;
        }

        let notional = taker
            .price
            .checked_mul(amount)
            .filter(|value| *value <= MAX_SUPPORTED_NOTIONAL)
            .ok_or(BookError::NotionalOutOfRange)?;

        if !limits.fill_mask.maker_allowed(taker.side) {
            return Ok(no_fill(status, reported_budget, MatchReason::LIMIT_OR_MASK));
        }
        if !limits.fill_mask.taker_allowed(taker.side) {
            return Ok(no_fill(MatchStatus::InsufficientMargin, 0, reason));
        }

        let maker_remaining = maker.quantity - amount;
        if maker_remaining == 0 {
            self.remove_slot(maker_slot, CancelReason::Internal)?;
        } else {
            self.occupied_mut(maker_slot)?.quantity = maker_remaining;
            self.aggregate_quantity = self.aggregate_quantity.saturating_sub(amount);
        }
        Ok(MatchOutcome::Fill {
            fill: Fill {
                maker_slot,
                maker_order_id: maker.order_id,
                taker_order_id: taker.order_id,
                maker_user: maker.user,
                taker_user: taker.user,
                taker_side: taker.side,
                price: taker.price,
                asset: taker.asset,
                quantity: amount,
                notional,
            },
            status,
            reported_budget,
            reason,
            maker_remaining,
            maker_removed: maker_remaining == 0,
        })
    }
}

const fn no_fill(status: MatchStatus, reported_budget: u64, reason: MatchReason) -> MatchOutcome {
    MatchOutcome::NoFill {
        status,
        reported_budget,
        reason,
    }
}
