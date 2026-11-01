use core::fmt;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OrderId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SlotId(pub u64);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserId(pub [u8; 20]);

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

impl UserId {
    pub const fn repeated(byte: u8) -> Self {
        Self([byte; 20])
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Side {
    Bid,
    Ask,
}

impl Side {
    pub const fn opposite(self) -> Self {
        match self {
            Self::Bid => Self::Ask,
            Self::Ask => Self::Bid,
        }
    }

    /// Node #94 stores bids under `-price` and asks under `+price`.
    pub(crate) fn signed_price_key(self, price: u64) -> Result<i64, BookError> {
        let price = i64::try_from(price).map_err(|_| BookError::PriceOutOfRange(price))?;
        Ok(match self {
            Self::Bid => -price,
            Self::Ask => price,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertOrder {
    pub order_id: OrderId,
    pub user: UserId,
    pub side: Side,
    pub price: u64,
    pub quantity: u64,
    pub reduce_only: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelationRequest {
    pub parent: Option<OrderId>,
    pub peer: Option<OrderId>,
    pub children: Vec<OrderId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CancelReason {
    Canceled = 2,
    SiblingFilled = 11,
    Delisted = 12,
    Liquidated = 13,
    OutcomeSettled = 14,
    Internal = 16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelRecord {
    pub slot: SlotId,
    pub order_id: OrderId,
    pub reason: CancelReason,
    pub removed_quantity: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookError {
    PriceOutOfRange(u64),
    SlotOutOfRange(SlotId),
    VacantSlot(SlotId),
    OrderNotFound(OrderId),
    UnsupportedDuplicateOrder(OrderId),
    UnsupportedReduceOnlyMatch(OrderId),
    UnsupportedRelationRewrite(OrderId),
    WrongMakerSide,
    NotionalOutOfRange,
    CorruptState(&'static str),
}

impl fmt::Display for BookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PriceOutOfRange(price) => {
                write!(f, "price {price} does not fit the verified signed key")
            }
            Self::SlotOutOfRange(slot) => write!(f, "slot {} is out of range", slot.0),
            Self::VacantSlot(slot) => write!(f, "slot {} is vacant", slot.0),
            Self::OrderNotFound(order) => write!(f, "order {} was not found", order.0),
            Self::UnsupportedDuplicateOrder(order) => {
                write!(f, "duplicate order {} behavior is unsupported", order.0)
            }
            Self::UnsupportedReduceOnlyMatch(order) => {
                write!(
                    f,
                    "reduce-only matching for order {} needs external position state",
                    order.0
                )
            }
            Self::UnsupportedRelationRewrite(order) => {
                write!(
                    f,
                    "rewriting an existing relation on order {} is unsupported",
                    order.0
                )
            }
            Self::WrongMakerSide => {
                f.write_str("selected resting order is not on the opposing side")
            }
            Self::NotionalOutOfRange => {
                f.write_str("price times quantity exceeds the verified notional ceiling")
            }
            Self::CorruptState(message) => write!(f, "book state is inconsistent: {message}"),
        }
    }
}

impl std::error::Error for BookError {}
