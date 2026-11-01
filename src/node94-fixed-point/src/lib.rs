//! Independently authored fixed-point primitives established for node #94.
//!
//! This crate intentionally exposes only behavior supported by the retained
//! RE-004 evidence packets. It is not a complete exchange arithmetic model.

#![forbid(unsafe_code)]

mod arithmetic;
mod quantity;
mod scale;
mod spot_wire;
mod tick;

pub use arithmetic::{ArithmeticOutcome, ArithmeticStatus};
pub use quantity::{
    AdmissionError, BigNotional, Notional, Price, QuantityKind, SignedNotional, SignedSize, Size,
    Wei,
};
pub use scale::{ScaleError, TokenDecimals, checked_pow10};
pub use spot_wire::{SpotWireError, parse_spot_wire_price, parse_spot_wire_size};
pub use tick::{
    Tick, TickError, is_tick_divisible, next_tick, perp_tick, require_tick_divisible,
    round_down_to_tick, significant_tick, spot_tick,
};
