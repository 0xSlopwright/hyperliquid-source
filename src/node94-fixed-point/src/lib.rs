//! Independently authored fixed-point primitives established for node #94.
//!
//! This crate intentionally exposes only behavior supported by the retained
//! RE-004 evidence packets. It is not a complete exchange arithmetic model.

#![forbid(unsafe_code)]

mod quantity;

pub use quantity::{
    AdmissionError, BigNotional, Notional, QuantityKind, SignedNotional, SignedSize, Size, Wei,
};
