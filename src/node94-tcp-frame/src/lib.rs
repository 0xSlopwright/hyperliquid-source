//! Offline codec for the statically verified node #94 TCP frame format.
//!
//! This crate deliberately contains no socket or peer-networking behavior.

#![forbid(unsafe_code)]

mod header;

pub use header::{HEADER_LEN, Header, HeaderError};
