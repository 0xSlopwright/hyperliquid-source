//! Offline codec for the statically verified node #94 TCP frame format.
//!
//! This crate deliberately contains no socket or peer-networking behavior.

#![forbid(unsafe_code)]

mod header;
mod limits;

pub use header::{HEADER_LEN, Header, HeaderError};
pub use limits::{CHUNK_LEN, Chunk, ChunkPlan, FrameLimits, LengthError};
