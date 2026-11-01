#![no_std]
use core::num::NonZeroU128;
#[inline(never)]
pub fn quotient(n:u128,d:NonZeroU128)->u128{ n / d.get() }
