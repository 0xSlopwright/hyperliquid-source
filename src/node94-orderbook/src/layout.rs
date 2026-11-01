//! Target layout facts retained separately from the safe Rust representation.
//!
//! The in-memory Rust types in this crate are intentionally not declared ABI
//! compatible with the captured program. These constants are the verified
//! offsets used to bind the modeled fields to node #94 evidence.

/// Authenticated node #94 target digest.
pub const TARGET_SHA256: &str = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f";

/// Verified offsets for the `0xf8`-byte resting-order slab monomorph.
pub struct TargetSlotLayout;

impl TargetSlotLayout {
    pub const STRIDE: usize = 0xf8;
    pub const PREVIOUS_OPTION: usize = 0x00;
    pub const NEXT_OPTION: usize = 0x10;
    pub const ORDER_BODY: usize = 0x20;
    pub const REDUCE_ONLY: usize = 0xb0;
    pub const QUANTITY: usize = 0xc8;
    pub const ORDER_ID: usize = 0xd8;
    pub const USER: usize = 0xe0;
    pub const VACANT_DISCRIMINANT: u32 = 2;
}

/// Verified offsets inside the relation body beginning at target slot `+0x20`.
pub struct TargetRelationLayout;

impl TargetRelationLayout {
    pub const PARENT_OPTION: usize = 0x10;
    pub const PEER_OPTION: usize = 0x20;
    pub const CHILDREN_VECTOR: usize = 0x30;
}
