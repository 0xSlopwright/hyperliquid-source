/// Authenticated node #94 artifact used by the retained evidence.
pub const TARGET_SHA256: &str = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f";

/// Observed target context offsets. The safe Rust types are not ABI-compatible
/// with this target layout and make no `repr(C)` claim.
pub struct TargetContextLayout;

impl TargetContextLayout {
    pub const EXPIRES_TAG: usize = 0x00;
    pub const EXPIRES_VALUE: usize = 0x08;
    pub const NONCE: usize = 0x10;
    pub const VAULT_TAG: usize = 0x18;
    pub const VAULT_BYTES: usize = 0x19;
}

/// Half-open ELF virtual-address ranges for the three established functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetFunction {
    pub start: u64,
    pub end_exclusive: u64,
}

impl TargetFunction {
    pub const AGENT_INLINE: Self = Self {
        start: 0x333f240,
        end_exclusive: 0x333f686,
    };
    pub const AGENT_WRAPPER: Self = Self {
        start: 0x37eb2d0,
        end_exclusive: 0x37eb702,
    };
    pub const EMBEDDED_INLINE: Self = Self {
        start: 0x3984fe0,
        end_exclusive: 0x39853ec,
    };
}
