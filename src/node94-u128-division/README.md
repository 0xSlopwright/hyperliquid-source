# Node94 unsigned128 quotient

This independently authored `no_std`, core-only module implements:

```rust
pub fn quotient(dividend: u128, divisor: core::num::NonZeroU128) -> u128
```

For every128-bit unsigned numerator and every nonzero128-bit divisor, the returned
value is the unsigned mathematical floor quotient. Zero is excluded by the chosen
safe Rust API. It does not reproduce node process exception/signaling behavior.
There is no Cargo workspace, registry dependency, original ABI or byte-match claim.

The implementation uses128 steps of bit-prefix restoring division. It contains
no division/remainder operator or wrapped compiler division function. Before each
step, the consumed prefix p satisfies p=q*d+r,0<=r<d. Append its next bit, shift q,
and subtract d at most once. Since the prior prefix has at most127bits and r<=p,
forming2r+bit does not overflow128; q's shift also fits. After128 steps p is the
complete numerator and q is its quotient. The complete separately reviewed native
proof, including all hardwareDIV and normalized-estimate safety obligations, is
in [the packet](../../research/work-items/RE-004-u128-division-94/PROOF.md).

The native proof concerns the numerical projection RAX+2^64*RDX at the actual
`0x565f5a0..0x565f666` node94 leaf, under explicit immutable-code/ordinary-call/stack
conditions. The Rust API's type/layout, physical clobbers, stack stores and calling
convention are newly chosen. Original zero-divisor faults, caller-wide rounding,
fee units/state effects and whole-node reconstruction remain outside this module.

The canonical7587-case input/expected files were frozen independently before any
new Rust was authored. `target-vectors.tsv` is their four-column serialization for
one real Rust fixture test; it is included only under `cfg(test)`. The separate
`input_only_driver.rs` links the actual ordinary library and reads only
`id|n32lowerhex|d32lowerhex`, emitting `id|q32lowerhex`. Neither expected results nor
native path/branch labels are arguments to the production client. This is a reviewed
data-flow property, not a filesystem sandbox. Normal malformed/zero-line refusal
is a new client input policy, not captured exception parity.

Use the documented research Rust1.94.1 compiler (commit e408947bfd200af42db322daf0fadfe7e26d3bd1),
not an inferred original node compiler. The bounded runner executes exactly the
fixed debug/O3 own-source profiles, four valued semantic mutants, two own rebuilds
and one build-only forbidden-delegation control:

```sh
python3 -B tools/u128_division_rust.py \
  --binary artifacts/node/94/hl-node \
  --rustc /path/to/verified/rustc \
  --output /tmp/new-u128-qualification --controls
```

Each ordinary library recipe emits an rlib, ELF object and LLVM IR with edition2021,
codegen-units1 and overflow checks enabled. The runner checks every actual library
for division/remainder builtins, DIV/REM IR and machine DIV instructions before
linking its actual input-only client. A separately labeled own `n/d.get()` wrapper
is compiled once and must be rejected before client linking or execution. It is
not the implementation or an oracle. Raw own-library rebuilds are compared without
normalization; that comparison is not target binary identity. Actual commands,
raw stdout/stderr, counts and artifact digests are retained in the evidence packet.
