# Node94 strict three-digit ASCII parser

This dependency-free `no_std`, safe Rust component reconstructs the scalar
contract of node94 FDE `1683670..16836c5` (85 bytes/30 native rows):

```rust
pub fn parse_three_digits(input: &[u8]) -> u16
```

The return is zero unless there are exactly three bytes, first in ASCII1..9
and the other two in ASCII0..9; otherwise it is100..999. The input is unchanged.
The function/interface names and Rust type are independently chosen. It is not
a full time parser, field meaning, source type, private ABI or whole caller.

The [proof packet](../../research/work-items/RE-005-three-digit-ascii-rust-94/)
binds actual target bytes, all byte predicates, every local transfer, exact
return bounds and separate31-byte used-result context. No unlicensed inferred
source or native code was copied into this implementation. There are no calls
or static-data dependencies inside the selected native body. Original compiler,
machine-byte identity, physical fault/read timing and runtime remain unqualified.

The original pre-Rust1663-case fixture contains all900 valid strings,
739 distinct single-invalid-byte strings and24 additional length/multi-invalid
boundaries. Inputs and expected answers are separate files. The ordinary Rust
unit embeds the combined fixture only under `cfg(test)`; it is one test
function, not1663 test functions. The production driver accepts one input-only
file with `id hex_or_dash` rows and prints `id decimal_value`. Its source does
not open expected files or receive expected-answer/length/role arguments.

Use the separately authenticated research rustc1.94.1 with direct component
builds; this adds no Cargo workspace, invented manifest, dependencies or lockfile.
Actual debug and optimized units and linked input-only clients pass all1663
fixture cases. The fixed run retains29 commands/58 streams, two equal7,724-byte
own optimized rlib archives and three normal-valued compiling controls (1/7/900 changed
results). A separate independently frozen64-record padded client also passes
against that retained rlib, without a library rebuild. These counts remain
separate; its valid values are already among the900 primary values. See the
packet's actual records and limits. Repository tooling alone is not a Rust
behavior claim.

The optimized archive carries crate metadata/bitcode without a standalone
defined parser FUNC. The linked consumers generate its actual input-dependent
code. Own archive equality is not an emitted85-byte or target-code match.

New independently authored code/docs are MIT. Captured evidence keeps its
original rights. No component/progress gate is changed.
