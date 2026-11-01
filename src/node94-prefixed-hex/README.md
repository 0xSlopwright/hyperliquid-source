# Node #94 prefixed hexadecimal encoder

This dependency-free Rust component implements the normal-return byte relation
of node #94's complete 414-byte helper at `0x29ed380..0x29ed51e`, SHA-256
`4467f0fb09786fc39b97b1925a7dda43d82bee4ffd4fa6c66920d6a471e3672e`.
The target is release #94, full SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Accepted stream-message research (#1162) leaves this helper open under the
20-byte proposer string writer; accepted arm-87 research (#955) includes its
shared interpreted bytes but implements no Rust. The new component closes
this specific codec dependency. It does not implement either parent protocol,
signing, a digest, a network path or the other MessagePack writers. The two
caller cuts remain separate from the 414-byte primary semantic denominator.

```rust
pub fn encode_prefixed_hex(
    input: &[u8],
    trim_first_nibble: bool,
    output: &mut [u8],
) -> Result<usize, UnsupportedDomain>;
```

The output starts with `0x`, then contains lowercase hexadecimal digits.
When the mode is set and the first byte is below 16, only its first high
nibble is omitted: `[0, 1]` becomes `0x001`, rather than `0x01`. Later bytes
always contribute both digits. No terminator is written. The returned length
is `2 * input.len() + 2` minus one exactly in that omission case; the rest
of the caller's output slice is preserved.

The admitted native domain requires nonempty input, nonwrapping
`2 * input.len() + 2` and that many output bytes even when trimming. Valid,
nonoverlapping slices and protected active stack/return/code/table regions
are explicit native proof assumptions. The safe Rust function uses immutable
and mutable borrows and checks its lengths before writing. Empty input,
overflow or insufficient output returns `UnsupportedDomain` with the whole
output unchanged. This is an intentionally separate safe-API policy: the
native empty/short paths invoke out-of-scope panic helpers and are not
claimed to return an error or preserve output.

`lib.rs` uses `no_std`, forbids unsafe code and has no external dependency.
It is built directly with the admitted research Rust 1.94.1 compiler; no
original Cargo package, node workspace, dependency lock or compiler is
inferred. The separate standard-library research driver takes one stimulus
file with four fields per row: `id mode input_hex initial_output_hex`.
Empty byte vectors use `-`. It prints the actual API status, length and
complete output in the original input order. Expected answers occur only in
the `cfg(test)` fixture or the external comparator, never in production
driver arguments.

The pre-Rust fixture contains 2,634 normal-domain records and 30 separately
labelled safe-API policy records. Its 512 exhaustive single-byte/mode checks
support the complete static loop proof; these counts are neither executed
target calls nor a whole-input-space equivalence claim. Independent
expectations were frozen before the Rust source. Actual build, mutation,
independent-client and repository-check results are recorded in the sibling
RE-005 evidence packet; unobserved checks must not be inferred from this API.

The new Rust is independently authored MIT work. Original captured evidence
keeps its ownership. No unlicensed inferred implementation was copied, and
no captured program, compatible assembly object or instruction emulator is
executed. Original Rust names/types/ABI, panic/unwind behavior, caller input
ownership, physical load/fault trace, target machine bytes and full-node
equivalence remain unqualified. No component gate changes.
