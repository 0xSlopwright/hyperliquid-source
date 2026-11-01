# Checked node #94 fast-state constructor

This standalone, dependency-free Rust component implements only the conditional
443-byte constructor contract documented in
`research/work-items/RE-001-huf-fast-state-init/PROOF.md`. It is independently
authored from target instructions. It neither decodes a compressed stream nor
claims an original ABI, source type, runtime dispatch or full native equivalence.
There is no root Cargo workspace and no invented dependency/lockfile.

`initialize` takes a detached mutable `[u64;19]` state image, symbolic addresses,
an output length, immutable source bytes and a complete four-byte table header.
It returns the actual raw0/-20/1 status within the documented normal domain and
preserves refusal-path partial writes. Unsupported domains are separate errors
and leave the state unchanged. The header is required even for output length0.
The checked address conditions include both output end and output cursor3;
failed-path stream-start values remain modulo2^64 and need not point into input.
Native code/stack/return validity are external proof assumptions, not checks
that this safe detached API claims to perform. Table payload and later decoder
behavior remain unqualified.

The companion driver is a real line-oriented client, not a target emulator.
It consumes eight whitespace-separated fields: hexadecimal state/output/input/
table bases, output length, four-byte header hex, input hex (`-` for empty), and
19 comma-separated hexadecimal state words. Each response reports raw status
or a distinct domain error, a tab, and all19 final words. Malformed requests
fail with exit2. Only this independently authored code and driver may execute.

The evidence collector builds the library and driver with the already
admitted direct rustc1.94.1 toolchain and records exact argv, inputs and outputs.
No Cargo, dependency download, captured binary, licensed assembly execution or
CPU emulator is involved. The compiler is a reproduction provider, not evidence
of the original capture's compiler. See the packet for actual validation status.
