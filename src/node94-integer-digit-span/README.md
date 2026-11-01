# Capacity20 unsigned decimal suffix

This independently authored `no_std` Rust library implements one qualified
numeric contract from node #94: `write_decimal_suffix(u64, &mut [u8;20])`
returns the first written index, writes ordinary unsigned decimal bytes up to
index20, and preserves every earlier byte. Zero writes one `0`; the maximum
u64 occupies all20 bytes. The implementation uses ordinary /10 arithmetic,
not copied library code, machine-code transplantation or an original ABI.

The primary target is the complete444-byte body `0x1570470..0x157062c` in
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The [proof and evidence](../../research/work-items/RE-005-integer-digit-span-94/README.md)
bind every raw instruction/operand, the actual pair table, all seven buffer
stores and a mathematical all-u64 capacity20 suffix/prefix argument. The
target's reciprocal/four-digit algorithm and this ordinary-/10 implementation
are different implementations of that established relation.

The safe fixed-array interface is newly chosen. Native proof conditions
include initialized scalar input, valid separated buffer/table/code/frame
regions, normal memory accesses and protected saved/return state. Other
capacities, invalid pointers, arbitrary aliases, faults/unwind/concurrency and
out-of-domain guard-call behavior are unqualified. This is not original type,
layout, calling convention, compiler, machine-code equality or full runtime.

The235-byte `0x14f7660` selector is reported separately as conditional context.
Its decimal buffer ends atB+20; its hex arms end atB+16. There is no Rust
hex/flags stub or complete G/formatter implementation. The downstream1295-byte
formatting helper remains opaque; no padding, fill, alignment, prefix rendering
or component progress gate is claimed.

## Real standalone build

There is no invented Cargo workspace, dependency or lockfile. Use the verified
repository research rustc1.94.1, which is not a recovered original compiler:

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_integer_digit_span \
  --crate-type=rlib -D warnings src/node94-integer-digit-span/lib.rs \
  -o /tmp/libnode94_integer_digit_span.rlib
/path/to/verified/rustc --edition=2021 --test -D warnings \
  src/node94-integer-digit-span/lib.rs -o /tmp/digit-span-tests
/tmp/digit-span-tests --nocapture
```

Use fresh owned output paths. The unit includes1697 independently frozen
marked-buffer vectors. Normal rlib builds exclude that test-only fixture.
The separate input-only executable reads `id n_hex initial20_hex` and emits
`id start_decimal complete20_hex`; it observes every byte without slicing at
the returned index. It never reads expected answers. That is data-flow
separation, not a filesystem sandbox.

`tools/integer_digit_span_rust.py` provides the reproducible debug/optimized
library/unit/production, semantic-control and own-rebuild workflow. Its actual
results and raw logs belong in the evidence packet; test or build success is
claimed only by the recorded completed run. Captured node/visor code and CPU
instruction evaluators are never executed by this component.
