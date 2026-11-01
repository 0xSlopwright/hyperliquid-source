# Node #94 qualified action-delay kernel

An independently authored, dependency-free Rust logical component for the
curve at ELF VA `0x392fab0`. The real Cargo lock contains only this package;
this is not a node workspace. Root MIT covers this new implementation. No
unlicensed inferred reference source was copied.

```sh
cargo test --offline --locked --manifest-path src/node94-action-delay/Cargo.toml
cargo build --release --offline --locked --manifest-path src/node94-action-delay/Cargo.toml
python3 tools/action_delay_fma_rust.py --rust-driver src/node94-action-delay/target/release/node94-action-delay
```

Use Rust 1.94.1 and the repository Python requirements. `CARGO_TARGET_DIR` may
redirect build output; adjust the driver path accordingly. The Python command
reads the authenticated original ELF but runs only our new Rust executable.

`evaluate(u8, i32, f64)` accepts raw words and returns a chosen `Result<Trace,
Guard>` observation carrier. It is not the original ABI, enum, panic payload,
or a claim that callers can actually produce every raw word. Mode 0 and 1 use
the default curve. The action word's unsigned tail comparisons intentionally
include negative i32 values. The helper performs one-round FMA, not a power.
The coefficient multiply and base addition remain separate operations.

Qualification: binary64 round-to-nearest/ties-even, masked exceptions, DAZ and
FTZ disabled, and target hardware FMA3 arm. The target software fallback,
feature detection, actual runtime floating environment, caller reachability,
original error payloads and whole-node equivalence remain unproved. NaN payload
identity is outside the API; NaN reaches a guard error. FMA4 bytes are recorded
but not included in the arithmetic qualification.

The evidence packet is in
`research/work-items/RE-004-action-delay-fma-rust-94/README.md`. Its 57 abstract
integer partition cells cover 2**40 raw mode/action patterns; this is not that
many executed tests. The 332 floating vectors use an independently computed
exact-rational one-round FMA oracle derived from static target operands, not
original-target differential execution. Retained stage bits make an unfused
multiply/add regression observable even when the final clamp hides it.
