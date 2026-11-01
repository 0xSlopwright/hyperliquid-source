# Node #94 offline TCP frame codec

This standalone Rust crate reconstructs the bounded, offline TCP frame format
established for Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It is independently authored from retained static evidence and does not contain
socket code, peer networking, a production transport client, or captured-target
execution.

The initial public contract is the verified five-byte header:

```text
+0..+4  payload length, big-endian u32
+4      compression flag; exactly 1 means LZ4, every other value means raw
```

`Header::decode` requires all five bytes and reports an explicit header EOF.
`Header::encode` preserves the original flag byte. `Header::from_payload_len`
rejects lengths that cannot be represented by the wire u32.

`FrameLimits` applies the reader's inclusive `declared <= max_len` admission
and the same inclusive gate to an LZ4 uncompressed-size prefix. `ChunkPlan`
implements the verified decimal 4,000,000-byte cap without allocating a list;
readers apply it to the payload and writers apply it to the complete frame.

The writer compression policy is also exposed without I/O: compress at lengths
at least 1,025 unless `(port & !1) == 3998`, which excludes ports 3998 and
3999. Its checked sizing helpers preserve the observed `len * 110 / 100 + 20`
output window, `+24` allocation, 65,535-byte hash-table switch, and truncating
little-endian u32 size prefix.

Build from the repository root with the pinned toolchain:

```sh
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
```

This component is a partial transport reconstruction. Passing its offline tests
does not establish TCP runtime compatibility, target binary identity, complete
transport recovery, or a repository progress gate.
