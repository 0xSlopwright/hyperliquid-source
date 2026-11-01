# Offline Rust codec for the node #94 TCP frame

Task: RE-012. This packet records an independently authored, bounded transport
implementation under `src/node94-tcp-frame/`. The target is Linux x86-64 node
#94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The implementation base is upstream `main` commit
`6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`.
No captured binary was executed and no unlicensed inferred source was used.

## Static evidence and claim boundary

Four existing, independently checked packets supply the contract:

- `transport-tcp-frame-read-94` establishes the five reader families, the
  five-byte header, inclusive frame admission, compression-flag handling,
  decimal 4,000,000-byte payload chunks, and early EOF behavior.
- `transport-tcp-frame-write-94` establishes three writer bodies, the 1,025
  compression threshold, exclusion of stream-field values 3998/3999,
  compression sizing, the 65,535-byte hash-table switch, complete-frame
  chunks, and the header layout.
- `transport-lz4-frame-94` establishes FDE `0x3d1abc0..0x3d1b62b`, its
  little-endian size prefix, inclusive decoded-size limit, five LZ4 error
  classes, and success-length handling.
- `transport-node-port-94` establishes NodePort values 3998 and 3999. Their
  relationship to the writer's u16 field is an evidence-packet inference, not
  a fully traced field identity.

The crate implements only those offline format and calculation behaviors. It
does not open sockets, select peers, perform timeouts, retry, reconnect, emit
statistics, reproduce async futures, or provide a production transport client.
It does not claim full TCP runtime compatibility, complete transport recovery,
target ABI/compiler identity, or a progress gate.

The target readers receive a caller-provided `max_len`; the packets do not
establish one global numeric maximum. The crate therefore requires its caller
to choose a bounded `FrameLimits` value and performs both allocation-relevant
admission checks against it before copying or decoding payload bytes.

## Implemented correspondence

The complete frame is `[u32 big-endian payload length][flag][payload]`. Exactly
flag 1 invokes LZ4; every other flag value is raw. Declared payload length and
the LZ4 little-endian decoded-size prefix are each admitted when equal to their
configured inclusive limits. The reader chunk plan covers payload bytes; the
writer chunk plan covers the header plus payload. Both use decimal 4,000,000.

Compressed payloads shorter than four bytes report `ExpectedAnotherByte`.
The decoder exposes the five established classes: `OutputTooSmall`,
`LiteralOutOfBounds`, `ExpectedAnotherByte`, `OffsetZero`, and
`OffsetOutOfBounds`. Successful output is truncated to the produced length;
the target evidence does not require equality with the advertised prefix.
Malformed headers, declared-length truncation, limit failures, and oversized
writer payloads have explicit Rust errors.

The writer compresses when `len >= 1025` and
`(stream_field & !1) != 3998`. Its checked sizing helpers preserve
`len * 110 / 100 + 20`, allocation `+24`, the 65,535 u16/u32 table boundary,
and the observed low-u32 little-endian size prefix. Complete encoded payload
lengths must still fit the wire u32 header.

The MIT-licensed dependency `lz4_flex = 0.11.6` is pinned in both manifest and
lockfile. Its crates.io archive SHA-256 is
`373f5eceeeab7925e0c1098212f2fbc4d416adec9d35051a6ab251e824c1854a`,
the archive identified by the static packet. This establishes source/API
correspondence for the used block operations, not binary-identical compressed
bytes, target allocation behavior, fast paths, panic formatting, compiler
output, or the target's full Cargo feature selection.

## Independent controls and tests

Fixtures construct literal-only LZ4 blocks independently of the new writer.
Negative controls mutate big-/little-endian fields, declared lengths,
compression flags, LZ4 offsets, advertised decoded sizes, and every truncation
point of raw and compressed frames. A bounded deterministic mutation corpus
checks arbitrary short inputs for panic freedom, stable outcomes, exact
consumption, and raw-payload preservation. Boundary cases cover empty input;
lengths around 1,025, 65,535, and 4,000,000; configured maxima; malformed
prefixes; all five decode classes; and unexpected EOF. Deterministic
complete-frame roundtrips are used only where both reader and writer behavior
are established.

Reproduce from the repository root with the pinned Rust toolchain:

```sh
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
python3 -m unittest tests.test_tcp_frame_read_static \
  tests.test_tcp_frame_write_static tests.test_tcp_lz4_frame_static \
  tests.test_node_port_static -v
PATH="/opt/homebrew/opt/binutils/bin:$PATH" make verify test catalogue-check
```

The focused Rust suite contains 53 tests. The four existing evidence suites
contain 96 tests and pass without target execution. Repository-wide results
are reported in the associated pull request after the final qualified run.

## Remaining paths

The target compressor bodies, compressor-output identity, raw-copy internals,
allocator failure, error formatter details, async read/write state machines,
timeouts, logging/statistics, caller message types, peer lifecycle, and live
network behavior remain outside this component. In particular, an offline
roundtrip only demonstrates internal codec agreement for established paths; it
is not evidence that a reconstructed client can communicate with a live node.
