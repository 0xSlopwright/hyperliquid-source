# RE-001: close the 95-byte character request edge

This packet reconstructs a conditional normal-callback request protocol for
node #94's complete `0x157cfa0..0x157cfff` function in independently authored
safe `no_std` Rust. The same function was an opaque supporting edge in the
earlier libcore correspondence packet. [PROOF.md](PROOF.md) gives the raw
operand, callback, data and frame premises and the exact remaining gaps.

The new primitive requests four spaces when the entry flag is nonzero,
canonicalizes only indentation errors, stores the full-character LF predicate
before the character callback, and forwards that callback's low8 status.
Callback changes to the flag and subsequent method behavior are observable.
The byte operation and all 3,023 existing byte fixtures are preserved.

`ORACLE-FREEZE.json`, `reference.py`, `INPUTS.txt` and `EXPECTED.txt` retain the
independent pre-Rust 320-case relation and wire. These transcripts describe
given normal proxy requests and state effects, not UTF8 rendering or a recovered
`fmt::Result` layout. The source API and its stronger valid-char/reference,
normal-return, role/frame and dispatch-bridge domain are explicit in the proof.

The tiny native listing and earlier admission metadata are historical evidence
from the original immutable target read. Fresh source qualification is performed
by the commands below. No full target or official object member is exported.
Official archive excerpts retain the Rust MIT/Apache notices in this directory;
new implementation and proof code use the repository MIT license.

```sh
python3 -B tools/pad_character_protocol_static.py \
  --libcore /path/to/pinned/libcore-e60dd2ab51fbc7de.rlib \
  --output work/character-static-new
HL_PAD_CHARACTER_LIBCORE=/path/to/pinned/libcore-e60dd2ab51fbc7de.rlib \
  python3 -B -m unittest discover -s tests -p test_pad_character_protocol_static.py -v
python3 -B tools/pad_character_protocol_rust.py \
  --libcore /path/to/pinned/libcore-e60dd2ab51fbc7de.rlib \
  --rustc /path/to/verified-1.94.1/bin/rustc \
  --output work/character-build-new --controls
```

Every output path must be new. Full artifact tests require the explicitly
provided archive; ordinary discovery may report an honest skip when that
optional provider is absent. A qualified local run must supply it and record
zero skips. The Rust provider is a research toolchain, not proof of the original
node compiler. There is no Cargo workspace or dependency invention.

Fresh static qualification passes: one real CLI plus all eight tests in normal
and optimized Python, zero skips. The exact static source, full target/archive
and seven pinned repositories remain unchanged across those checks. Their raw
records and logs are retained under `static-qualification/`.

The actual Rust run passes in both unoptimized and optimized profiles. Each
profile runs the unchanged 3,023-case byte test, the new 320-case external
character test and a separately linked input-only client producing all 320
matching character transcripts. Seven compiled semantic mutations produce
192/256/48/96/104/171/128 normal-row mismatches, respectively, and each fails an
actual Rust assertion with exit 101. Two independent 12,832-byte own-library
rebuilds are raw-equal with SHA-256
`a2af1e5f95a1ab2c1472174788ed3d4863ce1d2004828156100247913d69e877`;
this is not a captured-body comparison.

`rust-qualification/RESULT.json` and `RAW-LOGS.json` preserve all 53 actual
subprocess commands and 106 exact stdout/stderr streams. The outer audit binds
all 103 compiler payloads, 17 computational source/helper/fixture identities,
the full target and archive, HEAD/tree/status and seven genuine pinned Git
repositories before and after. All are unchanged. Root's private scheduling
policy credits only clean inactive non-shmem file cache and records both raw
and adjusted minima; it changes no repository resource policy or kernel state.

An independently authored post-build client links the retained optimized rlib
and matches 51 additional observations, including four scalars absent from the
320-case corpus, new flag/status values, changed method modes, ordering and
duplicates. Its source, independent inputs/expectations, chronology and exact
link/run outputs are under `independent-postbuild-client/`. This is explicitly
post-build corroboration after source review, not a pre-Rust expectation freeze.
The rlib contains generic MIR rather than standalone native function symbols;
the real clients instantiate that generic implementation. Neither the rlib
comparison nor the client link establishes captured native opcode identity.

One pre-build compatibility correction is retained in
`LEGACY-MUTATION-PREPARATION.json`: the new u8 guard uses equivalent `>0`
spelling, keeping the existing byte runner's old mutation needle unique.
The independent `LEGACY-CONTROL-COMPATIBILITY-REBIND.json` checks all seven old
and seven new mutation sites. The original native static qualification and
the later corrected-source real build are distinct historical observations;
their recorded hashes have not been restamped.

Repository-wide checks are still pending; no complete-suite result follows
from these bounded passes. All existing progress gates remain false.

Build commands inherit the trusted host subprocess environment. It is not
recorded in full and this is not a hermetic build or sandbox claim; host linker
runtime dependencies are not reconstructed. Exact source, explicit compiler
payloads, target/provider inputs and actual raw commands/results are recorded
for the measured research run.
