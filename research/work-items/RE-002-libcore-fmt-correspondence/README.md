# RE-002: three formatting spans versus published libcore

This published-artifact comparison narrows build-provenance uncertainty for
three node #94 spans. It does **not** reproduce all three raw bodies: the
adapter retains two genuine non-relocation byte differences.

- Component: foundation/build provenance; task RE-002.
- Baseline: `308e5127990217a9d6196992665da6ca1afd4b82`.
- Capture: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Published component: official `rust-std-1.94.1-x86_64-unknown-linux-gnu`.
  Its archive SHA-256 is
  `74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03`.
  The admitted 2,917,630-byte `libcore-e60dd2ab51fbc7de.rlib` has SHA-256
  `ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`;
  its unique 2,871,296-byte code member has SHA-256
  `57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.

## Measured result

Addresses are linked ELF virtual addresses, not process or rebased analysis
addresses. Each selected capture extent has an exact unique raw FDE. Official
source-artifact symbols are actual STT_FUNC symbols with value zero and size
equal to their complete executable sections; no padding or suffix is trimmed.

| Role | Capture VA range | Code bytes | Actual code RELA fields / bytes | Equal outside those fields |
| --- | --- | ---: | ---: | ---: |
| DebugStruct field | `0x1571f50..0x15720d6` | 390 | 9 / 36 | 354 / 354 |
| PadAdapter write_str | `0x157d000..0x157d26e` | 622 | 1 / 4 | 616 / 618 |
| Unsigned decimal inner | `0x1570470..0x157062c` | 444 | 9 / 36 | 408 / 408 |
| Total selected code | | **1,456** | **19 / 76** | **1,378 / 1,380** |

Every code field is an actual source-object R_X86_64_PC32 or
R_X86_64_GOTPCREL RELA record, width four, addend -4. The producer checks
nonoverlap, bounds, symbol and section-table relationships. It retains all
raw fields, raw differences and their exact positions. The 78 raw differing
bytes comprise 76 positions in those actual fields plus two adapter bytes.

At adapter offsets 464 and 467 the full four-byte sequences are official
`4d8d2437` and captured `4e8d243e`. Independent native inspection renders
the operands as `lea r12,[r15+rsi*1]` and `lea r12,[rsi+r15*1]`. This commutation
observation does not remove either raw gap or qualify exact adapter identity.
There is no user-defined mask, operand normalization, byte patch or transplant.
These are three selected comparisons, not a global matched-body denominator.

## Data and limited links

The producer derives the captured destinations of the actual signed fields,
keeping PC32 data destinations distinct from GOTPCREL slot addresses. It checks
raw pair-table bytes (200), a Location record (24), the referenced source path
(75), parent literal slices and the adapter's four spaces. The embedded path is
`/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/num.rs`.
The record contains length 75, line 599 and column 5. Its pointer has a separate
source ABS64 relocation and captured symbol-zero RELATIVE record.

The 48-byte referenced layout comprises **24 fixed bytes** (qwords 0,24,8)
and **three actual eight-byte source pointer-relocation fields**. Its offset-24
official symbol and the parent's two official GOT symbols must equal the actual
compared adapter symbol. Their captured RELATIVE records point to the separately
partially compared adapter. The other two method targets are mapped metadata
only: their code and semantics remain open. This is not a whole vtable/private
ABI or runtime-call qualification.

The decimal GOT references similarly bind the actual official panic symbol to
one captured RELATIVE destination. A **separate 61-byte supporting span** at
`0x157b64f..0x157b68c` has one exact FDE, three actual four-byte source fields,
and 49/49 equal remaining bytes. It is **outside the 1,456-byte denominator**.
Its further data, calls, fault/unwind behavior and transitive closure remain
unqualified. Data and pointer fields also do not enlarge the 76 code bytes.

## Reproduce

No download, extraction command, compiler, native provider, captured-code
execution or emulator is invoked by this producer. Supply an already acquired
official `.rlib`; the full identity is mandatory. An unsupported archive is
refused. The archive and target are read into separate immutable `bytes`
objects; all their metadata and excerpts derive from those exact objects.
No `ar` subprocess reopens a mutable admitted pathname.

```sh
python3 -B tools/libcore_fmt_correspondence.py \
  --core-archive /path/to/libcore-e60dd2ab51fbc7de.rlib \
  --out /tmp/libcore-fmt-new-output
```

The output directory must be absent and its parent must exist. The producer
retains deterministic JSON, small raw official/captured excerpts, upstream
notice/license and a manifest. It never copies a whole capture, library or
object member into the output. Input admission is a digest assertion on the
bytes actually read, not an atomic filesystem snapshot guarantee. Python/tool
source hashes are observational records under a trusted stable analysis
environment; they are not atomic execution provenance.

The tests use actual official/captured bytes, real source ELF records and tiny
ET_REL/ET_DYN format controls. They distinguish admission checks from below-gate
comparison, symbol, field-width, overlap, FDE and data/link controls. Unsupported
absence of the separately acquired official artifact is explicit; the recorded
supported qualification must have zero skips. Exact results are recorded only
after the checks run.

## Scope, prior work and rights

The official archive and embedded path support a concrete provenance lead;
they do not uniquely identify the original archive, compiler, version, fork,
crate graph, flags or types. No source build or reconstructed Rust is claimed
by this artifact-only packet. The original library's Cargo version metadata is
0.0.0; the distribution version is 1.94.1. No component gate changes.

The earlier #1015 diagnostic names, #1030 parent/adapter logical protocol and
#1128 decimal contract are separate semantic evidence. This tool does not
import or modify their unmerged implementations or claim their behavior as new
artifact work. #373's function census, closed #37 and #875 methods are not used
as comparison masks or global counts.

New Python and documentation are independently authored MIT. Official Rust
excerpts retain The Rust Project Contributors' rights, with the MIT option
explicitly elected; see `third_party/LICENSE-MIT` and `third_party/README.md`.
Captured Hyperliquid excerpts retain their existing ownership. The Rust license
does not relicense the whole captured executable. No inferred unlicensed Rust
implementation is read or copied, and no compiler/member payload is vendored.

Full upstream `make test` and automatic CI remain unrun pending separate
authorization for its captured-instruction evaluator families. Four cleared
static targets and the owned static tests are reported separately. Any draft
publication uses an identical-tree metadata-only `[skip ci]` child; it is not
marked ready and does not claim hosted CI or full-suite success.

Next: establish why the adapter's two non-RELA bytes differ with an independently
qualified source/build experiment, while retaining the raw gap and unresolved
transitive callees and methods.
