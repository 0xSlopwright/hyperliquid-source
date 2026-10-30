# foundation-hour-94: what does the hour-extraction path actually compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  `base/time.rs` was a search lead only. No inferred implementation was copied.
- Claim: observations about one target instruction window and its data/call edges;
  its source-level name and types remain inferences.
- Included: the 97-byte callee, one incoming call, two error-arm source records,
  and the integer identity on the entire returning input domain.
- Excluded: other time conversions, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior and transitive error-helper closure.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code
from private helpers. A reference label or a matching string cannot establish
that mapping. This packet connects an actual incoming call through a relocated
slot to a complete, independently disassembled FDE window, then follows its two
error arms to private source-location records. It establishes a concrete small
entrypoint for further reconstruction without declaring the component mapped.

## Reproduce

Working directory: repository root. Platform used: macOS 26.2 arm64, Python
3.12.14, Apple LLVM 21.0.0 (`llvm-objdump`), GnuPG 2.5.24. The checker and tests
use Python's standard library only. Initial exploratory queries used
pyelftools 0.32 and Capstone 5.0.6 outside the repository; neither is needed to
reproduce the retained results.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING.
In this run Git LFS was slow, so the node inputs and imported visor disassembly
were additionally recovered through immutable GitHub media URLs, in bounded
range requests, and checked against the existing manifests before use. The
reference #94 copy is byte-identical. No input or submodule pin changed.

The run used these isolated tools on PATH; substitute installed equivalents:

```sh
export PATH=/private/tmp/hype-analysis-tools/bin:/private/tmp/slop-python-verify/bin:$PATH
export LLVM_OBJDUMP=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump
export TMPDIR=/private/tmp
make doctor
make verify test catalogue-check
make reproduce
python3 tools/foundation_hour.py --check research/work-items/foundation-hour-94/evidence.json
python3 research/work-items/foundation-hour-94/crosscheck.py > work/hour-retained.json
python3 research/work-items/foundation-hour-94/crosscheck.py --objdump "$LLVM_OBJDUMP" > work/hour-fresh.json
cmp work/hour-retained.json research/work-items/foundation-hour-94/boundaries.json
cmp work/hour-fresh.json research/work-items/foundation-hour-94/boundaries.json
```

`make verify` uses a fresh GPG home and the pinned public key, not a personal key
ring. A sandboxed GPG import initially failed; the same check passed outside
that sandbox, still with an isolated temporary home. `make doctor` reported
`analysis_ready: true`, `exact_rebuild_ready: false`. Rust/Ghidra/Java were not
installed for this Python/LLVM-only research. No target binary, captured service,
networked node, chain operation or model-backed program was executed.

Raw exports were generated with:

```sh
"$LLVM_OBJDUMP" -d --start-address=0x14509f0 --stop-address=0x1450a51 artifacts/node/94/hl-node
"$LLVM_OBJDUMP" -d --start-address=0x14027b0 --stop-address=0x1403c29 artifacts/node/94/hl-node
"$LLVM_OBJDUMP" --dwarf=frames artifacts/node/94/hl-node > work/node94-frames.txt
```

The two `*.objdump.txt` files retain complete disassembly of those windows.
The `*.frames.txt` files retain excerpts from the last command, selecting FDEs
at `.eh_frame` section offsets `0xad08` and `0x2e86f4`. The checker locks these
raw FDE records and their CIEs, and reads their PC/range fields. It does not add
a second general FDE decoder or replace RE-001 (#2 / #5).
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase.
The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained
`.eh_frame` has equal file offsets and VAs. The tools resolve sections rather
than assuming one global VA/file-offset relationship.

### Entry, range and incoming call

- `.eh_frame+0xad08` describes `[0x14509f0, 0x1450a51)`, 97 bytes. LLVM's
  independent frame dump agrees. Complete linear decoding from that start
  gives **22 instructions**, ending exactly at the FDE endpoint.
- A `R_X86_64_RELATIVE` relocation maps slot `0x576efc0` to `0x14509f0`.
  At `0x140380f`, the caller prepares `rdi = rsp+0x10`; the instruction at
  `0x1403814` calls through that slot. The caller then compares `al` with a byte
  at `rbx+0x141` on one branch. This supports a narrow result interpretation;
  it does not establish a public ABI or recover the caller's type.
- The caller's FDE is `[0x14027b0, 0x1403c29)`, 5,241 bytes. Decoding **from
  that start**, rather than from a guessed interior address, yields 996
  instructions with continuous byte coverage and validates the retained call
  and surrounding instruction starts. This is not a complete CFG analysis.
- The exact `.text` byte-pattern scan covers 70,370,352 bytes. For `ff 15 disp32`
  and `ff 25 disp32` whose RIP target is slot `0x576efc0`, it finds one candidate,
  `0x1403814`, subsequently validated as an instruction start. For `e8 disp32`
  targeting the callee it finds zero candidates. Register-indirect references,
  other pointer paths, prefixes and data sections are not a complete xref census.

### Returning arithmetic and the two error arms

The callee loads a 32-bit value from `rdi+4`. Its unsigned branches are:

| Input value | Static path |
| --- | --- |
| `0..89999` | Return `(x * 0x91a2b3c5) >> 43` |
| `90000..921599` | Branch to `0x1450a38`, assertion-message arm |
| `921600..4294967295` | Branch to `0x1450a13`, unwrap-message arm |

The multiplication is 64-bit; on the returning domain its product fits in
64 bits. The checker extracts the operands from the retained instruction bytes
and exhaustively verifies the mathematical identity with `x // 3600` for
**90,000/90,000 returning input values**. This is static integer arithmetic,
not a run or emulation of the captured binary. Specific edges are `3599 -> 0`,
`3600 -> 1`, `86399 -> 23`, `86400 -> 24`, and `89999 -> 24`.
The first threshold is **921600**, not a normal day's 86400 seconds; it must not
be silently simplified when reconstructing this instruction path.

The error-arm data is connected through actual PC-relative instructions and
`R_X86_64_RELATIVE` relocations, not just substring presence:

| Arm | Message VA | Location-shaped record VA | Relocated path and recorded line:column | Call slot -> target |
| --- | --- | --- | --- | --- |
| `0x1450a13` | `0x219daa`, `called Result::unwrap() on an Err value` (backticks in raw data) | `0x566aac8` | `base/src/time.rs:62:44` | `0x576e048 -> 0x157aa10` |
| `0x1450a38` | `0x216f29`, `assertion failed: hour <= 24` | `0x5666dd8` | `base/src/hour.rs:12:13` | `0x576e108 -> 0x157b7f0` |

Each record has a relocated path pointer, a 64-bit path length of 45, and two
32-bit integers for line/column; the complete paths and values are retained in
`evidence.json`. The recorded paths use the build's `/home/ubuntu/hl/code_Mainnet/`
prefix; this is target evidence, not this operator's home directory. The helper
also passes a reference at `0x566ac40` in the unwrap arm; the complete bytes
lock its instruction, but the referenced formatting/type data is not decoded.

## Inferences and unknowns

- **Inferred:** this is an hour extraction helper for a datetime-like value,
  with a private `Time` / `Hour` boundary. Its `u32` field, quotient by 3600,
  private file records and caller's byte use support that label. The binary
  has no recovered symbol name here. Neither the source-level method name nor
  the full input layout, Chrono version, validity invariant or enum ABI is proven.
- The private paths support attributing the *call sites* to private base code.
  Unwrap/assert message shapes suggest compiler/library error helpers, but the
  outgoing target addresses are left unnamed: their own library ownership,
  transitive callees, unwind behavior and non-returning behavior are not closed.
  A private source-location argument does not make a generic panic helper private.
- The input domain reachable from valid application data is unknown. In
  particular, `86400 -> 24` is a fact about the returning machine path, not a
  demonstrated production bug, reachable invalid datetime, or safety finding.
- The incoming call establishes a real entry at the callee's FDE start. FDEs do
  not prove that every other function or incoming edge has been found. No global
  function-coverage denominator is inferred from the unwind index.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison,
normalization mask, behavioral execution or whole-ELF match is claimed. All are
**not yet implemented/measured**. The raw instruction bytes in the checker are
static evidence locks, not executable reconstruction or transplanted code.
New checker/test/documentation code is independently authored; imported bytes
and disassembly retain the artifact's original rights.

Before this change, the repository's 20 tests and required verification,
catalogue and reproduction recipes passed on the baseline. After the change,
30 tests pass. The added controls use the authenticated real target (explicitly
skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed field offset, threshold, branch, multiplier or shift;
- changed FDE extent, source line or relative relocation target;
- changed caller displacement and an additional direct-call pattern;
- an off-by-one instruction address, changed disassembly bytes and truncated
  retained disassembly.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at SHA-256.
The command-line tool always authenticates the complete target first. The
independent disassembly checker compares every decoded byte and contiguous
instruction address against that authenticated file. Identity cases pass for
both retained and freshly regenerated LLVM output. `make verify test
catalogue-check`, `make reproduce`, and repeated packet regeneration pass.
Hosted CI was not observed during local validation.

**No progress gate requested.** Foundation's four gates and generated progress
files stay unchanged. The denominator here is one bounded callee / one caller
window, not all time helpers. Next question: establish the caller's datetime
field provenance and valid input invariant, then independently attribute the
two outgoing generic error helpers before reconstructing Rust.
