# foundation-duration-guards-94: nonnegative guards after finite-only clamping

- Component: `foundation`, bounded static mapping of time/duration utilities.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its duration file was only a search lead; no inferred implementation is copied.
- Claim status: instruction/data/edge observations, plus a conditional architectural
  model of selected fragments. Source method names and business purpose are unknown.
- Included: one 522-byte FDE window, two finite-only clamp fragments, four
  nonnegative comparisons, two private source-location records and error arms.
- Excluded: actual captured-code execution, complete function semantics, caller
  reachability, preceding helper/arithmetic closure and any Rust reconstruction.

## Problem and result

A source-looking assertion or a reference `Duration` method does not establish
which binary paths reject negative/nonfinite values. In this window, isolated
nonnegative guards and the complete prefixes leading to them have different
behavior: finite negative values are clamped first. Treating the whole path
as a bare `x >= 0` check would lose that behavior.

The packet establishes the actual instruction boundaries, branches, binary64
constants, relative slots and private source records, and supplies a bit-pattern
model with explicit assumptions. It makes **no production defect claim**.
The exact source method and business-level inputs are not recovered. In
particular this is not identified as the reference's `to_std` conversion.

## Reproduce

Run from the repository root after materializing the pinned submodules/LFS:

```sh
make doctor
make verify test catalogue-check
make reproduce
python3 tools/foundation_duration_guards.py --check research/work-items/foundation-duration-guards-94/evidence.json
python3 tools/foundation_duration_guards.py --objdump /path/to/llvm-objdump > work/duration-fresh.json
cmp work/duration-fresh.json research/work-items/foundation-duration-guards-94/evidence.json
```

Actual environment: macOS 26.2 arm64, Python 3.12.14, Apple LLVM 21.0.0 and
GnuPG 2.5.24. PATH began with
`/private/tmp/hype-analysis-tools/bin:/private/tmp/slop-python-verify/bin`,
`TMPDIR=/private/tmp`; LLVM was
`/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.
The new checker/tests use only Python's standard library. Exploratory FDE
lookup used pyelftools 0.32, which is not needed to reproduce the packet.

The raw exports use these options:

```sh
llvm-objdump -d --start-address=0x392fab0 --stop-address=0x392fcba artifacts/node/94/hl-node
llvm-objdump --dwarf=frames artifacts/node/94/hl-node > work/node94-frames.txt
```

`function.objdump.txt` retains the complete first output. `frames.txt` retains
the matching FDE block from the second. `records.json` retains exact raw
FDE/CIE locks and source/relocation identities; `evidence.json` is generated.
`MANIFEST.sha256` records exact hashes of packet files. No captured binary is
executed. The checker validates full target size/SHA-256 before any analysis;
`--objdump` reruns LLVM and verifies every decoded byte and contiguous address.

## Observations: scope, bytes and edges

Coordinates are ELF VAs, without a guessed runtime base. The tools map through
the section table; `.text` here maps file offsets to VA minus `0x1000`.
`.eh_frame+0x18bf00` describes `[0x392fab0, 0x392fcba)`. LLVM's independent frame
export agrees. Full linear decoding gives **109 instructions / 522 bytes**,
ending exactly at that endpoint. This validates retained instruction boundaries,
not a complete CFG, incoming-reference census or all Duration functions.

### Finite-only prefixes

| Fragment | Sign-mask immediate | Maximum-finite immediate | Nonfinite branch | Finite max with zero | Upper-bound compare / branch | Later guard |
| --- | --- | --- | --- | --- | --- | --- |
| A | `0x392fae4` | `0x392faf1` | `0x392fafe -> 0x392fb1a` | `0x392fb04` | `0x392fb10 / 0x392fb18` | `0x392fb1e` |
| B | `0x392fc20` | `0x392fc2d` | `0x392fc3a -> 0x392fc56` | `0x392fc40` | `0x392fc4c / 0x392fc54` | `0x392fc5a` |

Both masks are `0x7fffffffffffffff`; both finite thresholds are
`0x7fefffffffffffff`. After masking, signed integer `JG` therefore skips the
clamp for infinity and NaN encodings. On the finite path, `MAXSD` has +0 as
destination and the input as source. The next bound is the exact binary64
constant **1.0**, loaded by both fragments from `0x20a730`. `JA` takes the path
which keeps that constant when the clamped value is above it.

The first pair of nonnegative guards uses zero in xmm0, compares xmm1 to it,
then moves xmm1 to xmm0 without changing flags. Their error branches are
`0x392fb26 -> 0x392fc88` and `0x392fc62 -> 0x392fc88`.
Two later guards compare xmm0 to zero in xmm1 and branch
`0x392fb64 -> 0x392fca1` and `0x392fc7c -> 0x392fca1`.
All four use `UCOMISD` followed by `JB`. The later pair occurs after additional
arithmetic; its operands must not be equated with the earlier fragment input.

### Private source-location and call data

Actual LEAs connect the two error arms to these relocated records:

| Error arm | Message VA / exact observed text | Location VA | Recorded path suffix / line:column |
| --- | --- | --- | --- |
| `0x392fc88` | `0x219d71`, `assertion failed: self >= 0.` | `0x566ab58` | `base/src/duration.rs:112:13` |
| `0x392fca1` | `0x219f59`, `assertion failed: self.0 >= 0.` | `0x566ae58` | `base/src/duration.rs:124:13` |

The terminal periods above are literal target bytes, not added punctuation.
The checker verifies the full path bytes, lengths, line/column fields and
`R_X86_64_RELATIVE` path addends, plus actual instruction boundaries/targets.
Both error calls use slot `0x576e108 -> 0x157b7f0`. An earlier helper call uses
slot `0x576f6e0 -> 0x565f8c0`. Those callees are left unnamed and unclosed.
The private source records support duration-related call-site attribution;
they do not establish ownership of a generic error helper or the enclosing
function's source-level method, ABI or business semantics.

## Architectural model and assumptions

Instruction rules were checked against Intel SDM revision 093 (September 2026):
[Volume 2B](https://cdrdv2.intel.com/v1/dl/getContent/671241), MAXSD (4-11) and
UCOMISD (4-733), and [Volume 2A](https://cdrdv2.intel.com/v1/dl/getContent/671199),
Jcc. For comparison with zero, unordered inputs set CF; `JB` follows CF.
Both signed zeros compare equal. MAXSD selects its source when both operands
are zero. These rules motivate the local model, not an executed target oracle.

The model assumes **binary64, DAZ disabled and SIMD exceptions masked**.
MXCSR was not observed. With unmasked signaling-NaN exceptions or a different
denormal mode, a comparison may trap or differ before the modeled branch.
No runtime floating environment, exception flags, FTZ/rounding behavior of
preceding arithmetic or reachability of any special value is established.

| Value presented at a fragment's entry | Isolated UCOMISD/JB guard | Complete finite-only prefix |
| --- | --- | --- |
| finite negative nonzero | error arm | +0 continuation |
| -0 / +0 | continuation | preserve input zero sign at this stage |
| positive finite through 1 | continuation | input unchanged |
| positive finite above 1 | continuation | 1.0 |
| +infinity | continuation | +infinity, bypassing the finite clamp |
| -infinity | error arm | error arm |
| NaN | error arm if flags are produced | error arm under stated assumptions |

The prefix result is at `0x392fb2c` or `0x392fc64`, before the later scaling,
addition and guards. It is **not** the function's return value. Positive infinity
surviving a local fragment is not evidence that a public input can produce it
or that the program has a reachable defect.

`bit_partition` describes nine disjoint contiguous unsigned-bit intervals
whose counts sum to `2**64`. Within each interval, sign/exponent/magnitude
rules yield the same guard category and prefix result kind (identity or a
constant). This is a deductive partition of the model, not an enumeration of `2**64` executions,
a binary differential test or a whole-function proof. First/middle/last interval
samples and numeric boundary cases are controls, not the basis of a coverage
claim. The symbolic model uses integer bit classification; it does not run
captured instructions.

## Implementation, controls and results

No Rust component, Cargo lock, source-equivalent build, runtime differential
comparison, normalized-body match or whole-ELF result is implemented/measured.
The raw-byte locks are evidence, not transplanted executable reconstruction.
New code/docs are independently authored; original binary evidence retains
its upstream rights. No private inferred source code is copied.

The main baseline has 20 passing tests; the change has **29 passing tests**.
`make doctor verify test catalogue-check reproduce` and fresh/retained LLVM
regeneration pass. Doctor reports static analysis ready, exact rebuild not
ready. GPG verification uses an isolated temporary home; the environment's
sandbox restriction requires that check outside the sandbox, without personal
keys. No hosted CI or container result is claimed by these local checks.

The controls compare the isolated guard model with independent host Python
floating comparisons and finite clamps, including subnormal/one-adjacent values,
both zeros and quiet NaNs. Signaling-NaN patterns are checked only as architectural
bit cases, without claiming a hardware exception experiment. Target controls
reject #115, truncation, changed instruction bytes/masks/branches, the 1.0 bound,
source line/assertion text, FDE/relocation changes and off-by-one, byte-corrupted
or truncated disassembly. Structural mutations deliberately bypass only the
complete digest in tests to exercise downstream checks; the CLI never does.

**No progress gate requested.** The denominator is one FDE window, two clamp
fragments and four retained compare sites. All component gates remain unchanged.
Next question: identify the preceding helper and caller/input contract, and
establish the floating environment before considering any runtime interpretation
or independently reconstructed Rust implementation.
