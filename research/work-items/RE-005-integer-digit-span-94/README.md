# RE-005: qualified 20-byte decimal digit span

Task RE-005, with a foundation numeric primitive used by a diagnostic value
descriptor. Source base `308e5127990217a9d6196992665da6ca1afd4b82`, tree
`c39830a007755baa9c1c443134fc71ef2421cbe9`. Target node #94 is 91,774,280 bytes,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No inferred/unlicensed implementation was read or copied. Imported inputs,
all seven source pins and component gates stay unchanged.

The primary implementation is the [real safe Rust decimal suffix](../../../src/node94-integer-digit-span/README.md).
For every u64 at the actual capacity20 call domain, it returns start=20-D(n),
writes n's ordinary decimal spelling at[start,20), and preserves the arbitrary
initial prefix. D(0)=1. This is a chosen safe API, not an original ABI or full
formatter. Its direct /10 algorithm was independently authored; no original
machine code or upstream library implementation was transplanted.

## Exact byte scope and boundaries

| Scope | Half-open ELF VAs | Bytes | Native rows | Claim |
| --- | --- | ---: | ---: | --- |
| Primary | `1570470..157062c` | 444 | 114 | Qualified all-u64 capacity20 digit-span relation |
| Separate selector context | `14f7660..14f774b` | 235 | 63 | Observed selector/call arguments; no closed formatter |

The primary SHA-256 is
`bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f`;
the context SHA-256 is
`a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf`.
Exact FDE/CIE and RELATIVE data bindings are in `observed/records.json`.
Unwind entries are metadata, not an accepted-function denominator. This is
not a 679-byte complete formatter or any original-byte matching result.

`integer_digit_span_static.py` checks every opcode/register/branch/store
shape and explicitly decodes its variable immediate/RIP fields. All such
fields are constrained by target bindings or the numeric proof; none is
silently ignored. The complete argument is in `INDEPENDENT-MATH-PROOF.md`.
The producer's actual record carries the same bounds, partition and all seven
store/guard/source certificates. Normal guarded stores remain in0..19, so
the three out-of-domain calls are unreachable under this capacity20 domain.

Every production metadata/literal/native fact derives from one plain immutable
full-digest-admitted bytes object. GNU sees only mode0600 raw444/235-byte files,
never the captured ELF pathname. Only the owned raw pathname is normalized in
the retained listings; raw bytes, VAs and operands remain visible. Listing
byte tiling and instruction boundaries are checked. Arbitrary rendered prose
is not independent semantic authority: proof uses raw operands/CFG, and the
honest forged-prose control records that limitation rather than inventing an
additional decoder claim.

## Context and remaining unknowns

Descriptor566fb00 has observed words(0,8,8,0), not a recovered nominal type.
Its unique symbol-free RELATIVE slot566fb18 binds14f7660. Existing #1015
parent evidence conditionally associates that descriptor with record+8 at
arm14f6a90/call14f6ae7. No variant name, application reachability or complete
rendered diagnostic is inferred. Existing #1015 names and #1030 parent/adapter
intervals are not new implementation scope here.

The selector gives lowDWORD flag25 priority over26, otherwise decimal. It
passes capacity20 to the primary, then forwards B+start and20-start to an
opaque helper. Hex context uses the actual two alphabets, a separate B+16
buffer end and a literal0x prefix argument; this does not prove prefix output.
Slot576e2d8 resolves to15723b0..15728bf (1295B), whose body is not interpreted.
The primary's guard-call slot576dfc8 resolves to157b64f..157b68c (61B), also
uninterpreted. Short-capacity/error/fault/unwind behavior remains outside the
normal capacity20 proof. No width, padding, fill, alignment, original
type/layout/vtable/compiler/ABI, physical-memory trace or complete G claim.

## Independent expectations and validation

Two independent pre-Rust sources are kept distinct. `independent-cases/`
retains completion's621 decimal marked-buffer and140 separate selector
context cases, with the original freeze and explicit listing-authority update.
The primary1697-vector corpus was independently frozen by the native/math peer
before any new Rust existed. It covers group counts0..5, high tails0..3,
zero, u64 boundaries and arbitrary prefix markers; it does not claim1697
distinct integers or Rust selector/hex coverage.

The public numeric oracle re-admits the target and derives fresh static proof
parameters/table. It applies only the proved abstract quotient/pair relations,
without PC/register/opcode execution, Rust or expected-answer reads. Fresh
expectations must equal the immutable pre-Rust fixture. The real production
client receives only numeric input and initial buffer, and reports raw start
plus all20 output bytes. No source-forged role tag, expected slice length or
normalization can conceal a changed output or incorrect returned index.

Actual native controls bind changed real operands below the full-image gate,
including reciprocal/threshold/store/zero/mask fields and separate selector
arguments. Byte/address/listing and table controls retain their raw outcomes.
The first owned static run passes 8 tests, with 29 actual fresh-native byte
counterfactuals, 4 table mutations and explicit listing/prose scope. Source,
fixture, tool versions/options and exact commands/results are retained by the
validation records. Those static tests are not Rust execution evidence.

The completed [Rust run](RUST-RESULT.json) records 39 actual subprocess calls
and [all 78 exact output streams](RUST-RAW-LOGS.json). Both debug and optimized
profiles pass the real unit test containing all 1,697 marked-buffer vectors
and a separately linked input-only client on all 1,697 cases. Five compiling
semantic mutants produce normal full-length client output with respectively
1, 1,642, 1,697, 1,697 and 1,544 changed results; each also fails a real unit
assertion. These controls cover zero emission, quotient progress, ASCII digit
encoding, returned start and untouched prefix. Two independently built
optimized copies of our own 6,630-byte library are raw-equal, without
normalization. This is an own-build reproducibility result, not equality to
the captured image.

The actual compiler is the separately authenticated research rustc 1.94.1
(`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8). All 9 computational
source/fixture/helper inputs, 103 compiler payloads, the captured target and
7 source pins are unchanged in [before](RUST-BEFORE.json) and
[after](RUST-AFTER.json) audits. The 4 owned runner-admission/comparator tests
also pass; their [result](ADMISSION-TEST-RESULT.json) and raw stderr are kept
separately from compilation. No compiler rerun is hidden in those tests.

`NATIVE-CONTROL-FILES.json.gz` losslessly retains the 134 original control
files, including the original 133-member manifest, every changed tiny raw
span/table and native listing. Decompress the JSON and encode `utf8` content
as UTF-8 or decode `hex` content with `bytes.fromhex`; verify each recorded
size/SHA-256 before using it. The public ledger records 36 genuine rejections
and one accepted optional-prose invariance observation. Neither compression
nor packaging changes the observed bytes or upgrades that scope. The exact
`retain_static_controls.py` is historical retention source with private intake
paths, not a standalone portable replay command; the preserved public design
and generator are under `independent-cases/`.

The pre-build source-guard correction is retained as preparation evidence:
the wrapper initially named unused helpers and omitted its actual
`bincode_varint.py` dependency. That was corrected before any compiler call;
the core and fixtures did not change. The earlier independent-case copy
stopped on a stale handoff hash and resumed only after the fixture owner
supplied the matching listing-authority update. Historical handoffs and
statuses are retained rather than restamped as new build results.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/integer_digit_span_static.py \
  --output /tmp/new-owned-digit-proof
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_integer_digit_span_static.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/integer_digit_span_rust.py \
  --rustc /path/to/verified/rustc --output /tmp/new-owned-digit-build --controls
```

Existing outputs are preserved. Wrong target identity exports nothing. Actual
Rust build/profile/control/rebuild records must be read separately; no pending
command is counted as passed. Current-base repository checks and the separate
authorization boundary for newly imported evaluator suites are reported in
the final PR validation, not waived by this packet. Captured code never runs.
