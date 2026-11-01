# RE-001: qualified normalized weight-table constructor

The selected compressed-weight caller needed a table whose every symbol,
bit count and next-state range was established from actual code. An inferred
FSE label or a header/entry census did not supply that guarantee. This outcome
provides the exact normal serialized-table relation and an independently
authored safe Rust implementation, with bounded input and output behavior.

Target node #94 is91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The fixed-source experiment used reviewed main
546081f30a3ebe6af1dadb6f90869f01bd08e1e4; a later integration base is
qualified separately without relabeling this experiment.
The primary measured FDE is `[0x556fb60,0x556fe63)`:771 bytes/213 complete
native rows,24 direct branches, one RET and no calls. No global function
denominator, accepted progress gate or whole-ELF match is claimed.

The [real Rust component](../../../src/node94-fse-weight-table/README.md)
emits the native four-byte header and32/64 four-byte rows under the actual
876-byte caller's qualified normalized-count domain. It preserves the
remaining output suffix. The new safe interface returns a chosen132/260
byte length, distinct from native successful RAX0. UnsupportedDomain is an
explicit policy outside the qualified native relation, not native malformed
error parity. Private Rust scratch does not claim the target's workspace image.

## Native proof and context

`observed/records.json` derives selected FDE/CIE, executable section/PT_LOAD,
complete raw instruction fields and fresh GNU rows from one immutable
full-digest-admitted input. GNU sees only a tiny private non-executable
771-byte file, never the captured ELF pathname. The complete selected FDE
record is72 bytes and CIE24 bytes; no full unwind-behavior claim follows.
The maintained provider's raw schema is a specific opcode/register/field
matcher, not a general disassembler or instruction interpreter. Optional
rendered prose is not semantic authority.

`PROOF.md` treats both spread routes separately. Reserved low-probability
symbols occupy descending high slots; the filtered odd-step permutation
covers every remaining slot. The optimized no-low route's padded QWORD/SIMD
symbol list stays within its reserved scratch and supplies the same exact
logical permutation. Final occurrence counters are nonzero and give bounded
base/bit rows. F=1 implies positive bit counts; F=0 may contain zero-bit rows.
The normal input includes the proved signed-WORD absolute-mass invariant,
not an assumed public C implementation or source type.

The actual876/outer-size formula and91/11 symbol caps are **separate caller
qualification**, not constants decoded from the771-byte body. The208 raw
caller witness bytes in `metadata.caller_context` and
`CALLER-QUALIFICATION.md` bind those units and their historical proof chain.
Header/decoder context is not added to primary constructor coverage and is
not claimed as implemented by the new Rust library. The later12,390-byte
HUF builder's complete symbol/advance coverage remains open.

Normal claims require accessible separated nonwrapping regions, protected
stack/return/code, and ordinary architectural integer/BSR/SSE behavior.
The contextual header proof also states its memcpy/memset and CPU conditions;
actual loaded runtime providers remain unqualified. This constructor itself
has no opaque helper. Invalid counts, arbitrary aliases, faults/unwind,
original private ABI/types/compiler and whole decoder behavior remain outside
the new implementation relation.

## Independence and evidence

`independent-oracle/` preserves the pre-Rust functional table oracle and its
42 frozen vectors:39 actual876-domain cases and3 broader standalone-only
cases. Only the39 are the primary implementation corpus. The3 are retained
as broader native proof or separate safe-API policy evidence. They never
count as qualified caller table matches. Source/expected streams remain
separate, and the actual production client receives no expected answers.

`independent-controls/` preserves the separate before-Rust native operand
design and supplementary API expectations. Actual changed-byte/listing
observations, provider rejection results, Rust executions and compiler
outputs must be read as distinct kinds of evidence. A static input rejection
does not masquerade as captured behavior, and a vector is not counted as a
separate Rust test function.

The native controls operate below complete-image identity, on genuine changed
771-byte inputs and their real tiny GNU views. The body has no RIP-relative
table literal: synthetic normalized-table/input/comparator changes are labeled
separately. Source/data/call/whole-ELF gaps and all source pins remain distinct.
No unlicensed inferred implementation, public C postcondition or original
machine-code transplantation supplies the Rust behavior.

## Reproduction and validation scope

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/fse_weight_table.py \
  --output /tmp/new-owned-fse-native-record
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_fse_weight_table.py -v
```

Use fresh owned output paths. Existing outputs are preserved and wrong
identity exports nothing. The source/header/node images never execute.
The real Rust build is complete: both profiles match all 39 primary outputs
and the separate 30 API observations; each passes one fixture test function.
Five compiling mutants produce normal valued differences, and two fresh own
libraries are raw equal. `component-build/BUILD-VALIDATION.md` and the exact
41-command/82-stream record state the actual scope. The independent client
also passes three orders of 48 frozen requests (45 qualified, including six
new cases, and three safe-API refusals) against the retained production rlib.
Its one extra client compilation does not rebuild the library. See
`independent-replay/` for exact inputs, expectations and eight raw streams.
Current-base repository checks and hosted results remain separately reported;
no full decoder, original-byte or project-gate success follows.

New independently authored code/docs are MIT. Imported captures retain
their original rights and ownership. All seven imported source pins and
generated component/progress gates remain unchanged.

The final independent computational/source/artifact review is
`independent-replay/FINAL-INDEPENDENT-SOURCE-ARTIFACT-NOVEL-REVIEW.json`.
It checked the existing raw artifacts and the frozen novel expectations; it
did not compile another library or execute a captured target. The guarded
client was written after production-source review. Its six additional
expectations were frozen before that peer first read the production source,
which is distinct from the original 42-prefix oracle predating production
authoring. Reordering and renaming repeat the same 48 cases, not 144 unique
semantic cases.

## Integration and repository checks

The fixed-source Rust experiment is preserved on main546.
`qualification/CURRENT-BASE-REBIND.json` binds its unchanged component inputs
to integration base4179 through the admitted78 and4179 source changes. Fresh
current-base native records and listing are byte-identical to the measured
ones. Four cleared static Make targets and all11 owned FSE methods pass on78;
the changed catalogue check and five tiny fixture methods pass on4179. Full
current-suite and hosted CI are pending separate authorization; the draft head
uses `[skip ci]`. No successful full-suite or Ready status is claimed.

The active RE-001 blocker was the selected compressed-weight decoder's opaque
constructor: existing ELF/FDE readers bounded code but did not establish table
coverage, row state/bit bounds or a target-grounded output oracle. The small
provider and build runner serve this concrete reconstruction and its proof;
no existing general tooling, infrastructure or workflow is changed.
