# RE-005: independently reconstructed strict three-digit parser

The accepted static packet in [PR627](https://github.com/lalalune/hyperliquid-source/pull/627)
established one call-free parser's instructions but expressly excluded Rust
reconstruction. This contribution supplies that missing implementation and
actual component qualification, without remapping an unrelated family.

Component: foundation/RE-005. Source base:
`4179e174f58ea877cb803abece4a3842c614daf3`, tree
`cc9d8be5cec3ed9f68b0320b4e4cacea66a24419`. Node94 is91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The chosen [safe Rust API](../../../src/node94-three-digit-ascii/README.md)
returns0 unless its slice is exactly three ASCII bytes, first1..9 and others0..9;
otherwise it returns100..999 and never modifies the input.

## Actual native contract

The complete selected FDE `1683670..16836c5` is85 bytes/30 native rows, SHA-256
`90c7bd6c996890a0c04b23ee47ff7aa6bdb911997e320fdb6989e741a090abca`.
There are two conditional forward edges, two RETs, no CALLs, no RIP data,
and no explicit stores. The11 subsequent INT3 padding bytes are excluded.

One full-digest-admitted immutable target snapshot supplies all ELF section,
PT_LOAD, FDE/CIE and raw facts. GNU receives only tiny owned non-executable
raw files, never the original ELF pathname. The primary zR CIE and separate
caller/neighbor zPLR CIE records are retained distinctly. The initial overly
strict preparation assertion and its correction are preserved; no evidence
or successful certificate existed for that failed attempt.

[PROOF.md](PROOF.md), frozen before Rust, accounts for all30 instructions.
It proves exact length-first behavior, all256 values of each byte predicate,
the OR join, zero sentinel and bounded weighted value. All three native loads
precede the DIL clobber. Valid tens are at most90, so their native low-byte
truncation is exact; the full value is at most999. The proof uses scalar
equations and full local CFG, without a PC/register/opcode evaluator.

The separately selected31-byte caller context `16825fe..168261d` loads the
pointer/length from[R15+8]/[R15+16], calls the parser, tests AX for zero and
conditionally stores AX plus a byte tag7. A separate1,301-byte caller decode
only corroborates those seven instruction boundaries; it is not a reconstructed
caller, new semantic denominator or field/type identity. The older packet's
first-load prose is incorrect; actual raw bytes are authoritative and the old
packet is left unchanged.

## Independence and actual own-Rust behavior

The primary native-equation corpus was frozen before any new Rust source:
1,663 distinct stimuli, comprising all900 valid triples,739 single-invalid-byte
triples and24 additional length/multiple-invalid boundaries. Three exhaustive
256-byte predicate checks establish the complete byte-class equivalence. The
900 accepted triples follow by9*10*10; this is not16million target executions.
Original inputs, answers, source generator and freeze remain separate and
unchanged under `pre-Rust-oracle/` and the component's fixture files.

The library is independently authored `no_std`/`forbid(unsafe_code)` Rust.
The single ordinary unit embeds expected vectors only under `cfg(test)`.
The production driver receives one input-only file containing `id hex_or_dash`,
calls the separately compiled production rlib, and reports `id decimal_value`.
It receives no expected answer, role, desired result or declared input length.
This is input-only data flow, not a filesystem sandbox claim.

The actual research rustc1.94.1 run in `build/RESULT.json` records29 commands
and all58 raw streams. Debug and optimized profiles each pass one ordinary
unit containing the1,663-case fixture and an input-only client on all1,663
cases. Three compiling controls return normal full-count scalar transcripts
with1,7 and900 changed values (leading-zero acceptance, relaxed exact length,
wrong hundreds weight); each also fails a real unit value assertion. A failing
unit stops at its first discrepancy: `fixture_cases` denotes the available
fixture, not a claim that every failing-unit case executes.

Two independently built7,724-byte own optimized rlibs are byte-equal, without
normalization. This is archive-level metadata/bitcode reproducibility:
the selected optimized code object has empty `.text`, embedded bitcode and
no defined FUNC. Actual input-dependent parser code is generated in the real
extern clients from the crate metadata; no standalone85-byte emitted body or
target-code match is asserted. The separate raw readelf/objdump observation
is retained under `independent-peer/own-object-static-observation/`.
All computational inputs,103 admitted compiler payloads,
streamed capture identity, linker identity and seven imported source pins match
before/after. Clean child environment, exact argv and tool identities are
retained. Compiler/payload hashes and before/after observations are not an
atomic hostile-host guarantee or an original-toolchain attribution.

An independently frozen padded-client corpus/review is separate from these
1,663 author cases. `independent-peer/` retains the independent native relation,
source/client review,64-record expectation freeze and actual one-client compile
and input-only run against the retained optimized rlib. All64 rows match exactly,
including duplicate IDs, order and middle slices with poisoned neighbors.
No library is rebuilt by that peer. Its21 nonzero rows cover12 distinct valid
values already among the900;28 distinct invalid vectors were absent from the
author corpus and34 rows exercise poisoned contexts. These overlapping counts
are not added into valid coverage. Seven pure output/comparator rejection
checks are separate from the three compiled Rust semantic controls.

The peer froze its expectation corpus before the production Rust existed,
and its client source before reading production. Its helper scripts retain
exact historical owned paths, not a new public tooling interface. The exact
public-safe allowlist excludes executables, rlibs, captures and compiler
payloads. There cannot be additional distinct valid triples beyond all900.

## Reproduce and remaining scope

The existing accepted checker remains the portable native recheck:

```sh
python3 -B tools/foundation_three_digit_ascii_parse.py \
  --check research/work-items/foundation-three-digit-ascii-parse-94/evidence.json
python3 -B research/work-items/RE-005-three-digit-ascii-rust-94/qualify_component.py \
  --repo "$PWD" \
  --oracle research/work-items/RE-005-three-digit-ascii-rust-94/pre-Rust-oracle \
  --rustc /path/to/authenticated/rustc \
  --output /tmp/new-owned-three-digit-qualification
```

Use a fresh owned output path and the exact admitted research compiler. The
component-local recipe is part of this concrete Rust reconstruction, not a
generic tool or workspace change. `preparation/admit_native.py` and the
oracle generator retain exact historical owned paths; they are historical
admission/freeze source, not advertised as new portable tooling. No compiled
executable, rlib, full capture or compiler payload is vendored here.

Current exact-commit repository checks and hosted status are separate pending
qualification. The safe-slice/u16 interface is chosen independently. Original
Rust name/type/ABI/compiler, invalid raw-pointer faults, physical read traces,
unwind/runtime behavior, value meaning, full caller/node and target-byte
identity remain unqualified. All component gates and pinned imports stay
unchanged. New code/docs are MIT; captured evidence retains original rights.
