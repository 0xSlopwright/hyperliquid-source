# RE-005: conditional flat diagnostic-field callback contract

- Component: serialization, RE-005 prerequisite investigation.
- Target: Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes).
- Maintained base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Status: byte-bound static observations and a conditional normal-return contract. No component gate changes.
- Included: the complete 390-byte helper at VA `[0x1571f50,0x15720d6)`, its flat-mode CFG, operands, callbacks and common state writes.
- Excluded: pretty-mode semantics, callback implementations, physical rendered output, original Rust types/ABI, application reachability and executable reconstruction.

## Question and relationship to earlier work

PR [#1015](https://github.com/lalalune/hyperliquid-source/pull/1015) establishes the selected integer-error diagnostic fields and actual name-table associations. It explicitly leaves field helper `0x1571f50` opaque. This packet independently reads the maintained base bytes to establish that helper's ordered flat-mode callback/state contract; it does not require or modify #1015's unmerged files. It also leaves the wire-codec work in #48, #253 and #371 untouched.

The actual RELATIVE record for slot `0x576e2c8` targets this helper. The caller field sites identified in #1015 are `0x14f6c51` and `0x14f6c6f`. The helper has its own complete FDE `0xcfa5b0`, CIE `0xce1518`, and file span `[0x1570f50,0x15710d6)`. Raw FDE/CIE bytes and selected RELA records are retained in `observed/records.json`. The helper span SHA-256 is `e6aec76f57413451c7a873712558e50e18c6f30b2001b6777c3fd29fda32388d`.

## Established conditional contract

Read [ASSUMPTIONS.md](ASSUMPTIONS.md) before applying this contract. Let `S` be incoming RDI, `E=byte(S+8)`, `H=byte(S+9)`, and `F=load64(S+0)`. These are observed access offsets, not a recovered nominal layout.

The entry `E!=0` route performs no formatter, name or value callback access. Otherwise this packet's flat domain requires `byte(F+0x12)&0x80==0` and `H` in `{0,1}`. The mode TEST at `0x1571f92` supplies the flags used by the branch at `0x1571f9b`; the intervening MOVZX preserves those flags.

There are exactly five flat normal-return termination routes over that domain:

| Route | Ordered callback sites | State writes at common return |
| --- | --- | --- |
| Entry E nonzero | none | byte(S+8)=1, then byte(S+9)=1 |
| Prefix AL nonzero | 0x1571fc5 | byte(S+8)=1, then byte(S+9)=1 |
| Name AL nonzero after prefix AL zero | 0x1571fc5, 0x1571fd9 | byte(S+8)=1, then byte(S+9)=1 |
| Colon AL nonzero after both earlier AL zero | 0x1571fc5, 0x1571fd9, 0x1571ff3 | byte(S+8)=1, then byte(S+9)=1 |
| All three writer AL values zero | all three above, then value 0x1572009 | byte(S+8)=low8(value EAX), then byte(S+9)=1 |

Each route returns the original `S` in RAX at `0x1571f86`. The first three callback errors are normalized to byte 1; the value callback is different: its low result byte is captured at `0x15720ce` without a flat-path success/error test. No nominal `fmt::Result` representation is inferred.

The actual callback operands are:

| Role | Arguments and target |
| --- | --- |
| Prefix | Fresh destination `load64(F+0)`; method `load64(load64(F+8)+0x18)`; H=0 selects VA0x252bfb/length3/bytes207b20 (`" { "`), H=1 selects VA0x252bef/length2/bytes2c20 (`", "`) |
| Name | Fresh destination/method reads again; original incoming RSI/RDX saved in R14/R13 |
| Colon | Fresh destination/method reads again; VA0x252bfe/length2/bytes3a20 (`": "`) |
| Value | Incoming RCX via saved frame slot `rbp-0x40`; original F in RSI; method `load64(saved incoming R8 descriptor+0x18)` via `rbp-0x38` |

The prefix length is the actual zero-extended H XOR3 expression. The selector is actual TEST-H/CMOVNE. We qualify only H0/H1; the presence of byte loads does not establish a valid arbitrary-byte state domain. Fresh destination/method reads matter: if earlier callbacks mutate F or its method slot, subsequent writer identity may differ. A stable-writer specialization requires additional preservation assumptions.

The full raw span has 109 native instruction rows, 14 basic blocks, 10 conditional branches, two unconditional jumps, nine indirect call instructions and one RET. These are inventories over all 390 bytes, not a claim that all nine calls belong to the flat contract. The bit-set route beginning `0x1572011`, including its adapter `0x157d000`, remains opaque. The actual RELATIVE records at `0x576e330` and `0x5674228` bind that unresolved adapter.

## Reproduce

From the repository root, use installed Python and GNU objdump, disable bytecode caches, and choose fresh output directories:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/bincode_diagnostic_field_static.py --output work/re005-field-proof
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-005-diagnostic-field-trace-94/controls.py --output work/re005-field-controls
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.test_bincode_diagnostic_field_static -v
```

The producer authenticates the complete node94 bytes before parsing. GNU objdump receives only an owned, non-executable copy of the 390-byte span, with `-D -b binary -m i386:x86-64 -M intel --insn-width=16 --adjust-vma=0x1571f50`. Every native row must tile the span and equal the admitted copied bytes. Relative branch destinations are independently decoded; operand templates and extracted immediates establish the specific relations above. A finite CFG walk enumerates symbolic zero/nonzero edge predicates and opaque normal-return callback events. It is not a concrete register/memory instruction interpreter, emulator or callback execution.

`observed/helper.objdump.txt` preserves the complete GNU listing, normalizing only the ephemeral raw-input filename. `observed/records.json` contains all blocks, edges, path predicates, operands, selected metadata and explicit unqualified conditions. `observed/counterfactuals.json` records all 18 actual mutated raw spans, their native-listing hashes, changed facts/edges and specific rejected relation. The controls command also retains every mutant's native listing in the chosen output directory.

## Controls and limits

All 18 actual raw-byte mutations retain the original 109 instruction rows, nine calls, ten conditional branches, two jumps and one RET. They change entry status/branch polarity, prefix short-circuit destination or polarity, XOR length/selector/test register, name/value arguments, colon pointer/length, value method slot, state-store offsets/constant, value-result source and formatter mode mask. Native decoding and relation extraction reject them for the changed ordering, arguments, slices or state transfer, rather than the instruction/call/branch counts or production image hash. These are checker controls, not behavior comparisons with an executed target.

Independent review found a concrete checker defect in the first frozen candidate: replacing prefix-error JNE bytes75a1 with75ba reaches the existing RET directly, skipping both common stores and the pointer-return MOV, but the first checker still reported those outputs. The regression failed before correction and passes after it (retained before/after logs beside the focused log). Output facts now come only from actual path-member store/definition/return witnesses in their path order; the direct-RET counterfactual reports no stores and an unclosed return value and is rejected. The actual pinned target paths were unchanged. This is a corrected checker error, not a target defect claim.

The 13 focused tests passed; the retained log is `observed/focused-tests.txt`. Exact tools/input identities and commands are in `INPUTS-AND-TOOLS.json`; `MANIFEST.sha256` hashes the source, tests and packet. Required repository checks and independent review are reported separately for the final tested commit.

No target executable, callback or reconstructed Rust component was run or built. There is no original function/type/ABI, full error rendering, runtime dispatch, full wire codec, source-equivalence or progress-gate claim. New source and documentation are independently authored MIT work from authenticated bytes and maintained MIT parsing helpers; no unlicensed reference implementation was read or copied.

The next concrete question is the conditional callback/state behavior of the mode-bit-set route and its still-opaque adapter `0x157d000`, including which callers establish its memory and alias preconditions.
