# RE-003: integration review of PRs #1265–#1275

- Question: do these eleven recorded heads preserve the pinned inputs and reproduce
  their bounded static evidence when integrated together?
- Base: `15f79350f790a04aed73b5fc9319f85b535f8282`; exact contributor heads are
  recorded in `reviewed-heads.json`. Incoming source and raw evidence are preserved;
  one derived README count is corrected below.
- Components: foundation, staking/CoreWriter, bridge/EVM, oracle/asset handling, storage/state-wrapper decoding,
  and the separate Visor artifact.
- Claim status: local static observations and integration validation. The
  original packets retain their inferred labels, helper assumptions and unknowns.
- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Visor: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Node #115 is used only by the existing inventory reproduction check, with digest
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Evidence

Four foundation helpers cover move assignment, five empty-range gates, a
destructor loop, and the set-once cell at `0x1515a30`. Native disassembly agrees
with 121 instruction rows in their 407 bytes. Actual `.eh_frame` records confirm
the four extents; native instruction starts and destinations validate all 22
recorded direct callers of the move-assignment and destructor helpers. The
set-once scan finds no direct rel32 byte-pattern candidate or qword reference;
this does not rule out indirect callers. The new set-once packet's 11 tests pass
against the materialized target, resolving its contributor's LFS-pointer blocker.
PR #1273 subsequently updated its provenance notes to distinguish retained
claims from checks performed on the contributor's machine. The updated head is
merged and revalidated: all 11 tests, the manifest, native bytes and FDE/xref
checks pass again. Initial receipts are retained alongside the current receipts.
Its incoming binary-corruption tests stop at the digest guard, so they do not
demonstrate independent structural-parser rejection.

CoreWriter, EVM block-step, SetGlobal oracle and asset-scaling regeneration
reproduces 38 retained files byte for byte. All eleven incoming manifests verify,
covering 119 recorded file hashes. The CoreWriter, EVM block-step and SetGlobal
oracle evaluators retain their
explicit helper stubs, unreached paths and surviving mutants. GNU objdump agrees
with 32,404 custom-decoder instruction partitions across 96 declared ranges.
These are not 96 complete functions: 60 ranges coincide with actual FDE extents,
while others are fragments or prefixes. The custom decoder reaches the end of
91 declared ranges and stops at unsupported instructions in five. Exact stops
and actual FDE bounds are recorded in `decoder-native.json`; unsupported tails
receive no credit. Partition agreement does not independently prove evaluator
semantics or correctness for all inputs.

Late PR #1274 adds a 101-byte sentinel/devirtualized-getter helper and its
9-byte known getter. Native decoding agrees with all 30 instruction rows; actual
FDE/CIE records and the symbol-zero `R_X86_64_RELATIVE` binding at `0x5778020`
confirm the recorded extent and getter address. All 25 tests pass. The dynamic
fallback callee remains unknown. This review does not rerun the contributor's
whole-corpus similarity/singleton survey and assigns no census credit.

Late PR #1275 reproduces its state-wrapper record byte for byte, bringing the
batch to 39 reproduced files. All seven tests pass. Native exports cover four
actual FDE ranges, 12,583 bytes and 2,672 instruction rows. All 28 selected pins
and 16 branch/call sites align with native instruction starts; all 1,036 table
target references in 518 pairs also land at instruction starts. Counts include
repeated target references and do not establish reachable tags or a complete CFG.
Map missing/duplicate decisions and the sequence-count branch agree with the
selected native paths; the inner value schema and unknown-key helper remain open.
Its table-corruption test rejects at the digest guard, not a table-structure check.

The asset-scaling packet reproduces its evidence and 77 vector records. Native
inspection agrees with all four full FDE extents, 519 instruction rows and the
five conversion/wrapper anchors. The distinction between u64-to-binary64 rounding
followed by division and exact decimal arithmetic remains explicit. Runtime
rounding mode, caller-domain closure and serializer behavior are not established.

The Visor draft passes static regeneration and ten corruption/preservation
controls under both normal and optimized Python. Both receipts agree. GNU and
LLVM agree on all 1,471 instruction partitions in eight complete FDE bodies,
6,320 bytes. Fresh target facts equal the submitted summary; only provider
versions differ. The host qualification changes version-admission strings in
ignored copies from GNU 2.42 / LLVM 18.1.3 to GNU 2.47 / LLVM 22.1.4. Submitted
scripts and provider claims are preserved. Shell command text, opaque formatting,
spawn internals and complete wait-status semantics remain unresolved as described
in the original proof. No captured node, Visor or shell command is executed.

## Caller-count correction in PR #1265

The submitted move-assignment README says its 17 direct callers occupy six
containing FDEs. Actual `.eh_frame` bounds and native exports place them in seven:
`0x522d9e0`, `0x5230000`, `0x5232b30`, `0x5232e80`, `0x5233380`,
`0x5233a50` and `0x5234090`. The count is corrected and its manifest refreshed.
`original-move-assign-count/` retains the submitted README and manifest; raw
evidence, call sites, helper semantics, tools and tests are unchanged. The
per-caller bounds are recorded in `foundation-and-asset-native.json`.

## Reproduce and validation

Run from the repository root with Python 3.13.2 and installed GNU binutils 2.47
and LLVM 22.1.4 on `PATH`. Original packets contain their exact reproduction
commands. `review-scripts/` preserves the executed integration scripts; reuse
requires restoring their ignored work-directory layout and replacing local-path
placeholders. Fresh native exports are retained under `native/`; only local
filename prefixes are replaced, with original and published hashes recorded.
The native byte comparisons use ELF virtual addresses without rebasing or byte
normalization masks. Full transient outputs remain under ignored
`work/merge-open-1265-1272/`.

The asset tool accepts its documented CLI, not `main(argv)`. The initial generic
review adapter fails on that signature; the subsequent direct CLI succeeds and
reproduces both retained files. This review-adapter failure is retained and is
not reported as a repository defect.

All 901 current test files pass: 14,528 reported tests, including 60 explicit
skips (14,468 passed). Repository integrity, catalogue consistency and imported
inventory/literal reproduction checks pass. Final per-file results, source identities,
reproduction comparisons and limitations are recorded alongside this file.
The full existing test inventory uses the same fresh isolated unittest command
per file as `tools/run_tests.py`, scheduled with sixteen concurrent subprocesses;
the three late test files are checked separately. Captured-execution and Unicorn
opt-ins remain disabled. Hosted CI is a separate result.

## Results and limitations

No Rust implementation or new compiled-byte comparison is included in this
batch. Original-source reconstruction, helper/data/relocation closure and
whole-node correctness remain unmeasured. No progress gate is requested, and
README completion percentages do not change. In particular, static target bytes
and matching decoder boundaries are not reconstructed matching byte windows.

Next question: can the CoreWriter-to-delay helper handoff be closed with
target-backed input/output layouts while retaining the existing sender, ABI and
unsupported-path controls?
