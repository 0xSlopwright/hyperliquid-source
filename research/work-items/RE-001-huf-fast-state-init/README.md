# RE-001: checked construction of the fast-loop state

## Current main integration

This original packet was prepared on `1f8c67c`; its original evidence and
validation below remain historical records. The exact patch is now applied to
reviewed main `308e5127990217a9d6196992665da6ca1afd4b82`.
Read [CURRENT-BASE.md](CURRENT-BASE.md) for the fresh parser/native rebind,
current ownership status and exact validation limits. Current source/helper
bindings are observations added beside the original records, not restamped
historical claims. Full upstream `make test` is not currently authorized:
its concrete captured-instruction evaluators require separate execution scope.
The cleared four targets and ten known static/own-Rust tests are reported
separately; they are not a full-suite PASS.

This packet answers one missing interface question around the two code spans
whose compatible licensed assembly recipe was established in #1065: what
state does the *actual captured constructor* pass to those loops, and what
happens when it refuses to construct it?

The primary semantic denominator is exactly the actual node #94 FDE
`[0x55dc5e0,0x55dc79b)`: **443 bytes, 130 instruction rows, 128 reachable
rows, 16 encoded branches, two RET sites, no CALL and 19 QWORD state writes**.
The target is `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The selected body SHA-256 is
`e7052c7ace72f939bcd09f0655e76d408c9e0bb3c25e84a6fb083e072bbb7f63`.
`PROOF.md` and `TRANSFER-LEDGER.json` cover every selected instruction and
preserve all guard/refusal/partial-write paths within the declared domain.

## Observed contract and independently authored Rust

The constructor first reads a complete table-header DWORD, even when output
length0 subsequently returns0. Positive output length with input length<=9
returns raw-20 before the table-kind test; a header byte2 other than11 returns0.
Later refusal paths retain four or twelve state writes; successful construction
writes all19 words. The exact late-output refusal set is {1,2,3,5,6,9}, not
merely lengths below4. Failed stream-start values are retained modulo2^64,
even when they do not denote readable input.

Success initializes four input cursors, four output cursors, four nonzero
initial bit cells, the incoming table base+4, input/output bounds and four
stream starts. The guarded BSR and OR1/shift equations prove each **initial**
bit cell nonzero. The statement does not qualify later refills or decoder
behavior. Table payload, symbol/advance values and runtime CPU support remain
unqualified; in particular the earlier X2 advance1..2 premise stays open.

`src/node94-huf-fast-state/lib.rs` is a real dependency-free Rust component
implementing this detached checked constructor. Its existing19-word image
preserves refused-path partial writes and raw0/-20/1 statuses in its documented
normal domain. Unsupported symbolic address, alias or signed-length domains
are separate errors and leave state unchanged. This boundary is not a native
error status, FFI entry point or decoder implementation. There is no invented
Cargo workspace, dependency graph, lockfile, assembly transplant or target-byte
compiler input. A real stdin/stdout client receives stimuli only, not expected
answers. Only this new component/client may execute.

The explicit domain includes nonwrapping state/input/output/header regions,
O+3*ceil(L/4) in addition to O+L, and nonaliasing roles. Native protected
save/return slots and immutable code are separate external premises. The state
is legitimately caller-local storage; separation does not exclude that whole
local allocation. Ordinary valid return state, table payload and later caller
behavior are not checked by the detached API.

## Separate context denominator

The two selected wrapper prefixes are109 bytes each; the dispatcher context
is313 bytes. Their **531 context bytes are separate from the443 constructor
bytes**. They establish selected pointer/argument flow: an incoming loop
pointer is saved, the constructor receives the stack-local state address, and
the proved status1 reaches the indirect loop call. Header-byte selection and
opaque caller flag bits explain the selected assembly-pointer paths. These
are not a whole-wrapper/dispatcher implementation, CPUID derivation, original
private type, complete caller closure or runtime dispatch qualification.
Node #115 context was only an intake lead; this packet's semantics bind #94.

#373's gap census, #37's FDE release drift and #875's ISA census are credited
and untouched. #981/#1022/#1043/#1048/#1065 establish distinct earlier loop,
span or source/build facts. This packet adds the previously unproved state
constructor; it imports none of those unmerged analyzers or implementations.
No original function/source/version identity or progress gate is claimed.

## Evidence and reproduce

The collector admits one immutable full target by its pinned digest; all
section/PT_LOAD/FDE/code/context facts derive from that same object. GNU sees
only tiny new raw spans, never the original capture pathname. Exact native
addresses/bytes, branch displacements and the complete reviewed transfer ledger
are checked. Real raw guard/store/shift/listing corruptions are separate from
full-image identity refusal. Source/helper/proof bindings accompany the export.

```sh
mkdir -p /tmp/huf-state
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python3 -B tools/huf_fast_state_init.py \
  --output-dir /tmp/huf-state/fresh \
  --rust-cases research/work-items/RE-001-huf-fast-state-init/evidence/independent-cases/STIMULI.json
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python3 -B -m unittest discover \
  -s tests -p test_huf_fast_state_init.py -v
make --jobs=1 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

Use a fresh output directory. Native-only collection is available by omitting
`--rust-cases`; it does not pretend that a Rust build occurred. Static and Rust
subdirectory output manifests each bind their own exports; the packet manifest
binds the delivered packet as a whole. Unsupported GNU/provider or Rust/toolchain
identities refuse direct collection explicitly. Native/component test groups
may report an explicit unqualified skip there; supported qualification requires
zero skips. No install or network fallback is attempted.

The actual reproduction compiler is the already authenticated direct rustc
1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM21.1.8), targeting
x86_64-unknown-linux-gnu, with the pinned GNU linker. All103 installed prefix
and four specified host-linker file identities are checked before/after.
Subprocess environment records list explicit overrides; the remaining inherited
host environment is trusted and unrecorded. Historical four-key environment
records retain a precise clarification and their original producer.
Runtime loader and system libraries remain trusted host inputs; these checks
are not atomic execution provenance or attribution to the original compiler.
`TOOLCHAIN.json` preserves the original official archive identities and terms.
Compiler and standard-library payloads are not vendored. Own Rust client
execution is recorded; captured and compatible assembly code are not executed.

Independent expectations were frozen before reading new Rust source. Separate
STIMULI/EXPECTED files contain51 full-state cases:17 success,18 raw0,3 raw-20
and13 unsupported-domain cases. They cover guard priority, every refusal phase,
endian/bit boundaries, late-output lengths, wrapped refused pointer values,
empty/adjacent regions, aliases and high-address/signed-length boundaries.
Expected answers never enter the runtime driver. A separate peer also froze
its own native-equation cases before source review. Actual compiled semantic
counterfactuals and native corruption controls test the proof/data boundary;
they are neither target defects nor substitutes for the static argument.

Observed component checks pass all10 normal and all10 optimized-Python tests
with zero skips. Final Rust debug responses match the independently frozen51
full-state expectations. Two fresh opt-level3 builds each match those51 cases;
their complete retained .rlib bytes match and complete linked-driver hashes
match. One documented physical-source-root remap flag explains the final
reproduction recipe; it is a compiler input, not a target-byte mask or rewrite.
The three earlier unremapped builds had equal drivers but different .rlib
hashes. A retained .rlib contains its temporary source path; absent older
payloads prevent full difference classification. Those original results remain
unchanged. Six single-change compiled counterfactuals under the earlier recipe
are each rejected by the frozen51-case expectations (31/1/2/3/17/3 differing
cases). These are source/contract controls, not original-target bugs.

The peer's distinct42-case runtime-input-only client also passes all cases,
linked against the actual retained pre-remap library. Its record qualifies
that source/library recipe, not later artifact reproducibility. No expected
answers enter either runtime client. Current source semantics are unchanged.
The logical assignments and returned partial images are checked; physical
generated Rust store order, ABI and instruction-byte identity are not measured.
All33 retained static negatives are rejected:21 constructor-byte changes,
four wrapper-byte changes, four wrapper-operand renderings and four listing
controls. Their raw tiny input/provider records remain in the packet.

Preparation preserves the first proof and its precise caller-local-stack
clarification. Actual focused/build/independent review results and final
exact-commit required checks are recorded separately as they are observed;
none implies hosted CI, captured execution, all-input decompression, whole-node
identity or a completed component gate. New source/docs use MIT; target bytes
remain evidence under their existing ownership. No unlicensed inferred source
is read or copied; compatible BSD source in #1065 supplies only hypotheses.
