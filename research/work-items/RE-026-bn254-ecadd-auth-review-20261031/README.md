# RE-026 ecAdd harness authentication and result review

Task: RE-003 bounded harness controls supporting RE-026. Target: node94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The reviewed code is Linux x86-64; this repair runs only Python host controls.
Original reviewed commit: `1f719ed976164fb1a03af2a509e02ae0c875c68f`.
Integration base: `caa7999b73fe3207a248bd7f40dafd1d1789a287`.

## Findings and preserved before-state

The original direct `emulate` API checked opt-in and fixture size but accepted
arbitrary bytes and caller-supplied mappings before constructing Unicorn. Its
positive extra-vector and gas-boundary tests also checked output/gas without
checking completion. The original harness caught a stopped-run error and still
read the guest output pointer, allowing those predicates to pass after a failed
run with a malformed vtable/tag.

`originals/` preserves both exact reviewed source files. Running
`python3 -I -S -B research/work-items/RE-026-bn254-ecadd-auth-review-20261031/original_counterexample.py`
reproduces both failures with fake modules, without loading Unicorn or executing
captured bytes. `original-counterexample.json` is that unchanged negative record.

`prior-authorized-receipts/` preserves root's earlier eight-test acceptance log,
command/result record and authorization verbatim, scoped to the earlier commit.
Those successful bounded experiments remain evidence for that exact head; this
repair does not silently replace them with results from modified code.

## Corrected boundary

The emulator now authenticates the whole file against the baseline digest or
one of the two exact, already reviewed single-byte mutations listed in
`input-identities.json`. An additional byte change, combined mutation, malformed
ELF or foreign mapping/relocation list fails before backend import. The normal
CLI still requires the unchanged target hash. Only the two original aligned heap
placements and boolean stub modes are admitted. The original no-stub negative
experiment can reach the allocator's ENDBR64 entry, but the existing code guard
still excludes the allocator body.

Guest writes are confined to the synthetic stack, 40-byte output and the single
64-byte allocation. The host malloc hook validates the return slot before
reading it, and permits exactly one allocation from the native call site.
Completion plus the exact success vtable, allocation pointer, length, tagged
pointer, gas and allocation log are required before reading the output pointer.
A stopped run or malformed result retains raw header/diagnostic fields with
`returned=false` and no pointer-derived output. The original length mutation
still records `len=65`, but cannot become positive acceptance. Positive tests
now explicitly require completion and no fault.

`native-result-header.txt` independently decodes the success stores at
0x4e96c57..0x4e96cd9. The aligned allocator return selects GOT 0x576e140, whose
RELATIVE addend is vtable 0x5670ae8; the tagged pointer is the allocation OR 1,
the length is 64, and gas is reloaded from the saved incoming cost.
`native-error-header.txt` retains the error header stores and return. Error-path
trailing bytes can be uninitialized and remain raw observations rather than a
claimed initialized ABI. `native-header-evidence.json` binds these records to
the target and records the command and relocation values.

## Verification and remaining scope

`validation.json` and adjacent logs record normal/optimized host suites, actual
Python 3.10 coverage and the light repository gates. The eight authorized
captured-code test methods remain present and are deliberately skipped by this
reviewer. Root must rerun the same eight on the repaired frozen head before
accepting its behavioral result, then run the combined repository gate.

The committed original `bn254-ecadd.json` and static/full expected output hashes
remain unchanged. No imported evidence, shared guard, progress gate, node94
artifact, original review packet or earlier raw receipt is modified. Native
node operation, arbitrary fuzzing, unreviewed instruction mutations, short-input
memcpy, allocator/panic/unwind execution, source recovery and whole-binary
equivalence remain outside this bounded review.
