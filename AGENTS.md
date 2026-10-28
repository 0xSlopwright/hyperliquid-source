# Agent instructions

## Read first and preserve scope

Read CONTRIBUTING.md, docs/SCOPE.md, docs/PROGRESS.md and docs/TASKS.md.
Node #94 is the initial Linux x86-64 baseline. #115 is a separate comparison
and later target. Visor has its own artifact identity. Use
provenance/artifacts.json for full SHA-256 values; bind every result to one.

This is an independent Rust reconstruction project. No full node build or
binary-equivalence claim exists yet. The can1357 tree is inferred, unlicensed
reference code: validate its labels, layouts, comments and tests against binary
evidence. Do not treat it as official source or copy it into MIT implementation.
Do not create a fake compiling workspace, invented dependency lock or stubs
and call that recovery. New Rust components need real, documented build scope.

## Workflow and ownership

1. Pick a task/component and bounded question. Inspect current work before
   overlapping it; note the task ID and intended files in the change.
2. Run `make doctor`, `make verify`, and inspect the relevant catalogue/seed
   records. Query focused addresses and xrefs before broad decompilation.
3. Keep observations, inferred names/types and unknowns separate. Comment seeds
   and executable-section membership do not establish function boundaries.
4. Save reusable evidence under research/work-items/<id>/ using the template.
   Put transient output and Ghidra projects under ignored work/.
5. Implement only established semantics; record assumptions explicitly. Test
   against target-grounded expectations with boundary and corruption controls.
6. Update progress only for a reviewed full-scope gate. Report partial results
   honestly and leave unfinished gates false.

Do not launch parallel agents by default. Delegate only when the user asks or
an applicable task instruction explicitly requires it. If delegated, assign
non-overlapping files/components, one target digest and a defined evidence
return format; a worker's status message is not validation.

## Evidence, data and tool rules

- Do not modify imported evidence or advance submodule commits implicitly.
  Preserve hashes, signatures, licenses and original negative results.
- `make index` parses unwind start tables only. It does not establish all
  functions, exact body sizes or component ownership. Use actual FDE/CFG/data
  analysis before publishing a matched-window denominator.
- Prefer installed native tools; `make doctor` reports their availability.
  Ghidra/IDA/REA are analysis providers, not evidence by themselves. Preserve
  options, tool versions, completeness, input digest and exported records.
- Keep raw comparison output. State normalization masks and track helper,
  call-target, relocation, vtable/data and whole-ELF gaps separately.
- Avoid whole-node rewrites from prose or artificial byte transplantation.
  Matching source text and passing self-derived tests are not target equivalence.
- Captured node/visor execution, private keys, chain actions, public networking
  and paid dataset sync require explicit authorization. Static parsing,
  disassembly and digest-specific Ghidra analysis are in scope.
- No secrets, personal runtime state or unsanitized user fixtures in commits.
  New code is MIT; upstream material keeps its own terms.

## Validation and reporting

Run `make verify test catalogue-check` for repository/tooling changes.
Run `make reproduce` when changing inventory/literal analysis or interpreting
those inputs. Regenerate with `make catalogue`; never hand-edit generated
PROGRESS.md, COMPONENTS.md or research/catalogue files. Check only relevant
builds/tests beyond these; do not claim hosted CI or container success without
its actual result.

Report changes, verification scope, failures and remaining gaps. A complete
task must satisfy its original acceptance criteria, not just pass a narrower
check. docs/PROGRESS.md is milestone completion; it is not proof of correctness,
function coverage or remaining engineering effort.
