# RE-003: integration review of PRs #1185–#1241

Task: review and merge the 57 new node reverse-engineering PRs captured in
`reviewed-heads.json`, from main `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`.
Scope: the exact recorded heads, their evidence and affected regression tests.
Later arrivals are outside this review. All changes are integrated without
rewriting contributor commits. No full-scope completion gate is advanced.

Targets (static inputs; captured executables were never launched):

- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115 comparison only: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Visor provenance remains `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

Artifact and reference pins, imported baseline evidence, generated catalogue
and progress gates are unchanged. Offline Python instruction evaluators and
the independently authored Rust clients were exercised.

## Review findings and repairs

The 26 parser changes add only a divisibility guard before 24-byte RELA
iteration. Their bounded research readers could otherwise accept an incomplete
relocation record or raise an incidental unpack error on malformed evidence.
The new corruption controls and existing target-backed tests exercise those
same readers. This is evidence-ingestion repair for the named active research
components, with no parser redesign or infrastructure expansion.

The URL-pin packet's constructor/`Arc::make_mut` census does not exclude
`Arc::get_mut` or unsafe writes. Its prose now states the observed absence of
enabling writes within the audited paths, leaving whole-program reachability
open. No executable implementation or observation was changed.

The startup packet originally failed two regeneration tests and one byte-output
comparison. Fresh CLI generation changes only the hashes of `elf_index.py`,
`fde_extents.py`, and a prior-work `hashers.json` record. No target fact,
metric, instruction byte or instruction partition differs. The regenerated
inventory and manifest are installed. `originals/` preserves the submitted
inventory and manifest; the original failing logs and exact three-field diff
are retained. The repaired 68-test module and packet verifier pass.
`static-checks.json` retains the first pass; `static-checks-final.json` records
the repaired result.

## Validation

`make doctor verify catalogue-check reproduce` passes with Python 3.13.2 and
installed native tools. `regression-validation.json` records 166 fresh affected modules with
2,494 reported tests, no unresolved failures and two artifact-dependent skips,
and their individual results and the separately retained baseline. This is incremental
coverage of the unittest discovery used by `make test`, not a newly executed
single full-suite `make test` invocation. The exact source selection and hashes
are retained; new Rust evidence dependencies were included explicitly.

All eight new evaluator packets regenerate: 90 generated files match the
submitted files byte for byte. All 28 incoming manifests validate (457 entries,
including the startup provenance refresh). Ten foundation collectors, four
handler producers and their independent verifiers, the AWS-name checker,
startup verifier and tokio-metrics record comparison pass.

GNU objdump 2.47 independently agrees with 48,618 instruction byte partitions
across 168 declared windows. Three bridge-nonce windows have explicit
unsupported tails; only their decoded prefixes are credited. The ten small
foundation windows also match native byte partitions. These observations do
not independently prove instruction semantics or all-input equivalence.

Rust 1.94.1 qualifications:

- Fixed point: 37 tests in each debug/release profile, formatting and Clippy
  with warnings denied; dependency-free Linux x86-64 release library build.
- Three-digit ASCII: 1,663 input-only vectors and unit corpus in debug/O3;
  Linux x86-64 objects compile. Safe slice behavior only, not the native ABI.
- Nonzero u128 division: 7,587 target-equation vectors plus 10,000 independently
  generated bigint-oracle pairs in each profile. Linux x86-64 O0/O3 objects
  and LLVM IR contain no division/remainder operation or division builtin.
  Original zero-divisor faults, clobbers and ABI remain outside scope.
- Character protocol: existing 3,023 byte cases and 320 character cases in
  debug/O3; seven actual compiled semantic mutants are rejected. Fresh local
  qualification uses the authenticated macOS build of the same Rust version,
  explicitly recorded as a provider override, not the original Linux compiler.

The complete 448-byte libcore body matches the authenticated official archive
and the available pinned ThinLTO object without normalization. Fresh native
checks use hash-pinned host GNU2.47. Two tests requiring the contributor's exact
linked ELFs remain skipped because those exact artifacts are unavailable here;
no fresh linked-artifact qualification is claimed. The original default run's
provider skip is replaced by the explicit host-provider run, leaving two skips.

## Remaining limits

No whole-node build, runtime networking, target execution, complete component
closure, or binary-equivalence claim is made. Shared helper behavior, dynamic
calls, ABI/layout details and other packet-specific gaps remain open. Hosted
CI was queued when reviewed; local checks do not establish hosted CI success.

## Reproduction records

The reviewed heads, source pins, test selection, fresh test results, generated
file comparisons, manifest checks, provider identities and Rust commands are
retained alongside this file. `<repo>`, `<ignored-work>`, `<review-output>` and
`<rustc-1.94.1-macos-bin>` and `<user-home>` replace machine-local roots in command logs. Original
PR evidence retains its own provider identities and limitations.
