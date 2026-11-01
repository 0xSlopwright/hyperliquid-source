# RE-002: a fixed published-bitcode PadAdapter code-generation experiment

- Component: foundation / build provenance; node #94 only.
- Target SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Current base: `546081f30a3ebe6af1dadb6f90869f01bd08e1e4`.
- Preliminary experiment and `observed/old308-*` controls retain their original
  `308e5127990217a9d6196992665da6ca1afd4b82` labels and source identities.
- Status: bounded observed code generation, with all recovery gates unchanged.

The published Rust 1.94.1 libcore native object has two genuine byte differences
from the captured 622-byte PadAdapter span. This experiment asks whether one
fixed ThinLTO recipe, applied to that release's published LLVM bitcode through
an independently authored wrapper, reproduces the captured LEA encoding. The
default recipe is the control. This is not a libcore Rust-source build, nor
evidence identifying the original node's compiler, flags or source tree.

Only [pad_probe.rs](../../../src/libcore-pad-codegen/pad_probe.rs) is newly
authored Rust. It uses real supplied `fmt::Write` and `fmt::Debug` traits; no
writer/value implementation is invented. The library is never loaded or run.
Published native/MIR/LLVM dependencies remain distinct from the wrapper.

## Reproduce

The exact official Linux x86-64 rustc 1.94.1 plus standard-library provider must
already be installed at an explicit private prefix. `provider-pins.json` binds
all 103 original provider payloads and the fixed host tools, loader/runtime and
link inputs observed in the preliminary experiment. The tool neither downloads
nor installs anything and rejects a different provider. This deliberately
reproduces one measured host rather than claiming a portable build recipe.

```sh
python3 -B tools/libcore_pad_codegen.py build \
  --prefix /path/to/verified/rust-1.94.1-prefix \
  --node artifacts/node/94/hl-node \
  --output /tmp/new-exclusive-pad-probe
```

The output path must be new. The tool authenticates one immutable target bytes
snapshot, the exact published libcore archive/member, the wrapper and provider
before compilation. It freezes the command arrays, explicit minimal environment
and all producer/helper source hashes before either result. Both builds use one
CPU, the same options and `save-temps`; **only `-Clto=thin` differs** apart from
output paths. No arbitrary flags, retries, source patches or flag search exist.
The cgroup must have more than 1 GiB headroom; a breach or a 60-second wall-time
limit terminates the tool's own build process group. All generated objects and
raw traces stay in `/tmp`.

`freeze.json`, per-build raw stdout/stderr/trace, output hashes, every ELF and
every matching complete function symbol are retained locally. The trace records
the own compiler/linker `openat` and `execve` paths, not file contents or
environment values. The report retains observed link-input identities and
rejects an unexpected executed program. These are observations under a trusted
host assumption, not a sandbox or protection against concurrent malicious
provider/path mutation. No captured target bytes are compiler input.

Static inspection can be repeated without compilation:

```sh
python3 -B tools/libcore_pad_codegen.py inspect \
  --default-dir /tmp/new-exclusive-pad-probe/default \
  --thin-dir /tmp/new-exclusive-pad-probe/thin \
  --node artifacts/node/94/hl-node \
  --core /path/to/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib \
  --output /tmp/new-exclusive-static-report.json
```

Such caller-supplied-output inspection always reports build provenance
`UNQUALIFIED`: filenames, byte equality and a supplied report do not establish
ThinLTO origin. Only controlled build mode binds actual commands, inputs and
outputs, still subject to the stated host assumptions.

## Exact comparison and interpretation

The node target is fully SHA-bound. The main-tree FDE reader binds
`0x157d000..0x157d26e`; the source section contains all 622 bytes. The RIP-relative
four-space operand is independently resolved from those admitted target bytes.
Source-address reads require one file-backed `PT_LOAD` with the same file offset
and executable flag as the selected allocated section. The same checks apply
to the linked probe's literal mapping, independently of its raw body comparison.
The published archive is SHA-bound to
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256` and its
selected native member to
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.

All matching defined `PadAdapter` / `write_str` function symbols in every
generated ELF are recorded. Only aliases with identical section/value/size
are coalesced, retaining all symbol names. Smaller/larger bodies, additional
clones and absence are reported; no favorable candidate is selected silently.
Whole-file and complete-body hashes are different evidence: path-sensitive
object bytes do not imply changed function bytes or vice versa.

For a complete saved ET_REL candidate, the tool requires its **actual** one
`R_X86_64_PC32` record at body offset 558, width 4, addend -4, addressing a
bounded four-byte data `STT_OBJECT` containing `20 20 20 20`. Only those four
serialized field bytes may be excluded, leaving a denominator of 618. Other
bytes, including both LEA differences, remain ordinary comparison bytes.
Linked ELFs have no corresponding actual code RELA and receive raw comparisons
only. A linked displacement is never relabeled as an object relocation.

The original native-artifact comparison is kept as a separate report. Its two
unmasked bytes at offsets 464 and 467 stay differences. The different LEA
encodings `4d 8d 24 37` and `4e 8d 24 3e` exchange the base/index registers of
the same addition; no instruction-equivalence mask is used. The experiment can
explain an encoding route without proving original provenance or source recovery.

## Measured replay on the current base

The controlled replay completed both fixed recipes: default in 0.301 seconds
and ThinLTO in 3.818 seconds, with at least 1,526,956,032 bytes of observed cgroup
headroom. The complete [report](observed/production-report.json) retains every
output file hash and all three matching bodies across 25 generated ELFs.

| Artifact | Complete body | Raw differences from capture | Actual object-field comparison |
| --- | ---: | --- | --- |
| Published native libcore member | 622 B | 464, 467, 558–561 | 616 / 618; two gaps retained |
| Default linked library | 622 B | 464, 467, 558–561 | N/A: raw linked comparison |
| ThinLTO linked library | 622 B | 558–561 | N/A: raw linked comparison |
| Saved ThinLTO ET_REL object | 622 B | 558–561 | 618 / 618; actual PC32 field only |

The saved generated object's full-file SHA-256 is
`affd45f96d6b380c047729ddb0bc7893bcd481460e6714507434da315bcd9640`.
Its **622-byte body**, a different denominator and identity, has SHA-256
`ab7fc88e156c3ef084ae3db3f3de8bbbccfbcf711365c253d3bb4251e8196086`.
Both linked artifacts and that saved object have the same full-file hashes as
the preserved preliminary experiment. This is a repeat on the same pinned
provider/host, not a cross-machine or historical-build provenance claim.

The [freeze](observed/production-freeze.json) binds the exact source, five
producer/helper input files, 133 provider records, commands and minimal
environment. The [after audit](observed/production-after-audit.json) independently
rechecks all 20 prelaunch files, the target SHA and seven genuine pinned imports.
Both recipes' 65 observed system/prefix runtime and link inputs match prebuild
pins. The actual compiler stdout/stderr streams are empty and retained in
[COMPILER-RAW-LOGS.json](observed/COMPILER-RAW-LOGS.json); the full private native
traces are represented by their hashes and structured input/exec observations.
Only the expected compiler, affinity helper and linker programs were executed.

The portable suite passes 13 tests normally and with Python optimization on
the current base, with zero skips. These declared rebased ELF fixtures use real
622-byte excerpts but do not masquerade as complete original objects. Separately,
the preserved [genuine-object controls](observed/old308-actual-controls.json) apply
17 in-memory changes to actual saved object/linked metadata and caller data:
15 refusals and two retained unmasked mismatches, including both LEA bytes.
The historical source/base labels are preserved. No target, object, generated
library or captured-instruction evaluator is executed by either control suite.

## Rights and remaining gaps

New wrapper, producer, tests and documentation are project-authored MIT.
Published libcore excerpts retain the Rust project's MIT terms in
`third_party/LICENSE-MIT`; full compiler/rlib/objects are not vendored. Captured
node excerpts remain evidence owned by their original owners. No unlicensed
inferred source is used.

No original Rust ABI, private formatter/vtable layout, callback semantics,
whole-ELF match, runtime behavior, original compiler/fork or component recovery
gate is claimed. The wrapper's types are a deliberate new build stimulus.
The operator has authorized all 73 audited offline evaluator families. Full
`make test` remains unrun while the complete suite is arranged as separate
module processes to fit available RAM. The four cleared static targets and
owned non-executing controls are reported separately. Historical receipts retain
their original authorization-state labels. Captured native binaries and the
produced probe libraries remain unexecuted. CI is authorized for the audited
families, but deliberately skipped on this draft while full-suite qualification
is pending; no hosted success is claimed.

The next provenance question is whether independent historical source/compiler
evidence can identify the original build route; this two-recipe result alone
does not answer it.
