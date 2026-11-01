# RE-001 / abci: What raw six-entry prefix and trailing record projection are prepared before the archive consumer?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `l1/abci/engine.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x37e2960..0x37e3a6b, 0x3bade80..0x3bae218.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

The complete caller at 0x37e2960 prepares an active prefix with metadata (1,0,6), six pointer/length pairs, and a separate trailing record span. The six pairs are tar, an opaque formatter result, -C, a tuple sourced at stack+0xf8/+0x100, -cf, and a tuple sourced at stack+0x90/+0xe8. Fixed pool strings and their lengths are read from the original instructions, not inferred command syntax.

A bounded MOV/LEA decoder interprets the actual constructor at 0x37e30e2..0x37e31bf with synthetic live-in registers and bounded synthetic stack RAM. It computes the trailing span end as base+24*count. It executes no formatter, allocator, helper or captured code.

The second complete owner, 0x3bade80, contains the prefix/tail lowering. This packet specializes its selected 16-byte row load at row+8 from each 24-byte record. The first qword is omitted; no Rust String ABI or ownership guarantee is assigned. The two-record loop and odd-tail load are available in the complete export. Full iterator execution and allocation are not modeled.

The pool also contains TAR_COMPLETE and compact exclusion-format bytes. Their presence and input references are observed, but formatting/quoting behavior is not reconstructed. Prepared pairs are not asserted to be effective shell argv. Existing #634 mechanically bounds the downstream 0x1455c00 consumer and its callers; this packet does not repeat that work or establish process execution.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/archive_argument_prefix.py --out research/work-items/RE-001-archive-prefix-94/records.json
python research/work-items/RE-001-archive-prefix-94/export_disassembly.py
python -m unittest discover -s tests -p test_archive_argument_prefix.py -v
```

Controls cover 54 pointer/length/count constructor classes, 65 trailing-record counts, actual stored-length/projection-offset mutations which change modeled results, literal/RELA/identity corruptions and bounded decoder rejection. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Before-change base run: 1997 tests in 709.765 seconds; FAILED (failures=23, errors=38, skipped=112). The before/after FAIL and ERROR header multisets are identical. New focused methods all pass in the full run. This establishes the observed Windows delta, not a clean Linux or native-equivalence result.

Focused controls: 6 tests PASS in 1.788 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
649.711 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Failures in existing tests
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites. Their causes are not all diagnosed; the unchanged-base run
above is preserved separately from this changed-tree run.
No imported inputs/pins/generated catalogue are changed by this PR; no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.

This is conditional static preparation only. Formatter rendering, generic iterator state, string consumer semantics, shell parsing/escaping, filesystem changes, archive contents, helper errors and typed ownership remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close the formatter and prefix/tail iterator state transitions before assigning effective command arguments.
