# RE-001 / abci: Which selected checkpoint rows survive the marker and three unsigned height bounds?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `l1/abci/engine.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x33084a0..0x33086f3.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

Owner 0x33084a0 constructs a /MARKED_FOR_DELETION suffix and calls
through the bound marker-predicate slot. A nonzero returned AL goes directly to
the keep route, irrespective of the height bounds. It is not an unmarked-row
bypass. This packet conditions on that helper result; no filesystem is queried.

For the other rows the raw height at row+0x18 requests a diagnostic when below
lower, then is retained iff lower <= height < upper and height <= cap. Thus
lower/cap are inclusive, upper is exclusive, and inverted/empty intervals keep
nothing on this route. The decoder executes actual unsigned CMP/Jcc operands;
the opaque diagnostic block is specialized to its observed normal successor.

The keep loop copies both 16-byte halves of a 32-byte row unchanged and advances
the output cursor by 32; input cursor likewise advances by 32. This establishes
selected copy/filter structure, not path deletion, allocation correctness or a
complete iterator ownership proof. Snapshot creation admission is a different
question and is not claimed here.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/checkpoint_retention.py --out research/work-items/RE-001-checkpoint-retention-94/records.json
python research/work-items/RE-001-checkpoint-retention-94/export_disassembly.py
python -m unittest discover -s tests -p test_checkpoint_retention.py -v
```

Controls cover 4,096 small/unsigned-edge bound combinations, distinct lower/upper/cap endpoints, actual upper-branch and cap-slot mutations, marker/copy/cursor/identity/domain corruptions. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Focused controls: 6 tests PASS in 2.347 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
721.882 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Failures in existing tests
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites; not every failure is diagnosed, and a separate unchanged-base
run on this new revision has not established that every failure predates this PR.
No imported inputs/pins/generated catalogue are changed by this PR; no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.

Marker/file helper effects, logger nonreturn paths, allocation, row validity, callers, filesystem deletion and complete ownership remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close the marker-predicate and caller bound provenance before recovering a checkpoint lifecycle.
