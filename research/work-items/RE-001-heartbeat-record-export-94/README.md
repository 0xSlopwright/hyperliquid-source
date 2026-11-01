# RE-001 / consensus: Which bytes does a selected heartbeat export record write, and which bytes remain unspecified?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/consensus/heartbeat_tracker.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x488c410..0x488c7d6.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

Owner 0x488c410 reads count at self+0x40 and computes a wrapping 48*count
span. The unsigned count comparison permits the direct allocation path at most
0x2aaaaaaaaaaaaaa; larger counts call the size-error target first. That helper's
nonreturn behavior is not proved here. The selected
iteration uses entry stride 0x68 and key stride 20. Entry+8 and entry+16 feed
raw qword/MOVSD stores; an opaque helper's returned XMM0 bits supply another
MOVSD store.

At output record offsets 0..19 the target writes the 20-byte key. Raw eight-byte
fields are stored at +24, +32 and +40. The four bytes at +20..+23 are not written
by the selected stores. The bounded replay uses the original destination
operands and preserves a synthetic initial record's padding rather than
inventing zero/canonical padding. Floating words, including NaN payloads, are
copied as bits; no duration interpretation or floating conversion is modeled.

The complete owner export includes the B-tree traversal and allocation/error
paths, but only the selected record stores are replayed. This is a memory-layout
observation, not a wire format, iterator-order guarantee or live statistics API.
The component also has a byte-bound source anchor: the exact 68-byte
node/src/consensus/heartbeat_tracker.rs compiler path at 0x6fda03, its LEA and
length, and raw stack header 0x9a00000001. No ABI type is assigned to that header.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/heartbeat_record_export.py --out research/work-items/RE-001-heartbeat-record-export-94/records.json
python research/work-items/RE-001-heartbeat-record-export-94/export_disassembly.py
python -m unittest discover -s tests -p test_heartbeat_record_export.py -v
```

Controls cover 20,480 key-byte/opaque-word comparisons, preserved padding canaries, raw signed-zero/NaN word bits, actual destination-offset changes, count/stride/key/helper/loop corruptions and synthetic RAM bounds. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Focused controls: 6 tests PASS in 2.441 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
628.841 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Failures in existing tests
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites; not every failure is diagnosed, and a separate unchanged-base
run on this new revision has not established that every failure predates this PR.
No imported inputs/pins/generated catalogue are changed by this PR; no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.

Iterator validity/order, duration-helper semantics, allocation contents, key identity, caller ownership and serialization remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close the clock/duration helper and consumers before assigning a public statistics schema.
