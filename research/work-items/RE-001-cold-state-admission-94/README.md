# RE-001 / node-runtime: Which raw digest and conditional result gates admit a fetched cold-state prefix?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/node.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x23ecd70..0x23ed020, 0x2209450..0x22095bd.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

The incoming 32-byte digest is compared with the fetched digest at caller
0x23ecd70 using two PCMPEQB vectors, PAND and PMOVMSKB. Both 16-byte halves
must agree. Mismatch reaches the cold-quorum diagnostic and UD2, not the normal
return. After agreement, a nonzero raw optional word +0x30 with zero +0x20
reaches a pre-helper assertion. Otherwise preparation reaches the outer helper;
its exact raw result 0x8000000000000040 gates returning the fetched first 56 bytes.
Other raw results take the unwrap path. Unused fields of an absent optional
value are not normalized to zero.

Only the actual 27-byte SIMD/mask/branch sequence is interpreted. Surrounding
input loads specialize four XMM registers; scalar route descriptions are
byte-bound conditional summaries. The second complete owner, 0x2209450,
provides caller/fetch context, not a recovered state/hash algorithm.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/cold_state_admission.py --out research/work-items/RE-001-cold-state-admission-94/records.json
python research/work-items/RE-001-cold-state-admission-94/export_disassembly.py
python -m unittest discover -s tests -p test_cold_state_admission.py -v
```

Controls cover 16,384 directed single-byte digest comparisons (32 positions x 256 values in both directions), equal zero/ff fixtures, actual SIMD source/compare/branch mutations, raw result boundaries and pre-helper gates. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Focused controls: 6 tests PASS in 3.414 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
637.824 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Existing suite failures
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites; not every baseline failure is diagnosed. No imported
inputs/pins/generated catalogue were modified, no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.

Fetched hash construction, state validity, clone/validation/logging helpers, cryptographic guarantees and typed reachable states remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close the fetch/hash and validation callees before interpreting this as a complete cold-state acceptance API.
