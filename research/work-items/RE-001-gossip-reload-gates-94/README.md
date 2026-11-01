# RE-001 / node-runtime: Which raw metadata gate reaches gossip configuration replacement, and when are check/cache fields stored?

Bounded maintainer task-queue static research. Target node94
`artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`. Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `node/gossip_config.rs` supplied seeds
only. No reference implementation was copied; new code/docs are independently
authored under the repository MIT license. Captures retain upstream rights.

## Observations, inference and scope

Complete FDE-described ranges, ELF virtual addresses: 0x4741210..0x4741694.
The records contain full owner hashes and FDE/CIE identities. Full disassembly
exports are distinct from the bounded models; no normalization masks are used.

Owner 0x4741210 stores the last-check raw time before its file predicate
and metadata helper. A zero previous-first-dword case bypasses UCOMISD; otherwise JBE
skips refresh for less/equal/unordered helper-result comparisons. The helper's
time units and behavior remain opaque.

The selected metadata comparison at 0x4741320 uses a signed first dword,
unsigned second dword, and unsigned third dword, in that priority order. Only
strictly newer triples reach parsing; equal and older triples skip it. The
bounded decoder executes actual CMP/SETcc/TEST/Jcc operands on raw triples.
The raw fields are not assigned a calendar schema by this packet.

Parse result tag 2 takes the diagnostic/error-carrier path without cached-triple
stores. Other tags reach payload replacement, then cached-triple stores and
error-carrier clearing. These are byte-bound ordering observations conditional
on helpers returning, not an atomicity or concurrency guarantee. The packet
does not reopen startup/root selection or peer-cap questions in other PRs.

## Reproduce and controls

Python 3.12.14; stdlib ELF readers and bounded synthetic models. Capstone 5.0.6
x86-64 Intel generates complete exports; no captured executable, external
service, real runtime state, signing or private data is used.

```
python tools/gossip_reload_gates.py --out research/work-items/RE-001-gossip-reload-gates-94/records.json
python research/work-items/RE-001-gossip-reload-gates-94/export_disassembly.py
python -m unittest discover -s tests -p test_gossip_reload_gates.py -v
```

Controls cover 15,625 pairwise raw metadata triples from five signed/unsigned boundary values, actual signedness/strictness mutations, IEEE throttle classes and refresh/parse/cache-store corruptions. The packet is regenerated from the full
digest-bound capture. Actual instruction changes are rejected even when a
synthetic comparison otherwise looks plausible. Before this packet main had
unverified seeds, not this bounded comparator; afterward it has original owner
exports and explicit conditional evidence. This is not a source-equivalence
comparison, recovered Rust or a fixed live defect.

## Results and limitations

Focused controls: 6 tests PASS in 3.453 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
741.095 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Existing suite failures
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites; not every baseline failure is diagnosed. No imported
inputs/pins/generated catalogue were modified, no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.

Timing helpers, filesystem metadata meaning, parse grammar, allocation, helper panics and concurrent behavior remain unclosed. No Rust/native equivalence, full CFG recovery, complete component
or progress gate is claimed. Next: close the metadata and parser callees before recovering the complete reload API.
