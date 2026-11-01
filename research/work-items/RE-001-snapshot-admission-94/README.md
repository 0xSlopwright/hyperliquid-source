# RE-001 / abci: snapshot admission across three lanes

Question: which raw lane state reaches a freeze snapshot, periodic snapshot,
housekeeping continuation, or past-freeze assertion? Three related copies belong
in one packet. This is static function-map research, not filesystem execution,
recovered Rust, a snapshot API or a completed component gate.

Node94 target `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`.
The unlicensed can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `l1/abci/engine.rs`,
supplied seed addresses only. No inferred implementation was copied.

## Observations and inference

Complete FDE-described owners, ELF virtual addresses, no normalization masks:
`0x220bed0..0x220c477`, `0x42e73d0..0x42e797d`,
`0x42e7980..0x42e7f2d`. Full body hashes, FDE/CIE bytes and complete
Capstone exports accompany selected-prefix replay, not a full CFG interpreter.

Height comes from `+0x28`. A raw u32 tag at `+0xb90`, `+0x1610`, `+0xb90`
respectively is compared with 1; the u64 target is eight bytes later.
For tag 1, target below height branches to the assertion path **before** testing
the periodic predicate. Equal target selects the six-byte `freeze` label even
at a periodic height. Other admitted states select eight-byte `periodic` or skip
to the continuation. Zero height is included by the periodic predicate.

The prefix multiplies the height by `0xd288ce703afb7e91` modulo 2^64,
rotates right by four, then compares unsigned below `0x68db8bac710cc`.
The multiplier is the inverse of 625 modulo 2^64; the strict bound is
floor(2^64/10000)+1. Divisibility by 10000 is the independently tested arithmetic
interpretation. The small decoder executes the original immediate values,
condition flags and relative branches on synthetic inputs. It stops at label,
continuation or assertion entry; it never runs a captured callee.

Observed labels and branch destinations are distinct from inference about the
typed lane state. There is no assertion that arbitrary raw tags/heights can
occur in a live node. Snapshot contents, helper return/error behavior, filesystem
effects, app-hash handoff, later housekeeping and release #115 remain unclosed.

Before this packet these seeds had no target-bound admission records in main.
After it there are three complete owner exports and a bounded input/control
comparator. Raw/normalized source equivalence is not measured. No progress gate
changes. Next: close each snapshot helper and its side effects before recovering
a complete checkpoint API.

## Reproduce

Python 3.12.14; stdlib static readers and bounded integer decoder. Optional
Capstone 5.0.6 x86-64 Intel for the full exports.

```
python tools/snapshot_admission.py --out research/work-items/RE-001-snapshot-admission-94/records.json
python research/work-items/RE-001-snapshot-admission-94/export_disassembly.py
python -m unittest discover -s tests -p test_snapshot_admission.py -v
```

Tests cover every height in 0..20000, four raw tag classes and all three lanes
(240,012 comparisons), exact/past/future freeze targets, unsigned 64-bit boundaries,
and real rotation/branch mutations which change the interpreted answer. Full
body bindings reject those mutations; label/identity/domain/decoder controls fail
closed. These are synthetic-state comparisons, not native execution.

Focused controls: 6 tests PASS in 5.906 seconds (controls.txt).
Required Makefile-equivalent Python checks ran because Make is unavailable.
Full suite on base 308e5127990217a9d6196992665da6ca1afd4b82 with these files: 2003 tests in
581.478 seconds; FAILED (failures=23, errors=38, skipped=112). This is NOT a full-suite pass.
Doctor, artifact verify, imports, catalogue-check and reproduce all exit 1.
Eight artifact digests/sizes match before missing GPG blocks signatures;
imports reject the Windows reference checkout, catalogue-check reports a stale
catalogue, and reproduce stops at artifact verification. Existing suite failures
include Windows path/newline and launcher/binutils expectations and missing
native prerequisites; not every baseline failure is diagnosed. No imported
inputs/pins/generated catalogue were modified, no signature/hosted-CI success
is claimed, and missing tools are not counted as passing controls.
