# Bounded build/tooling integration review

Task IDs: RE-001, RE-002 and RE-005. Intended files: the ten original PR file sets in REVIEW.json, active source manifests, action_dispatch_drift.py import compatibility, and this review packet. The independent Rust components have their own documented build scope; no workspace or dependency graph was invented.

Question: do the alias/kind5 components and selected unwind, dispatch, frame, fixture and bounds tools retain their measured contracts after integration?

## Observations

Both standalone Rust components built and passed debug/release tests offline with Rust/Cargo1.94.1. Target-grounded fixtures and17 compiling mutants were checked; each component produced identical raw release libraries in two clean builds. These are host library results, not captured-node runtime comparisons.

Fresh GNU2.47.20260726 and LLVM native decodes agree for the alias, compact-string unwind and visor unwind subjects. Their fact records reproduce unchanged. The harness positive fixture is independently hashed from all89 node94 bytes at VA144a010..144a069, file offset1449010, SHA-256e5786bcf006e4207862b5b8985c2a9ba7fd7488c171b9e86a5cc6a137b35ccdb.

Action-dispatch native audits cover59 node94 FDEs and68 node115 FDEs, including all published walks and instruction starts. The temporary importlib loading regression was repaired by adding the tools path before importing the shared helper; all87 tests and the isolated packet verifier then passed. No dispatch result was changed.

pyelftools0.32 reproduces the frame survey and complete TSV hash; GNU readelf independently agrees on all121299 records and CFA-register classes. Five corruption controls fail before producing accepted output. Native output versions are retained separately; no formatting difference is represented as a byte match.

The latest dynamic-symbol bounds fixes pass139 affected tests. Gossip-config inventory passes71 tests and normal/optimized packet verification. All27776 retained instructions in11 FDEs match fresh GNU decoding. Its only active inventory changes are two shared-producer source hashes and the prior hashers-packet hash; original inventory/manifest remain retained and all target facts are identical.

## Inference and unknowns

Original packet role/name inferences and helper exclusions remain explicit. LSDA metadata does not establish personality execution. Raw opcode scans do not become decoded call graphs. Frame survey records are unwind records, not a whole-node function-coverage denominator. No #94 result transfers implicitly to #115 or visor.

## Reproduction and results

Use the commands in each original packet, with GNU binutils on PATH and LLVM_OBJDUMP selecting an installed LLVM. Rust comparisons use locked offline builds. The frame survey requires pyelftools0.32. Detailed fresh output and initial failures remain under ignored work/pr-review-20261031; compact measured results and exact heads/digests are in REVIEW.json. Run make doctor verify test catalogue-check reproduce on the final integration tree. Full-suite publication is handled by the parent integration; this packet does not claim a new full-suite run by itself.

## Remaining gaps

No captured executable or captured instruction window was executed. No network, chain, runtime concurrency, full-node build, whole-ELF equivalence, or progress gate is established. PR1068 remains outside this accepted set while external archive verification is pending.
