# Bounded crypto execution review

Node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

PRs #550, #669, #1035, #1041 and #1124 were reviewed at source head `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104`. After explicit authorization, the isolated Unicorn2.1.4 harnesses reproduced all18 retained synthetic vectors and passed all22 specified mutation, edge and determinism tests with zero skips. The imported target and reviewed source head remained unchanged. Exact commands, dependencies, source heads, dates and log hashes are in validation.json. Raw logs are retained byte-for-byte here.

The five packet REVIEW.md files bound the measured FDEs, instruction references, original evidence, execution ranges, guest write ranges, time and instruction limits. Every execution must reach the expected return sentinel. The RIPEMD census correction retains the original JSON and changes only its independently verified MOV-reference count from1 to2; no emulated output was masked or repinned. SHA-NI rejection checks the allowlist boundary before alternate-path execution.

These receipts supersede the earlier pending-execution status only for these five packets and the listed fixtures. They do not authorize or validate other precompile packets, wrapper execution, external state, chain actions, arbitrary inputs or whole-node equivalence. The standard test command remains static by default; captured tests require explicit opt-in.

The initial CPython3.14 environment failure is retained under ignored work; the successful runs use CPython3.10.18. Full combined repository checks are recorded separately by the integrating review. No milestone gate is advanced.
