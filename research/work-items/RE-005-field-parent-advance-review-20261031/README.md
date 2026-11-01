# RE-005 advanced field-parent evidence review

PR #1030 exact head `38883e27597c1da7540d8ab0669290fb88aa66bc` adds only the 19 current546-rebind evidence files archived in originals. It leaves the previously reviewed source implementation and tests unchanged. Node94 SHA-256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

All 83 historical root-relative manifest entries still authenticate. Fresh native exports and 925 independently generated oracle rows reproduce the retained bytes. The two native-tool labels changed from GNU objdump 2.44 to 2.47.20260726; the unmodified raw new record and exact delta are retained. No other fields differ.

Actual Python 3.10 focused tests pass in normal and optimized modes (four each). The fresh independent Rust build uses the installed Rust 1.94.1 macOS arm64 compiler with the same source commit as the historical Linux provider. Only the in-memory compiler identity gate was changed for this supplemental run; production source pins are intact. Debug and optimized own-code builds each pass 12 independent tests, one fixture test, and 925 production rows. This is logical source validation on the current host, not reproduction of Linux binary hashes. Existing semantic mutation controls were unchanged and not rerun.

`make verify catalogue-check reproduce` passes. Captured code was never executed or emulated. This does not establish full-node recovery, historical compiler identity, ABI interchangeability, or whole-ELF equivalence.
