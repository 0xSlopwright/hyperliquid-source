# RE-005 advanced field-parent evidence review

PR #1030 exact head `38883e27597c1da7540d8ab0669290fb88aa66bc` adds only the 19 current546-rebind evidence files archived in originals. It leaves the previously reviewed source implementation and tests unchanged. Node94 SHA-256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

All 83 historical root-relative manifest entries still authenticate. Fresh native exports and 925 independently generated oracle rows reproduce the retained bytes. The two native-tool labels changed from GNU objdump 2.44 to 2.47.20260726; the unmodified raw new record and exact delta are retained. No other fields differ.

Actual Python 3.10 focused tests pass in normal and optimized modes (four each). The fresh independent Rust build uses the installed Rust 1.94.1 macOS arm64 compiler with the same source commit as the historical Linux provider. Only the in-memory compiler identity gate was changed for this supplemental run; production source pins are intact. Debug and optimized own-code builds each pass 12 independent tests, one fixture test, and 925 production rows. This is logical source validation on the current host, not reproduction of Linux binary hashes. Existing semantic mutation controls were unchanged and not rerun.

`make verify catalogue-check reproduce` passes. Captured code was never executed or emulated. This does not establish full-node recovery, historical compiler identity, ABI interchangeability, or whole-ELF equivalence.

## Reproduce this review

From any checkout containing the exact advanced commit, select GNU objdump on PATH and run:

```sh
python3 -B research/work-items/RE-005-field-parent-advance-review-20261031/validate.py --repo . --out work/recheck-field-parent --tests
```

`--python` selects the focused-test interpreter. Optional `--rustc /path/to/rustc --rustc-sha256 SHA256` also rebuilds independently authored Rust with that explicitly pinned host compiler. It records the provider override without editing production pins. No staged files, reviewer directory layout, or hardcoded installed interpreter path is required. Output must be new.

The new review receipts are historical records with exact literal path substitutions: `[REVIEW_TREE]` is the isolated checkout, `[REVIEW_OUTPUT]` its ignored evidence directory, and `[REVIEW_HOME]` the reviewer's home. The raw SHA-256 and sanitized SHA-256 for each changed record are in `path-redactions.json`; raw records are retained in ignored work. These masks change path text only, never instruction bytes, native records, test rows, compiler hashes or original19 PR evidence. `host-build/comparison-main.rs.txt` is a sanitized historical generated input, not a portable build entrypoint. Use the validator to produce a fresh runnable input.

The reusable validator was rerun on a clean index after this correction: exact19 blobs,83 manifests,925 rows,native exports, and four focused tests in each Python3.10 mode pass. The unchanged Rust925-row build was not repeated solely for the path-record correction.
