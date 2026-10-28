# Imported research status — 2026-10-28

The supplied investigation identifies the can1357 reconstruction target as
node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
The project verifies the reference's binary and detached signature against the
stored #94 evidence. Captured executables are not run.

## Saved classification versus supplied narrative

| Class | Saved JSON | Supplied written summary |
| --- | ---: | ---: |
| Grounded in #94 and #115 | 822 | 822 |
| Drift: #94 only | 60 | 60 |
| Agent notes | 80 | 116 |
| Partial + case / near-miss | 57 (46 + 11) | 67 |
| Unanchored / no trace | 432 | 386 |
| #115 only | 1 | 1 |
| Total | 1452 | 1452 |

The verbatim #94 total is 882/1452 (60.7%) in both. The supplied narrative
reports manual-looking refinements not present in the saved artifact. Their
provenance is unresolved; retain both views and do not silently substitute one.
The script deduplicates by (crate, literal), not globally by literal.

The supplied narrative also reports 173 embedded first-party paths in #94,
170 present in the reconstruction, 62 extra split files, and a #94-to-#115 path
difference of 35 added / 28 absent. Treat those as imported claims until a
path-comparison report reproduces them; missing embedded paths need not mean
files were removed. String overlap and unwind counts are proxies, not logic
correctness or function-identity evidence.

## Consolidation

- Captured #94/#115 node binaries, visor, public key and signatures are preserved.
- Original scripts, inventory JSON, classification JSON, vendor listing,
  visor strings/disassembly and collected upstream documentation are preserved.
- The local can1357 source snapshot was byte-compared to pinned upstream
  commit 999556f6e0a474b8312db96ec3149e1c44e97c23. Its only materialization
  difference was the local LFS pointer versus the downloaded #94 binary.
- Temporary GPG state, OS metadata and incidental command-output files were not
  imported. No private signing keys or node credentials are needed.
- Official companion repositories are pinned in submodules, not treated as
  the unavailable original private node source.

Remaining work: recover and validate logic, establish manifests/dependency
versions/private forks and exact Linux toolchains, and develop a component-wise
verification harness. This initialization does not establish buildability,
runtime compatibility, security, or full binary equivalence.
