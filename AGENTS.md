# Project working rules

This is an independent, evidence-led Hyperliquid reconstruction project.

- Read README.md, THIRD_PARTY_NOTICES.md and research/STATUS.md before changing scope.
- Original node and visor binaries are static evidence. Do not execute them as part of setup, CI, verification or analysis without explicit authorization for that execution.
- Keep imported evidence immutable. Write new output under work/; promote reviewed reports with the input hashes, command and limitations.
- Never label inferred source as official, compilable, semantically equivalent or byte-identical without evidence for that specific claim.
- Preserve submodule commit pins and upstream licenses. New project code is MIT; third-party material is not relicensed.
- Keep exact Rust/LLVM versions separate by release. Native macOS tools are analysis tools, not a matching Linux build environment.
- Run `make verify` and `make test` for tooling changes. `make reproduce` reruns the preserved static analysis.
