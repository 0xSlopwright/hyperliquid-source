# RE-000: Research readiness baseline — 2026-10-28

Status: static preparation complete; **no component acceptance gate claimed**.
Targets and full digests are those in provenance/artifacts.json. Source pins
are in provenance/sources.json. Pump.fun table methodology was inspected at
lalalune/pumpfun-source commit dc8f791d32ae7fd6d9660cd1bf003fb02737f78f.

## Observations and reproduction

- `make verify`: eight captured files pass size/hash checks; node #94, #115 and
  visor detached signatures validate; #94 matches the can1357 binary/signature.
- `make catalogue-check`: 237 reference Rust files are partitioned into 24 work
  areas. Of these, 232 use first-party paths and five are bincode-fork files.
  #94 has 173 observed first-party source paths, 170 present in the reference;
  three absent and 62 additional first-party reference paths. #115 has 180
  allowlisted paths, 35 new and 28 absent relative to #94.
- The unrecognized #115 concatenated-string pseudo-crate is explicitly excluded,
  with original input retained. No source file has been silently discarded.
- `make index`: parses 121299 unique #94 unwind starts and 135313 unique #115
  starts, matching the retained inventory counts. Adjacent-index upper bounds
  are not decoded FDE function extents. Compact summaries are beside this file;
  regenerate the TSVs under work/index/ with the command.
- `make test`: 14 offline tests pass, including corrupted/truncated headers,
  unsupported encoding, invalid executable targets, missing progress evidence,
  invalid coverage denominators, and artifact tamper/download controls.
- `make reproduce`: retained inventory JSON and refined literal entries match.
- `make doctor`: local static-analysis prerequisites available. Ghidra 12.1.4,
  Java 21.0.10 and LLVM 22.1.4 are present; Rust 1.94.1 and 1.95.0 available.
- Ghidra's `support/analyzeHeadless` with no arguments starts and prints usage
  under Java 21. No target was imported or executed by this check.
- `python3 tools/ghidra_plan.py --release 94`: validates the input hash and prints
  a digest-specific static import plan, without creating an analysis project.

## Retained REA evidence

- #94: `../../rea/node-94-rust.json`, evidence
  `ev_6cb041066bae0a2bb8bb903ca81ebb27a14f0e611c1ddb6460adabc350ea234b`.
- #115: `../../rea/node-115-rust.json`, evidence
  `ev_c0bcad173a4c555f5fe723b1d00799c47acca68ed7453e9b36715f79cc0ec555`.

Both report no `.dep-v0` section; compiler path hashes are inferred. This does
not recover a dependency graph or prove the absence of dependencies. The full
provider limitations are retained in the records. Both were target-free reads,
so no native analysis session was opened or left running.

## Limits and next action

No original executable was run. No complete Ghidra database, FDE body map,
component ownership proof, Rust implementation, target execution harness,
matched-function comparator or exact Linux rebuild environment exists yet.
The Docker definition is still unbuilt. The progress gates stay at 0/4.

Start RE-001 with a small validated address/data/call slice, alongside RE-002
build provenance and RE-003 offline-harness design. See docs/TASKS.md.
