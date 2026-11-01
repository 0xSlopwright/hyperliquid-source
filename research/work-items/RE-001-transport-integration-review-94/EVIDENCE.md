# RE-001: preserve transport evidence while integrating current tooling

- Component IDs: transport, node-runtime, consensus (bounded original packets).
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Exact original source heads: `REVIEW.json`; inferred reference commit `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as leads.
- Claim status: observed instruction/record facts; original semantic names and helper limitations remain inference or unresolved.
- Scope: the 17 listed packets and their integration. No captured executable or network operation ran.

## Reproduce

From the repository root, use Python 3.10+ and materialized authenticated artifacts/references.
Run each original `tests/test_<tool>.py` and producer command documented in its README.
Run `python3 -m unittest discover -s tests -p test_transport_manifest_integration.py -v`.
Run `make doctor verify test catalogue-check reproduce` for the full integration.
Review used macOS arm64, CPython 3.14.6 and actual 3.10.18 compilation, GNU objdump 2.47.20260726.
The two fresh raw listings use `objdump -d -w -M intel --insn-width=16 --start-address=<start> --stop-address=<actual-FDE-end> artifacts/node/94/hl-node`.
Their file names give the starts; actual ends and record hashes are retained in `REVIEW.json` and `SHA256SUMS`.

## Evidence

Independent full-FDE decoding confirms 132 selected unwind ranges and 63,864 instruction rows. These are review denominators, not function coverage or equivalence.
All published excerpt instructions agree with full-range decode boundaries and bytes. The original socket excerpt begins with an orphan continuation byte at `0x2048b05`; it is not a new instruction. The complete owning FDE listing `native/20487f0.asm` preserves its context. Seven `cc` bytes after the `0x157b480` panic-helper FDE are padding and excluded from function extents. Original excerpts, records and manifests remain unchanged.

The LZ4 ratio path at `0x3d231e3..0x3d23229` converts each u64 counter independently using PUNPCKLDQ/SUBPD/ADDSD before DIVSD. Python integer true division rounded the rational directly and differed by one ULP for the retained counterexample. Both per-entry and total model ratios now convert each operand to float first. The new test pins the target constants, DIVSD bytes and both distinct result bit patterns. The original record output is unchanged. Nearest-even, masked floating-point operation is the comparison environment; other MXCSR modes are not modeled.

## Implementation and comparison

All 17 CLI producers now use the shared strict `manifest_item` lookup, rejecting missing and duplicate identities before artifact access. The target-grounded record calculations are unchanged. The consensus-config Python model explicitly represents Ip values as IPv4Address objects and LocalNode values as integers; it does not decode the packed target field.

Original models retain their stated valid enum, count, memory and helper assumptions. Time models use logical day/seconds/nanoseconds values rather than claiming a wire encoding for Chrono dates; generated path strings illustrate branch/field selection rather than a recovered date formatter. Pointer/call/literal observations do not establish all callees or runtime reachability.

Independent Rust, build equivalence, full helper/data/vtable/relocation closure and whole-ELF comparison are not yet implemented or measured here. No byte masks are applied to these raw listings.

## Results and limitations

The original 465 focused tests and all 17 byte-identical producer regenerations passed. The integrated rounding and strict-lookup controls are separate review additions; complete repository results belong to the final integration run. All original negative results and uncertainty statements remain available. No progress gate is requested.

Next question: follow one caller's actual argument/data flow through the currently unresolved TCP timeout or reporter helper, retaining the same artifact identity.
