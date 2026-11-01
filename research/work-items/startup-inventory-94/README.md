# startup-inventory-94: exact startup.rs Location and literal census

- Task: RE-012 / RE-001; component: node-runtime. Bounded question: enumerate exact-path relocation-backed Locations, their decoded LEAs and enclosing FDEs, selected literal anchors and direct calls between scoped entries.
- Target: `artifacts/node/94/hl-node`, Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (provenance/artifacts.json). Addresses refer only to this digest.
- Base revision: `308e5127990217a9d6196992665da6ca1afd4b82`. Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`; reference file SHA-256 is in the inventory. The unlicensed inferred reference is a lead only; no code, comments, tests or types were copied.
- Files added: `tools/startup_inventory.py`, `tests/test_startup_inventory.py`, and this packet. No gate is requested.

## Reproduce

From repository root, Python 3.10+ stdlib (tested with Python 3.13.5, Linux x86-64):

```sh
python3 tools/startup_inventory.py --out research/work-items/startup-inventory-94/
python3 -m unittest tests.test_startup_inventory -v
python3 research/work-items/startup-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

Read-only mmap, no captured executable run, subprocess, network, objdump or native analysis provider is needed by the extractor or packet verifier. The digest is checked before parsing. The verifier uses an exact `MANIFEST` whitelist, checks file hashes, regenerates both JSON files byte-for-byte, pins target facts, and compares all derived report tables. The test suite exercises malformed and modified inputs. The compiler path embedded in the target is retained as original hex bytes, not analyst runtime state.

## Evidence and coordinates

[inventory.json](inventory.json) contains the complete exact-path census, Location and relocation bytes, link-time ELF VAs and file offsets, decoded LEAs and their context, FDE/CIE and unwind table records, literal occurrences and rejected candidates, rel32 transfers, seed checks, and overlap records. [instructions.json](instructions.json) contains a byte-level linear transcript for every scoped FDE. End addresses are exclusive; no ASLR or provider rebase is assumed. The Location path is selected by relative relocation to the exact embedded path and validated as a pointer, length, line and column; every matching relocation is counted separately. No deduplication by line is used.

Executable bytes are scanned for candidate RIP-relative LEAs; each accepted site must decode on a sequential instruction boundary from its actual FDE start, reference the exact slot, and have a completely decoded FDE with internal direct branches landing on decoded boundaries. Unknown encodings abort. This is not a reachability proof or exclusive source ownership. The seven catalogue address leads are checked as such rather than trusted as boundaries. The reference is structurally different: its line 39 is a constant declaration while the target has a Location at line 39, column 15. Its labels and layouts therefore cannot be substituted for the target's source lines. The reference's numeric constants remain unproven here.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 7 |
| counted_fragment_anchors | 0 |
| decoded_instructions | 7473 |
| diagnostics_absent | 0 |
| diagnostics_bound | 7 |
| diagnostics_probed | 8 |
| diagnostics_unresolved | 1 |
| indirect_calls_unresolved | 474 |
| indirect_jumps_unresolved | 16 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 302 |
| location_leas | 28 |
| locations | 23 |
| pointer_length_anchors | 7 |
| scoped_fde_bytes | 42439 |
| scoped_fdes | 7 |
| scoped_rel32_calls | 4 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 23 |
| unresolved_external_rel32_calls | 290 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

## Exact-path Location census

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x5692da0 | 271:17 | 0x2018a31 | 0x2017c80 |
| 0x569ea98 | 57:38 | 0x226c590 | 0x226c2d0 |
| 0x569eab0 | 57:64 | 0x226ff14 | 0x226c2d0 |
| 0x569eac8 | 57:22 | 0x226c632 | 0x226c2d0 |
| 0x569eae0 | 54:15 | 0x227033a, 0x227034c | 0x226c2d0 |
| 0x569eaf8 | 64:13 | 0x2270110 | 0x226c2d0 |
| 0x569eb10 | 73:17 | 0x226cb7a | 0x226c2d0 |
| 0x569eb28 | 73:43 | 0x22701ad | 0x226c2d0 |
| 0x569eb40 | 70:41 | 0x226cc31 | 0x226c2d0 |
| 0x569eb58 | 82:50 | 0x226cd67 | 0x226c2d0 |
| 0x569eb70 | 94:22 | 0x226d12c | 0x226c2d0 |
| 0x569eb88 | 162:33 | 0x22b5ec6 | 0x22b47c0 |
| 0x569eba0 | 190:71 | 0x22b5bdf | 0x22b47c0 |
| 0x569ebb8 | 148:29 | 0x22b5c4a, 0x22b5c57 | 0x22b47c0 |
| 0x569ebd0 | 192:56 | 0x22b5d01 | 0x22b47c0 |
| 0x569ebe8 | 211:29 | 0x22b5dcf, 0x22b5de1 | 0x22b47c0 |
| 0x569ec00 | 273:49 | 0x22b5da1 | 0x22b47c0 |
| 0x569ec18 | 39:15 | 0x2270303, 0x2270315 | 0x226c2d0 |
| 0x569ec30 | 282:15 | 0x227b6b0, 0x227b6bd | 0x227a0e0 |
| 0x569ec48 | 296:17 | 0x227bd12 | 0x227bcf0 |
| 0x5729e28 | 305:19 | 0x4546cd0 | 0x4546c60 |
| 0x5729e40 | 317:21 | 0x4546ff7 | 0x4546fd0 |
| 0x5729e58 | 325:19 | 0x45475de | 0x4546fd0 |
<!-- END GENERATED LOCATIONS -->

## Enclosing FDEs

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x2017c80 | 0x2018ded | 4461 | 0x10738d0 |
| 0x226c2d0 | 0x22713e1 | 20753 | 0x109a920 |
| 0x227a0e0 | 0x227bceb | 7179 | 0x109af84 |
| 0x227bcf0 | 0x227bd39 | 73 | 0x109afe4 |
| 0x22b47c0 | 0x22b649a | 7386 | 0x109d510 |
| 0x4546c60 | 0x4546fc2 | 866 | 0x12596c8 |
| 0x4546fd0 | 0x4547689 | 1721 | 0x1259714 |
<!-- END GENERATED FDES -->

These are unwind ranges, not a complete function inventory or matched-window denominator. Code without FDEs, split bodies, inlining and control-flow reachability remain open. Sequential decoding is intentionally limited to these ranges.

## Prior work and exclusions

The range starting `0x226c2d0` is also recorded by PR #1138, branch `node-rs-inventory-94`, commit `4647df111947397d3039cbb97df80a155c63cd62`, `research/work-items/node-inventory-94/inventory.json`; the range and code hash are checked and overlap is neutral, not ownership. The packet checks intersection with PR #170 and merged RE-009 / RE-012 records as recorded in the JSON. PR #430 and PRs #604/#582 are separate behavior work; this packet does not derive or dispute their claims. No behaviour for those or other files is asserted.

## Implementation and comparison

No Rust implementation, build, execution, comparator, normalized match, helper closure, vtable/data closure, full relocation comparison or whole-ELF comparison is provided. No normalization masks were used. The next useful question is whether independently established control-flow and dataflow can distinguish the shared range's source attribution and prove the role of a specific constant without importing reference semantics.
