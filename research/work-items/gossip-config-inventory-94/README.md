# gossip-config-inventory-94: exact-path Location and anchor evidence

Task: RE-012 / RE-001; component allocation: `node-runtime`. The bounded
question is which relocated panic Locations name exactly
`node/src/gossip_config.rs`, which instruction-boundary-checked RIP LEAs
reference them, and which literal constructions and direct calls can be
established in the containing FDE ranges. This is static evidence, not a
reconstructed gossip configuration implementation. No gate is requested.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Only this digest is accepted. Node #115 and visor have different identities.
The full embedded compiler-path bytes are retained as hexadecimal evidence;
the exact prefix is `PREFIX` in the producer, never an analyst home path.

Owned additions: [producer](../../../tools/gossip_config_inventory.py),
[tests](../../../tests/test_gossip_config_inventory.py), and this packet.
No existing tool, test, evidence packet, reference pin, progress or catalogue
file is changed. Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
The present `references/can1357-hl/node/gossip_config.rs` is inferred,
unlicensed research material. Its hash is recorded in the inventory; its
address and wording hints were checked against bytes. No reference code or
unverified reference prose is copied into this packet.

The Python decoder derives from the MIT tooling on local branch
`consensus-rpc-inventory-94` at `803c533618c3137cc31530c89bf3857b8617bc71`
(`tools/consensus_rpc_inventory.py`, PR #1032). Counted-byte pattern checking
derives from `nv-stream-inventory-94` at
`929b1b789e8b1bd40a8151d7628740310f9a011e`
(`tools/nv_stream_inventory.py`). These are files at the specified local
commits, not links to absent working-tree files. The inherited decoder is
extended only for the observed operand-size-prefixed compare forms. Neither
sibling's semantic claims transfer here.

## Reproduce

From the repository root, using Python 3.10+ standard library and the retained
artifact/reference inputs:

```sh
python3 tools/gossip_config_inventory.py --out research/work-items/gossip-config-inventory-94/
python3 -m unittest tests.test_gossip_config_inventory -v
python3 research/work-items/gossip-config-inventory-94/verify.py
python3 -O -B research/work-items/gossip-config-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

Observed environment: Python 3.13.5 on Linux x86-64. The producer, packet
verifier and focused tests use no objdump, readelf, external process or network.
The existing MIT `elf_index.py` and `fde_extents.py` parsers supply ELF sections
and actual FDE extents. Their source hashes are included in the inventory.
No REA connection was exposed, and `make doctor` reported no local Ghidra/Java;
no installation or registration was attempted. Native decompilation is not
part of this analysis. The captured executable is never launched.

`--out` writes only deterministic JSON after all analysis succeeds. It does
not update reports, pinned expectations or the manifest. The verifier checks
an exact `MANIFEST` whitelist including `RESULT.md` and itself, rejects
symlinks/foreign entries/missing files, checks each SHA-256, and requires
byte-identical regeneration. Its additional literal/layout/range/edge pins
and generated-report checks prevent stale counts from passing. The manifest
excludes its own hash. No code or operand normalization is performed.

## Observations and original coordinates

[inventory.json](inventory.json) retains locations, relocation entries,
instruction setups, raw CIE/FDE/index records, code hashes, finite diagnostic
probes, rejected candidates, transfers, seed checks and prior-work intersections.
[instructions.json](instructions.json) retains a complete linear byte transcript
of each scoped FDE. Addresses are ELF link-time VAs with explicit file offsets;
FDE ends are exclusive. No guessed ASLR or Ghidra rebase is used.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 3 |
| counted_fragment_anchors | 2 |
| decoded_instructions | 27776 |
| diagnostics_absent | 0 |
| diagnostics_bound | 3 |
| diagnostics_probed | 7 |
| diagnostics_unresolved | 4 |
| indirect_calls_unresolved | 1571 |
| indirect_jumps_unresolved | 95 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 1377 |
| location_leas | 59 |
| locations | 38 |
| pointer_length_anchors | 1 |
| scoped_fde_bytes | 163287 |
| scoped_fdes | 11 |
| scoped_rel32_calls | 7 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 16 |
| unresolved_external_rel32_calls | 850 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

### Complete relocated Location census

The scope rule compares the entire path and path length, not a filename suffix.
Each record preserves its own storage slot, even when line/column pairs repeat.
These are panic-Location layout observations, not proof that a panic is reachable.
“Owner” means the unwind range containing an accepted LEA; it never means
exclusive source-file ownership.

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x569e4f8 | 260:35 | 0x2261a27, 0x2261a39 | 0x22615b0 |
| 0x569e510 | 167:98 | 0x22619d7, 0x22619e4 | 0x22615b0 |
| 0x569e528 | 205:21 | 0x2266312 | 0x22615b0 |
| 0x569e540 | 133:98 | 0x227b785, 0x227b794 | 0x227a0e0 |
| 0x569e558 | 140:17 | 0x227b743 | 0x227a0e0 |
| 0x569e570 | 299:35 | 0x2261a62, 0x2261a8b | 0x22615b0 |
| 0x569e588 | 340:33 | 0x2261ab9, 0x2261ae7 | 0x22615b0 |
| 0x569e5a0 | 381:102 | 0x2267e48 | 0x22615b0 |
| 0x571ce38 | 260:35 | 0x4357079, 0x435708b | 0x4356c90 |
| 0x571ce50 | 167:98 | 0x435704d, 0x435705a | 0x4356c90 |
| 0x571ce68 | 205:21 | 0x435a458 | 0x4356c90 |
| 0x571ce80 | 146:98 | 0x439c07a, 0x439c0b4 | 0x439baf0 |
| 0x571ce98 | 161:17 | 0x439ca1b | 0x439baf0 |
| 0x571ceb0 | 299:35 | 0x43570af, 0x43570d3 | 0x4356c90 |
| 0x571cec8 | 340:33 | 0x43570f7, 0x435711b | 0x4356c90 |
| 0x571cee0 | 381:102 | 0x435be3a | 0x4356c90 |
| 0x572eba8 | 106:32 | 0x47413c6, 0x4741583 | 0x4741210 |
| 0x572ebc0 | 89:13 | 0x4742a0b | 0x4741dc0 |
| 0x572ebd8 | 90:13 | 0x4742a7c | 0x4741dc0 |
| 0x572ebf0 | 260:35 | 0x4759f53, 0x4759f6a | 0x4759970 |
| 0x572ec08 | 167:98 | 0x4759ece, 0x4759ee0 | 0x4759970 |
| 0x572ec20 | 205:21 | 0x475eca7 | 0x4759970 |
| 0x572ec38 | 146:98 | 0x4759e53, 0x4759e8e | 0x4759970 |
| 0x572ec50 | 161:17 | 0x475fdf7 | 0x4759970 |
| 0x572ec68 | 299:35 | 0x4759fbc, 0x4759fea | 0x4759970 |
| 0x572ec80 | 421:9 | 0x4743c38 | 0x4743490 |
| 0x572ec98 | 340:33 | 0x4744afa, 0x4744b07 | 0x4744160 |
| 0x572ecb0 | 381:102 | 0x474669d | 0x4744160 |
| 0x572ecc8 | 377:13 | 0x4746378 | 0x4744160 |
| 0x572ece0 | 470:21 | 0x4744002 | 0x4743490 |
| 0x57384a8 | 260:35 | 0x4b29c8f, 0x4b29ca1 | 0x4b29760 |
| 0x57384c0 | 167:98 | 0x4b29c27, 0x4b29c34 | 0x4b29760 |
| 0x57384d8 | 205:21 | 0x4b2d017 | 0x4b29760 |
| 0x57384f0 | 146:98 | 0x4b3ca92, 0x4b3cacd | 0x4b3c880 |
| 0x5738508 | 161:17 | 0x4b3d3e8 | 0x4b3c880 |
| 0x5738520 | 299:35 | 0x4b29cf9, 0x4b29d1d | 0x4b29760 |
| 0x5738538 | 340:33 | 0x4b29d79, 0x4b29d9d | 0x4b29760 |
| 0x5738550 | 381:102 | 0x4b2f00d | 0x4b29760 |
<!-- END GENERATED LOCATIONS -->

### Actual FDE ranges

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x22615b0 | 0x22689f0 | 29760 | 0x109a7b4 |
| 0x227a0e0 | 0x227bceb | 7179 | 0x109af84 |
| 0x4356c90 | 0x435cb15 | 24197 | 0x123494c |
| 0x439baf0 | 0x439ec8d | 12701 | 0x12384b0 |
| 0x4741210 | 0x4741694 | 1156 | 0x1287328 |
| 0x4741dc0 | 0x4742cb1 | 3825 | 0x12873d0 |
| 0x4743490 | 0x4744152 | 3266 | 0x12874c8 |
| 0x4744160 | 0x474822f | 16591 | 0x128751c |
| 0x4759970 | 0x47604b0 | 27456 | 0x1288140 |
| 0x4b29760 | 0x4b2fd98 | 26168 | 0x12c5e5c |
| 0x4b3c880 | 0x4b3f36c | 10988 | 0x12c6328 |
<!-- END GENERATED FDES -->

## Method and completeness limits

- Authenticate the entire artifact before interpreting its contents. Decode the
  ELF64 little-endian x86-64 image and require allocated, file-backed sections.
- Enumerate RELA records; every RELATIVE relocation into the exact path must
  decode as an aligned Location in `.data.rel.ro`. Preserve the zero
  pre-relocation pointer, path length, line/column, relocation type, addend and
  original entry bytes. No matching relocation is silently discarded.
- Parse actual CIE/FDE ranges and cross-check the unwind start table. Reject
  overlapping, duplicate, empty, unindexed or out-of-section ranges. The global
  unwind record population is not a matched-function coverage denominator.
- Scan executable sections for the specified `48/4c 8d` RIP-relative LEA forms.
  These are candidates until complete linear decoding from the actual FDE
  entry proves their boundaries and original operands. Require every Location
  to have a verified reference; an unsupported encoding stops generation.
- Consume prefixes, ModRM, SIB, displacement and immediate bytes explicitly.
  Do not resynchronize after an unknown instruction. Require exact FDE-end
  termination and instruction-aligned internal direct branches. This supplies
  instruction boundaries, not CFG reachability or semantic decoding of every
  opcode. Other addressing forms, split bodies and missing FDEs remain gaps.
- Bind the finite gossip-specific diagnostic list only through decoded LEAs
  in these ranges. Exact pointer/length proofs must preserve the pointer
  register and matching immediate through contiguous setup. Counted-fragment
  proofs walk a bounded sequence beginning at the LEA target, retaining each
  byte count, ASCII chunk and trailing marker. They do not infer a formatter
  grammar or argument roles. Generic helpers and neighboring component labels
  are deliberately excluded from the diagnostic candidate list.
- Decode E8/E9 signed rel32 operands. Credit a scoped edge only when the target
  is another independently anchored FDE entry. Preserve external calls and
  internal jumps separately; indirect transfers remain unresolved. No callee
  name is inferred from a reference comment.

## Implementation, comparisons and remaining work

No Rust implementation, Cargo/build scope, target execution, behavior test,
ABI reconstruction or binary-equivalence comparison is proposed. There is no
raw/normalized matched-body denominator. Helper closure, indirect/vtable/data
closure, non-Location relocation comparisons and whole-ELF identity remain
unmeasured. Numeric reference roles remain unresolved without a unique
instruction/dataflow binding. See [RESULT.md](RESULT.md) for negative results,
prior-work attribution, corruption controls, non-claims and the next question.
