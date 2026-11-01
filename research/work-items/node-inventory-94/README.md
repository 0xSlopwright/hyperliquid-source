# node-inventory-94: exact node.rs Location and literal census

- Task: RE-012 / RE-001; component: node-runtime.
- Bounded question: which relocation-backed panic Location records name exactly
  `node/src/node.rs`, which decoded RIP-relative LEAs reference them, and which
  length-bearing literals and direct call edges occur in those unwind ranges?
- Target: `artifacts/node/94/hl-node`, Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base source revision: `308e5127990217a9d6196992665da6ca1afd4b82`.
- Reference revision (leads only): `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  The reference `node/node.rs` is present. Its file digest and address checks are
  recorded in [inventory.json](inventory.json). No unlicensed code, comments,
  inferred type layouts or tests are copied. Probe text is independently read
  from the authenticated target. The MIT decoder is adapted from the local
  gossip-config, consensus-rpc and nv-stream packets; exact revisions and paths
  at those revisions are retained in the JSON.
- Status: static observations; source roles and semantics remain unresolved.
  No Rust implementation or gate is proposed.
- Intended new files: `tools/node_inventory.py`, `tests/test_node_inventory.py`
  and this packet. No existing evidence, tools, tests or generated gates change.

## Reproduce

From the repository root, using Python 3.10+ standard library only:

```sh
python3 tools/node_inventory.py --out research/work-items/node-inventory-94/
python3 -m unittest tests.test_node_inventory -v
python3 research/work-items/node-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

The extraction and packet verification use no objdump, native analysis provider,
subprocess, target execution, network access or installation. Tested with Python
3.13.5 on Linux x86-64. Ghidra/Java and a connected REA provider were unavailable;
no decompilation is claimed. Input is memory-mapped read-only; mutation tests use
copy-on-write mappings. Production entry points authenticate the entire binary
before parsing. Outputs are deterministic ASCII JSON without analyst paths,
hostnames, timestamps or environment values. The target's embedded compiler
path is retained as original hexadecimal bytes, not local runtime state.

`MANIFEST.sha256` hashes the whitelist in [verify.py](verify.py), including the
verifier itself and both reports. The verifier checks the exact file set,
regenerates both JSON files, compares every byte, checks pinned target facts and
compares every generated table below against regenerated evidence. Producer
source digests include both existing ELF/FDE helpers and the new extractor.

## Evidence and coordinates

Addresses are ELF link-time virtual addresses, without ASLR or provider rebasing;
file offsets are recorded explicitly and are not assumed equal to addresses.
FDE ends are exclusive. [inventory.json](inventory.json) records Location bytes,
path bytes, RELA entry bytes and addends, LEA bytes and following context, raw
CIE/FDE and unwind-index records, code hashes, accepted and rejected literal
setups, direct transfers, and prior-packet intersections.
[instructions.json](instructions.json) is the complete byte-decoded transcript
for each scoped FDE. It contains offsets, raw bytes and restricted instruction
kinds, not decompiler output or guessed source names.

The census examines all relative dynamic relocations to the exact path. It
requires the file-backed, aligned Location layout (pointer relocation, path
length, line and column), with no deduplication by source line. A whole-executable
byte search proposes RIP-relative LEAs. Acceptance then requires sequential
decoding from the actual FDE start, exact operand decoding, complete coverage to
the FDE end and alignment of every internal direct branch. An unknown encoding,
missing section, malformed record or unmatched candidate aborts extraction.
No instruction resynchronization is attempted. Linear decoding does not prove
control-flow reachability or exclusive source-file ownership.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 4 |
| counted_fragment_anchors | 3 |
| decoded_instructions | 13336 |
| diagnostics_absent | 0 |
| diagnostics_bound | 11 |
| diagnostics_probed | 18 |
| diagnostics_unresolved | 7 |
| indirect_calls_unresolved | 753 |
| indirect_jumps_unresolved | 24 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 465 |
| location_leas | 40 |
| locations | 33 |
| pointer_length_anchors | 10 |
| scoped_fde_bytes | 74384 |
| scoped_fdes | 14 |
| scoped_rel32_calls | 3 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 30 |
| unresolved_external_rel32_calls | 456 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

## Exact-path Location census

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x5692ce0 | 756:102 | 0x1fd57b6, 0x1fd57c3 | 0x1fd4570 |
| 0x5692cf8 | 241:65 | 0x2043a3a, 0x2043a47 | 0x20432b0 |
| 0x5692d10 | 244:112 | 0x2043a07 | 0x20432b0 |
| 0x569e678 | 217:48 | 0x22786af | 0x2275a10 |
| 0x569e690 | 204:7 | 0x22789cf, 0x22789f0 | 0x2275a10 |
| 0x569e6a8 | 230:48 | 0x2278801 | 0x2275a10 |
| 0x569e6c0 | 241:65 | 0x22c0a6e, 0x22c0a80 | 0x22c05a0 |
| 0x569e6d8 | 244:112 | 0x22c0a52 | 0x22c05a0 |
| 0x569e6f0 | 254:13 | 0x226fedb | 0x226c2d0 |
| 0x569e708 | 249:83 | 0x22702e9, 0x22702f6 | 0x226c2d0 |
| 0x569e720 | 305:96 | 0x226efd3 | 0x226c2d0 |
| 0x569e738 | 304:52 | 0x226eff6 | 0x226c2d0 |
| 0x569e750 | 301:18 | 0x227027f | 0x226c2d0 |
| 0x569e768 | 94:45 | 0x227887c, 0x2278893 | 0x2275a10 |
| 0x569e780 | 99:109 | 0x227898d, 0x22789ae | 0x2275a10 |
| 0x569e798 | 129:13 | 0x2276e00 | 0x2275a10 |
| 0x569e7b0 | 130:18 | 0x227856e | 0x2275a10 |
| 0x569e7c8 | 160:47 | 0x2277024 | 0x2275a10 |
| 0x56a6d20 | 140:25 | 0x23ecf3e | 0x23ecd70 |
| 0x56a6d38 | 146:108 | 0x23ecfa8 | 0x23ecd70 |
| 0x571cfb8 | 794:46 | 0x43958c7 | 0x43955c0 |
| 0x571cfd0 | 738:25 | 0x432ef99 | 0x432e930 |
| 0x571cfe8 | 748:41 | 0x432efda | 0x432e930 |
| 0x571ff88 | 801:25 | 0x4523d7a | 0x4523700 |
| 0x571ffa0 | 820:37 | 0x4523d36 | 0x4523700 |
| 0x572ed48 | 572:37 | 0x474a6ca | 0x474a4f0 |
| 0x572ed70 | 617:49 | 0x46780d8 | 0x4677fd0 |
| 0x572eda0 | 622:21 | 0x4678191 | 0x4677fd0 |
| 0x572edb8 | 622:90 | 0x4679393 | 0x4677fd0 |
| 0x572edd0 | 792:37 | 0x474b79b | 0x474b140 |
| 0x572ede8 | 794:46 | 0x47b1cbc | 0x47b1c60 |
| 0x572ee00 | 362:25 | 0x474dc9d | 0x474bfa0 |
| 0x572ee18 | 433:45 | 0x474ca74 | 0x474bfa0 |
<!-- END GENERATED LOCATIONS -->

## Scoped unwind extents

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x1fd4570 | 0x1fd5b28 | 5560 | 0x106cab8 |
| 0x20432b0 | 0x2043ad7 | 2087 | 0x1077830 |
| 0x226c2d0 | 0x22713e1 | 20753 | 0x109a920 |
| 0x2275a10 | 0x227a0db | 18123 | 0x109af24 |
| 0x22c05a0 | 0x22c0b4c | 1452 | 0x109db88 |
| 0x23ecd70 | 0x23ed020 | 688 | 0x10ab374 |
| 0x432e930 | 0x432f30a | 2522 | 0x122eaf4 |
| 0x43955c0 | 0x4395bd9 | 1561 | 0x12380e0 |
| 0x4523700 | 0x4523df3 | 1779 | 0x125355c |
| 0x4677fd0 | 0x46798ac | 6364 | 0x127693c |
| 0x474a4f0 | 0x474abdd | 1773 | 0x12876cc |
| 0x474b140 | 0x474ba81 | 2369 | 0x1287828 |
| 0x474bfa0 | 0x474e1a1 | 8705 | 0x12878f4 |
| 0x47b1c60 | 0x47b1ee8 | 648 | 0x1291660 |
<!-- END GENERATED FDES -->

FDE selection is solely from verified Location references, never from reference
comment seeds. Seed checks are reported separately; all selected address leads
have actual FDE starts and scoped references. This validates those address facts,
not their proposed function names. The same range can contain inlined or foreign
code. The negative literal results in [RESULT.md](RESULT.md) are part of the
packet and must not be promoted from source hints.

## Implementation and comparison

Not implemented or measured: independent Rust, Cargo/build provenance, runtime
differential behavior, raw/normalized implementation comparison, helper closure,
argument ABI, indirect-call/vtable closure, complete relocation/data equivalence
and whole-ELF equivalence. No normalization masks are used. This inventory is not
a matched-function denominator, complete node function map or completion metric.

## Prior work and ownership

The scoped FDE at `0x2275a10` overlaps the local PR #170 startup/CLI packet
(revision and original packet hash in JSON) and merged
[RE-012](../RE-012-info-request-path/info-request-path.json). We report that
intersection without rederiving their behavior. The merged
[RE-009 state](../RE-009-storage-state-roots/state-roots.json) and
[RE-009 hasher](../RE-009-storage-state-roots/hashers.json) records have no selected
FDE intersections; their packet digests and checks are retained. The PR #170
snapshot is identified by its local Git revision and path at that revision,
not by a link to an absent working-tree file.

The user-supplied ownership constraints identify PR #828 as a closed semantic
binding of `0x20432b0`, and PRs #604/#582 and #430 as separate accept-loop and
AbciState-startup work. This packet makes no such semantic claims; that address
is only one census-selected unwind extent. PR status was not queried offline.
No claim is made for gossip_config, gossip_rpc, gossip_rpc_client, startup,
hl_node, local_abci_state, consensus, slack_alert, spot_meta, spot_clearinghouse,
evm_kvs, nv_stream, tokio, networking internals or generic foundation helpers.

## Integration rebind (2026-10-31)

The original packet and sources are preserved byte-for-byte under
`../RE-001-shaw-new-review-20261031/original-1138/`. Regeneration on the reviewed
integration tree changes only the two ELF/FDE helper source hashes and the
previous hasher-packet hash in `inventory.json`; every target observation,
instruction, range, diagnostic, edge and generated metric is unchanged.
`source_commit` retains the original submission baseline; the producer hash
map identifies the currently used files. Original negative results remain
available in the preserved submission and review logs.
