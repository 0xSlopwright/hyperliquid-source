# Result: strong bounded static inventory, no recovered behavior

**Verdict: strong for the exact bounded inventory question.** The useful depth
is the complete relocated Location census, actual unwind extents, full scoped
instruction transcripts, an exact literal/length/Location setup, bounded
counted-byte anchors, direct call edges and retained negative results.
Literal and constant recovery remains limited; the packet does not reconstruct
`gossip_config.rs` or establish any runtime behavior.

All facts bind to `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Machine-readable evidence: [inventory.json](inventory.json) and
[instructions.json](instructions.json). Task: RE-012 / RE-001.

## Derived results

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

The distinct storage slots and references are enumerated in the generated
[README census](README.md). Repeated line/column pairs are retained. The
reported FDE byte span and decoded instruction count measure only the retained
unwind ranges, including shared/inlined code; they are not source coverage.

## Literal evidence and preserved negatives

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| override_gossip_config.json | present-but-unbound | 27 | 1 | 0 |
| assertion failed: !res.read().root_node_ips.is_empty() | bound | 54 | 1 | 1 |
| non-testing local chain | present-but-unbound | 23 | 1 | 0 |
| failed to load gossip config file at  | bound | 37 | 1 | 1 |
| using gossip config ( | bound | 21 | 1 | 1 |
| n_gossip_peers clipped to | present-but-unbound | 25 | 1 | 0 |
| GossipConfigInner | present-but-unbound | 17 | 4 | 0 |
<!-- END GENERATED LITERALS -->

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE start | LEA VA | Literal VA | Length | Proof |
| --- | --- | --- | --- | --- | --- |
| assertion failed: !res.read().root_node_ips.is_empty() | 0x4741dc0 | 0x4742a75 | 0x6fb494 | 54 | register_pointer_length_pair |
| failed to load gossip config file at  | 0x4741dc0 | 0x4741ff8 | 0x1fc492 | 41 | counted_ascii_chunks |
| using gossip config ( | 0x4741dc0 | 0x4742559 | 0x1f246a | 25 | counted_ascii_chunks |
<!-- END GENERATED ANCHORS -->

The root-IP assertion at `0x6fb494` has the direct LEA at `0x4742a75`, the
Location LEA at `0x4742a7c`, and the matching ESI length at `0x4742a83`, ending
in the indirect call at `0x4742a88`. The JSON retains every setup instruction,
the Location slot and the unresolved indirect pointer slot. This is unusually
local attribution: the literal and scoped Location participate in the same
contiguous setup. It does not establish that the assertion executes, which
branch reaches it, or what the indirect callee does.

The load-failure and using-config phrases are within counted ASCII chunks
addressed from `0x4741ff8` and `0x4742559`. Their whole chunk lengths differ
from the shorter probes. The evidence retains the initial marker, intervening
chunk, exact count bytes, probe offset, complete final chunk and its marker.
No adjacent descriptor is traversed after a zero terminator. These anchors
prove byte patterns at the LEA targets; they do not prove logging, formatting,
error handling, file access, chain selection or any placeholder semantics.

The non-testing-chain probe has a direct LEA at `0x4743ffb`, but the following
ESI immediate does not equal the probe length. The rejected setup is preserved.
The packet leaves it present-but-unbound instead of inventing a string
boundary through following nontext bytes. The override filename is present
but lacks an exact scoped LEA binding; proximity to a separately addressed
literal is rejected. `GossipConfigInner` appears in pooled data but receives
no scoped pointer/length attribution. None of these negatives proves missing
behavior. No absent probe is manufactured to increase negative-result counts.

The peer-clipping phrase is only a neutral presence/unbound observation.
PR #502's peer-cap behavior and PR #517's timed override snapshot behavior,
identified in the task, are outside this packet. No limit, timer, snapshot,
update policy or side-effect claim from those PRs is duplicated or contradicted.
Their remote contents were not fetched because this work is offline.

## Static direct calls

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x227a0e0 | 0x227a6d9 | e8d26efeff | -102702 | 0x22615b0 |
| 0x439baf0 | 0x439c15e | e8ad503a00 | 3821741 | 0x4741210 |
| 0x439baf0 | 0x439c4ac | e8dfa7fbff | -284705 | 0x4356c90 |
| 0x4759970 | 0x475bde9 | e82254feff | -109534 | 0x4741210 |
| 0x4759970 | 0x475dd93 | e8c863feff | -105528 | 0x4744160 |
| 0x4b3c880 | 0x4b3cb57 | e8b446c0ff | -4176204 | 0x4741210 |
| 0x4b3c880 | 0x4b3ce98 | e8c3c8feff | -79677 | 0x4b29760 |
<!-- END GENERATED EDGES -->

Each edge retains E8 bytes, signed displacement and next-instruction address:
`next_instruction + signed_displacement = callee`. Both endpoints reference
exact-path Locations and coincide with actual FDE entries. The call leads
from `0x4b3c880` into `0x4741210` and `0x4b29760` are confirmed as address-only
edges. The source labels and behavior descriptions attached to those leads
in the unlicensed reference are unvalidated. Every catalogue address lead
for this file is checked individually in `seed_checks`; executable-section
membership alone is never accepted as its boundary proof.

External rel32 transfers, internal jumps and unresolved indirect transfers
are partitioned in the JSON and metrics. No helper or external source label
is promoted into this graph. Static instructions do not establish reachable
calls, arguments, return values, scheduling or full call-graph closure.

## Constants

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| default runtime peer count | unresolved | none |
| default mainnet peer count | unresolved | none |
| root connection retry interval | unresolved | none |
<!-- END GENERATED CONSTANTS -->

The reference supplies configuration-role hints. No unique decoded
instruction/dataflow relation establishes these roles or their numeric values.
Literal lengths, shared-range immediates and helper arithmetic are insufficient.
The unresolved rows are explicit limits, not proposed parameter defaults.
Peer-cap and override-timing constants are outside this task's behavior scope.

## Prior work and reference checks

[RE-009 state-root evidence](../RE-009-storage-state-roots/state-roots.json)
already includes the ranges beginning at `0x22615b0`, `0x4356c90` and
`0x4b29760`, with gossip-config line co-locations.
[RE-009 hasher evidence](../RE-009-storage-state-roots/hashers.json) includes
caller ranges beginning at `0x439baf0`, `0x4759970` and `0x4b3c880`.
Their file hashes and precise range/caller intersections are recorded here.
No storage, hashing or helper semantics are rederived or imported.

[RE-012 InfoRequest evidence](../RE-012-info-request-path/info-request-path.json)
has an empty scoped-range intersection. The local PR #170 startup packet on
`contrib/hl-node-startup-inventory-94` at
`40ad27c14d2df8b439c774f40ef990f421330a1e` also has an empty FDE intersection.
Its `research/work-items/hl-node-startup-inventory-94/startup-inventory.json`
exists at that commit; its original file hash and range/hash snapshot are
retained in `prior_work`, rather than linking to a nonexistent local packet.
The empty intersections are negative overlap checks, not contradictions of
those packets. No startup, CLI or InfoRequest claims are repeated.

The reference file is available and its hash is pinned. Its address hints
survive the boundary/Location test, but this does not validate its function
names, schemas, inferred layouts, constants, comments or tests. Binary-derived
probe bytes are retained independently. The non-testing-chain length mismatch
and unbound filename/type/peer-clipping probes explicitly limit what those
leads establish.

## Validation and corruption controls

Passed locally: the generator command; focused unittests; packet verification
normally and under `python -O`; `make doctor`; `make verify`; `make test`;
`make catalogue-check`; and `make reproduce`. Artifact hashes, signatures,
imported evidence and reference pins verified without a public-key workaround.
The retained inventories and literal classifications reproduced. There are no
remaining validation failures. No hosted CI or container success is claimed.

The repository-wide suite includes pre-existing native-tool checks. Those are
separate from this packet's Python-only producer, verifier and tests. Final
report/link/count checks and the additional catalogue-seed consistency check
were also covered by the focused suite after the repository-wide run.

The focused suite exercises the artifact digest gate and also corrupts small
fixtures or private copy-on-write maps beneath that gate. Controls include
Location pointer/length/line/column corruption, changed legal line values,
missing/shifted/duplicate relocations, wrong machine, missing/non-executable/
NOBITS sections, FDE/index disagreement, malformed extents, shifted LEAs,
opcodes embedded in operands, invalid prefixes and groups, truncated and
overlong instructions, misaligned branch targets, changed rel32 operands,
wrong immediate lengths, nonadjacent fields, changed pointer registers,
register clobbers, interrupted call setups, corrupt count bytes/ASCII/markers,
zero terminators and bounded traversal. Unbound probes cannot become bindings
through substring matching or nearby pooled strings.

Manifest controls reject omissions, duplicates, extra files, traversal,
symlinks and tampering. Both reports' generated tables must exactly equal the
regenerated JSON-derived tables. The suite blocks external process/network
calls during generation and packet verification; regeneration compares exact
bytes. None of these controls substitutes for target behavior or proves the
restricted decoder is a complete general x86 disassembler.

## Explicit non-claims and next question

- No runtime behavior, protocol semantics beyond retained bytes, logging/file
  effects, source reconstruction, Rust build, ABI recovery or binary equivalence.
- No exclusive FDE ownership, recovered function names, complete function
  census, CFG reachability, source coverage denominator or progress gate.
- No claims for `gossip_rpc.rs`, `gossip_rpc_client.rs`, `node.rs`, `startup.rs`,
  `hl_node.rs`, `consensus/*`, slack_alert, spot_meta, spot_clearinghouse,
  evm_kvs, nv_stream, tokio, net_utils/networking internals or generic
  base/foundation helpers. Shared FDE bytes do not expand component scope.
- No indirect-callee, vtable/data or helper closure; only Location relocations
  are resolved here. Whole-ELF comparison remains unmeasured; masks are empty.
- No formatter grammar, recovered configuration schema, constant units, peer
  limits, retry intervals, chain selection or fallback addresses.
- No #115/visor parity, captured execution, network use, installation,
  GitHub comments/PRs, push, gate advancement or modification of existing
  evidence. All results remain local and static.

The next bounded question is the CFG predecessor and argument flow into the
root-IP assertion setup within `0x4741dc0`, including resolution of its indirect
call slot. That investigation must precede a behavior claim. It would not
require adopting the reference's loader name or expanding to another source
file's semantics.
