# Result: strong bounded static evidence, no behavior claim

This is a strong evidence packet for the bounded census and byte-level call edges, not a source reconstruction. Some literal anchors reside in a range shared with PR #1138; they establish co-location and length-bearing setups, not exclusive startup ownership or event behavior. No reviewed full-scope gate or progress update is requested.

## Regenerated counts

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

## Diagnostic and literal candidates

Candidates are selected from target bytes after reference-led searching; this finite list is not a string census. A binding requires a decoded scoped RIP LEA and an adjacent pointer/length store or a short contiguous, non-clobbering register setup with the matching immediate length and a call. A present-but-unbound hit has no such accepted proof; absence means only no exact whole-file byte occurrence. Candidate bytes, locations, instruction setups and rejected proposals are retained in [inventory.json](inventory.json). The test suite uses a synthetic absent probe as a negative control, not as a reported finding. Length and register facts do not establish Rust ABI parameter roles, rendered messages or effects.

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| firewall_ips | bound | 12 | 7 | 1 |
| failed to load firewall ips | bound | 27 | 1 | 1 |
| failed to load node config | bound | 26 | 1 | 1 |
| node_gossip_priority_config | bound | 27 | 2 | 1 |
| node_config.json | present-but-unbound | 16 | 1 | 0 |
| home_node_public_ip | bound | 19 | 1 | 1 |
| listen_get_home_node_ip | bound | 23 | 1 | 1 |
| initial_slow_state_for_join | bound | 27 | 1 | 1 |
<!-- END GENERATED LITERALS -->

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE start | LEA VA | Literal VA | Length | Proof |
| --- | --- | --- | --- | --- | --- |
| firewall_ips | 0x226c2d0 | 0x226c62b | 0x3d7ce6 | 12 | register_pointer_length_pair |
| failed to load firewall ips | 0x226c2d0 | 0x226ff06 | 0x3d7b71 | 27 | register_pointer_length_pair |
| failed to load node config | 0x226c2d0 | 0x227019f | 0x3d7c4d | 26 | register_pointer_length_pair |
| node_gossip_priority_config | 0x226c2d0 | 0x226efef | 0x3d7a51 | 27 | register_pointer_length_pair |
| home_node_public_ip | 0x226c2d0 | 0x226ee9e | 0x3d7aa0 | 19 | register_pointer_length_pair |
| listen_get_home_node_ip | 0x226c2d0 | 0x226e40e | 0x3d7e77 | 23 | register_pointer_length_pair |
| initial_slow_state_for_join | 0x22b47c0 | 0x22b5597 | 0x3d7d68 | 27 | adjacent_pointer_length_fields |
<!-- END GENERATED ANCHORS -->

## Direct edges

Each row decodes an E8 signed rel32 from an instruction boundary to another scoped FDE entry. They are static transfer facts, not observed executions or complete call graphs. Other direct and indirect transfers are retained or counted separately, and their destinations and semantic roles remain unresolved.

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x226c2d0 | 0x226c756 | e865800400 | 295013 | 0x22b47c0 |
| 0x226c2d0 | 0x226c860 | e87bd80000 | 55419 | 0x227a0e0 |
| 0x227a0e0 | 0x227b728 | e8c3050000 | 1475 | 0x227bcf0 |
| 0x22b47c0 | 0x22b51b4 | e8274ffcff | -241881 | 0x227a0e0 |
<!-- END GENERATED EDGES -->

## Constants

Reference leads are grouped by role. No value is promoted: a numeric immediate alone in a shared unwind range cannot uniquely establish a role or units.

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| default gossip peer count | unresolved | none |
| height lag threshold | unresolved | none |
| gossip RPC timeout | unresolved | none |
| height query timeout | unresolved | none |
| root retry delay | unresolved | none |
| client block request limit | unresolved | none |
| port values | unresolved | none |
<!-- END GENERATED CONSTANTS -->

## Explicit non-claims and limitations

No runtime behavior, networking, protocol semantics, source reconstruction, implementation, build, equivalence, whole-program function coverage or progress gate is claimed. No semantics are assigned to `node/src/node.rs`, `hl_node.rs`, gossip, consensus, ABCI, accept loops, tokio, networking internals, generic helpers or any other component. The path is a panic Location, not proof that the whole enclosing range belongs exclusively to that file. FDE decoding proves byte boundaries under this restricted decoder, not reachability, full CFG or function completeness. Literal setups do not prove that a log was emitted. Constants, all external callees, indirect calls, relocations outside the recorded Locations, data, vtables and whole-ELF comparison remain open. No claims extend to node #115 or visor.
