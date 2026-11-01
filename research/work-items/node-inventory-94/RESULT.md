# Result: strong bounded evidence; no reconstruction claim

The packet meets the bounded census question with relocation records, decoded
instruction boundaries, length-bearing literal anchors and scoped direct calls.
Its strength is the reproducible chain from target bytes to each observation,
including rejected candidates. It establishes neither node behavior nor recovered
source. No full-scope gate or progress update is requested.

## Regenerated counts

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

## Diagnostic and literal candidates

The finite probe list consists of labels and diagnostic fragments independently
observed in the authenticated binary after consulting reference hints. It is not
a census of all strings. `bound` requires a scoped decoded LEA plus a length
proof. `present-but-unbound` retains exact byte occurrences without an accepted
proof; it does not mean no possible reference exists. `absent` means no exact
whole-file byte occurrence, not absence of a feature. No synthetic negative
probe is included in this report.

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| node_fast | bound | 9 | 1 | 1 |
| node_disabler | bound | 13 | 2 | 3 |
| slow abci block | present-but-unbound | 15 | 1 | 0 |
| node slow abci_state driver | present-but-unbound | 27 | 1 | 0 |
| node_slow_abci_engine | bound | 21 | 1 | 1 |
| run_node_apply_abci_block | present-but-unbound | 25 | 1 | 0 |
| run_node_send_execution_state | present-but-unbound | 29 | 1 | 0 |
| replica_cmds | present-but-unbound | 12 | 2 | 0 |
| visor_abci_states | bound | 17 | 1 | 1 |
| @@ serializing abci state for greeting @@ | bound | 41 | 1 | 1 |
| @@ serialized abci state for greeting @@ | bound | 40 | 1 | 1 |
| visor lag increased | bound | 19 | 1 | 1 |
| Could not get home public ip | bound | 28 | 1 | 1 |
| connection_checks | present-but-unbound | 17 | 1 | 0 |
| error checking connection | present-but-unbound | 25 | 1 | 0 |
| node_startup_validator_config | bound | 29 | 1 | 1 |
| new_validator_get_wallet | bound | 24 | 1 | 1 |
| validator_gossip_priority | bound | 25 | 1 | 1 |
<!-- END GENERATED LITERALS -->

The register setup proof requires a matching immediate length, no integer
register clobber and a call within a short contiguous instruction sequence. It
also accepts one exact RIP-relative MOVSD load that cannot clobber those integer
registers. Register adjacency is a byte fact, not a recovered Rust ABI. The
adjacent-field proof requires storing the LEA destination and a qword immediate
length at the next field. Raw setup instructions are retained for both forms.
Counted chunk anchors instead traverse bounded u8-length ASCII chunks ending in
C0 from the LEA target. They retain the full chunk bytes and probe offsets; the
chunk length can exceed the selected substring length. They prove neither a
formatter grammar nor a rendered message or argument value.

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE start | LEA VA | Literal VA | Length | Proof |
| --- | --- | --- | --- | --- | --- |
| node_fast | 0x474bfa0 | 0x474bfcc | 0x6fb7d1 | 9 | register_pointer_length_pair |
| node_disabler | 0x43955c0 | 0x4395968 | 0x6f1128 | 13 | register_pointer_length_pair |
| node_disabler | 0x474b140 | 0x474b28c | 0x6fb78c | 13 | adjacent_pointer_length_fields |
| node_disabler | 0x47b1c60 | 0x47b1db1 | 0x6fb78c | 13 | register_pointer_length_pair |
| node_slow_abci_engine | 0x474a4f0 | 0x474a95b | 0x6fb6e5 | 21 | register_pointer_length_pair |
| visor_abci_states | 0x432e930 | 0x432e94e | 0x6f1135 | 17 | register_pointer_length_pair |
| @@ serializing abci state for greeting @@ | 0x4677fd0 | 0x4678ee9 | 0x1ec14b | 52 | counted_ascii_chunks |
| @@ serialized abci state for greeting @@ | 0x4677fd0 | 0x46791e1 | 0x1fb534 | 72 | counted_ascii_chunks |
| visor lag increased | 0x432e930 | 0x432ef8f | 0x1f131f | 44 | counted_ascii_chunks |
| Could not get home public ip | 0x474b140 | 0x474b794 | 0x6fb770 | 28 | register_pointer_length_pair |
| node_startup_validator_config | 0x226c2d0 | 0x226cc2a | 0x3d7d13 | 29 | register_pointer_length_pair |
| new_validator_get_wallet | 0x226c2d0 | 0x226cd60 | 0x3d7d30 | 24 | register_pointer_length_pair |
| validator_gossip_priority | 0x226c2d0 | 0x226d125 | 0x3d7d48 | 25 | register_pointer_length_pair |
<!-- END GENERATED ANCHORS -->

For example, the LEA at `0x474b28c` is followed by a pointer store and an immediate
length store into adjacent fields. The LEAs at `0x4395968` and `0x47b1db1` also
bind the same label through register-length setups that end at the scoped call
edges below. The home-IP diagnostic at `0x474b794` has its Location LEA in the
same setup. These are stronger than literal proximity alone.

The apply-block label at `0x474c663` is followed immediately by a call, with no
matching length after the LEA under this rule. The send-state label at
`0x474c74e` has an unsupported intervening load under the narrow setup rule.
Both remain unbound. Other reference labels have whole-file presence but no
accepted scoped setup. Rejected candidates, including nearby unrelated chunks,
are retained with reasons and following bytes. No log behavior is inferred.

## Direct call edges

Each accepted edge is an E8 signed displacement decoded from an instruction
boundary to an exact selected FDE entry: `target = site + 5 + signed_disp32`.
Both endpoints independently reference an exact-path Location. This table does
not assign function names or import another component's semantics.

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x2275a10 | 0x227691b | e8b059ffff | -42576 | 0x226c2d0 |
| 0x43955c0 | 0x4395978 | e883dd1800 | 1629571 | 0x4523700 |
| 0x47b1c60 | 0x47b1dc1 | e83a19d7ff | -2680518 | 0x4523700 |
<!-- END GENERATED EDGES -->

All other decoded E8/E9 transfers are retained in `rel32_transfers`, partitioned
into same-range instruction targets and destinations outside selected entries.
Indirect calls and jumps are counted separately and remain unresolved. Internal
jumps are not reported as unresolved external calls. This is not a full call
graph; reachability, callee closure, unwind-only paths and indirect targets remain
open questions.

## Constants

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| lag history capacity | unresolved | none |
| lag polling delay | unresolved | none |
| connection check delay | unresolved | none |
| validator alert threshold | unresolved | none |
<!-- END GENERATED CONSTANTS -->

These roles are search hints from the reference. No numeric value, units, field
identity or unique dataflow association is established. Literal lengths belong
to literal evidence, not to recovered node constants. Shared FDE membership or
an isolated immediate cannot establish a timeout, capacity or alert threshold.
The reference's inferred implementations and tests are not adopted.

## Corruption controls and verification

The dedicated unittest suite checks exact regeneration, pinned Locations,
FDE ends, call edges, literal setups, all instruction transcript hashes and the
report tables. It also exercises wrong digests, malformed ELF sections and FDEs,
missing/duplicate relocations, changed path/line/column/length values, shifted or
operand-embedded LEAs, changed call displacements, internal branches landing
inside operands, unsupported/prefixed/truncated encodings, pointer-register and
adjacent-field mismatches, wrong lengths, register clobbers and counted-chunk
length/content/marker corruption. Below-digest parser tests do not bypass the
production digest gate. Manifest controls reject extra, missing, duplicate,
traversal and symlink entries; documentation drift is a test failure.

Observed local validation outcomes:

| Check | Outcome |
| --- | --- |
| `make doctor` | Analysis ready; exact rebuild remains unavailable |
| Extractor command in README | Passed; committed JSON regenerates byte-identically |
| `python3 -m unittest tests.test_node_inventory -v` | Passed |
| Packet `verify.py` | Passed: whitelist, hashes, regeneration, pinned facts and report tables |
| `make verify test catalogue-check` | Passed; native macOS Java-resolver tests skipped on Linux |
| `make reproduce` | Passed; imported inventories and literal classifications reproduce |
| `git diff --cached --check` | Passed |

No validation failures remain. Hosted CI, containers, target execution and other
platform runs are not claimed. The new extractor, verifier and dedicated tests
use only the Python standard library; the broader pre-existing repository suite
also exercises its installed native tools.

## Explicit non-claims and next question

No runtime behavior, network/protocol semantics, private key or chain action,
source reconstruction, source-function names, Rust build, binary equivalence,
exclusive component ownership or coverage denominator follows from this packet.
Node #115 and visor are separate artifacts and are not analyzed here. No generic
helper, tokio, networking-internals or other source-file claim is made. The
prior-work intersections documented in README do not transfer their semantics.

The next bounded question is whether the currently unbound literal setups can
be established with explicit register dataflow across the preceding instruction
sequence. That requires a new reviewed evidence step; it cannot be answered by
relabeling literal presence or reference comments as a binding.
