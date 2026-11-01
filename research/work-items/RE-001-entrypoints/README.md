# RE-001 follow-up: entrypoint membership and raw-E8 candidates

- Component: foundation, cross-component unwind inventory; RE-001 remains open.
- Node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Separate node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Original PR #373 head: `4190e47bcb7a4c6c019c31b27f857078276cb5d4`.
- Review base: `308e5127990217a9d6196992665da6ca1afd4b82`.
- Scope: linked ELF entrypoint addresses, relative-relocated init/fini array slots,
  and byte-level `E8` candidate targets classified against decoded FDE extents.
  Static only; no captured program execution, CFG recovery or equivalence claim.

The original `node-*-entrypoints.json` and `node-*-other-byte-gaps.tsv` files
remain byte-for-byte historical outputs. Their `direct_e8_call_targets` and
`gaps_reached_by_direct_calls` field names overstate what the scan establishes:
these are raw byte candidates, including bytes inside immediates or data.
The new `node-*-entrypoint-candidates.json` reports use explicit candidate names.
Every original census count reproduces unchanged; the new reports additionally
identify the init/fini slots whose targets are not FDE starts.

## Reproduce

```sh
python3 tools/entrypoint_candidates.py --release 94 --output-dir work/entrypoints-review
python3 tools/entrypoint_candidates.py --release 115 --output-dir work/entrypoints-review
python3 -m unittest discover -s tests -p test_entrypoint_candidates.py -v
make verify catalogue-check reproduce
```

`make fde-index` retains its existing behavior. The additive analysis lives in
`tools/entrypoint_candidates.py`; the shared `tools/fde_extents.py` and its tests
are unchanged from the review base so existing producer-source pins remain valid.
The CLI authenticates each input against `provenance/artifacts.json`, including
the exact snapshot consumed. Tables must have valid widths and complete file
ranges; dynamic tags stop at `DT_NULL`; array address/size tags must be paired.
Zero-length arrays stay empty. Duplicate tags or relocation destinations,
unsupported array-slot relocations, partial ranges and explicit size-limit
violations fail rather than silently producing a partial census. Limits are
4,096 array entries and 65,536 dynamic records. RELATIVE addends are linked VAs;
no runtime loader base is applied.

## Observed counts

| Observation | #94 | #115 |
| --- | ---: | ---: |
| `e_entry`, `.text`, FDE start | `0x1343c80`, yes | `0x1419300`, yes |
| `DT_INIT`, `.init`, not FDE start | `0x56600b0` | `0x63f0a00` |
| Init-array slots / relative-relocated / FDE starts | 168 / 168 / 167 | 168 / 168 / 167 |
| Init-array exception target | `0x1343d60` | `0x14193e0` |
| Fini-array sole target, not FDE start | `0x1343d20` | `0x14193a0` |
| Raw E8 candidates targeting FDE starts | 483,120 | 545,621 |
| Raw E8 candidates targeting FDE interiors | 7,671 | 11,460 |
| Raw E8 candidates targeting gap starts / interiors | 8 / 108 | 26 / 157 |
| Raw E8 candidates targeting executable sections without FDEs (`.plt`) | 106,111 | 112,107 |
| Raw E8 candidates targeting outside executable sections | 102,044 | 131,078 |
| Distinct gaps with candidate targets / aggregate bytes | 82 / 61,876 | 151 / 62,868 |
| Of those, other-byte gaps / aggregate bytes | 3 / 60,994 | 3 / 61,393 |

The byte scan includes every `E8` with four following bytes within a file-backed
executable section, even inside another instruction. Signed rel32 addition wraps
at 64 bits. Membership uses the union of overlapping FDE ranges. Gap byte totals
are the sizes of the whole gaps containing targets, not recovered code sizes.
`int3_only` and `other-byte` are byte classes, not padding/code classifications.

## Independent native evidence and corrected interpretation

GNU binutils 2.47.20260726 provides fresh static disassembly, ELF headers, dynamic
tags, relocations and unwind records. `reviewed-native-evidence.json` records exact
commands, input identities, export hashes and selection rules. Complete startup
windows, header/dynamic outputs and selected raw relocation/FDE lines are retained
here; full relocation/unwind outputs and their hashes are in the review workspace.
No normalized or regenerated output replaces the original PR reports.

For #94, the FDE is `[0x1343c80, 0x1343ca6)`; for #115 it is
`[0x1419300, 0x1419326)`. Each contains the complete 38-byte startup block,
including register/stack argument setup, the indirect call through the relocation
for `__libc_start_main@GLIBC_2.34`, and the following `HLT`. The original assertion
that this argument setup has no FDE was incorrect. The gap begins after `HLT`.

The following gap contains two `endbr64` instructions, at #94 `0x1343d20` and
`0x1343d60` (#115 `0x14193a0` and `0x14193e0`), not just one. The former matches
the fini-array target and includes a guarded `__cxa_finalize@plt` call; the latter
matches the init-array exception and jumps to an earlier stub. Conventional names
such as `__do_global_dtors_aux`, `frame_dummy`, `register_tm_clones` and
`deregister_tm_clones` are pattern-based inferences, not recovered symbol names.
The raw evidence supports these bounded instruction observations; it does not
establish a complete CRT reconstruction or behavior outside these windows.

The original descriptions of short gaps as alignment filler and large gaps as
assembly without CFI are not conclusions of this census. Their instruction/data
meaning remains unvalidated. Likewise, an interior E8 candidate is not evidence
of a tail call. Decoding candidate source/target windows is separate future work.

## Validation and limits

Both original-head producer runs reproduce all retained summary fields. The
reviewed standalone tool reproduces both target reports and original counts.
Controls cover `DT_NULL`, explicit zero sizes, missing/duplicate tags, table
widths/types/truncation, ambiguous mappings, oversized arrays, unsupported and
duplicate relocations, raw slots without relocations, immediate-embedded E8,
section-end boundaries, NOBITS exclusion, 64-bit wrapping and overlapping FDEs.
Target controls authenticate both full digests before comparing regenerated data.

FDEs describe unwind ranges, not validated function boundaries. Raw E8 candidates
establish neither decoded calls nor reachability. No component completion gate,
function denominator, source equivalence or full node build is claimed. All new
code and prose are independently written and MIT licensed.
