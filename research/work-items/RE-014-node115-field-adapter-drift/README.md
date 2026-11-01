# RE-014: node #115 preserves the field caller but changes its adapter extent

- Component: foundation; task RE-014 (release drift).
- Target: node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Initial project source base: `308e5127990217a9d6196992665da6ca1afd4b82`, tree
  `c39830a007755baa9c1c443134fc71ef2421cbe9`.
- Status: target-bound static observations and a source-artifact correspondence;
  original type/compiler/ABI identity and behavior transfer remain unresolved.

The source and tests were carried unchanged to current base
`546081f30a3ebe6af1dadb6f90869f01bd08e1e4` (tree
`09e856239802e8da97f03d5cf92a1106445aeb3a`). The used static section reader is
AST-identical; its only file change is CLI exception handling outside this
import path. Current-base reproduction is fresh. Completed 308-based runs
remain historical, as recorded in `VALIDATION-STATUS.json`; later exact-commit
repository checks are reported separately rather than restamped here.

The selected #115 field caller has a complete code/data correspondence with
one explicitly supplied official libcore object section. Its selected helper
has a different extent. This identifies a precise boundary for reusing the
#94 controller/622-byte adapter work in #1030: that work does not qualify the
#115 helper. No #94 implementation or unmerged RE-002 tool is imported here.

| Domain | Selected ELF VA range / bytes | Qualified result |
| --- | --- | --- |
| Field caller | `0x167d950..0x167dad6`, 390B | All 354 non-RELA code bytes equal; all nine actual 4B source relocation fields separately bound |
| Literal references | Six references, 14B counting repetition | Actual source bytes equal; repeated references are not extra code credit |
| Constant table | 48B at `0x64078f8` | All raw bytes equal; three actual pointer relocations retained separately |
| Linked adapter | `0x1686bd0..0x1686e46`, 630B | Eight-byte extent drift from the source section's 622B; zero compared bytes, no mask or behavior transfer |

These are separate domains, not a combined matched-byte or function-window
score. The table's first words and source symbol labels are observed metadata,
not recovered nominal types or an original private layout. Parent GOT and
selected table pointers agree on the 630B helper. The two other table callees
remain opaque; a static RELATIVE addend is not an observed runtime pointer.

## Inputs, rights and immutable admission

`PROVIDER.json` binds the official rustc 1.94.1 standard-library archive,
its exact libcore rlib and selected member. The provider rlib is 2,917,630B,
SHA-256 `ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`.
The member SHA-256 is
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.
The exact original `RUST-LICENSE-MIT`, `RUST-LICENSE-APACHE` and
`RUST-COPYRIGHT` files are retained from that authenticated distribution.
Root MIT terms cover the new project-authored tool and documentation; the
artifact excerpts retain their upstream rights. No inferred implementation
was copied into Rust or reconstructed source.

This is a compatibility artifact, not proof of the captured node's original
compiler, build flags, source tree, target or fork. It is an explicit local
input; the tool never installs or downloads it and never launches a compiler.
Production `analyze` authenticates both full immutable byte snapshots before
any ELF/member parsing or evidence export. Every used code, data, symbol,
relocation, selected FDE/CIE and pointer fact comes from those same snapshots.
There is no whole-image or whole-member evidence file.

The tool reuses current-main `elf_index.sections` and
`build_provenance.program_headers`, adding only bounded ar/member, typed
symbol/RELA and selected-index reads. Its two unwind lookups use binary
probes of `.eh_frame_hdr`, verify local index neighbors, exact FDE/CIE
records, file-backed executable sections and PT_LOAD mappings. It does not
claim a global function census or global anchor uniqueness. Source fields
are excluded only after their actual RELA kind, offset, addend and symbol
relationship are verified; no arbitrary normalization mask is introduced.

## Reproduce

From the repository root, with Python 3.10+ and the explicit pinned provider:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node115_field_adapter_drift.py \
  --libcore /path/to/libcore-e60dd2ab51fbc7de.rlib \
  --output /tmp/new-owned-node115-field-drift
HL_RE014_LIBCORE=/path/to/libcore-e60dd2ab51fbc7de.rlib \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_node115_field_adapter_drift.py -v
HL_RE014_LIBCORE=/path/to/libcore-e60dd2ab51fbc7de.rlib \
  PYTHONDONTWRITEBYTECODE=1 python3 -B -O -m unittest discover -s tests \
  -p test_node115_field_adapter_drift.py -v
```

Use a fresh output path. Existing outputs are refused before either input is
read. Failed identity/metadata validation exports no record. The canonical
`observed/records.json` contains original VAs, file offsets, raw selected
body/data hex, actual typed references and explicit comparison limits. The
final guarded CLI completed on base546 in 0.325s with source/helper/input
identities, HEAD/tree/status and all seven pins unchanged. Its exact receipt
and raw streams are retained. The a410 CLI remains under
`HISTORICAL-A410-*`, with no restamped result. No native
disassembler, compiler, captured executable or evaluator is invoked.

## Independent controls and preparation history

Independent expectations and byte-control plans froze before the producer
was read. On initial base308, the owned module passed ten actual tests normally and
ten under Python `-O`, with zero skips and unchanged source/helper/input
hashes. Current-base exact-commit module results are reported separately.
Provider-dependent tests require `HL_RE014_LIBCORE`; when absent they report
that missing evidence rather than downloading or fabricating a provider.

Controls use actual in-memory source/target bytes below full-identity
admission: all nine masked displacements, an unmasked code byte, source
RELA kinds/defined symbols/addends, six literal references, the fixed table
header, typed pointer records and selected FDE/CIE fields. No CPU or native
memory evaluator supplies expected results. The independent design-only
32-row stimulus file is preserved as a plan, not an executed-case count.

`derive` is explicitly an unqualified below-identity seam. A changed valid
opaque-callee addend or changed opaque adapter byte can legitimately return
a new pointer/hash observation, while comparison and behavior credit remain
zero. Those accepted opacity observations are not labeled rejections.
Production `analyze` rejects a changed whole input before reaching that seam.

History is preserved without restamping results:

- The initial intake used two immutable admissions because its preliminary
  object was released before typed-data follow-up. A manually transcribed
  address was corrected; all machine-generated ranges were already correct.
- The first prototype incorrectly imposed a 16B header word; actual source
  data has 24 there. The false nominal-layout assumption was removed in
  favor of the real 48B raw equality relation. Source table pointer +40 uses
  STT_SECTION, unlike +24/+32's STT_FUNC; its actual kind is now checked.
- Independent review reproduced an actual used-FDE bound error on the
  prototype: declared length 4 was accepted while header reads extended
  outside that record. The before proof and exact correction patch are kept.
  The current reader first bounds the complete supported 17B header and
  its in-record zero augmentation length. Real length 4/8/12 and
  length-13/continuation-byte controls reject for both selected records.
- A subsequent actual multi-field control moved both GOT displacements and
  their RELATIVE record to an unmapped address. The prototype had checked
  the mapped addend but not the used slot's own eight-byte footprint. The
  current reader maps and records each used slot before following its
  addend. The actual before acceptance, exact patch and regression are
  preserved; no nominal section or ABI condition was invented.

`HISTORICAL-RECORDS-923F.json` and its success receipt are expressly from the
pre-bound-fix prototype. The later `HISTORICAL-A410-*` outputs predate the
used-slot correction. Final `observed/records.json` and its reproduction
receipt are the fresh546 post-slot-guard run. The three correction patches replay
back to the exact historical source hashes without changing this producer.
No source build, original-byte
reconstruction, Rust implementation, full-suite or hosted-CI success is
implied. Current-base cleared checks are reported separately in the draft PR;
full `make test` remains pending explicit authorization. No gate is requested.

The next bounded question is to account for the 630B adapter's actual changed
control/data paths before deciding whether any #94 protocol can transfer.
This packet does not answer that question or infer behavior from its length.
