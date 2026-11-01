# Preparation and review changes

The initial bounded intake distinguished the 1,456-byte primary denominator,
76 actual code-field bytes, 1,380 remaining bytes and two genuine adapter gaps.
It did not establish a source build or original unique compiler identity.
The first real producer export is retained under `evidence/preparation/` with
its originally observed analysis-source hashes. It is an early export, not
the final source-qualified packet or a claim that its old tool revision is
the published current producer. It launched no compiler or captured code.

The following concrete review refinements were integrated before final freeze:

- A draft phrase calling the entire 48-byte layout a fixed header was corrected
  to 24 fixed bytes plus three actual eight-byte pointer-relocation fields.
- Relocation widths are derived from actual kinds; a type-1/width-8 source data
  field is not accepted as a selected type-2/9 four-byte code field.
- The 61-byte supporting span now requires and reports an exact unique target
  FDE, alongside file-backed section/PT_LOAD coordinates.
- The immutable-content guarantee is explicitly limited to the two admitted
  artifacts. Python source hashes are observational records, not atomic
  execution provenance.
- Both parent's official GOT symbols and the layout's offset-24 official
  symbol are now bound to the actual compared adapter symbol. Captured
  destination equality alone would not establish that source relation.
  The decimal's three source GOT symbols likewise bind its selected function.
- Production helpers expose the same data, exact-FDE and symbol checks used
  by the producer, allowing real below-admission corruption tests without
  copying a complete captured image.
- Before any test run, the test reviewer corrected a proposed 48-byte-layout
  mutation from pointer-field byte 47 to fixed-header byte 8. The original
  test draft is retained; no failed target or runtime result is implied.
- Raw data excerpts include ASCII-only spaces and the 200-byte digit table,
  with no trailing newline. Scoped attributes classify `.bin` and `.rela`
  evidence as bytes instead of rewriting them to satisfy text whitespace
  checks. Python/docs/JSON/license/native-listing text remains checked.

These were checker/prose refinements, not fixes to the captured target or a
claim that the official adapter's two raw differences disappeared. Old
receipts and raw exports were preserved instead of restamping them.
