# RE-001: bind the node #94 24-byte growth helper 0x4f04bb0

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations plus the capacity and stride
  identities; the sibling label is inferred; no reconstruction, no gate
  request.
- Scope included: the 103-byte body `0x4f04bb0..0x4f04c17` (FDE `0xf636f0`),
  ten anchors, the direct allocator call and the error call against
  relocations, both identities, and the three-slot census.
- Scope excluded: the argument processor (`RE-001-init-entrypoints-94`), the
  capacity-growth helper (`RE-001-crossroads-callees-94`), the allocator variant
  `0x4f04fc0`, the 63 matching call-site encodings, #115, visor.

## Question

The argument processor's next stage calls a small growth helper: what does
`0x4f04bb0` compute?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/grow24_static.py --output work/g24-record.json
diff work/g24-record.json research/work-items/RE-001-grow24-94/observed/records.json
python3 -m unittest discover -s tests -p test_grow24_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact body and FDE,
ten anchors, both calls against relocations, the capacity and stride
identities, and the census. Disassembly text in `observed/` was rendered
with capstone 5.0.7 and labeled as such; byte records are authoritative.
Platform: Windows 10 22H2, Python 3.11.9.

## Observations

The body shares the capacity-selection shape of 0x454e5b0: it loads
the current capacity, doubles it, selects
`max(2 * current, 4)` through a `cmovae` (identity validated), passes the
alignment 8 in r8d and element stride `0x18` (24 bytes, three qwords) in r9d
to its own allocator variant `0x4f04fc0`, stores the new capacity and
pointer on success, and routes failures through the shared error entry
`0x1346068`. It is reachable through **three distinct GOT slots**
(`0x576ea38`, `0x57705a8`, `0x5776410`) from 63 sites, with zero direct or
`lea` references; the argument processor's call site `0x4edcfd3` is among
them.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (103 bytes) + FDE, 10 anchors, 2 relocation-checked calls, 2
  identities, 3 GOT slots; census denominator is the complete `.text` for
  `e8` / `ff 15` / `lea` encodings.
- 5 tests pass (record match, identities, three-slot census, sibling link,
  body mutation control). Author rerun, not independent peer review.
- Unknowns: the allocator variant's full internals and the semantics of callers
  at the 63 matching sites.
  The label stays inferred. No execution, Rust build, hosted CI, or gate.

Next question: the allocator variant `0x4f04fc0` and the two large
crossroads callees `0x143d010` / `0x4b31e70`.

## Independent review scope

The 2026-10-31 review re-authenticated the node #94 digest above and used
GNU objdump 2.47.20260726 for independent instruction decoding. FDE extents
are unwind-described ranges; they do not establish complete CFG ownership.
The whole-`.text` census covers the stated byte encodings, which can also
occur inside instructions; it is not a complete graph of callable targets
and does not exclude computed references or other instruction encodings.
Original retained disassembly and author validation logs remain unchanged.
See `REVIEW.md` for corrections made during independent review.
