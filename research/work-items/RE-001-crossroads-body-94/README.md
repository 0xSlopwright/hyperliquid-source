# RE-001: bind the node #94 crossroads body 0x44aa5a0

- Component: `foundation`; bounded static function validation under RE-001.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Claim status: byte/record observations; the crossroads label is inferred
  from the callee set; no reconstruction, no gate request.
- Scope included: the 4027-byte body `0x44aa5a0..0x44ab55b` (FDE
  `0x124c0b8`), all seventeen GOT-mediated call sites: thirteen RELATIVE targets
  and four imported sites with GLOB_DAT bindings, both panic Locations (std `sync/once.rs:219:20` under the rustc
  hash `e408947bfd200af42db322daf0fadfe7e26d3bd1` and chrono
  `naive/datetime/mod.rs:1631:38`), and the whole-`.text` census.
- Scope excluded: the four crossroads callees and their packets, the parent
  body `0x44adfa0..0x44b303a`, #115, visor.

## Question

The datediff callers packet bound the float-seconds wrapper's single call
site: which family calls it, and what else does that family touch?

## Reproduce

Python 3.10+ and the verified pinned Git LFS inputs from `scripts/setup.sh`.

```sh
python3 tools/crossroads_body_static.py --output work/crossroads-record.json
diff work/crossroads-record.json research/work-items/RE-001-crossroads-body-94/observed/records.json
python3 -m unittest discover -s tests -p test_crossroads_body_static.py -v
```

The tool authenticates size and SHA-256, then checks the exact 4027-byte body
and FDE, the seventeen call sites (opcode, GOT displacement, and
RELATIVE target or GLOB_DAT symbol), both Location structs (path bytes, line, column), and the census.
Disassembly text in `observed/` was rendered with capstone 5.0.7 and labeled
as such; byte records are authoritative. Platform: Windows 10 22H2,
Python 3.11.9.

## Observations

Thirteen RELATIVE-bound GOT calls span the series: the NaiveTime
addition `0x15206e0` (+0x253) and the NaiveDate day shift `0x151f870`
(+0x2b0) from the chrono-callees packet, the datediff float-seconds wrapper
`0x1450a60` (+0xc12), the std Once state machine `0x4ee3b20` (+0xeec), five
panic-callee sites (display panic twice, a third panic family twice, and a
sixth target once), and four further targets bound here only as relocation
facts. Two panic Locations anchor the body to the toolchain and chrono: std
`sync/once.rs:219:20` — the same Location family the read-lock helper packet
recorded — and chrono `naive/datetime/mod.rs:1631:38`, the
`NaiveDateTime + TimeDelta` overflow Location the ema window guard carries.

Four additional GOT sites call imported symbols: `memcmp` at
0x44aa731, 0x44aad11 and 0x44aae13, and `memcpy` at 0x44ab436.
These are dynamic-symbol declarations; runtime resolution is unobserved.

Census over the complete `.text`: exactly three direct `e8` call sites
(`0x44ae32a`, `0x44ae350`, `0x44b180c`), all inside the single parent FDE
`0x44adfa0..0x44b303a`, with zero GOT-mediated callers and zero `lea`
references.

## Implementation and comparison

Not implemented: no reconstructed Rust, no two-build comparison.

## Results and limitations

- 1 body (4027 bytes) + FDE, 17 GOT call sites with RELATIVE targets or GLOB_DAT symbols, 2 panic
  Locations; census denominator is the complete `.text` for `e8` / `ff 15` /
  `lea` encodings.
- 7 tests pass (record match, call-site targets, shared Locations, census
  with the single parent FDE, body size, body and call-site mutation
  controls). Author rerun, not independent peer review.
- Unknowns: what the family computes end to end and what the four
  non-series callees do. The label stays inferred. No execution, Rust build,
  hosted CI, or gate.

Next question: the parent body `0x44adfa0..0x44b303a` and the four
non-series callees (`0x14385c0`, `0x143d010`, `0x454e5b0`, `0x4b31e70`).

## Independent review scope

The 2026-10-31 review re-authenticated the node #94 digest above and used
GNU objdump 2.47.20260726 for independent instruction decoding. FDE extents
are unwind-described ranges; they do not establish complete CFG ownership.
The whole-`.text` census covers the stated byte encodings, which can also
occur inside instructions; it is not a complete graph of callable targets
and does not exclude computed references or other instruction encodings.
Original retained disassembly and author validation logs remain unchanged.
See `REVIEW.md` for corrections made during independent review.
