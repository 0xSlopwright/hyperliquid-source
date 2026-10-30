# RE-013: Visor compiler/index inventory (first packet)

- Component ID: `visor`
- Target release and full SHA-256: captured `hl-visor`,
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`
  (provenance `artifacts/visor/captured/hl-visor`, size 8305392)
- Source commit / reference commit: this repository tip when the packet landed;
  no Hyperliquid source tree is claimed recovered
- Claim status: observation (ELF structure and unwind index only)
- Scope included: separate retained inventory JSON for the captured visor,
  `make index` / `tools/elf_index.py --release visor` support, and reproduce
  coverage for that inventory
- Scope excluded: download/verify/spawn control-flow mapping, Ghidra decompilation,
  function extents beyond adjacent-index upper bounds, crate ownership,
  reconstruction, and any execution of the captured binary

## Reproduce

```sh
# From a clone with LFS (or `python3 tools/artifacts.py` after nodes are present),
# with the visor bytes matching provenance:
python3 -I tools/legacy/inv.py \
  artifacts/visor/captured/hl-visor \
  work/reproduced/hl-visor.inventory.json
python3 tools/elf_index.py --release visor --output-dir work/index
```

Tooling: CPython 3, no Ghidra, no network once the artifact is local.
`inv.py` and `elf_index.py` only read bytes; they do not execute the visor.
Expected: `fde_count_eh_frame_hdr` / `unwind_entries` = 11028, matching
`research/imported/hl-visor.inventory.json` and `visor-unwind.json` here.
Binary SHA-256 must equal the provenance digest above.

## Evidence

- Retained inventory: `research/imported/hl-visor.inventory.json`
  (same schema as the node inventories; produced by `tools/legacy/inv.py`)
- Unwind summary: `visor-unwind.json` in this directory
- Coordinate system: ELF VAs from the file's own section headers (PIE image;
  Ghidra may rebase; do not mix bases without recording the load address)
- Entry VA `0x2bd180`, build id `b55c82cd4de234f23c768e5adff1e84e6adbc9a6`,
  rustc `1.95.0` / commit `59807616e1fa2540724bfbac14d7976d7e4a3860`,
  git stamp `c6b742f0456580eac0f90e9ecdd9a63a39f5540a` (2026-09-09, committed)
- First-party path strings observed: `base`, `global_constants`, `net_utils`,
  `node`, plus concatenated-string noise
  `threadthread_spawn_forevertokio_spawn_foreverdiscriminantbase` (same noise
  class already excluded for node #115 in the catalogue; not credited as a crate)
- Analysis was complete for `.eh_frame_hdr` encodings `0x1b/0x3/0x3b` only

## Implementation and comparison

Not yet implemented. This packet is tooling and retained inventory only.
No Rust reconstruction, no body comparator, no progress gate request.

## Results and limitations

| Metric | Value | Denominator / note |
| --- | ---: | --- |
| Unwind-index entries | 11028 | `.eh_frame_hdr` count; not a function census |
| Unique starts | 11028 | no duplicate starts in the index |
| Accepted raw/normalized bodies | 0 | comparator pending |
| Whole ELF reproduced | No | |

Next question (remainder of RE-013): map the static download, verify and spawn
control flow in the captured visor with address-bound evidence, still without
executing it.
