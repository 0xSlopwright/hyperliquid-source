# RE-005 — bincode-fork varint / integer-encoding boundary (node #94, encode side)

Status: **evidence packet, no gate claimed.** Encode side located. Decode side **INCONCLUSIVE** (see Limits).

## Reproduce

Target: `artifacts/node/94/hl-node`, release #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes).
Static and offline. The binary is never executed.

```sh
make verify                                                     # artifact digests
python3 -I -B tools/bincode_varint.py > /tmp/varint-sites.json  # recompute
sha256sum /tmp/varint-sites.json                                # 48636be33d50d4c9f7f164bb7ef4ebbd2766b6af0d52cd1633b1c8a2bd9b86ea
python3 -I -B research/work-items/RE-005-bincode-varint/verify.py
python3 -O -B research/work-items/RE-005-bincode-varint/verify.py
python3 -m unittest tests.test_bincode_varint -v
```

The output is identical under any `PYTHONHASHSEED` (tested with seeds 0, 1 and 4242).

Files:

| file | sha256 |
|---|---|
| `varint-sites.json` | `48636be33d50d4c9f7f164bb7ef4ebbd2766b6af0d52cd1633b1c8a2bd9b86ea` |
| `objdump-excerpts.txt` | `d4ac4801d3dedb823964a2ffcbb50b1034ea4a33411b19a1817f4da2271329de` |

The objdump excerpts were made with GNU objdump 2.44 (Debian), using `objdump -d -M intel` over the seven FDE ranges. They are for human reading only. The tool and tests never parse them, so a different binutils version may change their text but not the evidence.

## Evidence (observations)

Coordinates are virtual addresses. Inside `.text` (va `0x1343c80`, offset `0x1342c80`), file offset = va − 0x1000.

Function bounds come from this binary's own `.eh_frame_hdr`/`.eh_frame` FDEs (121,299 FDEs). The tests cross-check them against `readelf --debug-dump=frames`.

| function (our label) | FDE | `e8` call hits | key anchors |
|---|---|---|---|
| `varint_encode_u32_vec` | `0x27ab0a0..0x27ab27c` | 3 | `cmp ecx,0xfb` @`0x27ab0aa`; `cmp ecx,0x10000` @`0x27ab0cf`; store `0xfb` @`0x27ab0e8`; `rol cx,8` @`0x27ab0f8`; store `0xfc` @`0x27ab128`; `bswap ecx` @`0x27ab138`; Ok=8 @`0x27ab156` |
| `varint_size_u32` | `0x27ab280..0x27ab2f5` | 2 | +1/+3/+5 @`0x27ab292`/`0x27ab2af`/`0x27ab2cd`; Ok=8 @`0x27ab2dc`; panic `lea` @`0x27ab2e8` |
| `varint_encode_u64_vec` | `0x27ab300..0x27ab5a8` | 25 | `cmp rcx,0xfb` @`0x27ab30b`; store `0xfb` @`0x27ab34b`; `shr rdi,32` @`0x27ab380`; store `0xfc` @`0x27ab397`; store `0xfd` @`0x27ab3d4`; `bswap rcx` @`0x27ab3e4`; Ok=8 @`0x27ab403` |
| `varint_size_u64` | `0x27ab5b0..0x27ab64b` | 25 | +1/+3/+5/+9 @`0x27ab5c3`/`0x27ab5e1`/`0x27ab605`/`0x27ab623`; panic `lea` @`0x27ab63e` |
| `varint_encode_u32_le_ptr` | `0x4aa9ae0..0x4aa9c86` | 75 | value read from `[rsi]` @`0x4aa9ae8`; store `0xfb` @`0x4aa9b29`; store `0xfc` @`0x4aa9b60`; plain LE u16/u32 stores @`0x4aa9b41`/`0x4aa9b78` (no swap arm) |
| `varint_encode_u64_vec_b` | `0x4aa9f80..0x4aaa228` | 86 | same arms as `0x27ab300`; store `0xfd` @`0x4aaa054`; `bswap rcx` @`0x4aaa064` |
| `varint_size_u64_b` | `0x4aaa230..0x4aaa2cb` | 87 | +3/+5/+9 @`0x4aaa261`/`0x4aaa285`/`0x4aaa2a3`; panic `lea` @`0x4aaa2be` |

The tool checks every anchor's exact bytes; the full list is in `varint-sites.json`.

- **Panic Locations.** The `lea` instructions at `0x27ab2e8` and `0x27ab63e` both point to Location `0x56c2e78`. The `lea` at `0x4aaa2be` points to `0x5737ce8`. Through the `R_X86_64_RELATIVE` relocations, all three resolve to `/home/ubuntu/hl/bincode-fork/src/enc/write.rs:78:9`. The path string is at `0x1e533e`, length 45.
- **Closure of the idiom scan.** The scan searches all of `.text` for three patterns:
  - `cmp r32,0xfb` followed by `cmp 0x10000`: 7 sites;
  - the `r64` form of the same: 4 sites;
  - `mov byte [..],0xfd`: 2 sites.

  All 13 sites fall inside the 7 FDEs listed above. The tool rejects any site outside them.
- **Thresholds and markers.** The observed values are `<251`, `0xfb`+u16, `0xfc`+u32 (selected when the high half is zero), and `0xfd`+u64. No `0xfe` (u128) arm was seen in these functions.
- **Every count is pinned exactly.** That covers the FDE count, the call hits per function, the idiom sites and the Location tuples. No `>=` comparisons are used.

## Inferences (not observations)

- The arms match the bincode 2 `varint` encoding rules. On that basis these seven functions are taken to be the fork's `varint_encode_u32` / `varint_encode_u64` writer paths and their `SizeWriter` counterparts (the size functions only count bytes and never store them).
- The `dl`/byte-swap arm in the `*_vec` encoders looks like a big-endian configuration flag compiled into one shared body. `varint_encode_u32_le_ptr` looks like a little-endian-only monomorphization. Neither inference has been checked against source.
- The function names are our labels. The binary has no symbols for them.

## Implementation and comparison

- `tools/bincode_varint.py` is pure stdlib. It checks the input SHA-256, then parses the section headers, FDEs and `.rela.dyn` RELATIVE entries. It checks the anchor bytes and counts `e8 rel32` byte-pattern hits on each function start. Output is canonical JSON with sorted keys. Any mismatch raises `EvidenceError` and exits 1.
- **Dependency on RE-001** (PRs #2 and #5, function-boundary / unwind inventory). These addresses do **not** rely on RE-001 output. Bounds are taken directly from #94's own FDEs, checked against its SHA, and cross-checked with readelf. If RE-001 lands, its boundaries should contain these seven ranges exactly. That comparison is not part of this packet.
- **PR #8** (bridge encoder at `0x3c9a570` / `0x58f650`) is a different layer. A test asserts that none of these FDEs contains either address, and this packet makes no claim about bridge encoding.

## Negative controls (`tests/test_bincode_varint.py`)

The following inputs are rejected:

- a corrupted last byte (digest);
- node #115;
- the binary truncated by half;
- the `0xfb` marker swapped to `0xfc` at `0x27ab34b`;
- the threshold `0xfb` changed to `0xfc` at `0x27ab0aa`;
- an FDE end off by 4;
- a call count off by 1;
- dropping the second family of functions, which leaves idiom sites outside every pinned function.

An identity "mutation" serves as the baseline and reproduces the output exactly.

## Limits / what this does not claim

- **Decode side: INCONCLUSIVE.** Two signature scans found no decoder:
  1. `0xfb`/`0xfc`/`0xfd` compares close together: 1 hit, at `0x29de1d2`, which is unrelated.
  2. `cmp 0xfa`/`0xfb` followed by `sub 0xfb`, an add, or a jump table: 9 hits, all unrelated.

  The fork's `de/impls.rs:499:20` and `de/decoder.rs:93:13` Locations exist (for example at `0x56bb1d0` and `0x56bb278`) but were not tied to a varint decoder. The decoder may be inlined into its callers or compiled as a jump table on the tag byte.
- `e8` hits are byte-pattern matches, not a control-flow graph. Calls through pointers, tail `jmp`s (0 found) and inlined copies are not counted.
- The idiom scan proves closure **for those three byte patterns only**. Varint logic that compiles to a different instruction shape would not be found.
- The packet covers node #94 only. #115 is rejected by design and was not ported.
- No semantic gate, no source equivalence, and no claim about zigzag/signed handling, u128, or `fixint` config paths.
