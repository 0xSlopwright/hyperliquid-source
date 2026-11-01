# RE-004: SetGlobal oracle action and HIP-3 stale refresh, wire price to Decimal row to timestep, in node #94

This packet shows how every oracle price enters a clearinghouse: the three-word Decimal row, the SetGlobal gates in their real order, the history ring, and the ten second stale refresh, so a reconstruction can write both producers of the shared timestep input without the reference's vector layout, its positive f64 parse, its unknown-asset error or its ten-day period.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `391fe838467760eefc04072c0ea762a7a1155c78`, `references/can1357-hl` as pinned there (searched for leads only, nothing copied)
- Claim status: observation for the rows, order, gates and values; inference for the field names not carried by a serde key or a text; unresolved items are under limits
- Scope included and excluded: included are handlers `0x1f67b30`, `0x47b99b0`, `0x47b8da0`, collect `0x2512300`, fold `0x26b7310`, row `0x1e82a80`, price map insert `0x285f0e0`, remove `0x28683e0`, ring push `0x25175c0`, row clone `0x3bc64b0`, refresh `0x2228a10` up to its metric, builder `0x2572180`, row entry `0x1e82600`, group insert `0x284dd30`, and their copies (`copies.tsv`). The handler and refresh addresses also appear as rows in the dispatch, inventory and oracle inventory lists, with no body read there. Edges run as real bytes and not edited: Decimal parse `0x3799510`, compare `0x4eadb90`, name lookup `0x374a1a0`, parse to f64 `0x374fe60`, f64 to Decimal `0x4eac740`, time add `0x15206e0`, tree split and removal helpers. Stubs: the signer test `0x33690c0`, the timestep `0x27078a0`, the mark reader `0x26e0660`, the clock and the recorder. Excluded: the timestep body, what `0x26e0660` computes from the book, readers of the ring and of the two words.

## Reproduce

```
python3 tools/set_global_oracle.py --out research/work-items/RE-004-set-global-oracle-94
python3 -m unittest tests.test_set_global_oracle
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. It emulates the subject rows in a Python model of x86-64 and takes about 210 s.

## Evidence

Coordinates are virtual addresses in copy a; `S` is the exchange state, `D` a dex row of stride `0x2f0`. Copy b adds `0xa80` to `S+0x3590`, `S+0x3840`, `S+0x3888`, `S+0x5b8..0x5c8` and `S+0x3370`, and keeps `S+0x580`, `S+0x588` (`copies.tsv`).

### Row format, the shared input

Both producers build a `Vec` of `0x3c`-byte rows and pass it to timestep `0x27078a0` / `0x4cf37f0` / `0x4cf94a0`. A row is three options, each a u32 flag then a 16-byte Decimal: `+0x00` oracle, `+0x14` mark, `+0x28` external. The `0x60`-byte `D+0x60` rows hold the stored raw oracle word at `+0`.

| Caller | rdx | r8 | Rows |
|---|---|---|---|
| SetGlobal handler | 0 | 0 | one per `pxs` item, in wire order |
| stale refresh | dex id | 1 | one per asset of that dex, external always none |

The third caller of `0x27078a0`, `0x273e080`, is not read here (`callers.tsv`).

### Wire fields

`wire-fields.tsv` binds serde keys to action offsets through the serializer at `0x1e8a0de`: `pxs` `+0`, `externalPerpPxs` `+0x48`, `usdtUsdcPx` `+0x18`, `nativePx` `+0x30`. `pxs` is a list of `0x30`-byte items of two optional strings, oracle then mark; cap word `2^63` is none. `externalPerpPxs` is a B-tree of string to string, node layout keys `+8`, values `+0x110`, parent index `+0x218`, length `+0x21a`, edges `+0x220`.

### SetGlobal order, all three copies

1. `S+0x5c8 == 0`: panic (`Result::unwrap`). The dex list head `S+0x5c0` is dex 0, the row all names and keys use.
2. Tree length above 10000: tag `0x143`.
3. For each tree entry in key order: name above 100 bytes tag `0x143`. Lookup `0x374a1a0`: first unit with an equal name gives `dex*10000+position`. An unknown name builds tag `0x64`, the error is dropped and the entry is skipped before its price is looked at, so a refused price under an unknown name passes. Price above 100 bytes tag `0x143`; Decimal parse error returns that tag (`0xac`); value at or below Decimal zero tag `0x77`; insert into a local tree from u64 to Decimal.
4. `pxs` length above 10000: tag `0x143`.
5. Each item in order, through `0x2512300`, `0x26b7310`, `0x1e82a80`: oracle if present, then mark if present, each with the same three gates (length `> 100` tag `0x143`, parse, `> 0` tag `0x77`). Then `key = 10000*dex + index` with panics on overflow, and `0x28683e0` removes that key from the local tree into the third option.
6. Local entries with no row are dropped with the tree, with no error. Equal names cannot reach the replace arm of the insert, because each name is a tree key and each asset has one first match.
7. Signer test `0x33690c0(S+0x3840, sender, word S+0x3888)`. Any refusal: rows freed, tag `0x94` ("Invalid validator"). It runs only after both lists parsed.
8. Timestep. Any refusal returns its status; rows belong to the callee.
9. `nativePx` if present: above 100 bytes tag `0x143`; parse `0x374fe60`, Decimal then f64; store `S+0x588`. Then `usdtUsdcPx` the same to `S+0x580`. Neither has a sign test. A refusal here comes after the timestep and after the first word, drops the timestep result and returns the error.
10. Ring: `S+0x60..0x6b` time plus a clone of `D+0x60` rows (dex 0) are pushed to the ring at `S+0x3590` (cap, buffer, head, length; entry `0x28` bytes). The clone copies `0x1c` of every `0x20` bytes.
11. While length is above 100 and front time + 300 s is strictly before now, the front goes and its vector is freed. Date, seconds and nanoseconds compare in that order, date signed.

Ok out byte is `0xb` with the timestep's result vector at `+8`; error out byte is `0xe` with the tag at `+8`.

### Stale refresh

`0x2228a10`, only caller `0x222a748` inside `0x22297c0`, label text `refresh_hip3_stale_mark_pxs` at `0x3efa6c` (`constants.tsv`).

1. Label byte `+0x20` not 1: return with nothing done. Read by eye at the caller, not run: this byte is `now_ms / S+0x3938 > S+0x3940`, so the refresh is bucketed by a period word.
2. `S+0x3378 != S+0x5c8`: recorder with Location `0x56e9ac8` and code 5, then continue over the shorter list, zipping dex rows with book tables (`S+0x3370`, stride `0x138`).
3. For each pair: mode byte `D+0x230 == 3` skip. `T = D+0x2e0` (date, seconds, nanoseconds, the `last_set_global_time` of RE-004-usdc-ntl-scale-94). If `T + 10 s` is strictly after now, skip; equality is due. Time add through `0x15206e0` with day carry.
4. `0x2572180` builds a row per asset index `0..D+0x10`: key `10000*id+index` with panics, `0x1e82600` splits it back. Bounds: index within `D+0x70` oracle rows, unit list, `sz` byte (unit `+0x2a`) below 7, book rows, each a panic. `oracle = f64(word) / table[6-sz]`, `mark = f64(0x26e0660(book row)) / table[6-sz]`, tables at `0x3e0e90` and `0x6f7470` (`size-divisors.tsv`). Each goes through `0x4eac740` as described in RE-004-decimal-px-map-94, so the Decimal keeps the float error: word 4096029 with `sz=3` gives `4096.029000000001`.
5. Rows go into a tree keyed by dex id through `0x284dd30`; an equal id frees the earlier rows.
6. Compare `D+0x10` with `D+0x280`: unequal pushes the id to a list that is only freed. No row of this function reads it.
7. After the loop each tree entry, in id order, calls the timestep with `(id, rows, r8=1)`. A refusal is dropped and the loop goes on.

Nothing in the function writes `D+0x2e0`.

### Differences from the reference

`reference-diff.tsv` has 13 rows; each names the case that shows the byte behaviour.

## Implementation and comparison

not yet implemented. A rule list in the tool (`Model`) is written apart from the emulation: it starts from the case fields and predicts result, callee events with full rows, both words, every ring entry, and that the rest of the fixture is unchanged and no block leaked. `float_decimal` restates the conversion rules of RE-004-decimal-px-map-94.

## Results and limitations

- 533 named cases and 267 vectors ran on all three copies with no mismatch (5547 rows, 26395 bytes across subjects).
- 715 edits to reached conditions, immediates and displacements: 606 killed, 109 survived (`mutations.tsv`). Copies b and c are not edited, they run the same cases. 41 status byte store rows are not edited. Survivors by reason:

- 46: not killed by the sampled cases; not argued equivalent
- 36: same: bytes of a status object behind the tag; tags are compared, these payload bytes are not
- 14: same: non-finite and subnormal arms, and the unused error tag, cannot be reached from a u64 over a power of ten
- 6: same on any date the fixture can hold: range window and sign word of the time add
- 5: same: the id list and its compare are never read
- 2: same: a collect stops at the first error, so the status slot still holds the ok tag

- 609 rows are unreached, listed in `evidence.json`: panics, unwind rows, allocator failure, the insert replace arm (see step 6) and the ok-with-flag arms of the fold, which a one item yield cannot enter. List bounds at exactly 10000 are shown through a fixture whose length word is 10000 and whose first entry stops the walk, not with 10000 real rows.
- Stubs check arguments, so the signer map, the timestep and the mark reader are edges. The tick byte's period and the writer of `D+0x2e0` are not established here.
- Names `oracle`, `mark`, `external` for the three options come from the serde keys `oraclePxs`/`markPxs`/`externalPerpPxs` of a sibling action and the reference, not from a label on the row. The second tag text for `0x64` is a format and is not printed. Date words in the fixture use one year; a year crossing is not run.
- Texts are decided by the real parser: values of `2^96` and above refuse with `0xac`, and `1e3`, `1_000`, `.5` parse. Only the forms in `outcomes.tsv` were run.
- The rows `D+0x60` are bounded by Location `clearinghouse/oracle/oracle.rs:202:18` and the book table by `books.rs:14:16` (`locations.tsv`), which is the basis for calling them oracle rows and books.

Next question: which rows of timestep `0x27078a0` consume the three options, and does a refresh with `r8=1` take a different branch from a SetGlobal row?
