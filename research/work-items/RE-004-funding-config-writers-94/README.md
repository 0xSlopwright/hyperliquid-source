# RE-004: funding configuration writers in node #94: multiplier and interest rate setters, impact and clamp votes

This packet shows every writer of the per-dex funding configuration except `hl_only_perps` and `use_binance_formula`, so a reconstruction can write the hip3 setters as two passes over a hash map keyed by the whole asset id, and the vote arms with the bounds `x >= 6e9`, `x >= 6e8` and "finite, not below zero".

- Component ID: RE-004 (quantities and rounding), funding parameters
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `546081f30a3ebe6af1dadb6f90869f01bd08e1e4` / reference `references/can1357-hl`, `l1/dex_registry/dex_registry.rs:345`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the multiplier setter `0x273c960`, the rate setter `0x2743860`, their copies (`copies.tsv`), the two table writers `0x27c5980` and `0x379c5c0`, the list gate `0x1e7fec0`, and the vote arms for words 20, 21 and 22 in all three dispatchers. The parser `0x3799510`, the float call `0x4ead680`, the tree iterators and the table growth run real as edges. The name split `0x3332080` and asset search `0x374a1a0` are stubs that check their arguments; `fees-growth-modes-94` runs them. Excluded: who authorises the action, the hip3 dispatcher arms, the readers of these fields

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/funding_config_writers.py --out research/work-items/RE-004-funding-config-writers-94
python3 -m unittest tests.test_funding_config_writers
cd research/work-items/RE-004-funding-config-writers-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and takes about 3 minutes at load 5 on this server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents, or the arm windows listed in `function-rows.tsv`. 783 named cases and 120 random cases run real rows; a separately written rule list predicts results, error texts, all three tables of every dex row, both words, every other fixture byte, and that no input block is left unfreed.

### Dex row fields

`rows = S+0x3370`, count `S+0x3378`, stride 0x138 (`S+0x3df0`, `S+0x3df8` in the third copy). The funding block starts at row `+0x48`. Observed writes:

| Row offset | Written by | Form |
| --- | --- | --- |
| `+0x48` | vote word 20 | hash map, 16-byte slots, asset id to u64 |
| `+0x78` | multiplier setter | hash map, asset id to f64 bits |
| `+0xa8` | rate setter | hash map, asset id to f64 bits |
| `+0xf0` | vote word 21 | f64 |
| `+0xf8` | vote word 22 | u64 |

Tables keep control bytes, mask, growth room and item count at `+0`, `+8`, `+0x10`, `+0x18`, and hash keys at `+0x20`. Inference: these are `override_impact_usd`, `perp_to_funding_multiplier`, `perp_to_funding_interest_rate`, `clamp` and `default_impact_usd`, from the field names beside the text `struct FundingTracker with 8 elements` (`error-texts.tsv`) and the kinds of value each writer stores; the binary shows no name on the writer rows.

### Setters, `(out, S, map)`

`map` is a B-tree of String name to String value (node keys `+8`, values `+0x110`, stride 24). Pass 1 walks it in key order:

1. Value over 100 bytes: tag 0x143.
2. Parse the value through `0x3799510`, then cut to f64 through `0x4ead680`. Parser failure passes its object out unchanged; a refused cut gives tag 0xab.
3. Bound. Multiplier: `0 > x` or `x > 10`. Rate: `|x| > 0.01`. Refused: tag 0xe0 with an owned text, `error-texts.tsv`.
4. Name over 100 bytes: tag 0x143. Split and asset search errors pass out.
5. `(id, x)` joins a vector.

Any refusal frees the rest of the map and writes nothing. Pass 2 walks the vector: `dex = id / 10000`, `dex >= count` panics, then `insert(row(dex).map, id, x)`. A later row with the same key replaces the value.

So a value is read before its name, and the bound reads the rounded f64: `10.00000000000000001` and `0.01000000000000000001` pass. NaN passes both bounds when injected into the float result; the parser never gave one.

Text forms from the real parser: `+1`, `1e1`, `1_0`, `.5`, `5.` are accepted; empty, ` 1`, `1 `, `abc`, `0x10`, `NaN`, `inf` give tag 0xac. `79228162514264337593543950336` (2^96) gives the same f64 as 2^96-1 after a first refused parse.

### Vote word 22, `default_impact_usd`

`x >= 0x0ccccccccccccccc` gives tag 0x13f with `x`. Then `x >> 10 > 0x59682e`, which is exactly `x >= 6000000000`, else tag 0x3c `Impact usd too small`. Stored on dex row 0.

### Vote word 20, `override_impact_usd`

The list gate `0x1e7fec0` refuses more than 10000 rows with tag 0x143 and frees the map. Rows then run in key order with no first pass: dex row 0 and meta row 0 must exist (panic), name at most 100 bytes (0x143), asset search on meta row 0 with the whole name, `value >= 0x0ccc...` tag 0x13f, `value < 600000000` tag 0x3c, then insert on dex row 0. A refused row keeps the rows before it. The 0x13f payload word comes from a spill slot that holds the previous row's value; on the first row it is stale stack.

### Vote word 21, `clamp`

Text at most 100 bytes (0x143), parse through `0x374fe60`, then refuse NaN, both infinities and everything below zero with tag 0x40 `Invalid clamp`. `-0.0` is stored. The class edges of the f64 bit patterns are tested by injecting the float result, in all three copies.

### Differences from the reference lead

`reference-diff.tsv` lists 9, each with a case.

## Implementation and comparison

not yet implemented. There is no Rust code in this packet. The rule list in `tools/funding_config_writers.py` is a Python comparison model against real instructions.

## Results and limitations

- 783 named cases and 120 random cases match. 36 tests pass. Two runs are byte identical, also with another hash seed, zone and a PATH with no binutils.
- 361 byte edits of reached conditions, immediates and field displacements in the first copy: 322 killed, 39 survived:

- 16: same: the parser error carries no payload, these rows copy stale stack bytes behind the tag
- 4: same: tag of an unused error that the next call drops; neither value owns memory
- 3: same: height word of a tree iterator handle, read only when it climbs from an empty handle
- 2: not killed: a shifted hasher field still gives a self consistent table, and no read back uses the first hasher
- 2: not killed: needs two equal tag bytes in one group where the first is another key
- 2: same: dangling pointer of an empty vector, never read
- 2: same: the fallible flag only matters when the allocator refuses
- 2: same: the found flag in eax is dropped by the caller
- 2: same: the four dwords of the tag vector are equal
- 2: same: the replaced value in xmm0 or rdx goes back to a caller that drops it
- 1: same on reached values: only a None key word equals this constant and no real key has it
- 1: same: the row pointer from this call is not read on this path

- 5919 bytes, 1276 instructions in the first copy. 199 rows stay unreached: unwind and allocation failure rows, the end of pass 1 for a `None` key word (no real key has it), the second table group probe rows when the fixture never collides, and the drop loop of the list gate, which needs more than 10000 real rows. The cap itself is tested with a null root and a chosen length word.
- Bounds are checked on the cases run, not proved for all inputs. The second and third copies run fewer text cases than the first.
- Unresolved: the action names behind the two setters are read from the error texts and key strings only; the hip3 dispatcher arms were not run. Which words write `hl_only_perps` and `use_binance_formula` is not established.
