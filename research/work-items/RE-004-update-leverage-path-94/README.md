# RE-004: updateLeverage in node #94: the leverage body, its handler and the routing wrapper

This packet shows what node #94 checks before it changes a leverage row: table ids below 50 are their own maximum, ids from 50 read a tier tree, a position with size runs a tier cap and up to two clone checks, and a switch from cross to isolated writes margin 0 while the reverse keeps the old word, so a reconstruction can write the gate order and the exact row writes of `updateLeverage`.

- Component ID: RE-004 (quantities and rounding), leverage on the isolated margin path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / reference `references/can1357-hl`, `l1/exchange/handlers/38_update_leverage.rs`, used as a lead to check
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the body `0x37098a0`, the handlers `0x21e0b70`, `0x4897800`, `0x48976c0` and the routing wrappers `0x2721860`, `0x4d26cc0`, `0x4d27490`. Earlier work on these addresses does not read the rules: request #757 binds `0x37098a0` as bytes and records, `RE-010-exchange-handlers` has dispatch rows for the handlers, and `clearinghouse-oracle-inventory-94` lists it. Companion packet `RE-004-isolated-margin-move-94` reads the shared move and the same class table for a sibling wrapper, and the wrapper part here repeats that table for these rows. Run real as edges and not claimed: B-tree clones, tree insert and drop, the one tier table builder `0x3398f50`, set insert `0x339b590`, user search `0x3596940`, open word update `0x36f7350`. Stubs that check their arguments: margin check `0x37d77e0`, tier cap `0x3333580`, default row `0x3bfffd0`, leverage index `0x370e6a0`, user lookup `0x36f57f0`, hash `0x399c7a0`, name clone, wire id decoder, dex lookups, user row, tracker, the pre, finish and settlement helpers, recorder `0x358dcd0`. Excluded: tier contents and what the stubs compute. The insert of a user with no table entry at `0x3709d1b` was not run

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/update_leverage_path.py --out research/work-items/RE-004-update-leverage-path-94
python3 -m unittest tests.test_update_leverage_path
cd research/work-items/RE-004-update-leverage-path-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took about 1 minute at server load 6.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 191 named cases and 300 random cases run real rows; a separately written rule list predicts the result, every callee event with its arguments, the words the subject may write, every other fixture byte, and that no block is left unfreed. Subject code is 2029 instructions in 9727 bytes.

`D` is one dex row. A perp row has its name `String` at `+0`, table id at `+0x18`, kind byte at `+0x28`. A position row has mode `+0`, leverage `+4`, margin `+8`, size `+0x10`, table id `+0x38`. `tag-texts.tsv` gives the Display texts.

### Body, `0x37098a0(out, D, user, asset, cross, level)`

1. `asset/10000 != D+0x30` or `local >= D+0x10`: panic at `l1/src/perp_meta.rs:194:38`. With `cross`, kind byte not 0 is 0x44.
2. Maximum for `table` from the perp row:
   - below 50: a one tier table is built on the stack with `0x3398f50` and its maximum is `table` itself;
   - from 50: search the tree at `D+0x38` (`u32` keys at node `+0x270`, 0x38 byte records at `+8`); a missing id panics at the Location in `locations.tsv`; the record's tier tree is at `+0x18`/`+0x20`, and the first tier's byte at `+0x18` is the maximum; no tiers means 3.
3. `level > maximum`: 0x43.
4. The row is looked up.
   - No row: `0x3bfffd0` runs and its result is left unread, then go to step 8.
   - Size 0: go to step 8.
5. `(mode == 0) != cross`: 0x45. Word 2 counts as isolated here, unlike the `mode == 1` test of the move.
6. `local >= D+0x70` panics. `cap = 0x3333580(tier record, price)`; `level > cap` is 0x50 with `cap` at status `+4` (`Max leverage at current position size is {}x...`).
7. If `table == row table` and `level >= row leverage`, no check runs. Otherwise the account struct is cloned, the clone's row gets the new leverage and table, and:
   - `table != row table`: `0x37d77e0(clone, !cross, asset, 2, _, D+0x60, D)`; negative is 0x4f with a clone of the perp name;
   - `level < row leverage`: the same call with mode 1; negative is 0x46 for cross and 0x47 for isolated (`0x47 ^ cross`).
8. The user joins the set at `D+0x188`, and only here: a refusal leaves it. The row is fetched or inserted, `+0x38 = table`, then:

| Old mode | `cross` | Writes |
| --- | --- | --- |
| 1 | set | mode 0, leverage |
| 1 | clear | mode 1, leverage |
| not 1 | set | mode 0, leverage |
| not 1 | clear | mode 1, leverage, margin 0 |

9. `0x36f7350(asset, size, size, value+0x20, D+0x170)` as in the move, then `0x370e6a0(D+0x128, user, asset, level)` when the leverage word changed.

Moving from isolated to cross keeps the margin word, and with size 0 no gate looks at it.

A new row runs `0x3bfffd0` twice: once in step 4, once inside `0x33bd420`.

The count tests at `0x3709f68` have no effect here, since both sizes passed to `0x36f7350` are equal; the set at `D+0x158` is not written.

### Handler and wrapper

Handler `0x21e0b70`: action `+0` level `u32`, `+4` wire id, `+8` cross byte. An error of the wire decoder passes, a spot id is 0x15e with the id, and the wrapper's status goes out with code 0x0e, or code 0x0d for ok. There is no range check on the level here.

The wrapper has the class table of `RE-004-isolated-margin-move-94`, with body slot `0x5773da8` in place of the move. Copy c uses the wide state layout (`copies.tsv`). A refused settle step is dropped in every path; `finish` runs for class exactly 4.

## Implementation and comparison

not yet implemented

`reference-diff.tsv` lists 5 comparisons with the lead, each with a case in `outcomes.tsv`.

## Results and limitations

- 191 named and 300 random cases match the rule list. Copies a, b and c of the handler and wrapper each ran their own cases.
- Mutation: 701 byte edits of conditional rows, immediates and field offsets on rows the cases reach, 634 killed, 67 survived (per edit in `mutations.tsv`):

- 30: not compared: copies of the status object past the tag; the body writes only the tag on these paths, so these bytes are stale stack bytes
- 12: same: panic argument, or the tag of a lookup value that is not used on the panic path
- 8: same: height word of a tree handle that is rebuilt before it is read
- 4: not killed: scan bound on a node where the key is found or stale slots hold a higher key
- 4: same: the second bound test of one dex index, after the first passed with the same value
- 2: not killed: first leaf descent details of a tier tree under 8 levels
- 1: not killed: an asset past the list panics later on the same case with this edit
- 1: not killed: table id 49 refusal path frees the same stack table under the edited bound
- 1: not killed: the cross path ran local ids of dex 0 and 1 only with a low immediate bit that keeps them
- 1: same: only the zero or nonzero state of this word is read on the reached path
- 1: same: the key is present in the clone, so the leaf bound never fires
- 1: same: the word is written over on every reached path
- 1: same: word copied to a stack record that no reached row reads

  Survivors are grouped by address range; a sample of each group was read, not every edit.

- `evidence.json` lists 184 unreached rows: landing pads, panic rows, the count rows above, tier descents of 8 or more levels, table tree descents (the fixture tree has one node), and the second bound test.
- Inference: reading modes 1 and 2 of `0x37d77e0` as a leverage and a table check rests on the tags they give here.
- Unresolved: what `0x37d77e0`, `0x3333580` and `0x370e6a0` compute; the Display text of tag 0x4f.
- Tier trees are fixtures with the real node shape; no tier table of the running chain is read.

Next question: what does `0x3333580` read from a tier record for a given price, and which tier fields does `0x37d77e0` use in modes 1 and 2?
