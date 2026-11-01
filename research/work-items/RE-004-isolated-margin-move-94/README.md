# RE-004: isolated margin in node #94: the shared move, the strict isolated top up, both handlers and the routing wrapper

This packet shows how node #94 moves margin between an account word and an isolated position: every update goes through one function that applies the delta to a clone first, and `topUpIsolatedOnlyMargin` raises equity to `abs(notional) * (1.0 / level)` truncated, on strict isolated assets rather than the reference's delisted assets, so a reconstruction can write the refusal order, the state left by a refused call and the exact rounding of the required equity.

- Component ID: RE-004 (quantities and rounding), isolated margin
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / reference `references/can1357-hl`, `l1/exchange/handlers/36_update_isolated_margin.rs` and `37_top_up_isolated_only_margin.rs`, used as leads to check
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the move `0x3707000`, the top up `0x3709560`, the `updateIsolatedMargin` handlers `0x21e2b60`, `0x4c02bc0`, `0x4c02a60`, the routing wrappers `0x2722010`, `0x4d27c60`, `0x4d28400`, and the `topUpIsolatedOnlyMargin` handlers `0x21e2ee0`, `0x4c03eb0`, `0x4c03ba0`. Earlier work on these addresses does not read the arithmetic: open and past pin requests #751, #794 and #875 record bytes and census rows with `the body's actual computation and all callee semantics` left unknown, `RE-004-qty-recorder-lines-94` has one recorder row for `0x3707000`, `RE-010-exchange-handlers` has dispatch rows for the handlers, `fees-collection-94` uses `0x3707000` only as the end of the previous FDE, and a collateral steps packet has call rows into `0x4d27c60` and `0x4d28400`. Run real as edges and not claimed: B-tree clone `0x33eb860` and `0x33e35c0`, tree insert and drop, set insert `0x339b590`, user search `0x3596940` and `0x379a390`, open word update `0x36f7350`, decimal text and float code. Stubs that check their arguments: available amount `0x36f7560`, margin check `0x37d77e0`, default row `0x3bfffd0`, user lookup `0x36f57f0`, hash `0x399c7a0`, wire id decoder slot `0x5773950`, dex lookups, user row, abstraction tracker, the pre, finish and settlement helpers and their drops, recorder `0x358dcd0`. Excluded: what those callees compute, `updateLeverage`, and margin tier code

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/isolated_margin_move.py --out research/work-items/RE-004-isolated-margin-move-94
python3 -m unittest tests.test_isolated_margin_move
cd research/work-items/RE-004-isolated-margin-move-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took about 1 minute at server load 6.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 309 named cases and 300 random cases run real rows; a separately written rule list predicts the result, every callee event with its arguments, the words the subject may write, every other fixture byte, and that no block is left unfreed. Subject code is 2583 instructions in 12275 bytes.

`S` is the exchange state and `D` one dex row, `[S+0x5c0] + dex*0x2f0` (copy c `S+0x1040`, `copies.tsv`). An asset id is `dex*10000 + local`. `tag-texts.tsv` gives the Display text of every tag below.

Layouts read from the rows:

| Where | Field |
| --- | --- |
| `D+8`, `D+0x10` | perp rows, stride 0x30; `+0x18` table id, `+0x28` kind byte, 2 is strict isolated |
| `D+0x30` | dex id |
| `D+0x68`, `D+0x70` | price rows, stride 0x60; `+0x20` price |
| `D+0xf8` | user table, seed `D+0x118`, element 0x78, 20 byte key, value at `+0x18` |
| `D+0x158` | user set, not written here |
| `D+0x170` | tree of asset to summed `abs(size)` |
| `D+0x188` | set of users that passed the first gates |
| `D+0x2ed` | byte passed to the margin check |
| value `+0` | account word, `i64` |
| value `+8` | position tree, keys at node `+0x2c8`, 0x40 byte rows; a B-tree handle of 3 words |
| value `+0x20` | count word, passed to `0x36f7350` |
| value `+0x28` | second tree, `u32` keys, cloned and never read here |
| row `+0`, `+4`, `+8`, `+0x10` | mode, leverage, margin `i64`, size `i64` |

### The move, `0x3707000(out, D, user, asset, delta)`

`delta` is signed. Refusals in order:

1. `available = 0x36f7560(D, user)`, read first and used only at step 5.
2. User not in the table: 0x48.
3. `delta == 0`: 0x49.
4. `asset/10000 != D+0x30` or `local >= D+0x10`: panic at `l1/src/perp_meta.rs:194:38`. Then `delta < 0` on kind 2: 0x4e. Increases on kind 2 pass.
5. `delta > available`, signed: 0x4b. A reduction never fails this.
6. The account struct is cloned, trees included, and the user joins the set at `D+0x188`. Everything below runs after that join.
7. The row is fetched from the real tree. A missing row is **inserted**: mode and leverage from `0x3bfffd0`, table id at `+0x38`, size 0.
8. `size == 0`: 0x4a. `mode != 1`: 0x4d. Word 2 and word 3 are both refused.
9. On the clone: `margin + delta` overflow 0xbe, `account - delta` overflow 0xbf. For `delta < 0` only, `0x37d77e0(clone, 1, asset, 4, D+0x2ed byte, D+0x60, D)` runs on the moved clone; a negative result is 0x4c.
10. On the real row the same two writes.

After every path from step 7 on, `0x36f7350(asset, size, size, value+0x20, D+0x170)` runs, so a refused call on a new asset leaves a new row and a new key with word 0 in the tree at `D+0x170`. Its effect on an existing word is `(x - abs(size)) + abs(size)` with saturation in each step (`impl_sz.rs:35:1`, `mod.rs:828:1`), and `size == i64::MIN` panics after the write. Then the clone is dropped.

The account may go below zero on an increase: the bound is `available`, not the account word.

Rows with no effect on this path, read from the bytes and never reached: the real add and subtract overflow rows (`0x370783f`, `0x370784b`), because the clone holds the same words and refused first, which also means the `impl_ntl.rs:62:1` recorder at `0x3707854` cannot fire here; the leverage compare `0x37075de` (the row is read twice with no write to `+4` between), so `0x370e6a0` is not called; and the count tests at `0x37076f2` (both sizes are equal, so `0x36f7350` leaves the count alone), so the set at `D+0x158` is not written.

### Top up, `0x3709560(out, D, user, asset, level)`

1. `level < 0.5` or `level > 1.0`: 0x43. This runs before anything else.
2. Same panic as step 4 above. Kind not 2: 0x139, `Asset not strict isolated`.
3. No user or no row: ok.
4. `price = D rows[local]+0x20`. A local past the list panics, a negative price or an overflowing `size * price` panics at `l1/src/clearinghouse/position.rs:204:57`, **before** the mode is read, so a cross row can panic.
5. Bit 0 of the mode word clear: ok. The move tests `mode == 1` and this tests bit 0, so word 3 gets past here and is refused there with 0x4d.
6. `equity = notional + margin`, saturating with recorder `impl_ntl.rs:62:1`.
7. `notional == i64::MIN` panics through `Result::unwrap`.
8. `need = trunc(f64(abs(notional)) * (1.0 / level))`, saturating to `i64::MAX` at `2^63`. The chain has a non-finite test and two clamps; `abs <= 2^63` and `level` in range keep the product finite and non-negative, so only the high clamp has an effect.
9. `delta = need - equity`; overflow 0xbf; `delta <= 0` ok.
10. The move with this `delta`; its tag passes through unchanged.

The reciprocal is computed first, and it shows: `size 39, price 1, level 0.65` gives 59 where `39 / 0.65` gives 60, and `size 33, level 0.55` gives 60 where the divide gives 59.

### Handlers

`0x21e2b60`, action `+0` delta, `+8` wire id:

1. Wire id through slot `0x5773950`; an error passes unchanged, a spot id is 0x15e with the id.
2. `abs(delta) >= 0x0ccccccccccccccc`: 0x13f with `abs(delta)`. `i64::MIN` is refused here with its own word.
3. Routing wrapper, then ok (code 0x0d) or the status (code 0x0e).

`0x21e2ee0`, action `+8`/`+0x10` text, `+0x18` wire id: wire id as above, length above 100 is 0x143, decimal text through slots `0x57731d8` and `0x5773968` (text error 0xac in the bad text case, float failure 0xab), dex bound panic, top up. `0x4c03ba0` has the wide state layout and pairs with update copy c; `0x4c03eb0` has the narrow layout and pairs with b.

### Routing wrapper `0x2722010`

`class` is byte `+0x3c` of the user row. `flag0 = S+0x5b0`, `flag1 = S+0x5b1`, `byte = S+0x3acb` (copy c `S+0x454b`).

| Case | Path |
| --- | --- |
| `class >= 4`, `flag0` set | direct |
| `class >= 4`, `flag0` clear | routed; `flag1` has no effect |
| `class < 4`, `flag1` set | direct; `flag0` has no effect |
| `class < 2` | direct |
| `class == 2`, `byte == 0` | direct |
| `class == 2`, `asset < 10000` | direct through slot `0x5773d80` |
| `class == 2`, other | settle, move, then settle again only when `byte == 1` |
| `class == 3` or more | routed |

Direct raises the counter `S+0x58` (saturating), checks the dex bound, runs the move, lowers it (stops at 0). A counter at `u64::MAX` ends one lower.

Routed: tracker row from `S+0x770`, two set searches over the time word `S+0x60` with windows `S+0x4e8/0x4f0` and `S+0x4f8/0x500`; both false gives 0x170 with nothing else changed. Otherwise row `+0x30` and `S+0x7d0` rise, `pre`, move, then `finish` for class exactly 4, or settle for the rest, so class 5 settles.

**A refused settle is dropped in every path**, and the wrapper returns the move's status. This holds for the settle before the move too, so the move runs after a refused settle.

## Implementation and comparison

not yet implemented

`reference-diff.tsv` lists 5 differences from the lead, each with a case in `outcomes.tsv`.

## Results and limitations

- 309 named and 300 random cases match the rule list. Copies a, b and c of both handlers and the wrapper each ran their own cases.
- Mutation: 923 byte edits of conditional rows, immediates and field offsets on rows the cases reach, 798 killed, 125 survived (per edit in `mutations.tsv`):

- 50: not compared: copies of the status object past the tag; the move writes only the tag on these paths, so these bytes are stale stack bytes
- 30: not compared: copies of the decimal parser status object past the tag
- 19: same: panic argument, or the tag of a lookup value that is not used on the panic path
- 4: same: height word of a tree handle that is rebuilt before it is read
- 4: same: the product is finite and not negative here, and the clamp gives the same value inside its range
- 3: not killed: with no position row the clone is refused empty, so the second tree copy is seen only through the free check
- 3: same: tag of an unused status that the next call drops
- 3: same: the second bound test of one dex index, after the first passed with the same value
- 2: not killed: probe step of a table search that never leaves a group end on the reached keys
- 1: not killed: inner node scan bound on a key the clone holds, with spare keys past the length
- 1: same: a copy of an ok status is still an ok status
- 1: same: flag read only on an unwind path
- 1: same: key copy read only by the leverage call, which is not reached
- 1: same: searching an empty table also misses
- 1: same: the four dwords of the tag vector are equal
- 1: same: the key is present in the clone, so the leaf bound never fires

  Survivors are grouped by address range; a sample of each group was read, not every edit.

- `evidence.json` lists 216 unreached rows: landing pads, panic rows, the rows named above as having no effect, and the shadow search rows for a missing row.
- Arithmetic is checked at edges and random points, not proved for all inputs. The bound in top up step 8 is a reading of the rows.
- Inference: kind byte 2 means strict isolated, from the two tag texts on the same byte. The tree at `D+0x170` as open interest rests on the Sz Location and the `abs(size)` rule. The set at `D+0x188` has no name here.
- Unresolved: what `0x36f7560` and `0x37d77e0` compute for this path; what the second tree holds; the settlement meaning of `pre`, `settle` and `finish`.
- The evaluator's `imul` rows set flags in this tool. Earlier tools built from the same core did not model the flags of two and three operand `imul`; that only matters where a `jo` follows such a row.

Next question: what does `updateLeverage` body `0x37098a0` check before it changes a row, and how does its change reach the two trees that the move leaves alone?
