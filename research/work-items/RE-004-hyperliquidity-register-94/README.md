# RE-004: RegisterHyperliquidity in node #94: deploy handler, gate body, price ladder, market cap band and seed sum

This packet shows every gate node #94 applies before it installs a Hyperliquidity book, in their real order and with their real arithmetic, including an exact balance gate that no reference file has, an integer `ceil(1.003^n)` multiple in place of an end price, a market cap band of 0.7 to 1.3 times the text bounds, and a no book path for `n = 0`, so a reconstruction can write `registerHyperliquidity` from the action strings to the installed levels and the USDC debit.

- Component ID: RE-004 (quantities and rounding), spot deploy on the Hyperliquidity path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / reference `references/can1357-hl`, `l1/hyperliquidity.rs`, `l1/exchange/impl_spot_deploy.rs` and `l1/exchange/handlers/26_spot_deploy.rs`, used as leads to check; the three disagree with each other
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the handlers `0x274fd60`, `0x4d72a80`, `0x4d73550`, the gate body `0x3261c40`, the ladder `0x32639c0`, the seed sum `0x3262590` and the band helper `0x3262600`. Earlier work lists these addresses without reading the rules: `RE-004-px-tick-ladder-94` and `RE-006-spot-sell-price-band-94` have call site rows for the tick calls inside the body and ladder, `fees-open-order-cap-94` names the body as a function with no volume code, `RE-004-decimal-scaled-u64-94`, `RE-004-perp-spot-scale-gate-94`, `RE-004-usdc-ntl-scale-94`, `RE-006-system-buy-order-94`, `bridge-withdraw-fee-route-94` and the two inventories have call site rows in the handlers. No packet reads the gate order, the ladder or the band. Run real as edges and not claimed: decimal parser `0x3799510`, scale `0x3750350` (merged in `RE-004-decimal-scaled-u64-94`), price wrapper `0x230b1e0`, tick ladder `0x36f3350` (merged in `RE-004-px-tick-ladder-94`), `0x32814c0` (closed form merged in `RE-004-spot-wei-scale-family-94`), `0x37606b0`, B-tree search and insert, vector growth, round `0x565f410`, ceil `0x565f670`, name builder `0x3c0d570`. Stubs that check their arguments: balance `0x36f7560`, user record `0x371b3a0`, tick override lookup `0x3728550`, dex lookup, amount scale `0x370c100`, send `0x370d980`, move core `0x270f6f0` and copies, `0x3987cb0`, event sink. Excluded: what happens after the send, the two callers in the outcome deploy at `0x274c9f0`, and resting of the levels, which `RE-006-hyperliquidity-refresh-94` reads

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/hyperliquidity_register.py --out research/work-items/RE-004-hyperliquidity-register-94
python3 -m unittest tests.test_hyperliquidity_register
cd research/work-items/RE-004-hyperliquidity-register-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took about 3 minutes at the load of this run.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 196 named cases and 300 random cases run real rows; a separately written rule list predicts the result, every callee event with its arguments, the words the subject may write, every other fixture byte, and that no block is left unfreed. Subject code is 2131 instructions in 11158 bytes. `messages.tsv` holds the 16 texts with their addresses, `constants.tsv` every bound with its immediate address, `outcomes.tsv` every named case.

`S` is the exchange state. Spot rows are at `S+0x1f8` (stride 0x20: base, quote), token rows at `S+0x210` (stride 0xe8: `+0`/`+8` written once here, name `+0x38`/`+0x40`, size decimals `+0x48`, wei decimals `+0x49`). Copy b moves the fields in `copies.tsv` by 0xa80, and it sends its event to `S+0x5b8` through slot `0x5776ad0`. All refusals in the body are tag 0xdf with a static text.

### Handler, `(out, S, user, spot, px text, sz text, n, seeded)`

1. `spot` past the list panics. The px text goes through `0x3799510`; a bad text gives its tag 0xac (`Invalid decimal number`).
2. `px = 0x3750350(decimal, mode 2, wei(quote) - sz(base))`, half even. A wei below size panics. Any refusal, or `px == 0`, is tag 0xa9 (`Error converting float to price`). Copy a does this in `0x230b1e0`, copies b and c inline.
3. The sz text goes through the same parser, then `sz = 0x3750350(decimal, mode 1, sz(base))`. Mode 1 refuses anything further than 0.001 from a whole raw size and notes a snap; refusal is tag 0xaa (`Error converting float string to size`).
4. An empty list at `S+0x5c0` panics. `available = 0x36f7560(first row, user)`. Above 0x68db8bac710cb gives `could not convert perp usdc to spot`.
5. The body runs with `(px, spot, sz, n, seeded, available*100)`, the spot row `S[+0x3388] + spot*0xd8` and `S+0x38d0`.
6. On success `amount = ceil(sum/100)`. If byte `token[+0]` of the base token is 0, `+0` becomes 1 and `+8` becomes `amount`; this happens even for amount 0.
7. `amount == 0` ends here. Otherwise: `0x370c100(dex 0, amount)`, send of that value to the all ones user (`0x370d980`), `move(S, 0, all ones, 1, amount)`; a refused send or move panics at an `expect`. Then a one user list, the words `S+0x60`, the words from `0x3987cb0` only if `S[+0] == 1`, and the event with name `USDC` and `-amount/1e6` go to the sink.

### Body, `0x3261c40`, in order

| Step | Test | Result |
| --- | --- | --- |
| 1 | `n > 4000` | `too many Hyperliquidity orders` |
| 2 | `seeded > n` | `cannot seed more levels than exist` |
| 3 | spot in the book map | `Hyperliquidity already exists` |
| 4 | read the base row in the `0xff..ff` user record: balance `+0x60`, hold `+0x68` | |
| 5 | balance 0 and `n == 0` | mark, empty book word, success with sum 0, tests 6 to 18 skipped; a hold or a bad quote passes here |
| 6 | hold nonzero | `Hyperliquidity already has token hold` |
| 7 | quote not token 0 | `quote token must be USDC for Hyperliquidity` |
| 8 | base not in the max supply map `S+0x408` | `Hyperliquidity missing max supply` |
| 9 | `n < 10` | `too few Hyperliquidity orders` |
| 10 | with `M = ceil(1.003^n)`, the product by repeated multiply: `sz*n`, `M`, `px*M`, `sz*px*M` | any overflow, or a value above `L = 0x1999999999999999`, or `M > 1e6`: `Hyperliquidity configuration invalid` |
| 11 | `sz == 0` | `zero Hyperliquidity order size` |
| 12 | `(n - seeded)*sz*10^(wei-sz)` differs from the balance, or overflows | `Hyperliquidity has incorrect balance` |
| 13 | ladder of `n` levels, see below | |
| 14 | `first*sz < 1e6` with no overflow | `Hyperliquidity starting order value must be at least 1 USDC` |
| 15 | `first == last` | `Hyperliquidity starting price too small` |
| 16 | row `(last, 1e9, 1e11)`, then row `(first, 0, 1e7)`: price above `0x38d7ea4c68000`, or not a multiple of its tick | `Hyperliquidity price is invalid` |
| 17 | same rows: `0x32814c0(max supply, base, price)` is exact, and `0x3262600(lo, hi, value)` holds | else the base name must be the four bytes `HYPE`, or `market cap must be in range [1B, 100B] USDC at Hyperliquidity end price and [0, 10M] USDC at Hyperliquidity start price` |
| 18 | seed sum refused, or above `available*100` | `insufficient usdc for seeding hyperliquidity` |
| 19 | success | raw `px` to spot row `+0x78`, book inserted under the spot id, result the sum |

The book value is `{cap, ptr, len, sz}`; a level is 24 bytes, word 0 is zero, word 1 is left unwritten and word 2 is the price. `RE-006-hyperliquidity-refresh-94` names the first two words as a tag and an order id. For `n == 0` the first word is `1 << 63`.

### Ladder, `0x32639c0`

`level[0] = max(floor(px / tick(px)) * tick(px), 1)`. After each push, `next = round(f64(level) * 1.003)` half away from zero, saturated to u64, then `level = max(floor(next / tick(next)) * tick(next), 1)`. The tick is the merged `0x36f3350`: 1000 on an override hit, else `min(10^max(0, digits-5), 10^(wei(quote)-sz(base)))`. It runs `n` times, one step past the last level.

`rise-table.tsv` holds every change of state over prices 1 to 2000 at tick 1: prices up to 166 stay put and 167 goes to 168. That is what `first == last` catches at tick 1, and a price at a tick override stays put the same way (case `body tick override stuck`).

### Seed sum `0x3262590` and band `0x3262600`

The sum adds `level*sz` over the first `seeded` levels. A product overflow, a product above `2^63-2` or an add carry refuses. The band is true when `lo*700000*100 <= value <= hi*1300000*100`, with every overflow refusing. So the end row admits 7e16 to 1.3e19 and the start row 0 to 1.3e15, and named cases sit on each side of each bound, alone and through the body with real ladders of 1430 and 3100 levels. `0x3262600` and `0x3262590` also run alone, with overflow inputs the body cannot reach.

## Implementation and comparison

Not yet implemented. `reference-diff.tsv` lists 12 places where the reference leads differ from the bytes or from each other, each with a named case that shows the bytes. `l1/hyperliquidity.rs` has the ladder, band helper and seed sum right; `impl_spot_deploy.rs` and `handlers/26_spot_deploy.rs` have ceil steps and exact bounds that do not exist in the bytes.

## Results and limitations

- Every named and random case matches. `tests.test_hyperliquidity_register` runs 65 tests with no skips, including edits of real bytes and damaged digest and text controls.
- 344 single edits of reached conditional rows, immediates and field offsets of the body, ladder, sum, band and handler a: 287 killed and 57 survived. Copies b and c and the ladders of more than 300 levels are outside the sweep, to keep the tool near two minutes; named cases run them. Survivor groups:

- 21: open: no case of the sweep set separates this edit
- 11: same: a bound test of a list index or a panic argument; the fixture keeps these lists in range, or the path ends in a panic either way
- 7: same: the power is finite, positive and below 2^63 for n up to 4000, so the float to integer guards and the 1e6 bound never decide
- 4: same: a level is positive and well below 2^63 here, the guards after the round never decide
- 4: same: a saturated word times 100 still overflows and refuses
- 3: left to the named body edge cases: ladders of 1430 and 3100 levels are outside this sweep, and these immediates are pinned in constants.tsv
- 3: same: the first push reallocates before the initial vector words are read
- 2: same: the 32 bit divide path gives the same quotient
- 1: not compared: status bytes past the tag on a refusal path
- 1: same: the low bound of the start row cannot bind, the end row needs a value at most 1.6e5 times larger

- 165 rows were not reached. They are panic and unwind rows, the copy panics for rows past a list, and these rows that the arithmetic closes: `0x3263acb`, `0x3263b7b`, `0x3263bcb` (level limits; step 10 keeps `px` under `L`, and a floor cannot overflow), `0x326206b` (a non finite power; `power-table.tsv` shows 159,858 at `n = 4000`, so the `M > 1e6` test never refuses), `0x3262525` (`sz*n` is under `L`), `0x3261f8f` (the old book word; step 3 proved no book), `0x3262516` (token bound, already passed in `0x37606b0`).
- The proof style is case based. The rule list holds for each case and each mutation target, not for all inputs. Whole domain results here are the band edges, which are read from the immediates, and the two closed arithmetic facts above.
- Inference: `0xff..ff` is the hyperliquidity user (`RE-006-token-genesis-book-word-94` reads its texts), and the text `[1B, 100B]` with the 0.7 and 1.3 factors means a tolerance around the text bounds. The fallback name test uses the base token name.
- Unresolved: the name of the word at token row `+0`/`+8`, and what the outcome deploy passes through `0x274c9f0`. The reference gives `usdc_seeded` for an amount stored in the book, and the bytes put no such word there.
- `callers.tsv` shows the handler has three callers per copy: the spot deploy dispatcher and two calls in the outcome deploy. 101 stores of status bytes past the tag in the handlers were left out of the edits, because those bytes are stale frame bytes on these paths and the rule list does not compare them.

## Next question

What does the outcome deploy at `0x274c9f0` pass as px and sz to this handler, and how does the book it creates differ from a spot deploy, given that its base balance gate still needs `(n - seeded)*sz` of the hyperliquidity user?
