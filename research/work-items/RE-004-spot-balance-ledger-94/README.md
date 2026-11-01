# RE-004: spot balance row writers: how node #94 moves total, hold and entry notional

This packet shows the five writers of the spot balance row, so a reconstruction can write the ledger update called from 65 sites, the order hold pair and both dust sweeps from one rule table; the reference's credit, notional and sweep rules all differ from the bytes.

- Component ID: RE-004 (quantities and rounding), Wei and notional arithmetic
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `308e5127990217a9d6196992665da6ca1afd4b82` / reference `references/can1357-hl`, `l1/qtys/impl_wei.rs:559`, `l1/spot_clearinghouse/types.rs:216`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are `ledger_update 0x371d120`, `try_hold 0x371b140`, `release_hold 0x372d5e0`, `fee_sweep 0x3721370`, `user_sweep 0x3721780`, run from their entries, and a class row for every direct call of the update. The value helper `0x32814c0`, the amount resolver `0x375e300`, and the map helpers `0x35964f0`, `0x33bb560`, `0x33c0d60`, `0x3398240`, `0x33bc720`, `0x33ab9d0`, `0x379acf0`, `0x399c7a0`, `0x35818f0` run real as edges and are not subjects. Excluded: callers' own logic and where their price word comes from, and the pro rata payout `0x37227a0`, which is the subject of `RE-004-spot-balance-payout-94`

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/spot_balance_ledger.py --out research/work-items/RE-004-spot-balance-ledger-94
python3 -m unittest tests.test_spot_balance_ledger
cd research/work-items/RE-004-spot-balance-ledger-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and takes about 9 minutes at load 10 on this server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 2773 named cases and 200 random step sequences run real rows from the five entries on real hash table and B-tree memory, starting from an empty table. A separately written rule list in the tool predicts every row word, index entry, fee word, recorder call and panic; after each case the real table and all trees are walked and compared whole. Hooks: allocator, copy, compare, the overflow recorder `0x358dcd0`, the tag logger `0x3762510`.

### State

`layouts.tsv` has every offset. In short, on the spot struct `S`: `S+0x298` hash table of 0x58-byte entries (20-byte user key, row tree at entry `+0x28`), `S+0x3a0` tree token to u64, serde key `token_fees_collected` (`field-keys.tsv`, the lea at `0x3721f37`, offset pinned by `lea 0x3a0`), `S+0x400` tree user to token set. A row is three u64 words: `+0` total, `+8` hold, `+0x10` third word. Inference: the table is serde `user_states`, by key order in the serializer `0x3721d10`, with no offset in the rows read. Inference: the third word is what info calls `entryNtl`; the key sits beside `total` and `hold` in the info row writer `0x2a3b410` (`+0x68`, `+0x70`, `+0x78`), but the code that fills that row was not found.

### `ledger_update(S, user, token, is_debit, amount, price)`, `0x371d120`, 65 direct calls

The row is fetched or created first, so a debit of 0 on a missing row leaves a zero row.

| Step | Debit | Credit |
| --- | --- | --- |
| Total | `amount > total` panics at `0x576e470`; else `total -= amount` | saturating add, recorder `0x56dfd78` on overflow |
| Hold | `hold -= amount`, saturates to 0, recorder `0x56dfd90` | not touched |
| Index | not touched | token added to the user's set in `S+0x400` |

Then, unless `price == 0` or `token == 0`, the third word `n` moves. `value(x) = x*price / 10^(wei-sz)` from `0x32814c0`, and past 64 bits `floor(x/10^k)*price`, which can fail. `k` is token `+0x49` minus `+0x48`; `k` from 20 up, `wei < sz` and a token past the table are panics, and they fall after the total was written.

| Case | New `n` |
| --- | --- |
| Debit, `n == 0` | `value(old - amount)`, 0 if that fails |
| Debit, `n >= 0x28f5c28f5c28f5c` | unchanged |
| Debit, else | `trunc(f64(n) * (f64(old - amount) / f64(old)))`, ratio 0 when `old == 0`; `n` converts as signed |
| Credit, `n == 0` | `value(s)`, `s` = wrapped `old + amount`, or `amount` if that is not above `amount`; stays 0 on failure |
| Credit, `n != 0` | `n + value(amount)`; stays `n` on a failed value or an overflowing add |

The float tail is held by `tail-edges.tsv`: 23 bit patterns entered at `0x371d4f8`. Non-finite stores 0, `x` at or above 2^63 stores `i64::MAX`, negative stores 0. From integer inputs `x` stays in `[0, n]`, so the clamp rows are reached only through this entry.

### `try_hold(S, user, token, amount) -> bool`, `0x371b140`, 31 slot calls

`token` past the table logs tag 0xea and returns false, ahead of the zero test. `amount == 0` returns true with no lookup. A missing user returns false and adds no entry; a known user with no row gets a zero row. `hold + amount` carrying, or above total, returns false. Otherwise `hold` rises and it returns true.

### `release_hold(S, user, spot, side, price, size)`, `0x372d5e0`, 3 slot calls

`0x375e300` picks token and amount from spot row `S+0x178`, stride 0x20: with side bit 0 the quote token `+8` and `price*size`, with side bit 1 the base token `+0` and `size*10^k`. A 64-bit overflow returns with nothing done. Otherwise the row and index entry are made and `hold -= amount` saturates with the recorder. A spot past the table panics.

### `fee_sweep(S, token, price)`, `0x3721370`, 15 slot calls

The sentinel user is twenty 0xee bytes (`0x203cc0`). Its entry is made if missing. A missing row or total 0 ends here. `try_hold` for the whole total refuses when any hold exists, and then nothing moves. Otherwise a debit of the total, then `token_fees_collected[token]` saturating add.

### `user_sweep(S, token, users, price)`, `0x3721780`, 6 slot calls

Walks a user map in key order (u64 values, not read). Each row's total joins a saturating sum, then the row is removed from the user's tree, so hold and third word go with it; the index entry stays. Finally `ledger_update(sentinel, token, credit, sum, price)` runs, also for an empty map, which creates a zero sentinel row. The map walk ran at tree heights 0 to 17, so the unrolled descent rows are real.

### Who calls the update

`update-calls.tsv` lists all 65 sites and `update-call-summary.tsv` counts them. Direction and token 0 come from fixed bytes before the call, and `price none` means `xor r9d, r9d` right before it:

| Direction | Token | Price | Calls |
| --- | --- | --- | --- |
| credit | 0 | none | 6 |
| credit | value | none | 3 |
| credit | value | value | 21 |
| debit | 0 | none | 9 |
| debit | value | none | 7 |
| debit | value | value | 19 |

`slot-calls.tsv` lists 55 slot calls of the other four writers.

### Differences from the reference lead

`reference-diff.tsv` lists 8, each with a case. The largest: credit raises only total, so the word the reference calls `available` is a hold; notional changes on credit, and on debit when it is 0, and through f64 rather than `u128`; sweeps delete rows.

## Implementation and comparison

not yet implemented. There is no Rust code in this packet. The rule list in `tools/spot_balance_ledger.py` is a Python comparison model against real instructions.

## Results and limitations

- 2773 named cases and 200 step sequences match on the first full model, apart from fixture words. 63 tests pass. A second full run of the tool under another hash seed, zone and PATH did not finish before the deadline (it was stopped on a loaded server), so that check is not done. 11 of 13 evidence files match byte for byte an earlier full run with the default environment; update-call-summary.tsv, update-calls.tsv differ because the call class scan changed between those runs.
- 360 byte edits of reached conditions, immediates and field displacements in the five functions: 338 killed, 22 survived:

- 6: equivalent: height word of a leaf handle, read only when a node splits to the root
- 4: equivalent: the hold word is written back to a row the next call deletes
- 2: not killed: a probe step of 17 still reaches the key or an empty byte in these tables
- 2: table reserve only: a larger reserve argument, no key or row changes
- 2: table reserve only: it changes when the table grows, not any key or row
- 1: equivalent: at this row the height is 0 or above 8 once a remainder of 1 to 7 was taken off
- 1: equivalent: past the high bound the unclamped conversion gives the same MAX through the cmova
- 1: equivalent: pshufd over a register whose dwords are all equal
- 1: equivalent: same unrolled step as the row before
- 1: equivalent: the clamp of an in-range value is that value, and past the low bound the conversion gives a negative word that stores 0
- 1: first leaf only: any nonzero word reads as a leaf that is not empty, and the walk starts at slot 0

- 4376 bytes, 1016 instructions. 10 rows stay unreached, all in `user_sweep`: the hold subtraction underflow (the hold was just raised by the same amount), the second total panic, and the empty iterator panic.
- Rules hold on the cases run; they are not proved for all inputs. The f64 path is compared against Python floats, which round the same way.
- Unresolved: what fills the `price` argument at each of the 40 sites that pass one (a merged packet reads one source at `0x2710e30`); the writer of the info row; which caller passes which user map to `user_sweep`; what `S+0x298` entry `+0x18` and `+0x40` hold. The `amount` of a `ledger_update` call and the row fetch order are observed only from these entries, not from callers.
