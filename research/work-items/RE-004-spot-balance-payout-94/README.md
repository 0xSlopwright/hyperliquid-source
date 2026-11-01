# RE-004: pro rata spot balance payout: stable sort, share scale, remainder walk and error texts in node #94

This packet shows how node #94 splits an amount across users by weight and pays it from the 0xee sentinel's token 0 row, so a reconstruction can write `normalize_wei_distribution` from the real order: stable sort, f64 share, floor drop, remainder to the largest row, and the five error texts of tag 0xfa.

- Component ID: RE-004 (quantities and rounding), Wei distribution
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `546081f30a3ebe6af1dadb6f90869f01bd08e1e4` / reference `references/can1357-hl`, `l1/qtys/impl_wei.rs:576`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are `normalize 0x37227a0`, `scale_fold 0x3308ab0`, `collect 0x3c1d1a0` and `pay_out 0x3720200`, run from their entries. The sort `0x3386fb0` and slot `0x5775df8`, tree copy `0x33e4b70`, vector builder `0x3badbe0`, the set insert `0x339b590`, the formatter and the map helpers run real as edges. `try_hold 0x371b140` is the subject of `RE-004-spot-balance-ledger-94`. Excluded: the second caller `0x3720a70` (genesis, in #449), the three block step callers of `pay_out`, and who builds the weight map

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/spot_balance_payout.py --out research/work-items/RE-004-spot-balance-payout-94
python3 -m unittest tests.test_spot_balance_payout
cd research/work-items/RE-004-spot-balance-payout-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and takes about 160 s at low load on this server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 1334 named cases and 200 random cases run real rows; a separately written rule list predicts rows, error objects, block counts and every balance. Hooks: allocator, copy, compare, overflow recorder `0x358dcd0`, the lazy cell call, and the clock pair `0x4ee3800`, `0x4ee3730`.

### `normalize(out, rows, target, floor, factor)`, `0x37227a0`

`rows` is a vector of 0x20-byte rows: 20-byte user, weight at `+0x18`. `factor` is in `xmm0`. Rows keep their buffer and are rewritten in place.

1. Stable sort, largest weight first. Below 21 rows the insertion sort `0x3386fb0`, else the slot `0x5775df8` sort.
2. `sum` of weights. Overflow or 0 gives tag 0xfa, `total balance of token is zero`.
3. `scale_fold 0x3308ab0` through `collect 0x3c1d1a0`: for each row `a = sat(trunc(f64(w)/f64(sum)*f64(target)))`. A share outside `0..=1.01` panics (no reached input does this). `a < floor` drops the row. A running sum overflow gives tag 0xfa, `error while computing existing token balances total_wei=Wei(d) marginal_wei=Wei(a)`, and the error object keeps `a` at `+0x20`.
4. No row left: tag 0xfa, `no user has wei after distributing`.
5. `target >= done`: the difference joins the first row, so the largest kept row takes all rounding dust.
6. `target < done`: this happens only through f64 rounding. Walk rows in order. `limit = sat(trunc(f64(a)*factor))`, `cut = min(excess, limit)`, `a -= cut`. The walk stops at the first row with `excess <= limit`. A factor outside `0..=1.01`, or NaN, skips the walk.
7. Excess left: tag 0xfa, `could not distribute remainder=Wei(e) to match exactly`.
8. The final sum is compared with `target`: otherwise tag 0xfa, `BUG: distributing to existing token final_allocation_check=Some(Wei(s)) target_wei_to_distribute=Wei(t)`, with `None` for an overflow.

Steps 5 and 6 always leave the sum equal to `target`, so step 8 was entered directly at `0x3722c05` with chosen rows (`final` cases). `error-texts.tsv` lists each text with its address.

### `pay_out(out, S, _, weights, target)`, `0x3720200`

`weights` is a tree of user to u64. An empty map gives an empty vector and the zero text. The tree is copied and turned into rows, then `normalize(rows, target, floor 0, factor 1.0)`; an error is copied to `out`. For each row in order:

1. `try_hold(sentinel, token 0, a)`. False ends the loop, and the function still returns OK with the users paid so far.
2. Sentinel row: total less `a`, hold less `a`. The third word stays.
3. User row for token 0: index entry, saturating total add. Hold and third word stay.
4. User added to the returned set.

Clock calls wrap the run; the elapsed value is dropped by these rows. Inference: `target` is the token 0 amount of the dust conversion, since the only callers are three copies of the block step that also calls `user_sweep`; the step itself was not run.

### Differences from the reference lead

`reference-diff.tsv` lists 8, each with a case. The reference has no scale step, sort or floor, and `pay_out` has no reference function.

## Implementation and comparison

not yet implemented. There is no Rust code in this packet. The rule list in `tools/spot_balance_payout.py` is a Python comparison model against real instructions.

## Results and limitations

- 1334 named cases and 200 random cases match. 39 tests pass. Two runs are byte identical, also with another hash seed, zone and a PATH with no binutils.
- 285 byte edits of reached conditions, immediates and field displacements: 240 killed, 45 survived:

- 13: padding: bytes of the error object that no tag 0xfa field uses
- 5: equivalent: token 0 stops the row scan at slot 0
- 4: equivalent: the clamp of an in-range value is that value
- 2: capacity bytes of a formatted text; the pointer and length are written after it
- 2: equivalent on reached values: only a NaN or infinity test, and the product is finite
- 2: equivalent on reached values: the slot still holds the OK word here, so no old error needs a drop
- 2: equivalent: both sort routes are stable and give the same order
- 2: equivalent: doubles at or above 2^63 have low bits clear, so the one bit shift of the mask changes nothing
- 2: equivalent: height word of a leaf handle, read only when a node splits to the root
- 2: not killed: bytes past the last index key never compare below the user in these trees
- 1: equivalent on reached values: a limit near 2^64 is far above any excess
- 1: equivalent on reached values: the row vector always has capacity here
- 1: equivalent: after a descending sort only trailing rows drop, so a kept row never moves and the word is already there
- 1: equivalent: back handle height word of the tree iterator, never read
- 1: equivalent: dead store, the capacity word of this return value is not read
- 1: equivalent: dead store, the error branch never reads this word
- 1: equivalent: the caller tests the error slot, not this flag
- 1: equivalent: the iterator start equals the buffer start at entry
- 1: equivalent: the product is never below zero

- 4857 bytes, 1019 instructions. 107 rows stay unreached: unwind and allocation failure rows, the share panic, the 0xbe overflow on step 5 (the sum after it is `target`), the hold underflow in step 2 of the walk, the amount clamp in the fold (a share of at most 1 times `target` stays under 2^64 after rounding), and the second total panic in `pay_out` (`try_hold` just proved the room).
- Reached rows are checked on the cases run, not proved for all inputs. Step 6 needs f64 rounding above the target, so cases sit near 2^60 to 2^64. The `cut > a` recorder at `0x3722a12` needs an excess above the largest row and was not reached.
- Unresolved: who builds `weights`, what fixes `target`, why the third word of paid rows stays at 0 while `ledger_update` would value them.
