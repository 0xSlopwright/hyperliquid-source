# bridge: withdrawal route and fee split in node #94

With this packet a Rust build can follow one `withdraw3` from the dispatch arm to the last credit: which users take the routed path, what the routed path moves between dexes, how the fixed fee leaves the amount, and how that fee is shared over validators by stake.

- Component ID: bridge (`l1/bridge2.rs`, `l1/bridge_request.rs`); the handler is RE-010 row 47
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `546081f30a3ebe6af1dadb6f90869f01bd08e1e4`, `references/can1357-hl` as pinned there (searched for leads only, nothing copied)
- Claim status: observation for row order, offsets, status tags, constants and all outcomes in `cases.tsv`; inference for every name given to a field; unresolved items are under limits
- Scope included and excluded: included as real bytes are `0x1f67810`, `0x2732530` and their copies, `0x370da60`, `0x370d980`, `0x370db70`, `0x36f7560`, `0x370a3d0`, `0x36ff4f0`, `0x3364ed0`, `0x3be39b0`, the B-tree and sort code they reach, `0x272d000`, `0x272fe00`, `0x272f880`, `0x272d9f0`, `0x272d970` and their copies. Excluded, and stubs here: the core `0x2734200` (merged in `RE-004-withdraw-amount-gates-94`), the fee source `0x27101a0` (merged in `fees-transfer-gas-94`), the collection credit `0x37067b0`, the rate limiter, `0x270f6f0`, `0x2710110`, `0x272de40`, `0x2764a00`, margin `0x37d79e0`, the user row map `0x3596940` and its dirty sets

## Reproduce

```
python3 tools/bridge_withdraw_fee_route.py --out research/work-items/bridge-withdraw-fee-route-94
python3 -m unittest tests.test_bridge_withdraw_fee_route
```

Run from the repository root with Python 3 and the standard library; no external program is used and the binary is never executed. The tool reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, then steps instructions in a Python evaluator. A run took about 100 seconds with 4 workers.

## Evidence

Coordinates are virtual addresses. Function extents are FDE extents (`functions.tsv`).

### The route in front of the core

`0x1f67810` is the first call of RE-010 row 47. It calls `0x2732530` with flag `rcx = 0`, key `r8 = 0` and `r9` pointing at a record whose first word is 0, then maps status `0x186` to tag `0xd` and any other status to tag `0xe` with the 0x60 byte record at `+8`. `0x2732530` has no other caller.

Row byte `+0x3c` from `0x2755400` (the class), state bytes `+0x5b0`, `+0x5b1`, and for class 2 the word at `r9`, state byte `+0x3acb`, `rcx`, `r8` pick the path (`route-table.tsv`):

| Class | Condition | Path |
|---|---|---|
| 0, 1 | none | direct |
| 2 | bit 0 of `+0x5b1` set, or `*r9 < 2` (low 32 bits), or `+0x3acb` bit 0 clear, or `rcx` bit 0 set, or `r8 == 0` | direct |
| 2 | otherwise | mirror |
| 3 | bit 0 of `+0x5b1` clear | routed |
| 3 | bit 0 of `+0x5b1` set | direct |
| 4 and up | bit 0 of `+0x5b0` set | direct |
| 4 and up | bit 0 of `+0x5b0` clear | routed |

Since the wrapper passes `*r9 = 0` and `r8 = 0`, the mirror path has no reach from `withdraw3`.

Routed path, in order:

1. Row from map `+0x770` for the user. Two rate calls run, both always: `(row, now, +0x4e8, +0x4f0)` and `(row + 0x18, now, +0x4f8, +0x500)`.
2. Both false: status `0x170` and nothing else. One true is enough.
3. Row `+0x30` and state `+0x7d0` each rise by one, saturating.
4. If `rcx` bit 0 is clear, dex `r8` is looked up in the vector at `+0x5c0` (length `+0x5c8`, stride `0x2f0`); a missing dex panics with `0x141`. The route word is dex `+0x50`.
5. `0x272fe00` runs, then the core.
6. Class 4 calls `0x272f880`. Others call `0x272d000`, and a failure there is dropped.

The core status is not read in between: the step after the core always runs, and the record returned is always the core record.

### Fee debit

`0x370da60(out, dex, user, x, staking, tracker)` is called through slot `0x5774b20` from the three core copies (`call-sites.tsv`). The fee is dex `+0x250`; `x` and fee are unsigned.

1. `x <= fee`: `0x5c`, no read of the user.
2. Withdrawable `w` from `0x36f7560`.
3. `x` with the top bit set: panic.
4. `w < x`: `0x33`.
5. Row of the user lowered by `x` (saturating at `i64::MIN`), then the split of `fee`.
6. Dex `+0x238` lowered by `x - fee`, saturating. Output `+8` is `x - fee`, status `0x186`.

So the row loses `x`, the bridge record gets `x - fee`, and the core's `bal` falls by `x - fee` only.

Inference: dex `+0x238` is `total_net_deposit` in the fee settlement packet. It falls by `x - fee` and not by `x` because the fee stays inside the dex as row credits or collection.

`0x36f7560`: from the margin call (`mode 4`, byte dex `+0x2ed`) take `value`, `used`; `used` with the top bit set panics; `t = sat(value - used)`; `c` is word `+0x48` of the 0x50 byte entry for the user in the table at dex `+0x128` (0 when the table is empty, the key is absent, or the exempt test `0x37e4fb0` holds). Result `max(t, 0) - c`, floored at 0.

`0x370d980(out, dex, user, dest, x, fee, staking, tracker)` is the sibling with a caller fee, through slot `0x57749e8` from six sites. `x <= fee`: `0x5b`. Same `w` gates, then the sender loses `x`, `dest` gains `x - fee`, and the split runs only if `fee != 0`. Three sites pass a fee from a stack word and a caller destination; the first of them is `usdSend`, whose fee comes from `0x27101a0`. The other three pass 0 and a destination of twenty `0xff` bytes.

Status text from table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x5b` | Usd transfer is smaller than fee. |
| `0x5c` | Withdrawal is smaller than fee. |
| `0x33` | Insufficient balance for withdrawal. |
| `0x97` | Epoch state does not exist |
| `0x170` | Too many abstraction operations. Automated users should manually manage collateral. |
| `0x141` | Invalid perp DEX |
| `0x168` | Abstraction: {} |

### Fee split

`0x370db70(dex, fee, staking, tracker)` has only those two callers. `staking` is state `+0x3840`; from the staking work its `+0x30` is `epoch_states` and `+0x48` `active_epoch`.

1. `fee` with the top bit set: panic.
2. Find `active_epoch` in the tree. Absent: status `0x97`, recorded and not returned, and the whole fee is the rest.
3. Stake map `0x3364ed0`: for each validator (`[u8; 32]` key, 0x40 byte value) stake is the sum of the `u64` values of its delegation tree at value `+0`, by checked add, and a new tree key -> stake is built. This answers which field `0x3364ed0` turns into stake.
4. `total` is the checked sum of all stakes. `total == 0` skips the loop.
5. In key order, a zero stake is skipped. For the rest `share = stake as f64 / total as f64 * fee as f64`. A value that is not finite gives 0. Then clamp to the `i64` range and truncate (`f64` words in `evidence.json`).
6. `rest` falls by `share`, saturating with a recorder call, and the validator's `hot_user` (value `+0x18`) gets `share` through `0x36ff4f0`, on the user's row in this dex. A share of 0 still touches the row.
7. `rest != 0`: slot `0x5774918` with `(dex, 0, rest, tracker)`. That is the fee collection credit, second amount.

`fee` in the product stays the original `f64`, so shares do not depend on order. Row credit `0x36ff4f0` and debit `0x370a3d0` saturate at the `i64` edges (`locations.tsv` names `l1/src/qtys/mod.rs` and `impl_ntl.rs`).

The tree nodes read here, as offsets: epoch key `+8`, value `+0x60` stride `0x28`, count `+0x21a`, child `+0x220`; validator value `+0` stride `0x40`, key `+0x2c0`, count `+0x42a`, child `+0x430`; delegation value `+8`, key `+0x60`, count `+0x13e`, child `+0x140`; built stake tree key `+0`, value `+0x168`, count `+0x1c2`, child `+0x1c8`.

### What the routed path moves

`0x272d000(out, state, user, token, from_dex, from_index, to_dex, to_index, cap_flag, cap)`, 41 direct call sites:

1. State `+0x7d8` and row `+0x38` rise by one, saturating, whatever comes next.
2. Same side (`from_dex == to_dex` as whole words, and `from_dex == 0` or equal indexes): success, moved 0.
3. User in the tree at `+0x8d0`: success, moved 0.
4. If `to_dex` bit 0: dex `to_index` is looked up. Unless its byte `+0x230` is 3, `room = max(0, +0x1c0 - sat +0x238)`; word `+0x1c0` with the top bit panics.
5. Source: if `from_dex` bit 0, the dex must hold `token` at `+0x50`, else status `0x168` is dropped and the result is success, moved 0. Amount is `max(0, 0x57738b8(dex, user, 4, +0x2ed))`. Otherwise the spot row: `(total - hold) / 100` for `token`, 0 when absent, and when `hold > total` a recorder call and 0.
6. Moved is the least of the amount, `room` when there is one, and `cap` when bit 0 of `cap_flag` is set. Moved 0 is success.
7. Out step `0x270f6f0(.., 1, moved)` on the source dex; failure gives `0x168` with the error as text. In step `0x270f6f0(.., 0, moved)` on the target dex; its token check gives `0x168` with the text `token mismatch` (so `Abstraction: token mismatch` when printed) with no undo, and a failure undoes through `0x2710110` and gives `0x168` with text.

`0x272fe00(state, user, token, to_dex, to_index, r9, special)`: when `special` is set and state `+0x568` holds a tree, `token` is searched in it. `0x272de40` runs with that bit; its vector is freed when the capacity word, without the top bit, is not 0. `special` set (class 4): tail call of `0x272d9f0`. Otherwise `0x272d000` with source spot, no cap, and a failure is dropped.

The `r9` word is the first word of a tagged record, not a count: `(tag, key, word)`. `0x272d9f0(state, user, token, to_dex, to_index, record, flag)` reads it. `listed` below means the token is in the tree at state `+0x568`, and `op(m)` is `0x2764a00` with mode `m`, the flag byte, and a dropped failure:

| Tag | Steps before the final transfer |
|---|---|
| 2 | if listed: `op(3)`, `op(0)` |
| 1, 3 | if `key` is in the tree: `op(3)` on `key` with `word` and extra `1`, and a failure here stops with no transfer; then if listed: `op(3)` |
| 0, 4 and up | if listed: `op(3)` |

The final step is `0x272d000` from spot to `(to_dex, to_index)` with no cap, failure dropped. From `withdraw3` the tag is 0 and the flag byte is 0.

`0x272f880(state, user, token, from_dex, from_index)` runs after the core for class 4: `0x272d000` from that dex back to spot, no cap, failure dropped, then if listed `op(2)` and `op(1)`, each failure dropped. So a class 4 user pulls collateral in from spot before the core and sweeps what is left back after it.

### Copies

`0x4d3d7e0` and `0x4d3fc00` repeat the route with other register choices, called from wrappers `0x47b8810` and `0x47b8760`, and each has its own helper copies. `copy-calls.tsv` pairs their 17 calls. The second copy moves every state offset from `+0x5b8` up by `+0xa80`, as in the core. In `0x46ea0b0` the text map `0x272d970` is inlined. All route, helper, prepare, finish and tail cases run on all three copies.

## Implementation and comparison

not yet implemented. The tool holds a rule list `Spec`, written apart from the bytes, that predicts the event list, row words and result of each run.

| Reference (`47_withdraw3.rs`, `39_usd_send.rs`) | Bytes |
|---|---|
| A routed core failure returns at once | The step after the core always runs |
| A failed post step replaces the result | It is dropped; the core record stands |
| Mirrored path reconciles first and rejects on failure | The failure is dropped and the core runs |
| Status 368 for a dual membership miss | Status `0x170` rate limit; either window passes |
| Mirrored path reachable with a route key | The wrapper passes key 0 and tag 0 |
| `routed_count` compared with 2 | First word of a tagged record; `0x272d9f0` branches on its tag |
| `finalize_privileged_routed_withdraw`, unnamed steps | Sweep back to spot, then `op(2)`, `op(1)` when the token is listed |
| Fee recipients are a configured weight list | Live validators of the active epoch, weight is the sum of delegations |
| One residual fee recipient user | Rest goes to the collection credit of the dex |
| Fee 0 returns before the loop | The debit walks the loop with shares of 0; only the transfer sibling skips it |

## Results and limitations

| metric | value |
| --- | --- |
| Cases | 1860 |
| Mismatches | 0 |
| Instructions stepped | 2,147,654 |
| Stepped / total, withdraw3 wrapper `0x1f67810` | 44 / 44 |
| Stepped / total, class route `0x2732530` | 266 / 287 |
| Stepped / total, withdraw fee debit `0x370da60` | 70 / 70 |
| Stepped / total, transfer with a caller fee `0x370d980` | 60 / 60 |
| Stepped / total, fee split `0x370db70` | 305 / 394 |
| Stepped / total, withdrawable word `0x36f7560` | 114 / 114 |
| Stepped / total, row debit `0x370a3d0` | 75 / 81 |
| Stepped / total, row credit `0x36ff4f0` | 74 / 80 |
| Stepped / total, stake map `0x3364ed0` | 107 / 142 |
| Stepped / total, stake sum fold `0x3be39b0` | 194 / 290 |
| Stepped / total, dex transfer helper `0x272d000` | 411 / 472 |
| Stepped / total, routed prepare `0x272fe00` | 118 / 119 |
| Stepped / total, error text map `0x272d970` | 23 / 29 |
| Stepped / total, class 4 finish `0x272f880` | 120 / 121 |
| Stepped / total, class 4 prepare tail `0x272d9f0` | 228 / 230 |
| Stepped / total, route copy `0x4d3d7e0` | 275 / 296 |
| Stepped / total, route copy `0x4d3fc00` | 275 / 296 |
| Stepped / total, wrapper copy `0x47b8810` | 44 / 44 |
| Stepped / total, wrapper copy `0x47b8760` | 44 / 44 |
| Stepped / total, transfer helper copy `0x46eaa10` | 411 / 472 |
| Stepped / total, transfer helper copy `0x46ea0b0` | 417 / 470 |
| Stepped / total, prepare copy `0x46ef9a0` | 118 / 119 |
| Stepped / total, prepare copy `0x46efb70` | 118 / 119 |
| Stepped / total, finish copy `0x46ef720` | 120 / 121 |
| Stepped / total, finish copy `0x46ef4a0` | 120 / 121 |
| Stepped / total, tail copy `0x46eb850` | 228 / 230 |
| Stepped / total, tail copy `0x46eb400` | 228 / 230 |
| Mutants killed / survived / unreached | 684 / 55 / 100 |

Example from `share-vectors.tsv`, label `split/epoch_found_three`: fee 1000000 over stakes 100, 200, 700 credits 100000, 200000, 700000 with rest 0. Fee 1 over the same stakes truncates every share to 0 and the rest is 1. Fee `2^53 + 1` credits `2^53 - 1` with rest 2, because `fee as f64` rounds.

- Every case matches with 0 mismatches, 345 of them split vectors; each compares the event list, row words, outputs and, for the split, freed nodes.
- The mutant control is the same compare under a step limit: every case must pass it first. Mutants are bit flips on conditions, immediates and field offsets of the 15 listed functions, run on the named cases that reach the row plus a sample.
- The 55 survivors and 100 unreached rows carry a class in `mutations.tsv`, by count: float clamp that gives the same value on every finite input 5, repeat of a bounds test that already passed 3, saturation arm whose word another minimum hides 2, sort size choice with the same sorted result 2, table probe word behind a stubbed hash 5, text byte a later store overwrites 2, tree walk bound or height word that ends at the same key on these fixtures 28, vector or iterator word 8. The classes are labels from reading each row, not proofs.

Limits:

- The value of dex `+0x250` is state. A store with that displacement sits at `0x2356c6e` in the vote function `0x2355f40`, read by hand and not traced to its base register, which fits the open bridge settings packet. The `1000000` here is a fixture word.
- `0x36f7560` and `0x57738b8` depend on margin words given by stubs.
- `0x2764a00`, `0x272de40` and `0x270f6f0` are stubs, so this packet does not show what those steps do to balances. The rate limiter is a stub with scripted results.
- The dirty set arms of the row helpers need the watched word `+0x20` to change during the set insert; no real caller is shown to do so. Those arms run only with a stub that writes the word.
- Trees of height 8 or more are not built; the eight-step descent rows stay unreached.
- `hot_user`, `delegation`, `active_epoch` come from the staking packets and the reference; this path only shows offsets.
- The hosts of the copies, `0x4d84170` and `0x4d83050`, are not read, and neither is the host `0x274fd60` of the all ones transfer beyond its setup.
- Class byte values are not named here.
