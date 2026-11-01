# RE-006: the node #94 perp order insert from gates to the reduce-only sweeps

This packet maps the whole perp insert `0x4311140` and its twin `0x4314da0`: every gate with its error text, the walk through the match core, the pull retry, what each match reason does, the rest, and two reduce-only sweeps that run after every insert and that the reference does not have at all, so a reconstruction can write the perp taker path from bytes and knows that a fill can shrink or cancel other resting orders of both parties.

- Component ID: RE-006 (book state transitions), the perp insert path
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference sketch is `l1/book/book/impl_insert_order.rs`; it was a lead only and differs from the bytes as listed.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants: `0x4311140` up to its unwind pads at `0x4314a28`, the retain test `0x43375e0` and the fill user pair `0x4a07df0`. Run on real bytes with the same cases and no mutants: the twin `0x4314da0` and its retain `0x48803f0`, retain `0x486e260`, level iterator `0x4894200`, set insert `0x4941fe0`, user map insert `0x4958ab0`, the local drops `0x433e5a0`, `0x49b05e0`. Stubbed at the edge, each with its arguments logged: every other callee, listed under Edges. Excluded: edge bodies, including the match core (#100) and fill settlement `0x3710a70` (#1066). The third copy `0x26ebdc0` is not run: #235 lists its statuses and leaves the walk open, and #47 names the spot body `0x430d610`. `0x4311140` and `0x4314da0` appear in other packets only as caller or inventory rows.

## Reproduce

From the repository root:

```
python3 tools/perp_order_insert.py --out research/work-items/RE-006-perp-order-insert-94
python3 -m unittest tests.test_perp_order_insert
```

The tool takes about 230 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `cases.tsv`, `mutations.tsv`. Addresses are ELF virtual addresses. Function ends come from `.eh_frame`. Offsets written `order+n` are in the order record the function receives by pointer, `state+n` in the exchange state, `market+n` in the row at `state+0x1040 + dex * 0x2f0`, `slot+n` in a `0xf8` slab row.

## Evidence

### Call shape

`rdi` result, `rsi` book, `rdx` order record, `ecx` and `r8d` two words copied into the taker record, `r9` exchange state, first stack word the row sink. `dex` = asset / 10000, `index` = asset % 10000. Callers are listed in `evidence.json` under `callers`.

### The two bodies

Same 2974 decoded rows, 0 shape differences (`twin`). They differ in seven call targets, among them match `0x431c530` / `0x431d020`, and in one state block: fields from `+0x1038` up sit `0xa80` lower in the twin (`+0x1040` / `+0x5c0`, `+0x11c0` / `+0x740`, `+0x1370` / `+0x8f0`). All cases give the same result on both.

### Entry gates, in order

Status words have the top bit set; the low byte indexes the error Display table `0x5a572c` (`status_texts`).

| # | Test | Outcome |
| --- | --- | --- |
| 1 | dex below `state+0x1048` | panic `clearinghouses.rs:11` |
| 2 | asset not in set `market+0x270` | `0x17` "Halted" |
| 3 | `market+0x230` is 3, or position row of the user with tag nonzero, or no row and meta byte `+0x28` of the asset set | passes |
| 3a | otherwise by `state+0x1371`: 0 | `0x16` "Cross margin disabled" |
| 3b | 1 with `order+0x90` zero | `0x15` "Cross margin currently only supports reduce-only orders" |
| 3c | no row: dex differs from `market+0x30`, or index out of bound | panic `perp_meta.rs:194` |
| 4 | best opposite price against the limit, table `0x6eec88` | tif 0 crossing: `0x06` with two payload words. Tif 1, 3, 4 with no cross: `0x08` "Order could not immediately match". Tif 2: nothing |
| 5 | size tag `order+0` zero with reduce zero | panic `assertion failed: reduce_only` |
| 6 | reduce byte set | position absent, zero or same side: `0x05` "Reduce only order would increase position." Otherwise size becomes min(size, abs position), or abs position with no size |
| 7 | limit <= 10^15, limit % tick `0x42c7600` == 0 | else `0x00` "Price must be divisible by tick size." |
| 8 | oracle row bound | panic `oracle.rs:197` |
| 9 | gate `0x4cd8360(user, asset, side, size, px, row word +0x20)` | any word but `0x18` returns with both payload words |
| 10 | gate `0x3711d00` with a block of asset, size, px, user, side, taker only, crossed, `state+0x1370`, reduce | same |
| 11 | `order+0xa8` zero | oid = `state+0x38`, which adds 1 and stays at `u64::MAX` |

Crossing is inclusive and reads the first key of the opposite tree: bids `book+0x80` for side 1, asks `book+0x98` for side 0. Inference: `market+0x230` value 3 is the main dex (RE-004 packets), so the cross margin gate is for builder markets, which matches `hip3CrossMarginReduceOnly` and `hip3CrossMarginDisabled` in the status names of #1058. Row tag nonzero as isolated margin is an inference.

### Walk

```
for level in opposite tree in key order:
    px = |key|
    stop when px is worse than the limit (equal goes on)
    allowed = 0x3714e70(state+0x1372 byte, asset, side, px, time)
    false: no fill so far, status 0x13 "Price too far from oracle"
           fills: may not rest, a given oid clears through 0x42fbc60, end
    level head absent: panic impl_insert_order.rs:514
    for slot from head along +0x10/+0x18:
        bad index or vacant: panic :517
        r = match(asset, slot, state, taker record, budget)
        pull retry, see below
        budget = r +0x250
        fill present: settle, see below
        reason arm, see below
        status word in r +0x238 is OK:
            budget 0: end, may not rest; next link or next level
        not OK:
            no fills at all: the word returns with its two payload words
            fills: text buffer freed, budget 0 ends, else NEXT LEVEL, the rest of this level is skipped
```

The tree is never changed during the walk. Budget is taken from the match result, not computed here, and the fill size then comes off it.

### Pull retry

When the reason byte `r +0x258` is outside 1..=3 and the table `state+0x11c0` is not empty, the maker user is looked up there (stride `0x58`, byte `+0x54`). Byte 3 with `state+0x5b1` zero, or byte above 3 with `state+0x5b0` zero: `0x46efb70(state, maker, row word +0x50, 1, dex, 2, byte >= 4)` then the match runs **again on the same slot**, and the second result replaces the first. A text status in the first result is freed. A rest of the taker inserts the user in this same table through `0x327b210`. #926 and #1064 hold the pull as a step, this is its caller.

### Reason arms

Jump table `0x6eec9c`, four rows (`reason_table`), run after the fill.

| Byte | Row | Later effect |
| --- | --- | --- |
| 0 | kind 2, slot oid and user | removal with reason 5 `marginCanceled`, user noted |
| 1 | skip | cancel reason 10 `reduceOnlyCanceled`, user noted |
| 2 | skip | cancel reason 9 `selfTradeCanceled`, user noted |
| 3 | none | none |

Names are from `status_names.tsv` of #1058. `note user` adds the oid to the user map the result returns.

### One fill

Settle `0x3710a70` runs on the `0x238` record first, and the body reads size `+0x210` and px `+0x200` back after it. Then maker size minus size through `0x49e4de0`, with `book+0xd0`. Budget down, filled total up, each with a panic on wrap. `0x4a07df0` adds a leg user to the **flip set** when its tag `+0` / `+0x100` is 1, the old position `+8` / `+0x108` is nonzero, and sign class differs after adding size for leg 0 or minus size for leg 1. Closing counts. Opening from zero does not. Both leg users always go to the **touched set**. Maker at 0 adds removal kind 0, `book+0x78` = px, fill row pushed.

### End of the walk

As in the spot body: removal rows run `0x43051f0`, then kind 0 removes with reason 1, kind 2 with reason 5, kind 1 only the relation step. Skip rows follow in order, then the set is dropped. Budget end adds taker row kind 1 for a given oid, and a second one for tif 1, 3, 4. Levels used up or the limit reached add one only for tif 1, 3, 4.

### Rest

`allowed` again at the limit price. False: no fills `0x13`, fills clear the relation and give a status row. Reserve `0x3712650` not `0x18`: a given oid runs collect and relations once more, no fills returns the word, fills give a status row. Otherwise the level from `0x45a3890` (bids key `-px`, asks `+px`), slab insert `0x42e8710` with size tag 1 and resting size at `+0x28` and `+0xc8`, original at `+0xd0`, reduce at `+0xb0`, `+0xf4` = size tag xor 1. Head, old tail link (panic `:445`), oid map `0x488da60`, client id `0x342aa50` when `order+0x91` is set, user state, tracker. A reduce-only order is also pushed on list `r` of its user state through `0x454c870`, and the user joins the touched set.

Status row: `0x46f55a0`, `0x42fc2f0`, row kind 3 inner 2, skipped for `order+0x70` = 9. Result: fills, user map, oid at `+0x30`, client id at `+0x38`, byte `+0x49` set only for a fresh oid that rested. A status row gives no error even with status set: the fills stand.

### Sweep one: reduce-only list of every touched user

This runs in user key order, after the rest or status row, for every insert that filled or rested a reduce-only order. List `r` is the VecDeque at `+0x00` of the user state, which #842 saw only as a freed Vec.

```
retain 0x486e260 with test 0x43375e0, oldest first:
    oid not in book +0x28 table, bad index or vacant: dropped, no cancel
    position nonzero and long with slot side 1, or short with side 0: kept
    otherwise: joins the cancel list
the kept oids become the new list, head 0
total = 0
for each kept order:
    target = min(slot +0x28, abs position) when slot +0x20 is set, else abs position
    new size = min(target, size), written through 0x49e4de0 even when equal
    total += size
while list not empty and total > abs position:
    excess = total - abs position
    oldest size > excess: size -= excess, stop
    else pop oldest, total -= size, it joins the cancel list
each cancel list oid: 0x42f7420 reason 10
```

So the oldest reduce-only order pays first, and all the resting reduce-only orders of a user sum to at most the position after every touching insert.

### Sweep two: reduce-only triggers of every flipped user

In user key order. For each entry of tree `u` (`+0x38` of the user state, value stride `0xb8`, #842 names the field): byte `+0x90` must be 1, byte `+0x10` zero, and the key must not be the given oid. Position absent, zero, or `side == (szi <= 0)`: cancel with reason 10. So a trigger that would not reduce after the sign change goes. Offset `+0x90` as reduce only of a trigger is inference from this rule and the text of reason 10.

### Differences from the reference sketch

| Reference | Bytes of these bodies |
| --- | --- |
| `0x17` duplicate order, from an oid lookup | "Halted", from the set at `market+0x270`. No oid lookup |
| `0x15` slot empty for replace, `0x16` slot missing | The two cross margin gates |
| `0x13` no valid cross | "Price too far from oracle" |
| `0x05` no user price quantity, from a map keyed by user and oid | "Reduce only order would increase position.", from the position row of the asset; the same clamp shape |
| One match call per slot | A second call after the pull |
| No reduce-only list or trigger sweep | Both sweeps run after every insert with a fill |

### Edges

Stubs check their pointers, sizes and text, and log their arguments. Slot targets are in `slots`.

Timer `0x3379490`, positions `0x36f57f0`, tick `0x42c7600`, gates `0x4cd8360`, `0x3711d00`, `0x4a078a0`, `0x4a06ae0`, `0x4cd82d0`, allowed `0x3714e70`, hash `0x473bf50`, match `0x431c530`, `0x3332600`, pull `0x46efb70`, settle `0x3710a70`, size `0x49e4de0`, `0x4450210`, `0x43051f0`, `0x42fa880`, `0x42f7420`, `0x49b34a0`, `0x42fbc60`, `0x430d380`, reserve `0x3712650`, `0x45a3890`, `0x42e8710`, `0x488da60`, `0x342aa50`, `0x45a3b30`, `0x4931420`, `0x454c870`, `0x327b210`, `0x46f55a0`, `0x42fc2f0`, Vec grow helpers.

## Implementation and comparison

Not yet implemented in Rust. The comparison here is between the real bytes, run in the tool's evaluator with edges stubbed, and a separately written specification in the same tool. Both give the ordered edge calls, the result and the changed book words, and a test needs all three equal.

| Metric | Value |
| --- | --- |
| Cases | 362 |
| Mismatches | 0 |
| Instructions stepped | 499,427 |
| Stepped / total: perp insert body `0x4311140` | 2550 / 2974 |
| Stepped / total: retain test of one oid, mutated with the body `0x43375e0` | 119 / 128 |
| Stepped / total: retain of the reduce-only list, run with no mutants `0x486e260` | 136 / 153 |
| Stepped / total: user pair of a fill, mutated with the body `0x4a07df0` | 125 / 132 |
| Mutants killed / survived / unreached | 982 / 78 / 110 |

Of the 78 survivors, 54 have a class reason in `mutations.tsv` from reading the site: repeats of a bound already passed, words the retain makes certain, low bits of the divide and hash multipliers, flags only unwind pads read, saturating tails after a recorder that panics here. The other 24 carry the default text: most are tree and iterator details of multi level walks, such as field offsets of parent links and the unroll count of a descent, and they were read but not probed, so a real gap among them is possible. The 110 unreached rows are allocation failure, capacity overflow, tree descents of height 8 or more, long group probes and panic tails. A first pass with 341 cases left 98 survivors and 145 unreached; 21 cases added for those groups took them to 78 and 110.

Negative controls in `tests/test_perp_order_insert.py`: wrong digest, a short file, a mid-function start, an address outside every mapping, a `.bss` address, wrong pin bytes, a jump table row past the end, flipped branches at the budget test, the limit stop, the sweep excess and the trigger side, a changed status, and a changed manifest digest.

## Results and limitations

- All cases agree on both bodies in ordered edge calls, results and book words.
- Fake state only. Positions are a fixed table: settlement in a run does not move them, so the sweeps read the position the case gives. The sweep order after real settlement is by the call order in the bytes.
- The match core is a script here, so which reason it gives in which state comes from #100 and is not proved by this packet.
- The status texts bind by low byte to table `0x5a572c`. Status `0x06` has an arm with no plain text and tag 7 holds the plain post only text, so the name of `0x06` is inference. That these words reach this Display is read from other packets' use of the table.
- The meaning of table `state+0x11c0` and its byte `+0x54`, and of `state+0x5b0` and `+0x5b1`, is unresolved.
- The third copy `0x26ebdc0` has other size and was not run.

No progress gate is requested.

Next question: what do bytes `+0x54` of `state+0x11c0` and `state+0x5b0`, `+0x5b1` mean, and which maker states make the match core return reason 0, so that a maker is removed as `marginCanceled` after the pull?
