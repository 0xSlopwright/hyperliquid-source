# RE-007: the auto-deleverage core 0x36f7c40 on node #94

This packet shows how a shortfall becomes forced trades: a reconstruction can now write the step that decides whether ADL runs, picks target rows, walks the candidates from the highest rank, moves margin around the fills, writes the 0x248 byte fill rows, sweeps positive equity to the fee credit and repeats until a round makes no fill.

- Component ID: RE-007
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bytes, order of effects, gates and arithmetic; inference for field names beyond those in the log texts; unresolved items are listed in Results and limitations
- Scope included: core `0x36f7c40` whole (27626 bytes), with key remove `0x33ad470`, total update `0x36f7350`, map entries `0x33bb3e0`, `0x33bb000`, `0x33bb960`, and the tree walks, inserts and removes they call, run real
- Scope excluded: row map build `0x3bc3b00` and `0x3bc4080`, candidate collection and rank `0x33c58e0`, fill `0x36fe830`, value `0x37d77e0` (#950), summary `0x37d79e0`, fee credit `0x37067b0`. These are checked at their edge and stubbed

## Reproduce

```
python3 tools/adl_core.py --out research/work-items/RE-007-adl-core-94
python3 -m unittest tests.test_adl_core
```

Python 3 standard library plus `tools/fde_extents.py` and `tools/elf_index.py`. The tool checks the input digest first and takes about 90 s. It writes `evidence.json`, `path-map.tsv`, `text-sites.tsv`, `reference-diffs.tsv`, `samples.tsv` and `mutations.tsv`. Output is byte-identical between runs, under another hash setting and time zone, and with an empty `PATH`. The binary is never executed.

## Evidence

Addresses are virtual addresses in the file-backed sections of the target. Function bounds are exact `.eh_frame` FDE starts and ends. All numbers below come from `evidence.json`.

The core has no direct caller. One data slot, `0x5774998`, holds it, and `0x27078a0`, `0x4cf37f0` and `0x4cf94a0` call through that slot, so they share this body. Arguments: out, dex row, mode byte, exchange, oracle table, address set; on the stack the fee credit word and the pair (root, height) of a second address set.

### Names from the log texts

`text-sites.tsv` reads 6 texts from the bytes at their `lea` sites. They name what the registers hold at each site:

- `total_shortfall` is the sum in stage 2. `self.adl_shortfall_remaining` is the word at dex `+0x248`, the word the liquidation plan lowers.
- `asset_and_side_to_adl_requirements` is the map keyed (id, side), value a vector of target rows.
- `position_index` is words 0 and 1 of a row, and `margin_available` is word 2.

### Order of effects

`path-map.tsv` holds the 19 stages. In short:

1. Scan: each row's value, shortfall = max(0, -value). A row is immediate when its market byte `+0x28` is set or its address is in the second set. An immediate row is kept and does **not** add to the total.
2. Trigger: `total_shortfall >= adl_shortfall_remaining` (unsigned) replaces the list by every row. Otherwise only the immediate rows go on, so a total below the word leaves ADL to those rows alone. 0 against 0 takes the first arm.
3. Targets: one row for word 0 low dword 1, whatever its size or tag. Otherwise every tag 0 position with size != 0. Key side is `size <= 0`.
4. Walk: keys in order, rows in list order, candidates from the last key of the set. A dead candidate is removed. `|size| > |left|` keeps the candidate and closes the target; otherwise the candidate is removed and its whole size is taken.
5. Margin: only with dex `+0x2ec == 1`. Word 0 == 0 moves nothing. Low dword 1 moves oracle * size + raw margin; other words move summary word 0 - word 1. Amounts of 0 or less move nothing. The amount leaves before the first fill and comes back after it, in the same word, so the fill sees the account without it.
6. Fills: `fill(id, price, delta, target)`, then `fill(id, price, -delta, candidate)`. Any status but 0x186 panics.
7. Row: 0x248 bytes in key order, buyer side first: side 1 puts the target first, side 0 the candidate.
8. Sweep: in list order the value is read again. A value above 0 leaves the account (raw margin on a low dword 1 row, else the balance) and goes to `0x37067b0` with the outer word. This covers every row of the list, with or without a fill, so a listed account with money left does not keep it.
9. Rounds: both addresses of every row join the address set, rows move to out `+0`, and the whole thing runs again until a round makes no row, or at once when dex `+0x2ec != 1`.

The fill id at exchange `+0x38` moves on every match, also with settlement off. With settlement off the rows are freed and out `+0` is empty, while the id map at `+0x20` stays.

### What the walk does not check

- Candidate sign. A candidate with the target's sign is taken as is and grows `left`; the set from `0x33c58e0` is trusted. Case `candidate same side grows`.
- `left` is a local. It is never read back from the row, and the fill stub's size has no effect on the loop.
- Texts: all 6 texts are built into a list at stack `+0x1c8`, moved to `+0x190`, that is only pushed to and freed, on the normal path and on unwind. No byte of them leaves this body.

### Panics

`neg` for a value of i64::MIN, a `left` of i64::MIN that needs negating, or a delta of i64::MIN. `none` for a missing or empty candidate set with size left, a row id on another dex or past the market table, a bad oracle in the margin step, and notional above 2^63 - 2. `bounds` for an id past the oracle table. `unwrap` for a fill status other than 0x186, summary word 1 below 0, or a size of i64::MIN in a total. `text` for a tag bit that the row kind forbids.

### Inferences

- Word 0 is the enum of `position_index`: 0 for the whole cross account, 1 for one isolated position. Other values reach the summary arm of the margin step and no case shows who builds them.
- Key side 1 is a short target, so the first address of a fill row is the buyer.
- Market byte `+0x28` and the second address set mean "always deleverage". Their names are not in this body.
- Dex `+0x2ec` turns settlement on. `immediate adl` is a log name only.

## Implementation and comparison

Not yet implemented in the Rust tree. The comparison is between the real bytes, run in a Python evaluator built from ELF bytes, and a separate specification written from the reading. Every stub argument, text argument, fill row field, final account, total and map must match.

| Metric | Value |
|---|---|
| Cases | 223 |
| Outcomes | finished: 182, panic bounds: 5, panic neg: 2, panic none: 21, panic text: 8, panic unwrap: 5 |
| Mismatches | 0 |
| Instructions stepped | 1,172,281 |
| Stepped / total: core | 3389 / 5171 |
| Stepped / total: key remove | 105 / 122 |
| Stepped / total: total update | 83 / 132 |
| Stepped / total: id map entry | 60 / 80 |
| Stepped / total: key map entry | 63 / 73 |
| Stepped / total: final map entry | 66 / 73 |
| Mutants killed / survived / unreached | 287 / 63 / 155 |

## Results and limitations

- The rank order, the choice of side and the scan of users all live in `0x33c58e0`, a stub here. Sets in the cases are given, so this packet shows how they are consumed and nothing about how they are built.
- `0x3bc3b00` and `0x3bc4080` are stubs, so rows and their margin_available are given. Which users enter the map is not shown.
- `0x36fe830`, read as one fill, is a stub that moves the size and optional money. Fee, price and position effects are not claimed. `0x37d77e0` (#950), `0x37d79e0` and `0x37067b0` are stubs.
- Only the shared body is run. The three callers were not traced past the slot, so what `0x27078a0` passes as arguments 3, 6 and 8 is open. Whether out `+0` reaches the fill output is also open.
- Arms that cannot run: the default position in both margin steps, count, set and leverage changes around them, and the early end of the map walk. Reasons are in `mutations.tsv`. They were read, not run.
- The lazy-init Once arms and allocation failure are not stepped.
- One mutation site in 4 is run, in address order within each function, each over at most 4 cases, to keep a tool run short. So this is a sample and 62 of the 63 survivors are unclassified: `no case in the budget tells it apart`. They are not shown to be equivalent. 155 are unreached.

Next question: how does `0x33c58e0` rank the candidates of an (id, side) key?
