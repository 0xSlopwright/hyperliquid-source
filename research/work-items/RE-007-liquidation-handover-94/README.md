# RE-007: the liquidation hand-over plan 0x36fff10 on node #94

This packet shows how a liquidated account actually moves to its liquidators: a reconstruction can now write the step that checks the receivers, simulates each receiver on a clone, refuses with 0x20, 0x21 or 0x22, commits the clones, clears the user and returns the rows the executor turns into events and orders.

- Component ID: RE-007
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bytes, order of effects, gates and arithmetic; inference for field names; unresolved items are listed in Results and limitations
- Scope included: plan `0x36fff10` whole, with position entry `0x33bd420`, total entry `0x33bc4d0`, plan insert `0x3396940`, account clone `0x33de780`, plan row sort `0x3316d60`, clone insert `0x33c0ed0`, output insert `0x33c2600`, and the map iterators, node splits and drops they use
- Scope excluded: the bodies of `0x37d7360`, `0x37d77e0` (#950), `0x37d79e0`, `0x3bd1220` (#746) and its closure `0x37615c0` (#954). These are checked at their edge and stubbed

## Reproduce

```
python3 tools/liquidation_handover.py --out research/work-items/RE-007-liquidation-handover-94
python3 -m unittest tests.test_liquidation_handover
```

Python 3 standard library plus `tools/fde_extents.py` and `tools/elf_index.py`. The tool checks the input digest first and takes about 300 s. It writes `evidence.json`, `path-map.tsv`, `status-texts.tsv`, `reference-diffs.tsv`, `samples.tsv` and `mutations.tsv`. Nothing is executed from the target: instructions are decoded from ELF bytes and stepped in a Python evaluator. No objdump or readelf output is parsed.

## Evidence

Addresses are virtual addresses in the file-backed sections of the target. Function bounds are exact `.eh_frame` FDE starts and ends. All numbers below come from `evidence.json`.

The plan has no direct caller. One data slot, `0x5774ac8`, holds it, and the 3 executor copies `0x2725150`, `0x4d2b3c0` and `0x4d2cd20` call through that slot, so all three share this body. Arguments are out, dex row, user, flag, id, route and the exchange on the stack. The route is an address vector at +0, a map of id to address at +0x18 and the default address at +0x30.

### Refusals

`status-texts.tsv` reads each message from the Display table at `0x59a8d0`:

| Status | Text | Words | Raised by |
|---|---|---|---|
| 0x20 (32) | `Position is not liquidatable: ` | user, flag, id | no matching row in the list of `0x37d7360` |
| 0x21 (33) | `Liquidator must use cross margin for asset ` | id | a receiver row of tag 1 with size or margin != 0 |
| 0x22 (34) | `Liquidator does not have enough margin available.` | none | a clone with word 0 - word 1 below 0 |

So position tag 1 is isolated, and flag 0 matches on word 0 alone: the list row's id word is not read in that arm.

### Order of effects

`path-map.tsv` holds all 15 stages.

1. Every route address gets a row for every market id of the dex, before any amount moves. An empty row of tag 1 is rewritten as tag 0, leverage 20, with +0x38 = 50. A missing id takes its default from `0x3bfffd0`, and a default of tag 1 is rewritten the same way.
2. `0x37d77e0` gives one signed word, kept to the end.
3. Isolated, when bit 0 of the flag is set: one plan row, id -> (size, margin at +0x8, oracle x size). The oracle is at dex +0x68 + (id % 10000) x 0x60, word +0x20.
4. Cross: `0x37d79e0` words 0 and 2 go to `0x3bd1220`, which returns rows (id, size, middle word, value). The word left in summary word 0 is added to the first row's middle word. With no rows it stays and goes to the default receiver.
5. The receiver of an id is the route map's value, else the default address. Each receiver works on a clone: size += row size, balance += middle word, all saturating with a log. A size change clears +0x28, a sign change clears +0x20, and the open count follows 0 to nonzero and back.
6. The gate runs on every clone in address order. On 0x22 the clones are dropped, and no account is replaced.
7. One output row per receiver, in address order, with an id from exchange +0x40 taken in plan order. Row +0x30 sums |value| as u64 and row +0x38 sums value + middle word, both saturating. The remainder adds to +0x38 of the default row, and creates that row if needed.
8. Each clone replaces its account. Old sizes leave the id totals and new sizes enter them, and an id with new leverage moves its note under +0x128.
9. The user is cleared. Isolated clears that one row and keeps the balance. Cross clears size on every tag 0 row, keeps the rows, keeps isolated rows and sets balance 0.
10. Sets +0x158 and +0x188 are updated, and a negative word from step 2 lowers dex +0x248 by its size, floor 0.

`samples.tsv` shows these on real runs.

### Inferences

- Tag 0 is cross and tag 1 isolated, from the 0x21 text and the isolated arm. Tag 0 in the isolated arm panics.
- `0x37d77e0` is read as account value, because `0x2725150` reads row +0x38 as `accountValue` and row +0x38 is the sum of value + middle word. The word itself is not modelled here.
- The middle word is the balance change of the receiver for that row. With value + middle word summing to row +0x38, the receiver takes the position at oracle value and pays the difference in balance.
- Dex +0x170 holds a total of |size| by id, +0x158 the users with an open count above 0, +0x188 users touched by this path, and +0x128 a per-user note keyed by id. +0x248 is unnamed. Its fall by a negative account value fits an accumulated loss, and that use is not shown.
- Flag 2 would be the `None` niche of the row enum: `0x3bb0970` stops at a row with word 0 == 2, which matches the executor's stop in the earlier liquidate packet. The action handler only ever sends 0 or 1.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison here is byte evaluation against a separately written Python specification, not a Rust build.

A case compares outward calls in order, their arguments, frees, status, words, output rows, the id counter, dex +0x248, overflow logs, and every final account and id total read back from memory. Real helpers and stubbed edges are listed in `evidence.json`.

| Metric | Value |
|---|---|
| Cases | 203 |
| Outcomes | panic bounds: 1, panic mul: 1, panic neg: 2, panic none: 3, panic text: 3, panic unwrap: 4, status 0x186: 166, status 0x20: 7, status 0x21: 7, status 0x22: 9 |
| Mismatches | 0 |
| Instructions stepped | 1,586,337 |
| Stepped / total: plan | 2354 / 3238 |
| Stepped / total: position entry | 95 / 104 |
| Stepped / total: total entry | 57 / 64 |
| Stepped / total: plan insert | 45 / 105 |
| Stepped / total: account clone | 57 / 70 |
| Stepped / total: plan rows sort | 117 / 140 |
| Stepped / total: clone insert | 89 / 109 |
| Stepped / total: output insert | 84 / 110 |
| Mutants killed / survived / unreached | 971 / 203 / 349 |

`reference-diffs.tsv` lists 5 points where `l1/exchange/handlers/10_liquidate.rs` has no counterpart: the plan body and these three statuses are absent from it. The reference is only a lead and nothing was copied from it.

Mutation pass: each condition, immediate and field offset of the 8 listed bodies is flipped alone. A mutant runs over at most 14 reaching cases to keep the tool short, half the cheapest and half spaced evenly over the rest, plus recent killers. 203 survived and 349 were not reached. Each has a reason in `mutations.tsv`; the reasons are class readings by instruction kind, not a proof for each mutant. 67 survivors carry the general reason that no case in the budget tells them apart: they are unexplained, not shown equivalent.

## Results and limitations

- 0 mismatches. This covers the listed bodies. It does not cover how the cross rows are computed: `0x3bd1220` is bound by open #746, so its rows here are fixtures and the share rule is not claimed.
- `0x37d7360`, `0x37d77e0` and `0x37d79e0` are stubs. Which accounts are eligible is not shown, only how the plan reads the list.
- On 0x21 and 0x22 the rows and set adds from stage 2 stay, and this body does not undo them. Whether a caller rolls back is not traced.
- The bookkeeping arms at `0x370034b` and `0x3700702` cannot run: size is unchanged in that loop. A row with +0x50 == 0 ends the commit walk, a fixture case only, since the clone keeps that word.
- A panic in `0x33bd420` or the plan for an id past 9999 of a dex is not exercised. The add overflow panic needs 1616 or more markets and is not reached.
- Height 8 or more is not built. Drive sort for 21 or more rows, `0x3bbfb90`, is not reached.
- The two stub-derived words used by the clone gate are a fixture rule, so the gate is shown as a sign test on the two words and not as a margin formula.
- No progress gate is requested.

Next question: what does `0x37d79e0` return in words 0, 1 and 2 for a clone, so that the receiver gate of stage 8 can be read as a margin rule?
