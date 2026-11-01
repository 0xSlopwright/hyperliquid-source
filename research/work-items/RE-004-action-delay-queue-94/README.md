# RE-004: action delay queue in node #94: linear delay curve, enqueue host, window gate, release, wipe and delayer votes

This packet shows that an action's delay is a clamped linear ramp built on a fused multiply add, keyed by the chain byte, and gives the whole queue path from the enqueue wrapper to release, so a reconstruction can drop the reference's `powf` curve and its queue keyed by action id, and write `action_delayer` as a time-keyed B-tree of 0x148-byte records with a total cap, a user cap of 100 and strictly-below-now release.

- Component ID: RE-004 (quantities and rounding), action delay arithmetic
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `cec50f68e01c967d21538d48c49683ddeea52767` / reference `references/can1357-hl`, `l1/action_delayer.rs`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the curve `0x392fab0`, the enqueue host `0x392c200`, the window gate `0x392d140`, the release `0x392ce80`, the classifier `0x3362e60`, the enqueue wrapper `0x27584a0` with copies `0x4d81290`, `0x4d81660`, the tail of `0x2207f30` from `0x2208481`, and the vote arms for words 79, 104, 106 and 108 in all three dispatchers. The fold `0x3be4e20` of `RE-004-vty-tracker-94` (where the curve was a hook), the time add `0x1459ca0`, chrono, the parser, the set iterators and the B-tree code run real as edges and are not claimed. `action-delayer-inventory-94` and `foundation-duration-guards-94` pin bytes of the curve and leave its data flow open; this packet answers that item. The FMA body, the action clone `0x39fe700`, the action drop `0x3bbba10`, the error drop `0x3999770`, the four classifier arms through slots `0x5775c30..48`, the run-now call and the row call of the wrappers, and the copy b notify slot `0x5776688` are stubs that check their arguments. Excluded: what the four classifier arms compute (see `RE-004-priority-admission-94`), the runner of released actions `0x2519470`, the status writer around `0x392fcc0`, word 105 (read by eye, below)

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/action_delay_queue.py --out research/work-items/RE-004-action-delay-queue-94
python3 -m unittest tests.test_action_delay_queue
cd research/work-items/RE-004-action-delay-queue-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took 120 to 450 s depending on load on this server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents, or the arm windows listed in `function-rows.tsv`. 2031 named cases and 200 random cases run real rows; a separately written rule list predicts results, queue rows, user rows, counters, every other fixture byte, and that no input block is left unfreed. Subject code is 1584 instructions in 7891 bytes.

### Fields

Serde keys in `field-names.tsv` give the names by offset from `action_delayer` (`S+0x31b8`; `S+0x3c38` in wrapper b and dispatcher c):

| Offset | Key | Form |
| --- | --- | --- |
| `+0x00` | `delayer_mode` | tag 0 `Enabled`; tag 1 `PerAsset`, B-tree at `+0x08` of u32 to u64 |
| `+0x20` | `status_guard` | not touched by this path |
| `+0x30` | `delayed_actions` | B-tree of 12-byte time to Vec of 0x148-byte records |
| `+0x48` | `user_to_n_delayed_actions` | B-tree of 20-byte user to u64 |
| `+0x60` | `n_total_delayed_actions` | u64 |
| `+0x68` | `max_n_delayed_actions` | u64 |
| `+0x70` | `vty_trackers` | read through `0x3be4e20` and inline |
| `+0x88` | `delay_scale` | f64 |

Record map: `+0x00` expiry present, `+0x08` expiry ms, `+0x10` action clone, `+0x100` word `S+0x28`, `+0x108` option at `S` or 0, `+0x110` user, `+0x124` byte argument, `+0x125` flag byte, `+0x126` 32 bytes after the flag.

### Curve, `0x392fab0(byte, kind, v)`

Slot `0x576f6e0` reaches `0x565f8c0`, an indirect call through `0x57882e8` whose resolver picks `vfmadd213sd`, an FMA4 form or a software path (three inputs, one result). So the call is `fma(v, 10000, c)`, not a power.

```text
byte < 2:                    w = fma(v, 1e4, -4) / 20,   slope 1.3
byte = 2, kind in 3 4 11054 11137:  w = fma(v, 1e4, -1.5) * 0.125, slope 1.8
byte = 2, kind = 0:          w = fma(v, 1e4, -3) / 12,   slope 1.8
byte > 2, kind in 0 1 10142 10151:  w = fma(v, 1e4, -1.5) * 0.125, slope 1.8
byte > 2, kind = 5:          w = fma(v, 1e4, -3) / 12,   slope 1.8
otherwise:                   as byte < 2
finite w: max(0, w), then at most 1
y = w * slope + 0.76
result = y * 0.65, or y * 0.2 for the default curve when kind >= 1e8 or 10000 <= kind < 110000
```

The default ramp starts at `v = 0.0004` and tops out at `v = 0.0024`. A positive infinity skips the clamp and stays infinite. NaN and negative infinity reach `assertion failed: self >= 0.`. The byte argument is the chain byte: the wrappers read `S+0x8f2` (`S+0x1372` in copy b) into the parameter block, and the host passes that byte to the curve and the fold.

### Enqueue, `0x392c200(out, delayer, params)`

The wrapper builds a parameter block from the state and its arguments. Checks run in this order:

1. Classify the action through `0x3362e60`: `classifier-table.tsv` lists the arms. Result: base f64 and two u32 sets. With the flag byte's bit 0 clear, an error is dropped and the base is 0.2.
2. With bit 0 set, gate `0x392d140` runs instead: a classifier error runs the action now, and `PerAsset` runs it now when each id of the merged sets either has no width or has a non-zero width `w` with `seconds / w` odd, where `seconds` is `max(0, unix seconds)`. An empty set passes. `Enabled` never passes.
3. Delay is `maxsd(fold over set 1, base)`. A set key with no tracker counts 0.001; an empty set counts 0.
4. Negative or NaN delay panics, negative or NaN scale panics. `delay * scale` not above 0 runs the action now.
5. `n_total >= max`: tag 0x13a. So `max = 0` refuses every delayed action.
6. Get or insert the user row at 0. Count above 99: tag 0x13b.
7. Due time is now plus the f64 through `0x1459ca0`, no rounding to seconds. With an expiry word, `ms(due) > word`: tag 0xca, and the zero user row stays.
8. Push the record on the Vec at the due time, then saturating +1 on the user row and on the total. Result code 0x0c with `S+0x28`, the option at `S`, the due time.

Wrapper result: an inner 0x0f becomes outer 0x0e with the error object. Inner 0x0e calls the run-now function; with the hash flag byte not 1 it first adds 1 to `S+0x50` and holds `S+0x78 = 1` over the call. Copy b alone then calls slot `0x5776688` (`0x4857370`) with the user, the counter, the 32 bytes and the action. The tag 0xca debit of `fees-request-budget-94` is run here as an edge.

### Release, `0x392ce80(out, delayer, now)`, and wipe

`0x2209e85` and two copies call it with the 12 bytes at `S+0x60`. Keys strictly below now leave, a key equal to now stays, records come out in key order then arrival order. Total is saturating minus the count. Each record then takes 1 from its user row, floor 0, and a row at 0 is removed; a missing row is skipped. The tail of `0x2207f30` drops both maps and zeroes the total, keeping `delayer_mode`, max and scale.

### Votes

| Word | Rule | Refusal |
| --- | --- | --- |
| 79 | chain byte not 3, `x < 0x0ccc...`, `100 <= x <= 300000`, store `+0x68` | 0x8d, 0x13f with x, 0x13c |
| 104 | chain byte not 3, drop the map, tag 0 | 0x8d |
| 106 | chain byte not 3, text at most 100 bytes, `0 < x <= 2`, store `+0x88` | 0x8d, 0x143, parse tag, 0x13f |
| 108 | any chain; third, first, second text parsed in that order; `0.01 <= a <= b <= 1`, `0 < d <= 0.01`, store `S+0x3660`, `+0x3668`, `+0x3670` | 0x143, parse tag, 0x140 |

Word 105, read by eye and not run: refuses chain byte 3, decodes each id through `0x1e80370` and slot `0x5773950`, builds the map, and when the new map is empty also wipes both queue maps and the total, then stores tag 1.

Tag texts are in `tag-texts.tsv`, constants in `constants.tsv`, the three wrapper offsets and three dispatcher offsets in `copies.tsv`.

## Implementation and comparison

not yet implemented

`reference-diff.tsv` lists 11 differences from the lead, each with a case in `outcomes.tsv`. The largest: `powf` is a misread FMA, the queue key is the time and not the action id, max 0 refuses, and `delayer_mode` has two tags and does not select the curve.

## Results and limitations

- 2031 named and 200 random cases match the rule list. Inference: "chain byte" for `S+0x8f2` rests on earlier packets; tag 0x8d at value 3 agrees with it. Inference: the meaning of the flag and the 32 bytes.
- Mutation: 561 byte edits of conditional rows, immediates and field offsets on rows the cases reach, 468 killed, 93 survived (per edit in `mutations.tsv`):

- 11: same: these rows copy words behind the code and tag of the result, which the path leaves unset
- 11: same: with an empty map the walk only drains the iterators and always ends in result 1
- 10: same: height word of a tree iterator handle, read only when it climbs from an empty handle
- 10: same: only years at or below 0 use this constant and the seconds floor at 0
- 8: not killed: a node length or scan bound of a B-tree search; the fixtures hold a key that stops the scan first
- 8: not killed: the edited peek state of the two set iterators still visits every id in the cases run, and the result depends only on the ids
- 5: same: a zero set root drains nothing, so its length and height words are unread
- 4: same except at one value: the edit moves the finite test by one step at the largest finite weight, which no case holds
- 4: same: the fields written on this classifier error are unread once the gate returns 1
- 3: same: index 0, index 0x14 and the edited index all reach the zero arm of the table
- 3: same: panic message length, the panic text is not compared
- 2: same: one bit in the last place of the constant rounds to the same nanosecond in the cases run
- 2: same: sign fix of a division, positive for every year that reaches it above the floor
- 2: same: this compare only splits ids above the listed values, both sides end in the default curve
- 1: not explained: left open
- 1: not killed: the S+0x50 counter starts at 3 in every case, so its saturation is not run
- 1: same: a nonzero length with a zero root is the panic row, no case holds it
- 1: same: dangling pointer of an empty vector, never read
- 1: same: one extra copied byte is padding at the end of the record
- 1: same: the edited word is also nonzero or zero like the tag on cases run, and the drop of a zero root is empty
- 1: same: the gate reads date and seconds only, this copies the nanosecond word
- 1: same: the row is removed right after this store
- 1: same: the saturated value needs a count of u64::MAX, and the caps stop counts before that
- 1: same: this branch only runs for a row just inserted at 0

- `evidence.json` lists 59 unreached rows: landing pads, panic rows for values the arithmetic cannot make, and the `0x235dd56` path for a NaN first bound (text never parses to NaN).
- The curve is checked at the ramp ends, one ulp either side, and at chosen and random points, for 6 bytes and 23 kinds; it is not proved for all 2^64 inputs. FMA is computed exactly in Python in the stub, so results are for correct rounding.
- Trees above the tested heights rest on real code run at height 0 or 1. Reachability of the panics was not traced.
- `Enabled` and `PerAsset` are variant texts from the serializer `0x2313010`; which writers run on chain byte 3 was not traced past words 79, 104, 105 and 106.

Next question: what do the four classifier arms return for each order type, and what do the two id sets name?
