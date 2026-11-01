# RE-008: node #94 automatic jail vote path, from event tag 0xf to the signed bundle

This packet shows how a node #94 validator decides by itself which peers to vote into jail and with what time, so the Rust node can write this path from one rule list. It settles that event tag 0xf walks the keys of the stake row through a fixed rule order (stored jail set, stored time over event time + 900 s, seen round lag over max(3000, 2 * total), bundle weight of 9001 or more, then the heartbeat status tags 0, 1 and 2), that the reason is dropped before signing, that every target gets a `voteJail` row with time event time + 1800 s in one bundle, and that a jailed node sends nothing.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `cec50f68e01c967d21538d48c49683ddeea52767`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: arm `0x44ae705` (event tag 0xf) run from the first byte of `0x44adfa0`; `0x4476200`, `0x47c1f30`, `0x47c0ae0`, `0x474e510`, `0x489dec0`, `0x4b314f0`, `0x44adbf0` run for real. 22 helpers run for real too, the status query and its list, the jail row lookup and the row sort and tree build among them
- Scope excluded: the sender of event tag 0xf, the parser `0x4721bb0`, the signer `0x3341af0`, the bundle `0x3340100`, the tracker prune `0x474f8a0`, the hourly file row `0x474e8c0`, the writers of the tracker rows
- Related work: merged `research/work-items/RE-001-heartbeat-status-94` reads `0x4726a50` and its consumer `0x4876f90` and keeps the tags unnamed until their use is known; here both run only as helpers, and this packet adds that use. Merged `research/work-items/RE-001-statistics-body-94` binds `0x4898810` under `0x474f8a0`, stubbed here. Merged `research/work-items/staking-c-signer-jail-94` reads the receiving `voteJail` handler and the inner tag; this packet is the sender and gives one answer to its question of where a jail time comes from. Merged `RE-008-commit-walk-94` and `RE-008-block-proposal-94` only list `0x44b9a50` as a callee. Our heartbeat draft fills `state+0xa68`. `0x4b314f0` and `0x4b31660` appear as error tag sites in `RE-008-consensus-error-tags-94`. The reference has an `unresponsive_validators` idea in `heartbeat_tracker.rs` with other numbers; none of it is used here.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes 80 to 240 s.

```
python3 tools/auto_jail_vote.py --out research/work-items/RE-008-auto-jail-vote-94
python3 -m unittest tests.test_auto_jail_vote
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

`gates.tsv` has 33 ordered rows with site and case count. `reasons.tsv` lists the row tags. `numbers.tsv` reads the two doubles. `layouts.tsv` has the event, target row, action row, tracker and state fields, each with a reading site. `dispatch.tsv` reads the jump table. `field-uses.tsv` lists every disp32 of the state fields in the dispatcher, the constructor and `0x44b9a50`. `triggers.tsv` comes from a byte scan of every `e8` rel32 in `.text`. `cases.tsv` gives the targets and reasons of every case.

### Observations: the arm

Event tag 0xf (table `0x6f2a34` index 5) has one flag byte at `+8`. The arm ends with answer byte 0xd at `0x44b13c4`.

1. Stake row of `state+0x918`. No row: error 0x28 dropped, stop. This node (`state+0xaec`) has no key in it: stop, silently. Neither stop touches anything else.
2. Flag set: `state+0x1e8` is taken by value and left empty, and a process clock read follows whose answer is unused. Flag clear: there is no weight map for this event, and `state+0x1e8` stays.
3. Lag = max(3000, 2 * sum of the row values). A sum with the top bit set gives u64::MAX, a sum over 64 bits panics (`0x4b33770`).
4. `0x4b314f0` copies the row keys into a set. `0x474f8a0` and `0x474e8c0` run over that set, then `0x474e510` gives the status map.
5. Time word = event time + 1800.0 s, through slot `0x576efb8` and the double at `0x20a7a0`.
6. `0x47c1f30` asks `0x4476200` once per key, in key order, and keeps rows of 0x28 bytes. No row: stop.
7. Jail row of the round. Missing: error dropped, stop. This node in it: stop. These two gates run only after the rules.
8. `0x47c0ae0` builds one row of 0x168 bytes per target: action tag 0xb0, inner tag 2, target at `+0x19`, time word at `+0x30`, the byte of `state+0xb04` at `+0x11e`. The reason tag and value are not read. Inner tag 2 and the time at inner `+0x18` are the `voteJail` shape of `staking-c-signer-jail-94`.
9. `0x44adbf0`: one bundle call, answer 0x186 gives outbox row tag 9 with an Arc of the bundle, any other answer is dropped.

### Observations: rules of 0x4476200

Applied per key, first match wins.

| Order | Test | Outcome |
| --- | --- | --- |
| 1 | stored event at `state+0x2e8` not tag 2, key in its set at `+0x100` | left alone |
| 2 | same event, tag bit 0 set, map at `+8` has a time over event time + 900 s | left alone; equal goes on |
| 3 | seen map row and saturating seen + lag under the round | reason 3, value the seen round |
| 4 | flag given, weight map row of 9001 or more | reason 5, value the weight |
| 5 | status map row | reason 0, 1 or 2 with the tag value |
| 6 | none | left alone |

A key with no seen row skips rule 3 and is not a lag. Time compares date (signed), then seconds, then fraction. The cut crosses midnight through the chrono helpers.

### Observations: status map

`0x474e510` first looks at a watched file. A last look exists and elapsed is at or under `tracker+0xd8`: skip. Otherwise last look = now. Missing file: skip. Metadata error: panic. Modified time not newer than `tracker+0xf8`: skip. Parser refused: log `Error updating FileModTimeTracker for`, the error replaces the held one, limit and time stay. Parser accepted: ratio limit at `+0xc8`, mute byte at `+0xd0`, time stored, held error cleared. The new limit counts in the same event.

`0x489dec0` then walks the set through `0x4876f90` and `0x4726a50` and collects a map of tags. Tag 3 is left out of the map. So a key with no row in `tracker+0x120` gets reason 0: an empty tracker names every key, this node too. Tag 2 is ratio over the limit with mute zero. Tag 1 is more than 180 s since the row time; a muted ratio still reaches that test. A held error logs on every status read, twice when the ratio is over the limit.

### Observations: what feeds the rules

- `state+0xa68`: maximum round per signer, written by the heartbeat arm at `0x44af8b1` and at `0x44b048b`.
- `state+0x1e8`: `0x44b9a50` (`add_tx` metric text at `0x6f4f2e`) adds the saturating sum of `0x33632e0` over the rows of an accepted bundle under a 20 byte key from the bundle at `0x44ba1f8`. Only event 0xf with the flag set clears it.
- `state+0x2e8`: the execution event, stored at `0x44b0a32` by the arm with answer byte 9.

### Inferences

- The map at stored event `+8` is read as `jail_until` and the set at `+0x100` as the jailed signers. The staking packet has a `jail_until` time map and a jailed set, and the 900 s rule then reads as: do not vote for a validator still jailed for more than 15 minutes. Nothing in these rows names the fields.
- Time word as a jail end time: the receiving handler takes a stake median of vote times and hands it to the jail helper. So an automatic vote asks for a jail of 30 minutes.
- The 20 byte key of the weight map is read as the bundle's broadcaster, and reason 5 as a flood limit between two flagged events. `0x33632e0` looks like an action weight, 1 by default and a list length for some tags. Its table was not walked.
- Tag 1 reads as a peer that has not acked for 180 s and tag 2 as a slow peer. The tracker rows' writers were not read.

## Implementation and comparison

not yet implemented

## Results and limitations

The real rows of 7 subject functions, the arm and 22 helpers ran over real B-tree fixtures, 4640 of 5568 subject bytes and 2191 arm bytes reached. 387 cases (87 named, 300 vectors) match a separate rule list on ordered trace, reason tag and value of each signed row, action row fields, weight map, config fields and outbox rows. 232 of 300 condition and immediate mutants killed, each on up to 12 cases reaching its row plus 33 named boundary cases; 68 survivors in `mutations.tsv`, 68 named. 80 byte pins, 12 slots, 3 strings, 3 Locations, 15 call sites, with negative tests. 54 unit tests pass. Two reruns with different hash seeds and time zones are byte identical.

Limits:

- No sender of event tag 0xf was found by a scan of `mov qword, 0xf` rows in the consensus range, so the period and the flag rule are unknown. Rule 4 can only fire on a flagged event.
- Signature bytes and bundle bytes are stubs. The arguments are checked and the action row is read at the sign call.
- `0x474f8a0` and `0x474e8c0` are stubbed; the key list they receive is checked. If the prune changes the tracker rows, that is not modelled.
- The config parser is a stub, so the file format and the path are not read here.
- Fixture sets stop at 20 keys. Rows of 21 or more use the sort at slot `0x5776770`, not run.
- The panic of `0x474e601` is reached by a fixture. Whether a file can fail there at runtime is not studied.
- Field displacement mutants were not run. The field scan covers three functions, so other readers of these fields are not excluded.

## Next question

What sends event tag 0xf and sets its flag, then the file format read by `0x4721bb0` and the second reader at `0x474f1c8`.
