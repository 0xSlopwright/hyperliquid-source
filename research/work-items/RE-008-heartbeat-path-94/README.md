# RE-008: node #94 heartbeat path, from the execution event to the ack match

This packet shows how a node #94 validator sends, checks, counts and acknowledges heartbeats, so the Rust node can write this path from one rule list. It settles that a heartbeat comes only from an execution state event and not from a timer, that its round is the execution round, that it goes out once per ten block of rounds and carries a snapshot and the peer round map once per hundred block, that it stops when the highest QC is more than 1000 rounds ahead, that a snapshot is counted per stake and jail key with the strict 2/3 rule and that the local compare and the lt hash block change nothing on this path, and that an ack counts only on the same round and the same 32 bit random id.

- Component ID: consensus (task RE-008)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference labels are leads only, nothing is copied
- Claim status: observation for every row marked as run or pinned; inference where the section says so; unresolved items are listed under Results and limitations
- Scope included: arm `0x44ae470` (event tag 0xb) with its send gates and tail, arm `0x44af6a4` (tags 0 and 1), arm `0x44affed` (tag 0xa), all run from the first byte of `0x44adfa0`; `0x454bd70`, `0x454b430`, `0x454aec0`, `0x454b300`, `0x474e1b0`, `0x474fa50`, `0x493fbc0`, `0x435de00`, `0x48c6a10`, `0x48c3f80`, `0x4b31660`, `0x43563b0` run for real. 61 helpers run for real too, B-tree insert, split and removal among them
- Scope excluded: arm `0x44ae705` (event tag 0xf, it reads `state+0x6f8` and the jail rows and builds its own outbox rows), `0x474f8a0`, `0x474e8c0`, `0x474e510`, digest bytes `0x454c050`, signature bytes `0x14a2710`, the stake table update `0x4b31a70`, what reads the outbox rows, what reads the peer maps at `0x44b3793`
- Related work: merged `research/work-items/RE-001-statistics-body-94` binds `0x4898810` under the wrapper `0x474f8a0`, which this packet leaves out. Merged `research/work-items/RE-001-heartbeat-status-94` reads `0x4726a50`. Open #1107 binds export record stores, a different layer. Merged `research/work-items/RE-008-consensus-wire-state` lists `0x454aec0` and `0x454b300` as `signed.rs` FDE starts with no rule. Our #890, #951, #975, #999 and the vote and timeout draft are the steps next to this one; `0x42c9930`, `0x4ad90d0`, `0x4b31d40` run here only as helpers. The reference puts ack handling at `0x474e510`; the arm calls `0x474fa50` for acks and `0x474e510` only from arm `0x44ae705`. It types `random_id` as 16 bytes; rows here read 4 bytes at `+0x11c`.

## Reproduce

Run from the repository root. Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. No external program runs, the binary is never executed, nothing touches a network. The tool refuses any other digest. One run takes about 130 s.

```
python3 tools/heartbeat_path.py --out research/work-items/RE-008-heartbeat-path-94
python3 -m unittest tests.test_heartbeat_path
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata` and `.rela.dyn`. Function bounds are FDE bounds from the shared parser. Every table is generated from bytes or from a run of the real rows.

`gates.tsv` has 44 ordered rows with site and case count. `layouts.tsv` has the heartbeat, ack, row and state fields, each with a reading site. `dispatch.tsv` reads the jump tables. `field-uses.tsv` lists every disp32 of the buffer, own round and peer map fields in the dispatcher and the constructor `0x44a8420`. `triggers.tsv` comes from a byte scan of every `e8` rel32 in `.text`.

### Observations: sending

Event tag 0xb (table `0x6f2a34` index 1) carries the execution state, 0x150 bytes. `0x454aec0` has one call site, in this arm, so this is the only source of a heartbeat. The event's round at `+0xf8` is the round of the heartbeat.

1. `state+0x2d8` keeps the first execution round seen.
2. Blocks are `round / 10`. Same block as the last sent round: nothing. 5009 after 5000 is silent, 5010 after 5009 sends.
3. Round over `table+0x58`: warning only.
4. No stake set at that round: error dropped. This node not in it: silent stop.
5. Highest QC round (`state+0x460`) over `round + 1000`, saturating: `Not sending heartbeat because execution round is far behind qc` (`node/src/consensus/state.rs` line 487) and stop. A lag of exactly 1000 sends. The last sent round is not written on any of these stops.
6. `state+0x2b8,+0x2c0` take this round.
7. Snapshot when there is no last snapshot round or `round / 100` differs from it. The snapshot has the stake map at this round, the jail set at this round, the event's Option lt hash block (`+0x20`, 0x90 bytes) and evm block number (`+0x148`). A jail row miss leaves None and goes on.
8. Random id from `0x4a11190`. The peer round map is a clone of `state+0xa68`, and only a heartbeat with a snapshot has one. Others carry tag 0 at `+0` and tag 2 at `+0x20`.
9. `0x474e1b0` writes a row at tracker `+0x108`: round to empty ack map, random id, wall clock. A row at that round is replaced.
10. Digest variant 3, outbox row of 0x168 bytes whose first word is the map tag. `state+0x2c8,+0x2d0` are written only here.

Every execution event then goes on, sent or not: `0x43563b0` stores round to evm number and lt block at `state+0x878`, in a ring whose limit is 100000 from the constructor (`0x44a9b19`, `state+0x890`), line 529. The buffer row of that round and every buffer row at or under it are freed.

### Observations: receiving

Event tags 0 and 1 go to `0x44af6a4` (table `0x6f2a50` index 7).

1. `0x454bd70`: stake set of the heartbeat round (tag 0x28), signer in it, then recovery over digest variant 3 (tag 1). An unknown signer has no recovery run. There is no version pair and no round gate, unlike the vote. Any failure is dropped and nothing below runs.
2. Peer map, if present, replaces the row of the signer at `state+0xa80`. Absent keeps the old row.
3. `state+0xa68` keeps the maximum round per signer. The vote arm writes this map too.
4. With no snapshot: go to step 9.
5. Round absent from the own round map: evm number, signer and lt block go on the buffer at `state+0xa98`. Present: nothing. The stored value is not read.
6. Jail row at the current round `state+0x918`, not the heartbeat round: a miss drops the error, a jailed signer is not counted. Both still get an ack.
7. Stake compare `0x49a5470` and jail compare `0x49a58f0` run, and the answer of the second reaches no branch (`0x44afb18`, next row reloads). The first only guards the second. A snapshot unlike the local table counts all the same.
8. Tracker `0x435de00` at `state+0x278` with cut flag `round >= 1000` and cut `round - 1000`. Below.
9. Ack only if this node is in the stake set of the heartbeat round: round, this node, the sender's random id, digest variant 4, outbox row tag 8, the sender's address at `+0x70`.

### Observations: tracker

Floor plus map round to row, as in the vote tracker, with a 1000 round window. The key of a slot is the pair at heartbeat `+0x20`: Option stake map, Option jail set, compared by value. Evm number and lt block are not part of the key. `0x48c6a10` keeps voter sets per key. Before is the decided byte `row+0x58` or a quorum read; the signer is added; before true stops; after true sets the byte and stores the key at the row head. Only a decision prunes rows under the cut and moves the floor, which keeps a higher value. Stake never adds across keys. A slot that already held quorum when undecided never decides. Over 100 rows, 100 keys are listed and freed unread (`0x48c7e7e`). The answer of `0x435de00` is dropped at `0x44afbb5`, and only a process clock read depends on it (`0x44afbc3`).

### Observations: ack

Tag 0xa, `0x44affed`, `0x474fa50`: `0x454b430` has the same order as the heartbeat check over digest variant 4. A failure is dropped. No row at the round: nothing. Random id other than the row's: nothing. Else the ack map row is signer to wall clock now, and a repeat replaces it. No membership or age gate beyond the check.

### Inferences

- The table row for tag 9 is the niche slot of the Heartbeat variant: tags 0 and 1 are the Option tag of the first field, other variants are `tag - 2`, and index 7 is Heartbeat. No sender of tag 9 was searched.
- `table+0x20` is read as a jail table. The rows are sets, the file is `validator_set.rs`, the snapshot field text is `jailed_validators`, and the row goes into the snapshot beside the stakes. Nothing in these rows names it.
- The 0x90 block is read as the concise lt hashes because the struct text lists that field and the size fits. Its inner fields are not read.
- The buffer looks like a compare of peers' lt hashes against the local one that is no longer done, since `field-uses.tsv` shows only the push and two discard paths in the dispatcher. This is a reading of absence in the scanned functions, not a proof about the whole binary.

## Implementation and comparison

not yet implemented

## Results and limitations

The real rows of 12 subject functions, the three arms and 61 helpers ran over real B-tree fixtures, 9502 of 11360 subject bytes and 5135 arm bytes reached. 412 cases (112 named, 300 vectors) match a separate rule list on ordered trace, last sent, last snapshot, first round, floor, walked trees of the tracker, seen map, peer maps, buffer, own rounds, sent rows and every outbox row. 363 of 560 condition and immediate mutants killed, each on up to 12 cases reaching its row plus 17 named boundary cases; 197 survivors in `mutations.tsv`, 72 named. 81 byte pins, 6 slots, 7 strings, 3 Locations, 15 call sites, with negative tests. 51 unit tests pass. Two reruns with different hash seeds and time zones are byte identical.

Limits:

- Digest bytes and signature bytes are stubs; the fixture digest stands in. Arguments and which variant is used are checked.
- The stake table update and the `state[0] == 1` branch of the execution tail do not run.
- Fixtures build trees of height 0 or 1. `0x4b31a70` is not modelled, so the table stays fixed across steps.
- The `no stake set` branch after the verifier at `0x44afad9` is reached by no case, since the verifier read the same set first; it is listed with no count.
- Field displacement mutants were not run.
- Unresolved: whether any function outside the dispatcher reads `state+0x858` values or `state+0xa98`, what reads a decided tracker row, whether rows at tracker `+0x108` are ever removed (the arm `0x44ae705` is the likely place), what the stored event at `state+0x2e8` feeds.

## Next question

Arm `0x44ae705`: which validators it builds rows for from `state+0x6f8`, the 3000 default at `0x44aed41`, and how `0x47c0ae0` turns them into the signed action. Then the reader of the peer maps at `0x44b3793`.
