# staking: round clock, freeze height and hardfork reset in node #94

This packet recovers who moves the rounds behind every epoch read in node #94, so a reconstruction can write the whole clock from bytes: `begin_block` writes `current_round` of both `EpochTracker`s, only the hardfork reset (live at the freeze height, or on a loaded frozen state) writes `initial_round`, and that reset also adds the tracker row that stake reads use for the next 2000 rounds. The chain of gates around it is mapped end to end: freeze vote, apply gates, begin, reset, reload, tracker roll.

- Component ID: staking (Staking and validator lifecycle), first task: stake accounting and epoch transitions for #94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only, compared at the end. Nothing is copied from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are the 15 functions in `path.tsv`: the freeze gate and begin function in three copies each, the head of apply in three copies up to the begin call, the reset `0x2207f30`, the reload `0x32725d0`, the tracker writers `0x37d9a10`, `0x37d9af0`, `0x37d9940` and the key reader `0x37d9cf0`. Excluded: the block step `0x22297c0`, the rest of `0x2209d40`, the state parser `0x3273810` (`RE-017-abci-state-link-94`). `0x3996730`, `0x37d5e10` and `0x2fe1490` have their logic in `staking-reward-tick-94` and earlier work. They run real here as context only, listed in `helpers.tsv`, with no rows and no mutants. `0x37d9a10`, `0x37d9af0` and `0x37d9cf0` were stubs in that packet, and `0x26f8b60` is a site label in `RE-006-book-mid-sampler-94`. Their logic is first stated here.

## Reproduce

From the repository root:

```
python3 tools/staking_round_clock.py --out research/work-items/staking-round-clock-94
python3 -m unittest tests.test_staking_round_clock
```

The tool takes 2 to 4 minutes under load. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, checks the input SHA-256 first, starts no external program and never executes the binary. It only reads bytes and runs them in its own interpreter.

Generated files: `evidence.json`, `path.tsv`, `helpers.tsv`, `function-rows.tsv`, `constants.tsv`, `texts.tsv`, `status-text.tsv`, `vote-arm.tsv`, `scenarios.tsv`, `callers.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. Slot targets come from `.rela.dyn` RELATIVE rows. `constants.tsv` binds the main instructions of the path to their bytes, `texts.tsv` binds the keys and panic texts.

### Words

`E` is the Exchange. Its head is `Context`, named by the serializer `0x3987280` (`struct Context with 13 elements`).

| Offset | Name | Written by this path |
| --- | --- | --- |
| `E+0`, `E+8` | `tx_index` (tag, value) | begin: None while the block step runs, then Some(0) |
| `E+0x10` | `initial_height` | reset |
| `E+0x18`, `E+0x20` | `hardfork` (version word, round word) | reset |
| `E+0x28` | `height` | begin |
| `E+0x30` | round | begin |
| `E+0x60` | `time`, 12 bytes | begin |
| `E+0x6c` | `prev_time`, 12 bytes | begin |
| `E+0x950` | `stakes.current_round` | begin |
| `E+0x9f0` | `jailed_signers.current_round` | begin |
| `E+0x928`, `E+0x9b0` | `initial_round` of both trackers | reset, reload |
| `E+0xb90`, `E+0xb98` | `scheduled_freeze_height` (tag, value) | gate sets, reset clears |
| `E+0x38f8`, `E+0x3900` | `begin_block_logic_guard` (width, last bucket) | begin |

`CStaking` sits at `E+0x8f8`. Tracker layout: `stakes` at S: current to `+0x28`, period `+0x28`, `initial_round` `+0x30`, `round_to_val` `+0x38` (root, height, length), `n_keep` `+0x50`, `current_round` `+0x58`. `jailed_signers` at S+0xb0: period `+0`, `initial_round` `+8`, `round_to_val` `+0x10`, current `+0x28`, `n_keep` `+0x40`, `current_round` `+0x48`.

### Path

```
vote value, jump index 32 of the VoteGlobal dispatcher (0x23589b0)
    value >= 0x0ccccccccccccccc refused by the arm
    0x2703a90  freeze gate                     sets E+0xb90
block
    0x2209d40  apply head, six gates           panics, no status
    0x26f8b60  begin                           height, round, time, current_round x2
    0x22297c0  block step                      (stub)
    0x3996730 at site 0x220a5ee                tick: tracker rolls
after the block, host 0x22689f0
    freeze value == height                     log text "applying hardfork to frozen local abci_state"
    0x2207f30  reset                           initial_height, hardfork, initial_round x2, one row each, freeze cleared
frozen state on a file, host 0x22b47c0
    0x32725d0  reload                          same writes on the parsed state
stake read
    0x37d5e10, 0x37d9cf0                       current_round and initial_round pick the row
```

Copies: `0x4cf0750`, `0x4cdf180` and `0x42e5d40` use the same offsets. `0x4cf0650`, `0x4cdf370` and `0x42e4600` add `0xa80` to every offset from `0x740` up, so `E+0x950` is `E+0x13d0`. All three copies of each function run the same cases. Only the third begin differs in behaviour: it also stores height at `E+0x1018` and the block time, as given, at `E+0x1020`.

### Freeze gate, `0x2703a90`

Result rdi, E rsi, value rdx. First failure wins:

```
set, and value >= old:                                0x73, word +8 = old
value < height or value > min(height + 50000, 2^64-1): 0x72, word +8 = value
else: tag = 1, freeze = value, 0x186
```

The Display arms give `Already frozen at height {}` for `0x73` and `Invalid height {} for freezing the chain.` for `0x72` (`status-text.tsv`). So a set height can only move down, it can move to the current height, and an old height behind the chain still refuses every value at or above it. The tag test reads 32 bits.

### Apply head, `0x2209d40`

Block fields: round `+0x18`, parent round `+0x20`, hardfork pair `+0x28`, `+0x30`, time `+0x38`. Order of the rows:

```
freeze set and freeze < height:      panic "freeze_height >= self.locus.context.height()"
freeze set and freeze == height:     panic "!self.state.is_frozen()"
round <= parent:                     panic "round > parent_round"
E.round != parent:                   assert_eq
(E.version, E.hardfork round) != block pair: assert_eq
chain byte != 3:                     panic "features_ok"
begin(E, block time, round, flag), flag = word E+0x3ae8 == 2
```

All are panics, none is a status. The `apply_*` cases stop at the begin call.

### Begin, `0x26f8b60`

Arguments E, time pointer, round, flag byte.

```
if new time > time (date word signed, then seconds, then nanos, each unsigned):
    prev_time = time; time = new time
height = saturating height + 1
tx_index = None
round = stakes.current_round = jailed_signers.current_round = round argument
bucket = max(ms(new time), 0) / width of E+0x38f8
if bucket > last: last = bucket
block step(label "begin_block", changed = bucket > old last, E, new time, old time, flag)
tx_index = Some(0)
```

So `time` never goes back, while height, round and the guard move in every case, and the guard reads the block time as given, not the stored one. `ms` ignores the low four bits of the date word, the date compare does not (`flags_differ`, `flags_low`). `prev_time` keeps the old value when the block time does not move forward.

### Reset, `0x2207f30`

Called once, from `0x2269157`, in the host `0x22689f0`, after `freeze == height` (`0x2269014`, `0x2269021`, `0x226902e`; a freeze below height panics at `0x2269760` with the first apply text).

```
initial_height = height
hardfork = (saturating version + 1, round)
scheduled_freeze_height = None
stakes.initial_round = round
stakes: row[round] = clone of current; pop lowest key while length > n_keep
jailed_signers.initial_round = round
jailed_signers: row[round] = clone of current; pop lowest key while length > n_keep
drop map E+0x31e8 and vec E+0x3200, zero them and E+0x3218
```

Height and round do not change. `current_round` does not change. No gate on `period`. `n_keep = 0` leaves no row at all, not even the new one.

### Reload, `0x32725d0`

Arguments out, a path vector with the wanted height at `+0x18`, one more word. Reached only through slot `0x5773cc8` at `0x22b4c2c`.

```
name = 0x332de90(vector, height); error panics
format the name with the text "rmp"
state = 0x3273810(...); error panics (unwrap)
state.height != wanted height: assert_eq panic
then the same writes as reset, with height as read
out = state (0x3ae8 bytes)
```

It uses `0x37d9a10` and `0x37d9940`, while reset has inlined copies with its own tree helpers (`helpers.tsv`). The cases show both give equal state.

### Tracker roll

- `0x37d9a10(S, r)`: row[r] = clone of current, then pop lowest while length > n_keep. No gate inside.
- `0x37d9940(T, r)`: the same on `jailed_signers`, no gate. Only the reload calls it.
- `0x37d9af0(T, r)`: the same with a gate inside: nothing if the map has rows and `r < saturating last key + period`.
- `0x3996730` runs the second, then tests the same rule inline for `stakes`, then calls the first. `r` is `Context` round, not `current_round`.

So a row whose key equals `r` is replaced, a key below the last key is legal (`stakes_low_key`), and the gate reads the last key, so a key far above `r` stops rolling until the rounds pass it (`stake_above`).

### Reads after a fork

`0x37d9cf0(S)` returns (1, key) or 0, and `0x37d5e10` returns pointers to the row, with the same rule:

```
end = saturating initial_round + 2000
start = initial_round                  when current_round < end
start = max(current_round - 200, initial_round)  else
last key <= start
```

Together with the reset this gives the use of `initial_round`: for 2000 rounds after a fork every stake read lands on the row the reset wrote at the fork round (`life_fork_read`, `life_fork_again`), and rows from before the fork stay in the map under `n_keep` but cannot be read. That row exists only because the reset wrote it. It holds while the row stays under `n_keep`: with `n_keep = 0` it never exists, and with a small `n_keep` later rolls can prune it inside the window. The live values of `period` and `n_keep` are state, not code, and are not known here.

### Fields named by the serializers

`Context` at `0x3987280`, Exchange at `0x275ab80` (`scheduled_freeze_height` with `E+0xb90`, `begin_block_logic_guard` with `E+0x38f8`). `constants.tsv` holds each pair.

### Callers

`callers.tsv` comes from a byte scan of `e8` and `ff 15` rows in `.text`, so a row of data that looks like a call is possible in principle. The tick has two more sites, in `0x446e7b0` and `0x446f130`, which are not read here. Reset has one site. Each freeze gate has one site, in its copy of the VoteGlobal dispatcher.

### Differences from the reference

| Reference claim | Bytes |
| --- | --- |
| `freeze_height != height` asserted only if not `frozen` (`exchange.rs`) | no such flag read in the head of `0x2209d40` |
| `Hardfork.version` is `u8` | a 64 bit word with a saturating add |
| `scheduled_height` on a lane | one Exchange field `E+0xb90`, read by name in the serializer |

The name `FreezeChain` and "case 0x20" of the reference fit jump index 32, read here from table `0x3dd1b8`. Reference files name neither `current_round` nor `initial_round`, and its `CStaking` has no `EpochTracker`.

## Implementation and comparison

Rust implementation: not yet implemented. There is no compiled comparison. The comparison is between the real instruction bytes and a rule list kept apart from the evaluator.

Tracker cases load a `CStaking` state through the real msgpack reader `0x175f130`, run the target with tree helpers real, and give the state back through the real writer `0x39908e0`. The rule list works on a plain value and emits msgpack itself. So state compares byte for byte. Context words compare through a digest of every word in the table above. Calls compare through a log of each stub's arguments in order.

Cases: 375 named (66 apply, 102 begin, 78 freeze, 42 history, 5 life, 27 record, 21 reload, 18 reset, 16 tick) plus 300 seeded. All match. Reached rows: 1492 instructions, 6817 of 26698 body bytes. The rest of the body bytes are mostly the unreached part of the three apply hosts, which are 20 KB between them.

Mutation: 424 possible edits of conditions and immediates in reached rows, 424 run, 308 killed, 116 survived. Each edit runs on up to 6 cases that reach it. Survivors per function: `hardfork_reset` 26, `frozen_state_reload` 20, `begin_block` 12, `begin_block_copy` 12, `begin_block_third` 12, `history_latest_key` 7, `signers_record_gated` 4, `signers_record_plain` 4, `stakes_record` 4, `freeze_gate` 3, `freeze_gate_copy` 3, `freeze_gate_third` 3, `apply_block` 2, `apply_block_copy` 2, `apply_block_third` 2. They were not classified one by one. The large groups are stack probes and `Once` tests, drop and iterator rows with no effect on the written state (a leak does not show), the year <= 0 arm hidden by the `max(0)` clamp, the 32 bit divide shortcut, and helpers with few picked cases near `2^64`, where each edit runs on 6 cases only. An unedited image runs under the same step limit first.

Tests: 41 pass, 0 skipped, with negative controls on digest, FDE bounds, pins, texts, patched bytes (window, status, round store, mirror, freeze clear, `initial_round`, due compares) and rule list edits (window, history key, prune).

## Results and limitations

- Requesting no progress gate. This is one path of the staking component.
- Stubs with argument checks: block step, `0x3373420`, `0x33709f0`, `0x336f9f0`, the clock `0x4ee3800`, drops `0x3402700`, `0x33f0da0`, path name `0x332de90`, format `0x1344760`, parser `0x3273810`. The `Once` call `0x4ee3b20` is a no-op stub.
- The host slice of `0x22689f0` is read by eye and bound by pins, not run, because it sits inside an 11 KB async body. What happens after the reset in that host is not read.
- The conditions that lead `0x22b47c0` to `0x22b4c2c` are not read. The text `Hardfork mismatch` and the chainspec are not tied to this path. So this packet states what the reload does, not when.
- Who else writes `initial_round`: a scan of `disp32` forms finds `0x2207f30`, `0x32725d0` and clone `0x4d78460`, plus the msgpack and JSON readers by way of their tree. Pointer paths are not excluded.
- The names of `E+0x31e8`, `E+0x3200`, `E+0x3218` and word `E+0x3ae8` are unknown.
- Inference: chain byte 3 is Mainnet, and this build panics on other chains in apply, from `features_ok` and the path text `code_Mainnet`. The apply head was run on chains 0, 1, 2 only as a panic.
- Inference: `tx_index` None marks the block step, from the key name and the two stores.
- Inference: `FreezeChain` for the arm. The binary's raw tag of the arm is not read, only the jump index.
- A zero width is not in the cases: wire `bucket_millis` is a nonzero type. A year below the range of the date word is not in the cases.
- `delegations_blocked` is still not cleared by any path read here.
- Trees above height 2 are not reached, so the unrolled eight level descents are partly unreached.

Next question: what leads `0x22b47c0` to the reload at `0x22b4c2c`, how the chainspec hardfork list relates to `Context.hardfork`, and what `E+0x31e8` and `E+0x3200` hold.
