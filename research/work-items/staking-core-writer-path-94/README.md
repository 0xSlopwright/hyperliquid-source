# staking: CoreWriter raw action path in node #94, from EVM log to the delay wrapper

This packet recovers how a HyperEVM contract reaches staking in node #94, so a reconstruction can write the path end to end from bytes: a `RawAction(address,bytes)` log at `0x3333..33` is decoded under exact ABI rules, version 1 and actions 1 to 16 map to fixed action tags (token delegate `0x95`, staking deposit `0xb2`, staking withdraw `0xb1`), three sender sets and a vote writable disabled set drop a log with no result, and each surviving row of 0x128 bytes goes through the delay wrapper. No part of this path had a packet, the reference tree has no decoder for it, and the upstream table differs from #94 in two rows.

- Component ID: staking (Staking and validator lifecycle), first task: stake accounting and epoch transitions for #94. This is the EVM entry of `tokenDelegate`, `cDeposit` and `cWithdraw`. The other 13 arms share the same host and decoder family, so they are mapped with it.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `7194e50b54c6cea3380f2e78d6edfe6fd73cc7bb` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only. Nothing is copied from it. Action numbering was first compared with `research/upstream-docs/docs/for-developers_hyperevm_interacting-with-hypercore.md`, then fixed from bytes.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are the 30 functions in `path.tsv`: host `0x333b2a0`, log decoder `0x37a31f0`, bytes decode and encode, the wallet head check, three sender lookups, the row push, 15 ABI decoders, the disabled set insert and remove, the reached arm of `0x2355f40` and its copies, and row loop `0x2760a70`. All of them, and the 53 helper functions in `helpers.tsv`, run as real bytes. Hooks in the host part: allocator, byte copies, compare, the CPU feature probe `0x4f15250`, and the clock read `0x14385c0`. Hooks in the loop part, with checked arguments: block function `0x2448500`, metric `0x358dcd0`, `0x2760040`, classifier `0x335ec90`, dispatcher `0x2759240`, result writers `0x2780900`, `0x334cc40`, context `0x3987cb0`, delay wrapper `0x27584a0`. Excluded: the first log decoder `0x34273d0`, the handlers behind the action tags, the wrapper itself (`RE-004-action-delay-queue-94`), loop copies `0x4d8db10`, `0x4d8ebc0`. Overlap: `0x37e6e90` and `0x37e7e00` are list hits of the ISA census #875; `0x2355f40`, `0x4caa870`, `0x4cb3200` and `0x2760a70` are hosts held by other packets, and only the rows reached here are claimed; `0x399c7a0` is a helper. No other function of the path appears in an evidence packet.

## Reproduce

From the repository root:

```
python3 tools/staking_core_writer.py --out research/work-items/staking-core-writer-path-94
python3 -m unittest tests.test_staking_core_writer
```

The tool takes about 2 minutes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, checks the input SHA-256 first, starts no external program and never executes the binary. It only reads bytes and runs them in its own interpreter.

Generated files: `evidence.json`, `path.tsv`, `helpers.tsv`, `arms.tsv`, `constants.tsv`, `function-rows.tsv`, `scenarios.tsv`, `callers.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. `E` is the Exchange pointer of `0x2760a70`.

### Method

Every host case enters at `0x333b2a0` with a log, the context words of the real caller, a disabled set of real B-tree nodes, two sender trees and a real hash table placed with the real hash `0x399c7a0`. A separately written rule list predicts whether a row comes out and, for a row, each named field, heap box, name string and the set of live blocks. 756 named cases (64 arm, 18 bool, 48 bound, 241 dirty, 42 enum, 20 gate, 24 header, 144 length, 24 log, 20 loop, 39 order, 24 wallet, 48 writer) and 300 seeded vectors match, 300 named rows and 436 named drops, with 0 mismatches. Rules were corrected from runs where the first reading was wrong; the corrections are the trailing byte rule, the bool rule, the extra topic rule and the dirty user topic rule below.

### Path

```
EVM log loop in 0x2448500
  0x34273d0 first decoder (tag 1 takes the log, not read here)
  0x333b2a0 raw action host, through slot 0x5774048
    log address must be 0x33 x 20                        else return
    0x37a31f0 decode, 0x3819c00 and 0x32fc560 inside     error: drop
    raw length 1..3 or above 1000                        drop
    (version, action) in disabled set E+0x3150           drop
    version != 1, action outside 1..16                   drop
    arm from jump table 0x5879fc, ABI decoder            refused: drop
    tag and fields built, raw bytes released
    sender in tree E+0x39e8                              drop
    sender absent from table E+0x740                     drop
    sender in tree E+0x8d0                               drop
    0x33c2f50 push row of 0x128 bytes
0x2760a70 row loop
  first list: action 0xad, run at once through 0x2759240
  second list: each row to 0x27584a0, stops at tag 0xcc
```

### Log rules, `0x37a31f0`

- `0x206290` and `0x204ce0` hold 16 and 4 bytes of `0x33`. Any other log address returns before decoding.
- The first topic must equal `0x20c6a0`, which is keccak256 of the text at `0x59b77f`. This tool computes the hash and compares.
- Exactly one topic is the `topic list length mismatch` error. Two or more pass. A third topic is ignored (`log_three_topics`).
- The sender is the low 20 bytes of the second topic. Its high 12 bytes are not tested (`log_user_top_byte`).
- With flag `r9` = 1 the data is re-encoded through `0x32fc560` and compared. Offset other than `0x20`, wrong length, a trailing word and dirty padding all give a drop.

### Header

`raw[0]` is the version, `raw[1..4]` a big endian action id. The disabled set is checked before the version test, on a key of (u8, u64) stride `0x10`. So a disabled row for version 0 or for action 99 is harmless and the log drops either way.

The 1000 byte cap cannot change a result here. A longer raw action fails the exact length rule of every arm, because no arm has a payload above 996 bytes: the wallet name is below 256 bytes. So edits of the cap survive by design.

### Arms

`arms.tsv` is read from the table and the tag sites. Types were first taken from upstream names and then proved by the cases.

| Action | Upstream name | Tag | ABI | Decoder |
|---|---|---|---|---|
| 1 | limit order | `0x82` | u32, bool, u64, u64, bool, u8, u128 | `0x37e6e90` |
| 2 | vault transfer | `0x9f` | address, bool, u64 | `0x37ea360` |
| 3 | token delegate | `0x95` | address, u64, bool | `0x37e7940` |
| 4 | staking deposit | `0xb2` | u64 | `0x37e8670` |
| 5 | staking withdraw | `0xb1` | u64 | `0x37e8670` |
| 6 | spot send | `0xad` | address, u64, u64 | `0x37e8ab0` |
| 7 | usd class transfer | `0xaf` | u64, bool | `0x37e9260` |
| 8 | finalize evm contract | `0xb7` | u64, u8, u64 | `0x37e87b0` |
| 9 | add api wallet | `0x75` | address, string | `0x37e8d60` |
| 10 | cancel by oid | `0x77` | u32, u64 | `0x37e98a0` |
| 11 | cancel by cloid | `0x78` | u32, u128 | `0x37ea130` |
| 12 | approve builder fee | `0xba` | u64, address | `0x37ea7e0` |
| 13 | send asset | `0xbb` | address, address, u32, u32, u64, u64 | `0x37e7e00` |
| 14 | not in the upstream table | `0xbc` | u64, u64, bool | `0x37e9d90` |
| 15 | borrow lend | `0xac` | u8, u64, u64 | `0x37e95a0` |
| 16 | set abstraction | `0xc2` | address, u8 | `0x37e9af0` |

Row fields, offset from the row start:

| Action | Fields |
|---|---|
| 3 | `+0x28` wei, `+0x38` validator, `+0x4c` chain byte, `+0x4d` isUndelegate |
| 4, 5 | `+0x28` wei, `+0x38` chain byte |
| 1 | Vec at `+0x30` of one box 0x38: `+0` tif code, `+9` 2, `+0x10` px, `+0x18` sz, `+0x20` asset, `+0x24` has cloid, `+0x25` cloid big endian, `+0x35` isBuy, `+0x36` reduceOnly |
| 2 | `+8` usd, `+0x10` vault, `+0x24` isDeposit |
| 6 | `+8` token, `+0x10` wei, `+0x18` destination |
| 7 | `+8` ntl, `+0x10` toPerp, `+0x18` chain byte |
| 8 | `+8` variant minus 1, `+0x18` token, `+0x10` nonce for variant 1 only |
| 9 | `+8` String (`1 << 63` for an empty name), `+0x48` address, `+0x5c` chain byte |
| 10, 11 | Vec at `+8` of one box: oid and asset, or cloid big endian and asset |
| 12 | `+8` fee, `+0x10` builder |
| 13 | `+8`/`+0x10` source dex Option, `+0x18`/`+0x20` destination dex Option, `+0x28` token, `+0x30` wei, `+0x38` destination, `+0x4c`/`+0x4d` sub account Option |
| 14 | `+8` first u64, `+0x10` second u64, `+0x18` bool |
| 15 | `+8`/`+0x10` wei Option, `+0x18` token, `+0x20` op code |
| 16 | `+0x30` address, `+0x44` mode, `+0x45` chain byte |

Every row also holds the sender at `+0xf0` and the 32 byte hash from the host's fifth argument at `+0x104`.

### Payload rules

- The payload must be exactly the head for the arm. One trailing byte or a zero word gives a drop (`arm_4_extra_1`, `arm_4_extra_32`).
- A uint with a non zero high byte above its width gives a drop. An address with dirty high bytes gives a drop.
- A bool needs its high 31 bytes zero. Any non zero low byte is true (`arm_3_bool_2_two`, flag stored as 1).
- Tif 1, 2, 3 map to codes 0, 2, 1 from `0x10200`. Other values drop.
- Price, size and oid at or above `0x0ccccccccccccccc` drop. The other arms take any u64, so a wei value is not bounded here.
- Finalize variant 1 to 3, set abstraction 1 to 3 (modes 1, 3, 4 in the row, from the words loaded at `0x333c200`, `0x333baac`, `0x333c19d`), borrow lend op 0 to 3 (codes 1, 3, 0, 2 from `0x2000301`). Other values drop.
- Borrow lend wei 0 is `None`. Send asset dex `0xffffffff` is `None`, and a zero sub account is `None`. Empty wallet name is `None`.
- Wallet head check `0x333b000` needs length `>= 0x60`, a clean address word, offset exactly `0x40` and a length word below 256. A name that is not UTF-8 drops.

### Sender sets

All are tested after the row is built, so a drop must release boxes through `0x3379f90`; the leak check covers this.

| Order | Context word | Address | Row | Effect |
|---|---|---|---|---|
| 1 | `+0x40` | `E+0x39e8` | tree, 20 byte key, value 0x20 | present: drop |
| 2 | `+0x38` | `E+0x740` | hash table, row 0x58 | absent: drop |
| 3 | `+0x28` | `E+0x8d0` | tree, 20 byte key, value 0xb0 | present: drop |

The context words are checked in the `0x2448500` hook of the row loop run: `+0` `E`, `+8` `E+0x3368`, `+0x10` `E+0x5b8`, `+0x18` `E+0x80`, `+0x20` `E+0x3380`, `+0x28` `E+0x8d0`, `+0x30` `E+0x8f8`, `+0x38` `E+0x740`, `+0x40` `E+0x39e8`, `+0x48` `E+0x3a30`, `+0x50` `E+0x498`, `+0x58` chain byte `E+0x8f2`.

### Disabled set writer

Raw tag `0x5b` of `0x2355f40` (arm `0x2359326`, copies `0x4caa870`, `0x4cb3200`, third field shift `0xa80`). Action `+8` id, `+0x10` version, `+0x11` enabled. An id at or above `0x0ccccccccccccccc` gives `0x13f` and no edit. Enabled 0 inserts through `0x285b7f0`, any other value removes through `0x2866420`, and a row that is present or missing is no error. The tree stays sorted through node splits. Cases then run the host on that same tree, so the vote and the decoder are tied by data, not by reading.

### Row loop, `0x2760a70`

- First list, rows of 0x48: `+0x20` token, `+0x28` wei, `+0x30` destination. Each becomes tag `0xad` and runs at once through `0x2759240`. The sender is 20 bytes of `0x22` when `E+0x80` is 1 and `E+0x88` equals the token, else `0x20`, 11 zero bytes, and the token big endian.
- Around that dispatch `E+0x78` is 1, and `E+0x50` rises by 1 with saturation before it.
- Second list, rows of 0x128: tag `0xcc` stops the loop and the remaining rows are released. Each row goes to `0x27584a0` with sender and hash. When `E+0` is 1 the context `0x3987cb0` takes chain byte, `E+0x28` and `E+8`.
- After each row `E+0` is 1 and `E+8` rises with saturation, or starts at 1. So one index runs across both lists.

## Implementation and comparison

Implementation: not yet implemented. No Rust was written. `tools/staking_core_writer.py` is an evidence tool.

Comparison with upstream and reference:

| Source says | #94 |
|---|---|
| upstream action 17, outcome operation | action 17 drops, the bound is 16 (`action_0x11`) |
| upstream has no action 14 | arm 14 builds tag `0xbc` from u64, u64, bool |
| upstream: abstraction 1, 2, 3 | modes 1, 3, 4 in the row |
| upstream: only order and vault transfer are delayed | every row reaches the delay wrapper here. Which are delayed is decided inside it |
| reference has `SetCoreWriterActionEnabled` raw `0x5d` | arm is raw `0x5b` in the table |

## Results and limitations

Coverage: 5101 rows reached of 30 functions, 24193 of 134189 bytes, where hosts count whole. 1247 possible edits on reached rows; 1247 tested, 886 killed, 361 survived. Survivors per function: `raw_action_host` 73, `block_row_loop` 37, `decode_order` 29, `decode_send_asset` 25, `decode_vault_transfer` 21, `raw_action_log_decode` 16, `decode_wallet` 14, `abi_bytes_encode` 13, `decode_bole` 13, `decode_finalize` 13, `decode_token_delegate` 11, `decode_class_transfer` 10, `abi_bytes_decode` 9, `decode_spot_send` 9, `decode_supply_delta` 9, `decode_abstraction` 7, `decode_builder_fee` 7, `decode_cancel` 6, `wallet_head_check` 6, `decode_cancel_cloid` 5, `disabled_set_insert` 5, `disabled_set_remove` 3, `sender_map_lookup` 3, `sender_tree_lookup` 3, `vote_apply_writer_arm` 3, `vote_apply_writer_arm_copy` 3, `vote_apply_writer_arm_third` 3, `decode_one_u64` 2, `row_push` 2, `sender_table_lookup` 1. They were not classified one by one. 23 constants are byte checked in `constants.tsv`. 39 unit tests pass with 0 skipped, including patched byte controls.

Limitations:

- `0x34273d0` is not read, so what makes the first list is unknown here. Its rows are hook inputs.
- Tag `0xbc` as `SystemAlignedQuoteSupplyDeltaAction` and the handler column in `arms.tsv` come from the dispatch packets, not from a run. Tag `0xc2` has no variant name in them.
- Inference: `E+0x3150` is `disabled_core_writer_actions`. Bound by its key shape, the reference label and the field text beside `l1_transfers_enabled`, not by a serializer row read here.
- Inference: `E+0x8d0` is the vault tree, as earlier packets say. `E+0x39e8` and the rows of `E+0x740` have no name here. A plain reading is that a sender needs a row in the table and must not be a vault.
- Row bytes other than the named fields are not compared. Some hold stale register bytes that are not fields.
- Copies of the loop and of the block function are not run. Only call sites are listed in `callers.tsv`. The host is a single body.
- `0x14385c0` is a hook; gates one and two call it and its result is not used at these sites.
- Metric blocks are hooks. Nothing here was run on a real block.
- Fixture trees are leaf nodes, except the writer cases, which build real internal nodes.

Next question: what `0x34273d0` accepts as a first list log, and which tree or fields `E+0x39e8` is.
