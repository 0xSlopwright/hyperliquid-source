# staking: node #94 VoteGlobal staking arms, 14 raw tags to state writes

This packet shows what each staking governance vote changes in node #94 once it reaches the apply function `0x2355f40`, so a reconstruction can now write these arms: which `CStaking` field each raw tag edits, its range check, its refusal status, and the rule of each helper. It also corrects the reference tag table: from `0x41` on, the reference is 2 too high, and the wire readers prove `DisableCValidator` is raw `0x43` and `DisableNodeIp` is raw `0x44`.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `308e5127990217a9d6196992665da6ca1afd4b82` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/action/vote_global.rs` was read as a lead only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an interpreter of those bytes. Items under Inferences are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are 14 arms of `0x2355f40`, reached from its entry, and the whole helpers `0x1e80420`, `0x2868d10`, `0x284bd00`, `0x284bd90`, `0x25a7ef0`, `0x3991e80`, `0x3bb4810`, `0x284d320`, `0x2867e30`, `0x285b5c0`, `0x2867270`, `0x284ca00`, `0x2866560`, `0x325dc00`, `0x325db20`. The host `0x2355f40` is shared: other packets hold other arms, and this one reads only the arms in `arms.tsv`. Excluded and stubbed, see `boundary.tsv`: the CValidator body `0x2768ff0` (delegate entry packet), drops, next row of the jail vote map, the `jail_until` drop. The vote quorum in the callers `0x2387390` and `0x2704d90` is not read. Implementation: not yet implemented.

## Reproduce

From the repository root:

```
python3 tools/staking_vote_arms.py --out research/work-items/staking-vote-arms-94
python3 -m unittest tests.test_staking_vote_arms
```

The tool takes about 3 minutes with 3 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program. The binary is never executed.

Generated files: `evidence.json`, `path.tsv`, `boundary.tsv`, `arms.tsv`, `variant-tags.tsv`, `copies.tsv`, `constants.tsv`, `texts.tsv`, `scenarios.tsv`, `vector-outcomes.tsv`, `function-rows.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. Offsets are from the Exchange pointer in `rdx`. `S` is `Exchange +0x8f8`, the `CStaking` base of the state wire packet; field names come from its serializer keys.

### Method

Every case enters at `0x2355f40` with an action buffer and a 0x3c00 byte Exchange image filled with a position pattern. Trees are real B-tree nodes, and the limit table is a real hash table placed with the real hash `0x2840fb0`. A separately written rule list predicts the status, every boundary call, every changed Exchange byte and the rows of each tree.

Across 970 named cases and 300 generated cases there are 0 mismatches. The rules matched on 15 of 16 first smoke cases. The later fixes were in the fixtures (a `0x58` value row starts at node `+8`, and an emptied tree keeps its root) and one rule, listed under the None word.

### Dispatch

The tag is the first action word. `0x2355f4f..0x2355f7d` subtracts `0x12`, sends tags below `0x12` to row `0x4e`, and jumps through table `0x3dd1b8`, `0x62` rows. `arms.tsv` holds each staking row, read from the table.

| Raw tag | Arm | Field | Offset | Rule |
|---|---|---|---|---|
| `0x24` | `0x235880c` | `allowed_validators` | `S+0x120` | map of address to bool, true inserts, false removes, more than 10000 rows gives `0x143` and no edit |
| `0x38` | `0x235911a` | `broadcasters` | `S+0x138` | bool, address |
| `0x39` | `0x2358ecb` | `stakes.period`, `jailed_signers.period` | `S+0x28`, `S+0xb0` | two words, zero keeps the old value |
| `0x3a` | `0x2357356` | CValidator body | | calls `0x2768ff0` with a named validator |
| `0x3b` | `0x23582ae` | `jailed_signers.current`, vote map, `jail_until` | `S+0xd8`, `S+0x88`, `S+0x1b0` | all three dropped |
| `0x3c` | `0x2358f86` | `stakes.current.max_n_validators` | `S+0`, `S+8` | Option pair |
| `0x3e` | `0x2356cb4` | `jailed_signers.current` | `S+0xd8` | removes one signer, a missing one is no error |
| `0x3f` | `0x23589e6` | limit rows | `Exchange +0x740` | see Refund walk |
| `0x41` | `0x2356920` | `self_delegation_requirement` | `S+0x240` | writes only when dword `+0x80` is 1 |
| `0x42` | `0x2356d8d` | `allow_all_validators` | `S+0x290` | writes only when `S+0x240` and `S+0` are not zero |
| `0x43` | `0x23572a3` | `disabled_validators` | `S+0x248` | bool, address |
| `0x44` | `0x2356295` | `disabled_node_ips` | `S+0x260` | 5 byte key, bool |
| `0x45` | `0x23593ab` | `stakes_decay_bucket_guard` | `S+0xa0` | width and bucket, see Guards |
| `0x46` | `0x2359278` | `distribute_reward_bucket_guard` | `S+0x110` | width and bucket, see Guards |

Failing rows use two statuses: `0x13f` with the word at output `+8` for a word at or above `0xccccccccccccccc`, and `0x13e` with no payload for arm `0x46` seconds out of range. Arm `0x3a` passes the status of `0x2768ff0` and copies its 0x60 byte result. Every other arm gives `0x186`.

A refused second period keeps the first: `periods_5_ccccccccccccccc` gives `0x13f` and `stakes.period` is 5 afterwards.

### Wire tags

`variant-tags.tsv` binds names to raw tags from the readers. The `expecting` text function of a variant is in a vtable, and the single reader that loads that vtable stores the raw tag with `movq $tag,disp(%rsp)`. Five stores are checked byte by byte: `ModifyCStakingPeriods` `0x39`, `CValidator` `0x3a`, `UnjailSigner` `0x3e`, `DisableCValidator` `0x43`, `DisableNodeIp` `0x44`.

### Sets

`0x285b5c0`, `0x284ca00` (insert) and `0x2867270`, `0x2866560`, `0x2868d10` (remove) work on `BTreeSet<[u8; 20]>` with the same rows: keys at node `+8`, slot `+0xe4`, length `+0xe6`, edges `+0xe8`, leaf 0xe8, inner 0x148. Insert returns 1 on a present key and leaves the tree alone. Remove returns 0 on a missing key. An emptied tree keeps its empty root leaf. Cases cover heights 0 to 2, leaf splits and every merge position of a 12 row tree.

The action map of arm `0x24` has bool values at node `+0xe8` and edges at `+0xf8`, leaf 0xf8, inner 0x158. All nodes are freed on both the edit and the refusal path, down to `toggle_over_cap` with 10001 rows. `toggle_exact_cap` passes with 10000.

### Node IP key

`disabled_node_ips` keys are 5 bytes: tag, then 4 bytes. Node: keys at `+0xc`, stride 5, slot `+8`, length `+0xa`, edges `+0x48`, leaf 0x48, inner 0xa8.

- Tags compare first.
- An even tag compares the 4 bytes big endian (`bswap`).
- An odd tag compares one byte only, so `01 0b 01 02 03` equals a stored `01 0b 0a 0b 0c`, and a remove with the first key drops the second.
- Tag 2 is never inserted: `0x284d320` returns before the write on `cmp $2,%sil`.

### Refund walk

Arm `0x3f` reads one word.

1. `0x3991e80` builds the sorted union of the keys of `allowed_validators` and `validator_to_profile` through `0x3bb4810`.
2. For each key: a key with no profile row is skipped, its `0x91` status dropped.
3. For a key with a row, the word is checked here, so a word above the cap is refused only when a profile row exists (`refund_allowed_only_over_cap` gives `0x186`).
4. The signer is the 20 bytes at profile value `+0x38`.
5. When the count at `+0x758` is not zero, the signer is looked up in the hash table at `+0x740` (seed `+0x760`, row 0x58) and row word `+0x20` takes a saturating subtraction.

Two validators with one signer charge that row twice (`refund_shared_signer`). The refusal path frees the union set.

### Guards

`0x325db20` turns block time into `(width, bucket)`: seconds since 1970 from the 12 byte time at `+0x60`, milliseconds added, clamped at 0, divided by the width. Arm `0x46` requires 1 to 172800 seconds. The bucket is the current one.

`0x325dc00` does the same from a fixed date, 719528 days, the first day of 1971, and clamps seconds to 172800. So arm `0x45` sets bucket `31536000000 / width`, far below any current bucket, and takes no time input. Arm `0x45` clamps where arm `0x46` refuses: `decay_2a301` gives width 172800000, `reward_2a301` gives `0x13e`. Arm `0x45` cases start at 1 second.

### None word

Arm `0x3c` stores the second word only when tag 1 is read. On tag 0 `rax` still holds the jump table address, so `S+8` gets `0x3dd1b8`. The copies leave their own table there (`0x711064`, `0x711244`). A reconstruction may store anything in that word when the tag is 0, as the wire writer reads it only for tag 1.

### Copies

`copies.tsv`: `0x4caa870` and `0x4cb3200` have their own tables and helper copies. Every named case with fewer than 1000 rows runs through both and matches, with the None word changed to the copy table. `0x4cb3200` has the state at shift `0xa80`, from `+0x740` up, and calls `0x4d9dcd0`; `0x4caa870` has shift 0 and calls `0x4d9e0d0`. Both reach `0x3991e80` and `0x325dc00` through the same slots as the first copy.

## Inferences

- Arm names without wire text (`0x24`, `0x3b`, `0x3c`, `0x3f`, `0x41`, `0x42`, `0x45`, `0x46`) follow the reference list and the field they write. Only the fields are observed.
- `0x3f` as a refund of signer request weights rests on the reference name. The bytes show a subtraction on a table keyed by signer; the table name is not known.
- Tags 0 and 1 of the node IP key as an IPv4 form and a one byte form are read from the compare code only.
- `S+0x88` as the jail vote map rests on its place inside `jvt`; only the two cleared words are observed.

## Implementation and comparison

Not yet implemented. Comparison with the reference file as a lead:

| Reference claim | Bytes |
|---|---|
| `DisableCValidator` raw `0x45`, `DisableNodeIp` raw `0x46` | reader stores `0x43`, `0x44` |
| `SetSelfDelegationRequirement` raw `0x43` | arm `0x41` writes that field |
| `SetAllowAllValidators` raw `0x44` | arm `0x42` writes that field, with 2 gates the list does not name |
| `SetStakesDecaySeconds` raw `0x47`, `SetDistributeRewardBucketSeconds` raw `0x48` | arms `0x45`, `0x46` |
| `MaxNValidators(u64)` | Option pair |
| `ModifyCStakingPeriods { stakes: u64, jailed_signers: u128 }` | two 64 bit words at `+8`, `+0x10` |
| `DisableNodeIp { ip: [u8; 5], disable }` | field order and tag rule above |

The reference raw tags up to `0x3f` match on the arms read here.

## Results and limitations

`evidence.json` has the totals: 16 functions, 1777 instructions reached, 7614 of 41043 body bytes, 970 named and 300 generated cases, 0 mismatches. 487 mutants, every reached conditional and immediate, 402 killed, 85 survived. Unit tests: 31 passed, 0 skipped, in a PATH without binutils.

Survivors by row type:

  - 31: `mov` rows
  - 18: `cmp` rows
  - 10: `jcc` rows
  - 7: `imul3` rows
  - 7: `mov al,1`, bytes `b001`
  - 5: `shr` rows
  - 3: `add` rows
  - 1: `pshufd` rows
  - 1: `set` rows
  - 1: `shl` rows
  - 1: `test` rows

Each mutant runs on at most 12 cases that reach its row, so a survivor may die on a case not picked. Survivors are grouped by row type and were read as a list, not proved one by one. The visible kinds are `mov` of a zero into iterator words no later step reads, the dropped `0x91` status bytes, the unused return byte `b001` of the set helpers, and date arithmetic of the year path, whose full cases are only partly picked. The `cmp` and `jcc` survivors were not read; the list from the first pass had most of its rows in `0x3bb4810` and the set helpers. None of these is claimed equivalent.

Unknown or not covered:

- Quorum, signer checks and action decoding before `0x2355f40` are not run, so this packet says what an accepted vote does, not who may send it.
- `0x2768ff0` is a stub. Arm `0x3a` is shown up to its arguments and result handling.
- Allocation failure and panic rows are not reached. Vote map rows are stubbed, so their drop is shown by the iterator words only.
- Dword `+0x80` is named nowhere in this packet. Hash table `+0x740` is not named.
- Which code reads `S+0`, `S+0x28`, `S+0xb0` and the disabled sets at epoch roll is not read here.
- `VoteGlobalAction::SetHardPolicy` has a reader but no raw tag or arm in this packet.
- Requesting no progress gate.

Next question: where are `max_n_validators` and the two periods read when an epoch rolls, and which raw tag is `SetHardPolicy`.
