# staking: VoteGlobal admission, vote tally, pass and row pop in node #94

This packet recovers who may vote a global change in node #94 and when a vote takes effect, so a reconstruction can write the whole path from bytes: a signer must be a validator or one of three listed addresses, each action key collects validator keys and listed signers in one tracker row, a strict two thirds stake test alone passes it in this build, and a pass pops the entire row, so votes for every other action are thrown away before the action is applied. The same read gives the gate class of all 88 actions: which need a validator signer, which take any signer, and which are refused.

- Component ID: staking (Staking and validator lifecycle), first task: stake accounting and epoch transitions for #94. Validator membership decides these votes.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only, compared at the end. Nothing is copied from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are the 21 functions in `path.tsv`: the VoteGlobal host in three copies, the vote and pop wrappers, the tally and quorum in two copies, the listed count, the two listed set initializers and the gate in three copies. Stubs with checked arguments, listed in `stubs.tsv`: apply `0x2355f40`, validator lookup `0x33690c0`, member test `0x3367530`, stake quorum `0x3366b60` (read in `staking-force-increase-epoch-94`), user resolve `0x275ea20`. Excluded: the dispatcher above the host, `0x1e8db10` above the gate, `0x45b0810` and its caller `0x4742f00`. Overlap: the hosts are named in earlier packets only as dispatch rows or as unread callers, `staking-vote-arms-94` and `bridge-settings-votes-94` both say the quorum in them is not read; `0x2329990` and `0x2329610` appear only as caller rows of call site lists. `helpers.tsv` keeps `0x13a9c60` and `0x335ecb0` as context with no rows and no mutants.

## Reproduce

From the repository root:

```
python3 tools/staking_vote_quorum.py --out research/work-items/staking-vote-quorum-94
python3 -m unittest tests.test_staking_vote_quorum
```

The tool takes 2 minutes under load. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, checks the input SHA-256 first, starts no external program and never executes the binary. It only reads bytes and runs them in its own interpreter.

Generated files: `evidence.json`, `path.tsv`, `helpers.tsv`, `stubs.tsv`, `function-rows.tsv`, `constants.tsv`, `status-text.tsv`, `action-classes.tsv`, `listed-sets.tsv`, `scenarios.tsv`, `callers.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. Slot targets come from `.rela.dyn` RELATIVE rows. `constants.tsv` binds 55 instructions of the path to their bytes. Status text comes from the Display table `0x59a8d0` (`status-text.tsv`).

### Map

```
gate 0x282ec60 (copies 0x48f5570, 0x48f52e0)
  0x335ecb0  class byte from 0x58c1d8
  class 0, 1  0x33690c0, class 1 falls to the listed set
  class 2     signer as it is
  class 3     0x275ea20
  class 4     0x7d
host 0x2704d90 (copies 0x4e03dd0, 0x4e04300)
  0x13a9c60  signer in the listed set
  0x33690c0  signer to validator key
  fast test  raw tag
  0x1eac160 or 0x1eabf10
    0x2329990 tally
      0x3367530 member test
      0x2329610 quorum, 0x3366b60 stake, 0x145a660 listed count
  0x2329770 row pop, through 0x1eabe10 on the fast side
  0x2355f40 apply
```

### Gate class

`0x335ecb0` reads the action word. A word of `0x74` or more gives index `word - 0x74`. A smaller word is a raw VoteGlobal tag in the same niche and gives index 20. The class byte comes from the 88 byte table at `0x58c1d8`. All rows are in `action-classes.tsv`.

| Class | Actions | Rule | Failure |
|---|---|---|---|
| 0 | `SetGlobalAction`, `VoteAppHash` | `0x33690c0` must find the signer | `0x7b` Signer must be a validator. |
| 1 | `VoteGlobalAction` | as class 0, then the listed set of the chain | `0x7b` |
| 2 | 36 actions | no test, the signer comes back | none |
| 3 | 43 actions | `0x275ea20` resolves a known user | its own status, `0x58` in the stub |
| 4 | `SystemBoleAction`, `SystemSpotSendAction`, `SystemUsdClassTransferAction`, `SystemApproveBuilderFeeAction`, `SystemSendAssetAction`, `SystemAlignedQuoteSupplyDelta` | refused | `0x7d` Action not allowed |

So the system actions can not come in as signed actions at all, and `SetGlobalAction` and `VoteAppHash` take no listed signer.

### Listed sets

`E+0x8f2 == 3` picks static `0x577ae70`, any other byte picks `0x577aea0`. Each is a `LazyLock` whose function is read from a RELATIVE row at its first word. The tool runs `0x1451fb0` and `0x14520e0` for real and walks the built set (`listed-sets.tsv`). The value is a B-tree set at `+0`, word `+0x18` = 0 and word `+0x20` = 1 on both chains.

| Chain byte | Addresses |
|---|---|
| 3 | `0x00..01`, `0x00..02`, `0x00..03` |
| other | `0x347e6c73..cc86`, `0xb9310ff6..5ac6`, `0xbdcae99d..ed49` |

### Tracker words

`T = E+0x3510` (third copy `E+0x3f90`).

| Offset | Word |
|---|---|
| `T+0x18`, `+0x20`, `+0x28` | row map root, height, length. The map has a zero size key, so one row is all any path here makes |
| row `+0` | passed action, word 0 is `0x74` for none |
| row `+0xf0`, `+0xf8`, `+0x100` | vote map root, height, length |
| row `+0x108` | passed byte |
| vote map node | 11 keys of `0xf0` at `+0`, values of `0x30` at `+0xa50`, length `+0xc6a`, edges `+0xc70` |
| vote value `+0` | set of 32 byte validator keys, keys at node `+0`, length `+0x16a`, edges `+0x170` |
| vote value `+0x18` | set of 20 byte signers, keys at node `+8`, length `+0xe6`, edges `+0xe8` |

The size `0x110` of a row with no key area is pinned at `0x2329de5`. Row size `0xbb0` of 11 values puts its length at `+0xbba`, the word `0x2329ca8` tests.

### Host

1. `listed = signer in set`. `0x33690c0` with `E+0x3840` and the word `E+0x3888` gives the 32 byte key.
2. Neither: `0x91` Unknown validator. The action is dropped and no tracker word moves.
3. Fast test. `index = tag - 0x12` for a tag of `0x12` or more, else `0x4e`. Fast means index `0xb`, `0x20`, `0x55`, or `0x4a` with byte `+8 == 1`. That is raw tags `0x1d`, `0x32`, `0x67`, and `0x5c` with the byte set.
4. Plain side: `0x1eac160` passes the static set. Fast side: `0x1eabf10` passes a clone of the map with `+0x18` and `+0x20` written as zero (`0x1eac004`). This is the only difference, and it is why a fast action never needs a listed count.
5. Result word `0x74`: status `0x186` with byte 0. The vote stays. No apply.
6. Otherwise the row pops first, `0x2329770` or `0x1eabe10`, and only then the action is rebuilt through jump table `0x3ed5e8` and applied. Apply status `0x186` gives byte 1. Any other status is returned as it is, and the row is already gone.

The second and third hosts take the action first and clone it, and report byte 9 with the flag at `+1`, or byte `0xe` with the status at `+8`.

### Tally

`0x2329990` walks at most two items: validator key if the lookup found one, then the signer if listed. For each item:

1. A key must pass `0x3367530` on the Staking at `E+0x3840`, else the item is skipped with no row. A signer is looked up in the passed set.
2. Row found or inserted empty, then the action key found or inserted with two empty sets.
3. `before = passed byte or quorum`.
4. The item goes into its set. A repeat changes nothing.
5. If `before`, next item. Else quorum again. On true: passed byte 1, the action stored in the row, result kept.

So one signer that is a validator and listed votes twice, one vote into each set, and the second sees the passed byte.

### Quorum

`0x2329610` is `stake and listed`:

- stake: `0x3366b60` over the validator keys of the action, with the epoch root, height and active epoch words of the Staking. Strict `3 * votes > 2 * total` as in `staking-force-increase-epoch-94`.
- listed: `0x145a660` counts the voted signers found in the passed set and returns `count >= set+0x18`.

Both are always evaluated. With the word at 0 the listed side is always true, so in this build the stake test alone decides. The word never changes after init in any function here.

## Implementation and comparison

not yet implemented

Reference comparison, `l1/exchange/handlers/20_vote_global.rs`:

| Point | Reference | Bytes |
|---|---|---|
| Quorum | comment says the wrapper owns tracker and quorum, no rule stated | two part test above |
| Row life | not stated | a pass drops all pending votes |
| Who votes | not stated | validator or listed, `0x91` else |

## Results and limitations

204 named cases (3 admit, 6 apply, 12 chain, 33 fast, 69 gate, 12 listed, 18 pass, 24 tag, 18 tally, 9 threshold) and 300 seeded vectors match a separately written rule list on results, the ordered stub log and the tracker read back after every vote, on all three copies. The rule list missed the fast side at first. A seeded vector showed a pass with a listed word of 2, and the clone in `0x1eabf10` explains it.

2873 rows of 23651 body bytes are reached (14007 bytes). 663 of 663 possible edits on reached rows run, one in every 1: 400 killed, 263 survived (`tally_copy` 55, `tally` 49, `row_pop_copy` 19, `row_pop` 17, `host` 15, `host_copy` 14, `host_third` 14, `vote_cloned` 10, `vote_cloned_copy` 10, `listed_count` 9, `gate_copy` 6, `gate_third` 6, `listed_init_chain_3` 6, `listed_init_other` 6, `quorum_copy` 5, `gate` 4, `pop_cloned` 4, `pop_cloned_copy` 4, `vote_plain` 4, `vote_plain_copy` 4, `quorum` 2). Survivors were not classified one by one. 30 unit tests pass, 0 skipped, with negative controls on digest, FDE bounds, pins, patched bytes and rule list edits.

- A listed word other than 0 is a fixture edit. No function here writes it, so those cases show the code, not this chain.
- Word `+0x20` = 1 has no reader in the functions here. Meaning unknown.
- `T+0x28` above 100 leads to `0x2562d40`. No path run makes a second row, so this branch is not reached and not claimed. `T+0x30` is passed to `0x145a660`, which does not read it.
- Raw tag `0x67` is not run: its payload layout is not known here. Index `0x55` is bound only by the pin. Rebuild arms of jump table `0x3ed5e8` other than the tags in `scenarios.tsv` are not run.
- Stubs: apply bodies, validator lookup, member test, stake quorum, user resolve. The stake rule in the stub is the one read in the earlier packet.
- The hosts are entered directly. What reaches `0x23e8640` is not read, and the gate is run on its own, not from `0x1e8db10`.
- `0x45b0810`, the second user of the listed count, is not run.
- Action names in `action-classes.tsv` come from `RE-014-action-dispatch-drift` and `RE-010-exchange-handlers`, not from this tool. Inference: raw tag `0x32` is the freeze vote, from the jump index label in the round clock work. The other fast tags are not named.

Next question: what the raw tags `0x1d`, `0x5c`, `0x67` are, and what `0x45b0810` decides with the same listed rule on the path from `0x4742f00`.
