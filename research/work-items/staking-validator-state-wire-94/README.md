# staking: validator state wire forms in node #94, both directions

This packet lets a reconstruction read and write the three validator owned state blocks of node #94 byte for byte: `Staking` (epochs and validator rows), `ValidatorL1VoteTracker` (with the `ValidatorL1VoteAction` key enum) and `ValidatorL1StreamTracker`. It settles decisions the reference tree cannot give: validator rows and `allowed_validators` are keyed by 32 bytes, not an address; an absent `epoch_duration_seconds` keeps 3153600000 (100 years); a vote tracker's `hc` defaults to 0.5 and 0.5 while the nested `hsc` defaults to 0 and 0.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `546081f3` of this repository / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/staking.rs` was read as a lead only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an interpreter of those bytes. Struct, key and variant names are rodata and decoder error text from the binary. Meanings of short keys are not claimed. Unresolved items are under limitations.
- Scope included and excluded: included are the six root readers and six root writers in `roots.tsv`, their nested functions in `path.tsv`, and 17 copies in `copies.tsv`. Every callee runs for real; only allocator, copy, compare and panic slots are hooked. Two small helpers, listed by other packets, run but are not named or mutated here. Excluded: every state transition that writes these fields, the Exchange level readers above these roots, one more writer pair of `Staking` and of the vote tracker that other packets list, the accepted forms of the `O` variant, and rows of `RawSignatureTracker.i`. Implementation: not yet implemented.

## Reproduce

From the repository root:

```
python3 tools/validator_state_wire.py --out research/work-items/staking-validator-state-wire-94
python3 -m unittest tests.test_validator_state_wire
```

The tool takes about 4 minutes with 3 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed.

Generated files: `evidence.json`, `roots.tsv`, `path.tsv`, `fields.tsv`, `vote-variants.tsv`, `outcome-variants.tsv`, `root-offsets.tsv`, `memory-checks.tsv`, `texts.tsv`, `route-rows.tsv`, `copies.tsv`, `wire-samples.tsv`, `scenarios.tsv`, `function-rows.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Coordinates: virtual addresses of node #94, FDE bounds from `.eh_frame` through the shared parsers.

### Method

A case gives bytes to a real reader. If it is accepted, the state it built leaves through the real writers as msgpack with names, msgpack as arrays, and pretty JSON, and all three must equal the bytes a separately written rule list predicts. If it is refused, the error text or error kind must match. Schema discovery used the decoders' own texts: `missing field`, `invalid type ... expected ...`, `invalid length ... with N elements`, and supplying each found field to reveal the next.

### `Staking`

| Key | Offset | Type | Absent key |
| --- | --- | --- | --- |
| epoch_states | 0x30 | map u64 to EpochState | error |
| active_epoch | 0x48 | u64 | error |
| cur_epoch_state | 0x8 | EpochState | error |
| cur_epoch | 0x50 | u64 | error |
| epoch_duration_seconds | 0x0 | nonzero u64 | 3153600000 |
| allowed_validators | 0x58 | set of 32 bytes | empty |

`EpochState` is `validator_states` (map 32 bytes to `ValidatorState`) and `start_time` (absent keeps `1970-01-01T00:00:00`). `ValidatorState` is `delegations` (map address to plain u64), `hot_user`, `cold_user`. Zero duration is refused through the nonzero type, which also marks a failed result in word 0 of the output.

The readers keep no relation between fields: `active_above_cur_kept` and `active_row_absent_kept` show an `active_epoch` above `cur_epoch` and one with no row in `epoch_states` both accepted and written back.

The field name of this block in the Exchange form is `staking`: `route-rows.tsv` shows the wrappers `0x27b4330` and `0x27b0f40` reaching the writers, checked from the jump and call bytes and the key text.

### `ValidatorL1VoteTracker`

Keys in order: `prune_bucket_guard`, `atT` (map vote key to `ActionTracker`, absent empty), `active`, `hvs` (set of address, absent empty), `hc` (`ValidatorHardPolicy` `q` and `i` as f64, absent 0.5 and 0.5). A failed result is marked by byte `+0x50` equal to 2.

| Index | Wire | Variant | Payload |
| --- | --- | --- | --- |
| 0 | D | name not printed | string |
| 1 | Q | QuarantineUser | address, bool |
| 2 | C | CanonicalTokenDeployer | string, address |
| 3 | P | DisablePerpDex | string, bool |
| 4 | A | AlignedQuoteToken | usize, bool |
| 5 | G | AllowHip3GrowthMode | string, bool |
| 6 | O | OutcomeDeploy | 10 row enum, `outcome-variants.tsv` |
| 7 | E | ModifyAqav2 | `token`, `technicalStaker`, `treasuryStaker`, `treasuryEvmAddress`, `evmRebalanceContract` |

Rows sort by variant index and then by payload fields (`vote_keys_sort_by_variant_index_then_fields`). `ActionTracker` is `eti` time, `vtr` `RawSignatureTracker`, `qre` bool, `sta` `L1VoteStakes` (`vas` map address to wei, `qsf` f64). In this form `RawSignatureTracker.hsc` is a `ValidatorHardPolicy` absent as 0 and 0, and `i` has a unit key. The CStaking jail tracker with the same struct name holds a `NoopHardQuorumPolicy` there, so the two are different instances of one generic.

### `ValidatorL1StreamTracker`

One key, `risk_free_rate`, a `MedianStreamTracker`: `v` (map address to `LatestValue` of `t` time and `v` f64), `m` (optional f64, may be absent in a map, required in an array) and `b` (`BucketGuard`). A failed result is marked by word 0 equal to 2.

### Reference comparison

| Reference `l1/staking.rs` | Bytes |
| --- | --- |
| `epoch_states` inside `CStaking` | a separate `Staking` block, field `staking` of the Exchange form, with 6 keys |
| `StakingEpochState { validators: BTreeSet }` | `EpochState` with a map under 32 byte keys and `start_time` |
| `EpochValidatorState { delegator_balances, validator, signer }` | `ValidatorState { delegations, hot_user, cold_user }` |
| `staking_epoch_duration_seconds` in `CStaking` | `epoch_duration_seconds` in `Staking`, default 3153600000 |

### Inferences

- The 32 byte key is most likely the validator's ed25519 key: the join path checks a 32 byte key in `allowed_validators` and in `validator_states` before ed25519 verification of the same key. This packet does not run that path.
- A 100 year default means a state without the key effectively never rolls its epoch by time. Whether any live state omits it is not known.

## Implementation and comparison

not yet implemented

## Results and limitations

- 476 named cases (327 refusals) and 30 generated states, 0 mismatches against the rule list. 40 functions, 9610 reached rows, 47505 of 112209 body bytes.
- 17 copies matched on a light case subset: `copies.tsv` has the counts. Copies are compared on that subset only, not on all cases.
- 179 sampled mutants, one edit in every 14: 139 killed, 40 survived. Survivors by row type:
  - 19: `mov` rows
  - 14: `cmp` rows
  - 2: `jcc` rows
  - 2: `test` rows
  - 1: `and` rows
  - 1: `shl` rows
  - 1: `shr` rows
  They are not classified one by one. A mutant runs only up to 8 cases that reach its row, so a survivor is not proof of a dead row.
- Unit tests: 21 passed, 0 skipped, in a PATH without binutils.
- The interpreter needed four additions for these readers: `movss` with a memory side as a 4 byte move, `pslld`, `psrad` and `pandn`. Before the `movss` addition it moved 16 bytes and truncated addresses in array form; the rule list caught that.
- A first reading of the array form suggested writer and reader disagree on the order in `MedianStreamTracker`. That was a misreading: an optional field took a nil and shifted the error. The case `validatorl1streamtracker_written_array_read_back` keeps it closed.
- `D` has no variant name in any error text. `O` is pinned on the refusal side only: 10 variant names, element counts and first required key.
- `ValueState` fields and rows of `RawSignatureTracker.i` are not pinned, so accepted cases keep `i` empty. Float text covers only short values; shortest form printing of arbitrary doubles is not tested.
- Meanings of short keys (`atT`, `hvs`, `hc`, `eti`, `vtr`, `qre`, `sta`, `vas`, `qsf`) are not claimed.

Next question: which function writes `allowed_validators`, since the bytes here show a state load can fill it, and which path fills `RawSignatureTracker.i` of an `ActionTracker`.
