# staking: CStaking state wire form in node #94, both directions

This packet gives a reconstruction the exact `CStaking` state type and its file form: 20 structs and 83 fields with key order, required or default rule, skip rule, map and set order and every decoder refusal, checked by running the real msgpack and JSON readers and writers of node #94 against a separately written rule list. It also shows three decisions the reference tree cannot give: `commission_bps` defaults to 10000, `UserState` drops default fields even in array form, and the msgpack writer's `Ip` tuple is refused by all three msgpack readers unless the writer's human flag is 1.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/staking.rs` was read as a lead only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an interpreter of those bytes. Struct and key names are rodata and decoder error text from the binary. Meanings of short keys are not claimed. Unresolved items are under limitations.
- Scope included and excluded: included are the state writers `0x39908e0` (msgpack) and `0x3990470` (JSON), the readers `0x175f130` (msgpack, copies `0x2bc6810`, `0x3eda980`) and `0x1d0cb80` (JSON, copy `0x318d7d0`), and the 43 functions in `path.tsv`. Every callee runs for real, helpers already listed elsewhere included (`0x3a05a10` is a stub of the tokenDelegate packet, `0x3a0bc50` is only a row of #875); only allocator, copy, compare and panic slots are hooked. Excluded: the Exchange level wrappers `0x3798c80`, `0x3793de0`, the outer readers `0x16d4030`, `0x1b31c40`, and every state transition that writes these fields. Implementation: not yet implemented.

## Reproduce

From the repository root:

```
python3 tools/cstaking_state_wire.py --out research/work-items/staking-cstaking-state-wire-94
python3 -m unittest tests.test_cstaking_state_wire
```

The tool takes about 5 minutes with 3 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed.

Generated files: `evidence.json`, `path.tsv`, `fields.tsv`, `root-offsets.tsv`, `memory-checks.tsv`, `texts.tsv`, `route-word.tsv`, `copies.tsv`, `wire-samples.tsv`, `scenarios.tsv`, `function-rows.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. The state is 0x298 bytes, from the 0x270 byte copy at `0x16fda84` plus the 0x28 head words moved around it. No hand built state is used: each case goes in through a real reader, and the memory it builds goes out through the real writers.

### Method

```
msgpack or JSON input -> 0x175f130 or 0x1d0cb80 -> state memory
state memory -> 0x39908e0 named, human 0
             -> 0x39908e0 array, human 0
             -> 0x39908e0 array, human 1
             -> 0x3990470 pretty JSON, two space indent
```

The rule list in the tool predicts all four outputs byte for byte, or the exact error text, for 566 named cases (467 of them refusals) and 6 generated states.

### Root, 22 fields in wire order

`root-offsets.tsv` gives each key and the state offset read from the `lea` rows of `0x39908e0`. `memory-checks.tsv` proves 21 of the words after a real decode.

| Key | Offset | Type | Absent key |
|---|---|---|---|
| stakes | 0x0 | EpochTracker of CValidatorStakes | error |
| allowed_validators | 0x120 | set of address | error |
| allow_all_validators | 0x290 | bool | error |
| broadcasters | 0x138 | set of address | error |
| validator_to_profile | 0x150 | map address to CValidatorProfile | error |
| delegations | 0x168 | Delegations | error |
| proposals | 0x198 | map 32 bytes to Proposal | error |
| stakes_decay_bucket_guard | 0xa0 | BucketGuard | error |
| jailed_signers | 0xb0 | EpochTracker of address set | error |
| jvt | 0x70 | RawSignatureTracker | name `jail vote tracker`, empty |
| jail_until | 0x1b0 | map address to time | error |
| signer_to_last_manual_unjail_time | 0x1c8 | map address to time | error |
| native_token_reserve | 0x60 | optional wei, tag +0x60, value +0x68 | nil |
| stage_reward_bucket_guard | 0x100 | BucketGuard | error |
| validator_to_staged_rewards | 0x1e0 | map address to wei | error |
| distribute_reward_bucket_guard | 0x110 | BucketGuard | error |
| user_states | 0x1f8 | map address to UserState | error |
| pending_withdrawals | 0x210 | PendingWithdrawals | error |
| self_delegation_requirement | 0x240 | wei | error |
| disabled_validators | 0x248 | set of address | empty |
| disabled_node_ips | 0x260 | set of Ip or LocalNode | empty |
| validator_to_state | 0x278 | map address to CValidatorState | empty |

`fields.tsv` lists all 83 fields of the 20 structs. BucketGuard memory order is `bucket_millis` then `last_bucket`, the opposite of wire order (`memory-checks.tsv`).

### Rules a reconstruction needs

- Maps are written as an array of `[key, value]` pairs in sorted key order. The readers take a map or that array. A repeated key gives `duplicate key`.
- Sets are arrays. Input in any order comes back sorted with repeats gone; `Ip` rows sort before `LocalNode` rows.
- Struct head: `0xde 0x0016` named, `0xdc 0x0016` array at the root, fix forms below 16.
- Serializer byte `+0xb` is the named flag and `+0xa` the human flag. The human flag changes only `Ip`: 4 element array at 0, dotted text at 1.
- Time text: fraction none, 3, 6 or 9 digits, the shortest that holds the value. `T` separator is required; a zone gives `trailing input`.
- Address text: lower case `0x` hex out. In: with or without `0x`, either letter case, but not `0X`, also 20 element byte arrays and bin8.
- Wei: integer, or an array whose first element is read. `[5, 6]` keeps 5. `-1` gives `invalid value -1 for WeiPriv when visiting i64`.
- `period` and `bucket_millis` are non zero.
- `commission_bps` absent keeps 10000 and `delegations_disabled` false. Its nil text says u64.
- `UserState`: `b` 0 and `l` nil are not written, also in array form, so its array shrinks. `[T]` (b 0, l set) is written by the array form and refused by the reader: `invalid type: string ..., expected u64 for WeiPriv` (case `array_form_of_time_only_row_refused`).
- Array input: a short array stops with `invalid length N, expected struct S with M elements` at the first field that must exist. `native_token_reserve` and `max_n_validators` may be absent in a map but not in an array.
- Array one element too long gives rmp error kind 4 (`*_array_long`).
- Unknown keys are skipped, a repeated field gives `duplicate field`, a byte after the value is left to the caller.
- `hsc` is `[]` in msgpack, `null` in JSON. `qst` is `N` as text or `{"Q": nil}`; text `Q` is refused. `qst` absent keeps `N`, in a map and in a short array alike (`uniquekeystate_qst_absent`, `uniquekeystate_array_1_of_3` stops at length 2, the `vts` slot).

### Ip tuple and the readers

`0x39908e0` with human 0 writes `{"Ip": [a, b, c, d]}`. All three msgpack readers take only text and give `invalid type: sequence, expected IPv4 address` for the array (`ip_tuple_refused`, unit test on all three copies). The file route options word `0x01000400` at `0x28eb25e` (`route-word.tsv`, from the Bridge2 JSON packet) sets human 0. So a state with an `Ip` row written by that word cannot be read back by these readers. Inference: `abci_state` files with `Ip` rows use another route or another reader. Not proved here.

### Reference comparison

| Reference `l1/staking.rs` | Bytes |
|---|---|
| `CStaking` with 11 fields, `user_to_delegations` at the root | 22 fields, the map sits in `delegations` |
| `epoch_states`, `validator_to_epoch_delegation` at the root | `stakes` EpochTracker and `delegations.validator_to_state` |
| `pending_withdrawals: map to Vec<WithdrawalRequest>` with `unlock_epoch` | `queue` map time to rows of user, wei, and `user_to_total_withdrawal` of wei, n |
| `rewards` two maps | no such keys; `user_states` has `b`, `l` |
| `CValidatorProfile` order `node_ip, name, description, commission_bps, delegations_disabled, signer` | `delegations_disabled` before `commission_bps` |
| `node_ip: Option<String>` | enum Ip or LocalNode(u8), required |
| no governance | `proposals` with `Proposal` 7 fields, category `accelerated, constitutional, ecosystem, electoral`, choice `yes, no, abstain` |

## Implementation and comparison

Not yet implemented. The rule list in `tools/cstaking_state_wire.py` (`STRUCTS`, `canon`, `emit`, `plain`) is a test model, not a port.

- 43 named functions, 8188 reached rows, 42223 of 77496 body bytes.
- 566 named cases and 6 generated states: 0 mismatches.
- Copies: `copies.tsv`, same outcome on a sample of cases.
- Mutation: every 12th edit of reached conditional and immediate rows, 216 edits, 117 killed, 99 survived. Survivors by row shape, from `function-rows.tsv`; none is classified one by one, each gave an equal outcome on every picked case that reaches the row:

  - 49: `mov al,1`, bytes `b001`
  - 21: `mov` rows
  - 11: `cmp` rows
  - 8: `jcc` rows
  - 4: `shr` rows
  - 2: `add` rows
  - 2: `test` rows
  - 1: `cmov` rows
  - 1: `sub` rows

- Unit tests: 15 passed, 0 skipped, in a PATH without binutils.

## Results and limitations

- `ValueState` fields are not pinned: only `struct ValueState with 2 elements`, a unit key, and empty `vts` were run.
- A set of 20 rows reached a panic slot in the interpreter and a set of 10 did not. Maps of 40 rows are fine. Not resolved: this may be the interpreter's sort path, so nothing is claimed for large sets.
- Meaning of `t`, `w`, `c`, `m`, `e`, `b`, `l`, `n` is not claimed. `memory-checks.tsv` covers root words and row counts, not nested row offsets.
- Which route carries the real state, and the Ip question above, are open.
- JSON refusals ran for the first field of each struct and the root, not for each field.
- Mutation is a sample and uses at most 8 cases per edit.
- Reader bytes after the first value are left to callers not run here.

Next question: which function writes `proposals` and reads `Proposal.category`, and which route and reader handle `abci_state` with `Ip` rows.

## Review correction: signed multiply overflow

The original PR #1129 head `0384f6e2c3f7e64188488ffd9716eb1e21bac461` left CF/OF unchanged after IMUL2 and IMUL3.
Native instruction starts and operands show 64-bit IMUL3 at `0x1515000` followed
by JO at `0x1515004`, and IMUL2 at `0x151a6ff` followed by JO at `0x151a704`.
GNU objdump 2.47.20260726 checked these against the target digest above.

The submitted evaluator accepted `+18446744073709553639-11-14T22:13:20` as year2023.
The corrected Python evaluator sets CF and OF from the full signed product at
the decoded width; overflowing years now return `input is out of range`.
This was an evaluator error, not an observation that node94 accepts those years.
`review-original-overflow.json` retains the original counterexamples and corrected
abstract results. `original-submission/` preserves the exact original source,
tests, README, manifest and exports with source binding. No captured target ran.

Four added tests cover both native IMUL/JO pairs, decoded16/32/64-bit multiply
boundaries and flag clearing, every relevant reader copy rejecting wrapped years,
and unchanged valid explicit +2023. `review-regeneration.json` records fresh
corrected export hashes beside their original hashes. Original schema and valid
fixture conclusions remain bounded by the limitations above.
