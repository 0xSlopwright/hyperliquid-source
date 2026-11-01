# staking: stake accounting and the active validator set in node #94

This packet recovers how node #94 moves stake and how stake becomes consensus power, so a reconstruction can write the path from bytes: every wei move of delegate, undelegate and reward compounding across four books, the history row a stake read uses (the last row at or below `current_round - 200`, not the newest), the top N filter, per mille signer power, and the foundation boost that leaves the foundation set less its largest member with more than 2/3 of the power.

- Component ID: staking (Staking and validator lifecycle), first task: stake accounting and epoch transitions for #94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `cec50f68e01c967d21538d48c49683ddeea52767` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is only compared at the end.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are the 32 functions in `path.tsv`. The core `0x398dc90`, its two books functions `0x3c0e8b0` and `0x3c0f6e0`, the sink `0x3990130` and the power map `0x3c10fa0` were named before only as stubs or as rows of a recorder list (`RE-004-qty-recorder-lines-94`, `RE-004-wei-saturating-ops-94`, `staking-delegate-entry-94`, `staking-reward-tick-94`, `staking-c-signer-jail-94`, `staking-validator-l1-vote-94`). No packet states their logic. Excluded: the gate in front of the core (`staking-delegate-entry-94`), the reward amounts behind the sink (`staking-reward-tick-94`), who advances `current_round`, and the consumers of the power map.

## Reproduce

From the repository root:

```
python3 tools/staking_stake_accounting.py --out research/work-items/staking-stake-accounting-94
python3 -m unittest tests.test_staking_stake_accounting
```

The tool takes about 4 minutes with 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program. The binary is never executed: an interpreter inside the tool evaluates its bytes.

Generated files: `evidence.json`, `path.tsv`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `status-text.tsv`, `lock-seconds.tsv`, `scenarios.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. `S` is the `CStaking` state (Exchange `+0x8f8`). Field names are the wire keys of `staking-cstaking-state-wire-94`. Offsets and immediates are pinned byte for byte in `constants.tsv`. The method needs no hand built memory: a state goes in through the real reader `0x175f130`, the functions run on that memory with every callee real (inserts, node splits and merges, removals, the sorts, `LazyLock` of the foundation sets, the time add), and the real writer `0x39908e0` gives the state back. Only the two failure sinks `0x3c1ada0` and `0x3999770` and the recorder `0x358dcd0` are hooked, and their calls are compared too.

### Path

```
token delegate gate (staking-delegate-entry-94) or sink below
  slot 0x5774d20 -> core 0x398dc90(out, S, row)
    row: +0 tag, +8 value, +0x10 wei, +0x18 block time, +0x24 user, +0x38 validator, +0x4c chain byte
    0x37d5e10 history key
    tag 2   -> 0x3c0f6e0 delegate books, then target += wei
    other   -> 0x3c0e8b0 undelegate books, then target -= wei, effective = min, self row test
reward payout 0x33709f0 -> sink 0x3990130 -> core, row (2, 1) per reward row

any stake reader, slot 0x5775128 (callers.tsv)
  0x3c10fa0(out, stakes row, chain byte, S)   signer -> power
    0x3c11bd0  active set
      0x3bb0300 + 0x3be5f30   rows (validator, effective)
      0x3387f80 / 0x3bc02c0   sort by 0x33c2fb0
      0x3316460 + 0x3307df0   filter, limit, map
    per mille, boost
    0x3316640 + 0x3bd4d80 + 0x3be48f0   validator to signer
```

### The four books

| Book | State | Row | Fields |
|---|---|---|---|
| User balance | `user_states` S+0x1f8 | 0x18 | `b` wei, `l` lock time |
| Delegation | `delegations.user_to_delegations` S+0x168 | user to map of validator to 0x18 row | `w` wei, `t` time |
| Epoch member | `delegations.validator_to_state` S+0x180 | validator to 0x20 row: `total_delegated`, map of user to `c`, `m`, `e` | `c` current, `m` low mark, `e` key of the last change |
| Stake | `stakes.current.validator_to_stake` S+0x10 | validator to 0x10 row | `effective` word 0, `target` word 1 |

The word the reward packet could not name, the member tree at S+0x180, is this `validator_to_state` map of `Delegations`, and its words are `c`, `m`, `e`.

### Core gates, first failure wins

| Step | Test | Status |
|---|---|---|
| 1 | validator not in `validator_to_stake` | `0x91` Unknown validator |
| 2 | no history key | `0x97` |
| 3 | tag 2, value bit 0 clear, profile row has `delegations_disabled` | `0xfd` |
| 4 | tag 2, no `validator_to_state` row (S+0x278) | `0x91` |
| 5 | tag 2, that row has `delegations_blocked` | `0xfd`, reward rows too |
| 6 | tag 2, available below wei | `0xfc` |
| 7 | not tag 2, no delegation row, or `w` below wei | `0xfe` |
| 8 | tag 0, row time after block time, nanosecond exact, equal passes | `0xff` |
| 9 | tag 0, `w - wei` below the value word | `0x130` |

`available = max(b - pending, 0)`, with `pending` from `user_to_total_withdrawal` (S+0x228) of the user. A refused call leaves all state as it was (each refusal case compares the written state). Value bit 0 skips step 3 only.

### Delegate, tag 2

```
b -= wei                            user row is created first if absent
t = value bit 0 ? t (or block time on a new row) : block time + lock seconds
w += wei
total_delegated += wei              group row created if absent
member new: c = wei, m = 0, e = key
member old: if e != key: e = key, m = c
            c += wei
target += wei, effective untouched
```

`w`, `total_delegated` and `c` saturate and call the recorder. A `target` overflow goes to `0x3c1ada0` with status `0xbe`, leaves `target` alone, and the core still gives `0x186` with the other books moved (`delegate_target_overflow`).

`lock-seconds.tsv` is the table `0x20be20`, indexed by the chain byte: 604800, 120, 120, 86400 s. So a mainnet row (chain byte 3) locks for one day, and any new delegation resets the whole row to that time. This is the time step 8 reads, and it is why reward rows keep the time: a compounded reward never extends a lock.

### Undelegate, other tags

```
b += wei                            saturating, row created if absent
w -= wei; w == 0: row dropped, user dropped when its map is empty
total_delegated -= wei              saturating, group row created if absent
member absent: created as c = 0, m = 0, e = key
c -= wei                            saturating
e == key: m = min(m, c)   else: e = key, m = c
c == 0: member dropped, group dropped when no member is left
target -= wei                       saturating
effective = min(effective, target)
user == validator and a validator_to_state row exists:
  self row absent or w below self_delegation_requirement: delegations_blocked = true
```

So a self exit below the floor blocks the validator instead of failing, and delegations stay blocked until something else clears the byte. No path in these functions clears it. `m` is the weight the reward packet reads while `e` equals the latest key, so wei added in an epoch earns nothing until the next key, and wei taken out stops earning at once. That reading of `m` is inference from the two packets together.

### History key, a correction

`0x37d5e10` calls `0x2fe1490`, whose first compare is an upper bound test: a bound below every key gives an empty range. The real result is:

```
start = low if cur < low + 2000 (saturating) else max(cur - 200, low)
key   = last key of round_to_val with key <= start, else None
```

`low` is `initial_round`, `cur` is `current_round`. `staking-reward-tick-94` states "the last row with key at or past start", read from a stub. The real bytes give the opposite side (`window_*` cases, 14 of them). So stake readers lag `current_round` by at least 200 rounds, and until the chain is 2000 rounds past `initial_round` they read the row at `initial_round` itself. The stage step of that packet reads this function. Its sibling `0x37d9cf0` has the same head and is not run here.

### Reward compounding, `0x3990130`

Input rows are 0x38 bytes: amount, user, validator, kind (0 commission, 1 delegator). Kind 2 ends the walk. For each row, `(user, kind) -> amount` is added to the returned map, saturating, and then the core runs with row `(2, 1)`, block time from Exchange `+0x60`. A refusal goes to `0x3999770` and the walk goes on, so the map still counts the row, the balance keeps the amount, and only that row is lost. The merged map has 0x15 byte keys, address then kind.

That closes the loop of the reward packet: rewards reach `b`, then `w`, `total_delegated`, `c`, `target`. `effective` follows by decay. A user with pending withdrawals keeps rewards in `b` whenever `b - pending` is below the amount.

### Active set, `0x3c11bd0`

Reads `effective` of a stakes row.

1. Order: foundation members first, then `effective` descending, then address ascending. `0x33c2fb0` is the compare, `0x3387f80` runs below 21 rows, `0x3bc02c0` from there.
2. Walk in that order with `left = max_n_validators`, `u64::MAX` when absent. `left` 0 gives an empty set.
3. Skip a row with no profile. Skip a non foundation row when `self_delegation_requirement` is not 0 and its self delegation `w` is below that, or absent. So a skipped row does not use up `left`.
4. A row taken with `effective` not 0 sets a live flag.
5. No live flag: each foundation member gets +1, inserted if absent. This is the zero stake start of a chain. The other arm of `0x3c11d7f` (empty set) is not reachable, the sets have 4 or 5 members.

Foundation set: the validators of chain byte 3 (5 keys, cell `0x5786238`), and the 4 keys of chain bytes 1 and 2, the lists in `staking-delegate-entry-94`. Chain byte 0 panics. `jailed_signers` is not read here: a jailed signer keeps its power.

### Power, `0x3c10fa0`

```
total = sum of the set
each validator: share = 1000 * value / total, floor
S = sum of shares, I = sum over foundation, M = largest foundation share
need = 2*S + 3*M - 3*I
need >= 0:  extra = ceil((need + 1) / (n - 3)), each foundation member += extra, inserted if absent
each validator -> signer of its profile, the validator itself with no profile
same signer twice: the row of the larger validator address stays, no sum
```

With `n` members, foundation less its top member holds `I + n*e - (M + e)` of `S + n*e`. The choice of `extra` makes `3*(I - M) + (n - 3)*e > 2*S`, which is the same as that part being above 2/3 of the new total. `test_boost_gives_foundation_less_top_member_over_two_thirds` checks one case, the algebra is the rest. When `need` is below 0 nothing is added.

A value with `1000 * value` above `u64::MAX`, or `total` 0, stops the walk there: rows done so far are shares, the rest stay raw, and no boost runs (`large_values_bail_raw`, `large_second_row_bails`).

### Callers

`callers.tsv` lists each site from a byte scan: `core` through slot `0x5774d20`, the power map through slot `0x5775128`, with the host function.

## Implementation and comparison

Not yet implemented in Rust. `tools/staking_stake_accounting.py` evaluates the real bytes and a rule list written apart from the evaluator predicts each run: return values, every recorder and failure sink call, and the byte exact msgpack of the whole 22 field state.

Cases: 189 named and 30 seeded sequences of 12 mixed operations on tall trees. All match. 1150 conditional rows and immediates were reached; every ninth one was edited, one at a time, and run against up to 6 cases that reach it: 128 edits, 103 killed, 25 survived. `mutations.tsv` has each row. Survivors were not classified one by one. By function: `insertion_sort_active` 4, `active_order` 3, `signer_power_map` 3, `stake_core` 3, `undelegate_books` 3, `active_filter` 2, `active_validators` 1, `delegate_books` 1, `history_latest_row` 1, `member_row_insert` 1, `reward_compound_sink` 1, `signer_vector` 1, `user_books_remove` 1.

Tests: `tests/test_staking_stake_accounting.py`, 28 tests pass, 0 skipped. Negative controls: a wrong digest, an address outside every FDE, a wrong pin, patched status and compare bytes, a wrong lock second and a wrong window rule.

Reference comparison, `l1/staking.rs`:

| Reference | Bytes |
|---|---|
| `delegate` adds to one `delegations` map and one global `total_delegated` | four books; no global total here, `total_delegated` is per validator |
| `undelegate` refuses when `delegations_blocked` is set on the user | the flag is on the validator and only gates delegate |
| `apply_token_delegate` reads `delegations_disabled` only | also `delegations_blocked` of `validator_to_state` |
| `EpochDelegation` has `total_delegated`, a map and a flag | `ValidatorState` row with `c`, `m`, `e` members |
| no lock on a delegation | row time plus chain seconds, tested on tag 0 |
| epoch profile sums balances | `effective` of a history row, top N, per mille, boost |

## Results and limitations

- Requesting no progress gate. This is one path of the staking component.
- Who advances `current_round` and `initial_round` is unknown. A byte scan of the staking ranges found no writer, so cases set them directly.
- Row tags come from the gate of `staking-delegate-entry-94` and the sink. Tags 0, 1 and 2 are the ones those build; which actions reach tag 1 is not shown here.
- Names `c`, `m`, `e` are wire keys. Their meaning as current, low mark and key is inference from the arithmetic.
- The name "foundation" for the sets is inference, the bytes name no such thing.
- What the consumers do with the power map is not read here. The set-empty arm and sets below 4 members cannot run on these three chains, so those rows are unreached.
- Panic rows are not run: chain byte 0, and a sum of stakes above `u64::MAX`.
- Sort path `0x3bc02c0` runs real on 21 and more rows and is not mutated.

Next question: which function writes `current_round` and `initial_round` of the `stakes` tracker, and what clears `delegations_blocked`?
