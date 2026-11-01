# fees: FeeTracker state wire form in node #94, both directions

This packet gives a reconstruction the exact `FeeTracker` state type and its file form: 14 structs and 56 fields with key order, required or default rule, skip rule and refusals, checked by running the real msgpack and JSON readers and writers of node #94 against a separately written rule list. It also ties the fee words other packets only knew by offset to their keys (`b` and `s` at user row +0x28 and +0x78, trial end `e` at +0x70, `l` at +0xb0, referrer `c`, `n`, `s`, `b`, `n_per_bucket`) and decides three things the reference tree does not give: `user_states` is a hash table with thread seeded keys that is written sorted, `total_fees_collected` is signed and `total_spot_fees_collected` is not, and an absent `aligned_quote_token_config` reads as 1.0, 1.0, 1.0.

- Component ID: fees (Fees and volume)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/fees/compute.rs`, `l1/action/vote_global.rs` and `55_start_fee_trial.rs` were read as leads only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an interpreter of those bytes. Struct and key names are rodata and decoder error text from the binary. Meanings of short keys are not claimed beyond the offset links. Unresolved items are under limitations.
- Scope included and excluded: included are writers `0x23386d0` (msgpack) and `0x23382e0` (JSON), readers `0x191fc80` (msgpack, copies `0x2df4790`, `0x3dec920`) and `0x1c42950` (JSON, copy `0x30a94a0`), and the 19 functions in `path.tsv`. Every callee runs for real; only allocator, copy, compare, memset and panic slots are hooked. `0x23382e0` was cited before as a key table by the fill ledger and collection packets; neither ran it. Excluded: the Exchange level wrappers (`0x2755770` holds the writer call, `0x1735c00` and `0x1befd10` the reader calls), every state transition that writes these fields, and the `FeeSchedule` vote decoder `0x1b2c4e0` (other packet). Implementation: not yet implemented.

## Reproduce

From the repository root:

```
python3 tools/fees_tracker_wire.py --out research/work-items/fees-tracker-wire-94
python3 -m unittest tests.test_fees_tracker_wire
```

The tool takes about 260 seconds with 3 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed.

Generated files: `evidence.json`, `path.tsv`, `fields.tsv`, `root-offsets.tsv`, `memory-checks.tsv`, `user-row-layout.tsv`, `texts.tsv`, `copies.tsv`, `wire-samples.tsv`, `scenarios.tsv`, `function-rows.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. No hand built state is used: each case goes in through a real reader, and the memory it builds goes out through the real writers.

### Method

```
msgpack or JSON input -> 0x191fc80 or 0x1c42950 -> state memory
state memory -> 0x23386d0 named
             -> 0x23386d0 array
             -> 0x23382e0 pretty JSON, two space indent
```

The rule list in the tool predicts all three outputs byte for byte, or the exact error text, for 436 named cases (271 of them refusals) and 6 generated states.

### Root, 10 fields in wire order

| Key | Tracker offset | Type | Absent key |
|---|---|---|---|
| fee_schedule | 0x0 | FeeSchedule | error |
| unrewarded_users | 0xf0 | set of address | error |
| user_states | 0xc0 | hash map address to UserState | error |
| referrer_states | 0x108 | map address to ReferrerState | error |
| code_to_referrer | 0x120 | map text to address | error |
| referral_bucket_millis | 0x138 | u64 | error |
| total_fees_collected | 0x140 | i64 `NtliPriv` | 0 |
| total_spot_fees_collected | 0x148 | u64 `NtlPriv` | 0 |
| collected_builder_fees | 0x150 | map address to map token to wei | empty |
| trials_disabled | 0x168 | bool | false |

The tracker offsets are the `lea` rows of `0x23382e0`; `memory-checks.tsv` proves the words and row counts after a real decode.

### Other structs

`fields.tsv` has all rows. Keys in wire order:

- `FeeSchedule`: `rates` (4 f64), `tiers`, `referral_discount`, `referrer_keep`, `destination`, `extra_destination_fractions` (map address to f64), `stake_discount_tiers`, `weigh_spot_volume_double`, `aligned_quote_token_config`.
- `FeeTiers`: `vip` of `VipFees` (`ntl_cutoff` u64 `NtlPriv`, `rates`, `staking_keep_frac_for_referrer`, absent keeps 0.0), `mm` of `MmFees` (`maker_fraction_cutoff`, `add`).
- `StakeDiscountTiers`: `tiers` of `StakeDiscount` (`boms`, `discount`).
- `AlignedQuoteTokenConfig`: `cross_scale`, `add_rebate_scale`, `vlm_contribution_scale`, all required when the struct is present.
- `UserState`: `r` optional address, `F` optional `UserFeeState`, `m` map address to u64, `l` optional date, `T` map token to `UserTokenState`.
- `UserFeeState`: `r` (4 f64), `b`, `t` optional `FeeTrial`, `s`.
- `FeeTrial`: `b` (4 f64), `n` (4 f64), `e` date, required.
- `UserTokenState`: `V` u64, then `U`, `C`, `r`, `F`, `T` wei.
- `ReferrerState`: `c` text, `n` usize, `s` map address to `ReferralState`, `b` u64, `n_per_bucket` usize.
- `ReferralState`: `t` time.

### Rules a reconstruction needs

- `user_states` is a hashbrown table at `+0xc0`: control pointer, mask, growth left, items, then two seed words at `+0xe0`, `+0xe8` taken from thread local storage at `fs:-0x470` (`memory-checks.tsv`; the fixture sets those words). Its rows are 0xe8 bytes. The writers collect the rows and sort by address first (`0x2579170`, `0x1febd10`), so the seed never reaches the file (`hash_map_of_40_rows_written_sorted`).
- Every other map is written as an array of `[key, value]` pairs in key order. Text keys sort by bytes. The reader takes a map or that array.
- A nested map in `collected_builder_fees` keeps an empty inner row (`builder_rows_sorted_empty_kept`).
- `UserState`, `UserFeeState`, `FeeTrial`, `UserTokenState`, `ReferrerState`, `ReferralState` drop every field at its default, in named and array forms, so array rows shrink. `F` with no fields stays as `{}`, row `dict()` stays as `{}`.
- The f64 skip test is a compare with 0.0: -0.0 is dropped and NaN is kept (`user_fee_b_negative_zero`, `fee_b_nan_kept`). The `r` test needs all 4 words to be zero.
- `ReferralState.t` at 1970-01-01T00:00:00 is dropped.
- f64 input: msgpack f64, f32 and integers are taken, also inside `rates`. Text gives rmp error kind 2. JSON writes NaN as `null`.
- JSON f64 text spelling: plain down to 0.00001, then exponent form (`1e-7`), `1e16` from there up.
- The JSON reader is not exact: `932133.0869140625` reads as `932133.0869140624` (`json_reader_f64_is_not_exact`). The msgpack route carries the bits.
- `rates` must have 4 rows: 3 gives `invalid length 3, expected an array of length 4`, 5 gives rmp error kind 4.
- `total_fees_collected` above i64 max gives `invalid value 18446744073709551615 for NtliPriv when visiting u64`. Negative `total_spot_fees_collected` gives `invalid value -1 for NtlPriv when visiting i64`.
- Date text is `YYYY-MM-DD`; a time tail gives `trailing input`. Time text fraction is none, 3, 6 or 9 digits, the shortest that holds the value.
- Unknown keys are skipped, a repeated field gives `duplicate field`, a byte after the value is left to the caller. Short arrays stop at the first required field; an array one longer gives rmp error kind 4.
- Text for a one field struct is `with 1 element`.

### User row, linked to other packets

`user-row-layout.tsv` reads one decoded row. Row +0 is the 20 byte address; value offsets below are row - 0x18. The offsets are observed; the Link column is inference from equal offsets in those packets.

| Key | Value offset | Link |
|---|---|---|
| F present | 0x0 | |
| F.r | 0x8 | row builders' rates, fees-tier-select |
| F.b | 0x28 | word the stake stage writes, fees-staking-link |
| F.t.b | 0x30 | |
| F.t.n | 0x50 | |
| F.t.e | 0x70 | trial end date, fees-start-trial |
| F.s | 0x78 | output +0x78 of the tier selection |
| m | 0x80 | map the builder gate reads, fees-approve-builder |
| T | 0x98 | six word value V U C r F T, fees-fill-ledger |
| l | 0xb0 | cooldown word fees-start-trial left open |
| r | 0xb4 present, 0xb5 address | binding of fees-set-referrer |

`l` is a packed date. Inference: the cooldown base is this stored field, so it survives a reload.

The `ReferrerState` keys name the profile of `fees-set-referrer` (inference, same offsets in the writer `0x220d8d0`): `c` code, `n` remaining, `s` log of `t`, `b` bucket, `n_per_bucket` the configured word that packet could only call +0x40. The key text is 12 bytes.

### Reference comparison

| Reference | Bytes |
|---|---|
| no `FeeTracker` type | 10 field state above |
| `FeeSchedule` of `vote_global.rs`: 9 u64 bps words | 9 keys above, f64 rate arrays, tier lists, an address, a map and a bool |
| `UserFeeState { has_active_fee_account, paid_scaled_fee_units, paid_unscaled_fee_units, by_day }` | `r`, `b`, `t`, `s`, no such words |
| `records_by_user: BTreeMap` of `FeeTrialRecord` | trial is `F.t` inside the hash row |
| `BuilderVaultSplitState.per_recipient`: address to address to units | `collected_builder_fees`: address to token to wei |

## Implementation and comparison

Not yet implemented. The rule list in `tools/fees_tracker_wire.py` (`STRUCTS`, `canon`, `emit`, `plain`, `pretty`) is a test model, not a port.

- 19 named functions, 8678 reached rows, 44533 of 96323 body bytes.
- 436 named cases and 6 generated states: 0 mismatches. Spec text matched on the third full pass; the JSON float spelling and the skip of `b`, `n` in `FeeTrial` were read from the mismatches, then fixed in the rule list.
- Copies: `copies.tsv`, same outcome on a sample of cases.
- Mutation: every 6th edit of reached conditional and immediate rows, 405 edits, 281 killed, 124 survived. Survivors are not classified one by one; each gave an equal outcome on every picked case that reaches the row. Rows are in `mutations.tsv`.
- Unit tests: 18 passed, 0 skipped, in a PATH without binutils.

## Results and limitations

- Interpreter decoder gained `fs:` addressing, `pslld`, `psrad`, `pandn`, `psubq`, `paddq`, `cvtss2sd`, `cmpsd`, `cmppd` neq, `shufps`, `movmskps`, `orps`, `andps`, and 32 bit `cvtsi2sd`. Thread local words are a fixture.
- `m` values are named only by the link to the builder gate; `V`, `U`, `C`, `r`, `F`, `T` meanings stay with fees-fill-ledger.
- Meaning of `b` and `s` in `UserFeeState` is only the offset link.
- JSON refusals ran for the first field of each struct and the root, not for each field.
- Mutation is a sample and uses at most 8 cases per edit. Reader bytes after the first value are left to callers not run here.
- Which file route carries this state above `0x2755770` is not shown.

Next question: which writer fills `l` (the `0x26ff460` rollover family or the trial writer), and how the Exchange level wrappers `0x1735c00`, `0x1befd10` place the tracker in the whole state.
