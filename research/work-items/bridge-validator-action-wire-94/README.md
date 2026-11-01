# bridge: the wire form of the validator withdrawal and validator set actions in node #94

This packet fixes the wire form of the four validator bridge actions the handler packets only read by offset, so a reconstruction can now build, parse and hash them: named fields and field order for `ValidatorSignWithdrawalAction`, `VoteEthFinalizedWithdrawalAction`, `SignValidatorSetUpdateAction` and `VoteEthFinalizedValidatorSetUpdateAction`, `signature` as `{r, s, v}` with `r` and `s` as trimmed hex words, and each validator profile as one string `power-validator-signer` parsed by `0x37a0f80` and kept sorted in a B-tree set on (power, validator, signer).

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; first task "Map message hashes, nonce lifecycle and validator signing threshold"; only the identity and wire form of the validator actions are claimed here)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`
- Claim status: static, instruction-level, partial. Real bytes run in an emulator on fixtures; the binary is not executed.
- Scope included and excluded: included are the writers and `Content` readers of the four actions and of `BridgeValidatorSet`, the signature readers and writers, the profile text in both directions, and the set order. Excluded are what the handlers do with the fields (`bridge-withdrawal-votes-94`, `bridge-validator-set-votes-94`), the msgpack byte reader that builds a `Content` value, and the enum dispatch over all actions.

## Reproduce

```
python3 tools/bridge_validator_action_wire.py --out research/work-items/bridge-validator-action-wire-94
python3 -m unittest tests.test_bridge_validator_action_wire
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read sections and FDEs, the tool checks the SHA-256 first, then a small x86-64 interpreter in the tool runs the listed bytes.

## Evidence

Addresses are virtual addresses. Reached instruction rows are in `function-rows.tsv`, function sizes in `path.tsv`. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run. The field names are in rodata (`texts.tsv`).

### Fields

| Action, `type` tag | Wire order | Layout in bytes |
|---|---|---|
| `ValidatorSignWithdrawalAction` | `user`, `destination`, `usd`, `nonce`, `signature` | `usd` +0, `nonce` +8, signature +0x10, `user` +0x58, `destination` +0x6c |
| `VoteEthFinalizedWithdrawalAction` | `user`, `destination`, `nonce`, `usd`, `ethTxHash` | hash +0, `nonce` +0x20, `usd` +0x28, `user` +0x30, `destination` +0x44 |
| `SignValidatorSetUpdateAction` | `validatorSet`, `signature` | set +0, signature +0x20 |
| `VoteEthFinalizedValidatorSetUpdateAction` | `validatorSet` | set +0 |
| `BridgeValidatorSet` (no tag) | `profiles`, `epoch` | tree root +0, height +8, count +0x10, `epoch` +0x18 |

`nonce` comes before `usd` in the finalize vote and after it in the sign action. The signature is `{r, s, v}`: `r` at +0, `s` at +0x20 as little-endian 256-bit words, `v` as one byte at +0x40.

### Text forms

- `user`, `destination`, `ethTxHash`: `0x` and lower hex at full width.
- `r`, `s`: `0x` and hex with no leading zeros, so zero is `0x0`, `0xabc` stays three digits.
- A profile is one string: decimal power, `-`, validator, `-`, signer, for example `5-0x00..00-0xff..ff`. The key has power at +0, validator at +8, signer at +0x1c, `0x30` bytes.

A sample in each writer form is in `wire-samples.tsv`.

### Profile parser `0x37a0f80`

The string is split on `-` (`0x37a0fcb`). `status.tsv` binds the three status tags to their text through the formatter table `0x59a8d0`.

| Check, in order | Row | Status | Text |
|---|---|---|---|
| Not exactly three parts | `0x37a1002` | `0x140` | `Invalid input` |
| Number empty, a lone `+` or `-`, a non digit, or above `u64` | `0x37a1018`, `0x37a1047`, `0x37a1050`, `0x37a10ec` | `0x13f` | `Invalid input number` |
| Validator or signer not a 20-byte hex address | `0x37a111b`, `0x37a1153` | `0xb6` | `Failed to parse user address` |

A leading `+` and leading zeros pass, a leading `-` is a fourth part. The address takes an optional lower `0x` and digits of either case. Success is status `0x186`. Numbers of at most 16 digits skip the overflow test (`0x37a1077`). The set holds parsed values, so `+5-abc..` and `5-0xabc..` are one entry. A profile also reads from bytes that are valid text.

### Set order

Readers build a B-tree set: leaf `0x220` bytes, branch `0x280` bytes, keys at +0, parent +0x210, parent index +0x218, length +0x21a, edges +0x220. Output order is power, then validator bytes, then signer bytes, and duplicates are dropped. `order_*` and `trip_*` cases cover power 256 against 1, ties on power and validator, duplicates in different spellings, and 13 rows across two levels. Each round trip goes through a real reader and a real writer.

### Input rules

`Content` readers come in two flavors, as in `bridge-eth-event-wire-94`. The first returns inline error text, the second a boxed `serde_json` error, and they differ in one word: unit is `unit value` or `null`.

| Rule | Example case |
|---|---|
| The four actions refuse an unknown key; `BridgeValidatorSet` and the signature ignore it | `sign_from_rmp_extra_key`, `set_from_rmp_extra_key`, `sign_from_rmp_signature_extra` |
| A struct with two fields names them as `a` or `b` in the refusal | `set_sign_from_rmp_extra_key` |
| Sequence form works at each level, and the signature can be `[r, s, v]` | `sign_from_rmp_seq_good`, `sign_from_rmp_signature_seq` |
| `r`, `s` take 1 to 64 hex digits, odd counts too, or 1 to 32 bytes read big-endian; `0x` alone is refused | `sign_from_rmp_signature_r_odd_three`, `..._r_prefix_only`, `..._r_bytes_one` |
| `v` is any integer form up to 255 | `sign_from_rmp_signature_v_over` |
| `usd`, `nonce`, `epoch` and `validatorSet` take one newtype layer, addresses any number, `ethTxHash` none | `*_newtype`, `*_newtype_newtype` |
| `profiles` must be a sequence; the first bad row ends the read | `set_from_rmp_profiles_map`, `set_from_rmp_profiles_after_good` |

Every allocation is checked: an accepted input leaves only tree nodes, an error leaves only the error, each free carries the right size.

### Copies

The binary holds these paths several times. `copies.tsv` lists 40 copies that match a sample of their primary's cases.

### Reference differences

| Reference | Bytes |
|---|---|
| `40_validator_sign_withdrawal.rs`: `withdrawal_data: WithdrawalData { raw: [u8; 72] }`, an opaque blob | `signature {r, s, v}`, 65 meaningful bytes in a `0x48` slot |
| `29_sign_validator_set_update.rs`: `signature: SignatureBytes`, "serialized signature blob" | the same `{r, s, v}` struct |
| `45_vote_eth_finalized_validator_set_update.rs`: action has `header: EthEventId` and `validator_set` | one wire field, `validatorSet`, "with 1 element" in rodata |
| `ForceIncreaseEpochProfiles`, `ValidatorProfile` struct | serde name `BridgeValidatorSet`; a profile is one text string on the wire |

The compact field order of `ValidatorProfile` in the reference matches the key layout here.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the machine, that predicts every output byte, every decoded field and every error text.

## Results and limitations

- 43 functions, 9085 reached rows. 1642 named cases and 200 generated cases: 0 mismatches.
- 909 byte edits on every fourth reached row: 650 killed, 259 survived (`mutations.tsv`). A survivor has a class label only and is not proved equal. Each edit runs at most 6 cases that reach it, from a third of the named cases.
- 16566 bytes of the listed bodies are not reached: landing pads, allocation failure, writer errors, and the parts of shared helpers outside these types.
- The rule list was written after probes of the real bytes, so a match shows it is complete on these cases and is not an independent prediction. The first full matrix had 20 mismatches of 2388 in three rules, all fixed in the list.
- The json flavor readers run about a third of the cases of the rmp flavor. Copies run a sample.
- `Content` values are built by the fixture from the serde tag layout, not by the real msgpack reader.
- The std backtrace style cache at `0x5788590` is set to "off" as a fixture, because the address parse creates an error object that would read the environment.
- The `type` tag text comes from the fixture. The callers load the same names at the rows in `key-rows.tsv`, but the outer action writers are not run, so the variant dispatch is not covered here.
- Field meanings beyond the key names are inference. Which of `power` and stake the first number holds is taken from the reference name `total_delegated`, and is not established.

Next question: which function builds these profiles from the staking state for an epoch, and whether its power matches the set hash in `bridge-signed-message-94`.
