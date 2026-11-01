# staking: wire forms and decoded layouts of the staking actions in node #94

This packet fixes, from the bytes, the wire keys, required and default rules, error texts and in-memory offsets of `tokenDelegate`, `cDeposit`, `cWithdraw`, `linkStakingUser`, `cUserModify`, `govVote`, `govPropose`, `CValidatorProfile` and all three `CValidatorAction` arms, so a reconstruction can write these decoders and serializers directly and can name the action offsets that the staking handlers read: `+0x45` of `tokenDelegate` is the bool `isUndelegate`, and a decoded `CValidatorAction` is split by its first word.

- Component ID: staking
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6d727b9ea2ca4dc497c96a2de35cfba064e14dcc, reference labels from `references/can1357-hl/l1/staking.rs` as clues only
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the two serde `Content` readers of each of seven tagged actions and of `CValidatorProfile`, the msgpack reader `0x190d510` of the `VoteGlobalAction::CValidator` struct variant with its nested readers, the JSON and msgpack writers of six tagged actions and of `CValidatorAction`, and the code copies in `copies.tsv`. Every callee runs for real. Only allocator, copy, compare and panic slots are hooked. Excluded: what any handler does with a decoded action, the outer action enum that strips the `type` key, the `CSignerAction` readers, and any `Content` reader of `CValidatorAction`. Stated gaps are under Results and limitations. No named function here appears in an existing work item: all 84 addresses were checked against `research/work-items`.

## Reproduce

From the repository root, with no binutils needed:

```
python3 tools/staking_action_wire.py --out research/work-items/staking-action-wire-94
python3 -m unittest tests.test_staking_action_wire
sha256sum -c MANIFEST.sha256    # inside the folder
```

The tool checks the SHA-256 of `artifacts/node/94/hl-node` first. It parses ELF, relocation and FDE bytes through `tools/elf_index.py` and `tools/fde_extents.py`, and evaluates x86-64 bytes in its own interpreter. The binary is never executed. A run takes about 3 minutes at load 6 on 4 cores. Output has no times or absolute paths.

## Evidence

Coordinates are virtual addresses in `.text`, offsets are from the start of the decoded action. Function list: `path.tsv` (41 functions, 95382 body bytes, 67125 bytes reached). Readers and writers per action: `roots.tsv`. Every field: `fields.tsv`. Every case with its outcome: `scenarios.tsv`. Output bytes: `wire-samples.tsv`. Every reached branch: `branch-rows.tsv`. Text anchors: `texts.tsv`.

### How the readers were found

The rodata text `struct TokenDelegateAction` and its siblings sit in 25 byte `expecting` functions. Each such function has a relocated vtable slot, and the vtable (slot minus 0x18) is loaded by two readers of one action, so each action has two `Content` readers. They differ in their error form: one leaves a box with a kind word and text, the other an inline error with tag 6 and the text at `+0x10`. Feeding an empty map and then supplying the field named by each `missing field` text gave the schema without a hand list. `CValidatorAction` has no such pair: the reference to `enum CValidatorAction` led to the invalid type helper `0x234a690`, whose only caller `0x190d510` turned out to be the reader of `VoteGlobalAction::CValidator`.

### Tagged actions

All seven begin with `signatureChainId` and `hyperliquidChain`. The wire order is the order below. Offsets are not in wire order.

| Action | Wire keys after the two head keys | Offsets |
| --- | --- | --- |
| `TokenDelegateAction` | `validator`, `wei`, `isUndelegate`, `nonce` | chain id 0, wei 0x20, nonce 0x28, validator 0x30, chain 0x44, isUndelegate 0x45 |
| `CDepositAction` | `wei`, `nonce` | chain id 0, wei 0x20, nonce 0x28, chain 0x30 |
| `CWithdrawAction` | `wei`, `nonce` | same as `CDepositAction` |
| `LinkStakingUserAction` | `user`, `isFinalize`, `nonce` | chain id 0, nonce 0x20, user 0x28, chain 0x3c, isFinalize 0x3d |
| `CUserModifyAction` | `extendLongTermStaking`, `nonce` | chain id 0, nonce 0x20, chain 0x28, extendLongTermStaking 0x29 |
| `GovVoteAction` | `id`, `choice`, `nonce` | chain id 0, id 0x20, nonce 0x40, chain 0x48, choice 0x49 |
| `GovProposeAction` | `title`, `description`, `category`, `nonce` | title 0, description 0x18, chain id 0x30, nonce 0x50, chain 0x58, category 0x59 |

Rules shared by all seven, each with named cases on both readers:

- `signatureChainId` is a hex quantity of 1 to 32 bytes with or without `0x`, stored as a little endian 256 bit integer. Odd digit counts are accepted. `0x` alone and an empty text give `invalid length 0`, and 33 bytes give `invalid length 66`.
- `hyperliquidChain` is `Local`, `Sandbox`, `Testnet`, `Mainnet`, stored as bytes 0 to 3. It is case sensitive and also takes the one key map form.
- Every key is required, order is free, a repeated key gives `duplicate field`, and any other key is refused with the full key list. That includes `type`, so the outer reader must remove the tag before these readers run.
- An array of exactly N values is accepted in key order. Other lengths give `invalid length`.
- `u64` fields accept 0 and 2^64-1 and refuse text, bool, float and negative values. `wei` is a plain `u64`.
- `isUndelegate`, `isFinalize`, `extendLongTermStaking` are real bools: an integer `1` is refused (`tokendelegateaction_isUndelegate_integer`).
- A null gives `invalid type: null` from the boxed error reader and `invalid type: unit value` from the inline error reader. This is the only text difference found between the two forms.
- After a read, on success or failure, both readers have freed every block of the `Content` tree, so both take it by value. The one exception is a text field of a decoded action, which keeps its `Content` block with no copy. Every read case checks this.

`choice` is `yes`, `no`, `abstain` (bytes 0 to 2) and `category` is `accelerated`, `constitutional`, `ecosystem`, `electoral` (bytes 0 to 3).

A failed result is marked inside the action type: byte `+0x45`, `+0x3d` or `+0x29` equal to 2 where the action has a bool, byte `+0x30` equal to 4 for the two amount actions, byte `+0x49` equal to 3 for `GovVoteAction`, and word 0 equal to 2^63 for `GovProposeAction` (error word at `+8`). See `roots.tsv` for the error word of each action.

### `CValidatorAction` and `VoteGlobalAction::CValidator`

`0x190d510` reads a struct variant with keys `a` (the action) and `c` (a 20 byte address). Unknown keys are skipped here, unlike the tagged actions, and the array form works. On success it writes tag `0x3a` at result `+0`, with the action at result `+8`. On failure it writes tag `0x74`. The offsets below are from the action, the full list is in `cvalidator-layout.tsv`.

Word 0 picks the arm: 2^63 is `changeProfile`, 2^63 + 1 is `unregister`, and anything below 2^63 is `register`, where the word is the capacity of the profile name.

| Arm | Keys | Rule |
| --- | --- | --- |
| `unregister` | none | text or one key map with nil |
| `register` | `profile`, `unjailed`, `initial_wei` | `unjailed` absent means false. `initial_wei` and `profile` are required. `+0x58` wei, `+0x60` unjailed |
| `changeProfile` | `node_ip`, `name`, `description`, `unjailed`, `disable_delegations`, `commission_bps`, `signer` | all absent allowed. Six are optional and take nil. `unjailed` is a bool that defaults to false and refuses nil. Unknown keys are refused |

`CValidatorProfile` has `node_ip`, `name`, `description`, `delegations_disabled`, `commission_bps`, `signer`. `delegations_disabled` absent means false and `commission_bps` absent means 10000. The two names are not the same: the profile key is `delegations_disabled` and the change key is `disable_delegations`. In the profile `disable_delegations` is skipped without effect (`profile_unknown_key_ignored`), and in the change `delegations_disabled` is refused (`cvalidator_change_profile_key_name_refused`). A decode accepts a commission of 99999, so any cap lies later.

`node_ip` is `Ip` with an IPv4 text or `LocalNode` with a `u8`. The bare text form gives `invalid type: unit variant, expected newtype variant`.

### Writers

The writers emit the keys in wire order, with `type` first, or as an array with the tag first when field names are off. The tag text comes from the caller's tagged serializer, not the writer: `CDepositAction` and `CWithdrawAction` share all four writers (`0x1e88c30`, `0x1e88460`, `0x1e889e0`, `0x1e88610`). The cases use the tag texts in `roots.tsv` as fixtures.

Chain id writes as lowest digits (`0x66eee`), addresses as lower case `0x` text. `Ip` writes as text in JSON and as an array of four integers in msgpack, so the writer follows the human readable flag. `changeProfile` writes all seven keys with nil for absent ones, and `unjailed` as a bool. `unregister` writes as a bare text.

### Reference comparison

| Reference `l1/staking.rs` | Bytes |
| --- | --- |
| `TokenDelegateAction.signature_chain_id: u64`, `hyperliquid_chain: String` | a 256 bit quantity and a 4 row enum byte |
| `CWithdrawAction { destination, wei, usd, builder }` | `signatureChainId`, `hyperliquidChain`, `wei`, `nonce` only |
| `CUserModifyAction { extend_long_term_staking, profile }` | no profile key, `nonce` instead |
| `LinkStakingUserAction { staking_user, trading_user, nonce }` | `user`, `isFinalize`, `nonce` |
| `CValidatorProfile.node_ip: Option<String>`, `commission_bps: u16`, name and description optional | enum `Ip` or `LocalNode` and required, commission a `u64` word with default 10000, name and description required |
| `Register { profile, initial_wei, disable_delegations }` | `profile`, `unjailed`, `initial_wei` |
| `ChangeProfile(CValidatorProfile)` | a separate struct of seven optional fields |

### Inferences

- `+0x4c`, `+0x51`, `+0x58`, `+0x5e`, `+0x60` here match the bytes that `staking-delegate-entry-94` read in the CValidator host, and `+0x29` matches what it called `extend_long_term_staking`. That packet marked those names as inference. With the same offsets, the key names here make them much stronger, but this packet does not run that host.
- `+0x45` of `tokenDelegate` being a bool means the decoder gives only 0 or 1 there.
- Field order inside each action looks like compiler layout (large fields first), not a chosen format.
- The boxed error form matches the JSON error form and the inline tag 6 form matches the msgpack error form that `staking-validator-state-wire-94` observed, so the two readers are probably the JSON and msgpack routes of one internally tagged action. Neither route's caller is run here.

## Implementation and comparison

not yet implemented

The rule list in the tool (`bad_rows`, `shape_cases`, `profile_cases`, `vote_cases`, `spec_write`, `vote_spec`) is a test oracle written apart from the bytes under test. It was corrected from the decoders' own texts during development, so it is a record of behaviour and not an independent specification.

## Results and limitations

`evidence.json`: 1058 named cases (562 with a failed outcome) and 300 seeded cases match. 13380 instructions reached in 41 functions. 43 copy rows in `copies.tsv` match: readers ran every named reader case of their action, writers ran one seeded sample per form.

Mutation: every reached conditional row and immediate in the named functions was edited, 3513 edits, 2846 killed and 667 survived (`mutations.tsv`). Survivors by form: 78 branch conditions and 589 immediates. They are grouped by form, not read one by one.

Unit tests: 22 pass, with negative controls for a wrong digest, a wrong error text, a wrong field offset, a changed branch, an address outside every FDE and truncated msgpack.

Limits:

- `GovVoteAction` has no writer here. All 177 functions of 300 to 1400 bytes in `0x1e80000..0x1ea0000` were tried and none gave the sample, so the writer was not located.
- No `Content` reader of `CValidatorAction` was found, so its arms are shown only through `0x190d510`. Its compact JSON writer is not named. The caller of `0x190d510` is not read, and neither are the readers of `CSignerAction`.
- The `type` tag handling is outside this packet. A tag text in a case is a fixture.
- Writer copies ran one seeded sample per form, and some forms have no copy listed. Third copies appear only in `copies.tsv`.
- The copy readers' mapping to a call path is not traced. Which copy serves which node mode is not stated.
- `Content` input is built by the fixture from observed tags. The step from JSON or msgpack bytes to `Content` is serde code and is not run here.
- 95382 body bytes hold 67125 reached bytes. The rest is not classified here. It includes allocator failure and unwind pads, and other rows were not read.

Progress gate: none requested.

Next question: which reader builds `CValidatorAction` from a tagged action, and which function strips `type` before these readers run?
