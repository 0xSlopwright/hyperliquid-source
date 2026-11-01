# staking: node #94 registerValidator join path, wire to state row

This packet shows how a validator enters `validator_states` in node #94, from the action bytes to the stored row, so a reconstruction can now write this path: the action form both ways, the gate order, the exact ed25519 message and cold user digest, the 1 wei first delegation, and the tree writes. It also corrects four labels: the tag text is `RegisterValidatorAction`, not `registerValidator`; the cold signature is a fixed `r, s, v` struct, not a byte vector; `r` and `s` are hex quantities; the seeded map is the `delegations` field with 1 wei for the action signer.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `3981f9e4377b6302f240f13ef1f40e73dce61738` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/exchange/handlers/16_register_validator.rs` was read as a lead only; the table below lists where the bytes differ.
- Claim status: observation for everything under Evidence, from ELF bytes and an interpreter of those bytes. Items under Inferences are not proved. Unresolved items are under limitations.
- Scope included and excluded: included are the join body `0x3367800`, its search `0x2fdce10`, map upsert `0x33a6920`, row place `0x33c1820`, tree inserts `0x2f38b80` and `0x2f43990`, ed25519 host `0x158f830`, key decode `0x1583680`, action readers `0x21321c0` and `0x210bc10`, and writers `0x1e953b0`, `0x1e95540`, `0x1e95110`, `0x1e95830`. Excluded and stubbed, see `boundary.tsv`: the final ed25519 equation `0x158f600`, the L1 typed data digest `0x37f2940`, secp256k1 recovery `0x14c6f50`, SHA-512 and keccak state code. Outer msgpack and JSON action routes that build the `Content` value are not run. Implementation: not yet implemented.

## Reproduce

From the repository root:

```
python3 tools/staking_register_validator.py --out research/work-items/staking-register-validator-94
python3 -m unittest tests.test_staking_register_validator
```

The tool takes about 3 minutes with 3 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed.

Generated files: `evidence.json`, `path.tsv`, `boundary.tsv`, `dispatch-arms.tsv`, `copies.tsv`, `constants.tsv`, `texts.tsv`, `scenarios.tsv`, `vector-outcomes.tsv`, `function-rows.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds.

### Method

The real bytes run in an interpreter inside the tool. Tree fixtures are real B-tree nodes with parent links, and after each case the tool walks the trees again. A separately written rule list predicts the status, every boundary call with its arguments, and the rows afterwards.

Across 363 named cases and 300 generated cases there are 0 mismatches. The body rule list matched on its first full run. The first wire run gave 5 rule corrections, listed under Comparison.

### Dispatch

`dispatch-arms.tsv` holds the three arms that call through slot `0x5773160`.

| Host | Call site | Mode byte | Staking base | Shift |
|---|---|---|---|---|
| `0x2759240` | `0x275971c` | `+0x8f2` | `+0x3840` | 0 |
| `0x4d83050` | `0x4d8352c` | `+0x1372` | `+0x42c0` | `0xa80` |
| `0x4d84170` | `0x4d8464c` | `+0x8f2` | `+0x3840` | 0 |

Arguments: output, Staking base, signer, action `+8`, mode byte.

### Gate order

Gates in order. The body returns a 16 bit status at output `+0`.

| Step | Check | Status on failure |
|---|---|---|
| 1 | 32 byte key is in the set at Staking `+0x58` | `0x94` |
| 2 | key decodes to a curve point (`0x1583680`) | `0x94` |
| 3 | ed25519 over the message below | `0x96` |
| 4 | typed data digest step | `0x7a`, boxed error at `+8` |
| 5 | secp256k1 recovery | `0x7a`, error at `+8` |
| 6 | recovered address equals `coldUser`, all 20 bytes | `0x11f` |
| 7 | key is not in `validator_states` at Staking `+8` | `0x93` |
| 8 | row written | `0x186` |

Step 7 comes after both signatures, so a key that is already registered still costs the full signature work. A failed step leaves the trees as they were and no block live.

### Proof message

The ed25519 message is the bytes `VALIDATOR_JOIN` followed by the nonce in decimal, with no separator. Case `join_nonce_0` gives `VALIDATOR_JOIN0`, and the top value gives `VALIDATOR_JOIN18446744073709551615`. The text comes from the real format call `0x1344760` with rodata pieces.

`0x158f830` hashes `R || key || message` with SHA-512. The rule list reduces that hash modulo the group order, and the scalar passed to `0x158f600` matches in every case. The key struct holds the 32 byte key and then the decoded point with X and T negated, checked by value at the stub.

`0x1583680` masks bit 255, runs no canonical test on y, and applies the sign bit. Key decode cases: `join_key_y_above_p`, `join_key_y_one`, `join_key_y_one_sign`, `join_key_sign_set`.

### Cold user digest

- Hashed input: `abi.encode(bytes32 key, string "VALIDATOR_JOIN", uint256 nonce)`, three tokens through the real encoder `0x1592160`, then keccak-256 with rate `0x88` and delimiter 1.
- Row passed to `0x37f2940`: source byte, that hash, chain id 1337, three zero words.
- Source byte: `a` when the mode byte is 3, else `b`. Only the low byte counts, shown by `join_mode_high_bytes`.
- The digest goes to recovery with the `r, s, v` part of the action.

### State row

`0x33a6920` builds a fresh map with one row, signer to 1. `0x33c1820` places a 0x40 byte value under the key:

| Value offset | Field |
|---|---|
| `+0` | delegations map, root, height, length |
| `+0x18` | hot_user, the action signer |
| `+0x2c` | cold_user |

Node sizes from the tree code: state map leaf 0x430 and inner 0x490, delegation leaf 0x140, keys at `+0x2c0` and `+0x60`. The allowed set keys 32 bytes from node `+0`. Cases cover empty tree, full leaf split and height 1 and 2.

`0x33a6920` is also tested alone on 31 cases: new key, replaced key returning the old value, leaf split, inner node.

### Action wire form

Tag text `RegisterValidatorAction`, 23 bytes, passed at 4 writer sites (`texts.tsv`). The lower case text `registerValidator` does not occur in the file at all. Fields in order:

| Key | Type | Payload offset |
|---|---|---|
| `validator` | hex text, 32 bytes, prefix optional | `+0x40` |
| `signature` | `{R_bytes, s_bytes}`, arrays of 32 integers | `+0`, `+0x20` |
| `coldUser` | hex text, 20 bytes | `+0xb0` |
| `coldUserSignature` | `{r, s, v}`, hex quantity, hex quantity, u8 | `+0x60`, `+0x80`, `+0xa0` |
| `nonce` | u64 | `+0xa8` |

- Unknown keys are refused: ``unknown field `extra`, expected one of ...``.
- Reader takes a map in any key order, or a sequence of 5. `signature` also takes a sequence of 2 (`read_signature_seq`).
- `r` and `s` are stored as little endian words and written without leading zeros, so zero is `0x0`. Text of 1 to 32 bytes is taken, odd length included. `0x` and the empty text give length 0 refused.
- Writers: compact JSON, pretty JSON, msgpack named and array in 2 serializer shapes. All give the same key order.

Reader cases run on both the owned `0x21321c0` and borrowed `0x210bc10` readers, with identical results. `copies.tsv` repeats them on 5 copies. Four `chain_` cases feed a real decoded action into the real body.

### Allowed set field

The writer `0x3365380` ends with `add $0x58,%rbx` right after the key `epoch_duration_seconds`, so the set at Staking `+0x58` is the last field, `allowed_validators`. Excerpt:

```
3365507: add $0x58,%rbx
```

## Inferences

- The names `R_bytes`, `s_bytes`, the stored negated point and a helper `0x1583420` with 3 doubling calls suggest the ed25519-consensus crate: a cofactored check with ZIP 215 rules. `0x158f600` was read by eye and is not run, so this is not proved.
- Mode 3 selecting source `a` suggests mainnet, as in other L1 action paths of this binary.
- The 1 wei row suggests that a joining validator starts with its hot user as sole delegator. How that weight is used later is not read here.

## Implementation and comparison

Not yet implemented. Comparison with the reference file as a lead:

| Reference claim | Bytes |
|---|---|
| wire type `registerValidator` (RE-010 row 16) | text absent, tag is `RegisterValidatorAction` |
| `cold_user_signature: Vec<u8>` | fixed `r, s, v`, 0x48 bytes inline |
| signature `[u8; 64]` | wire form is a struct of 2 arrays |
| `initial_signer_weight_by_address` as inferred bootstrap table | `delegations` field of `ValidatorState`, value 1 |
| `known_validator_keys` name unknown | `allowed_validators` |
| gate order and status numbers | match |

First wire run corrections of the rule list, all kept as cases: unknown key refused, `r` and `s` as quantities, long sequence text `expected 5 elements in sequence`, long array text `expected 32 elements in sequence`, quantity length text `between (0; 32] bytes`.

## Results and limitations

`evidence.json` has the totals: 17 functions, 4175 instructions reached, 21213 of 25181 body bytes, 363 named and 300 generated cases, 0 mismatches. 914 mutants, every reached conditional and immediate, 730 killed, 184 survived. Unit tests: 25 passed, 0 skipped, in a PATH without binutils.

Survivors by row type:

  - 72: `cmp` rows
  - 65: `mov` rows
  - 18: `jcc` rows
  - 12: `shl` rows
  - 10: `test` rows
  - 2: `add` rows
  - 2: `cmov` rows
  - 1: `and` rows
  - 1: `pshufd` rows
  - 1: `shr` rows

Survivors are grouped by row type. Only the 9 in the body `0x3367800` were read one by one, all `mov` immediates: copy sizes that only spill stack padding (`0xa0`, `0xc0`), the key size of a compare whose rows differ early, the loop start, 2 token list length words, and the `TOR_JOIN` store, whose low byte is overwritten by the `VALIDATO` store at text +0. The rest are not classified.

Unknown or not covered:

- `0x158f600` equation, `0x37f2940` and recovery are stubs. So this packet does not prove which signatures pass, only what goes in and how each result is handled.
- Allocation failure and panic rows are not reached.
- No copy of the compact JSON writer was found. Reader routes above the `Content` value are not run, so the tag is proved on the writer side only.
- Which code fills `allowed_validators` is not known. A displacement scan shows only copies of the state and readers.
- Requesting no progress gate.

Next question: which function writes `allowed_validators`, and when does a row placed here enter the active set of the next epoch.
