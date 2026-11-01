# bridge: user signed actions from wire struct to recovered signer, withdraw3 and 20 more (node #94)

This packet fixes the exact EIP-712 text, hash and refusal order of all 21 user signed actions and their 20 multi sig forms, so a Rust verifier for `withdraw3` and its siblings can now be compared digest by digest instead of trusting client SDK text: the same six tier shape repeats 41 times, each type text below was produced by the real bytes, and 164 digests are given as test vectors.

- Component ID: `bridge` (path rule `l1/bridge_request.rs`; the verified action is `withdraw3`, RE-010 handler `47_withdraw3`)
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `308e5127990217a9d6196992665da6ca1afd4b82`; `references/can1357-hl` holds no matching text (no `HyperliquidTransaction` in `l1/`)
- Claim status: observation, with inferences labelled; no gate requested
- Scope included and excluded: included are all 246 tier functions in `types.tsv`, the shared type hash `0x1594e50`, the snake to camel converter `0x37eaf70`, the agent name word `0x3b63f50`, the abstraction word `0x38e39b0`, the plain dispatch `0x333fc80` and the rows of the multi sig table `0x588ffc`. Excluded are secp256k1 recovery (slot `0x576fe58`, target `0x14c6f50`, stubbed) and signing (`0x14a2710`, stubbed), the multi sig action hash `0x3984fe0` (stubbed, see Limits), the shared rest of plain dispatch `0x333f690`, the multi sig dispatch body after its verifier call `0x336258c`, and the action handlers.

## Reproduce

Run from the repository root. Standard library only. No external program is called and the binary is never executed.

```sh
python3 tools/bridge_user_signed_types.py --out research/work-items/bridge-user-signed-types-94
python3 -m unittest tests.test_bridge_user_signed_types
```

The tool checks the artifact SHA-256 first and fails on a mismatch. Function bounds come from `.eh_frame` through the shared parsers and relocations from `.rela.dyn`. Real bytes run in a small x86-64 interpreter in the tool, in 4 worker processes for the mutants. Regeneration took about 360 s here on a loaded host. Output depends only on the artifact.

## Evidence

Coordinates are virtual addresses. Files beside this record:

| file | content |
| --- | --- |
| `types.tsv` | 41 rows: action, plain or multi, full type text, type hash, the six tier addresses, chain byte and chain id offsets |
| `fields.tsv` | every field: name, Solidity type, Rust form, offset in the action |
| `hops.tsv` | the call site and data slot of each tier hop, found in the caller's body bytes |
| `dispatch.tsv` | all 88 rows of both dispatch tables: tag, arm, exit, target, action |
| `vectors.tsv` | 164 worked cases: chain, signature chain id, struct hash, digest, for a Rust test |
| `cases.tsv` | every case with its outcome |
| `mutations.tsv` | every mutant with its result and reason |
| `evidence.json` | tier totals, shared functions, gate order, enum and text tables, mutation counts |

### Six tiers, one shape

| tier | role | withdraw3 | withdraw3 multi sig | reached by |
| --- | --- | --- | --- | --- |
| 1 | type hash, no input | `0x38e36b0` | `0x3a1ff30` | slot call from tier 2 |
| 2 | struct hash of the action | `0x38e30c0` | `0x3a1f860` | slot call from tier 3 |
| 3 | digest: domain, `19 01`, struct | `0x38ef850` | `0x38f0ce0` | direct call from tier 4 |
| 4 | turns a digest error into text | `0x37f0780` | `0x37ed3c0` | direct call from tiers 5 and 6 |
| 5 | verifier: gates, then recover | `0x3a1bff0` | `0x3a1c380` | dispatch tables |
| 6 | signer wrapper, used through `0x14a2710` | `0x359fb50` | `0x35a0110` | small wrappers beside tier 5 |

### Type text

A tier 1 function formats `HyperliquidTransaction:` + name, lists `hyperliquidChain` first, passes each other field name through `0x37eaf70`, which drops `_` and upper cases the next letter, and hands the list to `0x1594e50`, which joins `type name` pairs with commas and takes Keccak-256. The texts below were read from the absorb input of the real run and match the table in the tool.

| action | fields after `string hyperliquidChain` | last field |
| --- | --- | --- |
| `GovVote` | `bytes32 id, string choice` | `uint64 nonce` |
| `CDeposit` | `uint64 wei` | `uint64 nonce` |
| `ApproveAgent` | `address agentAddress, string agentName` | `uint64 nonce` |
| `UserSetAbstraction` | `address user, string abstraction` | `uint64 nonce` |
| `StakingLinkDisableTradingUser` | `address tradingUser` | `uint64 nonce` |
| `UsdSend` | `string destination, string amount` | `uint64 time` |
| `SpotSend` | `string destination, string token, string amount` | `uint64 time` |
| `Withdraw` | `string destination, string amount` | `uint64 time` |
| `CWithdraw` | `uint64 wei` | `uint64 nonce` |
| `SendAsset` | `string destination, string sourceDex, string destinationDex, string token, string amount, string fromSubAccount` | `uint64 nonce` |
| `GovPropose` | `string title, string description, string category` | `uint64 nonce` |
| `CUserModify` | `bool extendLongTermStaking` | `uint64 nonce` |
| `SendMultiSig` | `bytes32 multiSigActionHash` | `uint64 nonce` |
| `TokenDelegate` | `address validator, uint64 wei, bool isUndelegate` | `uint64 nonce` |
| `LinkStakingUser` | `address user, bool isFinalize` | `uint64 nonce` |
| `UsdClassTransfer` | `string amount, bool toPerp` | `uint64 nonce` |
| `ApproveBuilderFee` | `string maxFeeRate, address builder` | `uint64 nonce` |
| `SendToEvmWithData` | `string token, string amount, string sourceDex, string destinationRecipient, string addressEncoding, uint32 destinationChainId, uint64 gasLimit, bytes data` | `uint64 nonce` |
| `UserDexAbstraction` | `address user, bool enabled` | `uint64 nonce` |
| `UserPortfolioMargin` | `address user, bool enabled` | `uint64 nonce` |
| `ConvertToMultiSigUser` | `string signers` | `uint64 nonce` |

A multi sig row is the same text with `address payloadMultiSigUser,address outerSigner` right after `hyperliquidChain`. `SendMultiSig` has no multi sig row.

### Struct hash and digest

Tier 2 hashes `type hash || keccak(chain name) || one word per field`, where the chain name comes from the action's own chain byte through `0x57100c0` and `0x20cbe0`: `Local`, `Sandbox`, `Testnet`, `Mainnet`. Words are standard EIP-712: strings and `bytes` hashed, addresses left padded, numbers big endian. Five string fields are not strings in the action:

| field | Rust form in the action | hashed text |
| --- | --- | --- |
| `choice` | one byte | `yes`, `no`, `abstain` |
| `category` | one byte | `accelerated`, `constitutional`, `ecosystem`, `electoral` |
| `abstraction` | one byte, through `0x38e39b0` | `default`, `disabled`, `dexAbstraction`, `unifiedAccount`, `portfolioMargin` |
| `addressEncoding` | one byte | `hex`, `base58` |
| `agentName` | `Option<String>` at `+0`, through `0x3b63f50`; capacity `0x8000000000000000` means None | empty text when None |

`data` in `SendToEvmWithData` is a `bytes::Bytes` of four words at `+0x60` (vtable, pointer, length, data); tier 2 clones it through the vtable and calls vtable `+0x20` to drop.

Tier 3 builds the domain with name `HyperliquidSignTransaction`, version `1`, chain id from a 32 byte little endian word in the action (`signature_chain_id`, offset in `types.tsv`) and a zero verifying contract, then hashes `19 01 || domain || struct`.

### Verifier gates

Every tier 5 except `SendMultiSig` runs the same checks in this order. The argument registers are RDI output, RSI action, DL node chain byte, and RCX context, R8 signature for a plain row; multi sig rows take RCX user, R8 outer signer, R9 context, and the signature on the stack.

| order | check | status | text |
| --- | --- | --- | --- |
| 1 | action chain byte differs from the node chain byte | `0x8f` | Mainnet and testnet require different signature. |
| 2 | context `+0x18` bit 0 set | `0x15` | Vault may not perform this action. |
| 3 | context `+0x10` differs from the action `time` or `nonce` | `0x5d` | Nonce mismatch. |
| 4 | context `+0` non zero | `0x8c` | Action does not support expires_after |
| 5 | digest error, or recover error at slot `0x576fe58` | `0x7a` | Unable to recover signer. |
| 6 | success, address at output `+3` | `0x186` | |

`SendMultiSig` verifier `0x3a1b570` first calls `0x3984fe0` with the action, chain and context, then checks the chain byte and nonce of its result and recovers. It has no `0x15` or `0x8c` gate, which two cases show directly.

No verifier reads the signature chain id. It reaches only the domain word.

### Dispatch

`0x333fc80` subtracts `0x74` from the action tag at envelope `+0x10`; a smaller tag uses row 20. Row numbers match RE-010 handler numbers (`47_withdraw3`). The 21 verifier rows are in `dispatch.tsv`. Other rows call `0x333f690`, except row 82, which first requires envelope `+0xa8` to equal the envelope nonce, else status `0x5d`. The envelope gives payload `+0x18`, signature `+0x100`, context word 0 from `+0`, context `+0x10` from `+0x148`, and context `+0x18` onward from `+0x150`.

`0x3360b40` uses the same tag rule on the word at its input `+0`, with its own table `0x588ffc`. 20 rows call the multi sig verifiers, 67 jump to `0x336258c`, and row 68 stops at a call to `0x3393390`. `dispatch.tsv` lists them from bytes; this packet does not run that host.

## Inferences

- Context `+0` is `expires_after`, from the status text. Context `+0x18` is the vault address option, from the status text and envelope position. Neither name is in the bytes of the gate.
- `signature_chain_id` is named from the rodata field text; tier 3 only shows a 32 byte word.
- The texts in tier 4 suggest an `ethers` style `Eip712` trait. The five text arms of tier 4 are run here only by forcing tier 3 to fail, since the type lists are literals and no case fails on its own. Arm 0 also has its error drop stubbed.
- `SendMultiSig` omits gates 2 and 4 most likely because `0x3984fe0` already takes the context into its hash. That hash was not read in full.

## Implementation and comparison

Not yet implemented. The specification in the tool is Python written from the field table, kept apart from the machine. `vectors.tsv` is ready as a Rust test once a verifier exists. Nothing here is a binary equivalence claim.

## Results and limitations

| metric | value |
| --- | --- |
| Actions plain / multi | 21 / 20 |
| Cases | 1047 |
| Mismatches | 0 |
| Instructions stepped | 6,627,361 |
| Stepped / total, tier digest (41 functions, 35567 bytes) | 5356 / 6832 |
| Stepped / total, tier sign (41 functions, 14473 bytes) | 2173 / 3116 |
| Stepped / total, tier struct (41 functions, 67201 bytes) | 9272 / 12871 |
| Stepped / total, tier type (41 functions, 38588 bytes) | 5235 / 7135 |
| Stepped / total, tier verify (41 functions, 19870 bytes) | 4245 / 4522 |
| Stepped / total, tier wrap (41 functions, 23124 bytes) | 3485 / 4797 |
| Stepped / total, type text and hash `0x1594e50` | 124 / 154 |
| Stepped / total, snake to camel `0x37eaf70` | 103 / 216 |
| Stepped / total, plain dispatch `0x333fc80` | 284 / 290 |
| Stepped / total, agent name word `0x3b63f50` | 52 / 66 |
| Stepped / total, abstraction word `0x38e39b0` | 34 / 50 |
| Stepped / total, SendMultiSig verifier `0x3a1b570` | 75 / 75 |
| Mutants killed / survived / unreached | 1724 / 236 / 435 |

Mismatch 0 means every case's type hash, struct hash, digest, status and recovered address equal the specification. Keccak-f is replaced by the Python permutation for speed; one test runs the real bytes of the permutation. Fixtures use distinct filler bytes, so a wrong field offset changes a hash.

Mutants run in full on both Withdraw rows, `0x3a1b570`, `0x333fc80` and the shared functions, and one in 5 on the other rows, so a survivor in a sampled row says little on its own. Of 236 survivors, by kind: branch 57, immediate 157, offset 22. They carry a class label in `mutations.tsv`, not a row by row proof.

Not covered: secp256k1 itself, what the signature words mean, `0x3984fe0`, `0x333f690`, the multi sig body after the verifier, the tier 6 wrappers' callers, error arm 5 of tier 4 (a text error type that needs a real formatter object), allocator failure arms and unwind pads. The `0x15` context bit is shown only as a bit. Who builds the context beyond `0x333fc80` was not read.

Overlap: no address of the tier functions or shared helpers appears under `research/work-items` or `tools`. An older index of PR files lists `0x333fc80` and `0x3360b40` under #393 and `0x3a1b570` under #145, and three verifiers under the closed census #875. #393 and #145 are not in the current PR list and their text could not be read here, so a reviewer should check them. `0x14c6f50` and `0x14a2710` are stubs here.

Next question: what `0x3984fe0` hashes for `SendMultiSig` (it writes a msgpack body, then the nonce in big endian and a flag byte), and how the multi sig body after `0x336258c` counts signers.
