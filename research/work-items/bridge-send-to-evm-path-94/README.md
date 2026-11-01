# bridge: sendToEvmWithData and the send asset path of node #94, from the four arms through the route and the move to both L1 to EVM queues

This packet shows that `sendToEvmWithData` is a `sendAsset` to the token's system address with target `spot` plus a 0x58 byte EVM block, and how every send then passes one route and one move into `0x2715320`, which turns the amount into U256 wei, charges a gas fee and fills one of two L1 to EVM queues, so a reconstruction can write the cross-chain send of arms 69, 71, 76 and 82 end to end, with its gate order, status texts, queue rows and limits, where the reference has only a table row and no body.

- Component ID: `bridge`, "deposit/withdrawal requests and cross-chain signing". The bodies have no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims they live there.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (read for leads only, nothing copied; it names arm 76 in one table row and has no handler)
- Claim status: observation for bytes, branch order, constants, statuses, record offsets and all outcomes in `cases.tsv`; inference for every field name, for the word "mode" of user row `+0x3c`, and for the wire names of the arms, which come from `RE-010-exchange-handlers` and `bridge-user-signed-types-94`; unresolved items are under limits
- Scope included and excluded: included as real bytes are the arms `0x2729060`, `0x1f678c0`, `0x27288c0`, `0x2728e10`, the text parser `0x272b950`, the recipient parser `0x3988b80`, the route `0x2729c30`, the move `0x272bd60`, the system send `0x2715320`, the error map `0x2715130`, the record helpers `0x27b5760`, `0x2784560`, `0x27822a0` and the queue push `0x27a0450`. Run real, not claimed and not mutated: U256 product `0x27a1150`, dex row `0x3332600`, range test `0x37e5110`, SipHash `0x399c7a0`. Stubs that log their arguments: the transfer core `0x2712ce0` and credit (`vaults-subaccount-spot-transfer-94`), the shift `0x270f6f0`, gas quote `0x27101a0` and gas fee `0x37325d0` (`fees-transfer-gas-94`, #834), gas step `0x2711a80`, recipient step `0x2711440`, the unified account steps `0x272fe00`, `0x272f880`, `0x272d000`, `0x28cc390`, `0x1f84640`, user row `0x2755400`, margin rows `0x36f57f0`, `0x37d7f10`, token and dex lookups `0x3c0de00`, `0x3c0d6e0`, `0x37601e0`, `0x3331fd0`, address text `0x1444a00`, prices `0x371cf40`, `0x32815f0`, `0x3760360`, `0x375fb50`, `0x333e310`, `0x371b8a0`, `0x342a1b0`, balance row `0x371b3a0`, stamp `0x3987cb0`, event sink `0x3576710`, text format `0x1344760`, hex decode `0x156e650`, base58 decode `0x3bc5960`. In `0x2712ce0` only the arguments and the status are used here, so the record passing from the core into `0x2715320` is shown on each side, not across it.

## Reproduce

```
python3 tools/bridge_send_to_evm_path.py --out research/work-items/bridge-send-to-evm-path-94
python3 -m unittest tests.test_bridge_send_to_evm_path
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder steps the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run took 77 s on a loaded host.

## Evidence

Addresses are virtual addresses. Fixed rows are bound in `key-rows.tsv`, every ordered test in `gates.tsv`, the three records and two queue rows in `record-fields.tsv`, and all sites in `call-sites.tsv`.

### The path

```
arm 76 sendToEvmWithData 0x2729060   arm 69 sendAsset 0x1f678c0   arm 82 agentSendAsset 0x27288c0   arm 71 SystemSendAsset 0x2728e10
   recipient 0x3988b80, gas, data       |                            master test 0x183                 no text, direct record
   system address as text               |                            |                                 |
 text parser 0x272b950 <----------------+----------------------------+                                 |
 route 0x2729c30 <-------------------------------------------------------------------------------------+   (also 0x2761b20, the aligned quote loop)
   sub-account and vault, modes, same send, collateral, transfer limit
   route byte 0, 1, 2: move once          3: unified steps around one move        4 and up: steps, move, retry over the Insufficient list
 move 0x272bd60
   source dex shift -, core 0x2712ce0, target dex shift +, sink, then the balance before and after test
 core 0x2712ce0: destination is the token's system address (merged packet)
 system send 0x2715320
   native token: row 0x38 at state +0x3100      other tokens: row 0xc0 at state +0x3118, after a gas fee
```

`sendToEvmWithData` builds six text fields and calls the same parser as `sendAsset`: destination is the system address of the token written as text, target dex is the literal `spot`, sub-account is empty. The arm adds the EVM block the others leave zero.

### The EVM block

The 0x58 bytes at record `+0x30` are `bytes::Bytes data` (4 words), the 32 byte recipient, gas limit, nonce and u32 chain id. Its first word is the only thing the path tests: zero means no block.

| Field | Rule | Status |
| --- | --- | --- |
| recipient, encoding 0 | `0x` then up to 64 hex digits, left padded with zeros by `{:0>64}`, so `0x` alone is 32 zero bytes | 0xb6 |
| recipient, encoding 1 | base58, exactly 32 bytes; the 128 byte decode table at `0x5a8450` gives the alphabet in `evidence.json` | 0xb6 |
| gas limit | below 0xccccccccccccccc, then at most 1000000 | 0x13f, 0x149 |
| data | at most 0x400 bytes | 0x142 |
| recipient text | at most 100 bytes, like every text field | 0x143 |

The system address is 0x20, 11 zero bytes and the token as 8 big endian bytes; for the native token, with state `+0x80` equal to 1, it is twenty 0x22 bytes.

### Route

`gates.tsv` has the 14 ordered tests of `0x2729c30`. The sender is the signer, or the sub-account. A vault sender walks `+0x98` parent addresses until it meets the signer (0x7c when the chain ends), and may then only name itself as destination with token 0 and vault byte `+0xaf` set (0x15). User row byte `+0x3c` sets the route:

| Sender byte | From spot | From dex 0 | From another dex |
| --- | --- | --- | --- |
| 0, 1 | route 0, 1 | route 0, 1 | route 0, 1 |
| 2 | route 2 | route 2 | 0x169 |
| 3, 4 | route 3, 4 | 0x16e | 0x16e |
| 5 up | route 5 up | route 2 | 0x169 |

State byte `+0x5b1` (sender byte up to 3) or `+0x5b0` (byte 4 up) skips this table and gives route 1. Routes 3 and up read the byte again and, unless the same state byte is set, run `0x28cc390`, `0x272fe00`, the move, then `0x272f880` for byte 4 or `0x272d000` otherwise; a `0x272d000` failure is dropped. Route 4 and up also retries: on status 0xf6 with a non-zero amount it walks the list in the status, each row running the move again with counter state `+0x7d0` and the row counters at `+0x30`, `+0x38`, stopping at the first success, or at 0x17e, which returns the first error.

Transfer limit: a transfer into a live dex (`+0x230` not 3), unless it comes from that same dex, is refused with 0x15f when `a = amount / 100 + max(total, 0)` passes `+0x1c0`, unless the margin sum is non-zero, `amount / 100` is within it, and `a` is within `+0x1c8`. The status text value is `(lim1 - total) / 1e6` with a zero margin sum, else `max(lim1 - total, min(lim2 - total, margin)) / 1e6`, each room being 0 when the limit is at or below the total.

### Move

The source dex is debited first, the core runs when sender and destination differ, then the target dex is credited. A failed credit after a real transfer is dropped, so the transfer stands; with the same address it refunds the source and fails. When a step fails and the spot balance of the token differs from the value read at entry, the status becomes 0x17e `Unexpected mutation`.

The event carries the names, amount and USD words, the fee block, the nonce (zero without the flag, state `+0x50` when byte `+0x78` is set), the block time, one or two users, and a stamp when state `+0` is 1. Above token 1 the USD word is capped at 10^16 unless the token name is `HYPE`.

### System send

`gates.tsv` has the 13 ordered tests of `0x2715320`.

| Input | Result |
| --- | --- |
| EVM flag state `+0x3ac9` not 1 | 0x14a |
| multi sig sender | 0x14e `Multi-sig user cannot transfer token to EVM` |
| token 0 above 10^15 | 0x28, the withdrawal limit text |
| native token with an EVM block | 0x148 `Send to EVM with data not configured` |
| native token | wei = amount * 10^10, no fee |
| other token, row `+0xbc` is 1 | contract at row `+0xbd`, extra decimals i8 at row `+0xd1` |
| decimals d >= 0 | wei = amount * 10^d as checked U256, else 0xba |
| decimals d < 0 | wei = amount / 10^-d, and a remainder or a scale past u64 is 0xba |

Fee, for tokens other than native: the gas step `0x37325d0` gets a price of 10^8 when state `+0x2a30` is 2, else `0x342a1b0`, the native token id, a data byte and the gas limit. A non-zero quote from `0x27101a0` adds a scaled native value. A sum above 10^10 is 0x14d. The payer is the alternate address when byte `+0xa4` is set. A payer with no native row goes to `0x2711a80` when the token is tradable, else `Insufficient HYPE`.

Queues: native is a Vec of 0x38 byte rows, refused from 3000 rows up; other tokens a Vec of 0xc0 byte rows, refused from 10 rows up, both 0x14c. `L1ToEvmNativeTokenTransfer with 2 elements` in rodata fits the first and `L1ToEvmErc20Transfer with 6 elements` the second.

### Status text

| Status | Text |
| --- | --- |
| `0x15` | Vault may not perform this action. |
| `0x28` | Withdrawal amount over single withdrawal limit. |
| `0x7c` | no fixed text |
| `0xb6` | Failed to parse user address |
| `0xba` | Invalid number of decimals: value |
| `0xdc` | Sub-account value |
| `0xea` | Invalid token |
| `0xf6` | Insufficient value |
| `0xf8` | Unknown token value |
| `0xf9` | Spot disabled |
| `0xfb` | Native token does not exist |
| `0x13f` | Invalid input number |
| `0x141` | Invalid perp DEX |
| `0x142` | Invalid bytes |
| `0x143` | Invalid input length |
| `0x148` | Send to EVM with data not configured |
| `0x149` | gas_limit too large |
| `0x14a` | EVM transfer not configured |
| `0x14c` | L1 to EVM transfer queue too long |
| `0x14d` | L1 to EVM transfer unable to compute fee |
| `0x14e` | Multi-sig user cannot transfer token to EVM |
| `0x15b` | Invalid send |
| `0x15f` | Transfer limit is value |
| `0x160` | Price missing |
| `0x169` | Cannot transfer with DEX abstraction enabled |
| `0x16e` | Unified account only supports sending assets through spot |
| `0x17e` | Unexpected mutation |
| `0x183` | Agent can only send asset to same user or their sub-accounts. |
| `0x186` | success, no text |

## Implementation and comparison

not yet implemented. A rule list in the tool, written from the reading, was compared with the real bytes.

| metric | value |
| --- | --- |
| Cases | 387 (23 agent send, 33 move, 32 recipient, 180 route, 18 send asset, 31 send to evm, 59 system, 11 system send asset) |
| Mismatches | 0 |
| Instructions stepped | 319,781 |
| Stepped / total, sendToEvmWithData arm 76 body `0x2729060` | 421 / 567 |
| Stepped / total, sendAsset arm 69 body `0x1f678c0` | 110 / 111 |
| Stepped / total, agentSendAsset arm 82 body `0x27288c0` | 238 / 270 |
| Stepped / total, SystemSendAsset arm 71 body `0x2728e10` | 120 / 120 |
| Stepped / total, six text fields to the send record `0x272b950` | 221 / 237 |
| Stepped / total, recipient text to 32 bytes `0x3988b80` | 105 / 125 |
| Stepped / total, gates and route of a send record `0x2729c30` | 1147 / 1375 |
| Stepped / total, move and event of a send `0x272bd60` | 644 / 838 |
| Stepped / total, system send, both L1 to EVM queues `0x2715320` | 1004 / 1099 |
| Stepped / total, gas step error to Insufficient token `0x2715130` | 86 / 122 |
| Stepped / total, send record clone `0x27b5760` | 150 / 187 |
| Stepped / total, send record drop `0x2784560` | 31 / 31 |
| Stepped / total, arm text fields drop `0x27822a0` | 37 / 41 |
| Stepped / total, erc20 queue push `0x27a0450` | 20 / 33 |
| Stepped / total, checked U256 product, shared `0x27a1150` | 233 / 331 |
| Stepped / total, dex row by index, shared `0x3332600` | 13 / 27 |
| Stepped / total, system address range test, shared `0x37e5110` | 42 / 42 |
| Mutants killed / survived / unreached | 1038 / 372 / 228 |

## Results and limitations

Every case matches; the 372 survivors and 228 unreached rows carry a reason in `mutations.tsv`. A survivor is a row the sampled cases cannot tell, not a claim that the row is dead.

- `0x2729c30`, `0x272bd60`, `0x2715320` are run through stubs, so what a stub does is out of scope: a refund or a credit inside `0x270f6f0` shows as an argument list and a status.
- Which network or token a state word holds is not in the binary. The byte `+0x3c` names come only from status texts, and modes 5 and up were reached only as fixture values.
- The third address at system record `+0x90` is copied into the quote and the erc20 row; who fills it in the core was not read.
- `0x4d32190` and `0x4d32c20` call the recipient parser and look like two more copies of the arm 76 body, and `0x2761b20` calls the route. They are listed in `call-sites.tsv`, not compared.
- Who drains the two queues and what the EVM side does with `data`, `gas limit` and chain id was not read.
- `0x272d000` is shared by many callers; here only its status is used.

Next question: which function drains state `+0x3100` and `+0x3118` into the EVM block, and what do `recipient` and the chain id become there?
