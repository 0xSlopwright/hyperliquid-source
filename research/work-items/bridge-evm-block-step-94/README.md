# bridge: the EVM block step of node #94, from the two L1 to EVM queues through system transactions and EVM logs back to L1 actions, with the supply check, the automatic halt, held rows, retry and release

This packet shows how both directions of the L1 and EVM crossing run inside one block step `0x2760a70`, so a reconstruction can write the drain of the two queues into system transactions with their calldata, gas and kind, the rule that turns an EVM log into a `SystemSpotSendAction`, the token 0 supply check that sets the same halt byte `withdraw3` reads, and the three validator votes that retry a failed send, release held rows and link the token 0 contract, none of which any earlier packet evaluates.

- Component ID: `bridge`, "deposit/withdrawal requests and cross-chain signing". The bodies have no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims they live there.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `7194e50b54c6cea3380f2e78d6edfe6fd73cc7bb`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied; it has none of the queue, held map or escrow field names)
- Claim status: observation for bytes, branch order, constants, gas, kinds, selectors, topics, statuses, record offsets and all outcomes in `cases.tsv`; inference for every field name and for the words supply, cap, held and halt; unresolved items are under limits
- Scope included and excluded: included as real bytes are the step `0x2760a70` and its same-layout copy `0x4d8db10`, the head of the block run `0x2448500..0x2448888`, the drain `0x3270830`, the rebalance collect `0x3bae680` and row `0x3299180`, the transaction builder `0x3730d70`, the calldata writer `0x324d680`, the keep list append `0x24f4fd0`, the log loop `0x244a0ec..0x244a298`, the classifier `0x34273d0`, the decoders `0x37a3850`, `0x37a2990`, `0x37a4230`, the supply check `0x2760040` and copy `0x4d8c610`, the hold pass `0x2517d60`, the VoteGlobal arms raw `0x61`, raw `0x5e` selectors 0, 3 and 4, the push `0x239f460` and the set `0x274b7e0`. Run real, not claimed and not mutated: scale `0x3281770` (RE-004-evm-amount-scale-94), checked subtract `0x2760a10` (foundation-checked-subtract-94), U256 helpers, ABI encoder `0x3303050`, map helpers. Stubs that log their arguments: EVM execution `0x326d500`, balance read `0x326e540`, code install `0x3271680`, EVM reads `0x244bc40`, `0x244bea0`, apply `0x2759240`, `0x27584a0`, stamp `0x3987cb0`, transfer core `0x2712ce0`, credit `0x371d120`, balance row `0x371b3a0`, user row `0x1f849b0`, CoreWriter decoder `0x333b2a0`, environment `0x37dc090`. The transaction loop of `0x2448500` outside the two ranges, revm, and the CoreWriter action forms are excluded.

## Reproduce

```
python3 tools/bridge_evm_block_step.py --out research/work-items/bridge-evm-block-step-94
python3 -m unittest tests.test_bridge_evm_block_step
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder steps the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run took 40 s on a loaded host.

## Evidence

Addresses are virtual addresses. Fixed rows are bound in `key-rows.tsv`, every ordered test in `gates.tsv`, all records and state words in `record-fields.tsv`, tree nodes in `node-layouts.tsv`, event topics and system addresses in `signatures.tsv`, rodata names in `rodata-texts.tsv`, the two jump tables in `jump-rows.tsv`, callers in `call-sites.tsv`, and the byte census of the state words in `field-sites.tsv`.

### The path

```
0x2761b20 -> 0x2227c80 (mode 1), 0x222c650 (mode 0) -> step 0x2760a70
  block run 0x2448500 (EVM state = state +0xbc0)
    drain 0x3270830
      code of 0x33.., 0x22.., 0x55..
      rebalance rows, flag 1
      native queue evm +0x2540, then erc20 queue evm +0x2558, each row one system transaction
      kept rows -> list at evm +0x2570 (0x24f4fd0)
    each transaction in the block:
      receipt status clear: no log is read
      each log: classifier 0x34273d0 -> 0x48 byte row, or CoreWriter decoder 0x333b2a0
  sum of token 0 rows -> supply check 0x2760040
    tag 1: gauge +0x3180 rises     tag 0, 3: halt byte +0x31a2 = 1     tag 2: nothing
  halt byte set: token 0 rows move to the map +0x3168 (0x2517d60)
  user map -> +0x39d0
  each row left -> action 0xad from the token system address -> apply 0x2759240
  each signed row -> apply 0x27584a0
```

State `+0xbc0` is the EVM state, so the queues at state `+0x3100` and `+0x3118` are `+0x2540` and `+0x2558` from it. That is why a state offset scan finds no reader: the drain is the only function that reads the rows, through the shorter offsets.

### L1 to EVM: the system transactions

The drain takes both queues whole and leaves them empty. Every transaction goes through `0x326d500`.

| Source | From | To | Value | Gas | Kind | Calldata |
| --- | --- | --- | --- | --- | --- | --- |
| rebalance row | token contract or value `+0x40` | value `+0x54` | 0 | 200000 | 3 | `transfer(address,uint256)` of the gap |
| native row | `0x22..22` | row sender | wei | 30000 | 0 | none |
| linked token, before its row | value `+0x40` | value `+0x54` | 0 | 200000 | 4 | `transfer(row contract, min(balance, wei))` |
| erc20 row, no data | third address | row contract | 0 | 200000 | 1 | `transfer(sender, wei)` |
| erc20 row, data | third address | row contract | 0 | row gas | 2 | selector `6ddde35e`, then 7 words: sender, recipient, chain id, wei, nonce, 0xc0, length, then the data padded |

Rebalance, per row of the map at spot `+0x278` in token order, with `+0xbc` bit 0 of the token set: read the balance of the token contract and of value `+0x40` at target value `+0x54`. A missing read or a carry ends that row. `goal = total / 100 * 90`. A second balance below the goal takes the gap from the token contract, above it gives the excess back, equal sends nothing. All rows are computed first, and the transactions then run with flag 1, like the linked transfer. So value `+0x40` is steered to 90 of 100 of the two balances.

A kept row is an erc20 row with third address `0x20` and zeros, a missing or failed receipt, and wei at or above 10^9. Any other row loses its data. The signature behind selector `6ddde35e` is unresolved.

### EVM to L1: log to row

`keccak256("Received(address,uint256)")` is the 32 bytes at `0x2094e0` and `0x207ed0`, and `Transfer` and `Approval` are at `0x20c6c0`, `0x20bce0`; `signatures.tsv` proves all three with a Python Keccak. A transaction whose word at frame `+8` is negative gives no row at all; the same sign fills the status byte at `0x2449ff5`, so this reads as a failed receipt (inference).

| Log | Rule |
| --- | --- |
| address `0x22..22`, `Received`, at least 2 topics, exactly 32 data bytes, amount not 0, native record on | token = native token, amount = wei / 10^10 floored, user = low 20 bytes of topic 1. A scale refusal (at or above 0xccccccccccccccc) ends with no row |
| that address with any other shape | falls through to the contract map |
| address in the map the block run builds with `0x3316a60` (not run) | `Transfer` with at least 3 topics and exactly 32 data bytes, `to` equal to the token's system address, amount scaled by the map byte, user = `from` |
| anything else | no row, and the log goes to the CoreWriter decoder |

Extra topics are ignored, the 12 high bytes of an address topic are not tested, and an amount below one unit gives a row with amount 0. System address is twenty `0x22` for the native token, else `0x20`, 11 zeros and the token as 8 big endian bytes. The row becomes action tag 0xad, handler row 57 `SystemSpotSendAction` in RE-010, applied with the system address as sender, the nonce word `+0x50` raised and byte `+0x78` set around the call.

### Supply check

`0x2760040` works on token 0 only.

```
tag 2  no token row, or +0xbc clear
tag 3  +0xd1 is not 0xfe, or an EVM read is missing
value  = system balance + 100 * read0 + 100 * read1 - cap(+0x3a48) - (held sum + argument) - 100 * queued wei of that contract
tag 0  a carry or any step below zero
tag 1  the value
```

The products saturate at 2^256 - 1, the held sum and the argument saturate at 2^64 - 1, and only erc20 queue rows with contract equal to the token contract count. With a row for token 0 in the spot map there are two reads, the second with value `+0x40`. In the step the argument is the sum of the token 0 rows of the block.

Tag 1 raises the gauge `+0x3180`, never lowers it. Tag 0 and tag 3 set the halt byte `+0x31a2` with a recorder of level 3. While the byte is set, token 0 rows of the block leave the action list and add to the map `+0x3168`, saturating, in row order, so only other tokens are applied.

The same byte is read at two more places: the withdraw core `0x27342ea` (merged, status 0x27 `Error withdrawing from bridge`) and the transfer core `0x27133a9`, where a branch not traced here refuses with 0x26 `Error transferring to EVM. Use Arbitrum bridge instead.` when a balance word plus the amount passes the cap or the byte is set. Raw `0x5e` selector 1 (merged) writes the byte too, so this packet adds the automatic writer.

### Votes

| Raw tag | Effect |
| --- | --- |
| `0x61` | Pop the oldest kept row. Byte `+8` not 0 drops it. Byte `+8` 0 drops the data and pushes the row on the erc20 queue with no length test, so a retry is a plain transfer and can pass the 10 row limit of the send path |
| `0x5e` selector 0 | Zero address unsets: refused with 0xdf `unable to unset usdc evm contract` when cap + word 1 wraps or passes word 0 of the system balance, else debit the cap and clear it. Other address sets: refused for a contract in use or a cap not 0, else token 0 takes the address and 0xfe, the system balance moves to address zero, and the system address takes 2^63 - 1 as balance and cap |
| `0x5e` selector 3 | Halt byte clear and supply check tag 1 with argument 0: take the whole map `+0x3168`, each row through the transfer core from the token 0 system address to the user. A failure is dropped and the next row goes on |
| `0x5e` selector 4 | Clear the gauge |

### Status text

| Status | Text |
| --- | --- |
| `0x26` | Error transferring to EVM. Use Arbitrum bridge instead. |
| `0x27` | Error withdrawing from bridge |
| `0xdf` | Error deploying spot: value |
| `0x13f` | Invalid input number |
| `0x186` | success, no text |

### Copies

`0x4d8db10` and `0x4d8c610` run every step and supply check case with their own callees and match. The third step `0x4d8ebc0` and its check `0x4d8d060` use a layout shifted by 0xa80 from `+0x5b8` up (key rows `0x4d8ebdc`, `0x4d8ec90`, `0x4d8ed1c`) and were not run.

## Implementation and comparison

not yet implemented. A rule list in the tool, written from the reading, was compared with the real bytes.

| metric | value |
| --- | --- |
| Cases | 427 (74 classify, 58 drain, 1 gauge, 5 head, 13 hold, 12 keep, 24 link, 8 loop, 102 reconcile, 15 release, 15 retry, 100 step) |
| Mismatches | 0 |
| Instructions stepped | 205,136 |
| Stepped / total, EVM block step `0x2760a70` | 641 / 786 |
| Stepped / total, head of the block run: environment, drain, keep list, slot take `0x2448500` | 141 / 145 |
| Stepped / total, queue drain to system transactions `0x3270830` | 558 / 646 |
| Stepped / total, queue row to system transaction `0x3730d70` | 346 / 449 |
| Stepped / total, transfer(address,uint256) calldata `0x324d680` | 88 / 112 |
| Stepped / total, keep list append `0x24f4fd0` | 119 / 152 |
| Stepped / total, rebalance row collect `0x3bae680` | 179 / 308 |
| Stepped / total, rebalance row of one linked token `0x3299180` | 255 / 261 |
| Stepped / total, log loop of one transaction `0x244a0ec` | 68 / 74 |
| Stepped / total, log to L1 row `0x34273d0` | 245 / 247 |
| Stepped / total, Received decoder `0x37a3850` | 166 / 230 |
| Stepped / total, ERC20 event decoder `0x37a2990` | 363 / 455 |
| Stepped / total, 32 byte word read `0x37a4230` | 85 / 99 |
| Stepped / total, supply check `0x2760040` | 449 / 475 |
| Stepped / total, U256 checked subtract, merged `0x2760a10` | 27 / 27 |
| Stepped / total, token 0 rows into the held map `0x2517d60` | 243 / 301 |
| Stepped / total, erc20 queue push of the retry arm `0x239f460` | 22 / 33 |
| Stepped / total, raw 0x61 arm, pop and drop branch `0x2356007` | 32 / 32 |
| Stepped / total, raw 0x61 arm, requeue branch `0x235a6ca` | 18 / 18 |
| Stepped / total, raw 0x5e selector 3, gate `0x235b3c4` | 20 / 20 |
| Stepped / total, raw 0x5e selector 3, pay held rows `0x235d00f` | 85 / 86 |
| Stepped / total, raw 0x5e selector 4, gauge clear `0x235b2b4` | 4 / 4 |
| Stepped / total, raw 0x5e selector 0, set or unset the token 0 contract `0x274b7e0` | 228 / 245 |
| Stepped / total, EVM block step, copy with the same layout `0x4d8db10` | 641 / 786 |
| Stepped / total, supply check, copy with the same layout `0x4d8c610` | 472 / 508 |
| Stepped / total, wei scale, merged `0x3281770` | 97 / 122 |
| Stepped / total, decoder error drop, shared `0x34353c0` | 45 / 71 |
| Stepped / total, linked token map next, shared `0x330fb70` | 45 / 122 |
| Stepped / total, U256 division, merged `0x32d6ad0` | 185 / 237 |
| Stepped / total, U256 subtract, shared `0x32d8310` | 24 / 24 |
| Stepped / total, ABI encoder, shared `0x3303050` | 155 / 185 |
| Stepped / total, queue iterator drop, shared `0x330be30` | 33 / 79 |
| Stepped / total, pair times 100, shared `0x28f4830` | 99 / 99 |
| Stepped / total, U256 product, shared `0x1498bc0` | 195 / 331 |
| Stepped / total, map value sum, shared `0x28c3000` | 59 / 152 |
| Stepped / total, map take next, shared `0x2869350` | 76 / 225 |
| Stepped / total, map entry, shared `0x2878340` | 78 / 87 |
| Stepped / total, map entry, shared `0x28784e0` | 62 / 69 |
| Mutants killed / survived / unreached | 1265 / 353 / 179 |

## Results and limitations

Every case matches; the 353 survivors and 179 unreached rows carry a reason in `mutations.tsv`. A survivor is a row the sampled cases cannot tell, not a claim that the row is dead.

- EVM execution, balance reads and the two supply reads are stubs. The meaning of read 0 and read 1 is not in these bytes; only the arguments are: `0x244bc40` gets the contract twice, `0x244bea0` the contract and value `+0x40`.
- Field names are inference. `l1_to_evm_native_token_queue`, `l1_to_evm_erc20_queue` and `user_to_evm_to_l1_wei_remaining` fit by row shape, row names and order, but no serializer was read to bind a name to an offset. `0x3a48` near `initial_usdc_evm_system_balance` was not bound either, and `evm_transfer_escrows` is not bound to the spot map.
- Raw `0x5e` selector 2 at `0x235b2cf`, which builds a map from the action near `+0x3168`, was not evaluated, nor were selectors 6 and 7.
- Who writes the spot map at `+0x278`, and what value `+0x00..+0x40` holds, was not read.
- The block run outside the two ranges, the user map it returns, what mode 0 and 1 mean beyond picking `+0x2520` or `+0x21b8`, and the value of the output words at drain `+0x30` were not read.
- The transfer core row `0x27133a9` is shown as key rows with its status, not run.
- `0x4d8ebc0`, `0x4d8d060`, `0x44684d0`, `0x4464dc0` and the VoteGlobal copy `0x4caa870` are listed, not compared.
- `field-sites.tsv` is a byte census: unrelated structs can share an offset.
- `0x2760040`, `0x2760a70`, `0x2517d60`, `0x3299180`, `0x274b7e0`, `0x34273d0` and `0x2448500` appear in merged lists or as callers of a helper in other packets, which do not evaluate these questions; `RE-004-evm-amount-scale-94` records the entry of `0x34273d0` as unresolved, and `call-sites.tsv` answers it. `0x2760a10` is bound by a merged packet and is run here without a claim.

Next question: what do the CoreWriter decoder `0x333b2a0` and the action decoders it calls accept, how does `disabled_core_writer_actions` gate them, and how does the signed row reach `0x27584a0`?
