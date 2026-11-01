# bridge: the action nonce lifecycle of node #94, from a verified record to the prune of the set

This packet shows the whole life of the nonce that guards every signed action, withdraw3 included, so a reconstruction can build `address_to_nonce_set` and its gate as they run: the set lives in a hash table keyed by the third address of the verified record, the window is one day up and two days down (not one day each way), the cap is 100 or 400 and the 400 comes from a fixed list tested on the first address, a nonce is burned before the expiry test, signed bundles use the same table with their failures dropped, the proposer tests a bundle without inserting, and the only deletion is the agent removal prune. With the merged message hash and vote packets this closes the nonce part of the first bridge task.

- Component ID: `bridge`, first task "nonce lifecycle". The gate has no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims it lives in them: withdraw3 passes through it first, and `RE-004-withdraw-amount-gates-94` reads the second, withdraw-only nonce after it. No packet read these bodies; `RE-010-exchange-handlers/exchange-dispatch.json` lists four of the entries as FDE starts only.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (read for leads only, nothing copied; its one day lower window and its map type are refuted below)
- Claim status: observation for bytes, branch order, constants, texts, node and bucket layouts, offsets and call sites; inference for the names of the three record addresses and for what the block step does with a bundle that failed its nonce; unresolved items are under limits
- Scope included and excluded: included as real bytes are the three gates `0x4d9b6b0`, `0x4d9b820`, `0x2767bb0`, the candidate test `0x3986cc0`, the table probe `0x379ae30` and slot write `0x3577ae0`, the loops `0x444b430`, `0x444c310` and the one record host `0x2208580` up to their exec call, the bundle loop inside `0x42e4600`, `0x42e5d40`, `0x2209d40` (run as a fragment), the reverify `0x45485a0`, the prune `0x3422ce0` with `0x37a0860` and `0x33ba840`. Run as real bytes but not claimed and not mutated: the set insert and pop with their copies, the table growth slot, SipHash `0x399c7a0`, chrono date steps, the number formatter, the fixed list `0x37e4fb0` (shared, named in `fees-open-order-cap-94`). Stubs: allocator and memory slots, the clock of `0x45485a0`, the broadcaster test slot `0x5774360`, the weight slot `0x57739c0`, the budget row `0x47d7ca0` and `0x1f849b0` (`fees-request-budget-94`), the reduce-only test slot `0x57739c8`, the asset slot `0x57739d0` (always None here), exec `0x4d81290`, `0x4d81660`, `0x27584a0`, the reply writers.

## Reproduce

```
python3 tools/bridge_nonce_lifecycle.py --out research/work-items/bridge-nonce-lifecycle-94
python3 -m unittest tests.test_bridge_nonce_lifecycle
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder steps the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run took 70 s on a loaded host.

## Evidence

Addresses are virtual addresses. Fixed rows are bound in `key-rows.tsv`, `texts.tsv` and `tracker-fields.tsv`, so a moved row fails the run. All sites are in `call-sites.tsv`.

### The path

```
0x444b430 / 0x444c310 loop over 0x70 byte verified records, 0x2208580 one record
  status 0x186?  broadcaster test 0x5774360 (the two loops only), else 0xc1
  list 0x37e4fb0 on address 1 -> flag
  gate (state, flag, address 3, envelope +0x148)
    state +0x12e8 attempts + 1, saturating
    probe 0x379ae30 of state +0x41e0, on a miss slot write 0x3577ae0 of an empty set
    candidate test 0x3986cc0 through slot 0x5774dc8
    on pass: set insert, pop first while length > cap, state +0x12f0 passes + 1
  envelope +0 == 1 and expires +8 < now in ms: weight * 5 on address 1, status 0xca
  weight on address 1
  reduce-only set state +0x1338 holds address 1 or 2 and the action is not reduce-only: 0x111
  asset list, exec
0x42e4600 / 0x42e5d40 / 0x2209d40 bundle loop: gate (flag 0, bundle +0x30, bundle +0x28), status dropped
0x45485a0 proposer reverify: candidate test only, cap 100, no insert
0x3422ce0 through slot 0x5773a68 from three block step copies: the only deletion of a set
```

The second layout moves the table to `+0x3760` and the counters to `+0x868`, `+0x870`, which is `0xa80` below the first. The third gate is the second layout with its own copies of the set insert `0x2863ef0` and pop `0x2869060`. All 3 gates, 3 hosts and 3 bundle loops run here.

### The table

`tracker-fields.tsv` joins the name run in `.rodata` (`struct AgentTracker with 5 elements`) to the `lea` rows of `0x4d78460`: `AgentTracker` is at state `+0x36d0` with five hash tables `0x30` bytes apart, and `address_to_nonce_set` is the fourth at `+0x3760`. Each table is six words: control, mask, growth left, items and two SipHash keys. A nonce bucket is `0x30` bytes: 20 byte address at `-0x30`, set root `-0x18`, height `-0x10`, length `-8`. The set is a B-tree of `u64` (`node-layouts.tsv`). `0x48632e0` copies this table for the state snapshot in `0x4d78460`; that copy is read at its call only.

### The candidate test

`0x3986cc0` takes the time, flag, nonce and set, in this order. `n` is the nonce, `now` the time word as ms, floored at 0 by `cmovg`.

| Step | Test | Result |
| --- | --- | --- |
| 1 | cap = 400 if flag else 100; length >= cap and `n` < smallest | 0xc6 `nonce too low n < smallest` |
| 2 | `n` > max(now + 1 day, 0) | 0xc6 `nonce too high n > upper` |
| 3 | `n` < max(now - 2 days, 0) | 0xc6 `nonce too low n < lower` |
| 4 | `n` in the set | 0xc7 with `n` |
| 5 | pass | 0x186, cap in the next word |

The comparisons are unsigned, so a nonce with the top bit set is `too high`. The two day lower edge is two date steps of -86400 s, the second on the result of the first (`0x3986f73`, `0x3987005`), each with its own overflow panic. `window-bounds.tsv` prints the edges from the real text arms at 6 clock values. A date at the end of the range panics on the add (`date_end_panics_on_add`), one at the start on the subtract.

The gate's cap applies on every call, so a set of 150 written under flag 1 drops to 100 in one call under flag 0 (`evict_many_when_flag_drops`). The gate makes the bucket before the test, so a nonce that fails on a new address leaves an empty set (`failed_first_nonce_leaves_empty_set`). A full set still takes a nonce above its smallest, in any gap (`full_set_gap_inside`), and then drops the smallest.

### Who owns the nonce

The verified record holds three addresses at `+3`, `+0x17`, `+0x2b`. The fixed list and the weight use the first, the reduce-only set the first two, and the nonce key is the third (`nonce_key_is_third_address`). So cap 400 follows address 1 only: a list address as address 2 or 3 gets 100 (`list_key_alone_gives_no_400`, `list_second_address_gives_no_400`). The 8 addresses are in `fixed-list.tsv`, read from the `pcmpeqb` operands of `0x37e4fb0`.

### What burns a nonce

| Record | Nonce kept | Budget | Status |
| --- | --- | --- | --- |
| status not 0x186, or broadcaster refused | no gate call | none | carried, or 0xc1 |
| gate fails | no | none | 0xc6, 0xc7 |
| expired, expires < now | yes | weight * 5, saturating | 0xca |
| reduce-only refused | yes | weight | 0x111 |
| exec rejects | yes | weight | from exec |
| exec passes | yes | weight | from exec |

`expires == now` runs. `withdraw3` reaches its own nonce gate only after this table, as an action inside exec. In the two loops every record also raises the action count at state `+8` (the first one sets state `+0` to 1). That the set at `+0x1338` is a reduce-only list is inferred from the text of status 0x111.

| Status | Text |
| --- | --- |
| `0xc1` | Unexpected broadcaster |
| `0xc6` | Invalid nonce: {} |
| `0xc7` | Invalid nonce: duplicate nonce {} |
| `0xca` | Action already expired |
| `0x111` | Can only send reduce-only orders. |
| `0x158` | User actions frozen for token |
| `0x186` | success, no text |

### Bundles

The block step of each layout walks `0x28` byte items (32 byte hash, bundle pointer) and calls the gate with flag 0, the 20 bytes at bundle `+0x30` and the word at bundle `+0x28`. The status goes to a drop routine only (`0x4344430`, `0x2249ca0`). Both output lists gain the item before and after the call, whatever the status (`bundle_duplicate_dropped_list_kept`), so nothing in the loop removes a bundle.

The proposer side is `0x45485a0`, with call flag 1 at `0x489b199` and a caller byte at `0x44b9e61`. It reads a view: address set at `+0`, B-tree map of address to nonce set at `+0x18`. Signer absent from the map gives `TAG 0x...26` with hash and signer. A signer outside the address set must have only actions of row `0x57` or row `0x3c` with byte `+0x18` equal to 2, else the same tag. Then with the flag set the candidate test runs with cap 100, against the wall clock of slot `0x576e8a0`, not block time, with no insert. Pass gives `0x...2a`. A failure gives the status text, for example `Invalid nonce: duplicate nonce 1700000000128`, with the hash and signer beside it.

### The prune

`0x3422ce0` takes the tracker, a time and the user rows at state `+0x740`. For each user in `user_to_pending_agent_removals` it moves every `(agent, ready)` with ready <= time out of the tree, signed date first, then seconds and nanoseconds, into one sorted set of agents, and deletes the bucket of an emptied user. Then for each agent, in order: delete from `agent_to_user`, and if the agent has no user row delete its nonce bucket and free the set. A user row keeps the set (`real_user_keeps_set`). Nothing else deletes a set: outside this routine only eviction by cap removes a nonce, and age removes none.

The block step reaches it through slot `0x5773a68` from `0x22297c0`, `0x470e9a0` and `0x47162d0`, with the tracker at state `+0x36d0`; `0x2b1f1f0` also loads the address.

### Reference claims that do not hold

| Reference | Bytes |
| --- | --- |
| `NONCE_WINDOW_MS` both ways, lower edge now - 1 day | Lower edge now - 2 days; the upper edge is 1 day |
| `AddressToNonceSet` is a `BTreeMap` | SipHash table of `0x30` byte buckets at run time |
| `expanded_retention` caller flag with no source | Fixed list test on address 1 |

| metric | value |
| --- | --- |
| Cases | 245 (15 bundle, 127 gate, 69 host, 2 list, 2 panic, 13 prune, 17 reverify) |
| Mismatches | 0 |
| Instructions stepped | 1,094,008 |
| Stepped / total, nonce gate, primary layout `0x4d9b6b0` | 93 / 93 |
| Stepped / total, nonce gate, secondary layout `0x4d9b820` | 93 / 93 |
| Stepped / total, nonce gate, third copy `0x2767bb0` | 93 / 93 |
| Stepped / total, candidate test `0x3986cc0` | 309 / 338 |
| Stepped / total, hash table probe of the signer `0x379ae30` | 79 / 88 |
| Stepped / total, hash table slot write `0x3577ae0` | 37 / 51 |
| Stepped / total, signed action loop, primary `0x444b430` | 522 / 741 |
| Stepped / total, signed action loop, secondary `0x444c310` | 522 / 741 |
| Stepped / total, one signed action, third copy `0x2208580` | 308 / 485 |
| Stepped / total, proposer reverify of a signed bundle `0x45485a0` | 215 / 247 |
| Stepped / total, agent removal prune `0x3422ce0` | 263 / 311 |
| Stepped / total, pending removal drain per user `0x37a0860` | 177 / 202 |
| Stepped / total, pending tree drain step `0x33ba840` | 104 / 147 |
| Stepped / total, nonce set insert, shared `0x49400f0` | 71 / 85 |
| Stepped / total, nonce set insert copy, shared `0x2863ef0` | 71 / 85 |
| Stepped / total, nonce set pop first, shared `0x4946cc0` | 59 / 81 |
| Stepped / total, nonce set pop first copy, shared `0x2869060` | 59 / 81 |
| Stepped / total, fixed eight address list, shared `0x37e4fb0` | 66 / 66 |
| Stepped / total, SipHash 1-3 of twenty bytes, shared `0x399c7a0` | 83 / 83 |
| Stepped / total, block step, bundle loop only `0x42e4600` | 63 / 332 |
| Stepped / total, block step copy, bundle loop only `0x42e5d40` | 63 / 310 |
| Stepped / total, block step copy, bundle loop only `0x2209d40` | 63 / 702 |
| Mutants killed / survived / unreached | 714 / 357 / 240 |

## Implementation and comparison

Implementation status: not yet implemented in Rust. The comparison is between a rule list written from the reading (`decide`, `apply_gate`, `expected_host`, the prune model) and the real bytes. All cases matched first on the rule list after the window edge was corrected from one day to two by the first real run. Spec flips in the tests (lower edge of 1 day, key on the first address) fail, and the 357 survivors and 240 unreached rows carry a reason in `mutations.tsv`.

## Results and limitations

The nonce gate, its table, the three record hosts, the bundle loops, the reverify and the prune are mapped and evaluated from bytes with no mismatch. Limits:

- Names: the three record addresses are observed positions. That address 3 is the signer and address 1 the acting user is inferred from the reference and the fixed list use; `0x446fab0` sorts and passes these records and the writer was not read.
- The reduce-only test slot, weight, budget row, broadcaster test and exec are stubs. The asset arm (0x158) and the sink at state `+0x4508` are not reached.
- The bundle loops run as fragments, 63 instructions of each host. What the block step does with a bundle after the loop is not read, so that a failed bundle still executes is inference from the lists.
- The two gate counters have no reader named here: the offsets are too common to scan.
- `AgentTracker` serde and the snapshot copy are not run. `0x407b150` also calls the set insert and is not read.
- Table growth runs real on the fixtures but is checked only through the final table rows.
- Near the date range ends the rule list is checked for panic text only.

Next question: who writes the three addresses (`0x446fab0` and its verifier), and what are the wire bytes of `address_to_nonce_set` in `AgentTracker`, through `0x48632e0`, the serializer at `0x1873720` and the field matcher copies at `0x22e9c80`?
