# bridge: signed action admission of node #94, from the recovered signer to the record words, the multi sig threshold and the class order of a bundle

This packet shows how a recovered signer becomes the three addresses every later gate reads, so a reconstruction can build the admission of withdraw3 and every other signed action: the signer resolves by a class byte of the action row, the first address is the vault or sub-account or user, the second the user, the third the raw signer (which is why nonces key on the signer, agent included), a multi sig user needs distinct recovered members up to a threshold of 1 to 10 of at most 10 signers, a direct signature for a multi sig user fails unless that signer has an `agent_to_user` row, and a bundle runs in the order noop, post only, cancel, rest. With the merged hash and vote packets and `bridge-nonce-lifecycle-94` this closes the signer half of the first bridge task; it answers the next question of `bridge-user-signed-types-94` (how signers are counted) and of `bridge-nonce-lifecycle-94` (who writes the three addresses).

- Component ID: `bridge`, first task "message hashes, nonce lifecycle and validator signing threshold". The bodies have no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims they live there: withdraw3 passes through them before its own gates.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (read for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, tables, node and bucket layouts, statuses and all outcomes in `cases.tsv`; inference for every name given to a field or class (user, agent, vault, post only, cancel) and for the wire names in `action-rows.tsv`, which come from `RE-010-exchange-handlers`; unresolved items are under limits
- Scope included and excluded: included as real bytes are the record writers `0x46d49b0`, `0x46d54d0`, `0x1e8db10`, their map loops `0x4550650`, `0x45524a0`, `0x2584bb0`, the resolvers `0x48f5570`, `0x48f52e0`, `0x282ec60`, the agent lookups `0x4d8b030`, `0x4d8b3b0`, `0x275ea20`, the multi sig bodies `0x4c5ca60`, `0x4c5c2d0` (inlined in `0x1e8db10`), the asset gates `0x48f58a0`, `0x48f5a30`, `0x282eea0`, the row functions `0x335ecb0`, `0x335ecd0`, `0x3363370`, `0x3362f30`, the post only tests `0x3bde170`, `0x3c1d690`, the partition `0x446fab0` with its join `0x4873270`, the vault lookups `0x45a3f20`, `0x25a7bf0`, the entries `0x46bcb90`, `0x46bcd60`, `0x1e64010`, the checks `0x4d9e4b0`, `0x4d9f0d0`, `0x27693d0` and the store `0x3426290`. Run real but not claimed and not mutated: SipHash `0x399c7a0`, the map insert and remove, the set inserts, removes and drops. Stubs: secp256k1 recovery `0x333fc80` and `0x3360b40` (merged in `bridge-user-signed-types-94`, their results are fed in), the validator row `0x33690c0` (#133, #425), the sub-account slots `0x36f3fe0`, `0x36f3ed0` (`vaults-subaccount-paths-94`), the fixed lists `0x37e4fb0`, `0x37e4e50` (`vaults-lifecycle-path-94`), the dex meta slot `0x3c0cc70`, the leaf set builders of the asset gate, the JSON parsers `0x43a31b0`, `0x1b2c1c0`, the Once call `0x576e8b8` (a hook writes the list).

## Reproduce

```
python3 tools/bridge_signed_action_admission.py --out research/work-items/bridge-signed-action-admission-94
python3 -m unittest tests.test_bridge_signed_action_admission
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder steps the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run took 124 s on a loaded host.

## Evidence

Addresses are virtual addresses. Fixed rows are bound in `key-rows.tsv`, tables in `action-rows.tsv`, `lazy-lists.tsv`, `node-layouts.tsv`, and all sites in `call-sites.tsv`. Copy 0 uses the state offsets below, copy 1 adds `0xa80` to all of them except the user table at `+0x318`, copy 2 is copy 0 with the multi sig body inlined.

### The path

```
0x4550650 / 0x45524a0 / 0x2584bb0  loop over 0x168 byte envelopes, writes 0x70 byte rows (envelope, index, 0x60 byte result), stops on status 0x187
 record writer 0x46d49b0 (out, envelope, state)
  recover 0x333fc80 (chain byte state +0x8f2)            status passes through
  action tag == 0xa8 (multi sig wrapper at envelope +0x10)
     inner tag == 0xa8                                   0x112
     multi sig body 0x4c5ca60
  else resolve 0x48f5570 (action, signer)
     resolved address in the multi sig map +0x39e8
        and the raw signer has no row in agent_to_user   0x115
  chain byte != 3: asset gate, any failure dropped
  no vault at envelope +0x150:                           record 0, user, user, signer
  touch row >= 2                                         0x15
  vault in the vault map state +0x8d0                    vault arm
  else sub-account arm
0x444d5c0 / 0x444d9a0  per bundle: partition 0x446fab0 of the 0x70 byte rows, then 0x454cd30 (not read)
```

### Result words

| Offset | Plain | Vault | Sub-account |
| --- | --- | --- | --- |
| `+0` status | 0x186 | 0x186 | 0x186 |
| `+2` byte | 0 | 1 | 0 |
| `+3` address 1 | user | vault | sub-account |
| `+0x17` address 2 | user | user | user |
| `+0x2b` address 3 | raw signer | raw signer | raw signer |

`bridge-nonce-lifecycle-94` keys the nonce on address 3 and the fixed list on address 1, so an agent has its own nonce set, and on a vault action the 400 cap follows the vault.

### Class of the action row

The row is `tag - 0x74`, and any tag below `0x74` is row 20 (VoteGlobal in `RE-010`). The byte at `0x58c1d8 + row` selects the resolver arm through `0x6ffed4` (`action-rows.tsv`, 86 rows).

| Class | Rule | Fails |
| --- | --- | --- |
| 0 | validator row by `0x33690c0` | 0x7b `Signer must be a validator.` |
| 1 | validator row, else member of a lazy list of 3 addresses | 0x7b |
| 2 | the signer acts for itself | never |
| 3 | agent lookup | 0x58 |
| 4 | refused | 0x7d `Action not allowed` |

The lazy list is chosen by chain byte: 3 picks `0x577ae70`, others `0x577aea0` (`lazy-lists.tsv`). Chain byte 3 is the one that skips the asset gate; which network it names is not read here.

Agent lookup `0x4d8b030` takes three tables in order. `agent_to_user` at state `+0x3730`, `0x28` byte bucket, gives the user at bucket `+0x14`. Then every `0x2f0` byte row of the list at `+0x5c0`, table at row `+0xf8`, `0x78` byte bucket, gives the signer itself. Then the table at `+0x318`, `0x58` byte bucket, the same. A miss is 0x58 with the signer (`unknown_with_all_tables`), and an agent row wins over a user row (`agent_beats_user_row`).

### Multi sig body

`0x4c5ca60` takes the payload at envelope `+0x18`: signature rows at `+8`, count `+0x10`, inner action `+0x18`, multi sig user `+0x20`, outer signer `+0x34`.

| Step | Test | Status |
| --- | --- | --- |
| 1 | outer signer == recovered signer | 0x11d |
| 2 | user `0x00..07`: inner row in mask `0x80000006408` (rows 3, 10, 13, 14, 43) | 0x112 |
| 3 | class of the inner row is 2 or 3 | 0x112 |
| 4 | user in the map at state `+0x39e8` | 0x114 |
| 5 | resolve the outer signer for the inner action | carried |
| 6 | resolved address in the signer set of the user | 0x11d |
| 7 | count <= 0x2710 | 0x143 |
| 8 | each row: recovery, carried on failure, member, else 0x11e, then into a seen set | |
| 9 | seen count >= threshold at value `+0x18` | 0x116 |

So a duplicate counts once (`multi_duplicate_not_counted`), one outsider fails the action even past the threshold (`multi_outsider_after_quorum`), the outer signer need not sign a row, and the checks stop at the first bad row. The result is the multi sig user as user; address 3 stays the outer signer, so nonces of a multi sig action key on the outer signer. A map value is `0x20` bytes: set root, height, length, threshold.

### Vault and sub-account arms

| Step | Test | Status |
| --- | --- | --- |
| Vault arm 1 | asset gate fails | carried |
| 2 | no dex set | 0x15 |
| 3 | dex set minus dex 0 is not empty | 0x15 |
| 4 | leader = vault value `+0x98`; if the leader is a vault, its value `+0x98` once | |
| 5 | user `0x00..07`: vault in list `0x37e4fb0` or `0x37e4e50`; the text of 0x119 names an Hlp vault, so this arm reads as the HLP route | 0x119 |
| 6 | other user == leader | 0x7c with user, vault |
| Sub arm 1 | vault address is a sub-account | 7 with the address |
| 2 | master == user | 0xdc with user, address |
| 3 | touch row == 0 | 0xdb |

The two level leader is exact: a third level fails (`vault_two_levels_only`). The dex of an asset is the slot value `/ 10000` (`0x346dc5d63886594b`, shift 11, in `0x4a00bc0`), and an absent asset is 0x15e. Status 0x15 is `Vault may not perform this action.` and also covers a touch row of 2 on a vault, a sub-account or a free address.

### Bundle order

`0x446fab0` splits rows into four lists in input order and `0x4873270` joins them: tag `0x74`, then post only, then cancel, then the rest. A row test runs on the wrapper's inner action, but the noop test does not (`sort_multi`).

| Class | Rows | Test |
| --- | --- | --- |
| noop | 0 | tag at envelope `+0x10` |
| cancel | 3, 4 | table `0x58983c` |
| post only | 2, 12, 14 | all orders with type byte 2 and trigger byte 0, an empty list is not post only |
| rest | others | |

A row with status 0x187 ends the input, later rows are dropped. The status does not affect the class (`sort_failed_rows`), so failed rows keep their place. That type byte 2 means post only is inferred.

### Writer of the threshold

`convertToMultiSigUser` through `0x46bcb90`, `0x46bcd60`, `0x1e64010`:

| Step | Test | Status |
| --- | --- | --- |
| 1 | action text length < 0x3e9 | 0x143 |
| 2 | parse | 0xbd |
| 3 | user is not `0x00..07` | 0x118 |
| 4 | user is in a dex row table or the table at `+0x318` | 0x118 |
| 5 | no signer object: remove the row of the user | 0x118 when there is none |
| 6 | each signer in key order: known | 0x11a |
| 7 | not a key of the vault map and not a key of the table at `+0x3810`; the text of 0x11b says vault or sub-account, so that table reads as the sub-account key table | 0x11b |
| 8 | not the user | 0x11c |
| 9 | `threshold - 1 < count` as unsigned, so 0 fails | 0x113 |
| 10 | count <= 10 | 0x117 |
| 11 | insert, an old set is dropped | |

Step 9 comes before step 10 (`convert_eleven_threshold_first`), and an empty signer list with any threshold is 0x113. The action never touches `agent_to_user` in these bodies.

| Status | Text |
| --- | --- |
| `0x7` | Vault not registered: {} |
| `0x15` | Vault may not perform this action. |
| `0x58` | User or API Wallet {} |
| `0x7b` | Signer must be a validator. |
| `0x7c` | success, no text |
| `0x7d` | Action not allowed |
| `0xbd` | Serde json conversion failed |
| `0xdb` | Sub-account may not perform this action. |
| `0xdc` | Sub-account {} |
| `0x112` | Unsupported multi-sig action |
| `0x113` | Invalid multi-sig threshold |
| `0x114` | Invalid multi-sig user |
| `0x115` | Multi-sig required |
| `0x116` | Multi-sig threshold not met |
| `0x117` | Too many multi-sig signers |
| `0x118` | Invalid multi-sig user to convert |
| `0x119` | Invalid multi-sig Hlp vault |
| `0x11a` | Multi-sig authorized user must exist on L1 |
| `0x11b` | Multi-sig authorized user cannot be vault or sub-account |
| `0x11c` | Cannot register self as multi-sig authorized user |
| `0x11d` | Invalid multi-sig outer signer |
| `0x11e` | Invalid multi-sig inner signer |
| `0x143` | Invalid input length |
| `0x15e` | Spot not supported |
| `0x186` | success, no text |

| metric | value |
| --- | --- |
| Cases | 1925 (87 convert, 1809 core, 11 sort, 18 wrap) |
| Mismatches | 0 |
| Instructions stepped | 1,392,781 |
| Stepped / total, record writer, second layout `0x46d49b0` | 533 / 551 |
| Stepped / total, map loop over envelopes, second layout `0x4550650` | 87 / 109 |
| Stepped / total, signer to acting address, second layout `0x48f5570` | 148 / 154 |
| Stepped / total, agent lookup, second layout `0x4d8b030` | 182 / 210 |
| Stepped / total, dex set of an action, second layout `0x48f58a0` | 120 / 120 |
| Stepped / total, multi sig body, second layout `0x4c5ca60` | 374 / 386 |
| Stepped / total, record writer, first layout `0x46d54d0` | 533 / 551 |
| Stepped / total, map loop over envelopes, first layout `0x45524a0` | 87 / 109 |
| Stepped / total, signer to acting address, first layout `0x48f52e0` | 148 / 154 |
| Stepped / total, agent lookup, first layout `0x4d8b3b0` | 182 / 210 |
| Stepped / total, dex set of an action, first layout `0x48f5a30` | 120 / 120 |
| Stepped / total, multi sig body, first layout `0x4c5c2d0` | 374 / 386 |
| Stepped / total, record writer, third copy, multi sig inlined `0x1e8db10` | 797 / 825 |
| Stepped / total, map loop over envelopes, third copy, multi sig inlined `0x2584bb0` | 88 / 110 |
| Stepped / total, signer to acting address, third copy, multi sig inlined `0x282ec60` | 119 / 119 |
| Stepped / total, agent lookup, third copy, multi sig inlined `0x275ea20` | 182 / 210 |
| Stepped / total, dex set of an action, third copy, multi sig inlined `0x282eea0` | 121 / 121 |
| Stepped / total, convertToMultiSigUser entry, second layout `0x46bcb90` | 102 / 104 |
| Stepped / total, signer checks and clear, second layout `0x4d9e4b0` | 537 / 658 |
| Stepped / total, convertToMultiSigUser entry, first layout `0x46bcd60` | 102 / 104 |
| Stepped / total, signer checks and clear, first layout `0x4d9f0d0` | 537 / 658 |
| Stepped / total, convertToMultiSigUser entry, third copy, multi sig inlined `0x1e64010` | 102 / 104 |
| Stepped / total, signer checks and clear, third copy, multi sig inlined `0x27693d0` | 537 / 658 |
| Stepped / total, threshold test and store `0x3426290` | 80 / 82 |
| Stepped / total, multi sig map insert, shared `0x339cab0` | 140 / 165 |
| Stepped / total, multi sig map remove, shared `0x33aa550` | 95 / 134 |
| Stepped / total, resolve class of a row `0x335ecb0` | 8 / 8 |
| Stepped / total, touch class of a row `0x335ecd0` | 23 / 24 |
| Stepped / total, cancel row test `0x3363370` | 22 / 23 |
| Stepped / total, post only row test `0x3362f30` | 40 / 41 |
| Stepped / total, class partition `0x446fab0` | 271 / 328 |
| Stepped / total, join of the four lists `0x4873270` | 279 / 590 |
| Stepped / total, post only test of a batch `0x3bde170` | 37 / 37 |
| Stepped / total, post only test of an order list `0x3c1d690` | 28 / 28 |
| Stepped / total, vault lookup `0x45a3f20` | 62 / 63 |
| Stepped / total, vault lookup copy `0x25a7bf0` | 62 / 63 |
| Stepped / total, SipHash 1-3 of twenty bytes, shared `0x399c7a0` | 83 / 83 |
| Stepped / total, dex set remove, shared `0x4945fb0` | 48 / 72 |
| Stepped / total, dex set remove copy, shared `0x2867580` | 48 / 72 |
| Stepped / total, dex set insert, shared `0x4932ad0` | 66 / 85 |
| Stepped / total, seen set insert, shared `0x4941fe0` | 118 / 129 |
| Stepped / total, seen set insert copy, shared `0x284f810` | 118 / 129 |
| Stepped / total, signer set lookup copy, shared `0x284bb50` | 58 / 60 |
| Mutants killed / survived / unreached | 2043 / 524 / 409 |

## Implementation and comparison

Implementation status: not yet implemented in Rust. The comparison is between a rule list written from the reading (`expect_core`, `multi_rule`, `resolve_rule`, `assets_rule`, `sort_class`, `expect_convert`) and the real bytes. All cases matched; the only corrections were fixture ones (stack argument position, a fresh dex set per gate call, the third loop's sink layout). Spec flips in the tests (nonce key on the user, cancel before post only) fail, and the 524 survivors and 409 unreached rows carry a reason in `mutations.tsv`.

## Results and limitations

The admission path from recovered signer to the sorted rows and the writer of the threshold are mapped and evaluated from bytes with no mismatch. Limits:

- Recovery is a stub in both forms, so which bytes are signed comes from `bridge-user-signed-types-94` and `0x3984fe0` is still not read.
- The validator row, sub-account slots, fixed lists and leaf set builders are fed in. The leaf builders decide which assets each action touches; only the single asset arm runs real.
- The count limit 0x2710 is tested at 0x2711 only; a run of 0x2710 rows is too long for this harness.
- The vault map and multi sig map trees run at height 0 and 1, map splits only as the real insert leaves them.
- The status 0x15 test, the touch word and the class word are row tables, shown here without proof that each row name in `RE-010` is the row's action.
- `0x444d5c0` and `0x454cd30` are not run, so what the block does with the sorted rows beyond the nonce gate is not claimed here. The upstream parallel producers `0x4764ef0`, `0x47694e0`, `0x22919e0` are only named.
- The lazy lists are written by a hook from bytes read at the closures; the Once itself is not run.
- The action text parser and the wire of `authorizedUsers` and `threshold` are not read, though the serializer `0x34264c0` names both.
- Whether a convert also clears agents elsewhere is not read.
- Overlap: the record writers appear only as caller rows in `vaults-subaccount-paths-94`, `fees-perp-settlement-94`, `vaults-lifecycle-path-94`, `staking-delegate-entry-94`, and that first packet ends by asking which action reaches `0x1e8db10`. An older index of PR files lists `0x4c5ca60`, `0x48f58a0` and `0x1e64010` under #393; that PR is not in the current list, so a reviewer should check it. `bridge-nonce-lifecycle-94` is drafted but may not be merged yet; only its name is used.

Next question: what does `0x454cd30` do with the sorted rows, and what is the wire of `convertToMultiSigUser` through the parsers `0x43a31b0`, `0x1b2c1c0` and the map serializer at `0x34264c0`?
