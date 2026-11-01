# bridge: how node #94 signs and queues its own actions

With this packet a Rust build can make the same signed record as the node for every action it sends itself: which of the 88 action rows take a 30 second `expires_after`, how the nonce is picked, which rows sign with EIP-712 and which with the agent form, that a failed sign side gate does not stop the send but falls back to the agent form, and the exact bytes of the compact signed bundle these records travel in, both ways.

- Component ID: bridge (`l1/bridge_request.rs`, the shared request builder and its chain id site named in `research/work-items/bridge/README.md`); this answers the Next question of `bridge-signed-message-94`
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `cec50f68e01c967d21538d48c49683ddeea52767`, `references/can1357-hl` as pinned there (searched for leads only, nothing copied)
- Claim status: observation for offsets, tables, immediates, status tags and all outcomes in `cases.tsv`; inference for every name given to a field; unresolved items are under limits
- Scope included and excluded: included as real bytes are the builder `0x3341af0`, the senders `0x4a10f80`, `0x4a11020`, `0x4a110c0`, the signer map `0x3bad290`, the sign tables `0x3362b30` and `0x335edb0`, the agent tails `0x333f7b0`, `0x33609f0`, `0x359ee60`, the agent verifier `0x333f690`, the queue push `0x44adbf0`, the bundle writer `0x3340100` and record writer `0x3340a40`, the bundle reader `0x342e4b0` and record reader `0x333f820`, the msgpack size code they reach, and 41 gate hosts (`functions.tsv`). Excluded, and stubs here: the agent payload `0x333f240` and its multi sig twin `0x37eb2d0` (merged in `RE-005-action-signable-94`), the digest `0x37f2940` (merged in `bridge-signed-message-94`), the EIP-712 signers reached from the gate hosts (open #1156), the envelope hash `0x3984fe0`, secp256k1 signing `0x14a2710` and recovery `0x14c6f50`, the clock, the signer sample `0x13cd040`, the action writer `0x3362fd0` and reader `0x3340e90` (a token stands for the action bytes), Keccak absorb and squeeze (SHA-256 of the same bytes stands in), and what the queue does next

## Reproduce

```
python3 tools/bridge_node_action_signing.py --out research/work-items/bridge-node-action-signing-94
python3 -m unittest tests.test_bridge_node_action_signing
```

Run from the repository root with Python 3 and the standard library; no external program is used and the binary is never executed. The tool reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, then steps instructions in a Python evaluator. A run took about 25 seconds with 4 workers.

| file | content |
|---|---|
| `action-rows.tsv` | 88 rows: tag, RE-010 name, expiry class, plain and multi sign form, gate host, signer, chain and time offsets |
| `builder-sites.tsv` | the 8 calls of the builder: host, tag, nonce form, vault byte, multi byte |
| `date-vectors.tsv` | date record to unix ms and expiry |
| `status-text.tsv` | status texts read from the Display table |
| `cases.tsv` | every case with its outcome |
| `functions.tsv` | extents and stepped rows |
| `mutations.tsv` | every mutant with its result; survivors and unreached rows carry a reason |
| `evidence.json` | totals, call sites, constants |

## Evidence

Coordinates are virtual addresses. Function extents are FDE extents (`functions.tsv`).

### The request record

`0x3341af0(out, request)` is reached only through slot `0x5773c88`. It reads a 0x128 byte request:

| Offset | Size | Meaning, by use |
|---|---|---|
| `+0x0` | 4 | 1 means the nonce at `+8` is used; any other value calls the clock at slot `0x576e9f8` |
| `+0x8` | 8 | nonce |
| `+0x10` | 0xf0 | the action; word 0 is the tag |
| `+0x100` | 8 | wallet pointer; the address is at wallet `+0x80` |
| `+0x108` | 21 | vault option: flag byte, then 20 bytes |
| `+0x11d` | 1 | multi sig flag |
| `+0x11e` | 1 | chain byte |

The output is the 0x168 byte record:

| Offset | Size | Value |
|---|---|---|
| `+0x0` | 8 | expiry tag |
| `+0x8` | 8 | expiry value; with tag 0 this word holds the wallet pointer, left in the register |
| `+0x10` | 0xf0 | the action |
| `+0x100` | 0x41 | signature |
| `+0x148` | 8 | nonce |
| `+0x150` | 21 | vault option |
| `+0x165` | 1 | always 0 |

### Row number and expiry

The row is `tag - 0x74`, or 20 for a tag below `0x74`, the same rule as RE-010, in all three tables here. Row 20 is `VoteGlobal`, whose inner tags share the word. Table `0x587bd0` has two arms. Twenty rows, the EIP-712 ones, get no expiry. The other 68 rows take `now + 30000` ms. `now` comes from slot `0x576e8a0`, a date record of packed year and ordinal, seconds and nanoseconds, turned into milliseconds in place. A negative time is floored at 0 first, so a date before 1970 gives exactly 30000 (`date-vectors.tsv`). Leap second nanoseconds above 1e9 pass through.

### Sign tables and the fall back

`0x3362b30` picks an arm from `0x58915c`. 21 rows go through a slot to a gate host, the other 67 go straight to the agent tail `0x333f7b0`. A host runs these gates in order, with context `+0` expiry tag, `+0x10` nonce, `+0x18` vault flag:

| Status | Text |
| --- | --- |
| `0x15` | Vault may not perform this action. |
| `0x5d` | Nonce mismatch. |
| `0x7a` | Unable to recover signer. |
| `0x8c` | Action does not support expires_after |
| `0x8f` | Mainnet and testnet require different signature. |

Order: chain byte against the action's byte, vault flag bit 0, nonce against the action's time word, expiry tag not 0. All four pass: the EIP-712 signer runs and the arm returns. Any one fails: the status is built, dropped, and the host returns tag 0. The arm then jumps to `0x333f7b0`, so the same action is signed in the agent form instead. **No sign side gate stops the signature.** The verifier is not symmetric: a verifier host such as `0x38e2a90` for row 33 runs the same four gates and returns the status as a refusal, and the merge at `0x3340053` passes any status other than `0x186` straight out. So the node can sign a user row into a record that its own verifier refuses with that status. Offsets are per action, read from each host (`action-rows.tsv`).

Row 52 is different. `0x3a1aec0` calls `0x3984fe0`, then compares only the chain and nonce words of its output, with the same fall back. Its verifier twin has the same two gates.

The multi sig table `0x588d3c` in `0x335edb0` has the same shape with 20 hosts, plus user and outer signer. A host clones the action's texts first, then runs the same four gates. Its tail `0x33609f0` hashes through `0x37eb2d0` instead of `0x333f240`. Row 52 has no host in this table, so a multi sig cannot nest in the user form.

The agent tail is short: `0x333f240` payload, `0x37f2940` digest, `0x14a2710` sign. A digest or signing error is a panic through `Result::unwrap`, so the node has no refusal path here. `0x333f690` is the verifier with the same two first steps and recovery in place of signing: a digest or recovery error gives status `0x7a`, success gives `0x186` with the 20 byte signer at `+2`.

### Multi sig wrap

With byte `+0x11d` set, the builder calls `0x13cd040`, and for each signer `0x3bad290` calls `0x335edb0` with the inner action. It builds action tag `0xa8`: signature list at `+0x8`, the boxed inner action at `+0x20`, user at `+0x28`, outer signer (the wallet's address) at `+0x3c`, signature chain id at `+0x50`, three zero words at `+0x58`. The user is a fixed constant: 16 zero bytes from `0x58b94d`, then the store `0x7000000`, so `0x0000000000000000000000000000000000000007`. The chain id is 42161 for chain byte 3, else 421614. The record gets no expiry whatever the inner row is.

`0x13cd040` shuffles indices of the static wallet list at `0x577ab08` and keeps `min(n, 2)`; `0x14b14c0` turns each index into a 0x98 stride pointer. That static is the wallet list whose loader is pinned in `foundation-hlu-validator-keys-94`. Those bytes are read, not run.

### Who calls the builder

`builder-sites.tsv` reads each store from the bytes in front of the call:

| Site | Host | Tag | Nonce | Action, by RE-010 row |
|---|---|---|---|---|
| `0x22af2bf` | `0x22ae8a0` | parsed from text | clock | any |
| `0x22af83f` | `0x22ae8a0` | `0x75` | given | `approveAgent` |
| `0x22b01b9` | `0x22ae8a0` | `0x85` | given | `CValidator` |
| `0x44aeb59` | `0x44adfa0` | `0xcb` | clock word | `voteL1Hash`, by `bridge-l1-hash-votes-94` |
| `0x47c0ccc` | `0x47c0ae0` | `0xb0` | clock word | `cSigner` with inner byte 2 (`voteJail`, by `staking-c-signer-jail-94`), one per list item |
| `0x4a11006` | `0x4a10f80` | `0xb2` | clock word | `cDeposit` |
| `0x4a110a6` | `0x4a11020` | `0xb1` | clock word | `cWithdraw` |
| `0x4a11169` | `0x4a110c0` | `0x95` | clock word | `tokenDelegate` |

Every site writes 0 to the vault byte and **0 to the multi sig byte**. So the wrap, `0x3bad290`, `0x335edb0`, its 20 hosts and the signer sample have no caller in #94 that reaches them: `0x3bad290` and `0x13cd040` each have this one site. They are run here by setting the byte in a fixture. The three senders write the action's time and the nonce from the same clock read and the chain byte twice, so they always pass the gates; the 32 byte word at action `+8` is 1 in all three.

### The compact bundle

`0x44adbf0(state, records, count)` is reached from `0x44aeb8d` and `0x44af11b`, right after the `voteL1Hash` and `voteJail` builds. It reads the clock, calls `0x3340100` with the wallet at state `+0x9d0`, and on status `0x186` moves the bytes into an Arc of 0x28 bytes (counts 1, 1, then capacity, pointer, length) and pushes a 0x168 byte item with word 0 = 9 onto the vector at state `+0x4d0`. On another status it hands the record to `0x447cb60` and pushes nothing.

Bundle bytes, written by `0x3340100` and read by `0x342e4b0`:

| Field | Size | Form |
|---|---|---|
| size list length | 4 | big endian, of the next field |
| size list | n | msgpack array of one unsigned integer per record, in the shortest form |
| records | sum of sizes | one after another |
| time | 8 | big endian, the clock read in `0x44adbf0` |
| signature | 65 | r and s big endian, then v, by the state wallet over Keccak-256 of all bytes before it |

Record bytes, written by `0x3340a40` and read by `0x333f820`:

| Field | Size | Form |
|---|---|---|
| r, s, v | 65 | r and s big endian |
| nonce | 8 | big endian |
| vault | 1 or 21 | flag 0, or flag 1 and the address |
| byte `+0x165` | 1 | below 2 |
| expiry | 1 or 9 | flag 0, or flag 1 and big endian value |
| action | rest | `0x3362fd0` |

The reader refuses in this order: 134 bytes or less `0x86`, recovery failure `0x7a`, size list length over the room `0x87`, msgpack error `0xbb`, sum of sizes not equal to the room `0x88`, then per record the status of `0x333f820`: 75 bytes or less `0x86`, cut fields `0x87`, vault flag above 1 `0x89`, byte above 1 `0x8a`, expiry flag above 1 `0x8b`, with the byte at `+2`, and any action error. A bundle with no record is 78 bytes, so `0x3340100` can write what `0x342e4b0` refuses. The signer recovered from the bundle is returned at `+0x28` with the record list and time; it is not checked here. `0x342e4b0` has five sites (`evidence.json`), `0x3340a40` also has three outside the bundle writer. In the test `test_real_writer_into_real_reader`, bytes from the real writer go through the real reader.

## Implementation and comparison

Not yet implemented in Rust. The rule list in the tool (`Spec`) was written from the reading notes and predicts each record and event. Real bytes and the rule list agree on every case below. The 200 survivors and 118 unreached rows carry a class in `mutations.tsv`, by count: a year of 0 or below gives a negative time and the floor at 0 hides the whole cycle shift 5, action field copied into the struct of the stubbed signer, or the dangling pointer of an empty text; the stub reads only the user and outer pair 99, capacity bit below the 8 byte alignment of a pointer list, or the dangling pointer of an empty list 3, copy size one byte larger or a stack base that a later store overwrites 6, rounding of the divide by 100 that gives the same quotient on these years, or a sign fix on a value that is never negative here 2, stack probe word 1, tag bound or low tag row that lands on an arm of the same class 6, the sender puts the same clock word in the nonce and the action, so a None nonce gives the same record 3, wire code class, not hand checked row by row 75.

| metric | value |
| --- | --- |
| Cases | 1273 |
| Mismatches | 0 |
| Instructions stepped | 280,192 |
| Stepped / total, builder `0x3341af0` | 269 / 313 |
| Stepped / total, signer map `0x3bad290` | 111 / 128 |
| Stepped / total, multi sign table `0x335edb0` | 1121 / 1121 |
| Stepped / total, multi agent tail `0x33609f0` | 41 / 50 |
| Stepped / total, plain sign table `0x3362b30` | 234 / 234 |
| Stepped / total, agent sign `0x333f7b0` | 24 / 33 |
| Stepped / total, agent verify `0x333f690` | 58 / 68 |
| Stepped / total, digest then secp `0x359ee60` | 63 / 76 |
| Stepped / total, queue push `0x44adbf0` | 64 / 82 |
| Stepped / total, bundle encoder `0x3340100` | 365 / 495 |
| Stepped / total, record encoder `0x3340a40` | 205 / 251 |
| Stepped / total, bundle reader `0x342e4b0` | 291 / 326 |
| Stepped / total, record reader `0x333f820` | 222 / 222 |
| Stepped / total, cDeposit sender `0x4a10f80` | 34 / 34 |
| Stepped / total, cWithdraw sender `0x4a11020` | 34 / 34 |
| Stepped / total, tokenDelegate sender `0x4a110c0` | 45 / 45 |
| Stepped / total, 21 plain gate hosts | 695 / 695 |
| Stepped / total, 20 multi gate hosts | 1785 / 2068 |
| Mutants killed / survived / unreached | 1523 / 200 / 118 |

Mutation: conditions, immediates and non-stack offsets of the 57 functions were flipped one at a time, each against a sample of cases per outcome, all date and wrap cases included.

## Results and limitations

- 88 of 88 rows are classed; the 20 rows without expiry are exactly the 20 rows with a multi sig host, and the plain hosts are those rows plus row 52.
- The EIP-712 signers, payload hashes, signing and recovery are stubs, so the signature bytes here are test tokens and only their flow is shown. The field values of the struct given to a multi sig signer are not compared except for the user and outer pair.
- `0x13cd040` is not run: it reads thread local state. Its bytes are only read for `min(n, 2)` and the stride.
- The verifier hosts are read for row 33 and the merge only, and are not run here. Their gates are bound in #1156.
- That the multi sig path is dead rests on the 8 sites of slot `0x5773c88`. A computed call through a copy of that slot would not show, and none was seen.
- Row names come from RE-010, which has none above row 75.
- The action bytes in a record are a stub token, so `0x3362fd0` and `0x3340e90` (compact order forms, three action classes) are not shown. The reader's error texts for `0x86` to `0x8b` were not read.
- The Keccak calls are stubs here; the same absorb shape is bound in RE-005. Survivors in the five wire functions carry one shared class and were not hand checked row by row.
- What the CLI does with a built record, and who reads the queue at state `+0x4d0`, was not read.

Next question: what bytes do `0x3362fd0` and `0x3340e90` give each action class, and who drains the queue at state `+0x4d0`?
