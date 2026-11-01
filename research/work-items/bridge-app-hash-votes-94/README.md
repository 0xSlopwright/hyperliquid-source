# bridge: the voteAppHash path of arm 48 and the bodies of both vote trackers in node #94

This packet shows how a validator vote on an app hash becomes a quorum row, and what the two trackers `0x3946a80` and `0x39438e0` do with a vote, so a reconstruction can build `AppHashVoteTracker` and the tracker inside `lhvt`: the signed bytes are Keccak of the MessagePack pair `[height, "0x...hash"]`, a voter may hold votes for several hashes at one height because nothing replaces an earlier vote, one height crosses once, the row is rebuilt by hot user at the epoch of the crossing, the prune floor comes from the vote height, and the block step takes the list and drops rows with no hot user. The L1 hash tracker has the same shape with a second voter form, and its quorum is stake AND ratio.

- Component ID: `bridge`, for signature aggregation over the same voter context as the deposit and withdrawal votes (state `+0x3840`). Arm 48 has no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims it lives in them. It answers the Next question of `bridge-l1-hash-votes-94` and closes that packet's open item on `0x39438e0`.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `cec50f68e01c967d21538d48c49683ddeea52767`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (read for leads only, nothing copied; two of its claims are refuted below)
- Claim status: observation for bytes, branch order, constants, signed bytes up to the digest call, status text, serde names, node layouts and call sites; inference for Keccak as the name of the digest and for what the block step does with the taken list; unresolved items are under limits
- Scope included and excluded: included are the wrapper `0x1e5f5d0` and its two copies, the digest `0x37e5a30`, the core `0x336a4e0`, the tracker `0x3946a80`, the voter test `0x3367530`, the quorum `0x3941240`, both entry inserts, the height scan `0x3bca430`, the split `0x3942b90` with the list `0x3bcd010`, the take `0x336a360`, the L1 tracker `0x39438e0`, its quorum `0x3941070`, the listed insert `0x33a6d90` and its entry inserts. Run as real bytes but not claimed here, and not mutated: `0x33690c0`, `0x3369500`, `0x3366b60`, `0x339b0d0`, `0x33e79f0`, `0x3316090`, `0x32478a0`, `0x3bde1f0`, shared with the other vote packets. Stubs: recovery slot `0x576fe58`, the Keccak absorb and squeeze slots (SHA-256 stands in, so no digest value is claimed), the stake map `0x3364ed0`, the once slot, allocator slots. The L1 core `0x394ac70` and wrapper `0x1e5f010` are covered by `bridge-l1-hash-votes-94` and are not rerun: the L1 tracker is called directly with the argument form read at `0x394b13d`.

## Reproduce

```
python3 tools/bridge_app_hash_votes.py --out research/work-items/bridge-app-hash-votes-94
python3 -m unittest tests.test_bridge_app_hash_votes
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder steps the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run took 170 s on a loaded host.

## Evidence

Addresses are virtual addresses. Fixed rows are bound in `key-rows.tsv`, so a moved row fails the run.

### The path

```
table 0x3ede28 row 48 -> arm 0x27597d8 -> call 0x27597fb -> wrapper 0x1e5f5d0
wrapper     height limit, digest 0x37e5a30, recovery, recovered == sender, then slot 0x5773138
core        0x336a4e0: height limit, voter key 0x33690c0 at the current epoch, tracker 0x3946a80
  on a result: maximum of highest_quorum_height, collect 0x3316090, push one 0x40 row, once, split 0x3942b90
take        0x336a360 through slot 0x5774d70 from 3 block step bodies
```

The other two wrappers are called at `0x4d8360b` and `0x4d8472b` (`call-sites.tsv`). `0x46770e0` reads the tracker at state `+0x3fc0` and the voter context at `+0x42c0`, both `0xa80` above the plain form, which is where `0x4d7bed0` moves those fields. `0x4677280` uses the plain offsets. All three run here.

### Signed bytes

`0x37e5a30` writes the same pair as the L1 path through `0x32478a0`, then starts a sponge with rate `0x88` and suffix word 1 at `0x37e5afd` and absorbs the buffer. `signed-bytes.tsv` holds the bytes at every MessagePack form of the height:

```
92                      array of two
<uint>                  height in the smallest MessagePack form
d9 42                   str8 of length 66
30 78 <64 hex chars>    "0x" and lower-case hex of the hash
```

`bridge-l1-hash-votes-94` shows the L1 arm feeds these bytes to a BLAKE3 start. The two arms share the pair and differ in the digest.

### Status order

| Status | Text |
| --- | --- |
| `0x13f` | Invalid input number |
| `0x7a` | Unable to recover signer. |
| `0x11f` | Signer does not match expected user |
| `0x97` | Epoch state does not exist |
| `0x2a` | User is not a validator. |

Order in the wrapper: `0x13f` for a height above `0x0ccccccccccccccb`, `0x7a`, `0x11f`, then from the core `0x97` when the epoch is absent and `0x2a` when no validator of the epoch has the sender as hot user. The core has its own limit, one above the wrapper's, so it is unreachable through the wrapper. On `0x11f` the word at result `+0x10` is the compare mask. Success is tag 9 with the result byte at `+1`: 1 when a row was pushed. Only a hot user at the current epoch can vote: this arm has no listed address path.

### AppHashVoteTracker

Serde names are in `names.tsv`: state key `app_hash_vote_tracker`, `struct AppHashVoteTracker with 3 elements`, `tracker`, `quorum_app_hashes`, `highest_quorum_height`, `struct QuorumAppHash with 2 elements`.

| Field | At |
| --- | --- |
| first `0x18` bytes | not read or written by any function here (`head moved` check) |
| tracker height map | `+0x18` root, `+0x20` level, `+0x28` length |
| `quorum_app_hashes` | `+0x30` capacity, `+0x38` pointer, `+0x40` length |
| `highest_quorum_height` | `+0x48` |

A height value is `0x40` bytes: hash map at `+0`, then byte `+0x18` (0 on a crossing), the winning hash at `+0x19`, the done flag at `+0x39`. A hash value is `0x30` bytes with two maps. `node-layouts.tsv` has each node.

### What one vote does

1. The voter key must be in the current epoch (`0x3367530`). With no key, a foreign key or an absent epoch the tracker changes nothing and creates no height (`direct_none`, `direct_foreign_key`, `direct_epoch_absent`). Through the arm this test always holds, since the core has just resolved the key at that epoch.
2. The height and hash entries are created.
3. If the height is done, the vote is stored with no quorum test (`votes_after_done_other_hash`).
4. Otherwise the quorum runs before and after the insert. A row needs false then true. If the bucket already held a quorum before this vote, no row appears (`before_test_true_blocks_row`), which only an epoch change can cause.
5. A crossing sets the done flag, the hash and the output with a clone of both maps.

Quorum is `2 * total < 3 * voted` as in the other trackers (`exact_two_thirds_is_short`), per hash (`split_hashes_do_not_add`).

No code path removes a vote. `same_voter_two_hashes` holds one voter in two buckets of one height, and `second_hash_reaches_after_done` shows a second hash filling to quorum with no second row. The reference's `signer_votes` index with replacement does not exist in these bytes. The stack word 1 that the core passes after the context is read by no row of the tracker.

The second map of an app hash bucket is always empty. `0x3941240` runs a key iterator over it and stops at `ud2` `0x3941359` if it yields anything, so its key type has no values in this build.

The tracker runs one more step on the way out: with 101 or more heights, `0x3bca430` collects pointers to the first 100 height keys and the list is freed unread, so no state changes (`hundred_heights`).

### The row, the once and the prune

The row is `0x40` bytes: height, hash, then `hot_user_to_signature`. The map comes from `0x3316090`, keyed by the hot user of each voter at the epoch of the crossing, not of the vote: a voter with no hot user at that epoch is skipped (`crossing_skips_voter_without_hot_user`). The voter that crosses always has a hot user at that epoch, since the core has just resolved it, so through this arm a row is never empty.

Between the push and the split, the core forces the once at `0x577ab98` (init `0x143ef30`, reached by `once_first_use`). No later row of the core reads a value from it.

The split removes heights below `max(vote height - 50000, 0)`, floor kept (`prune_exact_floor`, `prune_one_below`). It uses the vote height, not `highest_quorum_height`, so an old vote that crosses prunes from its own height and a newer entry stays (`prune_old_quorum_uses_own_height`). The reference prunes from the watermark. A vote with no row prunes nothing (`short_vote_prunes_nothing`).

### The take

`0x336a360` moves the list out, leaves capacity 0, pointer 8, length 0, and drops rows whose map length at row `+0x38` is 0, keeping order. The arm cannot make such a row, so the `take_seeded_` cases put one in the list by hand to run that branch. Sites through slot `0x5774d70` are in `0x2761b20`, `0x4d8fce0`, `0x4d92a10`. At `0x27644f8` the result goes to the caller's output at `+0x18`. So the list lives until the next take.

### The L1 hash tracker `0x39438e0`

`bridge-l1-hash-votes-94` stubbed this body. It takes `(out, tracker, height, hash, record, signature, context, pointer to the listed set)`. The record is a tag and 32-byte voter key at `+0`, a tag and 20-byte address at `+0x21`. The height map is at tracker `+0x28`, and the `hsc` words at `+0x18`. Heights, hash values and the done flag have the same layout as above.

The call makes up to two passes, voter key first:

- The key passes when it is in the epoch, the address when it is in the listed set. A form that fails is skipped, and with no form left no height is created (`l1_listed_absent_makes_no_height`, `l1_key_not_eligible`).
- Each pass runs the same steps as above. The key goes to the first map, the address to the second, with one signature for both.
- `0x3941070` is `stake AND ratio` (`and` at `0x39411f3`): stake over the first map, ratio `0x3bde1f0` over the second, as read in `bridge-deposit-votes-94`.

Results: with `q = 0` hot votes alone cross (`l1_hot_only_q_zero`). With `q > 0` listed votes alone never cross (`l1_listed_alone_never_crosses`), and either test may pass last (`l1_ratio_last_to_pass`, `l1_stake_last_to_pass`). If the key pass crosses in a call that also has an address, the address is stored after the clone, so the output map lacks it while the bucket has it (`l1_both_forms_one_call_hot_crosses`). The arm that drops a first result for a second one in the same call starts at `0x394434c`, behind the test at `0x3944346`. No case reaches it, because the done flag from the first crossing stops the quorum test of the second pass.

## Implementation and comparison

Not yet implemented as Rust. `tools/bridge_app_hash_votes.py` holds rule lists `Model` and `HardModel`, written from the reading above, compared with real bytes. Each case runs a series of calls from an empty tracker, built by the real inserts, and after each call compares the result; at the end it compares every height, hash, voter, signature, done flag, the row list and `highest_quorum_height`.

| metric | value |
| --- | --- |
| Cases | 318 (213 app hash, 105 L1 tracker) |
| Operations | 2639 |
| Mismatches | 0 |
| Instructions stepped | 7,324,628 |
| Stepped / total, wrapper `0x1e5f5d0` | 97 / 97 |
| Stepped / total, wrapper copy `0x46770e0` | 97 / 97 |
| Stepped / total, wrapper copy `0x4677280` | 97 / 97 |
| Stepped / total, Keccak of the signable pair `0x37e5a30` | 67 / 105 |
| Stepped / total, arm core `0x336a4e0` | 181 / 195 |
| Stepped / total, tracker `0x3946a80` | 413 / 500 |
| Stepped / total, voter key in epoch test `0x3367530` | 82 / 91 |
| Stepped / total, bucket quorum `0x3941240` | 68 / 76 |
| Stepped / total, height entry insert `0x33bf1c0` | 66 / 86 |
| Stepped / total, hash entry insert `0x33bec30` | 78 / 98 |
| Stepped / total, first 100 heights scan `0x3bca430` | 132 / 197 |
| Stepped / total, height split `0x3942b90` | 64 / 69 |
| Stepped / total, removed height list `0x3bcd010` | 63 / 98 |
| Stepped / total, block step take and filter `0x336a360` | 79 / 100 |
| Stepped / total, voteL1Hash tracker `0x39438e0` | 539 / 754 |
| Stepped / total, stake AND ratio quorum `0x3941070` | 103 / 113 |
| Stepped / total, listed vote insert `0x33a6d90` | 155 / 166 |
| Stepped / total, L1 height entry insert `0x33c1d00` | 66 / 86 |
| Stepped / total, L1 hash entry insert `0x33c1fe0` | 78 / 98 |
| Stepped / total, listed map clone `0x33e8a80` | 84 / 264 |
| Stepped / total, listed key list `0x3bb2bc0` | 89 / 126 |
| Stepped / total, ratio test, shared `0x3bde1f0` | 126 / 231 |
| Stepped / total, signer to voter key, shared `0x33690c0` | 131 / 239 |
| Stepped / total, voter key to hot user, shared `0x3369500` | 92 / 105 |
| Stepped / total, two thirds stake test, shared `0x3366b60` | 209 / 553 |
| Stepped / total, vote insert, shared `0x339b0d0` | 151 / 162 |
| Stepped / total, signature map clone, shared `0x33e79f0` | 84 / 259 |
| Stepped / total, hot row collect, shared `0x3316090` | 69 / 101 |
| Stepped / total, pair writer, shared `0x32478a0` | 69 / 143 |
| Mutants killed / survived / unreached | 646 / 225 / 155 |

Each mutant flips one conditional, immediate or field offset of a reached row in the mutated functions and reruns up to 6 cheap cases plus the fixed sentinel list that reach that row. The 225 survivors and 155 unreached rows carry a reason in `mutations.tsv`. Survivors are not hand checked row by row, and many sit in tail copies of statuses, second tree searches and the dead scan.

## Results and limitations

- No progress gate is requested.
- The digest name is an inference from the sponge words, the absorb slot is a stub, and no digest value or vector is claimed. `0x14c6f50` recovery is a stub, so the sender match is a fixture input.
- `0x3364ed0` is a stub, and its stakes are fixture inputs. Epoch and validator maps are single fixture leaves with at most 11 rows, so tree steps in `0x33690c0` and `0x3367530` are unreached.
- The first `0x18` bytes of `AppHashVoteTracker` are not read in this path, and their meaning is unknown.
- The value of the once at `0x577ab98` is not read and its purpose here is unresolved.
- The consumer of the taken list past the output at `+0x18` of `0x2761b20` is not followed.
- The L1 tracker is run directly, so its join with the core of `bridge-l1-hash-votes-94` rests on the argument rows of that core, not on a joint run.
- `q` and the listed set are fixture inputs; live values are not in the binary.

Next question: what reads the row list that `0x2761b20` returns at output `+0x18`, and does `0x4d8fce0` use it the same way?
