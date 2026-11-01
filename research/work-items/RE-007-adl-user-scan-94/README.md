# RE-007: the ADL candidate sets and the liquidatable user scan on node #94

This packet shows who ADL and liquidation look at and in what order: a reconstruction can now write which users a block step scans under each flag, why the candidate set is read highest (score, address) first, and that every (id, side) key gets a set even when no user qualifies.

- Component ID: RE-007
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bytes, arm selection, order rules and memory effects; inference for field names beyond the serializer texts; unresolved items are listed in Results and limitations
- Scope included: 23 functions listed in `evidence.json` under `functions`, run whole from the two entries `0x3707910` and `0x33c58e0`. 46 more (rayon bridges, std sort, B-tree bulk push and node inserts) run real and are listed as not claimed
- Scope excluded: the row builder `0x37d7360`, the score `0x36f5d40` (open #799) and everything under them. These are checked at their edge and stubbed

## Reproduce

```
python3 tools/adl_user_scan.py --out research/work-items/RE-007-adl-user-scan-94
python3 -m unittest tests.test_adl_user_scan
```

Python 3 standard library plus `tools/fde_extents.py` and `tools/elf_index.py`. The tool checks the input digest first and takes about 50 s. It writes `evidence.json`, `path-map.tsv`, `scan-sites.tsv`, `reference-diffs.tsv`, `samples.tsv` and `mutations.tsv`. Output is byte-identical between runs, under another hash setting and time zone, and with an empty `PATH`. The binary is never executed.

## Evidence

Addresses are virtual addresses in the file-backed sections of the target. Function bounds are exact `.eh_frame` FDE starts and ends. All numbers below come from `evidence.json`.

### Two entries

`0x3707910` builds the set of rows that are short of margin. It has 16 call sites through the data slot `0x5774990`, in `0x27078a0`, `0x27d2770`, `0x4cf37f0` and `0x4cf94a0` (`scan-sites.tsv`). `0x33c58e0` builds the candidate sets. Its only caller is the ADL core `0x36f7c40`. That core also calls the set arm of the scan directly (`0x3bc3b00`, then `0x3bc4080`).

### Which users are read

`path-map.tsv` holds the 13 stages. Both entries share one users object at dex `+0xf8`:

| Offset in dex | Offset in object | Text in the serializer | Use |
|---|---|---|---|
| `+0xf8` | `+0` | `user_to_state` | table of 0x78 byte buckets, address at bucket start, user row at `+0x18` |
| `+0x158` | `+0x60` | `users_with_positions` | B-tree set of addresses, read when the flag is clear |
| `+0x1a0` | `+0xa8` | `check_all_users_for_liquidatables` (by field order, see Inferences) | byte; not 0 reads the whole table |

The scan picks in this order: a given set, even an empty one; then argument 6 or the flag gives the whole table; then the set. Every one of the 16 call sites clears argument 6, so in this build only the flag selects the whole table. The candidate path has no given set and reads the flag alone.

An address in a set that is not in the table is skipped without a call. If the table has no users, no address is hashed.

### Row set of the scan

Rows are 0x30 bytes: tag, word 1, word 2, address at `+0x18`. The set order is address bytes, then tag, then word 1 only when both tags are not 0, then word 2 as signed. Search (`0x2fdcbd0`) and sort (`0x3383c10`) agree on this: the two cross rows of case `two cross rows differ in word 1` fold into one in both arms. So word 1 of a cross row is not part of the key.

The whole-table arm reaches the same set by another way: an (address, rows) map, flatten, sort, then equal rows dropped by the bulk build. Up to 20 rows use insertion sort, 21 or more the std sort. Each ran real here.

The two byte arguments go straight to the builder. Sites pass mode 0, 2 or 3 in the first. `scan-sites.tsv` lists mode and given set per site.

### Candidate set of one key

One 0x28 byte row per key is collected first, then inserted into the out map in list order. For each user `0x36f5d40(id, side, oracle, dex, address, row)` either refuses or gives a score. Kept rows are (score bits, address), 0x20 bytes.

The set order is the f64 total order of the score, then address bytes: bits with the sign clear map to `x | 2^63`, bits with the sign set to `!x`, compared unsigned. So -0 sits below +0, negative NaN first and positive NaN last. The ADL core takes the last key, so ADL starts at the highest score and, on a tie, the highest address.

With the flag set the rows pass through a map by address and a sort, otherwise they are inserted one at a time. Both give the same set.

Every key in the list gets a map entry. A key with no candidate has root 0. This answers the question left by the ADL core packet: the core's panic on a missing set is the same state as an empty set, not a key left out.

Side byte 2 in a collected row ends the fold, and `0x3889650` then panics on the short count.

### Inferences

- Field names beside `user_to_state` come from the serializer text order, which runs `user_to_state`, `users_with_positions`, `check_all_users_for_liquidatables`. The struct offsets of these names are read from that order and the use above, not from a serializer body.
- The scan's byte argument 6 looks like a caller-side override of the flag that this build never uses.
- Mode bytes are the enum the builder hands to `0x37d79e0`. Their meaning sits past the stub. The second byte looks like its payload: the sites read by hand do not set `cl` near the call, and the tool does not check this.
- A side is a bool, so 2 is the niche value for no row, and a real key cannot hold it.

## Implementation and comparison

Not yet implemented in the Rust tree. The comparison is between the real bytes, run in a Python evaluator built from ELF bytes, and a separate specification written from the reading. Every stub argument, call order, final set and map must match, and every heap block must be freed or be a node of the result.

| Metric | Value |
|---|---|
| Cases | 254 (rank 85, scan 169) |
| Mismatches | 0 |
| Instructions stepped | 1,969,253 |
| Stepped / total: scan host `0x3707910` | 133 / 149 |
| Stepped / total: address keys `0x3bc3b00` | 132 / 187 |
| Stepped / total: given insert loop `0x3bc4080` | 103 / 151 |
| Stepped / total: touched insert loop `0x3bc3e00` | 103 / 151 |
| Stepped / total: row insert `0x3396340` | 107 / 118 |
| Stepped / total: row search `0x2fdcbd0` | 153 / 158 |
| Stepped / total: whole collect `0x33c31f0` | 70 / 126 |
| Stepped / total: whole collect loop `0x3307a60` | 60 / 91 |
| Stepped / total: whole sort `0x3bb36e0` | 146 / 201 |
| Stepped / total: row order `0x3383c10` | 117 / 118 |
| Stepped / total: row fold by address `0x3766090` | 123 / 139 |
| Stepped / total: row fold by pair `0x37664d0` | 98 / 124 |
| Stepped / total: candidate collect `0x33c58e0` | 61 / 343 |
| Stepped / total: set of one key `0x3761320` | 115 / 126 |
| Stepped / total: score fold by address `0x3766bb0` | 137 / 165 |
| Stepped / total: score fold by pair `0x3767460` | 97 / 112 |
| Stepped / total: touched set loop `0x3bc4300` | 90 / 136 |
| Stepped / total: rank insert `0x33a3610` | 136 / 148 |
| Stepped / total: flag address map `0x33c4530` | 204 / 278 |
| Stepped / total: flag sort `0x3bb2fc0` | 134 / 202 |
| Stepped / total: rank order `0x33864b0` | 120 / 124 |
| Stepped / total: key map insert `0x33a98e0` | 122 / 144 |
| Stepped / total: key fold `0x388df00` | 68 / 88 |
| Mutants killed / survived / unreached | 235 / 56 / 97 |

## Results and limitations

- What the score is and which rows the builder emits sit in `0x36f5d40` and `0x37d7360`, stubs here. Scores and rows are given, so this packet shows how they are collected and ordered, not how they are computed.
- The pool reports 0 threads so that the bridges run their leaf arm. Rayon splitting and a result list of more than one node are not stepped. The sets are ordered, so the order of parts should not change a result, except which of two equal keys wins, which the core does not produce. That is a reading, not a run.
- The list result arm of `0x33c58e0` (`0x33c590f` to `0x33c5d87`) cannot run because `0x3889650` returns word 0 == 0 on its normal path. Reason in `mutations.tsv`.
- Unwind and allocation failure paths are not stepped.
- The mode and given set of each site are read from the bytes before the call; what the hosts do with the result is not traced.
- One mutation site in 3 is run, each over at most 4 cases, to keep a tool run short. So this is a sample and 45 of the 56 survivors are unclassified: `no case in the budget tells it apart`. They are not shown to be equivalent. 97 are unreached.

Next question: what does the score `0x36f5d40` compute once #799 settles, and which sets do the two given-set sites of `0x27078a0` pass?
