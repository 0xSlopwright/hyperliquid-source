# RE-004: mark price volatility tracker: how node #94 turns mark samples into `val.min`, `val.max` and the delay fold

This packet shows that `vty_trackers` values are square roots of decayed squared returns, capped at 1, picked by a total order on bits, so a reconstruction can write the record step, the rate choice, the sample queue and the delay fold from this table instead of the unsquared rate in the reference.

- Component ID: RE-004 (quantities and rounding), with the f64 chain that feeds the action delay
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `3981f9e4377b6302f240f13ef1f40e73dce61738` / reference `references/can1357-hl`, `l1/time.rs:342` and `l1/action_delayer.rs`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are `record_sample 0x392b930`, `select_rate 0x3930c30`, `new_tracker 0x3930ff0`, `delay_fold 0x3be4e20`, the head of the metric step `0x33750f0`, and the serde keys of the tracker. Excluded are the delay curve `0x392fab0` (pinned by #600; a hook here), the callers `0x4cdf580` family (the input is the subject of `RE-006-book-mid-sampler-94`, where the writer was a stub), and the host `0x392c200`

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/vty_tracker.py --out research/work-items/RE-004-vty-tracker-94
python3 -m unittest tests.test_vty_tracker
cd research/work-items/RE-004-vty-tracker-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and takes about 90 s on a loaded server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 568 named cases and 160 sequences of random steps run real rows from the four entries; a separately written rule list in the tool predicts every stored field. Chrono time helpers, the format call, the tree insert and the queue growth run real. Hooks: allocator, copy, the lazy cell call `0x576e8b8`, the metric step, the delay curve and the set iterator `0x33b6170`.

### Tracker record

`vty_trackers` is a B-tree at ActionDelayer `+0x70` (state `+0x3228` in the copy `0x26f8d50`, whose call passes `+0x31b8`): key u32, value 0x80 bytes, node fields key `+0x588`, parent `+0x580`, index `+0x5b4`, length `+0x5b6`, edges `+0x5b8`. Serde text `struct DeterministicVty with 7 elements`; keys from `0x39314d0` are in `field-keys.tsv`, offsets from `0x3931a60` in `field-offsets.tsv`.

| Offset | Key | Default from `0x3930ff0` |
| --- | --- | --- |
| `+0x00` | `desc`, String | text `AssetWire(<key>)`, built before the default state |
| `+0x18` | `samples`, queue of 0x18-byte rows: time, then f64 at `+0x10` | capacity 0, dangling pointer; the first push gives 4 |
| `+0x38` | `emas`, vector of 0x30-byte rows: `num`, `denom`, `decay_duration`, `n_samples`, `last_sample_time` | 4 rows, decay 30, 100, 300, 1000 |
| `+0x50`, `+0x58` | bucket width and last bucket (inference: `alert_bucket_guard`) | 600000; 52560 |
| `+0x60`, `+0x68` | `val.min`, `val.max` | 0.0001, 0.0003 |
| `+0x70`, `+0x78` | `n_updates`, `n_bucket_updates` | 0, 0 |

The default last bucket is day 365 of the Unix epoch: `0x3930ff0` makes a date from the constant `0xafaa8` and floors its milliseconds by 600000.

### Record step, `0x392b930(tracker map, key, now, mark)`

1. Map miss: format the label, build the default, insert. The insert splits a full leaf through real code.
2. If a newest sample exists and `now < newest + 1 s`: return, nothing stored. `NaiveDateTime + TimeDelta` overflow panics at the last chrono date.
3. `elapsed = seconds(now, oldest)`, truncated to whole microseconds, 0 if `now` is earlier or the signed i64 microsecond conversion overflows.
4. `elapsed <= 20`: skip to the push and keep the queue. `elapsed > 100`: pop the oldest, no update. Otherwise update, then pop the oldest. So the queue is cut by age, not by capacity; a full young queue doubles.
5. Update: `m = mark / (old + 1e-20) - 1`, `v = m * m / elapsed`; `v > 1` becomes 1, except that infinity stays. NaN passes through.
6. Each row: `gap` is 1.0 with no last time, else seconds since it, 0 for a future time or a signed i64 microsecond conversion overflow. If `gap > decay` the row resets: `num = denom = 0`, `decay = max(10, decay)`, `n_samples = 0`, date word 0, seconds and fraction left as they were, and this sample is not added. Otherwise `keep = 1 - 1/decay`, `num = v*gap + keep*num`, `denom = gap + keep*denom`, `n_samples` saturating +1, last time = now. `gap == decay` updates.
7. `n_updates` and `n_bucket_updates` rise, saturating. If `n_updates > 20`, `select_rate` mode 0 stores `val.min` and mode 1 stores `val.max`; a row set with no valid row keeps the old value.
8. Push `(now, mark)`. `bucket = max(0, unix ms) / width`. If `bucket > last`, store it. The metric call `0x33750f0` gets the name `deterministic_vty_alert_n_bucket_samples`, bounds 0.01 and 0.05, and the flag. Real rows at its head clear `n_bucket_updates` when the flag byte is 1 and leave it otherwise (`logger-head.tsv`). The record step returns nothing.

### Rate choice, `0x3930c30(rows, n, mode)`

A row counts if not `decay > n_samples as f64`, not `1e-15 > denom`. `num` strictly between -1e-15 and 0 snaps to 0; `num` at -1e-15 or lower is dropped; NaN stays. Rate is `num / denom`. The pick compares keys: `bits | sign` for a value with a clear sign bit, `!bits` otherwise, unsigned. Mode 1 keeps the larger key, mode 0 the smaller. So a positive NaN sits above infinity. The result is `sqrt(rate)`, returned as it is if not finite, else `min(1, root)`. No valid row gives no value. `select-edges.tsv` lists 234 cases with result bits.

### Delay fold, `0x3be4e20(iterator, start)`

For each key of a set: tracker hit gives `curve(mode byte, key, val.max)` through slot `0x5776220`; a miss or an empty map gives 0.001 with no curve call. Keeps the largest value, `v >= best` replaces. An unordered compare goes to the `0x576e470` panic. The set is drained before return.

### Differences from the reference lead

`reference-diff.tsv` lists each one with the case that shows it. The main ones: `l1/time.rs` has no square root and no cap in `valid_rate`, snaps at `>= -1e-15`, uses f64 min and max, pops by capacity, starts the queue at 8, returns a bool and never clears the second counter.

Read by eye, not evaluated: host `0x392c200` handles the first key inline, calls the fold for the rest, takes `maxsd` with an earlier value, panics on a negative result, multiplies by f64 `+0x88` of the delayer (reference `delay_scale`).

## Implementation and comparison

not yet implemented. There is no Rust code in this packet. The rule list in `tools/vty_tracker.py` is a Python comparison model against real instructions.

## Results and limitations

- 568 named cases and 160 step sequences match. 63 tests pass. Two runs are byte identical, also with another hash seed, zone and a PATH with no binutils.
- 365 byte edits of reached conditions, immediates and field displacements in the four functions: 344 killed, 21 survived, all classified:

- 5: year at or below zero, the negative value ends at the clamp to zero
- 3: text length passed for a log line that is built and freed unread
- 2: fixed date constant, the calendar arithmetic has one input
- 2: range check of the seconds carry, a one second step cannot reach the bound
- 1: dangling pointer of an empty queue, never read
- 1: dangling pointer of an empty queue, the next store covers the moved word and the field is never read
- 1: fixed date constant, the floor by 600000 hides the low bit
- 1: low bit of the finite bound, a root never reaches the top of the double range
- 1: low bit of the finite mask, a root never reaches the top of the double range
- 1: low multiplier bit of a floor by 100, the floor is the same on every reached year
- 1: sign fix of a floor by 86400 on a value that is never negative
- 1: sign fix on a year whose negative side ends at the clamp to zero
- 1: word read only by the unwind path of the new tracker

- 4239 bytes, 939 instructions. 43 rows stay unreached: panic and unwind rows, and allocation failure rows of `0x3930ff0`.
- A row of the `rsp` frame is never edited, and constants in `.rodata` are held by `constants.tsv` plus three edited image tests.
- Rule text is checked on the cases run, not proved for all f64 inputs. The bit keys and all edges in `select-edges.tsv` are exact.
- Unresolved: what fills the key set of the fold; whether the label is read outside logs; who else reads `val.min`. `+0x50`, `+0x58` as `alert_bucket_guard` is inference from the metric call arguments. The cell behind the `0x577ab98` state is not read by these rows; the hook only records the call.

## Review correction: scalar division and elapsed-time overflow

The original submission is retained byte for byte in `original-submission/`,
including its source, tests and manifest; `source-binding.json` binds that archive
to PR #1141 head `b1525738ce8cbae4f7288ed938f6b2c9ab19b466`.
The original 63-test run on macOS arm64 / Python 3.14.6 failed two stored-output
checks. Its full generation completed but produced different signed NaN bits in
selector outputs; all 13 raw files remain in `original-host-regeneration/`, with
original-versus-host hashes in `review-original-host-regeneration.json`.
These are host evaluator results, not observations of captured node execution.

The decoder's `DIVSD` transfer and the separate scalar rule now explicitly model
masked x86 invalid division, instead of relying on the host's `inf / inf` NaN
sign. Actual `DIVSD xmm0,xmm6` at `0x3930cf2` is tested with literal result bits:
invalid `0/0` and `inf/inf` produce `0xfff8000000000000`; NaN inputs retain sign
and payload while signaling inputs are quieted; the first NaN source wins.
Signed zero and infinity controls also preserve the upper destination lane.
These rules use Intel SDM volume 1, Tables 4-7 and 11-1 and section 4.9.1.3
([December 2024 edition](https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf)).
The comparison assumes masked exceptions, round-to-nearest and DAZ/FTZ off;
it does not establish the node's runtime MXCSR or cover every floating-point
operation/input. The selector still compares exact bits; no NaN normalization
was added to make these checks pass.

A separate stale-OF defect affected `IMUL` at `0x1447181` followed by `JO` at
`0x144718c`; the intervening `XORPD` does not change integer flags. Two- and
three-operand IMUL now set CF/OF from the signed product at the decoded width.
The independently written elapsed rule now also returns zero when converting
a positive duration to signed i64 microseconds would overflow. The target helper
has both an IMUL/JO check and an ADD/SETO check. The original counterexample uses
valid chrono dates across approximately 500,000 years: stale OF allowed a wrapped
negative elapsed value to change stored EMA fields. Exact original and corrected
IMUL-only results, including raw bytes, remain in
`review-original-counterexamples.json`.

Five added tests cover those decoded native transfers, all signed IMUL widths,
NaN total-order selection, and the largest accepted microsecond value plus both
multiply and add overflow through the complete record path. Original generated
exports remain untouched; `review-regeneration.json` records their comparison
with a fresh corrected generation. No captured target instruction or process was
executed, and no whole-node or unrestricted f64 equivalence is claimed.
