# fees: volume day tree retention, the once a day prune of every total and user tree to the last 21 dates

This packet settles how long the daily volume rows live: when the block date changes, one step cuts the total tree and every user tree of every dex and of the clearinghouse down to dates at or after `today - 20`, so a reconstruction can write the time-window side of the fee tier inputs from bytes, and the reference tree has no such step.

- Component ID: fees
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: this repository at `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` used as a lead only
- Claim status: observation for the byte behaviour below; inference where marked; no Rust implementation
- Scope included and excluded: included as whole functions are the day gate `0x26ff350` and copies `0x4ce8920`, `0x4ce8a30`, the prunes `0x36ff620`, `0x371fb70`, the row lists `0x3bc9a80`, `0x3bd4f30`, the parallel entries `0x38dcd40`, `0x38dc9e0`, the drivers `0x3403ec0`, `0x3403ac0`, the row loop `0x388de00`, the tree split `0x2fb5180`, border repair `0x2fb2440`, length count `0x2fb2a60`, tree drop `0x33f2df0`, and the date add `0x151f870` as a real helper. Excluded are the writers of the day trees (`fees-unit-conversion-94`, `fees-spot-volume-94`), the fee row rebuild `0x26ff460` and `0x2700390`, which run later in the same step and are listed by open #140, the scheduled cancel step `0x2702760`, the rayon split arm, and node #115.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first, parses the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and never runs the binary.

```
python3 tools/fees_day_prune.py --out research/work-items/fees-day-prune-94
python3 -m unittest tests.test_fees_day_prune
```

The tool wrote 12 generated files; `MANIFEST.sha256` holds their hashes. It takes about 300 s.

## Evidence

Virtual addresses in node #94; function bounds from FDEs. `path-map.tsv` lists the stages, `layout.tsv` the fields, `call-sites.tsv` every caller, `step-order.tsv` the call order in the 3 block steps, `pins.tsv` the byte pins.

### Gate

Arguments: rdi state, rsi the previous block time. `cmp [rsi], edi` tests the previous date against the state date at +0x60, and `jge` skips the rest. The compare is signed. So the body runs once for each change to a later date, and a previous date equal or later does nothing.

`mov esi, -20` then the date add slot `0x576e8b0` gives the cutoff. A date with no cutoff panics with the 34 byte text at `0x219cb3`, before any tree moves. A non-zero word in cell `0x577ab98` runs Once after the date add and before the walk.

### Walk

Each dex in list order, through slot `0x5774928`, then the clearinghouse at state +0x80, as a tail jump through slot `0x5774930`. Within each: the total tree, then every occupied row of one hash table.

| Owner | Total tree | Table | Stride | Row tree |
|---|---|---|---|---|
| dex | +0x258 | +0xf8 | 0x78 | entry +0x40 |
| clearinghouse | +0x358 | +0x298 | 0x58 | entry +0x40 |

State +0x3d8 and dex +0x258 are the total trees of `fees-daily-view-94`, and the row trees are the ones `fees-tier-select-94` sums. The rows go into a Vec of (entry, value) pointers and through a rayon driver to the row loop `0x388de00`. With 2 or more rows and a non-zero thread count the driver splits.

### One tree

1. Length 0 skips the split. An unset root with a non-zero length panics at the Location `0x56e9fa0`.
2. `0x2fb5180` allocates a new right side of the same height and walks down, moving every key >= cutoff across. The compare is a signed 32 bit `jg`, so a key equal to the cutoff moves to the right side and stays.
3. The same function repairs the 2 borders: it takes rows from a sibling itself and merges through `0x2fb2440`. After the step every non-root node of the kept tree has at least 5 rows.
4. `0x2fb2a60` walks the tree of smaller height to count it, and gives the other length as the rest.
5. `0x33f2df0` frees the old side, and the root, height and length words take the new side.

Node layout: 11 values of 16 bytes at +0, parent +0xb0, 32 bit keys +0xb8, slot +0xe4, count +0xe6, edges +0xe8; leaf 0xe8 bytes, inner 0x148 bytes.

Two facts follow from the rows above and are checked by the run:

- A row stays in its hash table when its tree empties. The table is only read here.
- A tree cut to no rows keeps a non-null root with count 0. The next day's prune sees length 0, skips the split and frees that root, leaving root 0. With root 0 the height word is not written from a defined value: the code stores a register that the split branch would have set.

`window.tsv` gives 5 real dates. The cutoff is `date - 20` over a leap day and a year boundary, and year 0 gives a negative packed key, which is why the signed compare matters. The kept span is 21 dates, today included. `fees-tier-select-94` reads dates 1 to 14 days back and `fees-daily-view-94` lists 15 dates, so both windows are inside the kept span.

### Copies

`copies.tsv`: `0x4ce8920` differs from `0x26ff350` in the list offsets only (+0x5c0 and +0x5c8 become +0x1040 and +0x1048), and `0x4ce8a30` has no differing row. `0x4ce8a30` is called by block step `0x470e9a0`, `0x4ce8920` by `0x47162d0`. Date +0x60 and the clearinghouse at +0x80 stay put in all 3.

## Implementation and comparison

No Rust implementation: not yet implemented.

The evaluator runs every function above from its decoded bytes on real B-tree nodes and real hashbrown layouts, including tombstones, empty groups and full tables. A separate specification, written with a calendar from the Gregorian rule and not from the binary tables, predicts each tree's rows in order. After a run the tool walks each tree and checks parent links, slots, counts, key order and the length word; requires the reachable node set to equal the live block set, so a leak or a double free fails; and compares every other state, dex and table byte. Freed blocks are overwritten with 0xdd. `stubs.tsv` lists the stubs. Trees with every node at the minimum of 5 keys force the steal and merge arms.

Corruption controls in the tests: wrong hash, NOBITS address, address outside every FDE, wrong pin byte, wrong step order, a wrong expected tree, a planted leak, a flipped gate branch, a window of 19 or 21 days, and shifted tree and stride bytes.

## Results and limitations

- 631 vectors, 0 mismatches: 3 panic 0x566aa98, 4 panic 0x56e9fa0, 614 pruned, 10 skipped.
- Mutants: 787 over 14 functions: 596 killed, 84 survived and 107 unreached, each with a reason in `mutations.tsv`.
- Instructions stepped: 1578 of 1912 in the 14 functions. The rest are in `unstepped.tsv` with a reason: the rayon split arm, Vec growth, unwind pads and drop walks for height 8.
- Two full generations with different hash seed and time zone were byte-identical, with no binutils on PATH.
- `reference-diff.tsv`: 4 rows. The reference has no retention step, and it names the key an ordinal where the bytes hold a chrono packed date.
- Inference: the words are volume because earlier packets name them so; this path never reads a value word. Node comparison of values shows they move intact.
- Inference: "once a day" assumes state +0x60 moves only forward with the block date. The writer of +0x60 is not read here.
- Unresolved: why one copy keeps the dex list at +0x1040, and which build path picks it.
- The rayon split arm did not run, so the claim that rows are visited once rests on the leaf path. The order of rows across threads is not observed. No value in the row loop depends on it.
- The word at cell `0x577ab98` is not named.
- Date range: the lowest year comes from 3 vectors, and the highest date was run in one.
- Progress gate: none requested.

Next question: what do the loop at `0x2229de0` and its copy words at dex +0x68, stride 0x60, hold, and which reader uses the +8, +0x28 and +0x48 words after the same day change?
