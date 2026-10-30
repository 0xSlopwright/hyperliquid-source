# RE-004: the Wei cap chain around the 1.001 constant

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6fb86319763b30860f92b9da746cbe4f9b637573 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the constant, sites, tail instructions and evaluated behaviour;
  inference for the meaning of the inputs; unresolved items are listed under Results and limitations
- Scope included: the five functions that read the f64 constant 1.001, and the arithmetic tail in
  each, from the factor load to the success store.
- Scope excluded: the callees that produce the amount, the body of the overflow recorder, the
  callers of these functions, the other readers of 1.01, and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/wei_buffered_cap.py --out research/work-items/RE-004-wei-buffered-cap-94
python3 -m unittest discover -s tests -p 'test_wei_buffered_cap.py'
(cd research/work-items/RE-004-wei-buffered-cap-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x2723ee1 --stop-address=0x2724051 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 15 s.
Outputs: `evidence.json`, `sites.tsv`, `boundaries.tsv` and `tail-bytes.txt`. The analysis completed
and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. `.rodata` VA equals file offset.

**Constant.** The f64 1.001 occurs once in `.rodata`, at 0x20a6b0. Five `mulsd` instructions read it.
No RIP-relative LEA loads it, and no `movabs` carries it.

**Sites.** Each `mulsd` sits in its own FDE-bounded function (`sites.tsv`):

| mulsd | Function | Size | Loop form |
| --- | --- | --- | --- |
| 0x2723fbd | 0x2723c70 | 1075 | indexed table |
| 0x4d2a40d | 0x4d2a0c0 | 1075 | indexed table |
| 0x2724474 | 0x27240b0 | 1230 | divide by 10000 |
| 0x4d29ae4 | 0x4d29720 | 1230 | divide by 10000 |
| 0x4d29fb4 | 0x4d29bf0 | 1230 | divide by 10000 |

**Tail.** All five tails are the same 74 instructions after masking RIP displacements (replaced by
their targets), branch targets, the local drop call, and the drop-tag stack slot (+0x28 or +0x48).
The constants read are:

| VA | Value | Use |
| --- | --- | --- |
| 0x20a180 | 1e8 | factor scale |
| 0x20a528 | 1.01 | factor limit |
| 0x20a6b0 | 1.001 | buffer |
| 0x20a4b0 | +inf | clamp test |
| 0x20a510 | 2^64 | clamp bound |
| 0x20a7f0 | 2^63 | u64 lowering |
| 0x20a218 | largest double below 2^64 | saturation test |

**Evaluated behaviour.** For a u64 amount and a u32 factor:

```
fac = factor as f64 / 1e8
if !(fac <= 1.01): tag 0x13f
scaled   = clamp(amount as f64 * fac)
buffered = clamp(scaled as f64 * 1.001)
if buffered >= 2^64 - 1_000_000: call recorder, result = u64::MAX
else: result = buffered + 1_000_000
tag 0x186, value = result

clamp(x): NaN or +inf -> 0; x >= 2^64 -> u64::MAX; x <= 0 -> 0; otherwise truncate
```

The evaluator ran this at every site:

| Check | Per site | Sites | Mismatches |
| --- | --- | --- | --- |
| amount x factor grid | 1924 | 5 | 0 |
| factor window around the limit | 1001 | 5 | 0 |
| clamp blocks on 16,390 doubles | 2 blocks | 5 | 0 |

The double grid is every sign and exponent with four mantissas, plus the neighbours of 2^63 and 2^64.

**Factor bound.** `101000000 / 1e8` rounds to the same double as 1.01, and `101000001 / 1e8` is
larger. IEEE division by a positive constant is monotone, so the admitted set is exactly
0..=101000000 over all 2^32 factor values.

**No NaN or infinity is reachable.** The largest stage inputs are 0x1.028f5c28f5c29p+64 and
0x1.004189374bc6ap+64. Both are finite, and every step is monotone in the amount.

**Rounding and saturation** (`boundaries.tsv`):

| Amount | Factor | Result | Note |
| --- | --- | --- | --- |
| 0 | any admitted | 1000000 | the addend alone |
| 100000000 | 100000000 | 101099999 | one below the exact 101100000 |
| 18428315757950602239 | 100000000 | 18446744073709550144 | last value below saturation |
| 18428315757950602240 | 100000000 | u64::MAX | recorder called |
| 18245857186089704448 | 101000000 | u64::MAX | first saturating amount |

**Recorder.** The overflow path runs `xor edi,edi`, `lea rsi,[0x56dfd90]`, `call [0x5773190]`. The slot
relocates to 0x358dcd0. The Location at 0x56dfd90 is `l1/src/qtys/impl_wei.rs:6:1`.

**Loop head, read but not evaluated.**

- All five require `[rsi+0x80] == 1`, or return tag 0xfb.
- All five call 0x32814c0 per item, use the result only if its flag is set and it is below
  0x28f5c28f5c28f5c, and otherwise use the raw amount. The sum is checked with `add; jb`, tag 0x69.
- All five then call 0x333e310 with `ecx = 1`. A clear result flag gives tag 0x13f.
- The three 1230-byte forms divide the item key with `mul 0x346dc5d63886594b; shr 11`. That is exact
  division by 10000 for every u64 (`reciprocal_exact`). They bound the amount with
  `cmp rbx,0x68db8bac710cb; ja` and multiply it by 100.

**Reference comparison.** The lead `Wei::buffered_cap` (`l1/qtys/impl_wei.rs`) has the same constants.
On the amount x factor grid it matches with 0 mismatches. Differences:

- The lead takes `factor_int: u64`. All five sites load 32 bits from a slot stored from `r8d`.
- The lead tests `0.0..=MAX_FACTOR`. The binary has only the upper test; a u32 cannot be negative.
- The lead `saturating_f64_to_u64` maps +inf to u64::MAX. The binary clamp maps it to 0. Over the
  16,390 doubles, that is the only difference, and +inf is unreachable here.
- The lead uses a plain `saturating_add`. The binary calls the recorder on overflow.
- The lead reports `InvalidFactor`. The binary writes tag 0x13f, the same tag as a failed 0x333e310
  flag.

**Inferences (not proved).**

- The tail is the source `Wei::buffered_cap`, inlined into each function. The recorder Location names
  `impl_wei.rs`, and the constants match.
- The 1230-byte forms read per-dex items, since `key / 10000` indexes a table of 0x2f0-byte entries.
- Multiplying by 100 converts a 6-decimal amount to 8 decimals.
- Tag 0x186 is success. The value 390 is the `SUCCESS_STATUS` lead in `l1/asset/pdi.rs`.

## Implementation and comparison

Rust implementation: not yet implemented. No build comparison exists. The closed form above is the
behaviour a later Rust version must meet, and `boundaries.tsv` can seed its tests.

The evaluator is Python. It interprets objdump text for a small integer and scalar SSE2 subset, using
Python floats as IEEE binary64, with poisoned registers. It stops on any unmodelled mnemonic, call or
memory read. It treats the local drop call as clobbering caller-saved registers and treats the
recorder as a logged call.

## Results and limitations

Metrics: 5/5 sites, 1 tail form, 9620 grid vectors, 5005 window vectors, 163,900 clamp evaluations,
0 mismatches, 0 grid differences from the lead.

Negative controls in `tests/test_wei_buffered_cap.py` change the digest, immediates, branch sense,
constant targets and the overflow compare. Each changes the result or stops the run.

Limits:

- The grid is boundary values plus seeded random amounts, not all 2^64 amounts. The clamp check is a
  structured sample of doubles, not all 2^64 bit patterns. The factor bound is exhaustive by
  monotonicity.
- The local drop call with tag 0xb2 was not evaluated. The tail reads only `rbx` after it, which is
  callee-saved under SysV.
- What the recorder does with its arguments is unresolved.
- The loop head was matched as text. The meaning of `[rsi+0x80]`, and of the amount and factor, is
  unresolved.
- `.text` has one direct reference to these five entries: 0x1ea3c38 calls 0x27240b0. The other four
  have no direct call, jump or LEA, and indirect dispatch was not traced.
- Node #115 is not covered.

No progress gate is requested.

Next question: what state supplies the u32 factor, and which of the 36 readers of 1.01 share this
guard? The factor test here is `1.01 >= fac`, and other sites may differ.
