# RE-004: the spot token wei scale 10^(weiDecimals - szDecimals) and its conversion helpers

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6fb86319763b30860f92b9da746cbe4f9b637573 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the Location, the holders, the panic target and the
  evaluated instruction behaviour; inference for the helper names and argument meanings;
  unresolved items are listed under Results and limitations
- Scope included: every function that loads the Rust Location `l1/src/spot_meta.rs:1199:57`
  (15 functions), their exponent ladders, and closed forms for 12 small helpers among them.
- Scope excluded: 7 other ladder copies with other exponents (listed below), the callers of
  the helpers, the 128-bit divide body, and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/spot_wei_scale.py --out research/work-items/RE-004-spot-wei-scale-family-94
python3 -m unittest discover -s tests -p 'test_spot_wei_scale.py'
(cd research/work-items/RE-004-spot-wei-scale-family-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x3760790 --stop-address=0x376081c artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 20 s.
Outputs: `evidence.json`, `holders.tsv`, `helpers.tsv`, `pow10-exponents.tsv` and
`helper-bytes.txt`. The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. `.rodata` VA equals file offset; `.data.rel.ro` VA is
file offset + 0x2000.

**Anchor.** `.rela.dyn` gives two Rust `Location` records in `.data.rel.ro` that point at
`l1/src/spot_meta.rs`:

| Record | VA | Line:col | Role |
| --- | --- | --- | --- |
| scale | 0x56f2270 | 1199:57 | exponent unwrap |
| token | 0x56f21f0 | 113:33 | token index unwrap |

**Holders.** `.text` has exactly 15 RIP-relative LEAs of 0x56f2270, in 15 FDE-bounded functions
(`holders.tsv`). Each LEA is followed by `call [0x576e470]`. That GOT slot relocates to 0x157a9f0,
which loads the 43-byte message ``called `Option::unwrap()` on a `None` value``.

**Ladder.** One shape appears in all 15 functions. Example from 0x3760790 (140 bytes):

```
movzx edx, byte [rdi+0x19]
sub   dl, byte [rdi+0x18]
jb    panic
mov   eax, 1
jne   ladder
ret
ladder: bit 0 -> 10; bit 1 -> *100; bit 2 -> *10^4; bit 3 -> *10^8;
        bit 4 -> mul 10^16 with jo -> panic
        each step exits early when no higher exponent bits remain
```

The other 14 read `[record+0x49]` and `[record+0x48]`. In the leaf helpers the record is reached
by `imul idx,0xe8` on a table at `[meta+0x180]` with length `[meta+0x188]`; 0x3263760 uses
`+0x190/+0x198` for the same pair of fields.

**Exponent result.** The evaluator ran each ladder on all 256 exponents and all 255 borrow
cases, plus all 65536 byte pairs for 0x3760790:

| Input | Result |
| --- | --- |
| wei < sz | panic at 1199:57 |
| k = wei - sz, 0..=19 | 10^k |
| k >= 20 | panic at 1199:57 |

All 15 ladders produce one identical 256-row table (`pow10-exponents.tsv`), with 0 mismatches.

**Helpers.** Twelve small holders were evaluated against closed forms (`helpers.tsv`): 112,400
vectors, 0 mismatches. `k` is the exponent above; `flag` is a boolean argument.

| Entry | Evaluator name | Closed form |
| --- | --- | --- |
| 0x3760790 | spec_scale | 10^k from a TokenSpec pointer |
| 0x37606b0 | sz_to_wei_checked | (ok, a * 10^k), checked in 64 bits |
| 0x32813d0 | wei_to_sz_floor | floor(a / 10^k) |
| 0x32814c0 | mul_div_token | d = 1 if token == 0, else 10^k. If a*b fits u64: floor(a*b/d). Otherwise checked floor(a/d)*b |
| 0x333e310 | ratio_round | floor or ceil (flag) of a*10^k/b in u128; ok if it fits u64 |
| 0x3594ec0 | ratio_ceil | ceil(a*10^k/b) in u128, or 0 if it does not fit |
| 0x32815f0 | ntl_ratio_capped | floor or ceil (flag) of a*b/(100*10^k); ok if q < 0x28f5c28f5c28f5c |
| 0x3281190 | mul_div_reorder | d = 10^k of the pair quote token. a*b fits: floor(a*b/d). Else a%d==0: (a/d)*b; b%d==0: (b/d)*a; otherwise (max/d)*min. 0 if that overflows |
| 0x327f900 | max_sz_for_px | min(floor(10^18/b), floor(a/10^k)) with the pair base token |
| 0x375e300 | side_amount | flag: (quote token, checked a*b); otherwise (base token, checked b*10^k) |
| 0x3c09830 | mul_div_floor_one | b == 0: 0. a*10^k fits: q = floor(a*10^k/b). Else q = checked floor(a/b)*10^k, or 0. q == 0 becomes 1 |
| 0x327f720 | order_notional | q = min(floor(10^18/b), floor(a/10^k)); n = b*q; error store if n overflows or n > i64::MAX-1 |

Seven helpers take a token index. Index 4 on the 4-entry test table panics at 113:33 in all seven.
The ladders in 0x3263760, 0x371b950 and 0x37568b0 are inlined into larger functions, so only
their ladders were evaluated.

**Other ladders.** A byte signature (imul 10^8, with 10^4 before and 10^16 after) finds 22 sites in
22 functions: these 15 and 7 others (0x2715320, 0x3281770, 0x3750350, 0x375fb50, 0x4d0a6d0,
0x4d0bfa0, 0x4ead680). The 7 do not load 0x56f2270. For example, 0x375fb50 uses
`token[0].wei - token[t].sz` and 0x3281770 uses the absolute value of a signed byte.

**Reference comparison.** The lead `Ntl::from_px_wei_floor` (`l1/qtys/impl_ntl.rs`) is a u128
product, floored, and None above u64::MAX. On the non-zero-exponent grid of 7,777 vectors:

| Outcome against the lead | Vectors |
| --- | --- |
| same | 5955 |
| binary below the lead | 1810 |
| binary Some, lead None | 12 |
| binary None, lead Some | 0 |
| binary above the lead | 0 |

| k | a | b | binary | lead |
| --- | --- | --- | --- | --- |
| 3 | 1000000000000999 | 100000 | 100000000000000000 | 100000000000099900 |
| 2 | 9223372036854775807 | 3 | 276701161105643274 | 276701161105643274 |
| 1 | 2 | 9223372036854775808 | 0 | 1844674407370955161 |

Other lead differences:

- `TokenSpec::unit_scale` uses `.expect` with a custom message. The binary message is the plain
  `Option::unwrap()` text.
- `pow10_u64` is a linear loop. The binary uses bit steps with the same values on 0..=19.
- `scaled_wei_mul_fits_u64` returns bool. 0x37606b0 returns the flag in rax and the product in rdx.

**Inferences (not proved).**

- +0x18 and +0x19 are szDecimals and weiDecimals. The same offsets are read by the spot-deploy
  guards in the RE-004-spot-token-decimals-94 packet. The table record embeds the same spec at
  +0x30, so +0x48/+0x49 are the same two fields.
- The source is one expression that unwraps a `checked_sub` and `checked_pow` result, since borrow,
  overflow and high exponents all reach one Location.
- `b` in several helpers is a price, and `[meta+0x168]` is the spot pair table (32-byte entries:
  base token, quote token).
- 0x32814c0 is the binary counterpart of the `from_px_wei_floor` lead. The match is by shape only.

## Implementation and comparison

Rust implementation: not yet implemented. No build comparison exists. The helper table is the
behaviour a later Rust version must meet; the vectors can seed its tests.

The evaluator is Python. It interprets objdump text for a small integer instruction set, with
poisoned registers, and it stops on any unmodelled mnemonic, call, memory read or divide by zero.
`call [0x576e1a8]` is modelled as an unsigned 128-bit divide. That slot relocates to 0x565f5a0.

## Results and limitations

Metrics: 15/15 holders, 15/15 ladders, 256 + 255 cases each, 65536/65536 pairs on one helper,
12 helpers, 112,400 vectors, 0 mismatches, 7/7 token bounds.

Negative controls in `tests/test_spot_wei_scale.py` change the input digest, instruction constants,
branch senses and clamp direction. Each changes the result or stops the run.

Limits:

- The helper vectors are a boundary grid plus seeded random pairs, not the full 128-bit input
  space. The ladder result is exhaustive over its byte inputs.
- 0x565f5a0 was not evaluated. Treating it as a 128-bit divide is an inference from its call shape
  and the surrounding remainder arithmetic.
- `ratio_round`, `ratio_ceil`, `max_sz_for_px` and `order_notional` were evaluated for b >= 1 only.
- 0x3c09830 has a branch on `[0x577ab98]` before returning 1. Only the zero state was evaluated;
  the purpose of that state is unresolved.
- `order_notional` stops at the branch to its error or success store. The record it fills was not
  modelled.
- Whether a validated token can reach k >= 11 was not shown. The deploy guard packet bounds
  `sz <= wei <= 10` at its own sites only.
- Indirect references to the Location are not searched. Node #115 is not covered.

No progress gate is requested.

Next question: which callers feed `mul_div_token` and `mul_div_reorder`, and in what units is `b`?
That decides how often the reordered floor differs from the exact floor in real state.
