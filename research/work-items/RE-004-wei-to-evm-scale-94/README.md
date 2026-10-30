# RE-004: scaling a core u64 to a 256-bit EVM amount, and its gates

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6fb86319763b30860f92b9da746cbe4f9b637573 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the instructions, constants, texts and evaluated behaviour; inference
  for the direction and the meaning of the inputs; unresolved items are listed under Results and
  limitations
- Scope included: the gate and scaling blocks in 0x2715320, 0x4d0a6d0 and 0x4d0bfa0, from the 10^15
  limit test to the exit of each path, plus the U256 multiply helpers 0x27a1150 and 0x4de5500 as far as
  these blocks reach them.
- Scope excluded: everything before the limit test, the EVM transfer built after success, the callers,
  the EVM-to-core direction (a separate packet), and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/wei_to_evm_scale.py --out research/work-items/RE-004-wei-to-evm-scale-94
python3 -m unittest discover -s tests -p 'test_wei_to_evm_scale.py'
(cd research/work-items/RE-004-wei-to-evm-scale-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x271568d --stop-address=0x2715740 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 35 s.
Outputs: `evidence.json`, `exponent-table.tsv`, `boundaries.tsv`, `gates.tsv` and `block-bytes.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses.

**Copies.** The three functions are bounded by their FDEs: 0x2715320..0x2716bb7, 0x4d0a6d0..0x4d0bf96
and 0x4d0bfa0..0x4d0d866. A scan of `.text` for functions holding both a `movabs` of 10^15 and a byte
load at displacement 0xd1 finds exactly these three (`gate_function_scan` in `evidence.json`). The
displacement alone is common and says nothing, which is why the scan requires both. Each block is
located from the decoded instructions of its own copy, and `evidence.json` lists every entry, exit and
stack slot. The first copy calls 0x27a1150 and the other two call 0x4de5500.

**Behaviour.** For a token index and a u64 amount, in order:

```
token == 0 and amount > 10^15                -> tag 0x28
token is the configured native token:
    attached data present                    -> tag 0x148
    e = 10, flag = 0                         # record byte +0xbc is not read
otherwise:
    token >= table length                    -> bounds panic
    record byte +0xbc != 1                   -> tag 0x14a
    e = record i8 at +0xd1, flag = 1
e < 0: k = -e
    k >= 20, or amount % 10^k != 0           -> tag 0xba
    result = amount / 10^k
e >= 0:
    10^e overflows U256 (e >= 78)            -> tag 0xba, even for amount 0
    amount * 10^e overflows U256             -> tag 0xba
    result = amount * 10^e
```

- **Texts.** Tag 0x28 is `Withdrawal amount over single withdrawal limit.` (0x59c752), 0x148 is
  `Send to EVM with data not configured` (0x59e4bc), and 0x14a is `EVM transfer not configured`
  (0x59e4f3). Tag 0xba reaches Display arm 0x3800521 through the table at 0x59a8d0, and that arm uses
  the format pieces `Invalid number of decimals: {}` (0x1f11b6).
- **Tag 0xba payload.** The failure block converts the amount to f64 with the unsigned idiom, divides by
  table entry `[0x584b08 + 8 * record[+0x49]]`, and stores it for the shared tail. In 0x2715320 the tail
  writes `bx` to the output at +0 and the f64 to +8 (0x27163c5, 0x27163cf). The evaluated bits equal
  `float(amount) / 10.0^decimals` on every failing vector. The table's first 23 entries are exact
  powers of ten.
- **Exact division.** Both the 32-bit and the 64-bit `div` paths reach one test of the remainder
  (0x2716284 in the first copy). A remainder of 1 at e = -2 gives tag 0xba.
- **Limit.** 10^15 is a `movabs` at 0x27155ca, compared with `seta`, so the limit itself is admitted. The
  `sete` on the token register confines it to token 0. Amount 10^15 + 100 on token 1 passes.
- **U256 path.** e >= 0 builds 10^e by square-and-multiply with an overflow flag per step, then calls the
  helper once more for the product. The final squaring's overflow does not count. `boundaries.tsv` lists
  the limits: e <= 57 admits every u64, e = 58 first rejects 11579208923731619543, e = 77 admits only
  0 and 1, and e >= 78 admits nothing.
- **Flag.** `dl` is 0 for the native path and 1 otherwise, on success in both branches.
- **Dropped error value.** Before reading the exponent, each copy writes tag 0x14a to a stack slot and
  calls a local drop helper (0x277eba0 or 0x4daf4a0). The evaluator treats the call as clobbering the
  caller-saved registers, the xmm registers and the flags, and the later path never needs them.

**Evaluator.** The stack frame is filled with bytes derived from the vector number, so any dependence on
an unmodelled slot appears as a mismatch; a test shows that such a dependence does change the result. The
token and metadata fields are the only inputs, and record bytes outside the listed offsets stay unset, so
reading one stops the run. The helpers run as real instructions.

## Inferences

- This is the core-to-EVM direction, given the two `Send to EVM` and `EVM transfer` texts and the U256
  output.
- +0xd1 is `evm_extra_wei_decimals`, +0x49 is the token wei decimals, and exponent 10 is the native
  token, 18 EVM decimals over 8 core decimals.
- The separate evm decimals packet pins the field to -2..=18. Within that range the largest product is
  (2^64 - 1) * 10^18, 124 bits, so neither U256 overflow can occur, and the k >= 20 branch is not reached
  through a record that passed that guard.
- Flag `dl` selects an ERC-20 style transfer over a native value transfer. Its readers were not traced.
- The three copies are monomorphised from one source function. The identical digest shows equal
  behaviour on the grid, not a shared source.

## Implementation and comparison

Rust implementation: not yet implemented. No binary comparison was measured.

Comparison with the lead `evm_amount_to_internal_wei` in `l1/spot_meta.rs`:

| e | amount | Binary | Lead |
| --- | --- | --- | --- |
| 18 | 10^8 | 10^26 | error |
| 10 | 5 * 10^9 | 5 * 10^19 | error |
| 19 | 2 | 2 * 10^19 | error |
| -2 | 1000 | 10 | 10 |
| -2 | 1001 | error | error |
| 0 | 2^64 - 1 | 2^64 - 1 | 2^64 - 1 |

The lead's branch shape matches these blocks, including the exact-division test, but its name gives the
opposite direction, and its result is a checked u64 where the binary keeps a U256. With e = 18, any amount
of 19 or more fails in the lead and succeeds here.

The lead `TooManyDecimals` in `l1/qtys/mod.rs` is a unit variant with the text `Invalid number of
decimals`. The binary's tag 0xba carries an f64 and prints it. This resolves the constructor question
for one path. Other constructors of tag 0xba were not searched.

## Results and limitations

Metrics are in `evidence.json`.

- Copies: 3 of 3, with one identical SHA-256 over all vector results.
- Per copy: 2086 scale vectors (995 success, 1091 tag) and 288 gate vectors, 0 mismatches. All 256 i8
  exponents are covered, and exponents outside -19..=19 use four amounts each.
- Tests: 40, including mutated constants, branches, a helper carry and a frame-slot dependence.

Limits:

- The amount grid is boundary and seeded values, not all 2^64 amounts. The limits in `boundaries.tsv` rest
  on evaluated neighbours plus monotonicity.
- The evaluation enters at the limit test with a synthetic metadata struct holding only the fields read.
  How the real fields are filled, and what precedes the block, is unresolved.
- The drop helpers were not evaluated. The meaning of the attached-data slot is taken from the 0x148 text.
- Success stops at the store of the result. The EVM transaction that uses it was not read.
- 0x33062d0 also loads a byte at +0xd1 and moves it into a local with `cmovne`. It was not read further.
- The direct callers are 0x2713bf3, 0x4d06c54 and 0x4d08414, one each, and were not read.
- Node #115 is not covered. No progress gate is requested.

Next question: which other sites construct tag 0xba, and do they all carry the same f64?
