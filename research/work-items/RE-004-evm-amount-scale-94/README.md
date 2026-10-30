# RE-004: scaling a 256-bit EVM amount to a core u64 at 0x3281770

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6fb86319763b30860f92b9da746cbe4f9b637573 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the instructions, constants, call sites and evaluated behaviour;
  inference for the direction and the meaning of the inputs; unresolved items are listed under
  Results and limitations
- Scope included: the function 0x3281770..0x328195c, the two ruint helpers it calls (0x32d6ad0,
  0x32d7e40) as far as this function reaches them, and how each of its four call sites sets the
  exponent.
- Scope excluded: what callers do after the flag test, the EVM log and calldata decoders, the
  core-to-EVM direction (a separate packet), and node #115.

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/evm_amount_scale.py --out research/work-items/RE-004-evm-amount-scale-94
python3 -m unittest discover -s tests -p 'test_evm_amount_scale.py'
(cd research/work-items/RE-004-evm-amount-scale-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x3281770 --stop-address=0x328195c artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 10 s.
Outputs: `evidence.json`, `exponent-table.tsv`, `boundaries.tsv` and `function-bytes.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses.

**Boundaries.** The FDE gives 0x3281770..0x328195c (122 instructions). The helpers are
0x32d6ad0..0x32d7e3f and 0x32d7e40..0x32d830a. The only direct branches leaving these ranges are the
two helper calls. The evaluator resolves the indirect `memcpy` and `memset` slots from `.rela.dyn`, and
it stops on any other target.

**Interface.** The exponent is `sil`, read as i8. `rdx` points to four little-endian limbs. `al & 1`
is the Option flag and `rdx` the value. `rdi` is overwritten before any read: the evaluator leaves it
unset and never trips on it. All four callers load a u64 into `rdi` first; at 0x3baf52e and 0x3baf76e
it is the record index.

**Behaviour.**

```
k = |e| as an unsigned byte        # e = -128 gives k = 128
p = 10^k by a checked u64 power    # k >= 20 returns None
e >= 0: q = amount / p             # floor; the amount buffer is overwritten with q
e <  0: q = amount * p in 256 bits # overflow returns None; the buffer is unchanged
return Some(q) if q < 0xccccccccccccccc, else None
```

- **Power.** 0x328178f..0x3281822 is a square-and-multiply ladder with the bytes for 10, 100, 10^4,
  10^8 and 10^16 as immediates. Only the last step can overflow, and it is the only `mul` with a
  `seto`. Every one of the 256 i8 values was run with the amount pointer left unset, so the table in
  `exponent-table.tsv` does not depend on the amount: exactly -19..=19 are admitted, with 10^|e|.
- **Divide.** After the call at 0x3281901 the only memory reads are the four limbs through `rbx`
  (0x3281906..0x3281911). The helper leaves `amount mod p` in the local divisor buffer, confirmed on
  4059 vectors, and nothing reads it. So the remainder is computed and dropped; there is no
  non-integral rejection on this path.
- **Multiply.** The helper returns the overflow in `al`, tested at 0x328185e. A control that removes
  the test turns amount 2^237 at e = -19 from None into Some(0), because the product wraps to exactly
  zero.
- **Cap.** 0x328191e loads 0xccccccccccccccc, compared with `setb` at 0x328192b, and the upper limbs
  must be zero. The largest possible result is 922337203685477579. The constant equals
  `(2^63 - 1) / 10` and also `(2^64 - 1) / 20`; the bytes do not say which was written.
- **Boundaries.** `boundaries.tsv` lists, for each of the 39 exponents, the largest admitted amount and
  the first rejected one, both evaluated. For e >= 0 the largest is `0xccccccccccccccc * 10^e - 1`.
- **Dead code.** Of the 122 instructions, 118 were executed. The other 4 (0x3281943..0x3281956) are the
  `Division by zero` panic with Location `ruint-1.12.3/src/div.rs:13:19`. It cannot fire, because every
  admitted divisor is a non-zero power of ten. The zero test before it is likewise never taken.

**Call sites.** A scan of `.text` finds four `e8` calls, each followed by `test al,0x1`.

| Site | Caller | Exponent source |
| --- | --- | --- |
| 0x342753a | 0x34273d0 | `mov esi,0xa`, after a 20-byte compare with 0x22 repeated (0x203c60, 0x203fc0) |
| 0x342782e | 0x34273d0 | `movzx esi,bpl`, from the byte loaded at 0x3427665 |
| 0x3baf539 | 0x3baedf0 | `movzx esi,r15b`, from record byte +0xd1 at 0x3baf4ad |
| 0x3baf779 | 0x3baedf0 | `movzx esi,bl`, from record byte +0xd1 at 0x3baf6ff |

In 0x3baedf0, both paths index records with stride 0xe8 and require byte +0xbc to equal 1
(0x3baf489, 0x3baf6e0). In 0x34273d0, the map path builds a 20-byte address before the call: either
0x22 repeated (0x342767c, 0x3427692), or 0x20 followed by zeros and the byte-swapped identifier
(0x342769a, 0x34276ad).

**Evaluator.** `Machine` interprets the objdump text of all three functions. It tracks which register
bytes, flags and RAM bytes are set, and it stops on any read of unset state, an unmodelled mnemonic, an
unknown target, a write outside RAM or a misaligned `movaps`. Only `sil`, `rdx`, `rsp` and the amount
buffer are set on entry. The helpers run as real instructions, not as models.

## Inferences

- This is the EVM-to-core direction. The system-address shapes and the U256 input point that way, and
  the bytes do not name it.
- +0xd1 is `evm_extra_wei_decimals`. The offset, the i8 use and the reference note agree. The separate
  evm decimals packet pins that field to -2..=18, which would make the None branch for k >= 20
  unreachable through those sites.
- The fixed exponent 10 at 0x342753a is the native token, 18 EVM decimals over 8 core decimals. The bytes
  show only the constant and the address compare.
- 0x22 repeated and the 0x20-prefixed form are the native and token system addresses.

## Implementation and comparison

Rust implementation: not yet implemented. No binary comparison was measured.

Comparison with the lead `evm_amount_to_internal_wei` in `l1/spot_meta.rs`, which is a u64 function:

| e | amount | Binary | Lead |
| --- | --- | --- | --- |
| 2 | 1000 | 10 | 100000 |
| 2 | 1001 | 10 | 100100 |
| -2 | 1000 | 100000 | 10 |
| -2 | 1001 | 100100 | error |
| 10 | 10^19 | 1000000000 | error |
| 0 | 2^64 - 1 | None | 2^64 - 1 |

The signs are reversed, the lead has no 256-bit input, no cap, and rejects a remainder that this path
drops. The lead's shape matches the opposite direction, covered in the core-to-EVM packet.

## Results and limitations

Metrics are in `evidence.json`.

- Exponents: 256 of 256 i8 values evaluated, 39 admitted, exhaustive for the ladder.
- Function vectors: 13091, 0 mismatches against the closed form (value and final buffer): 2368 Some,
  5732 None after the ladder, 517 U256 product overflows. Longest run 348 instructions.
- Multiply helper alone: 3660 vectors, 327 overflows, 0 mismatches. The function only exposes products
  below the cap, so a dropped carry shows up only at this level.
- Tests: 41, including mutated constants, branches and helper steps.

Limits:

- The amount grid is boundary and seeded values, not all 2^256 amounts. The boundary rows rest on the
  evaluated neighbours plus monotonicity of floor division and of multiplication by a constant.
- Helper coverage is partial: 299 of 1289 divide instructions and 192 of 328 multiply instructions ran.
  The unrun divide code handles divisors of two or more limbs, which this function never passes, since
  10^19 fits one limb. It is not a proof of the crate's general behaviour.
- 0x34273d0 has no direct call or LEA in `.text`, so its entry path is unresolved.
- What a None leads to in each caller is out of scope here.
- Meaning of the identifier in `rdi` is unresolved; it is only passed, never read.
- Node #115 is not covered. No progress gate is requested.

Next question: which decoder fills the amount buffer at 0x3baf4f7 and 0x3baf738 (slot 0x57746a0), and
does it fix the byte order of the U256?
