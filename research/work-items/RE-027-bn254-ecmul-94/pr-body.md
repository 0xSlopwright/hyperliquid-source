RE-027: bn254 ecMul (precompile 0x07) @ 0x4e96cf0 (node #94), emulated with malloc stubbed

Static recovery of the revm-precompile 16.0.0 bn128 `run_mul` (EIP-196 scalar mul)
in the pinned node #94 binary: the bn254 field and scalar-field constants, the
40000/6000 gas wrappers, the GOT and precompile-table wiring, plus a Unicorn
behavioural proof on the go-ethereum EIP-196 scalar-mul vectors, G×r (infinity),
zero input, an off-curve point, x = p and out of gas.

Scope of emulation: Unicorn runs the hash-pinned `run_mul` FDE
(`0x4e96cf0`..`0x4e973d2`, carve sha256 `fa3a57ae…42a5`, len 1762) and its
callees, entered directly with gas 6000. The primary ret is at `0x4e973c1`; the
noreturn alloc-error tail `0x4e973c2`..`0x4e973d1` is inside the carve; the
`int3` padding after the FDE is outside it. The jemalloc `malloc` at `0x54c06b0`
(called once at `0x4e9732c`, `mov edi,0x40`, return `0x4e97332`) is replaced by
a bump-allocator hook. The proof therefore covers the function with the
allocator stubbed. It is not a fully self-contained emulation. The captured binary is
never run as a whole. Inputs shorter than 96 bytes take an unresolved memcpy
path and are not exercised.

## Identification

- bn254 p limbs as `movabs` in `run_mul` (`[4,4,1,3]`), recomputed from u; Fr order r
  limbs (`[1,1,1,3]`); Fq Montgomery constant `0x9ede7d651eca6ac9_87d20782e4866389`;
  Fr Montgomery constant; R mod p and R² mod r
- GOT slot `0x5776f08` ← RELA `0x4e96cf0`; 2 `ff 15` references, 0 direct `e8`/`e9`
- Wrappers `0x4e98a70` (`ecx=40000`, Byzantium) and `0x4e98b00` (`ecx=6000`, Istanbul), the
  addends of table objects `0x574f110` / `0x574f050`, both with Address `0x…07` at `+0x10`
- Not any single shared constant

## Prior work

#550 (RE-021, Blake2b) pins the precompile table object `0x574f0b0` (Address `0x09`)
and its layout. This packet reads the `0x07` objects using that layout. #550 is prior work
on the table, not evidence for this function. RE-026 recovered the sibling `run_add`.

## Proof

- Deterministic Python ELF tool (`tools/bn254_ecmul.py`); exact pins (never `>=`)
- Unicorn PT_LOAD maps, all RELATIVE relocs, TLS, stack, stop page; malloc bump stub
- All nine vectors match exactly (four geth EIP-196, G×r, zeros, AffineGFailedToCreate, FieldPointNotAMember, OutOfGas)
- Tamper tests on carve, field constants, wrappers, malloc call, scalar-mul call, RELAs, table Address, input, stub, heap
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` output
- `verify.py` holds under `-I -B` and `-O -B`; emulation soft-skipped when unicorn is absent
- `independent_verify.py` imports only hashlib / pathlib / struct

## What this does not claim

- Allocator stubbed: `malloc` is not executed
- Inputs shorter than 0x60 bytes (memcpy path) are not exercised
- Not all callers/forks are exercised; the gas wrappers are read statically
- No SIMD branch exists to cover
- No other node builds

### make verify test catalogue-check output

PLACEHOLDER: `make verify test catalogue-check` has not been run for this
packet yet; its output will be recorded here.

<!-- run-receipt.mjs disclose: Grok-Bot -->
