RE-026: bn254 ecAdd (precompile 0x06) @ 0x4e96610 (node #94), emulated with malloc stubbed

Static recovery of the revm-precompile 16.0.0 bn128 `run_add` (EIP-196 ecAdd)
in the pinned node #94 binary: the bn254 field constants, the 150/500 gas
wrappers, the GOT and precompile-table wiring, plus a Unicorn behavioural proof
on G+G, infinity, zero input, an off-curve point, x = p and out of gas.

Scope of emulation: Unicorn runs the hash-pinned `run_add` FDE
(`0x4e96610`..`0x4e96cee`, carve sha256 `89f39d1b…ad39`, len 1758) and its
callees, entered directly with gas 150. The jemalloc `malloc` at `0x54c06b0`
(called once at `0x4e96c5c`, `mov edi,0x40`, return `0x4e96c62`) is replaced by
a bump-allocator hook. The proof therefore covers the function with the
allocator stubbed. It is not a fully self-contained emulation. The captured binary is
never run as a whole.

## Identification

- bn254 p limbs as `movabs` in `run_add` (`[4,4,1,3]`), recomputed from u; Montgomery
  constant `0x9ede7d651eca6ac9_87d20782e4866389`; R and R² in `run_add` / decoder
- GOT slot `0x5776f00` ← RELA `0x4e96610`; 2 `ff 15` references, 0 direct `e8`/`e9`
- Wrappers `0x4e98a40` (`ecx=150`, Istanbul) and `0x4e98ad0` (`ecx=500`, Byzantium), the
  addends of table objects `0x574f020` / `0x574f0e0`, both with Address `0x…06` at `+0x10`
- Not the path string; not any single shared constant

The Location `0x574f258` (`revm-precompile-16.0.0/src/bn128.rs` 169:20) is referenced
from `run_pair`, not `run_add`. It is string+shape evidence only.

## Prior work

#550 (RE-021, Blake2b) pins the precompile table object `0x574f0b0` (Address `0x09`)
and its layout. This packet reads the `0x06` objects using that layout. #550 is prior work
on the table, not evidence for this function.

## Proof

- Deterministic Python ELF tool (`tools/bn254_ecadd.py`); exact pins (never `>=`)
- Unicorn PT_LOAD maps, all RELATIVE relocs, TLS, stack, stop page; malloc bump stub
- All six vectors match exactly (2G, zeros, zeros, AffineGFailedToCreate, FieldPointNotAMember, OutOfGas)
- Tamper tests on carve, field constants, wrappers, malloc call, RELAs, table Address, Location, input, stub, heap
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` output
- `verify.py` holds under `-I -B` and `-O -B`; emulation soft-skipped when unicorn is absent
- `independent_verify.py` imports only hashlib / pathlib / struct

## What this does not claim

- Allocator stubbed: `malloc` is not executed
- Inputs shorter than 0x80 bytes (memcpy path) are not exercised
- Not all callers/forks are exercised; the gas wrappers are read statically
- The Location is string+shape only (and belongs to `run_pair`)
- No SIMD branch exists to cover
- No other node builds

<!-- run-receipt.mjs disclose: Grok-Bot -->
