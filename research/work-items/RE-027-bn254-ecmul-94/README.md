# RE-027: bn254 ecMul (precompile 0x07) @ 0x4e96cf0 (node #94)

- Component ID: RE-027 (`RE-027-bn254-ecmul-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `308e5127990217a9d6196992665da6ca1afd4b82`; `references/can1357-hl` not consulted; no radare2 revision (r2 not used)
- Claim status: observation (static pins, RELA wiring, field constants, emulated vectors with the allocator stubbed)
- Scope included and excluded: `run_mul` FDE, its decoder / scalar-mul / to-affine callees, the Istanbul/Byzantium gas wrappers and table objects included; see "What this does not claim"

Deterministic static recovery of the revm-precompile 16.0.0 bn128 `run_mul`
(EVM precompile `0x07`, EIP-196 scalar mul) in the pinned node #94 `hl-node`, plus a
Unicorn behavioural proof of the function with jemalloc `malloc` stubbed.

## Reproduce

| Item | Value |
| --- | --- |
| Platform | Linux x86_64 |
| Python | CPython 3.13.5 (system `python3` for static runs; a venv with Unicorn for the emulated run) |
| Unicorn | 2.1.4 (Python binding; optional, only for the behavioural proof) |
| ELF parser | in-tool stdlib parser (`struct`): PT_LOAD headers for VA/file-offset mapping, `.rela.dyn` (`R_X86_64_RELATIVE` type 8, `GLOB_DAT` type 6) |
| Disassembly cross-check | GNU objdump (GNU Binutils for Debian) 2.44, used only to write this README; the tool does not call it |
| Capstone / radare2 | not used |
| Unicorn settings | `UC_ARCH_X86` / `UC_MODE_64`; every PT_LOAD mapped at its VA; all 78833 `R_X86_64_RELATIVE` relocations applied; FS base set to a TLS page; stack at `0x7FFF00000000`; return address -> stop page with `hlt`; bump heap at `0x70000000`; timeout 60s / count 50M (scalar mul is heavier than add) |
| Allocator stub | `UC_HOOK_CODE` at jemalloc `malloc` `0x54c06b0`: `rax` = bump pointer (16-byte steps), pop return address, jump to it |
| Vectors | go-ethereum EIP-196 `bn256ScalarMul.json` (chfast1/2, cdetrio1, zeroScalar) plus G×r (infinity), 96 zero bytes, off-curve, x = p, gas limit 5999 |
| Determinism | PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` stdout |

Declared execution / side effects: the captured binary is never run as a
whole. With unicorn present, only the hash-pinned `run_mul` and its callees
are emulated in-process on fixed vectors, with `malloc` replaced by the stub
above. Without unicorn, everything is static.

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/bn254_ecmul.py --no-emu -o out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/bn254_ecmul.py -o out.json

# packet verify (emu soft-skipped when unicorn missing)
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/verify.py
python3 -O -B research/work-items/RE-027-bn254-ecmul-94/verify.py

# independent (stdlib only: hashlib / pathlib / struct)
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/independent_verify.py

# unit tests
python3 -B -m unittest tests.test_bn254_ecmul -v
```

Seed / optim determinism (byte-identical stdout, expected sha256
`79149c497481d1f9daff231044ca8d2ca135af3907086a0f63393209208322f4`):

```bash
for s in 0 7 99; do
  PYTHONHASHSEED=$s python3 -B tools/bn254_ecmul.py --no-emu | sha256sum
done
PYTHONHASHSEED=0 python3 -O -B tools/bn254_ecmul.py --no-emu | sha256sum
```

### make verify test catalogue-check output

PLACEHOLDER: `make verify test catalogue-check` has not been run for this
packet yet; its output will be recorded here.

## Evidence

| Pin | Value |
| --- | --- |
| Binary | `artifacts/node/94/hl-node` sha256 `3b7179cd…459f` |
| `run_mul` (FDE) | `0x4e96cf0` .. `0x4e973d2` (exclusive); primary `ret` at `0x4e973c1` |
| Carve | whole FDE, len 1762, sha256 `fa3a57aef72db21e765e20e83db52a3c7ffb825112c2780fc3a7406406d942a5` |
| Carve extent | The primary `ret` is at `0x4e973c1`. The noreturn alloc-error tail (`mov edi,1; mov esi,0x40; call *[0x576dfb8]`) occupies `0x4e973c2`..`0x4e973d1` and is inside the FDE / carve. The `int3` padding `0x4e973d2`..`0x4e973df` is outside the FDE (next function `run_pair` starts at `0x4e973e0`). |
| Decoder | `0x4e961e0` .. `0x4e9660f`, called once at `0x4e96dda` (one point) |
| Scalar mul | `0x4f15b60` .. `0x4f15e02`, called at `0x4e96fb8` |
| To-affine | `0x4f160c0` .. `0x4f164d5`, called at `0x4e96fc8` |
| Fq/Fr mul | `0x4f1f9c0`, via GOT `0x5776ef8` (RELA); scalar-to-Fr call at `0x4e96f77`, Fq loads into `rbp` at `0x4e97075` |
| Other callees | `0x4f168d0`, `0x4f1dea0` (double), `0x4f1b0f0` (add), `0x4f200f0` (inverse) |
| GOT slot | `0x5776f08`, RELA `r_info 0x8` addend `0x4e96cf0` |
| References to the slot | 2 `ff 15` calls (`0x4e98a87`, `0x4e98b17`), 0 direct `e8`/`e9` to `0x4e96cf0` |
| Byzantium wrapper | `0x4e98a70`: `mov ecx,0x9c40` (40000); table object `0x574f110` RELA addend `0x4e98a70`; Address at `0x574f120` = `0x…07` |
| Istanbul wrapper | `0x4e98b00`: `mov ecx,0x1770` (6000); table object `0x574f050` RELA addend `0x4e98b00`; Address at `0x574f060` = `0x…07` |
| Siblings | `run_add` `0x4e96610` (slot `0x5776f00`), `run_pair` `0x4e973e0` (slot `0x5776f10`) |
| Allocation | `mov edi,0x40` at `0x4e97327`; `call *[0x576dfd8]` at `0x4e9732c` (RELA → jemalloc `malloc` `0x54c06b0`); return `0x4e97332`; alloc-error call at `0x4e973cc` via `0x576dfb8` |
| memcpy | GOT `0x576dfe0` is `GLOB_DAT` (type 6), called at `0x4e96d5c` only when input len < `0x60`; not stubbed |

Field identity: the four 64-bit limbs of the bn254 base-field prime
`p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`
appear as `movabs` immediates in `run_mul` (counts `[4,4,1,3]`). The tool
recomputes `p = 36u⁴+36u³+24u²+6u+1` and the scalar-field order
`r = 36u⁴+36u³+18u²+6u+1` with `u = 4965661367192848881`. The Fq 128-bit
Montgomery constant `-p⁻¹ mod 2¹²⁸ = 0x9ede7d651eca6ac9_87d20782e4866389`
appears `[1,1]`, the Fr constant `-r⁻¹ mod 2¹²⁸` appears `[1,1]`, R mod p
appears `[2,2,2,2]`, and R² mod r appears `[1,1,1,1]`.

The identifier is this combination: p, r, both Montgomery constants, the two
gas wrappers (40000/6000), the slot `0x5776f08` ← `0x4e96cf0` with 2 `ff 15`
and 0 direct calls, and the table-object addends with Address `0x07`. It is
not any single shared constant (p is shared with `run_add` and `run_pair`).

ABI: `rdi` = 40-byte result, `rsi`/`rdx` = input ptr/len, `rcx` = gas cost,
`r8` = gas limit. Ok: `[0]` Bytes vtable `0x5670ae8`, `[8]` data ptr,
`[0x10]` len `0x40`, `[0x18]` tagged ptr, `[0x20]` gas used. Err: `[0..0x10]`
zero, payload at `+0x10` (`0x8000000000000000` OutOfGas, `…06`
Bn128FieldPointNotAMember, `…07` Bn128AffineGFailedToCreate, in the upstream
`PrecompileError` order).

SIMD / feature scan: no `cpuid`, `xgetbv`, `adcx`, `adox` or `mulx` in
`run_mul` or any callee listed above. There is no feature branch.

Prior work: #550 (RE-021, Blake2b) pins the precompile table object
`0x574f0b0` (Address `0x09`, 0x30-byte stride, Address at `+0x10`). This packet
reuses that layout to read the `0x07` objects. #550 is prior work on the table
layout, not evidence for this function. RE-026 recovered the sibling `run_add`
under the same allocator-stub style.

## Implementation and comparison

Independent Rust path: not yet implemented. Comparison: the emulated output of
the carved function against an affine bn254 double-and-add written in the tool
(and again in `independent_verify.py`); the go-ethereum EIP-196 published
outputs are the ground truth for the four named vectors. Every ok vector
matches exactly. Corruption controls are the tamper tests in
`tests/test_bn254_ecmul.py` (prologue, p limb, Fq/Fr Montgomery constants,
R² mod r, wrapper gas, wrapper call, malloc call, scalar-mul call, GOT RELA,
table RELA, table Address, injected `cpuid`, unpinned byte, input tamper,
stub removed, heap moved, short-input fault). Two-build comparison: not yet
measured.

## Results and limitations

| Vector | Gas | Emulated result | Expected |
| --- | --- | --- | --- |
| geth chfast1 | 6000 | ok, published EIP-196 output; gas used 6000; one 64-byte alloc from `0x4e97332` | exact match |
| geth chfast2 | 6000 | ok, published EIP-196 output; gas used 6000 | exact match |
| geth cdetrio1 | 6000 | ok, published EIP-196 output; gas used 6000 | exact match |
| geth zeroScalar | 6000 | ok, 64 zero bytes; gas used 6000 | exact match |
| G×r (order) | 6000 | ok, 64 zero bytes (infinity); gas used 6000 | exact match |
| 96 zero bytes | 6000 | ok, 64 zero bytes; gas used 6000 | exact match |
| off-curve `(1,3)×2` | 6000 | err `…07` Bn128AffineGFailedToCreate; no alloc | exact match |
| x = p | 6000 | err `…06` Bn128FieldPointNotAMember; no alloc | exact match |
| G×2 | 5999 | err `0x8000000000000000` OutOfGas; no alloc | exact match |

No progress gate is requested.

### What this does not claim

- The proof covers `run_mul` with jemalloc `malloc` (`0x54c06b0`) replaced by a bump-allocator stub. It is not a fully self-contained emulation; the allocator itself is not executed.
- Inputs shorter than `0x60` bytes take the `memcpy` path (`GLOB_DAT` `0x576dfe0`), which is not stubbed. Short inputs are not exercised; the zero control uses 96 zero bytes.
- Not all callers or forks are exercised. The emulation enters `run_mul` directly with gas 6000; the Istanbul and Byzantium wrappers and the rest of the precompile lookup are read statically, not executed.
- No SIMD or CPU-feature branch exists in the recovered code, so there is no second path to cover.
- Does not assert anything about other node builds or unpinned binaries.

### Next step

Do `run_pair` (`0x4e973e0`) reproduce EIP-197 pairing-check vectors under the
same allocator stub?
