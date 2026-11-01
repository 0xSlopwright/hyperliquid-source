# RE-026: bn254 ecAdd (precompile 0x06) @ 0x4e96610 (node #94)

- Component ID: RE-026 (`RE-026-bn254-ecadd-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `308e5127990217a9d6196992665da6ca1afd4b82`; `references/can1357-hl` not consulted; no radare2 revision (r2 not used)
- Claim status: observation (static pins, RELA wiring, field constants, emulated vectors with the allocator stubbed)
- Scope included and excluded: `run_add` FDE, its decoder, the Istanbul/Byzantium gas wrappers and table objects included; see "What this does not claim"

Deterministic static recovery of the revm-precompile 16.0.0 bn128 `run_add`
(EVM precompile `0x06`, EIP-196 ecAdd) in the pinned node #94 `hl-node`, plus a
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
| Unicorn settings | `UC_ARCH_X86` / `UC_MODE_64`; every PT_LOAD mapped at its VA; all 78833 `R_X86_64_RELATIVE` relocations applied; FS base set to a TLS page; stack at `0x7FFF00000000`; return address -> stop page with `hlt`; bump heap at `0x70000000` |
| Allocator stub | `UC_HOOK_CODE` at jemalloc `malloc` `0x54c06b0`: `rax` = bump pointer (16-byte steps), pop return address, jump to it |
| Vectors | G+G, P+(-P), 128 zero bytes, off-curve point, x = p, gas limit 149 |
| Determinism | PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` stdout |

Declared execution / side effects: the captured binary is never run as a
whole. With unicorn present, only the hash-pinned `run_add` and its callees
are emulated in-process on fixed vectors, with `malloc` replaced by the stub
above. Without unicorn, everything is static.

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/bn254_ecadd.py --no-emu -o out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/bn254_ecadd.py -o out.json

# packet verify (emu soft-skipped when unicorn missing)
python3 -I -B research/work-items/RE-026-bn254-ecadd-94/verify.py
python3 -O -B research/work-items/RE-026-bn254-ecadd-94/verify.py

# independent (stdlib only: hashlib / pathlib / struct)
python3 -I -B research/work-items/RE-026-bn254-ecadd-94/independent_verify.py

# unit tests
python3 -B -m unittest tests.test_bn254_ecadd -v
```

Seed / optim determinism (byte-identical stdout, expected sha256
`8832409f27af72886b0f2cf4c1355e142bf29f76ac6a1faf7dc1d35684df1716`):

```bash
for s in 0 7 99; do
  PYTHONHASHSEED=$s python3 -B tools/bn254_ecadd.py --no-emu | sha256sum
done
PYTHONHASHSEED=0 python3 -O -B tools/bn254_ecadd.py --no-emu | sha256sum
```

### make verify test catalogue-check output

GNU objdump 2.44, head `42e63a5b23a7`:

```text
$ make verify test catalogue-check PYTHON=.venv/bin/python
Ran 2133 tests in 717.835s
OK (skipped=2)
...
{
  "path": "x",
  "sha256": "y",
  "provider_id": "z"
}
Catalogue and progress tables regenerated.
Catalogue and progress tables match pinned inputs.
Verified 1 imported files and all pinned source repositories.
Verified 1 imported files and all pinned source repositories.
Verified 0 imported files and all pinned source repositories.
Verified 0 imported files and all pinned source repositories.
{"call_sites": 6, "call_sites_with_exactly_one_sign_guard": 6, "constructors": 5, "guard_value_is_formatted_value": true, "lea_refs": 5, "ok_path_stores_unchanged": 4}
.venv/bin/python tools/catalogue.py --check
Catalogue and progress tables match pinned inputs.
MAKE_EXIT=0
```

LLVM objdump shim (`PATH=llvmshim:$PATH`); same 46 errors and 88 skips as origin/main 308e5127 under the same shim, 0 new, 0 gone, head `42e63a5b23a7`:

```text
$ make verify test catalogue-check PYTHON=.venv/bin/python
Ran 2025 tests in 634.724s
FAILED (errors=46, skipped=88)
...
{"all_sites_one_tied_guard": true, "call_sites": 34, "call_sites_with_exactly_one_sign_guard": 34, "caller_functions": 34, "constructors": 16, "guard_value_is_formatted_value": 34, "jns_guards": 23, "js_guards": 11, "lea_refs": 16, "mismatch_vs_message_predicate": 0, "narrow_guards": 21, "narrow_mismatch_vs_message_predicate": 0, "ok_path_stores_unchanged": 11, "unexplained_error_entries": 0}
{
  "path": "x",
  "sha256": "y",
  "provider_id": "z"
}
Catalogue and progress tables regenerated.
Catalogue and progress tables match pinned inputs.
Verified 1 imported files and all pinned source repositories.
Verified 1 imported files and all pinned source repositories.
Verified 0 imported files and all pinned source repositories.
Verified 0 imported files and all pinned source repositories.
{"call_sites": 6, "call_sites_with_exactly_one_sign_guard": 6, "constructors": 5, "guard_value_is_formatted_value": true, "lea_refs": 5, "ok_path_stores_unchanged": 4}
make: *** [Makefile:17: test] Error 1
MAKE_EXIT=2
```

## Evidence

| Pin | Value |
| --- | --- |
| Binary | `artifacts/node/94/hl-node` sha256 `3b7179cd…459f` |
| `run_add` (FDE) | `0x4e96610` .. `0x4e96cee`; `ret` at `0x4e967eb` |
| Carve | whole FDE, len 1758, sha256 `89f39d1b63955c1db57a998837ca6f826d190682a1c6ad8db722e37f707bad39` |
| Decoder | `0x4e961e0` .. `0x4e9660f`, called at `0x4e9671e` and `0x4e967a4` |
| Fq mul | `0x4f1f9c0`, via GOT `0x5776ef8` (RELA) loaded into `r12` |
| Other callees | `0x4f1b0f0`, `0x4f160c0`, `0x4f168d0` |
| GOT slot | `0x5776f00`, RELA `r_info 0x8` addend `0x4e96610` |
| References to the slot | 2 `ff 15` calls (`0x4e98a57`, `0x4e98ae7`), 0 direct `e8`/`e9` to `0x4e96610` |
| Istanbul wrapper | `0x4e98a40`: `mov ecx,0x96` (150); table object `0x574f020` RELA addend `0x4e98a40`; Address at `0x574f030` = `0x…06` |
| Byzantium wrapper | `0x4e98ad0`: `mov ecx,0x1f4` (500); table object `0x574f0e0` RELA addend `0x4e98ad0`; Address at `0x574f0f0` = `0x…06` |
| Siblings | `run_mul` `0x4e96cf0` (slot `0x5776f08`), `run_pair` `0x4e973e0` (slot `0x5776f10`) |
| Allocation | `mov edi,0x40` at `0x4e96c57`; `call *[0x576dfd8]` at `0x4e96c5c` (RELA → jemalloc `malloc` `0x54c06b0`); return `0x4e96c62`; alloc-error call at `0x4e96ce8` via `0x576dfb8` (→ `0x1346068`) |
| memcpy | GOT `0x576dfe0` is `GLOB_DAT` (type 6), called at `0x4e96686` only when input len < `0x80`; not stubbed |
| Location | `0x574f258`, lea at `0x4e989a3` / `0x4e989b0` inside the `run_pair` FDE (`0x4e973e0`..`0x4e98a3f`), not in `run_add`; path VA `0x1feb5e` len 101 sha256 `a36d5efe…874d`, suffix `revm-precompile-16.0.0/src/bn128.rs`, line 169 col 20 |

Field identity: the four 64-bit limbs of the bn254 base-field prime
`p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`
appear as `movabs` immediates in `run_add` (counts `[4,4,1,3]`). The tool
recomputes `p = 36u⁴+36u³+24u²+6u+1` with `u = 4965661367192848881`. The
128-bit Montgomery constant `-p⁻¹ mod 2¹²⁸ = 0x9ede7d651eca6ac9_87d20782e4866389`
appears `[1,1]`, R mod p appears `[2,2,2,2]`, and the decoder holds R² mod p
`[2,2,2,2]` and p `[1,1,1,1]`.

The identifier is this combination: p, the Montgomery constant, the two gas
wrappers (150/500), the slot `0x5776f00` ← `0x4e96610` with 2 `ff 15` and 0
direct calls, and the table-object addends with Address `0x06`. It is not
the path string, and not any single shared constant (p is shared with
`run_mul` and `run_pair`).

ABI: `rdi` = 40-byte result, `rsi`/`rdx` = input ptr/len, `rcx` = gas cost,
`r8` = gas limit. Ok: `[0]` Bytes vtable `0x5670ae8`, `[8]` data ptr,
`[0x10]` len `0x40`, `[0x18]` tagged ptr, `[0x20]` gas used. Err: `[0..0x10]`
zero, payload at `+0x10` (`0x8000000000000000` OutOfGas, `…06`
Bn128FieldPointNotAMember, `…07` Bn128AffineGFailedToCreate, in the upstream
`PrecompileError` order).

SIMD / feature scan: no `cpuid`, `xgetbv`, `adcx`, `adox` or `mulx` in
`run_add`, the decoder or any callee listed above. There is no feature branch.

Prior work: #550 (RE-021, Blake2b) pins the precompile table object
`0x574f0b0` (Address `0x09`, 0x30-byte stride, Address at `+0x10`). This packet
reuses that layout to read the `0x06` objects. #550 is prior work on the table
layout, not evidence for this function.

## Implementation and comparison

Independent Rust path: not yet implemented. Comparison: the emulated output of
the carved function against an affine bn254 add written in the tool (and
again in `independent_verify.py`); 2G is the well-known bn254 doubling of
(1,2). Every ok vector matches exactly. Corruption controls are the tamper tests in
`tests/test_bn254_ecadd.py` (prologue, p limb, Montgomery constant, R², wrapper
gas, wrapper call, malloc call, GOT RELA, table RELA, table Address, Location
line, injected `cpuid`, unpinned byte, input tamper, stub removed, heap moved).
Two-build comparison: not yet measured.

## Results and limitations

| Vector | Gas limit | Emulated result | Expected |
| --- | --- | --- | --- |
| G+G `(1,2)+(1,2)` | 1000 | ok, 2G `030644e7…d3`,`15ed738c…c4`; gas used 150; one 64-byte alloc from `0x4e96c62` | exact match |
| P+(-P) `(1,2)+(1,p-2)` | 1000 | ok, 64 zero bytes (infinity); gas used 150 | exact match |
| 128 zero bytes | 1000 | ok, 64 zero bytes; gas used 150 | exact match |
| off-curve `(1,3)+(1,2)` | 1000 | err `…07` Bn128AffineGFailedToCreate; no alloc | exact match |
| x = p `(p,0)+(1,2)` | 1000 | err `…06` Bn128FieldPointNotAMember; no alloc | exact match |
| G+G | 149 | err `0x8000000000000000` OutOfGas; no alloc | exact match |

No progress gate is requested.

### What this does not claim

- The proof covers `run_add` with jemalloc `malloc` (`0x54c06b0`) replaced by a bump-allocator stub. It is not a fully self-contained emulation; the allocator itself is not executed.
- Inputs shorter than `0x80` bytes take the `memcpy` path (`GLOB_DAT` `0x576dfe0`), which is not stubbed. Short inputs are not exercised; the zero control uses 128 zero bytes.
- Not all callers or forks are exercised. The emulation enters `run_add` directly with gas 150; the Istanbul and Byzantium wrappers and the rest of the precompile lookup are read statically, not executed.
- The Location (`bn128.rs` 169:20) is string+shape evidence only, and it belongs to `run_pair`, not `run_add`.
- No SIMD or CPU-feature branch exists in the recovered code, so there is no second path to cover.
- Does not assert anything about other node builds or unpinned binaries.

### Next step

Do `run_mul` (`0x4e96cf0`) and `run_pair` (`0x4e973e0`) reproduce EIP-196/197
vectors under the same allocator stub?
