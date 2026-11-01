RE-028: modexp precompile (EVM 0x05) @ 0x136bdd0 (node #94), emulated with alloc stubs

Static recovery of the aurora-engine-modexp arithmetic (EIP-198 / EIP-2565)
in the pinned node #94 binary: the core entry at `0x136bdd0`, the Berlin and
Byzantium gas wrappers, the GOT and precompile-table wiring, plus a Unicorn
behavioural proof on published modexp vectors with exact gas against both
formulas.

Scope of emulation: Unicorn runs the Berlin wrapper `0x4e91f20` and the
Byzantium wrapper `0x4e92810`, which call the hash-pinned core FDE
(`0x136bdd0`..`0x136bf34`, carve sha256 `ee1f99ab…3252`, len 356). The primary
ret is at `0x136beaa`; the zero-modulus path starts at `0x136beab`; EH /
`_Unwind_Resume` landing pads through `0x136bf33` are inside the FDE; the
`int3` padding after the FDE is outside it. The jemalloc malloc at `0x54c06b0`
(GOT `0x576dfd8`), the jemalloc size-product allocator at `0x54c0780` (scout
name realloc; GOT `0x576e298`), and the jemalloc sized free at `0x54c8cb0`
(GOT `0x576e010`) are replaced by bump / bump / no-op stubs; memcpy
(`GLOB_DAT` `0x576dfe0`) and memset (`GLOB_DAT` `0x576e1f8`) perform real
copy/fill; alloc-error `0x1346068` and panic `0x157b810` trap. The proof
therefore covers the function with those stubs in place. It is not a fully
self-contained emulation. The captured binary is never run as a whole.
Identity is weaker than the bn254 packets, so behaviour carries it.

## Identification

- Behaviour on EIP-198 example 1 (`…0001`), a larger 64-byte modulus case, an
  even-modulus case, the zero-modulus empty output, and a wrong-base negative
  control whose output changes
- Exact gas vs independently computed EIP-2565 and EIP-198 on ≥3 inputs
  (never `>=`); mutation controls on the `0x3` / `0xc8` / `0x14` immediates
- GOT slot `0x576e530` ← RELA `0x136bdd0`; 2 `ff 15` references, 0 direct `e8`/`e9`
- Wrappers `0x4e91f20` (Berlin, min gas 200, gas imms `0x3`/`0xc8`) and
  `0x4e92810` (Byzantium, `imul`/`shr 2`/`0x14`), addends of table objects
  `0x574ee70` / `0x574f170`, both with Address `0x…05` at `+0x10`
- Crate path (aurora-engine-modexp `arith.rs`) described in words only

## Prior work

#550 (RE-021, Blake2b) pins the precompile table object layout. This packet
reads the `0x05` objects using that layout. #550 is prior work on the table,
not evidence for this function. RE-026 / RE-027 recovered the sibling bn254
add / mul precompiles under the same stub style.

## Proof

- Deterministic Python ELF tool (`tools/modexp.py`); exact pins (never `>=`)
- Unicorn PT_LOAD maps, all RELATIVE relocs, TLS, stack, stop page; three alloc
  stubs + memcpy + memset + traps
- All six vectors match exactly on both forks; gas exact; mutations break
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` output
- `verify.py` holds under `-I -B` and `-O -B`; emulation soft-skipped when unicorn is absent
- `independent_verify.py` imports only hashlib / pathlib / struct

## What this does not claim

- Allocator stubs: jemalloc malloc / size-product allocator / free are not executed
- Static identity is weak; behaviour carries the claim
- Input shapes beyond the listed vectors are not claimed
- No SIMD branch exists to cover
- No other node builds

### make verify test catalogue-check output

The make ran at HEAD `40dd6dd7`; the later commits on this branch change only README / PR-body text (no pinned value or test change, no fresh make).

GNU objdump 2.44, head `40dd6dd70804`:

```text
$ make verify test catalogue-check PYTHON=.venv/bin/python
Ran 2120 tests in 691.938s
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

LLVM objdump shim (`PATH=llvmshim:$PATH`); same 46 errors and 88 skips as origin/main 308e5127 under the same shim, 0 new, 0 gone, head `40dd6dd70804`:

```text
$ make verify test catalogue-check PYTHON=.venv/bin/python
Ran 2012 tests in 618.179s
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

<!-- run-receipt.mjs disclose: Grok-Bot -->
