# RE-028: modexp precompile (EVM 0x05) @ 0x136bdd0 (node #94)

- Component ID: RE-028 (`RE-028-modexp-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `308e5127990217a9d6196992665da6ca1afd4b82`; `references/can1357-hl` not consulted; no radare2 revision (r2 not used)
- Scope included and excluded: core entry FDE, its bigint / from_be / to_be / arith callees, the Berlin and Byzantium gas wrappers and table objects included; see "What this does not claim"
- Method: own ELF parser (VA→offset via PT_LOAD) + Capstone/objdump cross-checks during recon; Unicorn 2.1.4 behavioural proof on the wrappers with three jemalloc alloc stubs + memcpy + memset + traps. Identity is weaker than the bn254 packets (no unique field modulus), so behaviour carries it.

## Rerun

```bash
# static only (no unicorn required)
python3 tools/modexp.py --no-emu | sha256sum
# expected: e7fb0730df145fa34bc18534712ec4b4b5fa1bcf8769540f4b2b6d8cfdf4eced

# full pin (needs unicorn 2.1.x)
python3 tools/modexp.py | sha256sum
# expected: 20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360

# packet verify (emu soft-skipped when unicorn missing)
python3 research/work-items/RE-028-modexp-94/verify.py
python3 research/work-items/RE-028-modexp-94/independent_verify.py

# unit tests (emu tests soft-skip without unicorn)
python3 -m unittest tests.test_modexp -v
```

Note: the committed emulated-output JSON hash `20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360` requires a unicorn-enabled Python interpreter; without unicorn the tool falls back to `emu.skipped=true` and emits a different artifact, while the `--no-emu` hash `e7fb0730df145fa34bc18534712ec4b4b5fa1bcf8769540f4b2b6d8cfdf4eced` is unaffected.

`verify.py` holds under `python3 -I -B` and `python3 -O -B`.

## Pins

| Item | Value |
| --- | --- |
| Core entry | `0x136bdd0` |
| FDE end (exclusive) | `0x136bf34` |
| Carve len / sha256 | 356 / `ee1f99abba09a6804f55da289130166de868f339c6294ea29a3e81bc7e4c3252` |
| Primary ret | `0x136beaa` (`c3`); zero-modulus path starts at `0x136beab`; EH / `_Unwind_Resume` landing pads `0x136bece`..`0x136bf33` inside the FDE; `int3` pad `0x136bf34`..`0x136bf3f` outside it |
| GOT slot | `0x576e530` RELATIVE addend `0x136bdd0` |
| ff15 refs | 2 (`0x4e92664` Berlin, `0x4e92f6d` Byzantium); 0 direct `e8`/`e9` |
| Berlin wrapper | `0x4e91f20` (FDE→`0x4e92807`, ret `0x4e92318`, min gas 200, table `0x574ee70` Address `0x05`, `+0x28=01`) → gas `0x4e93140` via GOT `0x5776ed8` (immediates `0x3`, `0xc8`) |
| Byzantium wrapper | `0x4e92810` (FDE→`0x4e93133`, ret `0x4e92bfb`, table `0x574f170` Address `0x05`, `+0x28=00`) → gas `0x4e93270` via GOT `0x5776ee0` (`imul` / `shr 2` / `0x14`) |
| Alloc stubs | jemalloc malloc `0x54c06b0` via GOT `0x576dfd8`; jemalloc size-product allocator `0x54c0780` (scout name realloc; sites pass nmemb=1) via GOT `0x576e298`; jemalloc sized free `0x54c8cb0` via GOT `0x576e010` |
| memcpy / memset | GLOB_DAT GOT `0x576dfe0` / `0x576e1f8` |
| Traps | alloc-error `0x1346068`, panic `0x157b810`, `_Unwind_Resume@plt` `0x5660110` |
| SIMD / CPUID | none in the core closure |
| Crate | aurora-engine-modexp `arith.rs` (absolute build path in `.rodata`, described in words only; never quoted in this packet) |

### Carve-extent reconciliation

The hash-pinned carve is the entry FDE only (`0x136bdd0`..`0x136bf34`). The primary ret at `0x136beaa` is the success / zero-modulus exit; bytes after it through `0x136bf33` are EH landing pads that call `_Unwind_Resume@plt` (noreturn). The twelve `int3` bytes at `0x136bf34`..`0x136bf3f` sit outside the FDE and are not part of the carve. Named callees in the contiguous arithmetic cluster `0x13686a0`..`0x136bf34` (to_be, from_be, helpers, modexp_arith) are scanned for SIMD and documented in the tool; they are not part of the pinned carve length.

## Vectors and gas (exact)

| Vector | Berlin gas (EIP-2565) | Byzantium gas (EIP-198) | Output |
| --- | --- | --- | --- |
| EIP-198 example 1 (`3^(p−1) mod p`) | 1360 | 13056 | 32-byte `…0001` |
| Large (48/40/64-byte base/exp/mod) | 6677 | 64102 | 64-byte residue (pinned) |
| Even modulus (`2^3 mod 8`) | 200 | 0 | `00` |
| Zero modulus | 200 | 0 | empty |
| Small `3^5 mod 7` | 200 | 0 | `05` |
| Wrong base `5^5 mod 7` (negative) | 200 | 0 | `03` (differs) |

Gas is recomputed independently from the EIP-2565 and EIP-198 formulas and asserted equal (never `>=`) to the binary's `gas_used` on at least the first three rows. Mutation controls flip the `0x3`, `0xc8`, and `0x14` immediates and confirm the gas expectation breaks.

## Stubs in the harness

Unicorn maps all PT_LOAD, applies every `R_X86_64_RELATIVE`, sets a stack and RET→`hlt` trampoline, then:

- malloc / size-product allocator = bump allocator
- free = no-op
- memcpy / memset = real copy / fill
- alloc-error / panic / unwind = `hlt`

The only external calls in the core closure are those three jemalloc helpers, memcpy, memset, and the trap helpers named above (soft-int helpers at PLT targets reached via GOT remain executable and are not stubbed). The proof covers the function **with those stubs in place**; it is not a fully self-contained emulation.

#550 (RE-021, Blake2b) is prior table-layout work only: it pins the precompile table object layout used here to read Address `0x05`. It is not evidence for this function.

### What this does not claim

- The proof covers the Berlin / Byzantium wrappers and the core with jemalloc malloc / size-product allocator / free replaced by bump / bump / no-op stubs, plus memcpy and memset hooked to real copy/fill. It is not a fully self-contained emulation; the allocator itself is not executed.
- Static identity is weaker than the bn254 packets (no unique field modulus). Behaviour on the published vectors + exact gas + mutation controls carries the identification.
- Short / exotic input shapes beyond the listed vectors are not claimed; the zero-modulus and even-modulus paths are exercised, but not every padding corner.
- No SIMD or CPU-feature branch exists in the recovered closure, so there is no second path to cover.
- Does not assert anything about other node builds or unpinned binaries.
- `make verify test catalogue-check` is held (not run for this packet).

### Next step

Do the remaining EVM precompiles under the same allocator-stub harness share this wrapper / table layout?
