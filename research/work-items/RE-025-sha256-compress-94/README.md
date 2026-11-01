# RE-025: SHA-256 compress @ 0x4ec9230 (node #94)

Review status: the submitted execution receipts below are retained historical evidence.
The maintainer review performed no captured execution. See [REVIEW.md](REVIEW.md)
for the static results, corrected harness boundaries, and pending execution gate.

- Component ID: RE-025 (`RE-025-sha256-compress-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `308e5127990217a9d6196992665da6ca1afd4b82`; `references/can1357-hl` not consulted; no radare2 revision (r2 not used)
- Claim status: observation (static pins, RELA, call edges, emulated plain-path vectors); SHA-NI branch static only
- Scope included and excluded: compress entry, inline dispatch, plain-code compress, SHA-NI branch (disassembly), GOT wiring and caller Locations included; see "What this does not claim"

Deterministic static recovery of the sha2-0.10.8 SHA-256 compress in the pinned
node #94 `hl-node`, plus a Unicorn behavioural proof of the plain-code path
against the FIPS 180-4 digests.

## Reproduce

| Item | Value |
| --- | --- |
| Platform | Linux x86_64 |
| Python | CPython 3 (system `python3` for static runs; a venv with Unicorn for the emulated run) |
| Unicorn | 2.1.4 (Python binding; optional, only for the behavioural proof) |
| ELF parser | in-tool stdlib parser (`struct`): PT_LOAD program headers for VA/file-offset mapping, section headers for `.rela.dyn` (`R_X86_64_RELATIVE`; NOBITS rejected) |
| Disassembly cross-check | GNU objdump (GNU Binutils for Debian) 2.44, used only to write this README; the tool does not call it |
| Capstone / radare2 | not used |
| Unicorn settings | `UC_ARCH_X86` / `UC_MODE_64`; every PT_LOAD mapped at its VA (`UC_PROT_ALL`, 0x1000 pages; bss zero-filled); feature byte `0x578687d` written as `0x00`; stack 0x100000 at `0x7FFF00000000`; scratch 0x10000 at `0x70000000`; return address -> stop page `0x600000000` (`hlt`); `emu_start(0x4ec9230, stop, timeout=30_000_000, count=50_000_000)` |
| Vectors | FIPS 180-4 `abc` (1 block), 448-bit two-block, empty (1 block) |
| Determinism | PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` stdout |

Declared execution / side effects: the captured binary is never run as a
whole. With unicorn present, only the carved, hash-pinned compress entry is
emulated in-process on known test vectors, with the feature byte forced to 0.
Without unicorn, everything is static.

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/sha256_compress.py --no-emu -o out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/sha256_compress.py --emulate -o out.json

# packet verify (static by default; --emulate requires authorization)
python3 -I -B research/work-items/RE-025-sha256-compress-94/verify.py
python3 -O -B research/work-items/RE-025-sha256-compress-94/verify.py

# independent (stdlib only: hashlib / pathlib / struct)
python3 -I -B research/work-items/RE-025-sha256-compress-94/independent_verify.py

# unit tests
python3 -B -m unittest tests.test_sha256_compress -v
```

Seed / optim determinism (byte-identical stdout, expected sha256
`9d931ebabf18dfaf49b329da7cb50f77d4d1303066480a01a4ca55a0942376cc`):

```bash
for s in 0 7 99; do
  PYTHONHASHSEED=$s python3 -B tools/sha256_compress.py --no-emu | sha256sum
done
PYTHONHASHSEED=0 python3 -O -B tools/sha256_compress.py --no-emu | sha256sum
```

`make verify test catalogue-check` output:

Head `f71a0486b8a7` (GNU objdump 2.44, Python 3.13):

```text
$ make verify test catalogue-check PYTHON=.venv/bin/python
Ran 2129 tests in 663.058s
OK (skipped=2)
...
Verified 0 imported files and all pinned source repositories.
Verified 0 imported files and all pinned source repositories.
{"call_sites": 6, "call_sites_with_exactly_one_sign_guard": 6, "constructors": 5, "guard_value_is_formatted_value": true, "lea_refs": 5, "ok_path_stores_unchanged": 4}
.venv/bin/python tools/catalogue.py --check
Catalogue and progress tables match pinned inputs.
MAKE_EXIT=0
```

## Evidence

| Pin | Value |
| --- | --- |
| Binary | `artifacts/node/94/hl-node` sha256 `3b7179cd…459f` |
| Compress entry (FDE) | `0x4ec9230` .. `0x4ecbecb` |
| Emulated carve | `0x4ec9230` .. `0x4ecbeca` inclusive (ret), len 11419, sha256 `937e311f6fb2fce19b5ae40389811bffebc67d1942a30be0f61fa2246f93bab9` |
| Plain-code body | `0x4ec9323` .. `0x4ecbeca` |
| Feature byte | `0x578687d` (loaded at `0x4ec924c`, stored at `0x4ec92ec` / cleared at `0x4ec9319`) |
| SHA-NI body | `0x4ecbf10` .. `0x4ecc2cc` (static only) |
| GOT slot | `0x576f7a8` (`.got`), RELA `r_info 0x8` addend `0x4ec9230` |
| Caller | FDE `0x145c1d0`..`0x145c32c`; `0x145c299` `ff 15 09 35 31 04` `call *[rip]` → `0x576f7a8` |
| Locations | `0x566bff0` (lea `0x145c312`, 62:54), `0x566c008` (lea `0x145c31f`, 62:23); path VA `0x1ee0b7` len 93 sha256 `7577f1e5…5243`, suffix `sha2-0.10.8/src/core_api.rs` |

Dispatch at the entry (objdump, AT&T):

```text
4ec924c: 0f b6 05 2a d6 8b 00    movzbl 0x8bd62a(%rip),%eax   # 578687d
4ec9253: 3c ff                   cmp    $0xff,%al
4ec9255: 74 0d                   je     4ec9264               # detection
4ec9257: 3c 01                   cmp    $0x1,%al
4ec9259: 0f 84 99 00 00 00       je     4ec92f8               # SHA-NI epilogue
4ec925f: e9 bf 00 00 00          jmp    4ec9323               # plain body
4ec926f: e8 7c 2c 00 00          call   4ecbef0               # cpuid leaf 1
4ec927c: e8 4f 2c 00 00          call   4ecbed0               # cpuid leaf 7
4ec9297: e8 84 ff ff ff          call   4ec9220               # xgetbv
4ec92ec: 40 88 2d 8a d5 8b 00    mov    %bpl,0x8bd58a(%rip)   # 578687d
4ec9314: e9 f7 2b 00 00          jmp    4ecbf10               # SHA-NI, after epilogue
```

SHA-NI branch (static only):

```text
4ecbf10: f3 0f 6f 07             movdqu (%rdi),%xmm0
4ecbf8e: 66 0f fe 05 ea 86 33 fb paddd  -0x4cc7916(%rip),%xmm0  # 204680 = K[0..3]
4ecbf9b: 41 0f 38 cb dd          sha256rnds2 %xmm0,%xmm13,%xmm3
4ecc004: 41 0f 38 cc fe          sha256msg1 %xmm14,%xmm7
```

The SHA-NI body contains 32 `sha256rnds2` (`0f 38 cb`). Its 16 rip-relative
16-byte constant loads (13 `paddd`, 3 `movdqa` into xmm9..xmm11) cover all 16
four-word K groups; one more `movdqa` at `0x4ecbf47` loads the byte-swap mask
at `0x2078c0`. The plain body contains every one of the 64 K constants as an
imm32. The tool derives K itself from the first 64 primes (FIPS 180-4 §4.2.2).

Caller path: `0x145c299` `call *[0x576f7a8]` → (RELA) `0x4ec9230` → feature
byte 0 → `jmp 0x4ec9323` plain compress → `ret 0x4ecbeca`. In the main text load
the slot has 33 rip-relative references (18 `ff 15` calls, 0 `ff 25` jumps,
15 `mov r64,[rip]`), and there are no direct `e8`/`e9` to `0x4ec9230`.

ABI: `rdi` = 32-byte state (8×u32, native LE), `rsi` = 64-byte blocks,
`rdx` = nblocks. FIPS byte order is BE per word.

Packet JSON `sha256-compress.json` sha256 `9dd7fda7ac294318790f69c971d3caaa1fef82abe09b0637897834692b0d9d27`
(`--no-emu` render `9d931ebabf18dfaf49b329da7cb50f77d4d1303066480a01a4ca55a0942376cc`); key instructions 22.

Prior listing: #154 has `0x4ec9230..0x4ecbecb` as an inventory row and merged
#23 (RE-009 `hashers.json`) lists `0x4ec9230` as a K-constant hasher. Neither is an
emulation or execution proof; this packet is the first.

## Implementation and comparison

Independent Rust path: not yet implemented. Comparison: Unicorn output of the
carved bytes (plain path) against the published FIPS 180-4 digests, pinned as
literals and cross-checked with hashlib; all three match exactly. Corruption
controls are the tamper tests in `tests/test_sha256_compress.py`. Two-build
comparison: not yet measured.

## Results and limitations

| Vector | Blocks | Emulated digest (plain path) | FIPS 180-4 |
| --- | --- | --- | --- |
| `abc` | 1 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` | match |
| 448-bit `abcdbcdecdef…nopq` | 2 | `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1` | match |
| empty | 1 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | match |

No progress gate is requested.

### What this does not claim

- Plain path emulated; the SHA-NI branch at `0x4ecbf10` is shown by static disassembly only and is not executed (Unicorn cannot run `sha256rnds2`; forcing the feature byte to 1 stops with an invalid-instruction error).
- The Location (`core_api.rs`, 62:54 / 62:23) is string+shape evidence only, not the identifier.
- The SHA-256 IV, which BLAKE3 also uses, is not used as an identifier.
- The other callers of GOT slot `0x576f7a8` (FDE `0x1471a00`..`0x1472885` and the rest of the 33 references) are counted, not all examined.
- The detection, cpuid and xgetbv paths are not emulated.
- Does not assert anything about other node builds or unpinned binaries.

### Next step

Which higher-level hasher in the `0x1471a00` group feeds which state root, and
does the SHA-NI branch give the same state on these vectors on real hardware?
