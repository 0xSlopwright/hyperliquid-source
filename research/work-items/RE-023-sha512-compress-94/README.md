# RE-023: SHA-512 soft compress @ 0x4ec4a40 (node #94)

- Component ID: RE-023 (`RE-023-sha512-compress-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` pinned at `999556f6e0a474b8312db96ec3149e1c44e97c23` (not consulted); no radare2 revision (r2 not used)
- Claim status: observation (static pins, RELA, call edges, emulated vectors); AVX path and ed25519 call sites unresolved
- Scope included and excluded: soft compress, dispatcher soft branch, update/finalize wiring and Location pin included; see "What this does not claim" for exclusions

Deterministic static recovery of the sha2-0.9.9 soft SHA-512 compress path in
the pinned node #94 `hl-node`, plus a Unicorn behavioural proof against
FIPS 180-4 digests.

## Reproduce

| Item | Value |
| --- | --- |
| Platform | Linux x86_64 |
| Python | CPython 3.13.5 (venv used for the emulated run; same version as system `python3`) |
| Unicorn | 2.1.4 (Python binding; optional, only for the behavioural proof) |
| ELF parser | in-tool stdlib parser (`struct`): PT_LOAD program headers for VA/file-offset mapping, section headers for `.rela.dyn` (`R_X86_64_RELATIVE`) |
| Disassembly cross-check | GNU objdump (GNU Binutils for Debian) 2.44 |
| Capstone | not used (not installed) |
| radare2 | not used (not installed) |
| Unicorn settings | `UC_ARCH_X86` / `UC_MODE_64`; every PT_LOAD mapped at its VA (`UC_PROT_ALL`, 0x1000 pages); stack 0x100000 at `0x7FFF00000000`; scratch 0x10000 at `0x70000000`; return address -> stop page `0x600000000`; `emu_start(..., timeout=30_000_000, count=50_000_000)` |
| Vectors | FIPS 180-4 empty / abc / two-block (3) |
| Determinism | PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` stdout |

Declared execution / side effects: the captured binary is never run as a
whole. With unicorn present, only the single carved, hash-pinned function is
emulated in-process on known test vectors; nothing else is executed. Without
unicorn, everything is static.

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/sha512_compress.py --no-emu \
  -o out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/sha512_compress.py -o out.json

# packet verify (emu soft-skipped when unicorn missing)
python3 -I -B research/work-items/RE-023-sha512-compress-94/verify.py
python3 -O -B research/work-items/RE-023-sha512-compress-94/verify.py

# independent (stdlib only: hashlib / pathlib / struct)
python3 -I -B research/work-items/RE-023-sha512-compress-94/independent_verify.py

# unit tests
python3 -B -m unittest tests.test_sha512_compress -v
```

Seed / optim determinism (byte-identical stdout):

```bash
for s in 0 7 99; do
  PYTHONHASHSEED=$s python3 -B tools/sha512_compress.py --no-emu | sha256sum
done
PYTHONHASHSEED=0 python3 -O -B tools/sha512_compress.py --no-emu | sha256sum
```

### `make verify test catalogue-check` output

<!-- PLACEHOLDER: paste the verbatim `make verify test catalogue-check` output and the HEAD label it ran on. Not run yet; do not fill by hand. -->

```text
HEAD: <pending>
<pending: make verify test catalogue-check not yet run>
```

## Evidence

| Pin | Value |
| --- | --- |
| Binary | `artifacts/node/94/hl-node` sha256 `3b7179cd…459f` |
| Soft compress | `0x4ec4a40` .. `0x4ec857a` (carved len 15163) |
| Dispatcher | `0x4ec9170` (flag `0x578687c`; soft `e9` @ `0x4ec9183`) |
| Update | `0x4ec4900` (GOT `0x57708d0`, RELA addend) |
| Finalize | `0x4ec47d0` |
| Caller | `0x158f8d1` `mov rbx,[GOT]`; `0x158f8e5` `call *rbx` |
| Location | VA `0x1fd941` len 90 sha256-pinned; suffix `sha2-0.9.9/src/sha512.rs` |

Caller path: `0x158f8d1` → update `0x4ec4900` → `e8` dispatcher `0x4ec9170` →
`e9` soft compress `0x4ec4a40`. Finalize also `e8`-calls the dispatcher.

ABI: `rdi` = 64-byte state (8×u64 LE), `rsi` = blocks, `rdx` = nblocks
(`rdx==0` no-op). Digest words are stored LE; FIPS byte order is BE per word.

Packet JSON `sha512-compress.json` sha256 `8cb0c2e8bb4b4da347cf14b3142fcee8a2458275d9adc85550bf780da745e5e4`.
Carved compress sha256 `88b5bbdb2171f51f7102d46e8411c4a7c6099e62f2bf0ee3e7339da7f54ce57c`; GOT `0x57708d0` RELA
`r_info 0x8` addend `0x4ec4900`; GOT mov consumers 1; key instructions 15.
Analysis was limited to the ranges above and completed (no timeout).

## Implementation and comparison

Independent Rust path: not yet implemented. Comparison: Unicorn output of the
carved bytes against hashlib digests (FIPS 180-4 empty / abc / two-block); all match exactly. Corruption
controls are the tamper tests in `tests/test_sha512_compress.py`. Two-build comparison: not yet
measured.

## Results and limitations

Emulated vectors 3/3 match (empty, abc, two_block). No progress gate is requested.

### What this does not claim

- Does not claim the AVX compress path at `0x4ec8590`.
- Does not claim ed25519 / ed25519-dalek hram/sign/verify call sites beyond the
  sha2 update/finalize wiring shown.
- Does not reimplement SHA-512 in Python beyond hashlib cross-checks; the
  behavioural proof is Unicorn on the carved binary bytes.
- Does not assert anything about other node builds or unpinned binaries.

### Next step

Which ed25519 hram/sign/verify call sites reach update `0x4ec4900`, and does the AVX branch at `0x4ec8590` produce the same state on these vectors?
