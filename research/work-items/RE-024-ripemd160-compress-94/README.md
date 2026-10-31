# RE-024: RIPEMD-160 compress @ 0x4ea55f0 (node #94)

- Component ID: RE-024 (`RE-024-ripemd160-compress-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` pinned at `999556f6e0a474b8312db96ec3149e1c44e97c23` (not consulted); no radare2 revision (r2 not used)
- Claim status: observation (static pins, RELA, call edges, emulated vectors); alternate SIMD paths and other finalize branches unexamined
- Scope included and excluded: scalar compress, finalize GOT wiring, Location pin and Location RELA/lea included; see "What this does not claim" for exclusions

Deterministic static recovery of the ripemd-0.1.3 RIPEMD-160 compress path in
the pinned node #94 `hl-node`, plus a Unicorn behavioural proof against
published RIPEMD-160 KATs.

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
| Unicorn settings | `UC_ARCH_X86` / `UC_MODE_64`; every PT_LOAD mapped at its VA (`UC_PROT_ALL`, 0x1000 pages); stack 0x100000 at `0x7FFF00000000`; scratch 0x10000 at `0x70000000`; return address -> stop page `0x600000000`; `emu_start(..., timeout=10_000_000, count=5_000_000)` |
| Vectors | RIPEMD-160 KATs empty / abc / message digest / a..z / alphanum (5) |
| Determinism | PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` stdout |

Declared execution / side effects: the captured binary is never run as a
whole. With unicorn present, only the single carved, hash-pinned function is
emulated in-process on known test vectors; nothing else is executed. Without
unicorn, everything is static.

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/ripemd160_compress.py --no-emu \
  -o out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/ripemd160_compress.py -o out.json

# packet verify (emu soft-skipped when unicorn missing)
python3 -I -B research/work-items/RE-024-ripemd160-compress-94/verify.py
python3 -O -B research/work-items/RE-024-ripemd160-compress-94/verify.py

# independent (stdlib only: hashlib / pathlib / struct)
python3 -I -B research/work-items/RE-024-ripemd160-compress-94/independent_verify.py

# unit tests
python3 -B -m unittest tests.test_ripemd160_compress -v
```

Seed / optim determinism (byte-identical stdout):

```bash
for s in 0 7 99; do
  PYTHONHASHSEED=$s python3 -B tools/ripemd160_compress.py --no-emu | sha256sum
done
PYTHONHASHSEED=0 python3 -O -B tools/ripemd160_compress.py --no-emu | sha256sum
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
| Compress | `0x4ea55f0` .. `0x4ea6c7f` (carved len 5776) |
| Finalize | `0x4ea0200` (GOT `0x5776fb0`, RELA addend = compress) |
| Finalize calls | `0x4ea043a` mov rbx,[GOT]; `0x4ea044a`/`0x4ea0486` call *rbx; `0x4ea049b` ff15 [GOT] |
| Location | VA `0x1f1474` len 89 sha256-pinned; suffix `ripemd-0.1.3/src/lib.rs` |
| Location RELA | slot `0x574f610` addend `0x1f1474`; lea @ `0x4ea0541` |

Caller path: finalize `0x4ea0200` → GOT `0x5776fb0` (RELA → compress
`0x4ea55f0`). Location string is pinned by sha256 + suffix only.

ABI: `rdi` = 20-byte state (5×u32 LE), `rsi` = one 64-byte block. Digest words
are stored LE (matching hashlib / ISO/IEC 10118-3 RIPEMD-160 byte order).

Packet JSON `ripemd160-compress.json` sha256 `6167af924de2bbdb68943119ea66c3866448fa024b20992a10cd9bdd7ecefb43`.
Carved compress sha256 `9da4dd9d6f7ad3288ba0fafbc8323f441ff24d39bef6e9deb5922fa7c5e9303c`; GOT `0x5776fb0` RELA
`r_info 0x8` addend `0x4ea55f0`; GOT mov consumers 1, ff15 consumers 1; key instructions 8.
Analysis was limited to the ranges above and completed (no timeout).

## Implementation and comparison

Independent Rust path: not yet implemented. Comparison: Unicorn output of the
carved bytes against hashlib digests (published RIPEMD-160 KATs); all match exactly. Corruption
controls are the tamper tests in `tests/test_ripemd160_compress.py`. Two-build comparison: not yet
measured.

## Results and limitations

Emulated vectors 5/5 match (empty, abc, message_digest, az, alphanum). No progress gate is requested.

### What this does not claim

- Does not claim any alternate SIMD / AVX RIPEMD path (none examined; this is
  the scalar compress carved above).
- Location evidence is string+shape only (VA / len / sha256 / suffix + RELA /
  lea); no host cargo-registry path is committed.
- Does not claim other finalize / absorb dispatcher branches beyond the GOT
  consumers shown.
- Does not reimplement RIPEMD-160 in Python beyond hashlib cross-checks; the
  behavioural proof is Unicorn on the carved binary bytes.
- Does not assert anything about other node builds or unpinned binaries.

### Next step

Which callers reach finalize `0x4ea0200`, and does any other dispatcher branch reach a non-scalar RIPEMD-160 compress?
