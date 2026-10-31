RE-024: RIPEMD-160 compress @ 0x4ea55f0 (node #94)

Static recovery of the ripemd-0.1.3 RIPEMD-160 compress in the pinned node #94
binary, wired through finalize into GOT slot 0x5776fb0 (RELA addend = compress),
with a Unicorn behavioural proof against published RIPEMD-160 KATs
(empty / abc / message digest / a..z / alphanum).

r2 note: first submission for this VA; Location pinned by sha256+suffix only.

Pins

- Binary: `artifacts/node/94/hl-node` sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Compress: `0x4ea55f0`..`0x4ea6c7f` (carved sha256 `9da4dd9d…303c`, len 5776)
- Finalize `0x4ea0200`: `0x4ea043a` mov rbx,[GOT `0x5776fb0`] / `0x4ea044a`+`0x4ea0486` call *rbx / `0x4ea049b` ff15 [GOT]
- RELA: slot `0x5776fb0` `R_X86_64_RELATIVE` addend `0x4ea55f0`
- Location: VA `0x1f1474` len 89 sha256 `36b68195…9d35`; suffix `ripemd-0.1.3/src/lib.rs` only
- Location RELA slot `0x574f610` addend `0x1f1474`; lea @ `0x4ea0541`

Proof

- Deterministic Python ELF tool (`tools/ripemd160_compress.py`); exact pins (never `>=`)
- Unicorn contiguous PT_LOAD maps + RET trampoline; state/block LE
- Negative controls + mutation/tamper tests (carve / state / block); PYTHONHASHSEED 0/7/99 and `-O` byte-identical
- `verify.py` holds under `-I -B` and `-O -B` (emu soft-skipped without unicorn)
- `independent_verify.py` imports only hashlib / pathlib / struct

What this does not claim

Scalar compress only (no alternate SIMD dispatcher examined), Location
string+shape evidence only, other finalize branches not examined, other node
builds, or any runtime forge.

<!-- run-receipt.mjs disclose: Grok-Bot -->
