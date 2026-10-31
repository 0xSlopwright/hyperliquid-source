# RE-024: RIPEMD-160 compress @ 0x4ea55f0 (node #94)

Deterministic static recovery of the ripemd-0.1.3 RIPEMD-160 compress path in
the pinned node #94 `hl-node`, plus a Unicorn behavioural proof against
published RIPEMD-160 KATs.

## What lands

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

## Rerun

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/ripemd160_compress.py --no-emu \
  -o /tmp/out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/ripemd160_compress.py -o /tmp/out.json

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

## What this does not claim

- Does not claim any alternate SIMD / AVX RIPEMD path (none examined; this is
  the scalar compress carved above).
- Location evidence is string+shape only (VA / len / sha256 / suffix + RELA /
  lea); no host cargo-registry path is committed.
- Does not claim other finalize / absorb dispatcher branches beyond the GOT
  consumers shown.
- Does not reimplement RIPEMD-160 in Python beyond hashlib cross-checks; the
  behavioural proof is Unicorn on the carved binary bytes.
- Does not assert anything about other node builds or unpinned binaries.
- Does not open, push, or disclose; this packet is local evidence only.
