# RE-023: SHA-512 soft compress @ 0x4ec4a40 (node #94)

Deterministic static recovery of the sha2-0.9.9 soft SHA-512 compress path in
the pinned node #94 `hl-node`, plus a Unicorn behavioural proof against
FIPS 180-4 digests.

## What lands

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

## Rerun

```bash
# static only (no unicorn required)
PYTHONHASHSEED=0 python3 -B tools/sha512_compress.py --no-emu \
  -o /tmp/out.json

# with Unicorn behavioural proof (optional)
python3 -B tools/sha512_compress.py -o /tmp/out.json

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

## What this does not claim

- Does not claim the AVX compress path at `0x4ec8590`.
- Does not claim ed25519 / ed25519-dalek hram/sign/verify call sites beyond the
  sha2 update/finalize wiring shown.
- Does not reimplement SHA-512 in Python beyond hashlib cross-checks; the
  behavioural proof is Unicorn on the carved binary bytes.
- Does not assert anything about other node builds or unpinned binaries.
- Does not open, push, or disclose; this packet is local evidence only.
