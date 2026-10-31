# RE-021-blake2b-compress-94

Standalone packet. `tools/blake2b_compress.py` builds `blake2b-compress.json` from node #94 bytes (Python standard library + optional `unicorn` for behavioural proof; no objdump/pyelftools).

Finding (bytes + emulation): `0x4e9a8a0` is the BLAKE2b compression function F used by revm-precompile 16.0.0 (`src/blake2.rs` Location pin). ABI `(rounds, h, m, t, f)` = `(rdi, rsi, rdx, rcx, r8)`. All eight IV `movabs` immediates, the final-block `~IV[6]` `cmovne`, the rounds==0 early path, the SIGMA u64 table at `0x7c4a90`, and G-function rotates `rol 0x20/0x28/0x30/1` (eight of each) are pinned. Behavioural proof runs the **carved function bytes** under Unicorn on official EIP-152 vectors (vector 4 rounds=0, vector 5 rounds=12, plus vectors 6 and 7); outputs are byte-identical to the EIP.

HyperEVM precompile address `0x09` dispatch, the 213-byte length check, the `f ∈ {0,1}` reject in `run()`, and gas-per-round are **not** statically shown here — see "What this does not claim".

## Rerun

```
python3 -m venv .venv && .venv/bin/pip install unicorn
.venv/bin/python -I -B research/work-items/RE-021-blake2b-compress-94/verify.py
.venv/bin/python -O -B research/work-items/RE-021-blake2b-compress-94/verify.py
.venv/bin/python -I -B research/work-items/RE-021-blake2b-compress-94/independent_verify.py
.venv/bin/python -O -B research/work-items/RE-021-blake2b-compress-94/independent_verify.py
.venv/bin/python -B -m unittest tests.test_blake2b_compress
for s in 0 7 99; do PYTHONHASHSEED=$s .venv/bin/python -B tools/blake2b_compress.py | sha256sum; done
PYTHONHASHSEED=0 .venv/bin/python -O -B tools/blake2b_compress.py | sha256sum
```

## File hashes

See `MANIFEST.sha256` for the authoritative per-file digests (packet-relative paths; tools/tests via `../../../`). JSON pin: `8b977ba014e10bb78c6aa73ac046c3cf5b73f196fb6a1f655977c2dadb0bbfcd`.

## What this does not claim

- It does **not** claim a statically recovered HyperEVM precompile address `0x09` dispatch site in this binary.
- It does **not** claim a statically recovered 213-byte EIP-152 input-length check or an `f ∈ {0,1}` reject path in a `run()` wrapper (those live in revm-precompile source; this packet pins the compress F body).
- It does **not** claim a statically recovered gas-cost-per-round constant in the bytes.
- It does **not** claim that #154's inventory mention of `0x4e9a8a0` is a competing EIP-152 behavioural claim (non-claiming overlap only).
- Behavioural proof **does** emulate the real carved bytes via Unicorn (not merely an independent reference). The independent verifier additionally recomputes the same EIP-152 vectors with a portable Blake2b F as a cross-check.
- Node #115 and other releases are not covered.
