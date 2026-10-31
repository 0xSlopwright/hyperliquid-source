# RE-022-chacha12-guts-94

Standalone packet. `tools/chacha12_guts.py` builds `chacha12-guts.json` from node #94 bytes (Python standard library + optional `unicorn` for behavioural proof; no objdump/pyelftools).

Finding (bytes + emulation): `0x4e13780` is the SSE4x ChaCha block used by `rand_chacha-0.3.1` (`src/guts.rs` Location pin). ABI `(state, double_rounds, out)` = `(rdi, esi, rdx)` with 48-byte DJB state (key||counter64||nonce64) and 256-byte sequential 4-block output. The GOT-exported wrapper `0x4e14560` (slot `0x576e900`) dispatches on CPU features; a refill caller at `0x13c9ed2` passes `esi=6` (ChaCha12) and consumes `0x100` bytes. Behavioural proof runs the **real function bytes** under Unicorn on ChaCha20/12/8 reference vectors (ndr=10/6/4); outputs are byte-identical and the in-state counter advances by 4.

## Rerun

Emulation tests (`test_output_pin_and_expectations`,
`test_emu_tamper_expand_breaks_vector`, `test_exact_counts_emu_byte_identical`) run only when `unicorn` is importable (`unittest.skipUnless`); static pins and `--no-emu` JSON hash always run.

```
python3 -m venv .venv && .venv/bin/pip install unicorn
.venv/bin/python -I -B research/work-items/RE-022-chacha12-guts-94/verify.py
.venv/bin/python -O -B research/work-items/RE-022-chacha12-guts-94/verify.py
.venv/bin/python -I -B research/work-items/RE-022-chacha12-guts-94/independent_verify.py
.venv/bin/python -O -B research/work-items/RE-022-chacha12-guts-94/independent_verify.py
.venv/bin/python -B -m unittest tests.test_chacha12_guts
for s in 0 7 99; do PYTHONHASHSEED=$s .venv/bin/python -B tools/chacha12_guts.py | sha256sum; done
PYTHONHASHSEED=0 .venv/bin/python -O -B tools/chacha12_guts.py | sha256sum
```

## File hashes

See `MANIFEST.sha256` for the authoritative per-file digests (packet-relative paths; tools/tests via `../../../`). JSON pin: `66f083054342ba1320e13341e3fdfe568f26c57f10b90f2d528910d0aab8d4cf`.

## What this does not claim

- It does **not** claim an IETF RFC 8439 §2.3.2 (32-bit counter + 96-bit nonce) ABI; the carved function uses the DJB / `rand_chacha` 64-bit counter + 64-bit nonce layout.
- It does **not** claim the AVX2/YMM sibling paths inside the CPU-feature wrapper; only the SSE `xmm` block at `0x4e13780` is emulated.
- The full `StdRng` / `ThreadRng` type layout beyond the observed refill caller (`+0x120` state, `+0x158` remaining) is not reconstructed.
- Node #115 and other releases are not covered.
