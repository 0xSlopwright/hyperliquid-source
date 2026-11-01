RE-025: SHA-256 compress @ 0x4ec9230 (node #94), plain path emulated against FIPS 180-4

Static recovery of the sha2-0.10.8 SHA-256 compress entry in the pinned node #94
binary: the inline CPU-feature dispatch, the plain-code compress, the SHA-NI
branch (static only), and the GOT wiring into a real caller. The plain path is
proven with Unicorn against the FIPS 180-4 `abc`, two-block and empty digests.

Scope of emulation: Unicorn runs only the carved, hash-pinned compress entry
(`0x4ec9230`..`0x4ecbeca`, carved sha256 `937e311f…bab9`, len 11419) with the
feature byte at `0x578687d` forced to 0, so execution goes straight to the
plain-code compress at `0x4ec9323`. The execution proof covers the plain path
only. The SHA-NI branch (`jmp 0x4ecbf10`, `sha256rnds2`) is shown statically by
disassembly and is not executed: Unicorn cannot run `sha256rnds2`, and forcing
the byte to 1 stops with an invalid-instruction error. The captured binary is
never run as a whole.

The closest repository text is CONTRIBUTING.md (Licensing, execution and review):
"The default workflow is static. Running captured binaries, networked services,
chain actions or signing requires explicit authorization and an isolated
harness with declared effects." and docs/SCOPE.md (Current exclusions and
separate authorization): "Differential execution requires a separately
approved, isolated offline harness." Neither passage mentions emulating a
carved function. Whether carved-function emulation counts as the
authorized-execution or differential-execution case is left to the maintainer.

## Identification

The identifier is the K constants, the dispatch structure and the wiring chain:

- All 64 FIPS 180-4 SHA-256 round constants appear as imm32 in the plain body;
  the SHA-NI body loads all 16 four-word K groups rip-relative (K[0..3] at `0x204680`)
  and contains 32 `sha256rnds2`.
- Dispatch on byte `0x578687d`: `0xff` → detection (cpuid helpers `0x4ecbef0`/`0x4ecbed0`,
  xgetbv `0x4ec9220`); `1` → epilogue then `jmp 0x4ecbf10` (SHA-NI); else → `jmp 0x4ec9323` (plain).
- Wiring: `R_X86_64_RELATIVE` addend `0x4ec9230` at GOT slot `0x576f7a8`; caller
  `0x145c299` `ff 15` `call *[rip]` → slot. No direct `e8`/`e9` reaches `0x4ec9230`.
  The slot has 33 rip-relative references in the main text load (18 `call`, 15 `mov`), pinned as a count.
- Caller panic Locations `0x566bff0` (62:54) and `0x566c008` (62:23) point to a 93-byte
  path ending `sha2-0.10.8/src/core_api.rs`. This is string+shape evidence only.
  The SHA-256 IV (also used by BLAKE3) is not used as an identifier.

## Prior listing

The extent `0x4ec9230..0x4ecbecb` already appears as an inventory row in #154, and
merged #23 lists `0x4ec9230` as a hasher (K-constant match). Both are listings,
not execution proofs. RE-025 is the first Unicorn/execution proof for this function.

## Proof

- Deterministic Python ELF tool (`tools/sha256_compress.py`, own program-header VA→offset parser); exact pins (never `>=`)
- Unicorn PT_LOAD maps + stack + RET trampoline; feature byte 0; state words LE → FIPS BE
- `abc`, two-block and empty digests match the published FIPS 180-4 values exactly
- Negative controls and tamper tests on the carve, dispatch, K, GOT RELA, caller, Location, state and block
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical `--no-emu` output
- `verify.py` holds under `-I -B` and `-O -B`; emulation soft-skipped when unicorn is absent
- `independent_verify.py` imports only hashlib / pathlib / struct

## What this does not claim

- Plain path emulated; SHA-NI branch static-only (not executed)
- The Location is string+shape evidence only
- The shared IV is not used as an identifier
- The other GOT-slot callers (`0x1471a00` group, `0x4e9e…` group) are counted, not all examined
- Detection / cpuid / xgetbv paths are not emulated
- No other node builds

<!-- run-receipt.mjs disclose: Grok-Bot -->
