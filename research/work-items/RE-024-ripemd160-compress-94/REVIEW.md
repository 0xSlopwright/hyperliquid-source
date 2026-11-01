# Maintainer review of PR #1041

Original head: `972534d8dd8bbf2c005535d2038e0202cf468b29`.

Target node94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Static inspection verified the declared compression extent against actual FDE records, full-range GNU disassembly bytes, selected instruction operands, literals and relocation/caller anchors. This supports the bounded static observations; it does not reproduce the submitted captured-code output receipt or establish general cryptographic equivalence.

The original JSON remains byte-for-byte unchanged. Source and documentation checksums are updated intentionally for the harness changes. The original execution claims are historical contributor receipts, not fresh maintainer results.

## Harness correction

Producers and packet verification now default to static mode even when Unicorn is installed. Explicit `--emulate` requires separately obtained authorization; the flag itself does not grant it. Unit tests also require `HL_ALLOW_CAPTURED_CRYPTO_EMULATION=1` before any captured execution.

The common runner checks every executed instruction and guest write, rejects escape, applies time/instruction limits, and requires RIP to reach the return sentinel. Original harnesses returned memory after any normal `emu_start` return, including a timeout/count stop. A fake backend that executes zero instructions reproduced that defect in all five helpers; corrected helpers reject it. Callback tests cover valid completion, instruction/write boundaries and cleanup without running an emulator.

Allowed code: 0x4ea55f0..0x4ea6c80. Writes are limited to the synthetic stack and the declared state/output buffers. Target mappings are not host addresses; no syscall/network/filesystem bridge is installed. The current harness still maps captured PT_LOAD data in four tools; instruction/write hooks bound guest use. This is not an OS sandbox or a claim about emulator vulnerabilities.

Fixtures: Empty, abc, message digest, a..z and alphanum; one/two 64-byte blocks and the 20-byte RIPEMD-160 IV state.

## Pending acceptance

After explicit authorization and with a locally available reviewed Unicorn installation, the minimal full-receipt comparison is:

```sh
python3 -I -B research/work-items/RE-024-ripemd160-compress-94/verify.py --emulate
```

This was not run during the maintainer review. No package installation or public download was performed. Static tests, hashes, FDEs and independent standard-library algorithms do not replace this remaining acceptance check. The opt-in emulation mutation tests are also unrun; they require authorization covering their declared synthetic inputs and captured-byte mutations.

## Corrected caller census

The original scanner accepted only REX 48 MOV encodings and reported one MOV consumer. Fresh GNU decoding shows `4c8b25ae6c8d00` at 0x4ea02fb loads R12 from 0x5776fb0; the existing RBX load at 0x4ea043a and FF15 call at 0x4ea049b remain. The corrected census is two MOV references and one direct indirect-call encoding, all inside finalize FDE 0x4ea0200..0x4ea055e. This is an instruction-reference count, not three distinct reachable callers.

`ripemd160-compress.json` retains the original receipt and its count 1. `static-reviewed.json` is freshly generated with count 2 and no emulation. Future full verification compares the archived receipt with exactly this documented metadata correction; it does not change or normalize any emulated output. Original full SHA256: 6167af924de2bbdb68943119ea66c3866448fa024b20992a10cd9bdd7ecefb43; corrected expected full SHA256: 83668b82009784802f8c16f8eaf6bc83bcb3a30466bef680967347b5b0fbc7ec; fresh static SHA256: 6ca0789fb398d47cfd51c6a04e7ed003b1203f1ecf130a2b1519dc02dba72520.

Raw-byte scanner controls now include complete instructions ending at the final byte and extended-register MOV encodings. Eight original synthetic cases failed; all corrected cases pass. These scans propose instruction references; native GNU decoding separately confirmed every reported reference on this digest.
