# Maintainer review of PR #1124

Original head: `c69f74062f25569120dfeef6410e275c031ce0cb`.

Target node94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Static inspection verified the declared compression extent against actual FDE records, full-range GNU disassembly bytes, selected instruction operands, literals and relocation/caller anchors. This supports the bounded static observations; it does not reproduce the submitted captured-code output receipt or establish general cryptographic equivalence.

The original JSON remains byte-for-byte unchanged. Source and documentation checksums are updated intentionally for the harness changes. The original execution claims are historical contributor receipts, not fresh maintainer results.

## Harness correction

Producers and packet verification now default to static mode even when Unicorn is installed. Explicit `--emulate` requires separately obtained authorization; the flag itself does not grant it. Unit tests also require `HL_ALLOW_CAPTURED_CRYPTO_EMULATION=1` before any captured execution.

The common runner checks every executed instruction and guest write, rejects escape, applies time/instruction limits, and requires RIP to reach the return sentinel. Original harnesses returned memory after any normal `emu_start` return, including a timeout/count stop. A fake backend that executes zero instructions reproduced that defect in all five helpers; corrected helpers reject it. Callback tests cover valid completion, instruction/write boundaries and cleanup without running an emulator.

Allowed code: 0x4ec9230..0x4ec9264 and 0x4ec9323..0x4ecbecb (plain path; feature detection/SHA-NI excluded). Writes are limited to the synthetic stack and the declared state/output buffers. Target mappings are not host addresses; no syscall/network/filesystem bridge is installed. The current harness still maps captured PT_LOAD data in four tools; instruction/write hooks bound guest use. This is not an OS sandbox or a claim about emulator vulnerabilities.

Fixtures: Empty, abc and 448-bit message; one/two 64-byte blocks and the 32-byte SHA-256 IV state. Feature byte forced to 0.

## Pending acceptance

After explicit authorization and with a locally available reviewed Unicorn installation, the minimal full-receipt comparison is:

```sh
python3 -I -B research/work-items/RE-025-sha256-compress-94/verify.py --emulate
```

This was not run during the maintainer review. No package installation or public download was performed. Static tests, hashes, FDEs and independent standard-library algorithms do not replace this remaining acceptance check. The opt-in emulation mutation tests are also unrun; they require authorization covering their declared synthetic inputs and captured-byte mutations.

The SHA-NI rejection control now stops at the declared plain-path boundary before entering an unapproved alternate path. The historical invalid-instruction observation is retained but is not reproduced by that control.

Raw-byte scanner controls now include complete instructions ending at the final byte and extended-register MOV encodings. Eight original synthetic cases failed; all corrected cases pass. These scans propose instruction references; native GNU decoding separately confirmed every reported reference on this digest.
