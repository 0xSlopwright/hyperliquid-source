# Maintainer review of PR #1144

Original head: `2ab8ace6d13f04ade3b6725f71bbd383bf4a7ab0`.
Target: node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

The maintainer performed static inspection and safe Python controls only. The original `modexp.json` is preserved byte-for-byte, SHA-256 `20d1c278107e8688d04bd79ca27139606a4bcb88a942a5d288fd4d47dc843360`. Its captured-execution results are historical contributor receipts. They have not been reproduced by this review. The original six-vector static JSON remains byte-identical after the corrections; no execution output was normalized or repinned.

## Native findings and corrected claims

Actual FDE records and complete GNU disassembly validate the core extent `0x136bdd0..0x136bf34`, both wrappers, both gas functions and the declared arithmetic cluster. The fixture allowlist additionally includes seven required helper FDEs: allocation-growth adapters at `0x136bf40`, `0x136bfa0`, `0x136c040`; iteration-count and multiword division at `0x4e93460`, `0x4e935e0`; and compiler-runtime arithmetic at `0x565f5a0`, `0x565f7f0`. These are bounded static call-graph findings, not an assertion that every path is understood or exercised. `review-static.json` records all 22 allowed FDEs and selected native anchors.

The original “no SIMD” statement was false. There are 117 decoded XMM instruction rows in the original core/callee cluster, including `pxor` at `0x136891f` and `movdqu` at `0x1368930`. The retained `simd` / `simd_any` JSON fields count only five specific CPUID/XGETBV/ADX/MULX byte patterns. Their false/zero values do not mean absence of SIMD. No feature-dispatch or syscall instructions were found in the 22 reviewed FDEs; this observation does not cover the whole node or excluded helpers.

The following oracle defects were corrected with native-grounded controls; all original fixture outputs remain unchanged:

- Berlin iteration count is at least one: `CMP/ADC` at `0x4e934a7..0x4e934ab`, followed by multiplication in the gas function and division by three. For 256-byte base/modulus and exponent zero or one, the bounded native formula gives 341 gas; the original reference returned 200.
- Byzantium retains the `8*(exponent_length-32)` contribution even for a long all-zero exponent. For 64-byte base/modulus and a 33-byte zero exponent, native arithmetic gives 1,638 gas; the original reference returned 204.
- The core returns an empty Vec for numerical modulus zero, but the wrapper pads that result to the declared modulus length (`0x4e92674..0x4e926ab`). A two-byte zero modulus therefore produces two zero bytes. The original helper returned empty. The retained fixture named `zero_modulus` actually has modulus length zero, so its empty output remains correct.

The direct-call count was previously a literal zero. It now measures raw E8/E9 candidates; the current result is still zero. Raw candidates and RIP-relative references do not establish reachability. Scanner controls cover terminal instructions, truncation and extended-register MOV encodings.

## Harness changes

All entrypoints default to static mode. `--emulate` requires separate authorization; unit tests also require `HL_ALLOW_CAPTURED_MODEXP_EMULATION=1`. Installing Unicorn, importing the module or running ordinary repository tests does not grant or trigger execution. A requested run without Unicorn fails instead of silently producing a successful static result.

Before loading Unicorn, the harness validates the two permitted wrapper entries, gas limit 0..10,000,000 and complete synthetic input with each field at most 256 bytes. It authenticates node94 or exactly one of the three declared immediate mutations, then derives mappings and relocations from those authenticated bytes. Arbitrary caller-supplied mappings are ignored.

The execution guard permits only the 22 recorded FDEs and five one-byte intercepted stub entries. Guest writes are limited to the synthetic 1 MiB stack, 40-byte output and 4 MiB heap. Each call is limited to 120 seconds and 200 million instructions and must reach the exact return sentinel. Host callback reads/writes are separately checked because Unicorn guest-write hooks do not cover host `mem_write` calls. Each copy/fill/allocation is limited to 64 KiB; the bump allocator has a 4 MiB total and 4,096-allocation ceiling. Stub return stack and destination are checked. Oversized memcpy/memset operations fail rather than silently do nothing. The size-product allocation stub multiplies its arguments even if one is zero; it does not claim native allocator equivalence.

Malloc, size-product allocation and free are intercepted; captured allocator instructions are not executed. Free remains an explicitly modeled no-op. Memcpy and memset are bounded host copy/fill operations. Original traps are replaced by fail-closed range rejection. PT_LOAD data is mapped in the guest, but no host syscall, filesystem or networking bridge exists. These controls are not an OS sandbox or a claim about emulator vulnerabilities.

Additional static edges remain outside the model: allocation growth at `0x136bfe6` can call native resize `0x54c5620` through GOT `0x576e030`, and multiword division at `0x4e93ebc` can call unresolved `memmove` through GOT `0x576e0e0`. These paths are excluded and must stop the proposed run if reached. No claim is made that the retained vectors avoid them until authorized execution supplies that evidence. Other panic/unwind paths also fail closed.

The original acceptance checker ignored `returned` and success kind. Pure record-mutation controls showed incomplete vector runs, an error-kind vector and an incomplete gas mutation were all accepted when comparison flags remained true. The corrected checker rejects these records. Fake guard/callback tests execute no captured instructions and do not certify Unicorn backend behavior.

## Pending original acceptance

This PR remains held pending a separately authorized run of its original behavior checks. Authorization for other crypto packets does not cover this packet. With an approved Unicorn 2.1.4 interpreter, from the repository root:

```sh
<approved-venv>/bin/python -I -B research/work-items/RE-028-modexp-94/verify.py --emulate
HL_ALLOW_CAPTURED_MODEXP_EMULATION=1 <approved-venv>/bin/python -I -B tests/test_modexp.py -v ModexpEmuTests
```

Each full analysis performs six known synthetic inputs under both Berlin and Byzantium wrappers, plus three gas-immediate mutations: divisor 3→4, floor 200→201, divisor 20→21. The five existing behavioral tests repeat that same 15-call analysis. Only temporary memory copies are patched; imported artifacts are not modified. The known fixtures have field lengths at most 64/40/64 bytes and gas limit 10,000,000. The larger oracle controls above are independent arithmetic tests, not extra captured-execution fixtures.

Full semantic identity, general EVM precompile acceptance, native allocator behavior and whole-node equivalence remain unproved. Public EIP/source URLs were not fetched during this review; current evidence consists of authenticated target bytes, native instruction analysis, retained fixture literals and independently checked arithmetic.
