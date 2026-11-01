# RE-003: align harness tests with the accepted real positive fixture

- Component: cross-cutting harness; no progress gate requested.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `8ea994d6fac1272b408fd47efe8d51e5e8eac18c`.
- Status: observed integration-test mismatch, corrected test expectations.
- Scope: seven harness test files and this review record. Production, fixture,
  protocol, example requests, imported evidence and submodule pins are unchanged.

## Cause and retained failures

Accepted PR #323 (`a996eec74d275cac7fd8b017e0568f3dd62b710f`) replaced the empty
synthetic positive with `94-pos-equal-window-v1`, a real 89-byte expectation.
Tests from #203, #464, #490, #493, #494, #503 and #506 still expected the old ID;
#203 also expected all three payload hashes to be the empty hash. #494 had an
earlier integration adjustment at `c83a3ad19c80f09bd079edc8f0b892a00f07e973`.
`source-mapping.json` records exact commits and before/after hashes.

The original full suite ran 8,959 tests with eight failures, five errors and two
unrelated optional skips. All 13 diagnostics are listed in initial-failures.json,
which binds the full raw log/result and the independent 118-test reproduction.
The full original log is preserved in ignored work, including a separate copy;
it was not replaced by passing reruns.

## Correction and static target binding

Tests now select the real positive ID. The payload test asserts the established
89-byte digest separately, while retaining both empty negative-template hashes
and the intentionally wrong target digest. Duplicate requests still require the
duplicate-specific refusal, and malformed payload/type/document/required-key,
privacy, approval, side-effect and corruption controls remain in the 118-test set.
The malformed-payload CLI test propagates -O when the test interpreter uses it.

Static review authenticated the complete target file, independently mapped the
window through ELF64 section headers to executable .text, and compared its bytes
to all 25 contiguous retained disassembly rows. VA `0x144a010..0x144a069` maps to
file offset `0x1449010`, length89, payload SHA-256
`e5786bcf006e4207862b5b8985c2a9ba7fd7488c171b9e86a5cc6a137b35ccdb`.
`target-binding.json` retains the bytes, coordinate mapping and source-output hash.
No target process or instruction was executed. Harness tests remain plan-only;
the target authentication was a separate static review action.

## Reproduce and results

Run from the repository root with Python3.14.6 and Python3.10.18, each normally
and with -O:

```sh
python -m unittest discover -s tests -p 'test_harness_*.py' -v
python -O -m unittest discover -s tests -p 'test_harness_*.py' -v
make doctor verify catalogue-check reproduce
```

All four focused runs pass118 tests. Light gates pass with installed GNU binutils
first on PATH. Initial doctor failure under Apple objdump is retained separately.
validation.json records exact commands, log hashes and results. No complete suite
was rerun here; the integrating reviewer owns the final combined full-suite gate.
No Rust implementation, comparator execution or binary-equivalence claim is made.
