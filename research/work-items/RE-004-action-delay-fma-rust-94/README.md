# RE-004: recover the qualified action-delay curve as independent Rust

- Component: foundation / action-delayer numerical leaf; bounded RE-004 follow-up.
- Target: node #94, Linux x86-64, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Analysis base: `cec50f68e01c967d21538d48c49683ddeea52767`; full inventory validated on `ef9226639e3162396b762aef518ab791825072dc`, then rebased to delivery base `de089f488ddb7d381a2e0aaccde7a4a2e9ad9bac` and its new/affected modules checked.
- Pinned unlicensed can1357 reference:
  `999556f6e0a474b8312db96ec3149e1c44e97c23`; not copied or used as a numerical oracle.
- Observed: function extents, control/data operands, indirect slots and FMA3
  instruction. Inferred: logical curve names and chosen Rust observation API.
- Included: full local dispatch and arithmetic under the FMA3 qualification.
  Excluded: recovered source ABI, caller protocol, software FMA, CPU detector,
  whole-node reconstruction. No progress gate requested; all remain unchanged.

## Why this advances the reconstruction

The existing `foundation-duration-guards-94` packet (PR #18) establishes local
floating guards but supplies no executable independent curve. The merged
`RE-004-vty-tracker-94` research hooks this leaf rather than recovering it.
Closed-invalid PR #600 guessed a power helper and misclassified mode 1. Its
maintainer review explicitly establishes the mode<2 default path. We did not
copy that PR's implementation and do not adopt its conditional power-model
numeric examples as target results.

The new work closes the helper-operand and complete conditional-curve gap as a
real standalone Rust crate. The shared helper's FMA role was already noted by
`RE-006-twap-slice-94`; the new finding is its concrete operands and relation to
this action-delay leaf, not discovery of FMA in the binary.

## Binary observations

All coordinates are linked ELF virtual addresses, before loader rebasing.
`target-records.json` locks five complete FDE extents, 665 bytes in total:

| Range, end exclusive | Role |
| --- | --- |
| 0x392fab0..0x392fcba | complete local curve, 522 bytes |
| 0x565f8c0..0x565f8d1 | indirect helper trampoline, 17 bytes |
| 0x565fd20..0x565fd26 | FMA3 arm, 6 bytes |
| 0x565fd30..0x565fd37 | FMA4 arm, 7 bytes, arithmetic unqualified here |
| 0x565fd40..0x565fdb1 | resolver, 113 bytes |

Existing `fde_extents` obtains exact extents; retained LLVM 21.0.0 and Capstone
5.0.6 exports agree on every instruction start and byte with gap-free coverage.
GNU objdump 2.44 ELF exports are also retained (`*.gnu.txt`); this is a source-built
x86_64-linux-gnu target tool, not the Mach-O-only macOS conda objdump. Its official
source archive SHA-256 is `ce2017e059d63e67ddb9240e9d4ec49c2893605035cd60e92ad53177f4377237`
([upstream release](https://sourceware.org/pipermail/binutils/2025-February/139195.html)).
The verifier checks both exports, original bytes, a comparison-tree projection
against the set-form dispatch at partition endpoints, dispatch anchors, RIP operand
addresses, data constants and R_X86_64_RELATIVE addends. Nearest symbol names in
LLVM's output are not function identity evidence.

Slots are `0x5776220 -> 0x392fab0`, `0x576f6e0 -> 0x565f8c0` and the trampoline
cache `0x57882e8`, initially `0x565fd40`. The resolver can select FMA3
`0x565fd20`, FMA4 `0x565fd30`, or software `0x565f8e0`. Its detector call and
software branch are not closed here. FMA3 bytes `c4e2f1a9c2c3` decode as
`vfmadd213sd xmm0,xmm1,xmm2; ret`: one-round input*multiplier+bias.

| Raw mode | Medium12 actions | Eighth actions | Other actions |
| --- | --- | --- | --- |
| 0, 1 | none | none | Default20 |
| 2 | 0 | 3, 4, 11054, 11137 | Default20 |
| 3..255 | 5 | 0, 1, 10142, 10151 | Default20 |

Default20 computes `fma(input,10000,-4)/20`, Medium12 computes
`fma(input,10000,-3)/12`, Eighth computes `fma(input,10000,-1.5)*0.125`.
Finite values alone are clamped to [0,1], preserving negative zero; nonfinite
values bypass the clamp. The guard rejects unordered/negative values. Multiply
by 1.3 (default) or 1.8 (others), then separately add 0.76. A second guard
precedes the final factor. Only default uses 0.2 when raw u32 action>=100000000
or `(action-10000) mod 2**32 <100000`; otherwise the factor is 0.65.

The instruction semantics follow the Intel SDM v093
<https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>.
Rust `f64::mul_add` provides the one-round primitive:
<https://doc.rust-lang.org/std/primitive.f64.html#method.mul_add>.

## Reproduce

From repository root with Python 3.12.14 and its pinned requirements, Rust
1.94.1 (e408947bf), Cargo 1.94.1 (29ea6fb6a), on macOS aarch64:

```sh
python3 tools/action_delay_fma_rust.py
cargo test --offline --locked --manifest-path src/node94-action-delay/Cargo.toml
cargo build --release --offline --locked --manifest-path src/node94-action-delay/Cargo.toml
python3 tools/action_delay_fma_rust.py --rust-driver src/node94-action-delay/target/release/node94-action-delay
python3 -m unittest discover -s tests -p test_action_delay_fma_rust.py -v
python3 research/work-items/RE-004-action-delay-fma-rust-94/mutation_controls.py
cargo build --lib --target=x86_64-unknown-linux-gnu --release --offline --locked --manifest-path src/node94-action-delay/Cargo.toml
make doctor verify catalogue-check reproduce
```

`--write` regenerates dispatch/vector/evidence records only after target
validation. Set `PYTHON` on make and `CARGO_TARGET_DIR` if needed. In this run
both pointed to isolated `/private/tmp` toolchains/build output. No captured
binary was loaded as code, executed, emulated, patched or transplanted.

For each retained LLVM export use `llvm-objdump -d --start-address=START
--stop-address=END artifacts/node/94/hl-node`. The matching Capstone export is
`Cs(CS_ARCH_X86,CS_MODE_64).disasm(original_window_bytes,START)`, serialized as
`address: bytes_hex mnemonic operands`. No instruction simulation is involved. Trailing text whitespace was trimmed in decoder exports; original instruction bytes are unchanged.

## Implementation and comparisons

The independent MIT crate is `src/node94-action-delay` with a real dependency-free
Cargo.lock. `Result/Trace` are deliberately chosen logical carriers; no claim of
original calling convention or panic payload equivalence. The target qualification
is round-to-nearest/ties-even, DAZ=0, FTZ=0, masked exceptions and FMA3 dispatch.
Actual target runtime MXCSR and arm reachability were not measured.

The Python oracle uses exact Fraction multiplication/addition and one conversion
to binary64 for FMA, independent of host FMA. Subsequent binary64 operations match
the observed instruction order. Its expectation derivation is static and
conditional, not a dynamic target oracle. There are 332 concrete input vectors
including mode/action boundaries, signed actions, adjacent clamp transitions,
subnormal, maximum finite, signed zero, infinities and NaN. The 314 successful cases
compare 1,570 arithmetic stage bit patterns; 18 errors compare the logical guard.
`rust-driver.stdout` retains the actual release-driver output.
57 contiguous abstract cells cover 256*2**32 raw mode/action patterns, not that
many executions. Rust checks all mode values per cell and endpoint/midpoint
actions, plus the retained vector corpus. No normalization mask is applied.

Actual results: all 3 Rust integration tests, 332-case release-driver comparisons
and 5 scoped Python tests pass. All four mutants in `mutations.json` fail real
Rust tests: wrong mode-1 dispatch, unfused arithmetic, signed tail comparisons,
and clamping positive infinity. Python corrupt-input controls reject wrong
target identity, control/call/FMA bytes, constants and a relocation addend.

The Linux x86-64 library cross-build passes (compile only, no target execution).
Two fresh optimized object builds match byte-for-byte, SHA-256
`985248f18d58430c3efd7d452153649e0aa95d6216883123756f8aaa4c28c4f6`:

```sh
mkdir -p work/action-delay-build
rustc --edition=2024 --crate-type=rlib --crate-name=node94_action_delay --target=x86_64-unknown-linux-gnu -Copt-level=3 -Cpanic=abort -Ccodegen-units=1 --emit=obj src/node94-action-delay/src/lib.rs -o work/action-delay-build/a.o
rustc --edition=2024 --crate-type=rlib --crate-name=node94_action_delay --target=x86_64-unknown-linux-gnu -Copt-level=3 -Cpanic=abort -Ccodegen-units=1 --emit=obj src/node94-action-delay/src/lib.rs -o work/action-delay-build/b.o
```

This is reproducibility of our component, not original machine-code equality.
No target-vs-reconstruction byte, ABI, layout or whole-ELF comparison is claimed.

## Repository checks and remaining gaps

`make doctor verify catalogue-check reproduce` passed. Doctor cannot identify
standalone Rust through its optional rustup probes; compiler and Cargo versions
above were verified directly. Target signatures, imported inputs and submodule
pins pass verification.

The historical monolithic `make test` attempt on the analysis base exceeded a
3 GiB RSS ceiling during discovery (11.25s, 3,719,712 KiB aggregate RSS).
Upstream then merged #1159, replacing that discovery with isolated file runs.
After rebasing, the sequential launcher was attempted and the complete inventory
was validated with four independent test subprocesses at a time. The 804-file
inventory completed in 1,029.78s. Initial environment failures in 27 modules used
a Mach-O-only objdump; one further module could not find LLVM on PATH. All 28
pass when rerun with the proper ELF GNU 2.44 and LLVM tools. No test suppression
or repository runner modification was made.

The delivery rebase adds two test modules and changes the resting-order parser;
all three `test_match_resting_order*.py` modules and the new
`test_validator_state_wire.py` pass. Aggregate coverage is **806 files, 12,795
reported tests, 63 reported skips and zero unresolved failed modules**. This is
not a single successful `make test` invocation, hosted CI or container result.
Optional provider/emulator/toolchain skips remain skips. See `checks.json`.

The full-inventory method, with both GNU ELF and LLVM tools on PATH, was:

```python
# From repository root, using the same Python and inputs as make test.
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess, sys
files = sorted(Path("tests").glob("test*.py"))
def run(path):
    return subprocess.run([sys.executable, "-m", "unittest", "discover",
                           "-s", "tests", "-p", path.name, "-v"]).returncode
with ThreadPoolExecutor(max_workers=4) as pool:
    assert all(code == 0 for code in pool.map(run, files))
```

The observed run retained one log per subprocess outside the source tree,
then reran the environment failures and delivery-base affected modules with
those same unittest arguments. The sketch above describes the final clean
environment reproduction; it is not an additional claimed test run.

Next question: independently close the software FMA arm and feature-detector
preconditions before widening the qualification, then establish native caller
reachability and error payload/ABI. No full RE-004 gate is requested.
