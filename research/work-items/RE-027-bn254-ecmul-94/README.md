# RE-027: bounded bn254 ecMul evidence, node94

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Task: review precompile `0x07` candidate at `0x4e96cf0`, its arithmetic
closure, result layout, gas wrappers, and allocator-stub assumptions.

The original packet at PR #1143 head
`cbfb19f8f6b8bf107774f4b51088b043b1877e89` is preserved in `review-original/`.
`bn254-ecmul.json` and `independent_verify.py` remain byte-identical to that
submission. The JSON contains **the author's historical emulation record**;
the current review has performed static parsing, native disassembly and host
unit tests only. Its emulation acceptance remains pending explicit execution
authorization and a successful bounded rerun. No milestone gate is advanced.

## Static findings and their limits

The actual `.eh_frame` extent is `[0x4e96cf0,0x4e973d2)`: 1762 bytes, SHA-256
`fa3a57aef72db21e765e20e83db52a3c7ffb825112c2780fc3a7406406d942a5`.
GNU objdump 2.47.20260726 independently decodes the complete extent into 298
instructions. The `ret` at `0x4e973c1` precedes an allocation-error tail still
inside the FDE; the 14 `int3` padding bytes start at the exclusive FDE end.
All 40 original byte pins match, and every instruction pin starts and ends
on native instruction boundaries. The explicit padding pin is data outside
the FDE. Thirteen reviewed FDEs include eleven arithmetic functions and two
gas wrappers; `review-evidence/native-review.json` retains their bounds,
byte hashes, native call/branch records, relocation targets and pin results.

The observed combination of base and scalar field moduli, Montgomery
constants, point decoder, scalar multiplication, affine conversion, wrappers
with gas constants 40000/6000 and table Address `0x07` supports the inferred
bn254 scalar-multiplication identification. Source names and Rust types are
inferences, not recovered symbols or official source. `references/can1357-hl`
is not used for semantic interpretation. The two native wrapper calls are confirmed; the export's zero
`e8/e9` count is a byte-pattern scan and does not establish all possible xrefs.

The original `callees`/`simd_scan` JSON fields describe a selected inventory.
Native call-target review additionally identifies two transitive helpers:

| GOT slot | Actual FDE | Bounded interpretation |
| --- | --- | --- |
| `0x5777658` | `[0x4f1f8e0,0x4f1f9b1)` | four-limb add with modular reduction |
| `0x5777668` | `[0x4f20020,0x4f200e3)` | four-limb subtract with modular adjustment |

Both helpers are included in the execution allowlist. The listed feature
mnemonics (`cpuid`, `xgetbv`, `adcx`, `adox`, `mulx`) are absent in these
reviewed native rows. This is a bounded scan, not proof of all possible
feature dispatch. Baseline SSE instructions, including packed equality tests,
are present. No whole-node or whole-precompile-table claim is made.

The native success path requests exactly 64 bytes at `0x4e9732c`, returning
at `0x4e97332`. With the reviewed aligned synthetic allocation, the result is
five qwords: vtable `0x5670ae8`, heap pointer, length 64, pointer OR 1, and gas
cost. Error results zero the first two qwords and retain the observed error
payload. The wrapper's inferred Rust enum names are labels; raw layout and
payload bytes remain the evidence. Error, panic, actual jemalloc, short-input
`memcpy`, wrapper execution and whole-node behavior are not established by a
stubbed arithmetic experiment.

## Reproduction

Ordinary commands are static, even when Unicorn is installed:

```bash
python3 -B tools/bn254_ecmul.py --no-emu
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/verify.py
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/independent_verify.py
python3 -B -m unittest tests.test_bn254_ecmul tests.test_crypto_emulation_guard -v
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/review_native.py \
  --objdump /path/to/GNU/objdump --output-dir work/re027-native-new
```

The static JSON remains SHA-256
`79149c497481d1f9daff231044ca8d2ca135af3907086a0f63393209208322f4`.
The retained author emulation JSON is
`ae212bc9791ccdd53cc48dff1446aec74f07693be008b62746d83a601af3b980`.
These two records are separate evidence scopes. The original claimed Debian
GNU 2.44 / Python 3.13.5 / Unicorn 2.1.4 recipe was not reproduced here.
The original geth source-commit attribution is retained; its external file
was unavailable during this review. Two affine reference implementations
recompute the six success expectations locally, which is corroboration of
those mathematical vectors, not a new target-execution receipt.

## Explicit emulation boundary

Captured-code execution requires separate user authorization. `--emulate`
is an intentional runtime opt-in, not a grant of that authorization. Direct
Python callers also require `allow_execution=True`; missing Unicorn is a
failure when requested. Ordinary unit discovery skips the ten emulation
tests unless `HL_RE027_EMULATION=1` is explicitly set.

After authorization, this bounded command runs only the nine committed
vectors; verification compares the raw output with the unchanged author JSON:

```bash
python3 -I -B research/work-items/RE-027-bn254-ecmul-94/verify.py --emulate
```

Each run is limited to 60 seconds / 50 million instructions, exact reviewed
FDE ranges and the intercepted first allocator instruction. Guest writes are
restricted to the 1 MiB synthetic stack, 40-byte output header and 64-byte
heap allocation. The malloc callback checks its stack slot before reading,
requires the exact call return/size and permits only one allocation. It
changes registers only; it does not write host memory. Completion requires
the return sentinel; pointer/length/tag/vtable/gas/allocation validation
precedes any output-pointer read. These guards bound an experiment; their
host/fake-engine tests do not establish Unicorn execution success.

The target digest and its mapping/relocation metadata are checked before
constructing an engine. Only 96-byte inputs, unsigned 64-bit gas fields and
the two declared synthetic heap placements are accepted. Short inputs,
mutated captured instructions and removing the allocator stub fail before
emulation. The original corresponding negative experiments remain archived;
current tests check their rejection instead of executing outside this scope.
`--output` creates a new file exclusively. Completed raw comparison records
are preserved even on a mismatch, accompanied by a nonzero exit status; an
execution-bound or completion failure raises before any success record. The code never starts the node, opens a network connection, or
installs dependencies.
