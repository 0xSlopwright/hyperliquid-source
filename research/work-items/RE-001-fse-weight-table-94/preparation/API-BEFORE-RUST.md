# Exact proposed API/domain before production Rust

Preparation only. The isolated checkout is clean main
546081f30a3ebe6af1dadb6f90869f01bd08e1e4 with seven genuine pins.
The independent native/table oracle was frozen before any production Rust:
ORACLE-FREEZE eb57a5e1ea71e483b5fc9f9113f871f63f0696cefc95145921167f664befd3bd.
This document requires final root GO; it writes no production implementation.

## Source and API ownership

Proposed primary files:

- `src/node94-fse-weight-table/lib.rs`: real independent no_std component.
- `src/node94-fse-weight-table/input_only_driver.rs`: real linked client.
- `src/node94-fse-weight-table/target-inputs.txt`, `target-expected.txt`,
  `target-vectors.tsv`: serialized frozen valid-domain vectors only.
- `tools/fse_weight_table.py`: bounded static target/provider and proof facts.
- A separately assigned runner/tests and one RE-001 evidence packet after
  root approves exact ownership. No shared-reference/import files are edited.

Chosen signature:

```
pub fn build_weight_table(
    log: u8,
    max_symbol: u8,
    normalized: &[i16; 256],
    output: &mut [u8; 260],
) -> Result<usize, UnsupportedDomain>
```

`UnsupportedDomain` is a newly chosen unit error type, not a recovered target
enum. No original ABI, signature, private layout, allocator, Cargo workspace,
dependency, runtime provider or whole FSE decoder is claimed.

## Qualified input domain

1. log is5 or6; T=2^log.
2. max_symbol<=91 for log5, or<=11 for log6, matching the actual876-byte
   outer caller admission. This is stricter than the constructor's direct
   scratch check, which would permit95/15 for the same residual.
3. Every coefficient through max is-1 or an integer0..T.
4. Every coefficient after max is0, and the coefficient at max is nonzero.
5. The sum of absolute coefficients through max is T.

On that complete domain, the native771-byte function's ordinary successful
serialized table relation is closed. The new safe API validates the domain
before changing output. Unsupported inputs return `Err(UnsupportedDomain)`
and preserve all260 output bytes. That is an explicit policy outside this
qualified native relation, not a claim about native malformed-input raw
errors or partial workspace stores.

## Exact successful output

Let F be1 unless any nonnegative coefficient is at least T/2, in which case
F is0. The first DWORD, little endian, is log|(F<<16). Each of T four-byte
rows is `[base_lo, base_hi, symbol, bits]`, with the exact native spreading,
occurrence and state formulas proved by the independent packet. All
4+4*T bytes are overwritten; every later output byte is preserved. Return
`Ok(4+4*T)`, hence132 or260. This length is chosen API metadata; native RAX
success is0 and is not mislabeled as returning the length.

Private implementation scratch is allowed to differ from the original
workspace. Only the qualified serialized output/suffix relation is claimed,
not a native scratch image or generated physical store sequence. One scalar
algorithm may implement both native spread routes, whose logical outputs
have been separately proved equivalent.

## Input-only observable wire

One ASCII input line has five single-space-separated fields:

`id log_decimal max_decimal coefficients initial260_hex`

The identifier contains only ASCII letters, digits, hyphen or underscore.
`coefficients` is exactly256 comma-separated signed decimal i16 values.
`initial260_hex` is exactly520 lowercase hex characters. None of these
fields is an expected answer, phase label, reference path, desired length
or expected table row. The driver receives exactly one input-file argument.

The actual linked client emits either:

`id ok length_decimal complete260_hex`

or

`id unsupported 0 complete260_hex`

It always serializes all260 bytes without slicing by the returned length.
Malformed wire input is a client-protocol failure outside the library's
domain tests; semantic mutants must complete normally on valid protocol
rows and produce valued differences. No filesystem sandbox claim follows
from this observed input-only data flow.

## Frozen expectation binding

The independent oracle has42 cases:39 actual876-domain cases and3 broader
standalone-only cases. The39 are the primary implementation corpus. Extend
their coefficient lists with zeros to256, preserve their explicit max as
list-length-minus-one, and serialize without changing their coefficient or
expected table bytes. Deterministic initial260-byte markers are stimulus;
each expected full output is the independently frozen table prefix followed
by that same stimulus suffix. Marker serialization does not recalculate
table semantics or change the oracle's frozen table hashes.

The3 standalone-only cases must not count as qualified native caller/table
matches. They may remain broader native proof evidence and/or be separate
safe-API rejection controls, with those two meanings clearly distinguished.
In particular log6/all64 low symbols and symbol255 cases fail the actual
caller domain even though the native standalone constructor can have a
larger valid workspace.

The library's vector unit is cfg(test)-only; a normal production rlib must
not include expected answers. Actual debug/optimized clients link that real
production library and are compared externally with the independent frozen
expected output. Counts are reported as actual tests/cases/commands/streams,
not inflated by multiplying vectors into separate Rust test functions.

## Precompiler/static provider and control requirements

Before compiler GO, the maintained provider will admit one immutable full
node94 bytes object by complete SHA/size and derive only target-bound tiny
raw views/FDE/section/PT_LOAD facts. GNU only decodes tiny private nonexecuting
views. Native opcode/register/store/stride/flag/row constraints and their
proof parameters are authenticated below the whole-input gate, with genuine
changed-byte and listing controls. Synthetic normalized-input or output-table
comparator controls must be labeled separately; this constructor has no captured
RIP-relative table literal. No PC/register/memory evaluator, target
execution or oracle-derived source flag/layout grid is introduced.

Keep primary771-byte coverage separate from revisited caller/header/buffer
context. Preserve header low-probability/mass proof, the outer876 versus
constructor scratch units, both spread routes including padded SIMD writes,
the defensive raw-error reachability distinction, normal CPU/memory/import
domain and all earlier negative/preparation results. Every source/helper and
raw result gets its real identity; no gate is changed.

The final runner must pin source/fixture/provider/toolchain inputs before and
after real builds. Candidate semantic mutations target distinct relations:
low symbol order, reserved-slot skipping, odd stride, signed-1 handling,
half-threshold flag, state/bit arithmetic and untouched suffix. Require
actual compilation and normal valued output differences, not only panics or
syntax failures. Two fresh own-library builds may establish raw own
reproducibility; they do not establish captured-byte equality.

Only the already verified research rustc prefix may be reused after root's
resource/compile GO; no install, Cargo invention, captured execution or full
upstream evaluator suite is authorized by this preparation document. Root
coordinates current-main checks, independent reviews, draft publication and
the single Slop registration if a contribution is approved.
