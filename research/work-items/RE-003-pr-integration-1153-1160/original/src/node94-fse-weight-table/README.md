# Qualified normalized weight-table constructor

This independently authored `no_std`, safe Rust component implements the
serialized table relation established for node #94's constructor at
`0x556fb60..0x556fe63`. The exact primary FDE is771 bytes/213 native rows,
SHA-256 `8d7636d905df5188c3a5d0d495cf337bf1eca14949a373cc7e5393f5ae94484e`,
inside target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The [evidence packet](../../research/work-items/RE-001-fse-weight-table-94/README.md)
separates this constructor from all caller/header/decoder context.

## Chosen safe API

`build_weight_table(log, max_symbol, &[i16;256], &mut [u8;260])`
returns `Result<usize, UnsupportedDomain>`. Its qualified input domain is:

- log5 or6, with T=2^log;
- max<=91 for log5 or<=11 for log6, from the actual876-byte outer caller;
- each coefficient through max is-1 or0..T, with absolute sum T;
- the last used coefficient is nonzero and all later cells are zero.

The lower constructor scratch check alone would permit max95/15 for the
same residual. Those broader inputs are not silently counted as actual
caller matches. `UnsupportedDomain` preserves all260 output bytes; this is
an explicit safe-API policy outside the qualified native relation, not the
target's malformed-input raw errors or partial workspace effects.

Success writes exactly132 or260 bytes: a little-endian DWORD `log|(F<<16)`,
then T rows of little-endian WORD base, BYTE symbol and BYTE bit count.
F is1 unless a nonnegative coefficient is at least T/2. Zero-bit rows are
valid when F=0. Every row satisfies `base+(2^bits-1)<T`; its serialized
symbol multiplicity and placement match the proved native relation.
Every later output byte is preserved. The returned length is newly chosen
API metadata: the target's successful RAX is0.

The private arrays and one scalar spreading algorithm are independently
chosen. This component does not claim the original ABI, private scratch
image, nominal types, physical generated stores, compiler identity or
instruction-byte equality. It implements no header reader, bitstream
decoder or full HUF DTable builder. No dependency, allocator, Cargo workspace,
unlicensed inferred source or captured machine code is introduced into the
Rust implementation.

## Reproducible component workflow

Use only the separately authenticated repository research rustc provider,
with an explicit edition. The examples below show the standalone build
scope; the packet retains the exact measured commands and flags:

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_fse_weight_table \
  --crate-type=rlib -D warnings src/node94-fse-weight-table/lib.rs \
  -o /tmp/libnode94_fse_weight_table.rlib
/path/to/verified/rustc --edition=2021 --test -D warnings \
  src/node94-fse-weight-table/lib.rs -o /tmp/fse-weight-table-tests
/tmp/fse-weight-table-tests --nocapture
```

The unit's39 caller-domain table prefixes were independently frozen before
production Rust. Full-buffer marker serialization is separately recorded;
marker strings are not falsely described as predating first authoring.
The fixture is cfg(test)-only. Normal production libraries do not read
expected answers, and the separately linked client receives only one input
file with id/log/max/coefficients/initial260 bytes. It emits raw status,
chosen length and all260 bytes, never a slice selected by that length.
This is observed data-flow separation, not a filesystem sandbox.

Three original standalone-only cases and independent supplementary cases
remain separately labeled. Their safe-API policy checks do not inflate the
39 qualified native caller cases. Actual completed builds, raw output,
semantic controls, own-build reproducibility and repository-check scope
belong in the evidence packet and final validation record.

## Completed fixed-source experiment

The recorded main546 experiment completes 41 top-level commands and 82 raw
streams: debug and optimized libraries, one Rust test function per profile,
39 complete primary outputs and a separate 30 API observations per profile,
five compiling semantic controls, and two raw-equal 22,216-byte own rebuilds.
The independent client then reuses the production rlib for three orders of
48 requests, with no library recompilation. Full commands, compiler identity,
raw logs, assumptions and exact case denominators are in the evidence packet.
This measured experiment is not relabeled as a rebuilt later-main result.
