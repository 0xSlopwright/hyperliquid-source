# RE-002: official archive review receipt

This integration review accepts PR #1068 at
`fb5cc42d58a96f953230d3ff8bee1d7c7cd7050d` and PR #1136 at
`b8da679fb87fdabfa6a246766bc91046e602cbd7` for their bounded static
published-artifact comparisons. The review base is
`e7309f15c194a701a15ec367bd457125360a02b9`. No source build, original
compiler attribution, captured-code execution, runtime compatibility, or
whole-node equivalence is established.

## Admitted inputs

The integration coordinator acquired the two explicitly authorized official
Rust standard-library archives. Separate fresh signature checks returned the
expected full fingerprint `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE` for both
archives and both release manifests. The live official release-key bytes also
matched the retained key. `acquisition/` preserves the authentication summary,
four raw GPG status outputs and data-only libcore extraction receipt. These are
new review observations; the original packets' historical acquisition claims
and their distinction between hash checks and signature checks remain intact.

| Distribution | Compressed bytes | Archive SHA-256 |
| --- | ---: | --- |
| rust-std 1.94.1 x86_64-unknown-linux-gnu | 29,846,424 | `74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03` |
| rust-std 1.95.0 x86_64-unknown-linux-gnu | 29,573,972 | `047ea7098803d3500fa1072e9cee5392697e21525559e4458128a2bf874aa382` |

The admitted 1.94.1 libcore archive is 2,917,630 bytes, SHA-256
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`.
Its selected code member is 2,871,296 bytes, SHA-256
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`.
An additional separate ar-framing/pyelftools check verified all three primary
symbol extents and all 19 actual relocation records. Reading the official
tar's unique regular `LICENSE-MIT` entry reproduced the retained 1,068-byte
license exactly. No archive member was installed or executed.

The full capture identities are:

- node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- node #115: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- visor: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

## #1068 reproduction

Fresh Python 3.14.6 and Python 3.10.18 `-O` runs both reproduced the original
results, target observations, and corruption-control JSON byte-for-byte. Each
run checks 218 eligible candidates in 654 comparisons across the three
captures. The archive census remains 675/676 matching RC2 comment carriers,
with 35 compiler-builtins and 20 profiler-builtins carriers per release.
The seven sanitizer/runtime carrier groups remain outside the bounded binding
subset. The 1.94.1 and 1.95.0 producer stamps differ; their selected 98-byte
`__popcountdi2` bodies are identical.

The fresh independent parser verifies all 110 exact carrier identities across
four libraries. It used an existing pyelftools 0.32 cache after verifying all
59 hashed RECORD entries; no dependency was installed or downloaded. Its two
fresh native listings are byte-identical to the retained listings. The current
Apple LLVM 21.0.0 reader's binary digest and full version output are recorded
separately; they are not substituted for the historical reader identity.

Native static decoding verifies all 27 instructions in each 98-byte target
window and one actual caller FDE per target. No FDE covers any selected target
window, so no complete target function size is inferred. Raw E8 candidates
remain separate from the three validated caller witnesses and from a complete
xref census. Wrong-release, shifted-window, wrong-section, code corruption,
comment corruption, NOBITS/non-executable metadata, and malformed container
controls remain active. There is no normalization mask.

## #1136 reproduction and explicit integration refresh

All 13 tests passed with the actual admitted archive and zero skips on Python
3.14.6, Python 3.14.6 `-O`, and Python 3.10.18. These include malformed ar/ELF,
actual symbol/link corruption, relocation width/bounds/overlap, raw data and
terminal-byte corruption, exact FDE extent/ambiguity, immutable input snapshot,
and output-preservation controls.

The fresh collector reproduces all 30 current raw exports/notices byte-for-byte.
All target, official-object, relocation, data/link, raw-difference and limit
fields match the original current report. The three complete primary FDEs
remain 1,456 bytes: 19 actual four-byte code RELA fields account for 76 bytes,
and 1,378 of the remaining 1,380 bytes agree. The adapter retains its genuine
raw gaps at offsets **464 and 467**. The separate 61-byte supporting callee
remains outside the primary denominator; transitive closure remains open.

The new report differs only in Python version and observational hashes of the
already integrated `elf_index.py` and `fde_extents.py` helpers. The original
report and output manifest remain unchanged. `libcore/regeneration-delta.json`
records every identical export and both metadata differences.

The packet's top-level `MANIFEST.sha256` needed exactly two current-helper
hash updates. The original bindings were checked against the exact original
PR tree before the coordinator approved this integration-only refresh. The
entire original manifest is retained as `libcore/MANIFEST.original.sha256`;
`libcore/manifest-refresh.json` records both old and new hashes. All other 124
entries remain unchanged. No imported provenance file is repinned.

`original-file-preservation.json` verifies 159 of 160 original packet/tool/test
files unchanged, with the one manifest refresh just described. The original
#1068 six-line qualified cross-reference in the build-provenance README is
also retained by the merge. Historical negative and preparation evidence is
unchanged. The fresh report/output manifest in this receipt refer to the
identical raw exports retained in the original packet; they do not duplicate
those binary files.

## Commands and gates

From the isolated repository root, with `INPUTS` pointing to the coordinator's
authenticated archive directory and `CORE` pointing to its selected libcore:

```sh
python3 research/work-items/RE-002-std-clang-carriers/probe.py \
  --repo . --inputs "$INPUTS" --out work/research15-carriers \
  --native-objdump /usr/bin/objdump
python3 -B research/work-items/RE-002-std-clang-carriers/independent/check_carriers.py \
  --repo . --inputs "$INPUTS" --primary work/research15-carriers \
  --out work/research15-independent --native-objdump /usr/bin/objdump
HL_LIBCORE_ARCHIVE="$CORE" python3 -B -m unittest tests.test_libcore_fmt_correspondence -v
HL_LIBCORE_ARCHIVE="$CORE" python3 -O -B -m unittest tests.test_libcore_fmt_correspondence -v
python3 tools/libcore_fmt_correspondence.py \
  --core-archive "$CORE" --out work/research15-libcore
make doctor verify catalogue-check reproduce
```

All named output directories must be fresh. The independent command requires
the existing pyelftools 0.32 environment; the primary native commands require
the already installed LLVM reader. The 3.10 qualification used the same
commands with the actual Python 3.10.18 executable, and the carrier producer
also used `-O`. Raw successful command output is under `logs/`.
The six committed target/caller native listings remove only the absolute
repository prefix from the input-file header. `native-path-portability.json`
binds those portable copies to the unchanged raw output retained under ignored
`work/research15-carriers/`; instruction bytes and operands are unchanged.

All four light gates passed. The full integrated repository suite belongs to
the coordinator and was not rerun by this lane. No milestone or semantic gate
was advanced by this evidence receipt.
