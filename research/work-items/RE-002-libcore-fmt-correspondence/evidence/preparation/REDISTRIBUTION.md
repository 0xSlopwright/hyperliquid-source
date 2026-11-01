# Rust 1.94.1 precompiled libcore excerpts: rights and provenance

The already-admitted official `rust-std-1.94.1-x86_64-unknown-linux-gnu`
archive independently rehashes to
`74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03`.
Its embedded `libcore-e60dd2ab51fbc7de.rlib` is exactly the installed
2,917,630-byte archive, SHA-256
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`.
The actual ar member
`core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o`
is 2,871,296 bytes, SHA-256
`57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`,
and matches the existing extracted member. Header/section checks also bind the
444-byte formatter section, its actual216-byte/nine-record RELA section and
the selected200-byte table,24-byte Location and61-byte panic helper excerpts.
No new whole-member copy, object execution, native snapshot or compiler job
was used in this audit.

The distribution identifies release1.94.1 and source commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. Its actual archive supplies
`LICENSE-MIT`, `LICENSE-APACHE` and `COPYRIGHT`; the last explicitly permits
Apache2.0 **or** MIT at the recipient's option, except stated exceptions.
The same immutable upstream commit's `library/core/Cargo.toml` declares
`license = "MIT OR Apache-2.0"`. Its package version is **0.0.0**:1.94.1 is
this Rust distribution version, not an invented crates.io `core` version.
The pinned REUSE metadata applies `MIT or Apache-2.0` to `library/**`;
its only core-specific exception is the separate Unicode data file, not the
selected fmt/panicking material. The admitted generated standard-library
copyright notice corroborates that default and exception. No fmt source
implementation was fetched or read.

## Minimal route for the selected official artifact excerpts

Choose the **MIT option** explicitly. Ship the original complete1,068-byte
`LICENSE-MIT` with the excerpts, preserving its
`Copyright (c) The Rust Project Contributors` notice, permission and warranty
text. A single adjacent license file can cover a clearly enumerated set of
binary sections, relocation records and their textual representations.
Keep Rust attribution distinct from new project-authored MIT analysis/code;
the project's own copyright/license file alone does not replace that notice.
Do not decide the excerpts are exempt merely because they are short or data.

A short third-party notice should identify the release/source commit,
official distribution URL, the outer/core/member SHA-256 values, exact
section names/indices and selected ranges, and say that the MIT option is
used. Preserve original bytes and clearly identify derived comparison,
relocation rendering or counterfactual files separately. These exact identity
fields are project provenance requirements and useful attribution; the
literal MIT redistribution condition itself is the retained copyright and
permission notice. `COPYRIGHT` is useful supporting evidence; retaining both
original license options is also fine, but Apache text is not an additional
requirement when the MIT option is selected for this default-licensed subset.
No source publication or source rebuild is required by that MIT grant.

If instead choosing Apache2.0, provide its complete license and meet section4:
mark modified files prominently, retain relevant source notices, and carry
relevant NOTICE attribution if one is supplied. The81-member rust-std archive
has no file named NOTICE. This does not waive separate notices for unrelated
third-party content. Prefer the simple MIT route for the scoped default-
licensed fmt/panicking excerpts and keep the supplied original notices intact.

Do not vendor the whole2.87MB core object,2.92MB rlib or compiler as a
substitute for independently authored recovery. The whole object/library
contains more than this selected material and can carry other notice duties.
This audit covers the official licensed artifact excerpts. It does not grant
rights over the entire captured Hyperliquid binary or relicense captured
reference bytes as new project code.

## Technical claim limits

This is a **published precompiled artifact correspondence** constraint.
The reported444-byte comparison has408 equal non-relocation bytes and36
raw differing bytes in nine actual4-byte relocation fields; it is not a raw
whole-body match. The root's relocation targets/data/helper qualification is
separate from this rights audit. No source build was reproduced, no original
compiler/flags/archive/fork/version is uniquely inferred, and no original
Hyperliquid source or whole-ELF identity follows. The existing download receipt
records TLS and official SHA sidecar matching; this audit rehashes those local
bytes. It does not claim an independently checked release signature.
