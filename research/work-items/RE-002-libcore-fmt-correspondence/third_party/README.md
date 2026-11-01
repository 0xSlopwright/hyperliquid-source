# Official Rust artifact excerpts

The files under the evidence directories named `official/`, including the
historical preparation export, are small excerpts of the published
`rust-std-1.94.1-x86_64-unknown-linux-gnu` libcore artifact. Official-byte fields
in retained expectation/review JSON have the same attribution. The current
export also retains the notice/license. The adjacent metadata identifies every section/symbol/field.
The exact .rlib and member hashes are in `../UPSTREAM.json`. They are evidence,
not newly authored MIT implementation or a source build.

The Rust Project distributes this material under MIT OR Apache-2.0. This packet
elects **MIT** and retains the original complete 1,068-byte `LICENSE-MIT`,
including The Rust Project Contributors' copyright, permission and warranty
notice. No whole .rlib, object member, standard library or compiler is vendored.
The surrounding captured Hyperliquid bytes retain their original ownership;
this election does not apply the Rust license to the whole captured binary.

The source revision's `library/core/Cargo.toml` declares MIT OR Apache-2.0 and
version 0.0.0. The pinned `REUSE.toml` applies that dual-license choice to
`library/**`; its separate generated-Unicode exceptions do not describe the
selected fmt/panicking sections. Applicable source revision:
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. The archived notices and independently
checked metadata are recorded in the packet. Exact source/version/flags or
original compiler identity are not inferred from this license/provenance lead.

The installed research compiler and host headers are neither run nor copied by
this contribution. Their system licenses are not replaced by this MIT election.
