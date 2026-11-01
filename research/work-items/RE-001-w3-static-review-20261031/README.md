# Review of w3-bounty static packets (2026-10-31)

Target: node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

These are bounded static evidence packets. No captured binary or instruction
emulator was run, no public artifact was downloaded, and no full-node recovery
or binary-equivalence gate is advanced. The original 89 changed Git blobs are
preserved byte-for-byte under `originals/`; historical negative controls are
retained under `historical-controls/`. Exact heads, files, hashes, limitations,
and review findings are in `review.json`.

The native audit cross-checks actual `.eh_frame` pc ranges with GNU readelf and
retains GNU objdump instruction-boundary and byte checks in `native-audit.json`.
Raw command output is retained in ignored
`work/pr-review-20261031/w3-static-review/`. Reproduce a listed range with GNU
`objdump -d -M intel --insn-width=16 --start-address=START --stop-address=END artifacts/node/94/hl-node`;
use `readelf -wf artifacts/node/94/hl-node` for actual FDE pc ranges.
The native provider was GNU binutils 2.47.20260726; Python validation uses real 3.10.18.

## Per-head findings

- **#226** `ad161cb7dde4e9e6246f831e5fba4c90c8600dee`: Three 88-entry RELATIVE name tables, 12 dispatcher arms and all first-call FDEs, 244-byte tail, branch sites and 96/104-byte copies agree with native instructions. Names remain an index-match inference; source-level tag meaning and callee semantics remain unproven.
- **#253** `616da138a3bd562494a2b5860b7cb6e798fad139`: u32/u64 slice gates, Reader tables/length checks/endian paths, raw error codes and all 35 cmp-reg-0xfb instruction starts match native decoding. Narrowed no-u16 conclusion to the explicitly measured length2-adjacent idiom; it cannot exclude other decoder shapes.
- **#262** `a43e8b066f7564a1c03b67169a01d9aea65dfa2e`: All three update calls read 0x800 bytes from producer output, separately from zeroed 0x810-byte scratch at rsp+0xa60. Corrected misleading buffer_zeroed_len to scratch/scratch_zeroed_len. Finalize outputs are replaced by 12 timestamp bytes before the 0x4ee3730 helper reads those 12 bytes, then memcpy 0xf8 replaces all 32 digest bytes before record assembly. This is a normal-return static dataflow result; timing-only purpose, producer meaning and runtime execution remain unproven.
- **#285** `4e016e0a146e61ecfe0d69b7013c604886086c0d`: Native writer, save-helper branch, map/array headers, JSON punctuation, three key strings and offsets corroborate both possible encodings. Which path predicate selects for the literal filename and field-value serialization remain excluded. Historical hashers.json control retained; current integration hash pin updated to reviewed base.
- **#316** `d71efa2b25abb108eea1932177d97268e6182a52`: Three actual leaf FDEs show six big-endian u16 modular-add loops, 1024 lanes and saturating u64 trailer additions; native/relocation checks confirm 3 selected BLAKE3-shaped slots and 53 reference sites. Independent algebra 393216 word-add and 10049 counter cases passed. Removed contradictory all-links-direct-call wording; only the four explicitly scanned reference forms are covered, no published-LtHash identity/security claim.
- **#332** `70d18f587a8125731f17acfa16c6a9b477061bf3`: Full 840-byte 147-instruction digest FDE hashes three 2048-byte lattice regions and copies 16-byte trailers into exact 144-byte output. Caller-A/B inspected windows support no observed downstream digest read; changed title to match the existing explicit unresolved pointer-escape caveat. No global discarded-digest proof or live BLAKE3 comparison.
- **#363** `ad119fcd2ec146d05ea5cbf5a9198f7d5c83db53`: Two unique RELATIVE bindings and five chain edges, observed copies 0x1b20/0x1b38/0x25e8 and normal-return branch counts 0/0/1 corroborated. Corrected whole-function wording: first-return windows 448/112/44 instructions exclude cleanup tails; actual unwind ends 0x3752b37/0x327082f/0x326e53b. No snapshot/export, copied-field meaning or full-callee behavior claim.
- **#381** `b0493b6e5f232e582daba48c6e29aaba53b6b867`: Actual FDE 0x3273810..327396c, state.rs:107 Location, loader call 0x3c155a0, result first-word 2 branch and later GOT 0x5773aa8 call agree with native instructions. Three-register/rawpayload paths observed; source Err identity/materializer semantics remain inferred.
- **#408** `603b2d5efb38040347d7c382a5d0da1af278b6cc`: All five four-pointer argument setups and six total ff15 sites match actual instruction starts and FDE owners. Added missing RDI definition at 0x2268f3f (lea rdi,[rbx+0x88]) to both verifiers/JSON and tamper coverage, bringing 39 pins. Buffer roles remain inferred and whole caller FDE semantics excluded.
- **#465** `db2b8b05a59af92e5a536810ba2d138a73f778a9`: Actual FDE 0x3c155a0..3c15c62 is 1730 bytes; excluded 14 padding bytes previously mistaken for body. Both parsers now read pc_range, with padding/range mutation controls. Native gate confirms ~/compare, absolute flag, helper-returned candidate exact-.. and three-byte ASCII-folded rmp suffix with nonempty stem; two decode arms and raw tag 2 observed. Whole path helper/filesystem/Err type semantics excluded.
- **#467** `ab81b4300f8a15283e43a77e2ccd940ac284fb07`: Actual FDEs 0x22ae8a0..22b107c(10204 bytes) and4546ba0..4546c51(177 bytes) exclude 4/15 padding bytes. Four ff15 slot 0x5773c70 calls and their path-pointer sources, unique RELATIVE target, preserved RSI/RDX and injected Location corroborated. Both parsers now use pc_range with negative controls. Full thunk error/unwrap behavior, filename identity and field producers are not claimed.
- **#595** `dd4835a060c3bf152c76f3a42cdabc2e95aac385`: Scoped cleanup removes personal local invocation/path prefixes from two existing packets. Merge retains current reviewed README semantics and source bindings, recomputing only conflicted manifest hashes. Original excerpts and all changed original blobs retained.

## Validation scope

Original exact-head tests and both packet verifiers were run before correction.
The four partial snapshots lacking referenced baseline JSONs were repaired using
blobs from those exact commits; original setup failures are preserved.
The integration uses the reviewed current hashers.json negative-control hash,
while retaining its historical counterpart. Updated packets regenerate from the
pinned target; no target evidence was altered. Final normal/optimized test,
compile, verify, catalogue and reproduction receipts are maintained in the
ignored review ledger after the branch is frozen. Full combined repository tests
are owned by the parent integration run.

## Independent review correction

Review of candidate `687eafa6ca6f8913ccfddb7771a4e6011cc94cbd` found a
missing-section error in the RE-019 independent FDE reader correction. FDE body
parsing now stays inside the matching `.eh_frame_hdr` branch, and a missing header
raises `KeyError`. A new negative control previously reproduced
`UnboundLocalError`. RE-020 wording now distinguishes the lookup table from the
actual FDE `pc_begin`/`pc_range` fields. The prior candidate remains in Git history
and the original failure is recorded in the ignored review evidence.
