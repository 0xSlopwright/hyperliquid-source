# RE-001 / foundation: specialized 20-byte table hash

Question: what math does the address-labelled table-hash helper apply to a fixed
20-byte message and two supplied seed words? Scope: fresh-writer specialization,
captured arithmetic interpreter, independent math/control tests and this packet.
No sub-account address derivation, signing, cryptographic API or progress gate.

Target node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `308e5127990217a9d6196992665da6ca1afd4b82`.
Unlicensed reference can1357-hl revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`,
`l1/exchange/impl_create_sub_account.rs`, identifies a `hash_user_address` seed.
That name is a lead, not copied implementation or proof of address derivation.

## Observations

ELF virtual addresses, no masks. Actual FDEs: caller `0x2840fb0..0x28410f5`
(325 bytes / 83 instructions), writer `0x288e280..0x288e457` (471 bytes /
141 instructions). Complete exports total **796 bytes / 224 instructions**, with
raw FDE/CIE, hashes and selected arithmetic/path boundaries. The denominator is
complete disassembly, not full generic-writer semantic coverage.

The caller loads two seed words, uses PSHUFD to duplicate each into paired lanes,
and XORs four captured constants into state order v0/v2/v1/v3. Length/tail fields
start at zero. Its writer call receives length **20**. On this fresh fixed-length
path, the writer processes two little-endian 8-byte words with one compression
round each and retains a four-byte tail. The caller combines length 20 in the
high byte with that tail, compresses once, XORs 0xff into the finalization state,
and performs three final rounds before combining four words into the u64 result.

The independently authored bounded interpreter executes the actual register
arithmetic at `0x288e3a4..0x288e3da` and caller finalization at
`0x2841003..0x28410f0`, with synthetic registers/stack. It rejects unknown
opcodes, unset reads and unmapped stack accesses. Initial shuffles, fixed-length
writer loop/tail selection and memory-state packing are byte-bound specialized
lowerings, not claims that all generic writer instructions are interpreted.

The resulting fixed-domain math matches SipHash-1-3. Rust's
[public SipHash source](https://doc.rust-lang.org/src/core/hash/sip.rs.html)
provides algorithm-name/round context; it is not evidence for the captured
binary's exact Rust/library version. The independent math was authored from the
target's operations, not copied from the unlicensed reference or public Rust code.

## Limits and before/after

All seeds and messages used here are explicit synthetic fixtures. No runtime
seed, credential, wallet material, address state or captured function is read or
executed. Original caller ownership, runtime seed selection, broader table API,
incremental writes/nonzero initial tails and other message lengths are unclosed.
Before: an address-hash seed without a measured fixed-domain algorithm. After:
exact fresh 20-byte math, round/tail paths and an actual-arithmetic differential.
Next question: map caller seed provenance and the generic incremental writer
before assigning a complete hash-table interface or library identity.

## Reproduce and controls

Python 3.12.14, static stdlib ELF readers and a synthetic instruction interpreter.
Optional Capstone 5.0.6 x86-64 Intel complete export; no native target execution.

```
python tools/address_hash20.py --out research/work-items/RE-001-address-hash20-94/records.json
python research/work-items/RE-001-address-hash20-94/export_disassembly.py
python -m unittest tests.test_address_hash20 -v
```

Six focused methods pass in 3.764 seconds. **20,480** declared synthetic
seed/message-byte cases compare actual arithmetic with independent fixed-length
SipHash-1-3 math, plus zero/ff/tail boundaries. The regression value for seed
(0,0), bytes 0..19 is an observed interpreted fixture, not a claimed native Rust
test vector. Changing actual compression/finalization rotations changes the hash
and binding checks reject the mutated capture. Other controls cover constants,
initialization, length/loop/tail, unsupported instructions, both FDEs and identity.
Make is unavailable; required Python commands ran directly on base
308e5127990217a9d6196992665da6ca1afd4b82 with these added files. Full suite:
**2,003 tests in 563.730 seconds; 23 failures, 38 errors, 112 skips**.
The six new methods pass. Failures include Windows path/newline expectations,
launcher/binutils assumptions and unavailable prerequisites; this is not a clean
baseline and not all existing failures have been diagnosed. Doctor exits 1.
Eight artifact sizes/digests pass before missing GPG blocks signatures (exit 1).
Imports reject the modified Windows reference checkout (exit 1); catalogue-check
reports stale research/catalogue/components.json (exit 1). Reproduce stops at
artifact verification (exit 1). No generated catalogue/import/pin was changed.
No full-suite/signature/hosted-CI, native Rust/vector or native-equivalence
success is claimed.
