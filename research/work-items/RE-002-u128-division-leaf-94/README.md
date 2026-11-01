# RE-002: node94's complete unsigned-division leaf matches compiler-builtins

Task/component: RE-002 compiler/runtime attribution, supporting the existing
RE-004 wide-integer arithmetic packets. Target: captured Linux x86-64 node94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Addresses below are ELF virtual addresses before load bias.
Source baseline: `4179e174f58ea877cb803abece4a3842c614daf3`.

The bounded question is whether the complete helper at `0x565f5a0`, selected by
slot `0x576e1a8`, can be identified with an authenticated named compiler artifact.
The answer is a raw match of all **198/198 bytes**, without normalization, to
both defined `__udivti3` candidates in the pinned official compiler-builtins
archive. This is one runtime dependency, not a recovered fee engine or a new
Rust implementation.

## Existing gap and resulting evidence

The accepted [spot-scale packet](../RE-004-spot-wei-scale-family-94/README.md)
explicitly called this helper's division behavior an inference from call shape;
it did not evaluate the helper. The accepted
[L1 transfer-fee packet](../RE-004-l1-evm-transfer-fee-94/README.md) and
[priority-cost packet](../RE-004-priority-native-cost-94/README.md) ran helper rows
on finite inputs, while their broader claims assumed its division semantics.
Those packets are preserved. This packet supplies a complete, zero-mask named
artifact correspondence for their shared leaf. It does not enlarge their caller
or whole-domain numerical claims.

The unique intersecting FDE is exactly `[0x565f5a0,0x565f666)`, 198 bytes. The
complete body has one consistent executable section/PT_LOAD file mapping. The
entire eight-byte slot has a separate valid mapping and exactly one symbol-zero
`R_X86_64_RELATIVE` record with addend `0x565f5a0`. No dynamic relocation overlaps
the leaf. The retained complete native listing has no calls or RIP-relative data
loads; memory operations are the conditional RBX save/restore and returns.
Thus no external callee or static-data identity is hidden by a code mask. This
observation does not specify the surrounding stack/exception environment.

## Official artifact and complete candidate set

The already-authenticated official Rust 1.94.1 x86_64-unknown-linux-gnu standard
library distribution contains:

- archive `libcompiler_builtins-58c8d4715a55733a.rlib`, 4,400,606 bytes,
  SHA-256 `f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6`;
- member suffix `cgu.019.rcgu.o`, 41,864 bytes, SHA-256
  `cef03767df991d42e3ad613ff963a7878ea17d2962d038f40774bcd80fee826d`,
  defining the hidden global FUNC
  `_ZN17compiler_builtins3int4udiv9__udivti317h7f7f8794247d2394E`;
- member suffix `cgu.129.rcgu.o`, 9,672 bytes, SHA-256
  `cc3613e3e208e899fdfeca485bcdf23a59dbac31eefae9c312ddb5a162294861`,
  defining the hidden weak FUNC `__udivti3`.

The complete member prefix is recorded in `observed/record.json`. Each function
covers its entire 198-byte executable PROGBITS section and has **no code RELA**.
Debug/unwind relocations elsewhere in the objects are not erased or credited as
code matches. Both raw bodies and the capture have SHA-256
`45f632dd0c1fc0915e680ad7ad98cabda1fcf34ba7835c2e73e3569b570a288d`.

The producer scans all 301 named archive members, retaining all six symbol
records whose names contain `__udivti3`: two definitions and four undefined
references. It requires the complete two-definition set rather than selecting a
convenient member. It preserves raw offsets of any byte differences and uses no
normalization fields. Whole objects, archive metadata, DWARF, unwind data and
whole ELF files are not claimed equal.

## Source and rights witnesses

The official member's DWARF strings name the compiler-builtins `int::udiv`
module and `u128_div_rem`; the artifact has a defined symbol, not just a guessed
function label. At the documented distribution revision
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, the
[official source declaration](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/compiler-builtins/compiler-builtins/src/int/udiv.rs)
labels `__udivti3(n: u128, d: u128)` as returning `n / d`. This is a source
provenance witness; this contribution does not independently prove every input's
quotient or reconstruct the original ABI. No can1357 implementation is copied.

The crate is **not MIT-only**. Its official manifest states
`MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)`.
The complete, unmodified upstream
[license](third_party/LICENSE-compiler-builtins.txt) accompanies the 198-byte
official excerpt. The manifest/source/license Git blob identities and source
URLs are in `SOURCE-PROVENANCE.json`. New producer/tests/documentation are
independently authored under the repository's MIT terms; imported excerpts keep
their upstream terms.

This uses an existing published standard-library artifact. It does not build
compiler-builtins from Rust source, identify the original node compiler, or
claim that its entire toolchain/archive/link context matches the node.

## Reproduction and controls

No compiler, object loader, captured executable or instruction evaluator is
called. The collector has no subprocess or download path. Supply the local
pinned official artifact explicitly:

```sh
python3 -B tools/u128_division_leaf.py \
  --binary artifacts/node/94/hl-node \
  --builtins /path/to/libcompiler_builtins-58c8d4715a55733a.rlib \
  --output /tmp/new-division-leaf-output
python3 -B -m unittest discover -s tests -p test_u128_division_leaf.py -v
```

`analyze` hashes and parses the same immutable full-input byte objects. It grants
pinned-input origin only after full size/digest admission. The `inspect_*`
counterfactual seams always return unqualified origin; their standalone use is
not artifact authentication. Existing output paths, including broken symlinks,
are refused before input reads.

Independent review first reproduced a structural seam error: an extra SHT_RELA
record in another table could target the same slot while the original checker
reported only the `.rela.dyn` record. The preserved before-fix control is in
`preparation/SLOT-UNIQUENESS-BEFORE.json`. The corrected inspector rejects every
duplicate or partially overlapping selected eight-byte write across all RELA
tables, while requiring the one exact `.rela.dyn` record. This is a structural
uniqueness check, not a claim that every arbitrary ELF relocation table would be
loaded at runtime. No maintained generic ELF parser was changed.

The twelve portable tests use explicitly rebuilt small ELF containers around the
licensed excerpt. They check full FDE boundaries, executable PT_LOAD consistency,
all eight mapped slot bytes, relocation type/symbol/addend, symbol
binding/type/visibility/extent, unexpected definitions, aliases, code relocations
and an unmasked opcode change. These tiny containers are **not** authentic target
or whole compiler objects. Separate actual full-input validation and independent
corruption receipts are identified in `VALIDATION.json`; neither kind of evidence
is substituted for the other.

The retained native listing can be reproduced from the emitted 198-byte slice:

```sh
objdump -D -b binary -m i386:x86-64 -Mintel --adjust-vma=0x565f5a0 \
  /tmp/new-division-leaf-output/target-198.bin
```

## Limits and next step

All progress gates remain false. This resolves the concrete helper identity
relative to the named pinned artifact, leaving the existing callers' guards,
units, error handling, state effects and ABI obligations as their own work.
There is no full fee-engine, full-node, source-build, compiler-origin or
whole-ELF claim. Zero-divisor exception handling and an independent all-input
mathematical proof are not established by this correspondence. A later caller
proof can cite this exact dependency instead of relying only on its inferred
label, while still stating its numerical and environment assumptions.
