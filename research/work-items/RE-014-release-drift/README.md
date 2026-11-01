# RE-014: Which #94 functions survive into #115, and do the catalogue's missing paths match the binaries?

- Component ID: none (binary-wide release drift; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
  node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
  Every row carries both coordinates; no #94 address is reused for #115.
- Depends on: RE-001 (PR #2, head `191b83b`). Function extents come only from
  `tools/fde_extents.fde_extents`; this packet has no FDE decoder of its own.
- Claim status: observation (byte and instruction equality, catalogue path
  strings); inference (`changed` and `duplicate_ordered` pairings); unresolved
  (unmatched rows)
- Scope included: every `.text` FDE extent in both releases, and the
  `absent115` / `added115` path lists in `research/catalogue/components.json`.
- Scope excluded: behaviour, source attribution, `.rodata` contents, code with
  no FDE, split hot/cold reassembly. RE-014 is **not** complete.


## Portability (objdump)

Mutation controls (`mutation_controls.py`) use a **pure-Python** AT&T decoder for
the tiny x86-64 opcode subset they assemble. They do **not** shell out to
`objdump`, so they pass on macOS under LLVM objdump and on Linux under GNU
objdump alike.

`tools/release_drift.py` fingerprints still require **GNU** objdump (AT&T text
is the evidence input). `gnu_objdump()` inspects `objdump --version` for `GNU`
and returns `(None, reason)` otherwise. `verify.py` and `crosscheck.py` then
**SKIP with an explicit reason** (exit 2 / SystemExit) — they do **not** PASS
when the GNU verifier is unavailable. The retained JSON evidence was regenerated
with the fingerprint contract below under the pinned tool version,
`GNU objdump (GNU Binutils for Debian) 2.44`; `validation.json` pins that exact
string and `verify.py` refuses any other.
Drift-verify is only authoritative in the CI container (pinned GNU objdump 2.44); elsewhere it reports SKIPPED.

## Reproduce

Platform: Debian (box), Python 3.13, GNU objdump 2.44 (Debian). Static only;
no captured binary is executed. About 4 minutes and a single objdump stream
per binary.

```sh
make verify
make drift            # writes work/drift/node-94-115-drift{.tsv,.json} and -paths.json
python3 -I -B research/work-items/RE-014-release-drift/verify.py
python3 -O -B research/work-items/RE-014-release-drift/verify.py
python3 -I -B research/work-items/RE-014-release-drift/mutation_controls.py  # pure-Python; no objdump
python3 -O -B research/work-items/RE-014-release-drift/mutation_controls.py
python3 -I -B research/work-items/RE-014-release-drift/independent_verify.py
python3 -I -B research/work-items/RE-014-release-drift/crosscheck.py --tsv work/drift/node-94-115-drift.tsv
# optional, needs the independent cross-check CSV (not in the repo):
python3 -I -B research/work-items/RE-014-release-drift/reconcile.py work/drift/node-94-115-drift.tsv classification.csv
python3 -m unittest tests.test_release_drift
```

`tools/release_drift.py` verifies both artifact digests, takes `.text` FDE
extents from RE-001, disassembles `.text` once per binary with
`objdump -d --no-show-raw-insn -w -j .text`, and refuses to write into a
non-empty output directory. It fails closed on an extent with no decoded
instruction, and unless each binary is ET_DYN (PIE) with no `DT_TEXTREL` and
no `DF_TEXTREL`: that is what makes it safe to compare immediates verbatim. `verify.py` refuses to run unless the objdump version string
matches the pinned one, because disassembly text is the fingerprint input.

### Fingerprints and masking

Each extent gets two hashes:

- **raw**: SHA-256 of its file bytes.
- **masked**: SHA-256 over one line per instruction, `<length>\t<text>`, where
  the length is the distance to the next decoded instruction (capped at the
  extent end) and the text has only address-like operands masked. Every rewrite
  of objdump's text is counted (`masked_operands` in the summary):

| Rewrite | Replaced by | #94 | #115 |
| --- | --- | ---: | ---: |
| Direct branch/call to an FDE start | `@fde` | 496,825 | 558,403 |
| Direct branch/call into `.plt` | `@plt` | 107,390 | 113,386 |
| Direct branch/call elsewhere outside the extent | `@unknown` | 7,422 | 7,421 |
| RIP-relative displacement | `RIP` | 884,000 | 955,207 |
| Direct branch inside the extent (`branch_intra`) | `+<offset from extent start>` | 1,999,858 | 2,386,084 |
| objdump `<symbol>` annotation removed (`annot_symbol`) | nothing | 2,611,495 | 3,065,294 |
| objdump `# ...` comment removed (`annot_comment`) | nothing | 884,000 | 955,207 |

Only the first four replace an address. `verdict()` calls a pair `moved_only`
only when raw bytes differ, masked digests are equal **and** at least one of
those four was applied on either side; otherwise the pair is `changed`. The
annotations are objdump's rendering of an address that is already in the
operand (the `# ...` comment on these images is always the computed RIP target:
the comment count equals the RIP count). Whitespace runs are collapsed, which is
lossless for AT&T text; nothing else is rewritten.

#### Prefixes are kept (fix for closed PR #37)

PR #37 stripped a leading `notrack ` or `bnd ` and counted nothing, so
`ff e0` (`jmp *%rax`), `3e ff e0` (`notrack jmp *%rax`) and `f2 ff e0`
(`bnd jmp *%rax`) had the same masked digest with an empty mask counter and
`verdict()` called them `moved_only`. No prefix is stripped now. Audit of every
prefix class, against GNU objdump 2.44 `--no-show-raw-insn` text:

| Prefix bytes | How 2.44 prints it | #37 | Now |
| --- | --- | --- | --- |
| `3e` before indirect jmp/call | `notrack` | **stripped, uncounted** | kept |
| `f2` before jmp/call/ret/jcc | `bnd` | **stripped, uncounted** | kept |
| `f2` / `f3` (rep/repne) | `rep`, `repz`, `repnz`, or part of the mnemonic (`pause`, `movsd`, `popcnt`, `endbr64`) | kept | kept |
| `f0` lock | `lock` | kept | kept |
| `2e 36 3e 26 64 65` segment | `cs ss ds es fs gs`, or `%fs:` in the operand | kept | kept |
| `3e` / `2e` before jcc | `,pt` / `,pn` hint suffix | kept, but the branch target **was not masked** (regex missed it) | kept, target masked and counted |
| `66` data16 | `data16`, `w` suffix or 16-bit registers | kept | kept |
| `67` address-size | `addr32` or 32-bit address registers | kept | kept |
| REX `40`–`4f` | `rex`, `rex.WRXB` when redundant; otherwise in register names / `q` suffix | kept | kept |
| any prefix GNU does not print, or a different encoding length (`eb 00` vs `e9 00000000`, both `jmp`) | not visible in text | **invisible** | instruction length hashed |

Direct branches still match after any prefix mnemonic (`bnd call`, `ds call`,
`notrack bnd jmp`) and keep the prefix in the masked text (`bnd call @fde`).
One residual, stated rather than hidden: same-length alternate encodings that
objdump prints identically (`01 c3` and `03 d8` are both `add %eax,%ebx`) give
equal masked lines; in a function with no address mask that pair is `changed`,
and with an address mask elsewhere it can still be `moved_only`.

In these two binaries the fix changes no classification: regenerating with the
#37 code reproduces #37's committed hashes exactly (`3e5cc0de…` / `2d6a10f4…`),
and the new TSV differs from it only in the `masked-<digest>` evidence column of
210,036 unpaired rows; class, both starts and both sizes agree on all 233,324
rows. `.text` holds 176 `notrack` and no `bnd` instructions in each release.

Branches inside the extent keep their extent-relative offset. Immediates,
stack offsets and register choices are compared verbatim. In a PIE without
text relocations every image address in code is RIP-relative, so an immediate
is a constant. An earlier draft also masked immediates inside the mapped image
range; because these images map from `0x2e0` that hid real constants such as
frame sizes (`sub $0x348,%rsp` vs `sub $0x3d8,%rsp`), and the reconciliation
below caught it. The
target kind stays in the text, so retargeting a call from a function to the
PLT is a change. Only `call @fde` targets are used as call-graph edges;
unresolved targets are never guessed.

### Pairing and classes

Pairs are seeded by a hash unique on both sides (raw first, then masked), then
grown through the call graph: a callee or caller of a paired function is paired
when its masked hash is unique within that neighbourhood, or by call position
when both callee lists have the same length, the sizes are within 2× and
neither body has a masked twin anywhere on the other side.

Leftover functions with equal masked bodies (duplicate groups) are then paired
by address order, but only inside one gap between anchors: the anchors are the
longest chain of existing pairs that increases in both releases, and a group
is paired in a gap only when that gap holds the same number of its members on
each side. These pairs get their own class because which copy pairs with which
is an inference.

| Class | Meaning | Claim |
| --- | --- | --- |
| `identical` | paired, raw bytes equal | observation |
| `moved_only` | paired, raw differs, masked equal | observation (masked-only match) |
| `changed` | paired by call-graph position, masked differs | inference |
| `duplicate_ordered` | masked equal, paired by order within one anchor gap | inference (pairing); observation (masked equality) |
| `equivalent_unpaired` | a masked twin exists on the other side (possibly already paired), no pairing of its own | observation |
| `unmatched_94` / `unmatched_115` | no pairing and no masked twin | unresolved |

## Evidence

Generated outputs (byte-identical across two runs, `PYTHONHASHSEED=0` under
`-I -B` and `PYTHONHASHSEED=99` under `-O -B`; GNU objdump 2.44; SHA-256):

| File | Rows | SHA-256 |
| --- | ---: | --- |
| node-94-115-drift.tsv | 233,324 | `d6ad8ecd6c7db5046f99ca496bd131c0695920b940434a3a698da9dc51a773e6` |
| node-94-115-drift.json | — | `cd5b97a7d0eecfb5435bcbd326c4c34897386665df435ccae6bfe3bc334af551` |
| node-94-115-paths.json | 63 | `2510fca9ee11e3174fec9407377de8f1ad8e3a7254b96623d3e43a49e6441f9b` |

The 14 MB TSV stays in ignored `work/`. The summary and path results are
retained here, and `validation.json` pins all three hashes plus every count
below.

| Observation | #94 | #115 |
| --- | ---: | ---: |
| `.text` FDE extents (= RE-001 FDE records) | 121,299 | 135,313 |
| Instructions decoded inside extents | 15,730,149 | 18,827,581 |
| `identical` rows / bytes | 2,016 / 396,679 | 2,016 / 396,679 |
| `moved_only` rows / bytes | 14,608 / 8,039,647 | 14,608 / 8,039,647 |
| `changed` rows (inferred pairs) / bytes | 1,606 / 1,861,740 | 1,606 / 1,882,017 |
| `duplicate_ordered` rows / bytes | 5,058 / 637,831 | 5,058 / 637,831 |
| `equivalent_unpaired` rows / bytes | 41,386 / 5,916,192 | 44,306 / 6,785,593 |
| `unmatched` rows / bytes | 56,625 / 52,545,326 | 67,719 / 64,919,650 |

- **Uniquely paired masked matches are limited:** 16,624 FDE extents (8.44 MB, 12.2% of #94's
  69.40 MB of FDE-covered code) pair uniquely with equal masked text; only
  2,016 of them are byte-identical. For 14,608 of these pairs raw bytes differ while masked instruction text
  agrees; data references and alternate-encoding residuals remain unresolved.
  Another 5,058 (0.64 MB) pair by duplicate order.
- **Duplicates dominate the remainder:** 85,692 rows have a masked twin across
  releases but no pairing of their own (generic instantiations and small
  thunks), so they are counted, not paired.
- **Catalogue paths agree with the binaries:** a path matches only as
  `<crate>/src/<file>` at a path boundary (#94 embeds absolute
  home-directory build paths, #115 relative ones). All 28
  `absent115` paths occur in #94 and not #115; all 35 `added115` paths occur
  in #115 and not #94 (`node-94-115-paths.json`). A bare suffix match would
  have hit std's `/src/time.rs`; the boundary test is a unit-tested negative
  control.
- **Independent cross-check:** `crosscheck.py` takes every 97th
  `identical`, `moved_only`, `changed` and `duplicate_ordered` row
  (21 / 151 / 17 / 53). It slices
  bytes using `readelf -S` offsets rather than the tool, and disassembles
  each function separately with `objdump --start-address/--stop-address`.
  Every sampled `identical` row has equal bytes; every `moved_only` row has
  differing bytes, equal size and equal disassembly once every hex number is
  masked (a wider mask than the tool's); every `changed` row has differing
  bytes; every `duplicate_ordered` row has equal size, equal masked
  disassembly and byte equality exactly as its `raw_equal` column says.
  0 contradictions.

## Reconciliation with an independent classifier

A separate classifier written without this tool's code
(`classification.csv`, SHA-256
`27b7e51c819aa7a5b3bfde6a48ebbe0df31952849906193e02f53d9d5303f40f`, not in
the repo) takes ranges from `readelf -wf`, digests from
`objdump --insn-width=16`, and pairs raw groups, then norm groups (zipped by
address order), then shape groups (size and mnemonic sequence → `changed`),
then positional pairs between anchors (→ `changed_positional`).
`reconcile.py` reads only the class, `start_94` and `start_115` columns of
our TSV, and those are identical row for row between the #37 TSV and the
regenerated one, so `reconciliation.json` is unchanged. It joins on the #94 start: all 121,299 #94 rows
join, with none missing on either side. Every cell is retained in
`reconciliation.json`. "Their norm equal" counts our pairs that the other
classifier's own digest also calls equal.

| Ours → theirs | Rows | Same partner | Their norm equal on our pair | Why |
| --- | ---: | ---: | ---: | --- |
| identical → moved | 2,015 | 2,004 | 2,014 | agree; theirs needs the same address for `identical` (0 by construction) |
| moved_only → moved | 14,133 | 12,026 | 14,133 | agree; 2,107 other partners are duplicate assignment |
| duplicate_ordered → moved | 4,937 | 3,688 | 4,937 | agree on equality; partner choice among duplicates differs |
| changed → changed / changed_positional | 196 / 5 | 184 / 5 | 0 | agree; 12 partner conflicts, below |
| equivalent_unpaired → moved / removed / changed | 32,039 / 7,476 / 1,871 | — | — | definition: we do not pair duplicates outside one anchor gap; they zip by address order |
| moved_only / identical / duplicate_ordered → removed | 344 / 1 / 92 | — | 343 / 1 / 92 | duplicate assignment: their address-order zip gave our partner to another group member |
| moved_only / duplicate_ordered → changed | 131 / 29 | 72 / 1 | 49 / 28 | 77 duplicate assignment; 83 their masking (below) |
| changed → removed | 1,405 | — | 0 | matcher strength: our call-graph inference; their shape rule needs equal size and mnemonics |
| unmatched_94 → changed / changed_positional | 3,170 / 15 | — | — | matcher strength: their shape rule pairs bodies we leave unpaired |
| unmatched_94 → removed | 53,440 | — | — | agree |

What the reconciliation found and fixed here:

- **Our immediate masking was wrong.** Masking immediates inside the mapped
  image (from `0x2e0`) hid real constants, and because the #94 and #115 image
  ranges differ, one constant could be masked on one side only. Before the fix
  this produced 142 `unmatched_94 → moved` and 66 `moved_only → changed` rows
  (for example `sub $0x348,%rsp` vs `sub $0x3d8,%rsp` at
  `0x1400d30 → 0x155fa10`). Immediates are now compared verbatim behind the
  PIE/no-TEXTREL guard; a mutation control with in-range constants and a unit
  test cover it.
- **Call-position pairing could claim a duplicate.** 72 `changed → moved`
  rows were call-position pairs whose #94 side had a masked-equal twin in
  #115. Call-position pairing now skips any body with a masked twin; the cell
  is 0.
- **A copy of an already-paired body was called unmatched.** 187 rows were
  `unmatched_94` although their masked body exists in #115, paired to another
  #94 copy. They are now `equivalent_unpaired`; `unmatched_94 → moved` is 0.

What remains, explained but not changed:

- **Their masking is asymmetric (83 + 1 + 1 rows).** The other classifier
  masks immediates ≥ `0x10000` inside each binary's own LOAD span (#94 to
  `0x59b0e80`, #115 to `0x6728924`). A constant between the two ends, such as
  `0x5f5e100` (100,000,000) or `0x5f5e0ff`, is masked in #115 only. For all
  85 of our masked-equal pairs that their digest calls different, recomputing
  their digest with the #94 span on both sides makes them equal; none is
  unexplained. That classifier's directory was not modified.
- **12 `changed → changed` rows have different inferred partners.** We pair
  by call position; they pair the same-size, same-mnemonic body by address
  order. Both sides label these as inferences, and neither result is an
  observation. 5 of our partners differ in size from the #94 function (for
  example 602 → 355 bytes), so their partner may be the better guess. For one
  row (`0x3c97270`) their partner is already our `moved_only` partner of
  another #94 function.
- **Matcher strength.** 1,405 `changed → removed` rows are our inferences that
  their shape rule cannot make, and 3,185 `unmatched_94 → changed*` rows are
  theirs that ours does not make. Neither is an observation.

## Implementation and comparison

No Rust implementation; deterministic offline tooling and static observation.

- `mutation_controls.py` assembles a C→A→B call chain, decodes the real
  bytes with its own pure-Python AT&T decoder (no objdump or readelf; the
  GNU tools are only an optional cross-check in `crosscheck.py` and
  `verify.py`, which skip with a reason on non-GNU) and mutates the #115 side. The checks are: moving B
  gives `moved_only` for A; changing an instruction, a constant (including
  one inside the code's address range on both sides), or a call
  target (to non-FDE code or to the PLT) gives `changed`; an added function
  gives `unmatched_115`; no mutation gives all `identical`. Nine prefix
  cases end B with `ff e0`, `3e ff e0` or `f2 ff e0` on each side: the six
  cross pairs must be `changed` and the three same-bytes pairs `identical`.
  Under the #37 normalize the six cross pairs come out `moved_only`.
- `tests/test_release_drift.py` checks that the three `jmp *%rax` encodings
  give three masked digests and `changed`; that the same bytes give
  `identical`; that every prefix mnemonic class stays in the text; that
  prefixed direct branches and `,pt`/`,pn` hints are masked with the prefix
  kept; that `eb 00` and `e9 00000000` differ; and that a text-equal pair with
  no address mask is `changed`. It also adds negative controls: immediates and stack
  offsets are never masked, even inside the image range; duplicate masked
  hashes never get a hash-match class, and duplicates split across anchor gaps
  or with unequal counts stay unpaired; call position never claims a body with
  a masked twin; non-PIE or text-relocated inputs fail closed; the 2× size bound rejects a 201-byte partner of a 100-byte function;
  a path only behind a non-boundary byte does not match; an empty extent
  fails closed; output bytes are independent of input order and of
  `PYTHONHASHSEED` (0, 1, 4242).
- Nine deliberate tool mutations each fail the unit tests: masking every
  immediate, merging branch-target kinds, dropping call-position pairing,
  dropping the twin guard, dropping the per-gap count check, ignoring text
  relocations, dropping intra-extent branch offsets, not masking RIP
  displacements, and counting twins among unpaired rows only. The first three
  also fail `mutation_controls.py`.
- `verify.py` rebuilds into a temporary directory and checks the three output
  hashes, the retained files, 11 pinned summary values, the cross-check result
  and the mutation controls. It uses no `assert` and passes under `-I -B`
  and `-O -B`.

## Results and limitations

What this does not claim:

- **Not behavioural equivalence.** `moved_only` compares instruction text
  with addresses masked. Data behind a RIP-relative or image address is not
  compared, so a changed `.rodata` constant can still be `moved_only`.
- **`duplicate_ordered` pairs are inferred.** The bodies are equal after
  masking; which copy pairs with which is a guess by address order.
- **`changed` pairs are inferred** from call-graph position and size, not
  proven to be the same source function.
- **Unmatched is not added or removed.** A function can be unmatched because
  it changed and has no paired neighbour, was inlined differently, or was
  split differently.
- **An FDE is not a function.** Split hot/cold parts are separate rows and code
  without unwind data is absent (RE-001 limits apply). objdump's linear sweep
  can mis-decode data inside `.text`.
- **Path rows describe embedded strings only,** not code ownership. No
  progress gate is requested; every component gate stays false.

Optional, not required by this packet: REA 6.8.0 `rea-doctor` and
`rea-smoke` pass statically for both releases. A Ghidra function-matching pass
could check a sample of `changed` pairs independently.

Next question: for the 1,606 inferred `changed` pairs, which differ only in
`.rodata`-referenced data or inlining? Which of the 56,625 unmatched #94
functions sit under the 28 `absent115` source paths?

## Review correction: retain mnemonics in the independent spot-check

PR #1123's original `crosscheck.py` applied its broad hexadecimal regex to an
entire disassembly line. As a result `adc` and `add` could both become `N`;
`review-original-crosscheck.json` retains that counterexample. The spot-check
now preserves prefixes and the instruction mnemonic before masking only its
operand text. A regression covers hex-letter mnemonics, prefixes and bare
hexadecimal branch operands. This remains a broader mask than the primary
fingerprint and establishes only the listed sampled invariants.

The original crosscheck, tests, README and manifest are archived with the exact
head binding in `original-submission/`. Primary fingerprints and retained target
exports are unchanged. Review on GNU objdump 2.47.20260726 reproduced all class,
byte, instruction, extent and mask counts and the paths output, but the TSV and
summary hashes differ from the pinned Debian2.44 run. That raw host comparison
is kept separately under ignored work; the exact2.44 verifier correctly skips
on this host and its guard remains intact. This is not an exact pinned-recipe
or hosted-CI pass. The optional external classifier CSV remains unavailable.
`independent_verify.py` independently checks retained hashes/counts and decodes
one unchanged synthetic layout, but delegates mutation classifications to the
primary implementation; it is not an independent whole-binary classifier.
