# RE-003: report measured bytes independently of module completion

- Component: foundation (shared dependency comparisons); other components are
  unmeasured. No first-party ownership is inferred from these shared windows.
- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Separate node #115: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7194e50b54c6cea3380f2e78d6edfe6fd73cc7bb`; reference and
  imported evidence pins are unchanged.
- Bounded question: how many retained compiled-source bytes and complete
  comparison windows match each target, separately from full-module gates?
- Status: observed byte equality for selected windows; whole-module byte
  denominators, semantics and full identity remain unresolved.

## Reporting blocker and scope

The user requested per-module byte percentages alongside module completion.
The previous generated dashboard reported zero credited bodies and a pending
comparator, although reviewed libcore and Zstandard packets already retained
compiled comparisons. Its input model had neither a byte denominator nor a
deduplicated registry of those comparisons. The change adds that accounting to
the existing catalogue generator, without changing any reconstruction or gate.

The registry contains 11 unique ELF VA intervals: eight for the baseline and
three for the later comparison. It pins 13 existing source/evidence files,
their full target identities, source excerpt identities and reviewed boundary
bases. Sources are published native artifacts, a published-bitcode rebuild and
licensed assembly builds. This is not newly recovered first-party Rust.
Original source/compiler provenance and limitations remain in the linked
packets. No upstream material or original negative result is modified.

## Reproduce

From the repository root with Python 3.13.2, GnuPG and the pinned inputs hydrated:

```sh
make doctor verify
make catalogue catalogue-check reproduce
python3 -m unittest discover -s tests -p test_byte_progress.py -v
python3 -m unittest discover -s tests -p 'test_catalogue*.py' -v
python3 -m unittest discover -s tests -p test_research_tools.py -v
make test
```

The full suite uses installed GNU binutils 2.47 and LLVM on PATH, with the
existing Rust toolchains. The reporting operation only parses static files;
it does not launch captured node/visor code, compile new candidates, run a
container, contact the chain or create a Ghidra project. Provider-dependent
qualification retained in the original evidence is not a fresh provider run.

## Evidence and calculations

[`research/byte-windows.json`](../../byte-windows.json) records each interval,
source excerpt, hash and original evidence. Generated
[`byte-coverage.json`](../../catalogue/byte-coverage.json) retains every raw
difference offset and every non-relocation difference offset, as well as byte
and window totals. A generation failure on changed inputs prevents silently
publishing stale counts.

- Raw byte percentage: sum of equal byte positions / sum of compared bytes.
  This weights by bytes, not by an average of window percentages.
- Raw window percentage: entirely equal windows / compared windows.
- Raw plus relocation-qualified window percentage: windows equal outside
  actual recorded PC32/GOTPCREL fields / compared windows. Only four-byte
  fields with addend -4 are admitted. Excluded fields are not credited as raw
  equality; they remain unresolved in this metric.
- Module completion: all four full-scope gates must pass. The selected
  comparisons neither supply complete module sizes nor advance these gates.

The reviewed ThinLTO adapter replaces the older native candidate for the same
622-byte interval. The original candidate's two non-relocation differences
at offsets 464 and 467 are preserved in the registry and its source packet.
Repeated builds and alternative candidates do not add windows or bytes.
The 61-byte panic and 95-byte character callees are counted once without
rewriting the source packets' distinct primary/supporting denominators.
Zstandard uses source labels and a complete compiled section endpoint; no
function sizes or FDEs are inferred for those two windows.

Node #115's 630-byte adapter has an extent mismatch with the 622-byte candidate;
it has no admitted comparison and contributes no compared bytes. Its parent
and two Zstandard comparisons are reported separately from baseline totals.
One parent relocation byte happens to match raw; that is why 355/390 raw
matching positions coexist with 354/354 non-relocation matching positions.

## Results and remaining limits

| Target | Raw matching bytes | Raw-equal windows | Raw + relocation-qualified windows | Compared / .text |
| --- | ---: | ---: | ---: | ---: |
| Node #94 | 4,386/4,478 (97.95%) | 3/8 (37.50%) | 8/8 (100.00%) | 4,478/70,370,352 (0.00636%) |
| Node #115, separate | 2,773/2,808 (98.75%) | 2/3 (66.67%) | 3/3 (100.00%) | 2,808/83,719,936 (0.00335%) |

Whole-module byte completion remains unknown for all 24 modules. The baseline
raw-equal positions occupy only 0.00623% of `.text`; a 97.95% match inside the
selected windows is not node completion. All 96 acceptance gates remain false,
so fully completed modules remain 0/24 (0%). Behavioral implementations,
disassembly agreement and equal self-rebuilds are not machine-byte credit.
Helpers, dynamic calls, data/vtables, ABI and whole-ELF closure remain open.

Accounting controls cover weighted arithmetic, raw versus masked differences,
invalid masks, duplicate/overlapping intervals, target separation, changed
target/source hashes, missing/outside files and truncated excerpts. Existing
catalogue fixture tests exclude the real registry when using synthetic ELF
inputs; the dedicated comparison tests exercise both synthetic and actual
authenticated targets. Validation results are recorded in `validation.json`.

All 874 test files were run with the same per-file unittest commands as
`make test`, scheduled as eight isolated subprocesses after interrupting the
serial invocation. They reported 13,767 tests with 60 skips. One source-walk
fixture initially omitted the new registry; its three-test rerun passes after
the fixture repair, leaving no unresolved failures. The skip record preserves
unavailable exact providers/artifacts and unauthorized captured-code execution
as unqualified. Doctor, verification, catalogue consistency and reproduction
checks pass. Hosted CI is separate.

Next question: establish a target-bound first-party component inventory and
compare independently reconstructed code over that declared scope; do not use
the unwind index or source-file counts as a module-byte denominator.
