# RE-005 / RE-009: complete scanner bounds and candidate-search performance

Review base: `da97c34d6fa24600672bf74653a9af0f582b6cdb`.
Target: node94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Scope: bincode slow-reader indirect-call scanner and its independent verifier,
and the LtHash independent reference scanner. No captured execution, downloads,
full repository suite, generated catalogue/progress edits or reconstruction
milestone claims. Main `lthash_mechanism.py` already used candidate searches
with complete bounds and is unchanged.

## Defect and correction

The bincode implementations used `range(len(text)-6)` for six-byte `ff15`
candidates. The LtHash independent verifier used `range(len(text)-5)` for
five-byte `e8/e9` and six-byte `8d` patterns. These loops visited every text
byte in Python, with the bincode loops allocating a two-byte slice each time.
They also omitted the final complete six-byte indirect call or five-byte
direct call/jump respectively.

The corrected loops use `bytes.find`, advancing by **one byte** after each
candidate. They decode only candidates with `i+width <= len(text)`. This
retains starts inside another candidate's displacement, signed rel32 values,
byte-pattern false positives, relocation handling and sorted result order.
No native instruction-boundary filter or known-address shortcut was added.
The independent bincode count loop is isolated into `reader_call_counts` for
direct boundary testing and still imports no production scanner.

Node94 has 70,370,352 `.text` bytes, with 361,350 `ff15` candidates and
2,462,766 combined `e8/e9/8d` opcode bytes. The corrected loops visit these
candidates in Python rather than every offset. `target-scan-domain.json`
records the authenticated dimensions and opcode counts. Native GNU disassembly
of the final 16 bytes confirms a real final-fitting jump at `0x56600ab` to
`0x5661240`. The former independent loop omitted it. Its target is outside
the pinned LtHash closure, so correcting the domain does not change this
packet's output. This observation does not assert new function ownership.

`before-boundaries.log` retains the initial six-test run: four failures and
three subtest errors, caused by missing final candidates. All six tests pass
after correction, including overlapping candidates and truncated tails.
Original source, packet manifests and JSON exports are preserved byte-for-byte
under `original/`, with the base commit and hashes in `original/SOURCE.json`.
Current packet manifests bind the corrected independent verifiers. Output
hashes were not changed to suppress a discrepancy.

## Validation

Fresh generators and independent verifiers pass on the authenticated target:

| Check | Time | Result |
| --- | --- | --- |
| Bincode generator | 5.953s | identical `slow-sites.json` |
| LtHash generator | 2.150s | identical `lthash-mechanism.json` |
| Bincode independent verifier | 5.635s | pass |
| LtHash independent verifier | 0.931s | pass |
| Affected modules + new boundaries | 49 tests / 150.450s | pass, no skips |
| Same with `-O` | 49 tests / 150.761s | pass, no skips |
| doctor / verify / catalogue-check / reproduce | exit 0 | pass |

The unchanged full-text GNU disassembly check, all original corruption tests,
all hash-seed/optimization controls and the frozen fast-path JSON check remain
in the affected suites. Raw log receipts and regeneration hashes are retained
here. Local-path masks and one trailing-whitespace removal are documented in `log-normalization.json`; raw
local logs remain under `work/pr-review-20261031/`.

Unchanged output SHA-256 values:

- Bincode: `c974cce1fb38ef48235890eeec8eaf5a57ee2738499f1baef847c33594702688`.
- LtHash: `fd44957c759ec48f8499ac966e89cfab7c92a5405ab3087a1476df3897b9339e`.

`synthetic_benchmark.py` compares the three actual corrected implementations
against complete-offset brute-force versions of the archived original loops.
It changes only the reference loop endpoints, which the dedicated before/after
tests establish independently. The 2,671 fixtures produce 8,013 exact results,
covering every offset of small buffers, all 256 ModRM bytes, signed rel32
extremes, interior/overlapping candidates, truncation and relocation records.
The original LtHash byte scanner's `site=i-1` convention for a LEA candidate
is retained, including its limitations; this performance repair does not
reclassify byte candidates as native instructions.

Measured synthetic medians are in `benchmark.json`. On uniform 1MiB buffers,
bincode was 63.65x and LtHash 8.84x faster in that run. Sparse buffers improve
more; dense overlapping 32KiB buffers were 1.19x and 0.88x respectively.
These are scanner microbenchmarks, not a measured full-suite speedup. No
quadratic algorithm was found here: the costly pattern was repeated linear
whole-text Python work, repeated copies and full generation in multiple tests.
The production LtHash generator already used candidate searches. Its
independent reference scan runs repeatedly across injected/lost-reference
controls; those controls were preserved.

An intermediate benchmark-harness attempt failed because the per-fixture
expected-count map was stale (`14 != 0`); the harness was corrected and all
final comparisons rerun. This was a synthetic harness setup error, not a target
output mismatch. Its diagnostic is retained separately from the original
scanner failures.

Reproduction from repository root (GNU objdump must be selected on PATH):

```bash
python3 -B research/work-items/RE-005-RE-009-scanner-bounds-performance/synthetic_benchmark.py
python3 -B -m unittest tests.test_bincode_varint_slow tests.test_lthash_mechanism tests.test_static_scanner_boundaries -v
python3 -O -B -m unittest tests.test_bincode_varint_slow tests.test_lthash_mechanism tests.test_static_scanner_boundaries -v
make doctor verify catalogue-check reproduce
```

The benchmark rewrites its local measurement JSON only; timings vary by host.
Full integration validation remains the root review's responsibility.
