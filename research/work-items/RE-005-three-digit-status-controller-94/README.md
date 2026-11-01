# RE-005: node94 `:status` dispatch and ordered pre-callback stores

The caller at `0x1682220` reaches the established three-digit parser exactly for a seven-byte key containing `:status`, under the ordinary valid-memory/control domain below. A nonzero parse result produces a WORD store followed by tag byte 7; a zero result produces a BYTE store followed by tag byte 8. These are observations before two unresolved dynamic callbacks, rather than a guarantee about returned memory.

This closes the bounded caller-selection/result-use questions left open by [PR627](https://github.com/lalalune/hyperliquid-source/pull/627). The existing [85-byte leaf and its Rust reconstruction](https://github.com/lalalune/hyperliquid-source/pull/1194) are prior work. That packet already retained the 31-byte successful-call context; this contribution adds the complete key selector, actual six-entry table, invalid-result store width/order and explicit later-call boundary. It introduces no Rust component or stage API.

- Component/task: RE-005, foundation parsing and selected caller control/data flow.
- Target: node94, full SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source context: `4179e174f58ea877cb803abece4a3842c614daf3`. Latest-main qualification is metadata-only; it does not claim the complete moving-main source was executed.
- New code/docs are MIT; small captured instruction/data evidence keeps its existing artifact status. No inferred reference implementation was read or copied.
- No component/progress gate changes, captured execution, emulator, compiler, live service or chain action.

## New observed relation

Incoming RDI is retained in R14 as the output address, RSI in RBX as the key-record address, and RDX in R15 as the value-record address. These are physical address roles, not identified Rust layouts or a private ABI.

1. Read the key length at `[RBX+16]`. A nonzero length permits the key-pointer read at `[RBX+8]` and first-byte comparison with 0x3a.
2. The unsigned-u64 condition `((length-5) mod2^64)<=5` selects lengths 5..10. A signed-DWord table at linked VA `0x27fac8` maps those six lengths to actual local destinations. Only length 7 selects `0x168242c`.
3. The selected comparisons require the remaining bytes `73 74 61 74 75 73`. Thus the complete key is exactly `3a737461747573`, with no case folding, prefix/trailing-byte acceptance or inferred string conversion.
4. At `0x16825fe/0x1682602`, the caller loads leaf pointer=`[R15+8]` and leaf length=`[R15+16]`. CALL `0x1682606` reaches the admitted 85-byte parser at `0x1683670`.
5. The leaf returns AX=0 unless the value has length 3 and bytes ASCII `[1..9][0..9][0..9]`; valid values are 100..999. The caller tests AX and performs the following ordered writes:

| Leaf outcome | First store | Second store | Observation boundary |
| --- | --- | --- | --- |
| AX100..999 | `0x1682614`: WORD `[R14]`=AX | `0x1682618`: BYTE `[R14+64]`=7 | Immediately after the second store |
| AX0 | `0x16822fd`: BYTE `[R14]`=7 | `0x1682301`: BYTE `[R14+64]`=8 | Immediately after the second store |

The zero path does not write output byte 1 in this stage. Other key routes receive no invented result in this contribution. The literal is compatible with an HTTP-style status pseudo-header interpretation; that interpretation is an inference, not a proven type/protocol identity or live behavior.

## Evidence and denominators

| Evidence role | Bytes | Qualification |
| --- | --- | --- |
| Full caller boundary | 1,301 | Exact FDE and retained 318-row GNU decode; not all caller behavior recovered |
| Selected caller proof spans | 262 | Six disjoint subsets of that 1,301-byte body; not additional code coverage |
| Existing parser leaf | 85 | Prior exact parser behavior, independently rebound here |
| Jump table | 24 | Six real signed 32-bit entries; data, not instructions |

`native/` preserves historical GNU instruction rows, tiny captured bytes and the path-header-normalized listings. `RETAINED-STDOUT-FORMAT.json` identifies that header-only change; exact original stdout is recovered by its reversible replacement and checked against the original admission digest, without a new native invocation. No instruction bytes, addresses or operands are normalized. `native/PROVENANCE.json` distinguishes that original boundary-only admission from the new table/selected-flow analysis. `PROOF.md` explains the exact selector and effects. The fresh collector's `observed/REPORT.json` records unique source-section/PT_LOAD mappings, narrow FDE/CIE records, actual branch/table/operand fields, source bindings and limits. Any raw byte lengths repeated in exports are copies/subsets, not extra matched windows. No normalized bytes or recovered-function percentage is reported.

## Reproduce

Use the pinned capture and Python standard library. The collector imports only the maintained `elf_index.sections` parser and emits deterministic static evidence from one complete SHA-authenticated immutable byte object:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/three_digit_status_controller.py --output-dir work/status-controller
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_three_digit_status_controller.py -v
```

The output directory must be absent. The collector does not launch GNU or execute instructions. Retained native evidence was originally decoded by GNU objdump 2.44 from tiny private raw views; its exact provider hash/options/provenance are retained. GNU labels each raw view as synthetic `.data`; the actual `.text` and table `.rodata` qualifications come from the authenticated ELF mappings. Analysis-source hashes are host observations, not an atomic-host guarantee.

The focused tests exercise actual code/table/branch/argument/store/callback fields, complete real-instruction ordering, full-input refusal/output preservation and the static local CFG. They do not turn opaque callbacks into no-ops or execute target instructions. Actual commands, outcomes and original preparation failures are retained separately in this packet; final repository checks are reported for the exact tested commit when they run. A full moving-main/evaluator suite and hosted CI are not implied by these focused results.

## Remaining obligations

Both selected paths subsequently invoke a dynamic target through the first QWORD of the value record plus 0x20 (`0x1682691` on nonzero, `0x1682318` on zero), then the analogous key-record callback at `0x16826a3`, before normal RET `0x16826b7`. Their targets, write footprints, alias behavior, register/frame preservation, normal returns and unwind behavior remain unknown. The later epilogue observes RAX<-R14 bytes; it does not prove R14 still contains the original output address after either callback. They are not identified as destructors, frees or harmless cleanup. Final returned output contents and full caller lifecycle are therefore unqualified.

The proof assumes the exact code/table under a common load bias; ordinary entry and local control without external jumps/exceptions; protected valid stack/RET/code; valid record/key/value reads and output writes. If preservation of records/key/value/frame/code is required, those regions must be explicitly separated from the output; the capture does not establish an original ownership invariant. Next needed question: bind those runtime callback targets and effect/return contracts from an independently justified caller state before reconstructing a whole-return controller.
