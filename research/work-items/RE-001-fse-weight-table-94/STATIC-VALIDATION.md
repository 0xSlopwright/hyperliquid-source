# Native and independent static qualification

The maintained provider is `tools/fse_weight_table.py`, SHA-256
`a10d34aac3770169a01bfa2c4aa1cb8b98196b61465cca30e412c41a4f9f63ef`.
The independent test file is `tests/test_fse_weight_table.py`, SHA-256
`3ae37accf364ebb0b445bd0c052470644c461536aaaeae62c6b1050560048172`.
The test author froze native controls and separate API expectations before
reading the production Rust source. These static tests do not compile or
execute that Rust implementation.

One actual collector invocation admitted the complete node94 digest into an
immutable bytes object and decoded only its private 771-byte view. It exited
zero with empty stderr. The exact `observed/records.json` and
`observed/table.objdump.txt` are its outputs, not manually filled records.
The selected complete FDE is 72 bytes and CIE is 24 bytes. Three separately
counted caller windows contain 208 raw bytes. Provider/source helper and
target identities were preserved.

The eleven independent methods passed in each Python mode, with no skips.
Resource isolation split them into two invocations per mode:

| Invocation | Methods | Result | Reported test seconds |
| --- | ---: | --- | ---: |
| Normal Python, tiny native/fixture/admission controls | 7 | PASS | 0.132 |
| Optimized Python, same tiny controls | 7 | PASS | 0.129 |
| Normal Python, metadata controls | 4 | PASS | 2.577 |
| Optimized Python, same metadata controls | 4 | PASS | 2.490 |

This is eleven unique methods per mode, not a claim that a literal complete
module or repository suite ran in those four invocations. The exact raw
stdout/stderr, before/after bindings and result files are retained losslessly
in `independent-controls/RAW-ARTIFACTS.json`. Its 141 members also retain
the earlier actual decoder-only observations. UTF-8 and base64 encodings are
explicit per member, with the original length and SHA-256; reconstructing
those bytes requires no native or target execution.

The unique native controls include 39 real, same-length, changed instruction
rows. Every changed span was actually decoded into 213 rows, then rejected
by `prove_table` below the whole-image identity gate. The raw schema and
decoded/constrained fields, rather than a full-image hash failure, supply
that rejection. Listing byte/address/missing/duplicate changes also reject.
A prose-only change deliberately preserves the raw semantic certificate:
rendered mnemonic text is not a second, unqualified disassembler.

Nine below-identity metadata changes exercise the complete selected FDE/CIE
and executable section/PT_LOAD bindings. Extent, wrong-identity,
non-executable-provider and existing-output controls remain distinct.
`CONTROL-RESULTS.json` is the ledger of those unique controls; repeating
them in optimized Python does not multiply native byte or case denominators.

Fixture consistency checks distinguish the 39 qualified baseline cases,
three broader standalone cases, and a separate test author's 30 API cases
(14 qualified and 16 chosen unsupported-policy cases). They do not claim
that the linked Rust client has run. Actual compiled-client results and
semantic source mutations belong to the later component build evidence.

The original design, generator lexical failure and decoder-only ledger
remain historical. Their pending fields are not rewritten as completed
rejection evidence. Historical generator files ending `.py.txt` record the
original preparation, including private `/tmp` paths; they are not portable
reproduction entrypoints. The maintained provider and tests are the public
reproduction interfaces. No target instruction, captured object, emulator,
register/PC evaluator, network service or chain action ran in this lane.
