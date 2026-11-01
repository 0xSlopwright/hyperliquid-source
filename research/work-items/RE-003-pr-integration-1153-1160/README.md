# RE-003: integration review of PRs #1153–#1167

Target: Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The fork-base packet separately binds node #115
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
and visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`;
these identities are not substituted for node #94.

Integration base: `cec50f68e01c967d21538d48c49683ddeea52767`.

The user requested merging the latest contributions. This review integrates six
bounded research packets, the qualified FSE table implementation (RE-001), and
the RE-003 isolated unittest launcher. All component completion gates remain
false. Imported artifacts and seven source repository pins are unchanged.

| PR | Reviewed source head |
| --- | --- |
| #1153 | `5c825bb633d897723b1c9f49ffb1cabf358d37d3` |
| #1154 | `778dac9b5b6b1d1633e27299ed894efe601c25ee` |
| #1155 | `65bee85a698f35aae31d813159283c586cdf80ac` |
| #1156 | `9c5d74b64ec99aa577854416838ffd2e3d1c64d3` |
| #1157 | `10f57d187f66533a50c46eb2f80d53f432705e47` |
| #1158 | `0af4bef8453ae386bc115c7d782777a019d87086` |
| #1159 | `f0242fabfa1597818477e31bf8d1bf9977a9a063` |
| #1160 | `29724b9d94b3d6fa463de864adf300572c6cf576` |

## Concrete blockers and minimal repairs

The isolated launcher exposes six existing synthetic ELF tests that import
`exchange_dispatch` by filename without putting its sibling `source_files`
module on the import path. Their earlier success depended on other test modules
having changed the process import path. Each now declares the repository tools
path itself. No scientific assertion or production parser changes. The actual
new launcher passes all six repaired files (15 tests); its nine real-process
integration controls pass separately. `parser-controls.log` and
`runner-controls.log` retain these results.

The FSE static collector pins a Debian GNU objdump pathname and digest that are
unavailable on this macOS review host. The static CI workflow also selects
Ubuntu 24.04 rather than the measured Debian provider. The absent provider
blocks RE-001's fresh native qualification on this host.
The collector now permits an explicitly selected absolute `FSE_OBJDUMP` plus
`FSE_OBJDUMP_SHA256`, preserving the original default and before/after hash
checks. Partial selections are rejected, and an incorrect digest fails before
execution. Optional native tests report an unavailable default as a skip;
explicit selection must pass. All 12 FSE tests pass with the installed GNU
2.47.20260726 provider, digest
`1d45527c5f290d089491f9cc63e9ba4d91c5870ebf59ed261b833d024a866e4c`.
The fresh record is in `fse-static-record/`; original native records remain
unchanged. The original tool, test, component README and full manifest are
preserved under `original/`. The live FSE manifest rebinds only those three
changed source/document files, without relabeling historical experiments.

## Fresh bounded checks

All six research generators completed with `PYTHONHASHSEED=17`, `TZ=UTC` and
two workers where supported. Every generated file equals its retained packet
byte-for-byte, including mutations and explicit survivor records. File hashes
and counts are in `packet-reproduction.json`. This is one fresh reproduction
per packet, not a claim that the author's incomplete second spot-ledger run
completed. Full local generated records remain under ignored
`work/merge-latest-1153-1160/packet-reproduction/`.

An independent GNU disassembly comparison validates the bytes and instruction
boundaries of all 11,471 recorded rows across 40 FDE bodies in the fee-state,
staking and spot-ledger packets. The audit details are in
`native-rows-audit.json`; raw listings remain under the ignored review work
directory. This does not establish helper completeness or all-input behavior.

The unchanged safe Rust FSE implementation builds with actual Rust 1.94.1 on
macOS in debug and optimized profiles. Each profile passes one fixture test
function, matches 39 primary full-buffer outputs, and passes the independent
48-case client in original, reversed and renamed order. Reorders do not add
unique semantic cases. `fse-rust-validation.json` records compiler identity and
scope. This is a fresh host build, not the old pinned Linux compiler experiment,
original ABI, captured-byte identity, or a complete decompressor.

`make doctor verify catalogue-check reproduce` passes with Python 3.13 and
installed GNU binutils. Repository-wide regression status is recorded separately
in `repository-validation.json`. No captured native process, private fixture,
live network/chain action, progress promotion or hosted CI success is claimed.

## Additional submissions received during review

PRs #1161–#1163 add only new packet, tool and test files. Their tests run
separately while the original complete 796-file inventory continues; the final
validation inventory includes all 803 modules after the later additions. `reviewed-heads.json` records
the additional exact heads.

The u128 division collector was rerun against the already retained, fully
hash-admitted official compiler-builtins archive (4,400,606 bytes,
`f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6`).
Its complete record exactly matches the submitted record: two defined
candidates, each equal to all 198 target bytes with zero normalization.
The stream-message collector also regenerates the retained JSON exactly.
These observations retain the original limits and advance no component gate.

The spot-payout generator also regenerates every retained file byte-for-byte,
including its mutation results. All three additional modules pass 85 tests
without skips; see `additional-tests.json` and `additional-reproduction.json`.

## RE-002 fork-base comparison integrity (#1164)

The next submission adds an offline extractor for fork panic Locations and
overflow-helper sites across node #94, node #115 and visor, plus inferred
upstream-version scores. The earlier build-provenance README links those
explicitly labeled inferences; no gate changes. The offline check reproduces
the submitted binary-derived record. Upstream Git/crates source scoring was
not rerun in this integration, and its retained inferences remain conditional.

Review found that deleting an entire comparison file, row or revision could
pass the supposed complete-point-set check. `fork-omission-before.json` records
the original acceptance of a missing file. The validator now requires the
complete declared row, revision and file sets, while retaining explicitly
absent upstream files as legitimate control observations. Five omission and
duplication controls now reject; all eight module tests and the offline packet
check pass. The original tool and tests are preserved under `original/`.
This is a repair to active RE-002 evidence validation, not a new fork identity
or a reconstruction completion claim.

## Funding configuration and signable parser (#1165–#1166)

The funding writer contribution adds separate binary-backed setter/vote
observations with explicit stub, branch and mutation-survivor limits. Its 36
unit tests pass. The signable-parser change rejects duplicate ELF section
names instead of silently replacing an earlier section mapping. Review runs
all 29 existing signable tests plus its three duplicate-section controls on the
materialized node #94 and GNU binutils: 32 pass, zero skips. This resolves the
contributor's missing-capture validation gap; it grants no new reconstruction
completion credit. All new test modules are included in the final inventory.

The funding configuration generator reproduces all ten generated files exactly,
including mutation survivors; see `additional-reproduction.json`.

## Final order-relation parser submission (#1167)

The same duplicate-section ambiguity also affected the order-relation image
reader. Its minimal guard is reviewed with all four affected test modules:
53 tests pass with zero skips, including real target transitions and existing
relocation/FDE corruption controls. Those reruns replace the earlier parser
results in the final aggregate. All original PR heads remain merge ancestors.
