# <task-id>: <bounded question>

- Component ID:
- Target release and full SHA-256:
- Source commit / reference commit:
- Claim status: observation / inference / unresolved
- Scope included and excluded:

## Reproduce

Exact commands, tool versions, options, input and output hashes, working directory,
platform, environment requirements, and any declared execution/side effects.

## Evidence

Original addresses and coordinate system (VA/file offset), validated boundaries,
raw disassembly/data, callers/callees/indirect calls, source mapping evidence,
ABI/layout/rounding/overflow observations. Keep raw files beside this record.
State whether analysis was complete, timed out or limited to a range.

## Implementation and comparison

Independent Rust path, Cargo.lock, compiler/linker/build flags, two-build result,
raw and normalized comparisons and masks, helper/data/relocation closure,
fixture identities, boundary/error cases and corruption controls. Use "not yet
implemented/measured" where applicable, rather than implied success.

## Results and limitations

Machine-readable metrics with explicit denominators, what passed/failed, what
remains unknown, and why any requested progress gate covers its entire scope.
If requesting no gate, say so. Finish with a concrete next question.
