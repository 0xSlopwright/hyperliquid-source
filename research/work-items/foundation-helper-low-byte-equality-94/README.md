# foundation-helper-low-byte-equality-94: what does the helper low-byte equality window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-helper-low-byte-equality-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the all-records flag-scan packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 49-byte FDE window, its fifteen int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact low-byte equality rule over the callee result and the stored byte.
- Excluded: the shared callee body at `0x4ff8ac0`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose low-byte equality rule reads directly from its own bytes: call a helper, then report whether the low byte of its result equals a stored byte. It is the tenth packet from the calls category's gate-singleton slice: like the all-records flag-scan window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5004e70`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.105 against the divide-by-million window, 0.122 against the scaled-count window, 0.061 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.244 against the cached-pointer-refresh window, 0.122 against the min-cap gap-check window, 0.143 against the offset-equality window, 0.102 against the two-mode limit-check window, 0.122 against the global-bounds-gated equality window, 0.245 against the struct-init flag-pack window, 0.041 against the all-records flag-scan window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, mov, mov, mov, mov, mov, lea, mov, call, cmp, pop, sete, ret`) is a singleton among small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_helper_low_byte_equality.py --check research/work-items/foundation-helper-low-byte-equality-94/evidence.json
python3 -m unittest tests.test_foundation_helper_low_byte_equality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5004e70 --stop-address=0x5004eb0 artifacts/node/94/hl-node
objdump -d --start-address=0x50070f0 --stop-address=0x50073c7 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x0028fdc4` (this window), `0x0028f740` (the shared callee), and `0x00626be4` (the first caller) — the window and the callee share CIE `0x00000000`, while the caller uses CIE `0x006205d0`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x0028fdc4` describes `[0x5004e70, 0x5004ea1)`, 49 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5004ea0`).
- The unwind index stride to the next entry is 64 bytes, ending at `0x5004eb0`, only because fifteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those fifteen padding bytes, and the checker locks the 49-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x50071c9`, verified as an instruction start by disassembly from its containing FDE start (`0x50070f0`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one dereference, one helper call, one low-byte comparison

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5004e70` | `endbr64` | Entry |
| `0x5004e74` | `push rbx` | Save callee-saved register |
| `0x5004e75` | `mov rbx, rdi` | Save input struct pointer |
| `0x5004e78` | `mov rdi, qword ptr [rdi]` | First field dereferenced: inner pointer |
| `0x5004e7b` | `mov r8d, 1` | Fifth callee argument: 1 |
| `0x5004e81` | `mov edx, dword ptr [rbx + 8]` | Third callee argument: input u32 at +0x08 |
| `0x5004e84` | `lea rsi, [rbx + 0x388]` | Second callee argument: input + 0x388 |
| `0x5004e8b` | `mov ecx, dword ptr [rdi + 0xaf0]` | Fourth callee argument: inner u32 at +0xaf0 |
| `0x5004e91` | `call 0x4ff8ac0` | Shared callee; its body is excluded |
| `0x5004e96` | `cmp byte ptr [rbx + 0x1014], al` | Stored byte vs callee result's low byte |
| `0x5004e9c` | `pop rbx` | Restore callee-saved register |
| `0x5004e9d` | `sete al` | Verdict 1 iff the low bytes are equal |
| `0x5004ea0` | `ret` | Return |

- The return rule, over the callee result `callee_result` (u64 rax from the call) and the stored byte `stored_byte` (byte at input struct + `0x1014`), is: return 1 in `al` iff `(callee_result & 0xff) == stored_byte`, else 0 in `al`.
- The callee is called with rdi = inner (the pointer stored in the input struct's first field, dereferenced before the call), rsi = input + `0x388`, rdx = input u32 at +`0x08` (a 32-bit load, so the upper half of rdx is zeroed), rcx = inner u32 at +`0xaf0` (likewise zero-extended), r8 = 1. The rule depends only on the callee result's low byte, not its internals.
- The low-byte-only comparison is observable: a callee result of `0x1234` against stored byte `0x34` returns 1, while `0x1200` against `0x34` returns 0, and `0x100` against `0x00` returns 1. The checker verifies all of these, plus zero and max edges (`0xffffffffffffffff` against `0xff` returns 1).
- The verdict is delivered in `al` only: `sete` sets just the low byte, so the upper bytes of `rax` are not normalized. The rule is therefore stated over `al`, not over full `rax`.
- The shared callee at `0x4ff8ac0` IS an FDE start (104 bytes, `.eh_frame+0x0028f740`, CIE `0x00000000`, the same CIE as the window) — but its body is excluded here all the same, so no claim about what it computes is made.

## Inferences

- Inferred label: helper low-byte equality helper. The rule is observed and proven above; only the label is inferred.
- The dereference-then-call-then-compare shape suggests a predicate that checks whether a helper's byte-sized outcome matches a stored expected byte, but what the input struct, the inner pointer, the helper, and the stored byte mean are not closed here, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input struct, its inner pointer, and its shared callee.
- What the callee computes, and why its second argument is input + `0x388`, its third the input u32 at +`0x08`, its fourth the inner u32 at +`0xaf0`, and its fifth 1.
- What the stored byte at +`0x1014` represents.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x4ff8ac0`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
