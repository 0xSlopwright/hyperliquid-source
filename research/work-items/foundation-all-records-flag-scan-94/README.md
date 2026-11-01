# foundation-all-records-flag-scan-94: what does the all-records flag-scan window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-all-records-flag-scan-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the struct-init flag-pack packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 91-byte FDE window, its five int3 padding bytes, the shared-callee call edge (result ignored), and the exact all-records flag-scan rule over the inputs.
- Excluded: the shared callee body at `0x3c1ada0`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose all-records flag-scan rule reads directly from its own bytes: a count threshold selects either a fast path that calls a helper and returns 1, or a scan that requires every record's flag byte to be nonzero. It is the ninth packet from the calls category's gate-singleton slice: like the struct-init flag-pack window, its rule is stated over its inputs, with the callee itself explicitly excluded — here even more strongly, since the callee's result is ignored entirely. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x3bde0b0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.053 against the divide-by-million window, 0.041 against the scaled-count window, 0.088 against the TLS-table-index window, 0.175 against the error-band range-check window, 0.024 against the cached-pointer-refresh window, 0.011 against the min-cap gap-check window, 0.053 against the offset-equality window, 0.035 against the two-mode limit-check window, 0.060 against the global-bounds-gated equality window, 0.083 against the struct-init flag-pack window, none against the older claimed corpus). Its mnemonic skeleton (`sub, mov, cmp, jb, mov, lea, call, mov, add, ret, mov, shl, lea, nop, test, sete, je, add, cmp, lea, jne, add, ret`) is a singleton among small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_all_records_flag_scan.py --check research/work-items/foundation-all-records-flag-scan-94/evidence.json
python3 -m unittest tests.test_foundation_all_records_flag_scan -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3bde0b0 --stop-address=0x3bde110 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x001bb6a0` (this window) and `0x00509b84` (the shared callee, whose body is excluded). The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x001bb6a0` describes `[0x3bde0b0, 0x3bde10b)`, 91 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x3bde10a`).
- The unwind index stride to the next entry is 96 bytes, ending at `0x3bde110`, only because five `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those five padding bytes, and the checker locks the 91-byte body and the padding separately.
- A byte-pattern scan of `.text` finds zero direct `e8` calls to the window. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census. No caller file is included, so this packet has 7 files.

### Body behavior: one threshold, one fast path, one all-records scan

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x3bde0b0` | `sub rsp, 0x68` | Stack frame (104 bytes) |
| `0x3bde0b4` | `mov rax, qword ptr [rdi + 0x10]` | Count input |
| `0x3bde0b8` | `cmp rax, 0x2711` | Count vs 10001 |
| `0x3bde0be` | `jb 0x3bde0d8` | Count below 10001 takes the scan path |
| `0x3bde0c0` | `movw [rsp + 8], 0x143` | Fast-path slot value 323 |
| `0x3bde0c7` | `lea rdi, [rsp + 8]` | Callee argument: slot address |
| `0x3bde0cc` | `call 0x3c1ada0` | Shared callee; result ignored |
| `0x3bde0d1` | `mov al, 1` | Fast-path verdict 1 |
| `0x3bde0d3` | `add rsp, 0x68` | Fast-path epilogue |
| `0x3bde0d7` | `ret` | Fast-path return |
| `0x3bde0d8` | `mov rcx, qword ptr [rdi + 8]` | Records base pointer |
| `0x3bde0dc` | `shl rax, 4` | Count times 16 |
| `0x3bde0e0` | `lea rdx, [rax + rax * 4]` | Remaining byte budget: count times 80 |
| `0x3bde0e4` | `nop` (12 bytes) | Alignment padding inside the window |
| `0x3bde0f0` | `test rdx, rdx` | Loop head: budget exhausted? |
| `0x3bde0f3` | `sete al` | Verdict 1 iff budget is zero |
| `0x3bde0f6` | `je 0x3bde106` | Budget zero exits with verdict 1 |
| `0x3bde0f8` | `add rdx, -0x50` | Budget minus one 80-byte record |
| `0x3bde0fc` | `cmp byte ptr [rcx + 0x4e], 0` | Current record's flag byte |
| `0x3bde100` | `lea rcx, [rcx + 0x50]` | Advance to the next record |
| `0x3bde104` | `jne 0x3bde0f0` | Nonzero flag continues the scan |
| `0x3bde106` | `add rsp, 0x68` | Scan-path epilogue |
| `0x3bde10a` | `ret` | Scan-path return |

- The return rule, over the count `count` (u64 at input struct + `0x10`), the records base `records_base` (pointer at input struct + `0x08`), and the flag bytes at `records_base + i * 80 + 0x4e`, is: if `count >= 10001` (unsigned), write u16 `0x143` to a stack slot, call the callee with that slot's address, ignore the result, and return 1 in `al`; otherwise return 1 in `al` iff every flag byte is nonzero for `i` in `0..count-1`, else 0 in `al` (count 0 returns 1 vacuously, without scanning).
- The threshold compare is unsigned (`jb`): exactly 10001 takes the fast path, 10000 takes the scan path. The checker verifies both sides of the boundary.
- The scan checks records in forward order and exits early on the first zero flag: a zero flag in the first, middle, or last record all return 0, while all-nonzero records return 1. The byte budget (`count * 80`, built as `(count << 4) * 5`) guarantees exactly `count` flag checks, one per 80-byte record.
- The verdict is delivered in `al` only: the scan path's `sete` and the fast path's `mov al, 1` set just the low byte, so the upper bytes of `rax` are not normalized. The rule is therefore stated over `al`, not over full `rax`.
- The shared callee at `0x3c1ada0` IS an FDE start (1070 bytes, `.eh_frame+0x00509b84`, CIE `0x0022d474`), unlike the callees of the last several packets — but its body is excluded here all the same, and its result is ignored on the only path that calls it, so no claim about what it computes is made.
- The window has no `endbr64` and saves no callee-saved registers; its only frame is the 104-byte stack reservation.

## Inferences

- Inferred label: all-records flag-scan helper. The rule is observed and proven above; only the label is inferred.
- The threshold-plus-scan shape suggests a "large input takes a bulk path, small input is validated record by record" helper, but what the records, the flag byte, the threshold 10001, and the slot value 323 mean are not closed here, so that reading is an inference only.
- Zero incoming direct calls does not mean the window is dead code: it may be reached through a pointer or from another object, but no caller is established here.

## Unknowns

- The source-level name and types of this window, its input struct, its records, and its flag byte.
- What the shared callee computes with the stack slot holding 323, and why its result is ignored.
- What the threshold 10001 and the slot value 323 represent.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x3c1ada0`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
