# foundation-triple-min-inequality-94: what does the triple-min inequality window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-triple-min-inequality-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the byte-gate counter packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 90-byte FDE window, its six int3 padding bytes, the shared-callee call edge (the memcmp@plt stub), and the exact triple-min inequality rule over the low byte of the return value.
- Excluded: the shared callee body behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose triple-min inequality rule reads directly from its own bytes: take the minimum of three length fields, compare two buffers over exactly that length with memcmp, and report whether the buffers differ or the two partial minima disagree. It is the twelfth packet from the calls category's gate-singleton slice: like the byte-gate counter window, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded — here the callee is a PLT stub, so there is no callee body in this binary at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x52f2b50`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.184 against the divide-by-million window, 0.245 against the scaled-count window, 0.033 against the TLS-table-index window, 0.025 against the error-band range-check window, 0.244 against the cached-pointer-refresh window, 0.184 against the min-cap gap-check window, 0.093 against the offset-equality window, 0.106 against the two-mode limit-check window, 0.096 against the global-bounds-gated equality window, 0.056 against the struct-init flag-pack window, 0.033 against the all-records flag-scan window, 0.082 against the helper low-byte equality window, 0.145 against the byte-gate counter window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, push, sub, mov, mov, mov, mov, mov, mov, cmp, mov, cmovbe, cmp, mov, cmovbe, mov, cmp, cmovbe, mov, call, test, setne, cmp, setne, add, or, pop, pop, ret`) is a singleton among 31,898 small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_triple_min_inequality.py --check research/work-items/foundation-triple-min-inequality-94/evidence.json
python3 -m unittest tests.test_foundation_triple_min_inequality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x52f2b50 --stop-address=0x52f2bb0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains the excerpt selecting the FDE at `.eh_frame` section offset `0x002ae0cc` (this window). The checker locks this raw FDE record and reads its PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002ae0cc` describes `[0x52f2b50, 0x52f2baa)`, 90 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x52f2ba9`).
- The unwind index stride to the next entry is 96 bytes, ending at `0x52f2bb0`, only because six `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those six padding bytes, and the checker locks the 90-byte body and the padding separately.
- A byte-pattern scan of `.text` finds zero direct `e8` calls to the window. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census. No caller file is included, so this packet has 7 files.

### Body behavior: three minima, one memcmp, two inequality legs

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x52f2b50` | `endbr64` | Entry |
| `0x52f2b54` | `push rbp` | Save callee-saved register |
| `0x52f2b55` | `push rbx` | Save callee-saved register |
| `0x52f2b56` | `sub rsp, 8` | Stack alignment for the call |
| `0x52f2b5a` | `mov rdx, qword ptr [rsi]` | B.first pointer |
| `0x52f2b5d` | `mov rcx, qword ptr [rsi + 8]` | B.second pointer |
| `0x52f2b61` | `mov rax, qword ptr [rdi + 8]` | A.second (first length) |
| `0x52f2b65` | `mov rbp, qword ptr [rdx + 8]` | B.first.second (second length) |
| `0x52f2b69` | `mov rsi, qword ptr [rcx + 8]` | B.second.second (third length) |
| `0x52f2b6d` | `mov rdi, qword ptr [rdx]` | B.first.first (first buffer) |
| `0x52f2b70` | `cmp rax, rbp` | First length vs second length |
| `0x52f2b73` | `mov rbx, rsi` | Stage the third length |
| `0x52f2b76` | `cmovbe rbp, rax` | rbp = min(A.second, B.first.second) |
| `0x52f2b7a` | `cmp rax, rsi` | First length vs third length |
| `0x52f2b7d` | `mov rsi, qword ptr [rcx]` | B.second.first (second buffer) |
| `0x52f2b80` | `cmovbe rbx, rax` | rbx = min(A.second, B.second.second) |
| `0x52f2b84` | `mov rax, rbp` | Stage the first partial minimum |
| `0x52f2b87` | `cmp rbx, rbp` | Partial minima against each other |
| `0x52f2b8a` | `cmovbe rax, rbx` | rax = min(rbp, rbx) = triple minimum |
| `0x52f2b8e` | `mov rdx, rax` | Third callee argument: length |
| `0x52f2b91` | `call 0x5660150` | memcmp@plt; its body is excluded |
| `0x52f2b96` | `test eax, eax` | memcmp result vs zero |
| `0x52f2b98` | `setne al` | al = 1 iff memcmp result is nonzero |
| `0x52f2b9b` | `cmp rbx, rbp` | Partial minima against each other again |
| `0x52f2b9e` | `setne dl` | dl = 1 iff the partial minima differ |
| `0x52f2ba1` | `add rsp, 8` | Epilogue |
| `0x52f2ba5` | `or eax, edx` | Combine the two legs |
| `0x52f2ba7` | `pop rbx` | Restore callee-saved register |
| `0x52f2ba8` | `pop rbp` | Restore callee-saved register |
| `0x52f2ba9` | `ret` | Return |

- The three `cmovbe` steps are unsigned minima: each `cmp` + `cmovbe` keeps the smaller of its two operands (below-or-equal moves the compared value in). So rbp = min(A.second, B.first.second), rbx = min(A.second, B.second.second), and the final rax = min(rbp, rbx) = min(A.second, B.first.second, B.second.second).
- The return rule, over the first length `a_second` (u64 at first input struct + `0x08`), the second length `first_second` (u64 at B.first + `0x08`), the third length `second_second` (u64 at B.second + `0x08`), and the buffers at B.first.first and B.second.first, is: `rbp = min(a_second, first_second)`; `rbx = min(a_second, second_second)`; `n = min(rbp, rbx)`; return low byte = (1 if memcmp(first_buf, second_buf, n) != 0 else 0) | (1 if rbx != rbp else 0).
- The callee is called with rdi = B.first.first, rsi = B.second.first, rdx = n. The first input struct contributes only its second field; its pointer is never passed to the callee.
- The partial-minimum leg is not redundant: when the first-input second is the overall minimum, both partial minima equal it and the leg is clear; when a field second is strictly smallest on exactly one side, the partial minima differ and the leg sets the low byte even if the buffers are equal over the triple minimum. The checker verifies both shapes.
- The rule is stated over the low byte only: the final `or eax, edx` is full-width, and edx's upper bits after the memcmp call are whatever the callee left (rdx is caller-saved), so the upper bytes of the returned eax are not determined by this window's bytes alone. No claim about them is made.
- The shared callee at `0x5660150` is the memcmp@plt stub (`jmp *GOT`, `push`, `jmp PLT0`), not an FDE start, so no body size is claimed for it. The window's rule is stated over the memcmp result's zero/nonzero status, not over memcmp's internals.

## Inferences

- Inferred label: triple-min inequality helper. The rule is observed and proven above; only the label is inferred.
- The min-then-compare shape suggests a predicate that checks whether two variable-length records agree over their common length and whether their length fields are consistent, but what the input structs, the buffers, and the length fields mean are not closed here, so that reading is an inference only.
- Zero incoming direct calls does not mean the window is dead code: it may be reached through a pointer or from another object, but no caller is established here.

## Unknowns

- The source-level name and types of this window, its input structs, its buffers, and its length fields.
- What the three length fields represent, and why the partial minima are compared as well as the buffers.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body behind the memcmp@plt stub, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
