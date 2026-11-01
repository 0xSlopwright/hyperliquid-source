# foundation-move-assign-tail-94: what does the move-assign-tail window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-move-assign-tail-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked first from the #142 scout's fresh-mining backups (move-assign 6 bytes + tail pointer, free old tail via PLT 0x5660480) after the named big-band backups were exhausted.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 111-byte FDE window, its single int3 padding byte, seventeen incoming direct call edges verified as instruction starts (first caller FDE retained), the single call edge to the operator delete[] PLT stub, and the exact move-assign rule over the 6 inline bytes, the tail pointer, and the old-tail free.
- Excluded: the delete[] implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose move-assign rule reads directly from its own bytes: unless dest and source are the same struct, copy the 6 inline bytes while zeroing the source, transfer the tail pointer while zeroing the source tail, free the old dest tail when it is nonzero, and return dest. It is the fifth packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x522d940`, and a full-corpus byte comparison against every FDE body finds no body of 20 bytes or more sharing 60% or more of this window's bytes (0.105 against the divide-by-million window, 0.102 against the scaled-count window, 0.041 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.244 against the cached-pointer-refresh window, 0.069 against the min-cap gap-check window, 0.080 against the offset-equality window, 0.059 against the two-mode limit-check window, 0.060 against the global-bounds-gated equality window, 0.139 against the struct-init flag-pack window, 0.055 against the all-records flag-scan window, 0.184 against the helper low-byte equality window, 0.079 against the byte-gate counter window, 0.056 against the triple-min inequality window, 0.098 against the u32 second-field equality window, 0.111 against the cache-refresh zero-test window, 0.045 against the length-prefix encode window, 0.045 against the validate-or-EINVAL gate window, 0.018 against the capacity-clamp window, 0.027 against the retry-loop window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, mov, cmp, je, movzx, mov, movzx, mov, mov, movzx, mov, mov, movzx, mov, mov, movzx, mov, mov, movzx, mov, mov, mov, mov, mov, mov, mov, test, je, call, mov, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population. It is also not a member of the excluded struct-init family: it moves bytes between two existing structs and frees a tail pointer; it does not initialize a fresh struct, and its skeleton and bytes match no family member.

The raw min-length comparison does report eight 0.80 hits, and they are addressed head-on rather than hidden: all eight are 5-byte `endbr64; ret` stubs that score 4/5 against this window's opening bytes, and the corpus holds 2,440 such stubs. A 5-byte stub is not a twin of a 111-byte window; with the same >=20-byte substance floor the skeleton corpus uses, there are no >=0.60 hits at all.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_move_assign_tail.py --check research/work-items/foundation-move-assign-tail-94/evidence.json
python3 -m unittest tests.test_foundation_move_assign_tail -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x522d940 --stop-address=0x522d9b0 artifacts/node/94/hl-node
objdump -d --start-address=0x522d9e0 --stop-address=0x522daab artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002a5514` (this window, CIE `0x00000000`), `0x0063e2f4` (the next FDE, bounding the padding, CIE `0x006205d0`), and `0x0063e2a4` (the first caller, CIE `0x006205d0`) — the window's CIE differs from the other two, and each record is locked with its own CIE rather than a shared one. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002a5514` describes `[0x522d940, 0x522d9af)`, 111 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x522d9ae`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x522d9b0`, only because one `int3` byte (`0xcc`) pads the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by that one padding byte, and the checker locks the 111-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 17 direct `e8` calls to the window, each verified as an instruction start by disassembly from its containing FDE start. The sites are 0x522da93, 0x523008b, 0x52302e8, 0x5230357, 0x5232d0a, 0x5233076, 0x52330c4, 0x52331ba, 0x5233206, 0x5233242, 0x523349f, 0x5233531, 0x5233cfc, 0x5234296, 0x5234485, 0x52344d1, and 0x52344ff, in seven containing FDEs. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census. The first caller FDE is retained; the full 17-site list is locked in evidence.

### Body behavior: move 6 bytes, transfer the tail, free the old tail

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x522d940` | `endbr64` | Entry |
| `0x522d944` | `push rbx` | Save callee-saved register |
| `0x522d945` | `mov rbx, rdi` | Save the dest pointer |
| `0x522d948` | `cmp rdi, rsi` | Self-assign test |
| `0x522d94b` | `je 0x522d9aa` | Self-assign returns dest unchanged |
| `0x522d94d` | `movzx eax, byte [rsi]` | Load source byte 0 |
| `0x522d950` | `mov byte [rdi], al` | Store dest byte 0 |
| `0x522d952` | `movzx eax, byte [rsi + 1]` | Load source byte 1 |
| `0x522d956` | `mov byte [rsi], 0` | Zero source byte 0 |
| `0x522d959` | `mov byte [rdi + 1], al` | Store dest byte 1 |
| `0x522d95c` | `movzx eax, byte [rsi + 2]` | Load source byte 2 |
| `0x522d960` | `mov byte [rsi + 1], 0` | Zero source byte 1 |
| `0x522d964` | `mov byte [rdi + 2], al` | Store dest byte 2 |
| `0x522d967` | `movzx eax, byte [rsi + 3]` | Load source byte 3 |
| `0x522d96b` | `mov byte [rsi + 2], 0` | Zero source byte 2 |
| `0x522d96f` | `mov byte [rdi + 3], al` | Store dest byte 3 |
| `0x522d972` | `movzx eax, byte [rsi + 4]` | Load source byte 4 |
| `0x522d976` | `mov byte [rsi + 3], 0` | Zero source byte 3 |
| `0x522d97a` | `mov byte [rdi + 4], al` | Store dest byte 4 |
| `0x522d97d` | `movzx eax, byte [rsi + 5]` | Load source byte 5 |
| `0x522d981` | `mov byte [rsi + 4], 0` | Zero source byte 4 |
| `0x522d985` | `mov byte [rdi + 5], al` | Store dest byte 5 |
| `0x522d988` | `mov rax, [rsi + 8]` | Old source tail |
| `0x522d98c` | `mov byte [rsi + 5], 0` | Zero source byte 5 |
| `0x522d990` | `mov qword [rsi + 8], 0` | Zero source tail |
| `0x522d998` | `mov rdi, [rdi + 8]` | Old dest tail |
| `0x522d99c` | `mov [rbx + 8], rax` | Dest tail = old source tail |
| `0x522d9a0` | `test rdi, rdi` | Old dest tail vs null |
| `0x522d9a3` | `je 0x522d9aa` | Null old tail skips the free |
| `0x522d9a5` | `call 0x5660480` | Free old dest tail via PLT stub |
| `0x522d9aa` | `mov rax, rbx` | Return dest |
| `0x522d9ad` | `pop rbx` | Epilogue |
| `0x522d9ae` | `ret` | Return |

- The rule, over dest pointer (`rdi`), source pointer (`rsi`), dest bytes (bytes `[0..6)` of dest), source bytes (bytes `[0..6)` of source), dest tail (the qword at dest + 8), and source tail (the qword at source + 8), is: if dest == source, return dest with no writes and no call; else set dest bytes = source bytes, source bytes = 0, dest tail = old source tail, source tail = 0, call `0x5660480` with the old dest tail iff it is nonzero, and return dest.
- The source zeroing is staggered by one byte in the instruction order (byte i + 1 is loaded before byte i is zeroed), but the net effect is exact: all 6 source bytes end at 0 and all 6 dest bytes end equal to the old source bytes. Bytes `[6..8)` of both structs are never touched, and no other dest or source field is written.
- The callee at `0x5660480` is the operator delete[] PLT stub (`jmp *GOT`, `push 0x39`, `jmp PLT0`), not an FDE start, so no body size is claimed for it — the same exclusion pattern as the memcmp/memcpy PLT callees of earlier calls packets. The delete[] implementation behind the stub is excluded, and the callee result (void) is not read.
- The first caller at `0x522da93` sits in a 203-byte FDE (`0x522d9e0..0x522daab`, `.eh_frame+0x0063e2a4`, CIE `0x006205d0`, a different CIE from the window). Immediately before the call it zeroes a fresh dest struct (`movl $0, 0x0(%rbp)`; `mov %ax, 0x4(%rbp)`; `movq $0, 0x8(%rbp)`) and passes a stack address as the source, then jumps to a free path after the call. That zeroing is caller context, not part of the window's rule, and the caller role beyond the call site is not established.
- The next FDE at `0x522d9b0` is a landing-pad-shaped block (free, stack check, `_Unwind_Resume`); which function's handler it belongs to is not established, so no claim about it is made beyond its FDE record bounding the padding.

## Inferences

- Inferred label: move-assign-tail helper. The rule is observed and proven above; only the label is inferred.
- The 6 moved bytes plus a tail pointer at +8 read as a small-buffer-optimized string-like struct (inline buffer plus heap tail), but what the struct is, what the tail points to, and what bytes `[6..8)` are is not established, so that reading is an inference only.
- The seventeen incoming direct calls suggest a widely used helper, but no caller purpose is established beyond the first call site.

## Unknowns

- The source-level name and types of this window, its struct, and its tail allocation.
- What bytes `[6..8)` of the struct are, and why the inline buffer is exactly 6 bytes.
- Whether any caller passes overlapping-but-unequal dest and source pointers, and what the window would do then (the bytes say the copy would interleave with the zeroing, but no such caller is verified).
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The delete[] implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
