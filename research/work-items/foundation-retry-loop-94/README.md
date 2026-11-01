# foundation-retry-loop-94: what does the retry-loop window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-retry-loop-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from fresh big-band calls mining after the named big-band backups were exhausted (the length-prefix encode, validate-or-EINVAL gate, and capacity-clamp windows built, the struct-init compound backup rejected).
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 115-byte FDE window, its thirteen int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the single call edge to a shared callee, and the exact retry-loop rule over the attempts count and the callee result sequence.
- Excluded: the callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose retry-loop rule reads directly from its own bytes: take an attempts count from the struct, call a shared helper with fixed arguments up to that many times, return the first nonzero result at once, and return 0 only when every attempt returns 0. It is the fourth packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x3cbefb0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.026 against the divide-by-million window, 0.020 against the scaled-count window, 0.071 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.000 against the cached-pointer-refresh window, 0.046 against the min-cap gap-check window, 0.013 against the offset-equality window, 0.035 against the two-mode limit-check window, 0.012 against the global-bounds-gated equality window, 0.014 against the struct-init flag-pack window, 0.143 against the all-records flag-scan window, 0.000 against the helper low-byte equality window, 0.013 against the byte-gate counter window, 0.011 against the triple-min inequality window, 0.000 against the u32 second-field equality window, 0.022 against the cache-refresh zero-test window, 0.078 against the length-prefix encode window, 0.009 against the validate-or-EINVAL gate window, 0.036 against the capacity-clamp window, none against the older claimed corpus). Its mnemonic skeleton (`push, push, push, push, push, push, sub, mov, test, je, mov, lea, mov, lea, lea, nop, mov, mov, mov, mov, mov, call, test, jne, dec, jne, xor, add, pop, pop, pop, pop, pop, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Integration review corrected the instruction table at `0x3cbefe1`: GNU's
default seven-byte display wraps one 15-byte NOP over three lines. The original
table retained only its first seven bytes. The full-body SHA-256 already pinned
all 115 bytes; the instruction table now also covers them without gaps or
overlap. Two regressions fail before the correction and pass afterward.
[Original records and failing logs](../RE-003-pr-integration-1242-1262/README.md)
are preserved. Raw exports and the retry-loop rule are unchanged.

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_retry_loop.py --check research/work-items/foundation-retry-loop-94/evidence.json
python3 -m unittest tests.test_foundation_retry_loop -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3cbefb0 --stop-address=0x3cbf030 artifacts/node/94/hl-node
objdump -d --start-address=0x3cbf7a0 --stop-address=0x3cbfbc2 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x001ccb3c` (this window, CIE `0x00000000`), `0x0050d7d4` (the next FDE, bounding the padding, CIE `0x002dc714`), `0x0050d87c` (the first caller, CIE `0x002dc714`), and `0x0050dd20` (the shared callee, CIE `0x002dc714`) — the window's CIE differs from the other three, and each record is locked with its own CIE rather than a shared one. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x001ccb3c` describes `[0x3cbefb0, 0x3cbf023)`, 115 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x3cbf022`).
- The unwind index stride to the next entry is 128 bytes, ending at `0x3cbf030`, only because thirteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "128-byte FDE-bounded" would overstate the frame by those thirteen padding bytes, and the checker locks the 115-byte body and the padding separately.
- The window starts with `push rbp`, not `endbr64`; no claim is made about why it lacks the landing pad.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x3cbfa87`, verified as an instruction start by disassembly from its containing FDE start (`0x3cbf7a0`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: bounded retry, first nonzero wins

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x3cbefb0` | `push rbp` | Entry |
| `0x3cbefb1` | `push r15` | Save callee-saved register |
| `0x3cbefb3` | `push r14` | Save callee-saved register |
| `0x3cbefb5` | `push r13` | Save callee-saved register |
| `0x3cbefb7` | `push r12` | Save callee-saved register |
| `0x3cbefb9` | `push rbx` | Save callee-saved register |
| `0x3cbefba` | `sub rsp, 0x18` | Frame for the stack slot |
| `0x3cbefbe` | `mov r12, [rdi + 0x18]` | Attempts count |
| `0x3cbefc2` | `test r12, r12` | Zero-attempts test |
| `0x3cbefc5` | `je 0x3cbf012` | Zero attempts skip the loop |
| `0x3cbefc7` | `mov rbx, rdi` | Save the struct pointer |
| `0x3cbefca` | `lea r13, [rdi + 0x20]` | Slot first qword: struct + 0x20 address |
| `0x3cbefce` | `mov rbp, [rip + 0x1aaf7ab]` | Slot second qword: global at 0x576e780 |
| `0x3cbefd5` | `lea r14, [rip - 0x3ad4b8f]` | Fixed callee rsi: address 0x1ea44d |
| `0x3cbefdc` | `lea r15, [rsp + 8]` | Stack slot address for callee rdx |
| `0x3cbefe1` | `nop` (15 bytes, including prefixes) | Alignment padding before the loop |
| `0x3cbeff0` | `mov [rsp + 8], r13` | Slot[0] = struct + 0x20 address |
| `0x3cbeff5` | `mov [rsp + 0x10], rbp` | Slot[1] = global qword |
| `0x3cbeffa` | `mov rdi, rbx` | Callee rdi = struct pointer |
| `0x3cbeffd` | `mov rsi, r14` | Callee rsi = 0x1ea44d |
| `0x3cbf000` | `mov rdx, r15` | Callee rdx = stack slot |
| `0x3cbf003` | `call 0x3cc6500` | Shared callee; its body is excluded |
| `0x3cbf008` | `test rax, rax` | Callee result vs zero |
| `0x3cbf00b` | `jne 0x3cbf014` | Nonzero result returns at once |
| `0x3cbf00d` | `dec r12` | Attempts remaining, minus one |
| `0x3cbf010` | `jne 0x3cbeff0` | Repeat while attempts remain |
| `0x3cbf012` | `xor eax, eax` | Return 0 (zero attempts, or all attempts zero) |
| `0x3cbf014` | `add rsp, 0x18` | Epilogue |
| `0x3cbf018` | `pop rbx` | Epilogue |
| `0x3cbf019` | `pop r12` | Epilogue |
| `0x3cbf01b` | `pop r13` | Epilogue |
| `0x3cbf01d` | `pop r14` | Epilogue |
| `0x3cbf01f` | `pop r15` | Epilogue |
| `0x3cbf021` | `pop rbp` | Epilogue |
| `0x3cbf022` | `ret` | Return |

- The rule, over struct pointer (`rdi`), attempts count (the qword at `[rdi + 0x18]`), and the callee results (one u64 per attempt), is: if attempts == 0, return 0 without calling; else repeat up to attempts times: call `0x3cc6500` with `rdi` = struct pointer, `rsi` = `0x1ea44d`, `rdx` = stack slot (slot[0] = struct + 0x20 address, slot[1] = qword at `0x576e780`); if the callee result is nonzero, return it at once; if it is zero, decrement attempts and repeat while attempts != 0; if every attempt returns 0, return 0.
- The loop re-sets the slot contents and the three callee arguments on every iteration from loop-invariant values, so every attempt is made with identical arguments. The attempts count is a qword; the dec/jne counter means exactly N calls happen when all N results are zero, and fewer when an early result is nonzero.
- The window writes nothing into the struct itself: the only stores are the two slot qwords on the stack. The callee may read or write through the slot pointer, but that is excluded with the callee body.
- The callee at `0x3cc6500` IS an FDE start (302 bytes, `.eh_frame+0x0050dd20`, CIE `0x002dc714`, a different CIE from the window) — but its body is excluded here all the same, so no claim about what it computes, or what its nonzero values mean, is made.
- The single caller at `0x3cbfa87` sits in a 1,058-byte FDE (`0x3cbf7a0..0x3cbfbc2`, `.eh_frame+0x0050d87c`, CIE `0x002dc714`). The caller passes a stack address (`lea rdi, [rsp + 0x40]`) and, after the call, jumps to a continuation inside its own FDE. The caller role beyond the call site is not established.
- The neighboring window at `0x3cbf030` shares the opening prologue shape with this one (six pushes, sub) and also calls `0x3cc6500`, but it is not a twin: its body bytes match this window at only 0.296 over the overlap, its skeleton differs, and it is a 944-byte window with a different shape. It is context, not a duplicate.

## Inferences

- Inferred label: retry-loop helper. The rule is observed and proven above; only the label is inferred. The callee result convention (nonzero terminates, zero retries) follows directly from the test/jne branch; calling the loop a "retry" is the inference.
- The fixed rsi address, the global qword, and the struct + 0x20 slot entry read as a context bundle passed to the callee on every attempt, but what they mean is not established, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the call site.

## Unknowns

- The source-level name and types of this window, its struct, and its attempts count.
- What the shared callee at `0x3cc6500` computes, what its nonzero values mean, and what the fixed address `0x1ea44d`, the global at `0x576e780`, and the struct + 0x20 slot entry are.
- Why the attempts count lives at struct + 0x18, and whether any caller other than the verified one distinguishes the 0 return from a callee 0.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
