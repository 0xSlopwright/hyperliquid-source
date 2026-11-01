# foundation-capacity-clamp-94: what does the capacity-clamp window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-capacity-clamp-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the big-band calls category's gate-singleton slice after the small-band queue was exhausted, as the first usable compound backup behind the length-prefix encode window (the other compound backup, the struct-init window at 0x54d7320, was not built: it writes six struct fields and calls an 1104-byte callee, so it falls in the excluded struct-init family).
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 110-byte FDE window, its two int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE, which itself checks the sentinel return), the single call edge to a shared callee, and the exact capacity-clamp rule over the clamp formula and the callee flag byte.
- Excluded: the callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose capacity-clamp rule reads directly from its own bytes: clamp a requested count between a floor of 4 and twice the old capacity, call a shared helper with the old capacity, the old pointer, and the clamped value, and then either store the clamped value and return a sentinel or return the helper's output pair, depending on the helper's flag byte. It is the third packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x4f050a0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.053 against the divide-by-million window, 0.041 against the scaled-count window, 0.031 against the TLS-table-index window, 0.050 against the error-band range-check window, 0.049 against the cached-pointer-refresh window, 0.034 against the min-cap gap-check window, 0.027 against the offset-equality window, 0.071 against the two-mode limit-check window, 0.024 against the global-bounds-gated equality window, 0.000 against the struct-init flag-pack window, 0.011 against the all-records flag-scan window, 0.041 against the helper low-byte equality window, 0.026 against the byte-gate counter window, 0.044 against the triple-min inequality window, 0.000 against the u32 second-field equality window, 0.022 against the cache-refresh zero-test window, 0.036 against the length-prefix encode window, 0.036 against the validate-or-EINVAL gate window, none against the older claimed corpus). Its mnemonic skeleton (`push, mov, push, push, sub, mov, inc, mov, lea, cmp, cmovbe, cmp, mov, cmovae, mov, lea, mov, mov, call, cmp, je, mov, mov, jmp, mov, mov, mov, movabs, add, pop, pop, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population. It is also not a member of the killed cmovbe comparator family: the cmovbe here is one clamp step inside a 33-mnemonic skeleton that includes a call and a flag branch, not a pure comparator, and no family member shares its skeleton or 60% of its bytes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_capacity_clamp.py --check research/work-items/foundation-capacity-clamp-94/evidence.json
python3 -m unittest tests.test_foundation_capacity_clamp -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4f050a0 --stop-address=0x4f05110 artifacts/node/94/hl-node
objdump -d --start-address=0x4f04a30 --stop-address=0x4f04a59 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x00282368` (this window), `0x0028238c` (the next FDE, bounding the padding), `0x0028213c` (the first caller), and `0x00282318` (the shared callee) — all four use CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x00282368` describes `[0x4f050a0, 0x4f0510e)`, 110 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x4f0510d`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x4f05110`, only because two `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those two padding bytes, and the checker locks the 110-byte body and the padding separately.
- The window starts with `push rbp`, not `endbr64`; no claim is made about why it lacks the landing pad.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x4f04a37`, verified as an instruction start by disassembly from its containing FDE start (`0x4f04a30`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: clamp, call, then store-plus-sentinel or pair return

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4f050a0` | `push rbp` | Entry |
| `0x4f050a1` | `mov rbp, rsp` | Frame |
| `0x4f050a4` | `push r14` | Save callee-saved register |
| `0x4f050a6` | `push rbx` | Save callee-saved register |
| `0x4f050a7` | `sub rsp, 0x20` | Frame for the out-struct |
| `0x4f050ab` | `mov rbx, rdi` | Save the struct pointer |
| `0x4f050ae` | `inc rsi` | Requested + 1 |
| `0x4f050b1` | `mov rax, [rdi]` | Old capacity |
| `0x4f050b4` | `lea rcx, [rax + rax]` | Twice the old capacity |
| `0x4f050b8` | `cmp rsi, rcx` | Upper-clamp test |
| `0x4f050bb` | `cmovbe rsi, rcx` | rsi = min(requested + 1, 2 * oldcap) |
| `0x4f050bf` | `cmp rsi, 5` | Floor test |
| `0x4f050c3` | `mov r14d, 4` | Floor value |
| `0x4f050c9` | `cmovae r14, rsi` | newcap = rsi if rsi >= 5, else 4 |
| `0x4f050cd` | `mov rdx, [rdi + 8]` | Old pointer |
| `0x4f050d1` | `lea rdi, [rbp - 0x28]` | Out-struct for the callee |
| `0x4f050d5` | `mov rsi, rax` | Callee rsi = old capacity |
| `0x4f050d8` | `mov rcx, r14` | Callee rcx = newcap |
| `0x4f050db` | `call 0x4f04f30` | Shared callee; its body is excluded |
| `0x4f050e0` | `cmp byte [rbp - 0x28], 0` | Flag test on the callee output |
| `0x4f050e4` | `je 0x4f050f0` | Flag clear takes the store path |
| `0x4f050e6` | `mov rax, [rbp - 0x20]` | Pair first element (out + 8) |
| `0x4f050ea` | `mov rdx, [rbp - 0x18]` | Pair second element (out + 16) |
| `0x4f050ee` | `jmp 0x4f05105` | Join the epilogue |
| `0x4f050f0` | `mov rax, [rbp - 0x20]` | Out + 8 for the store |
| `0x4f050f4` | `mov [rbx + 8], rax` | Store out + 8 into the struct pointer field |
| `0x4f050f8` | `mov [rbx], r14` | Store newcap into the struct capacity field |
| `0x4f050fb` | `movabs rax, 0x8000000000000001` | Sentinel return value |
| `0x4f05105` | `add rsp, 0x20` | Epilogue |
| `0x4f05109` | `pop rbx` | Epilogue |
| `0x4f0510a` | `pop r14` | Epilogue |
| `0x4f0510c` | `pop rbp` | Epilogue |
| `0x4f0510d` | `ret` | Return |

- The rule, over struct pointer (`rdi`), requested count (`rsi`), old capacity (the qword at `[rdi]`), old pointer (the qword at `[rdi + 8]`), and the callee outputs (flag byte at out + 0, qword at out + 8, qword at out + 16), is: let `newcap = max(4, min((requested + 1) mod 2^64, (2 * oldcap) mod 2^64))`; call `0x4f04f30` with `rdi` = the stack out-struct at `[rbp - 0x28]`, `rsi` = oldcap, `rdx` = oldptr, `rcx` = newcap; if the flag byte at out + 0 is 0, store newcap into the struct capacity field and out + 8 into the struct pointer field and return `0x8000000000000001`; else return `rax` = out + 8 and `rdx` = out + 16.
- The clamp is unsigned and exact on both sides of both bounds: the upper clamp binds at requested + 1 = 2 * oldcap (cmovbe takes the equal value, so the equality case is covered, not just the strict case), and the floor binds at minimum 5 (cmovae keeps the minimum) versus minimum 4 and below (the floor 4 replaces it). The arithmetic wraps mod 2^64: requested `2^64 - 1` increments to 0, and an old capacity of `2^64 - 1` doubles to `2^64 - 2`; both wraps are recorded as edges.
- The window does not set `rdx` on the flag-clear path, so `rdx` after a sentinel return is not determined by this window's bytes alone; only `rax` = sentinel is claimed there. On the flag-set path the window returns the (out + 8, out + 16) pair in `rax:rdx` without storing into the struct.
- The callee at `0x4f04f30` IS an FDE start (144 bytes, `.eh_frame+0x00282318`, CIE `0x00000000`, the same CIE as the window) — but its body is excluded here all the same, so no claim about what it computes, or what makes it set or clear the flag byte, is made.
- The single caller at `0x4f04a37` sits in a 41-byte FDE (`0x4f04a30..0x4f04a59`, `.eh_frame+0x0028213c`, CIE `0x00000000`, the same CIE as the window). The caller stores its `rsi` into the struct capacity field immediately before the call, so for that caller oldcap equals requested at entry and the formula reduces to requested + 1 floored to 4; that reduction is caller context, not the general rule. The caller then compares the window return against the sentinel (`movabs rcx, 0x8000000000000001; cmp rcx, rax; jne`), so the sentinel convention is consumed by a verified caller. The caller role beyond that check is not established.
- The neighboring window at `0x4f05110` shares the opening prologue shape with this one, but it is not a twin: its body bytes match this window at only 0.118 over the overlap, its skeleton differs, and it has no call to `0x4f04f30`. It is context, not a duplicate.

## Inferences

- Inferred label: capacity-clamp helper. The rule is observed and proven above; only the label is inferred. The label says "clamp", not "grow", because the formula can produce a value below the old capacity when the request is small; whether the caller ever passes such a request is not established.
- The out-struct plus flag byte reads as a try-resize contract — the callee reports back through the flag whether the caller should use the stored struct fields or the returned pair — but what the callee does, what the flag means, and what the pair's second element is are not established, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the call site and its sentinel check.

## Unknowns

- The source-level name and types of this window, its struct, and its requested count.
- What the shared callee at `0x4f04f30` computes, what sets or clears its flag byte, and what the out + 16 qword means.
- Why the sentinel is `0x8000000000000001`, and whether any caller other than the verified one distinguishes it.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
