# foundation-all-empty-gate-94: what does the all-empty-gate window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-all-empty-gate-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked first from the #142 scout's fresh-mining backups (five range-emptiness checks, then a no-op-stub call plus a counter decrement) after the named big-band backups were exhausted.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 109-byte FDE window, its three int3 padding bytes, the single call edge to a shared 5-byte no-op callee, and the exact all-empty-gate rule over the five qword pairs and the 32-bit counter decrement.
- Excluded: the callee implementation beyond its 5 retained bytes, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose all-empty-gate rule reads directly from its own bytes: unless five qword pairs in an inner struct are all equal, return without calling anything; when they are all equal, call a shared helper with a fixed argument and decrement a counter. It is the sixth packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x50a90a0`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes (0.158 against the divide-by-million window, 0.143 against the scaled-count window, 0.102 against the TLS-table-index window, 0.050 against the error-band range-check window, 0.098 against the cached-pointer-refresh window, 0.069 against the min-cap gap-check window, 0.080 against the offset-equality window, 0.118 against the two-mode limit-check window, 0.084 against the global-bounds-gated equality window, 0.083 against the struct-init flag-pack window, 0.033 against the all-records flag-scan window, 0.082 against the helper low-byte equality window, 0.092 against the byte-gate counter window, 0.067 against the triple-min inequality window, 0.078 against the u32 second-field equality window, 0.133 against the cache-refresh zero-test window, 0.092 against the length-prefix encode window, 0.073 against the validate-or-EINVAL gate window, 0.055 against the capacity-clamp window, 0.018 against the retry-loop window, 0.073 against the move-assign-tail window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, mov, mov, cmp, je, ret, nop, mov, cmp, jne, mov, cmp, jne, mov, cmp, jne, mov, cmp, jne, push, mov, mov, lea, call, mov, sub, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The raw min-length comparison does report 309 hits at or above 0.60, and they are addressed head-on rather than hidden: all 309 are bodies of 5–16 bytes (mostly 5-byte `endbr64; ret` stubs scoring 4/5 against this window's opening bytes). A 5-byte stub is not a twin of a 109-byte window; with the same >=20-byte substance floor the skeleton corpus uses, there are no >=0.60 hits besides the window itself.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_all_empty_gate.py --check research/work-items/foundation-all-empty-gate-94/evidence.json
python3 -m unittest tests.test_foundation_all_empty_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x50a90a0 --stop-address=0x50a9110 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002957c8` (this window), `0x002957e4` (the next FDE, bounding the padding), and `0x002afdc4` (the shared callee) — all three use CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002957c8` describes `[0x50a90a0, 0x50a910d)`, 109 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x50a910c`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x50a9110`, only because three `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those three padding bytes, and the checker locks the 109-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window, so no caller file is included and this packet has 7 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: five equality gates, then one call and a counter decrement

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x50a90a0` | `endbr64` | Entry |
| `0x50a90a4` | `mov rax, [rdi]` | Inner pointer |
| `0x50a90a7` | `mov rdx, [rax + 8]` | Pair 1 first qword |
| `0x50a90ab` | `cmp [rax + 0x10], rdx` | Pair 1 test |
| `0x50a90af` | `je 0x50a90b8` | Pair 1 equal continues |
| `0x50a90b1` | `ret` | Early return |
| `0x50a90b2` | `nopw 0x0(%rax,%rax,1)` | Alignment padding between paths |
| `0x50a90b8` | `mov rcx, [rax + 0x38]` | Pair 2 first qword |
| `0x50a90bc` | `cmp [rax + 0x40], rcx` | Pair 2 test |
| `0x50a90c0` | `jne 0x50a90b1` | Pair 2 unequal returns early |
| `0x50a90c2` | `mov rsi, [rax + 0x68]` | Pair 3 first qword |
| `0x50a90c6` | `cmp [rax + 0x70], rsi` | Pair 3 test |
| `0x50a90ca` | `jne 0x50a90b1` | Pair 3 unequal returns early |
| `0x50a90cc` | `mov rsi, [rax + 0x80]` | Pair 4 first qword |
| `0x50a90d3` | `cmp [rax + 0x88], rsi` | Pair 4 test |
| `0x50a90da` | `jne 0x50a90b1` | Pair 4 unequal returns early |
| `0x50a90dc` | `mov rsi, [rax + 0xb0]` | Pair 5 first qword |
| `0x50a90e3` | `cmp [rax + 0xb8], rsi` | Pair 5 test |
| `0x50a90ea` | `jne 0x50a90b1` | Pair 5 unequal returns early |
| `0x50a90ec` | `push rbx` | Save callee-saved register |
| `0x50a90ed` | `mov rax, [rdi + 8]` | Second pointer |
| `0x50a90f1` | `mov rbx, rdi` | Save the outer pointer |
| `0x50a90f4` | `lea rdi, [rax + 0x700]` | Callee argument |
| `0x50a90fb` | `call 0x5334d60` | Shared callee; a 5-byte no-op |
| `0x50a9100` | `mov rax, [rbx + 8]` | Second pointer, reloaded |
| `0x50a9104` | `sub dword [rax + 0x149c], 1` | Counter decrement |
| `0x50a910b` | `pop rbx` | Epilogue |
| `0x50a910c` | `ret` | Return |

- The rule, over outer pointer (`rdi`), inner pointer (the qword at `[rdi]`), second pointer (the qword at `[rdi + 8]`), the five qword pairs in the inner struct, and the counter (the dword at `[second + 0x149c]`), is: if any of the pairs `([inner + 8], [inner + 0x10])`, `([inner + 0x38], [inner + 0x40])`, `([inner + 0x68], [inner + 0x70])`, `([inner + 0x80], [inner + 0x88])`, `([inner + 0xb0], [inner + 0xb8])` is unequal, return with no call and no counter change; if all five pairs are equal, call `0x5334d60` with `rdi` = second + `0x700`, then decrement the dword at `[second + 0x149c]` by 1 (32-bit wrap) and return.
- The callee at `0x5334d60` IS an FDE start (5 bytes, `.eh_frame+0x002afdc4`, CIE `0x00000000`, the same CIE as the window), and its entire body is exactly `endbr64; ret` — a no-op. So the call itself is the only observed effect of the call step; the counter decrement is the window's only other effect, and it happens unconditionally once the gates pass, regardless of the callee (which returns nothing meaningful).
- The decrement is a 32-bit `subl`, not a 64-bit decrement: a counter of 0 wraps to `0xffffffff`, and a counter of `0x80000000` decrements to `0x7fffffff`. Both edges are recorded.
- No return value is claimed: on early paths `rax` still holds the inner pointer, and on the call path `rax` is reloaded to the second pointer before the decrement, so `rax` at `ret` is path-dependent and is not part of the rule.
- The window writes nothing else: the only store is the counter decrement, and the call path pushes and pops exactly one register, so the stack is balanced on every path.

## Inferences

- Inferred label: all-empty-gate helper. The rule is observed and proven above; only the label is inferred. The five pairs read as five ranges whose begin and end qwords must coincide (empty ranges), but what the pairs are is not established, so that reading is an inference only.
- The call-plus-decrement tail reads as a "release the last reference" or "drop the final guard" step gated on all five ranges being empty, but what the second struct, the `0x700` argument, and the counter mean is not established, so that reading is an inference only.
- The absence of incoming direct calls suggests a narrowly used helper, or one reached only indirectly, but the caller role is not established at all.

## Unknowns

- The source-level name and types of this window, its outer, inner, and second structs, and the five qword pairs.
- What the `0x700` callee argument and the `0x149c` counter field mean, and why the callee is a no-op.
- Whether any caller passes an inner struct whose pairs are ranges, and what happens to the counter if the window is reached indirectly.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation beyond its 5 retained bytes, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
