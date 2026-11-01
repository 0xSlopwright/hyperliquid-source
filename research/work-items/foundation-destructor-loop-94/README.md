# foundation-destructor-loop-94: what does the destructor-loop window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-destructor-loop-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was the second member of the destructor-loop pair ranked below 0x50a90a0 in the #142 scout's backups, examined only after its sibling 0x4f95980 was killed by the twin guard (see below), and it passed every guard on its own merits.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 136-byte FDE window, its eight int3 padding bytes, the single call edge to the operator delete PLT stub, the tail jump to the same stub, the five incoming direct call edges, and the exact destructor-loop rule over the 0x68-stride elements and the outer buffer.
- Excluded: the delete implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose destructor-loop rule reads directly from its own bytes: walk 0x68-byte elements, clear and release each live one, then release the outer buffer. It is the seventh packet from the big-band calls category's single-call slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x4fbb610`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes besides itself (0.240 against the offset-equality window, 0.143 against the helper low-byte equality window, 0.137 against the u32 second-field equality window, 0.115 against the min-cap gap-check window, 0.110 against the validate-or-EINVAL gate window, 0.105 against the divide-by-million window, 0.102 against the scaled-count window, 0.100 against the triple-min inequality window, 0.098 against the cached-pointer-refresh window, 0.097 against the struct-init flag-pack window, 0.089 against the cache-refresh zero-test window, 0.082 against the two-mode limit-check window, 0.072 against the global-bounds-gated equality window, 0.072 against the move-assign-tail window, 0.066 against the byte-gate counter window, 0.066 against the length-prefix encode window, 0.064 against the capacity-clamp window, 0.061 against the TLS-table-index window, 0.055 against the all-empty-gate window, 0.044 against the all-records flag-scan window, 0.017 against the retry-loop window, 0.000 against the error-band range-check window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, mov, push, push, mov, mov, cmp, je, nop, cmp, je, mov, mov, cmp, je, mov, test, je, mov, add, sub, call, cmp, jne, mov, test, je, mov, mov, sub, pop, pop, pop, jmp, nop, add, cmp, jne, jmp, pop, pop, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The raw min-length comparison does report 201 hits at or above 0.60, and they are addressed head-on rather than hidden: all 201 are bodies of exactly 5 bytes (5-byte `endbr64; ret` stubs scoring 4/5 against this window's opening bytes). A 5-byte stub is not a twin of a 136-byte window; with the same >=20-byte substance floor the skeleton corpus uses, there are no >=0.60 hits besides the window itself.

The sibling question is also addressed head-on, not hidden. The pair sibling 0x4f95980 (109 bytes, stride 0x10, per-element delete[] of the second field) was examined first and REJECTED, not built: its full-corpus >=20-byte-floor comparison reports two >=0.60 hits besides itself (0x50baf90 and 0x520a7c0, both 0.817, byte-identical to each other: stride 0x8, per-element virtual-destructor call, same tail) — so 0x4f95980 is a member of a repeated destructor-loop population and fails the twin guard. This window 0x4fbb610 is genuinely distinguishable from that sibling: byte similarity 0.349, stride 0x68 versus 0x10, per-element zero-plus-sync-plus-sized-delete versus plain delete[], call target operator delete PLT 0x5660440 versus operator delete[] PLT 0x5660480, size 136 versus 109 bytes, and a distinct mnemonic skeleton. Only this one member of the pair is built; the sibling is not claimed anywhere in this packet.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_destructor_loop.py --check research/work-items/foundation-destructor-loop-94/evidence.json
python3 -m unittest tests.test_foundation_destructor_loop -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4fbb610 --stop-address=0x4fbb6a0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly around each of the five direct call sites, with the call instruction verified as an instruction start inside its containing FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x0028d724` (this window), `0x0028d75c` (the next FDE, bounding the padding), and the five caller FDEs at `0x0062441c`, `0x00625504`, `0x006254a8`, `0x0063632c`, `0x0063650c` — the window and next FDE use CIE `0x00000000`, while all five caller FDEs share CIE `0x006205d0`, which differs from the window's CIE; the checker locks each record's own CIE rather than assuming one shared CIE. (Note the `objdump --dwarf=frames` line format: the third column is the FDE record's own field offset, not its CIE — the CIE is the value after `cie=`.) The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x0028d724` describes `[0x4fbb610, 0x4fbb698)`, 136 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x4fbb697`).
- The unwind index stride to the next entry is 144 bytes, ending at `0x4fbb6a0`, only because eight `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "144-byte FDE-bounded" would overstate the frame by those eight padding bytes, and the checker locks the 136-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 5 direct `e8` calls to the window, so a caller file is included and this packet has 8 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: per-element zero, sync, and sized delete, then an outer sized-delete tail

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4fbb610` | `endbr64` | Entry |
| `0x4fbb614` | `push r12` | Save callee-saved register |
| `0x4fbb616` | `mov rdi, r12` | Save the outer pointer |
| `0x4fbb619` | `push rbp` | Save callee-saved register |
| `0x4fbb61a` | `push rbx` | Save callee-saved register |
| `0x4fbb61b` | `mov 0x8(%rdi), %rbp` | End pointer |
| `0x4fbb61f` | `mov (%rdi), %rbx` | Begin pointer (loop cursor) |
| `0x4fbb622` | `cmp %rbx, %rbp` | Empty-range test |
| `0x4fbb625` | `je 0x4fbb669` | Empty range skips the loop |
| `0x4fbb627` | `nopw 0x0(%rax,%rax,1)` | Alignment padding between paths |
| `0x4fbb630` | `cmpq $0x0, (%rbx)` | Element first qword test |
| `0x4fbb634` | `je 0x4fbb63d` | Already zero skips the zeroing store |
| `0x4fbb636` | `movq $0x0, (%rbx)` | Zero the element first qword |
| `0x4fbb63d` | `mov 0x50(%rbx), %rdi` | Element second pointer |
| `0x4fbb641` | `cmp 0x58(%rbx), %rdi` | Sync-field test |
| `0x4fbb645` | `je 0x4fbb64b` | Already in sync skips the sync store |
| `0x4fbb647` | `mov %rdi, 0x58(%rbx)` | Sync the second pointer into its sync field |
| `0x4fbb64b` | `test %rdi, %rdi` | Second-pointer null test |
| `0x4fbb64e` | `je 0x4fbb688` | Null second pointer skips the call |
| `0x4fbb650` | `mov 0x60(%rbx), %rsi` | Element second end |
| `0x4fbb654` | `add $0x68, %rbx` | Advance the cursor (before the call) |
| `0x4fbb658` | `sub %rdi, %rsi` | Sized-delete size |
| `0x4fbb65b` | `call 0x5660440` | Operator delete PLT stub |
| `0x4fbb660` | `cmp %rbx, %rbp` | Loop-end test |
| `0x4fbb663` | `jne 0x4fbb630` | More elements |
| `0x4fbb665` | `mov (%r12), %rbx` | Outer buffer pointer |
| `0x4fbb669` | `test %rbx, %rbx` | Outer null test |
| `0x4fbb66c` | `je 0x4fbb693` | Null outer returns |
| `0x4fbb66e` | `mov 0x10(%r12), %rsi` | Outer end |
| `0x4fbb673` | `mov %rbx, %rdi` | Outer buffer argument |
| `0x4fbb676` | `sub %rbx, %rsi` | Outer sized-delete size |
| `0x4fbb679` | `pop %rbx` | Epilogue |
| `0x4fbb67a` | `pop %rbp` | Epilogue |
| `0x4fbb67b` | `pop %r12` | Epilogue |
| `0x4fbb67d` | `jmp 0x5660440` | Tail jump to operator delete PLT stub |
| `0x4fbb682` | `nopw 0x0(%rax,%rax,1)` | Alignment padding between paths |
| `0x4fbb688` | `add $0x68, %rbx` | Advance the cursor (call skipped) |
| `0x4fbb68c` | `cmp %rbx, %rbp` | Loop-end test |
| `0x4fbb68f` | `jne 0x4fbb630` | More elements |
| `0x4fbb691` | `jmp 0x4fbb665` | Loop done, fall into the tail |
| `0x4fbb693` | `pop %rbx` | Epilogue |
| `0x4fbb694` | `pop %rbp` | Epilogue |
| `0x4fbb695` | `pop %r12` | Epilogue |
| `0x4fbb697` | `ret` | Return |

- The rule, over outer pointer (`rdi`), begin pointer (the qword at `[rdi]`), end pointer (the qword at `[rdi + 8]`), each 0x68-byte element, and the outer buffer (the qword at `[rdi]`, with end at `[rdi + 0x10]`), is: for each element from begin to end in steps of 0x68: if the element first qword `[elem]` is nonzero, set it to 0; if the sync field `[elem + 0x58]` differs from the second pointer `[elem + 0x50]`, set `[elem + 0x58]` to `[elem + 0x50]`; if `[elem + 0x50]` is nonzero, call `0x5660440` with `rdi` = `[elem + 0x50]` and `rsi` = `[elem + 0x60]` - `[elem + 0x50]` (the call still happens when that size is 0). After the loop, if the outer buffer `[rdi]` is nonzero, tail-jump to `0x5660440` with `rdi` = `[rdi]` and `rsi` = `[rdi + 0x10]` - `[rdi]`; if it is zero, return.
- The callee at `0x5660440` is the operator delete PLT stub (`jmp *GOT`, `push 0x35`, `jmp PLT0`), not an FDE start, so no body size is claimed for it — the same exclusion pattern as the memcmp/memcpy/delete[] PLT callees of earlier calls packets. The delete implementation behind the stub is excluded, and the callee result (void) is not read. The call and the tail jump go to the same stub.
- The window writes nothing else: the only stores are the per-element zeroing and sync stores, and all three pushed registers are popped on every path, so the stack is balanced on every path (the tail jump pops before jumping, so the callee returns to the window's caller).
- No return value is claimed: the tail path never returns to the window at all, and the return path leaves `rax` untouched by the window's own logic.
- The five direct callers are `0x4fc861a` (FDE `0x4fc8130..0x4fc86b9`), `0x4fe1b40` (FDE `0x4fe1a2c..0x4fe1c10`), `0x4fe338f` (FDE `0x4fe1c10..0x4fe376a`), `0x5173670` (FDE `0x5172fc0..0x517379c`), and `0x51747a3` (FDE `0x5174755..0x5174849`), each verified as an `e8` instruction start inside its containing FDE; all five caller FDEs share CIE `0x006205d0`, distinct from the window's CIE `0x00000000`.

## Inferences

- Inferred label: destructor-loop helper. The rule is observed and proven above; only the label is inferred. The per-element zero-plus-sync-plus-delete shape reads as destroying a container of elements that each own a buffer, but what the container, the elements, and the sync field are is not established, so that reading is an inference only.
- The outer tail reads as releasing the container's own buffer after its elements, but what the outer struct is and why its end lives at offset `0x10` is not established, so that reading is an inference only.
- The five callers suggest a shared cleanup helper, but what calls it and why is not established.

## Unknowns

- The source-level name and types of this window, its outer struct, and its elements.
- What the element first qword, the `0x50`/`0x58`/`0x60` fields, and the outer `0x10` end field mean.
- Whether the sync field is ever observed differing in practice, and what the delete implementation does with a zero size.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The delete implementation behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
