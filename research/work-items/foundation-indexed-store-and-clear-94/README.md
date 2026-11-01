# foundation-indexed-store-and-clear-94: what does the indexed-store-and-clear window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-indexed-store-and-clear-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was mined fresh from the small-band (20–100 byte) non-gate single-call slice after the big-band gate-singleton direct-call well ran dry, and it passed every guard on its own merits.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 59-byte FDE window, its five int3 padding bytes, the single call edge to the 58-byte callee, the single incoming direct-call scan result (none), and the exact indexed-store-and-clear rule over the object, the table holder, the index, and the value.
- Excluded: the callee implementation beyond its 58 retained bytes, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose indexed-store-and-clear rule reads directly from its own bytes: compute a table entry from an index, store through a callee, then clear the caller's own object fields and return the object. It is the tenth packet from the calls category's single-call slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5240c20`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes under either measure (max-length best 0.254 against `0x4fd4040`, a 67-byte body; 0.119 against the scaled-count window and the cache-refresh zero-test window, the rest lower, none against the older claimed corpus); its mnemonic skeleton (`endbr64, mov, push, mov, mov, mov, mov, shl, add, call, xor, mov, mov, mov, mov, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The min-length comparison is reported head-on rather than hidden: across the same full corpus with the same >=20-byte substance floor, there are zero hits at or above 0.60 — no >=20-byte body shares 60% or more of this window's shorter length. The 5-byte `endbr64; ret` stubs that produced min-length hits for earlier packets are below the floor and are not twins of a 59-byte window.

The neighbor question is also addressed head-on, not hidden. The three windows immediately following this one share only the 4-instruction entry computation (`mov` table-struct pointer, `mov` index, `shl` 4, `add` table base) and then tail-jump instead of calling, clearing, and returning: `0x5240c60` (jumps to `0x5434080`), `0x5240c80` (jumps to `0x5434fe0`), and `0x5240ca0` (jumps to `0x5436ee0`). Their skeletons (`endbr64, mov, mov, shl, add, jmp`) repeat among themselves and are not singletons. This window `0x5240c20` is genuinely distinguishable from each of them: it is the only one that calls a callee with the computed entry, zeroes three fields of its own object (with the 2-byte hole at offsets 6–7 preserved), and returns the object pointer. Only this one window is built; no neighbor is claimed anywhere in this packet.

The callee question is addressed head-on as well. The callee at `0x54340c0` is called directly from exactly one site in `.text`: this window's call at `0x5240c3d`. It is not a shared callee population (contrast the 15-window shared callee that killed a big-band candidate in #146). Its 58 retained bytes are kept in the packet, but its behavior is excluded from the rule: the rule claims only the call edge and its argument registers, never what the callee does with them.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_indexed_store_and_clear.py --check research/work-items/foundation-indexed-store-and-clear-94/evidence.json
python3 -m unittest tests.test_foundation_indexed_store_and_clear -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54340c0 --stop-address=0x5434100 artifacts/node/94/hl-node
objdump -d --start-address=0x5240c20 --stop-address=0x5240c60 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the callee and the window including their padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002a6664` (this window), `0x002a6680` (the next FDE, bounding the padding), `0x002bb3a8` (the callee), and `0x002bb3d4` (the FDE after the callee) — all four use CIE `0x00000000`. (Note the `objdump --dwarf=frames` line format: the third column is the FDE record's CIE-pointer delta, not its CIE — the CIE is the value after `cie=`.) The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002a6664` describes `[0x5240c20, 0x5240c5b)`, 59 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5240c5a`).
- The unwind index stride to the next entry is 64 bytes, ending at `0x5240c60`, only because five `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those five padding bytes, and the checker locks the 59-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window, so no caller file is included and this packet has 7 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: indexed entry call, then three-field clear and object return

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5240c20` | `endbr64` | Entry |
| `0x5240c24` | `mov %rsi, %rax` | Table-holder pointer |
| `0x5240c27` | `push %rbx` | Save callee-saved register |
| `0x5240c28` | `mov %rdi, %rbx` | Save the object pointer |
| `0x5240c2b` | `mov %edx, %edi` | Index into edi (zero-extended) |
| `0x5240c2d` | `mov 0xa8(%rax), %rax` | Table-struct pointer |
| `0x5240c34` | `mov %ecx, %esi` | Value into esi (zero-extended) |
| `0x5240c36` | `shl $0x4, %rdi` | Index times 16 |
| `0x5240c3a` | `add (%rax), %rdi` | Entry = table base + 16 * idx |
| `0x5240c3d` | `call 0x54340c0` | Indexed callee (behavior excluded) |
| `0x5240c42` | `xor %eax, %eax` | Discard the callee result |
| `0x5240c44` | `movl $0x0, (%rbx)` | Zero bytes [obj + 0 .. 4) |
| `0x5240c4a` | `mov %ax, 0x4(%rbx)` | Zero bytes [obj + 4 .. 6) |
| `0x5240c4e` | `mov %rbx, %rax` | Return the object pointer |
| `0x5240c51` | `movq $0x0, 0x8(%rbx)` | Zero bytes [obj + 8 .. 16) |
| `0x5240c59` | `pop %rbx` | Epilogue |
| `0x5240c5a` | `ret` | Return |

- The rule, over object pointer (`rdi`), table holder (`rsi`), index (`edx`, zero-extended to 64 bits), and value (`ecx`, zero-extended to 64 bits), is: let table_base be the qword at `[[rsi + 0xa8]]` and entry be table_base + (index * 16) in 64-bit arithmetic; call `0x54340c0` with `rdi` = entry and `rsi` = value; then set bytes `[obj + 0 .. 6)` and `[obj + 8 .. 16)` to 0, leave bytes `[obj + 6 .. 8)` untouched, and return the object pointer in `rax`.
- The callee at `0x54340c0` IS an FDE start (58 bytes, `.eh_frame+0x002bb3a8`, CIE `0x00000000`, the same CIE as the window), and its 58 retained bytes are kept in the packet. Six `int3` bytes pad it to the next FDE at `0x5434100`. The callee's behavior is excluded from the rule: the rule claims the call edge and its two argument registers only, never what the callee does with the entry and the value, and never the callee's own control flow (including its conditional path). The disassembly's PLT annotations inside the retained callee bytes are relocation-based labels, not identifications of this window.
- The callee result is discarded: `xor %eax, %eax` immediately follows the call, so the window's return value is the object pointer, never the callee result.
- The window writes nothing else: the only stores are the three zeroing stores (dword at +0, word at +4, qword at +8), and the single pushed register is popped on the only path, so the stack is balanced.
- Direct callers: none. A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window. The window is reached only indirectly, or not at all, by direct call.

## Inferences

- Inferred label: indexed-store-and-clear helper. The rule is observed and proven above; only the label is inferred. The 16-byte stride reads as indexing a table of 16-byte entries, and the three-field clear reads as resetting the caller's object after the store, but what the table, the entries, the object, and the preserved 2-byte field are is not established, so that reading is an inference only.
- The absence of incoming direct calls suggests a narrowly used helper, or one reached only indirectly, but the caller role is not established at all.

## Unknowns

- The source-level name and types of this window, its object, its table holder, and its table entries.
- What the callee does with the entry and the value, and what the preserved bytes at object offsets 6–7 mean.
- Whether the callee's conditional path is reachable in practice; the callee's behavior is excluded, so this is not established.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation beyond its 58 retained bytes, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
