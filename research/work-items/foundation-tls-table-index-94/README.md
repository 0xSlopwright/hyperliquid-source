# foundation-tls-table-index-94: what does the TLS-table-index window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-tls-table-index-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was found by mnemonic-skeleton enumeration of small gate single-call windows.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 98-byte FDE window, its fourteen int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the slow-path call edge, and the exact index formula over the input domain.
- Excluded: the slow-path callee body at `0x555a760`, the other 173 raw call sites beyond the scan list, the table contents, other TLS-index windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose index rule reads directly from its own bytes: two constant sentinels, one table-driven sentinel, a plus-two general case, and a scaled table load, behind a TLS byte gate with a slow-path initializer call. It is the first packet from the calls category's gate-singleton slice: like the scaled-count window, its rule is stated over its inputs and the table pointer, with the callee and table contents explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x54f3190`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (closest below 0.30 against the claimed corpus, at most 0.09 against round-25 do-not-build bodies). Its mnemonic skeleton is a singleton among small gate single-call windows. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tls_table_index.py --check research/work-items/foundation-tls-table-index-94/evidence.json
python3 -m unittest tests.test_foundation_tls_table_index -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54f3190 --stop-address=0x54f3200 artifacts/node/94/hl-node
objdump -d --start-address=0x54f3200 --stop-address=0x54f34c0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2c40f0` (this window) and `0x2c4110` (the first caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c40f0` describes `[0x54f3190, 0x54f31f2)`, 98 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x54f31dc` is inside the FDE, and so are the `nop` at `0x54f31de` and the slow path at `0x54f31e0`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x54f3200`, only because fourteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those fourteen padding bytes, and the checker locks the 98-byte body and the padding separately.
- A byte-pattern scan of `.text` finds 174 direct `e8` calls to the window. The first call site (`0x54f32b4`) was verified as an instruction start by disassembly from its containing FDE start (`0x54f3200`). The other 173 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one TLS gate, one table, one index formula

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x54f3190` | `push rbx` | Save callee-saved register |
| `0x54f3191` | `mov rbx, rdi` | Save input |
| `0x54f3194` | `mov rdi, 0xffffffffffffef60` | TLS slot constant (sign-extended imm32 `-0x10a0`) |
| `0x54f319b` | `cmp byte ptr fs:[rdi + 0x330], 0` | TLS byte gate |
| `0x54f31a2` | `jne 0x54f31e0` | Nonzero byte routes to the slow path |
| `0x54f31a5` | `mov rdx, qword ptr [rip + 0x4a74c4]` | Load table base `0x599a670` |
| `0x54f31ac` | `xor eax, eax` | Index 0 default |
| `0x54f31ae` | `cmp rbx, 0x1000` | First constant sentinel |
| `0x54f31b7` | `mov eax, 1` | Index 1 |
| `0x54f31bc` | `cmp rbx, 0x1001` | Second constant sentinel |
| `0x54f31c5` | `mov ecx, dword ptr [rdx + 8]` | Table sentinel (second qword; low 32 bits) |
| `0x54f31c8` | `lea eax, [rbx + 2]` | General index |
| `0x54f31cb` | `mov esi, 0` | Index 0 for the table-sentinel case |
| `0x54f31d0` | `cmp rbx, rcx` | Table-sentinel test |
| `0x54f31d3` | `cmove rax, rsi` | Table sentinel maps to index 0 |
| `0x54f31d7` | `mov rax, qword ptr [rdx + rax*8 + 0x18]` | Entry load |
| `0x54f31dc` | `pop rbx` | Restore callee-saved register |
| `0x54f31dd` | `ret` | Return the entry |
| `0x54f31e0` | `add rdi, qword ptr fs:[0]` | Slow path: add the TLS base |
| `0x54f31e9` | `xor esi, esi` | Slow path: zero second argument |
| `0x54f31eb` | `call 0x555a760` | Slow-path initializer; its body is excluded |
| `0x54f31f0` | `jmp 0x54f31a5` | Slow path rejoins at the table load, skipping the gate |

- The index formula, over a u64 input `rbx` and the table's second qword `table1`, is: `0` if `rbx == 0x1000`; `1` if `rbx == 0x1001`; `0` if `rbx == zero_extend(low32(table1))`; otherwise `(rbx + 2) mod 2**64`. The entry address is `table_base + 0x18 + index * 8`.
- The gate polarity is observed, not assumed: a nonzero TLS byte routes to the slow path, a zero byte proceeds directly. After the slow-path call, control rejoins at the table load without re-testing the gate.
- The table-sentinel comparison uses only the low 32 bits of the second qword (`mov ecx, dword ptr [rdx + 8]`, zero-extended into `rcx`), while the general index is a full 64-bit `rbx + 2`. The sentinel condition is therefore `rbx == zero_extend(low32(table[1]))`: the table qword's high 32 bits play no role, and only inputs exactly equal to that zero-extended value map to index 0.
- The slow-path callee at `0x555a760` is a 706-byte FDE whose body is excluded here. The window's rule is stated over its inputs and the table pointer, not over the callee's internals.
- The checker verifies the index formula on `0x1000 -> 0`, `0x1001 -> 1`, `table1 -> 0`, `0 -> 2`, `5 -> 7`, `0x1002 -> 0x1004`, `table1 + 1 -> table1 + 3`, and the wraparound edge `2**64 - 1 -> 1`, and the entry addresses for indices 0, 1, and 7 against the computed table base.

## Inferences

- Inferred label: TLS-table-index helper. The formula and the gate behavior are observed and proven above; only the label is inferred.
- The TLS byte gate plus the initializer call plus the rejoin-without-retest shape suggests lazy initialization of the table or its TLS slot, but the flag's meaning, the callee's role, and the reason the slow path skips the re-test are not closed here, so that reading is an inference only.
- The two constant sentinels plus one table-driven sentinel plus a plus-two general case suggest a table whose first two entries are reserved for special inputs, with general inputs shifted by two — but the table contents and the meaning of the entries are unknown.
- The 174 incoming direct calls suggest a widely used helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its table, and its slow-path callee.
- What the table entries contain; what the sentinel values mean.
- Why the TLS gate routes a nonzero byte to initialization; what `0x555a760` initializes.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The slow-path callee body at `0x555a760`, the other 173 call sites beyond the scan list, the table contents, other TLS-index windows, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
