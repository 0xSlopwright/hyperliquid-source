# foundation-u32-second-equality-94: what does the u32 second-field equality window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-u32-second-equality-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the triple-min inequality packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 51-byte FDE window, its thirteen int3 padding bytes, the shared-callee call edge (the memcmp@plt stub), and the exact u32 second-field equality rule over the return low byte.
- Excluded: the shared callee body behind the PLT stub, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose u32 second-field equality rule reads directly from its own bytes: compare two 32-bit count fields, and only when they agree compare the two buffers over count times eight bytes with memcmp. It is the thirteenth packet from the calls category's gate-singleton slice: like the triple-min inequality window, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded — here the callee is a PLT stub, so there is no callee body in this binary at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x552fbe0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.105 against the divide-by-million window, 0.082 against the scaled-count window, 0.000 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.171 against the cached-pointer-refresh window, 0.118 against the min-cap gap-check window, 0.098 against the offset-equality window, 0.098 against the two-mode limit-check window, 0.137 against the global-bounds-gated equality window, 0.098 against the struct-init flag-pack window, 0.000 against the all-records flag-scan window, 0.102 against the helper low-byte equality window, 0.078 against the byte-gate counter window, 0.098 against the triple-min inequality window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, mov, cmp, jne, sub, mov, mov, shl, call, test, sete, add, ret, nop, xor, ret`) is a singleton among 31,898 small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_u32_second_equality.py --check research/work-items/foundation-u32-second-equality-94/evidence.json
python3 -m unittest tests.test_foundation_u32_second_equality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x552fbe0 --stop-address=0x552fc20 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDE at `.eh_frame` section offset `0x002cbaa0` (this window) and the header line of the next FDE at `0x002cbab8` (whose PC start `0x552fc20` bounds the padding). The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002cbaa0` describes `[0x552fbe0, 0x552fc13)`, 51 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x552fc12`).
- The unwind index stride to the next entry is 64 bytes, ending at `0x552fc20`, only because thirteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those thirteen padding bytes, and the checker locks the 51-byte body and the padding separately.
- A byte-pattern scan of `.text` finds zero direct `e8` calls to the window. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census. No caller file is included, so this packet has 7 files.

### Body behavior: one u32 gate, one scaled memcmp, one low-byte verdict

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x552fbe0` | `endbr64` | Entry |
| `0x552fbe4` | `mov edx, dword ptr [rdi + 8]` | First input's u32 second field |
| `0x552fbe7` | `cmp edx, dword ptr [rsi + 8]` | Second input's u32 second field vs first |
| `0x552fbea` | `jne 0x552fc10` | Unequal seconds take the zero return |
| `0x552fbec` | `sub rsp, 8` | Stack alignment for the call |
| `0x552fbf0` | `mov rsi, qword ptr [rsi]` | Second buffer pointer |
| `0x552fbf3` | `mov rdi, qword ptr [rdi]` | First buffer pointer |
| `0x552fbf6` | `shl rdx, 3` | Scaled length: count times 8 |
| `0x552fbfa` | `call 0x5660150` | memcmp@plt; its body is excluded |
| `0x552fbff` | `test eax, eax` | memcmp result vs zero |
| `0x552fc01` | `sete al` | al = 1 iff memcmp result is zero |
| `0x552fc04` | `add rsp, 8` | Epilogue |
| `0x552fc08` | `ret` | Return |
| `0x552fc09` | `nop dword ptr [rax]` | 7-byte padding inside the window |
| `0x552fc10` | `xor eax, eax` | Gate-failure verdict 0 |
| `0x552fc12` | `ret` | Return |

- The return rule, over the first second `a_second` (u32 at first input struct + `0x08`), the second second `b_second` (u32 at second input struct + `0x08`), and the buffers at first input struct + `0x00` and second input struct + `0x00`, is: if `a_second != b_second`, return 0 in `al` (eax fully zeroed, no call); else return 1 in `al` iff `memcmp(a_first, b_first, a_second << 3) == 0`, else 0 in `al`.
- The gate compares 32-bit fields: `mov edx, dword ptr [rdi + 8]` zero-extends the first second into rdx, and `cmp edx, dword ptr [rsi + 8]` compares it against the second second as a u32. The memcmp length is therefore the u32 count shifted left by 3 — count 8-byte elements, not bytes.
- The callee is called with rdi = a_first, rsi = b_first, rdx = a_second << 3. On the equal path the two seconds agree, so the length is the common count times eight either way.
- The rule is stated over `al` only: the gate-failure path zeroes all of eax, but the memcmp path's `sete` sets just the low byte, and the upper bytes of eax after the memcmp call are the callee's return bits, not determined by this window's bytes alone. No claim about them is made.
- The shared callee at `0x5660150` is the memcmp@plt stub (`jmp *GOT`, `push`, `jmp PLT0`), not an FDE start, so no body size is claimed for it. The window's rule is stated over the memcmp result's zero/nonzero status, not over memcmp's internals.

## Inferences

- Inferred label: u32 second-field equality helper. The rule is observed and proven above; only the label is inferred.
- The gate-then-compare shape suggests a predicate that checks whether two variable-length records with 8-byte elements agree over their full extent, after first requiring their element counts to match — but what the input structs, the buffers, and the count fields mean are not closed here, so that reading is an inference only.
- Zero incoming direct calls does not mean the window is dead code: it may be reached through a pointer or from another object, but no caller is established here.

## Unknowns

- The source-level name and types of this window, its input structs, its buffers, and its count fields.
- What the count fields and the 8-byte element size represent.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body behind the memcmp@plt stub, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
