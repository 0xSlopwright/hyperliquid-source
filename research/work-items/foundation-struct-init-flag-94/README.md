# foundation-struct-init-flag-94: what does the struct-init flag-pack window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-struct-init-flag-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the global-bounds-gated equality packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 72-byte FDE window, its eight int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact struct-init flag-pack rule over the inputs and the callee result.
- Excluded: the shared callee body at `0x5660c60`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose struct-init rule reads directly from its own bytes: initialize two fields, skip the callee call on a zero second input, otherwise pack a flag byte into a call argument and map a -1 callee result to zero. It is the eighth packet from the calls category's gate-singleton slice: like the global-bounds-gated equality window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x53349d0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.158 against the divide-by-million window, 0.102 against the scaled-count window, 0.056 against the TLS-table-index window, 0.025 against the error-band range-check window, 0.220 against the cached-pointer-refresh window, 0.056 against the min-cap gap-check window, 0.097 against the offset-equality window, 0.083 against the two-mode limit-check window, 0.083 against the global-bounds-gated equality window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, mov, mov, mov, test, je, movzx, xor, mov, xor, shl, mov, or, call, xor, cmp, cmove, mov, mov, pop, ret`) is a singleton among small (20–150 byte) single-call FDE windows. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_struct_init_flag.py --check research/work-items/foundation-struct-init-flag-94/evidence.json
python3 -m unittest tests.test_foundation_struct_init_flag -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53349d0 --stop-address=0x5334a20 artifacts/node/94/hl-node
objdump -d --start-address=0x5334a20 --stop-address=0x5334a64 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002afd84` (this window) and `0x002afda0` (the first caller) — the two FDEs share CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002afd84` describes `[0x53349d0, 0x5334a18)`, 72 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5334a17`).
- The unwind index stride to the next entry is 80 bytes, ending at `0x5334a20`, only because eight `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those eight padding bytes, and the checker locks the 72-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x5334a41`, verified as an instruction start by disassembly from its containing FDE start (`0x5334a20`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: two field stores, one zero skip, one flag pack, one -1 mapping

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x53349d0` | `endbr64` | Entry |
| `0x53349d4` | `push rbx` | Save callee-saved register |
| `0x53349d5` | `mov rbx, rdi` | Save input struct pointer |
| `0x53349d8` | `mov qword ptr [rdi], 0` | First field initialized to 0 |
| `0x53349df` | `mov qword ptr [rdi + 8], rsi` | Second field stores the second input |
| `0x53349e3` | `test rsi, rsi` | Zero-second test |
| `0x53349e6` | `je 0x5334a13` | Zero second skips the callee call |
| `0x53349e8` | `movzx ecx, dl` | Flag byte, zero-extended from dl |
| `0x53349eb` | `xor r9d, r9d` | Sixth callee argument: 0 |
| `0x53349ee` | `mov edx, 3` | Third callee argument: mode 3 |
| `0x53349f3` | `xor edi, edi` | First callee argument: 0 |
| `0x53349f5` | `shl ecx, 0x12` | Flag shifted left by 18 |
| `0x53349f8` | `mov r8d, 0xffffffff` | Fifth callee argument: -1 |
| `0x53349fe` | `or ecx, 0x22` | Packed fourth argument: (flag << 18) \| 0x22 |
| `0x5334a01` | `call 0x5660c60` | Shared callee; its body is excluded |
| `0x5334a06` | `xor edx, edx` | Zero for the -1 mapping |
| `0x5334a08` | `cmp rax, -1` | Callee result vs -1 |
| `0x5334a0c` | `cmove rax, rdx` | -1 maps to 0 |
| `0x5334a10` | `mov qword ptr [rbx], rax` | First field stores the mapped result |
| `0x5334a13` | `mov rax, rbx` | Return the input struct pointer |
| `0x5334a16` | `pop rbx` | Restore callee-saved register |
| `0x5334a17` | `ret` | Return |

- The return rule, over the second input `second` (u64 in rsi), the flag byte `flag` (low byte of rdx at entry), and the callee result (u64 rax from the call), is: `out[0] = 0; out[1] = second; if second == 0, return out` (no call); `packed = ((flag & 0xff) << 18) | 0x22`; `result = callee(0, second, 3, packed, -1, 0)`; `out[0] = 0 if result == 2**64 - 1 else result`; return `out` (the input struct pointer in rax).
- The callee is called with rdi = 0, rsi = second (never reassigned before the call), rdx = 3, rcx = packed, r8 = -1, r9 = 0. The rule depends only on the callee's return value, not its internals.
- The zero-second skip is observable: with second == 0 the window returns with out[0] = 0 and out[1] = 0 without calling, regardless of the flag byte. The checker verifies this on two edges (flag 0x00 and flag 0xff).
- The flag packing is exact: flag 0x00 packs to 0x22, flag 0x01 to 0x40022, flag 0xff to 0x3fc0022, flag 0xab to 0x2ac0022. Only the low byte of rdx matters, because `movzx ecx, dl` zero-extends exactly that byte.
- The -1 mapping is exact and distinct from a zero result: callee result 2**64 - 1 maps to out[0] = 0, while callee result 2**64 - 2 passes through unchanged and callee result 0 passes through as 0. The checker verifies all three.
- The shared callee at `0x5660c60` is not an FDE start, so no body size is claimed for it. The window's rule is stated over the callee result, not over the callee's internals.

## Inferences

- Inferred label: struct-init flag-pack helper. The rule is observed and proven above; only the label is inferred.
- The initialize-then-conditionally-call shape suggests a constructor that fills a two-field record and, for a nonzero second field, resolves the first field through a helper keyed by a packed flag, but what the struct, the callee, and the flag mean are not closed here, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input struct, its shared callee, and its flag.
- What the callee computes; why its first argument is 0, its third is 3, and its fifth is -1.
- What the packed flag's bit 0x22 and the shifted flag bits represent.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5660c60`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
