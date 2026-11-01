# foundation-global-bounds-equality-94: what does the global-bounds-gated equality window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-global-bounds-equality-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the two-mode limit-check packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 83-byte FDE window, its single int3 padding byte, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact return rule over the callee result and the second-field difference.
- Excluded: the shared callee body at `0x5660df0`, the other 2 raw call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose return rule reads directly from its own bytes: an unsigned global-bounds gate on one input field, followed by a shared-callee equality test against the field difference. It is the seventh packet from the calls category's gate-singleton slice: like the two-mode limit-check window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x528e900`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.105 against the divide-by-million window, 0.082 against the scaled-count window, 0.036 against the TLS-table-index window, 0.000 against the error-band range-check window, 0.171 against the cached-pointer-refresh window, 0.084 against the min-cap gap-check window, 0.080 against the offset-equality window, 0.133 against the two-mode limit-check window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, xor, push, sub, lea, mov, cmp, jae, add, pop, pop, ret, nop, mov, mov, mov, call, mov, mov, sub, cmp, sete, add, pop, pop, ret`) is a singleton among 31,898 small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_global_bounds_equality.py --check research/work-items/foundation-global-bounds-equality-94/evidence.json
python3 -m unittest tests.test_foundation_global_bounds_equality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x528e900 --stop-address=0x528e954 artifacts/node/94/hl-node
objdump -d --start-address=0x528f020 --stop-address=0x528fb9f artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2a99fc` (this window, CIE `0x00000000`) and `0x647b68` (the first caller, CIE `0x006205d0` — the two FDEs do not share a CIE). The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a99fc` describes `[0x528e900, 0x528e953)`, 83 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x528e952`).
- The unwind index stride to the next entry is 84 bytes, ending at `0x528e954`, only because one `int3` byte (`0xcc`) pads the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "84-byte FDE-bounded" would overstate the frame by that one padding byte, and the checker locks the 83-byte body and the padding separately.
- A byte-pattern scan of `.text` finds 3 direct `e8` calls to the window. The first call site (`0x528f20d`) was verified as an instruction start by disassembly from its containing FDE start (`0x528f020`). The other 2 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one global gate, one callee call, one difference equality

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x528e900` | `endbr64` | Entry |
| `0x528e904` | `push rbp` | Save callee-saved register |
| `0x528e905` | `xor eax, eax` | Return 0 default |
| `0x528e907` | `push rbx` | Save callee-saved register |
| `0x528e908` | `sub rsp, 8` | Stack alignment for the call |
| `0x528e90c` | `lea rbp, [rip + 0x4ff5ad]` | Global table base `0x578dec0` |
| `0x528e913` | `mov rcx, qword ptr [rbp + 8]` | Global second field at `0x578dec8` |
| `0x528e917` | `cmp qword ptr [rdi + 8], rcx` | Input second vs global second, unsigned |
| `0x528e91b` | `jae 0x528e928` | Input second >= global continues |
| `0x528e91d` | `add rsp, 8` | Early return epilogue |
| `0x528e921` | `pop rbx` | Restore callee-saved register |
| `0x528e922` | `pop rbp` | Restore callee-saved register |
| `0x528e923` | `ret` | Return 0 (gate failed) |
| `0x528e924` | `nop dword ptr [rax]` | 4-byte alignment padding inside the window |
| `0x528e928` | `mov rsi, qword ptr [rbp]` | Callee argument: global first field |
| `0x528e92c` | `mov rdx, 0xffffffffffffffff` | Callee argument: -1 |
| `0x528e933` | `mov rbx, rdi` | Save input struct pointer |
| `0x528e936` | `call 0x5660df0` | Shared callee; its body is excluded |
| `0x528e93b` | `mov rdx, rax` | Callee result |
| `0x528e93e` | `mov rax, qword ptr [rbx + 8]` | Input second field |
| `0x528e942` | `sub rax, qword ptr [rbp + 8]` | Difference: input second - global second |
| `0x528e946` | `cmp rax, rdx` | Difference vs callee result |
| `0x528e949` | `sete al` | Return 1 iff callee result equals the difference |
| `0x528e94c` | `add rsp, 8` | Restore stack |
| `0x528e950` | `pop rbx` | Restore callee-saved register |
| `0x528e951` | `pop rbp` | Restore callee-saved register |
| `0x528e952` | `ret` | Return 0 or 1 |

- The return rule, over the input second field `input_second` (u64 at input struct + 0x08), the global second field `global_second` (u64 at global table + 0x08, i.e. `0x578dec8`), and the callee result (u64 rax from the call), is: if `input_second < global_second` (unsigned), return 0; `difference = (input_second - global_second) mod 2**64`; return 1 iff `callee_result == difference`, else 0.
- The gate is unsigned: `jae` passes exactly when the input second field is greater than or equal to the global second field. On the call path the difference is therefore always non-negative, so no wraparound case arises for the difference itself; the mod-2**64 form is stated for completeness.
- The callee is called with the input struct pointer still in rdi (never reassigned before the call), the global first field (at `0x578dec0`) in rsi, and -1 in rdx. The rule depends only on the callee's return value, not its internals.
- The checker verifies the rule on 12 edges: both gate outcomes (including a nonzero callee value on the rejection path, proving the call is skipped), equal seconds with callee 0 and nonzero, above-global matches and mismatches, zero callee against a nonzero difference, and max-value edges (equal maxima, zero global with max input, zero-zero, one-one, near-max global).
- The shared callee at `0x5660df0` is not an FDE start, so no body size is claimed for it. The window's rule is stated over the callee result, not over the callee's internals.

## Inferences

- Inferred label: global-bounds-gated equality helper. The rule is observed and proven above; only the label is inferred.
- The global-table gate plus difference-equality shape suggests a check that an input's position has advanced past a global watermark by exactly the amount a helper reports, but what the table, the input struct, and the callee mean are not closed here, so that reading is an inference only.
- The 3 incoming direct calls suggest a reused helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input struct, its global table, and its shared callee.
- What the callee compares; why its third argument is -1.
- What the global table's two fields represent; why the gate compares the second fields.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5660df0`, the other 2 call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
