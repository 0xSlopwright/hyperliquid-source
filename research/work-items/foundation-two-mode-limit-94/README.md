# foundation-two-mode-limit-94: what does the two-mode limit-check window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-two-mode-limit-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the offset-equality packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 85-byte FDE window, its eleven int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact two-mode return rule over the struct fields, the input, and the callee result.
- Excluded: the shared callee body at `0x5172b00`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose two-mode rule reads directly from its own bytes: a signed field gate selects either a static count-vs-base-plus-offset check or a dynamic callee-result-plus-input check against the same field. It is the sixth packet from the calls category's gate-singleton slice: like the offset-equality window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5172c10`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.184 against the divide-by-million window, 0.122 against the scaled-count window, 0.047 against the TLS-table-index window, 0.025 against the error-band range-check window, 0.098 against the cached-pointer-refresh window, 0.129 against the min-cap gap-check window, 0.053 against the offset-equality window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, push, mov, sub, cmp, jg, movsxd, xor, test, jle, mov, add, cmp, setb, add, mov, pop, pop, ret, nop, mov, call, lea, cmp, setae, add, mov, pop, pop, ret`) is a singleton among small (20–150 byte) single-call FDE windows. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_mode_limit.py --check research/work-items/foundation-two-mode-limit-94/evidence.json
python3 -m unittest tests.test_foundation_two_mode_limit -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5172c10 --stop-address=0x5172c70 artifacts/node/94/hl-node
objdump -d --start-address=0x51739d0 --stop-address=0x5173a5e artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c42c` (this window), `0x29c608` (the first caller), and `0x29c3e4` (the shared callee, 257 bytes) — all three share CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c42c` describes `[0x5172c10, 0x5172c65)`, 85 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5172c64`).
- The unwind index stride to the next entry is 96 bytes, ending at `0x5172c70`, only because eleven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those eleven padding bytes, and the checker locks the 85-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x5173a41`, verified as an instruction start by disassembly from its containing FDE start (`0x51739d0`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one signed gate, two modes, one shared callee

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5172c10` | `endbr64` | Entry |
| `0x5172c14` | `push rbp` | Save callee-saved register |
| `0x5172c15` | `push rbx` | Save callee-saved register |
| `0x5172c16` | `mov rbx, rdi` | Save input struct pointer |
| `0x5172c19` | `sub rsp, 8` | Stack alignment for the call |
| `0x5172c1d` | `cmp qword ptr [rdi + 0x38], 0` | Mode gate: field at +0x38 |
| `0x5172c22` | `jg 0x5172c48` | Positive field routes to the dynamic mode |
| `0x5172c24` | `movsxd rax, dword ptr [rdi + 0x30]` | Static count: i32 at +0x30, sign-extended |
| `0x5172c28` | `xor edx, edx` | Return 0 default |
| `0x5172c2a` | `test eax, eax` | Count sign test |
| `0x5172c2c` | `jle 0x5172c3c` | Non-positive count returns 0 |
| `0x5172c2e` | `mov rdx, qword ptr [rdi + 0x28]` | Static base at +0x28 |
| `0x5172c32` | `add rdx, qword ptr [rdi + 0x10]` | Limit: base + offset at +0x10 |
| `0x5172c36` | `cmp rax, rdx` | Count vs limit, unsigned |
| `0x5172c39` | `setb dl` | Return 1 iff count < limit |
| `0x5172c3c` | `add rsp, 8` | Static epilogue |
| `0x5172c40` | `mov eax, edx` | Return 0 or 1 |
| `0x5172c42` | `pop rbx` | Restore callee-saved register |
| `0x5172c43` | `pop rbp` | Restore callee-saved register |
| `0x5172c44` | `ret` | Return |
| `0x5172c45` | `nop dword ptr [rax]` | 3-byte alignment padding inside the window |
| `0x5172c48` | `mov rbp, rsi` | Dynamic mode: save input |
| `0x5172c4b` | `call 0x5172b00` | Shared callee; its body is excluded |
| `0x5172c50` | `lea rsi, [rbp + rax]` | Input + callee result, mod 2**64 |
| `0x5172c55` | `cmp rsi, qword ptr [rbx + 0x38]` | Sum vs the field at +0x38, unsigned |
| `0x5172c59` | `setae dl` | Return 1 iff sum >= field |
| `0x5172c5c` | `add rsp, 8` | Dynamic epilogue |
| `0x5172c60` | `mov eax, edx` | Return 0 or 1 |
| `0x5172c62` | `pop rbx` | Restore callee-saved register |
| `0x5172c63` | `pop rbp` | Restore callee-saved register |
| `0x5172c64` | `ret` | Return |

- The return rule, over the field `field38` (i64 at struct + 0x38), the static count `count` (i32 at struct + 0x30, sign-extended), the static base `base` (u64 at struct + 0x28), the static offset `offset` (u64 at struct + 0x10), the dynamic input `input` (u64 in rsi), and the callee result `callee_result` (u64 rax from the call to `0x5172b00`), is: if `field38 > 0` (signed), return 1 iff `(input + callee_result) mod 2**64 >= field38` (unsigned); else (static mode): if `count <= 0` (signed), return 0; `limit = (base + offset) mod 2**64`; return 1 iff `count < limit` (unsigned).
- The mode gate is signed: zero and negative values of `field38` take the static path, because `jg` requires strictly greater than zero. The checker verifies the negative-field38 static edge explicitly.
- In static mode the count comparison is unsigned (`setb`), but the count reaching that comparison is always positive (the non-positive case returns early), so the sign-extension of the i32 count only matters for the `jle` test, not for the limit comparison.
- In dynamic mode the callee is called with the struct pointer still in rdi and the input in rsi; the rule depends only on the callee's return value, not its internals. The shared callee at `0x5172b00` is a 257-byte FDE, the same callee used by the cached-pointer-refresh window (#127); its body is excluded here.
- The checker verifies the rule on 12 edges: static zero and negative counts, the negative-field38 static path, static below/equal-limit, the static base+offset wraparound, the static zero limit, dynamic exact-equality, dynamic one-below, dynamic zero callee result, the dynamic input+result wraparound, and dynamic max values at the boundary.

## Inferences

- Inferred label: two-mode limit-check helper. The rule is observed and proven above; only the label is inferred.
- The shared gate field serving as both the mode selector and the dynamic limit suggests one struct field that is either a limit (when positive) or a disabled/empty marker (when zero or negative), but what the struct, the callee, and the fields mean are not closed here, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input struct, its shared callee, and its fields.
- What the callee returns; what the static count, base, and offset represent.
- Why the same field selects the mode and bounds the dynamic sum.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5172b00`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
