# foundation-min-cap-gap-94: what does the min-cap gap-check window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-min-cap-gap-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the cached-pointer-refresh packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 87-byte FDE window, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact return rule over the callee result and the second-field gap.
- Excluded: the shared callee body at `0x5660150`, the other 7 raw call sites beyond the scan list, the neighboring FDE window at `0x5430e07`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose return rule reads directly from its own bytes: a min-capped callee equality gate, followed by a signed i32-range guard and a gap-zero test on the second-field gap. It is the fourth packet from the calls category's gate-singleton slice: like the cached-pointer-refresh window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5430db0`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.158 against the divide-by-million window, 0.163 against the scaled-count window, 0.034 against the TLS-table-index window, 0.025 against the error-band range-check window, 0.146 against the cached-pointer-refresh window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, push, sub, mov, mov, cmp, cmovbe, test, je, mov, mov, mov, call, mov, xor, test, jne, sub, xor, cmp, jg, cmp, jl, test, sete, add, pop, pop`, ret-truncated) is a singleton among 31,898 small (20–150 byte) single-call FDE windows. The window is not a member of a repeated-window population.

It is also not a member of the killed cmovbe comparator family, despite sharing that family's callee (`0x5660150`) and its min-cap idiom: byte ratios against all seven family members are 0.195–0.266, the skeletons differ, and the rule differs — a boolean gap-zero test, not a lexicographic 3-way compare with an inline second-key tiebreak.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_min_cap_gap.py --check research/work-items/foundation-min-cap-gap-94/evidence.json
python3 -m unittest tests.test_foundation_min_cap_gap -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5430db0 --stop-address=0x5430e07 artifacts/node/94/hl-node
objdump -d --start-address=0x522d4b0 --stop-address=0x522d933 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2bae74` (this window, CIE `0x00000000`) and `0x63e22c` (the first caller, CIE `0x006205d0` — the two FDEs do not share a CIE). The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and the missing padding

- `.eh_frame+0x2bae74` describes `[0x5430db0, 0x5430e07)`, 87 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5430e06`).
- There is no int3 padding after this window: the next FDE begins immediately at `0x5430e07` (a 69-byte neighbor window, excluded here), and the 4 int3 bytes at `[0x5430e4c, 0x5430e50)` belong after that neighbor, not after this window. Any description of this window as carrying int3 padding to the next FDE would be wrong, and the checker locks the 87-byte body with a padding count of zero.
- A byte-pattern scan of `.text` finds 8 direct `e8` calls to the window. The first call site (`0x522d600`) was verified as an instruction start by disassembly from its containing FDE start (`0x522d4b0`). The other 7 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one min-cap, one callee equality gate, one gap guard

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5430db0` | `endbr64` | Entry |
| `0x5430db4` | `push rbp` | Save callee-saved register |
| `0x5430db5` | `push rbx` | Save callee-saved register |
| `0x5430db6` | `sub rsp, 8` | Stack alignment for the call |
| `0x5430dba` | `mov rbp, qword ptr [rsi + 8]` | Second field of input b |
| `0x5430dbe` | `mov rbx, qword ptr [rdi + 8]` | Second field of input a |
| `0x5430dc2` | `cmp rbp, rbx` | Unsigned min comparison |
| `0x5430dc5` | `cmovbe rbx, rbp` | rbx = min(a_second, b_second), unsigned |
| `0x5430dc9` | `test rbx, rbx` | Min-zero test |
| `0x5430dcc` | `je 0x5430de4` | Min zero skips the callee call |
| `0x5430dce` | `mov rsi, qword ptr [rsi]` | Callee argument: first field of b |
| `0x5430dd1` | `mov rdi, qword ptr [rdi]` | Callee argument: first field of a |
| `0x5430dd4` | `mov rdx, rbx` | Callee argument: the min cap |
| `0x5430dd7` | `call 0x5660150` | Shared callee; its body is excluded |
| `0x5430ddc` | `mov edx, eax` | Callee result (low 32 bits) |
| `0x5430dde` | `xor eax, eax` | Return 0 default |
| `0x5430de0` | `test edx, edx` | Callee equality test |
| `0x5430de2` | `jne 0x5430e00` | Nonzero callee result routes to return 0 |
| `0x5430de4` | `sub rbx, rbp` | Gap: min - b_second, mod 2**64 |
| `0x5430de7` | `xor eax, eax` | Return 0 default, again |
| `0x5430de9` | `cmp rbx, 0x7fffffff` | Upper i32-range bound |
| `0x5430df0` | `jg 0x5430e00` | Above the range routes to return 0 |
| `0x5430df2` | `cmp rbx, -0x80000000` | Lower i32-range bound |
| `0x5430df9` | `jl 0x5430e00` | Below the range routes to return 0 |
| `0x5430dfb` | `test ebx, ebx` | Gap-zero test (low 32 bits) |
| `0x5430dfd` | `sete al` | Return 1 iff the gap's low 32 bits are zero |
| `0x5430e00` | `add rsp, 8` | Restore stack |
| `0x5430e04` | `pop rbx` | Restore callee-saved register |
| `0x5430e05` | `pop rbp` | Restore callee-saved register |
| `0x5430e06` | `ret` | Return 0 or 1 |

- The raw return rule, over the inputs `a_first` (u64 at a + 0x00), `a_second` (u64 at a + 0x08), `b_first` (u64 at b + 0x00), `b_second` (u64 at b + 0x08), and the callee result (low 32 bits of eax from the call with `(a_first, b_first, min)`), is: `min = min_u64(a_second, b_second)`; if `min != 0` and the callee result is nonzero, return 0; `gap = (min - b_second) mod 2**64`; return 1 iff `gap` interpreted as signed lies in `[-2**31, 2**31 - 1]` and `low32(gap) == 0`, else 0.
- The range guard is observable, not redundant: a gap of `-2**32` has low 32 bits zero yet is rejected, because `-2**32` lies below `-2**31`. The checker verifies this trap on two edges (min-zero path with `b_second = 2**32`, and callee-passing path with `b_second = a_second + 2**32`). A gap of `-2**31` is in range but has nonzero low 32 bits, so it is also rejected — verified as a boundary edge.
- The gap is always `<= 0` before the mod (`min <= b_second`), so a positive in-range gap never occurs; the range guard is only observable on negative gaps whose low 32 bits are zero. The mod-arithmetic edge (`a_second = 1`, `b_second = 2**64 - 1`, callee 0) yields gap `2` mod 2**64, in range but nonzero, so it returns 0.
- Derived form, verified by the checker to agree with the raw rule on every edge: return 1 iff `b_second <= a_second` (unsigned) and (`b_second == 0` or the callee result is 0). The `b_second == 0` case returns 1 without any callee call, because the min-zero path skips the call and the gap is then exactly 0.
- The shared callee at `0x5660150` is not an FDE start, so no body size is claimed for it. The window's rule is stated over the callee result, not over the callee's internals.
- The checker verifies the rule on 13 edges: the min-zero skip (with a meaningless callee value, proving the skip), callee pass/fail at equal and ordered seconds, both `-2**32` traps, the `-2**31` boundary, equal seconds, top-of-range seconds, and the mod-arithmetic edge.

## Inferences

- Inferred label: min-cap gap-check helper. The rule is observed and proven above; only the label is inferred.
- The min-cap plus equality-gate plus gap-zero shape suggests a check that two records agree up to the smaller of two lengths and that the second length is fully covered, but what the structs, the callee, and the gap mean are not closed here, so that reading is an inference only.
- The 8 incoming direct calls suggest a reused helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input structs, its shared callee, and its gap.
- What the callee compares; why the min cap, rather than either second field directly, is its third argument.
- Why the range guard sits between the callee gate and the gap-zero test, given that only gap 0 passes both.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5660150`, the other 7 call sites beyond the scan list, the neighboring FDE window at `0x5430e07`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
