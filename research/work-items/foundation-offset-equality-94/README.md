# foundation-offset-equality-94: what does the offset-equality window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-offset-equality-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the min-cap gap-check packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 75-byte FDE window, its five int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact return rule over the callee result and the second-field offset.
- Excluded: the shared callee body at `0x5660150`, the other 7 raw call sites beyond the scan list, the neighboring FDE window at `0x5430db0`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose return rule reads directly from its own bytes: two fast paths (an ordered-seconds rejection and a zero-second acceptance) plus a shared-callee equality test on a computed offset. It is the fifth packet from the calls category's gate-singleton slice: like the min-cap gap-check window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5430d60`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.158 against the divide-by-million window, 0.102 against the scaled-count window, 0.067 against the TLS-table-index window, 0.050 against the error-band range-check window, 0.171 against the cached-pointer-refresh window, 0.093 against the min-cap gap-check window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, mov, mov, xor, cmp, jae, mov, ret, nop, mov, test, je, sub, sub, mov, add, mov, call, test, sete, add, mov, ret`) is a singleton among small (20–150 byte) single-call FDE windows. The window is not a member of a repeated-window population.

It is also not a member of the killed cmovbe comparator family, despite sharing that family's callee (`0x5660150`): byte ratios against all seven family members are 0.080–0.093, the skeletons differ, and the rule differs — a two-fast-path offset-equality test, not a lexicographic 3-way compare with an inline second-key tiebreak.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_offset_equality.py --check research/work-items/foundation-offset-equality-94/evidence.json
python3 -m unittest tests.test_foundation_offset_equality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5430d60 --stop-address=0x5430db0 artifacts/node/94/hl-node
objdump -d --start-address=0x522d4b0 --stop-address=0x522d933 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2bae5c` (this window, CIE `0x00000000`) and `0x63e22c` (the first caller, CIE `0x006205d0` — the two FDEs do not share a CIE). The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2bae5c` describes `[0x5430d60, 0x5430dab)`, 75 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5430daa`).
- The unwind index stride to the next entry is 80 bytes, ending at `0x5430db0`, only because five `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those five padding bytes, and the checker locks the 75-byte body and the padding separately.
- A byte-pattern scan of `.text` finds 8 direct `e8` calls to the window. The first call site (`0x522d665`) was verified as an instruction start by disassembly from its containing FDE start (`0x522d4b0`). The other 7 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: two fast paths, one offset, one callee equality test

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5430d60` | `endbr64` | Entry |
| `0x5430d64` | `mov rdx, qword ptr [rsi + 8]` | Second field of input b |
| `0x5430d68` | `mov rax, qword ptr [rdi + 8]` | Second field of input a |
| `0x5430d6c` | `xor ecx, ecx` | Return 0 default |
| `0x5430d6e` | `cmp rax, rdx` | Unsigned seconds comparison |
| `0x5430d71` | `jae 0x5430d80` | a_second >= b_second continues |
| `0x5430d73` | `mov eax, ecx` | Fast path: a_second < b_second returns 0 |
| `0x5430d75` | `ret` | Return 0 |
| `0x5430d76` | `nop word ptr cs:[rax + rax]` | 10-byte alignment padding inside the window |
| `0x5430d80` | `mov ecx, 1` | Return 1 candidate |
| `0x5430d85` | `test rdx, rdx` | Zero-second test |
| `0x5430d88` | `je 0x5430d73` | Fast path: b_second == 0 returns 1, no call |
| `0x5430d8a` | `sub rsp, 8` | Stack alignment for the call |
| `0x5430d8e` | `sub rax, rdx` | Difference a_second - b_second (non-negative here) |
| `0x5430d91` | `mov rsi, qword ptr [rsi]` | Callee argument: first field of b |
| `0x5430d94` | `add rax, qword ptr [rdi]` | Offset: a_first + difference |
| `0x5430d97` | `mov rdi, rax` | Callee argument: the offset |
| `0x5430d9a` | `call 0x5660150` | Shared callee; its body is excluded |
| `0x5430d9f` | `test eax, eax` | Callee equality test |
| `0x5430da1` | `sete cl` | Return 1 iff callee result is 0 |
| `0x5430da4` | `add rsp, 8` | Restore stack |
| `0x5430da8` | `mov eax, ecx` | Return 0 or 1 |
| `0x5430daa` | `ret` | Return |

- The return rule, over the inputs `a_first` (u64 at a + 0x00), `a_second` (u64 at a + 0x08), `b_first` (u64 at b + 0x00), `b_second` (u64 at b + 0x08), and the callee result (low 32 bits of eax from the call), is: if `a_second < b_second` (unsigned), return 0; if `b_second == 0`, return 1; `offset = (a_first + (a_second - b_second)) mod 2**64`; return 1 iff `callee(offset, b_first, b_second) == 0`, else 0.
- On the call path `a_second >= b_second` always holds (the smaller case returns early), so `a_second - b_second` is non-negative and the offset is `a_first` plus a non-negative difference, mod 2**64. The callee's third argument register `rdx` still holds `b_second` at the call; the rule depends only on the callee's return being zero, so the third argument does not change the rule, but the checker locks the register setup through the retained bytes.
- The checker verifies the rule on 10 edges: both fast paths (including a nonzero callee value on the rejection path, proving the call is skipped), the zero-zero case, equal seconds with callee 0 and nonzero, ordered seconds with callee 0 and nonzero, max values, and the wraparound edge (`a_first = 2**64 - 3`, difference 7, offset wraps to 4).
- The shared callee at `0x5660150` is not an FDE start, so no body size is claimed for it. The window's rule is stated over the callee result, not over the callee's internals.

## Inferences

- Inferred label: offset-equality helper. The rule is observed and proven above; only the label is inferred.
- The two-fast-path plus offset-equality shape suggests a check that two records agree after shifting one by the difference of their lengths, but what the structs, the callee, and the offset mean are not closed here, so that reading is an inference only.
- The 8 incoming direct calls suggest a reused helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input structs, its shared callee, and its offset.
- What the callee compares; why its third argument is `b_second` rather than the min cap used by the neighboring gap-check window.
- Why the zero-second case returns 1 without consulting the callee.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5660150`, the other 7 call sites beyond the scan list, the neighboring FDE window at `0x5430db0`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
