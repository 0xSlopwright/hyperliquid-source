# foundation-validate-einval-gate-94: what does the validate-or-EINVAL gate window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-validate-einval-gate-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the big-band calls category's gate-singleton slice after the small-band queue was exhausted, as the first usable backup behind the length-prefix encode window.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 110-byte FDE window, its two int3 padding bytes, the single direct call edge to a shared callee, and the exact validate-or-fail rule over five gate conditions.
- Excluded: the callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose validate-or-fail rule reads directly from its own bytes: five conditions must all hold, or the window returns 22 without calling anything; when they hold, it calls a shared callee with base-derived arguments and returns 0. It is the second packet from the big-band calls category's gate-singleton slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x54e1b10`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.132 against the divide-by-million window, 0.082 against the scaled-count window, 0.010 against the TLS-table-index window, 0.050 against the error-band range-check window, 0.098 against the cached-pointer-refresh window, 0.080 against the min-cap gap-check window, 0.093 against the offset-equality window, 0.106 against the two-mode limit-check window, 0.060 against the global-bounds-gated equality window, 0.083 against the struct-init flag-pack window, 0.022 against the all-records flag-scan window, 0.082 against the helper low-byte equality window, 0.105 against the byte-gate counter window, 0.056 against the triple-min inequality window, 0.137 against the u32 second-field equality window, 0.133 against the cache-refresh zero-test window, 0.055 against the length-prefix encode window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, test, je, test, je, sub, cmp, setne, test, sete, or, jne, cmp, je, mov, add, ret, nop, lea, mov, push, lea, push, lea, lea, lea, mov, call, pop, pop, xor, add, ret, nop, mov, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_validate_einval_gate.py --check research/work-items/foundation-validate-einval-gate-94/evidence.json
python3 -m unittest tests.test_foundation_validate_einval_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54e1b10 --stop-address=0x54e1b80 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002c2468` (this window), `0x002c2494` (the next FDE, bounding the padding), and `0x002c9c6c` (the shared callee) — all three use CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002c2468` describes `[0x54e1b10, 0x54e1b7e)`, 110 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x54e1b7d`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x54e1b80`, only because two `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those two padding bytes, and the checker locks the 110-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window, so no caller file is included and this packet has 7 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: five gates, then one call, or 22

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x54e1b10` | `endbr64` | Entry |
| `0x54e1b14` | `test rcx, rcx` | Gate 1: base pointer nonzero |
| `0x54e1b17` | `je 0x54e1b78` | Fail if base is null |
| `0x54e1b19` | `test r8, r8` | Gate 2: second pointer nonzero |
| `0x54e1b1c` | `je 0x54e1b78` | Fail if second pointer is null |
| `0x54e1b1e` | `sub rsp, 8` | Stack alignment for the call |
| `0x54e1b22` | `cmp qword [rsp + 0x10], 8` | Gate 3: first stack argument equals 8 |
| `0x54e1b28` | `setne al` | al = 1 iff the stack argument differs from 8 |
| `0x54e1b2b` | `test r9, r9` | Gate 4: third pointer nonzero |
| `0x54e1b2e` | `sete dl` | dl = 1 iff the third pointer is null |
| `0x54e1b31` | `or dl, al` | al = (stack argument != 8) OR (third pointer is null) |
| `0x54e1b33` | `jne 0x54e1b3b` | Fail if either of gates 3–4 fails |
| `0x54e1b35` | `cmp qword [r8], 0x30` | Gate 5: pointee of the second pointer equals 0x30 |
| `0x54e1b39` | `je 0x54e1b48` | Call path if the pointee matches |
| `0x54e1b3b` | `mov eax, 0x16` | Failure value 22 |
| `0x54e1b40` | `add rsp, 8` | Epilogue |
| `0x54e1b44` | `ret` | Return 22 |
| `0x54e1b45` | `nopl (%rax)` | Alignment padding between paths |
| `0x54e1b48` | `lea r8, [rcx + 0x28]` | Seventh callee argument, staged |
| `0x54e1b4c` | `mov rsi, [r9]` | Callee rsi = pointee of the third pointer |
| `0x54e1b4f` | `push rcx` | Eighth callee argument, staged |
| `0x54e1b50` | `lea r10, [rcx + 0x10]` | Fourth callee argument, staged |
| `0x54e1b54` | `push r8` | Seventh callee argument, pushed |
| `0x54e1b56` | `lea rdx, [rcx + 8]` | Third callee argument |
| `0x54e1b5a` | `lea r9, [rcx + 0x20]` | Sixth callee argument |
| `0x54e1b5e` | `lea r8, [rcx + 0x18]` | Fifth callee argument |
| `0x54e1b62` | `mov rcx, r10` | Fourth callee argument |
| `0x54e1b65` | `call 0x55275b0` | Shared callee; its body is excluded |
| `0x54e1b6a` | `pop rax` | Discard the pushed seventh argument |
| `0x54e1b6b` | `pop rdx` | Discard the pushed eighth argument |
| `0x54e1b6c` | `xor eax, eax` | Return 0, discarding the callee result |
| `0x54e1b6e` | `add rsp, 8` | Epilogue |
| `0x54e1b72` | `ret` | Return 0 |
| `0x54e1b73` | `nopl 0x0(%rax, %rax, 1)` | Alignment padding before the failure path |
| `0x54e1b78` | `mov eax, 0x16` | Failure value 22 (null-pointer path) |
| `0x54e1b7d` | `ret` | Return 22 |

- The rule, over base pointer (`rcx`), second pointer (`r8`), third pointer (`r9`), and first stack argument (the seventh argument overall), is: return 22 (`0x16`) unless `rcx != 0` and `r8 != 0` and `r9 != 0` and the first stack argument `== 8` and the qword at `[r8] == 0x30`; when all five gates pass, call `0x55275b0` with `rdi` = entry `rdi` (passed through untouched), `rsi` = `[r9]`, `rdx` = `rcx + 8`, `rcx` = `rcx + 0x10`, `r8` = `rcx + 0x18`, `r9` = `rcx + 0x20`, first stack argument = `rcx + 0x28`, second stack argument = `rcx`, and return 0.
- The first stack argument is the seventh argument overall: at entry `[rsp]` holds the return address and `[rsp + 8]` holds it; after `sub rsp, 8` the window reads it as `[rsp + 0x10]`. The gate order in bytes is base, then second pointer, then (stack argument, third pointer) combined by `or`, then pointee, but the rule is a pure conjunction, so order does not change the result.
- The gate boundaries are exact and verified on both sides: the stack argument fails at both 7 and 9, and the pointee fails at both 0x2f and 0x31, so neither gate is a range check.
- The failure value is exactly 22 on every failure path (three separate `mov eax, 0x16` sites: the combined gate-3/4 path, the pointee path, and the null-pointer path), not a generic error code, and the window writes nothing on failure: no store instruction executes on any failure path.
- The pass path returns exactly 0 (`xor eax, eax` after the call), whatever the callee returns, because the callee result is discarded. The callee at `0x55275b0` IS an FDE start (994 bytes, `.eh_frame+0x002c9c6c`, CIE `0x00000000`, the same CIE as the window) — but its body is excluded here all the same, so no claim about what it computes is made.
- The neighboring window at `0x54e1b80` shares two surface features with this one — it also reads the first stack argument against 8 and also returns 0x16 — but it is not a twin: its gate structure differs (an `or` of two pointers, then a different call), its callee differs (`0x55448f0`), its mnemonic skeleton differs, and its body bytes match this window at only 0.09 over the overlap. It is context, not a duplicate.

## Inferences

- Inferred label: validate-or-EINVAL gate helper. The rule is observed and proven above; only the label is inferred. The value 22 is the Linux EINVAL errno, so the "EINVAL" reading is an inference from the constant, not a claim about any caller's errno handling.
- The five gates read as a validity check on a base object plus a version or kind tag (the 0x30 pointee and the exact-8 stack argument), but what the object, the tag, and the stack argument mean is not established, so that reading is an inference only.
- The absence of incoming direct calls suggests a narrowly used helper, or one reached only indirectly, but the caller role is not established at all.

## Unknowns

- The source-level name and types of this window, its base object, and the meaning of the 0x30 pointee and the exact-8 stack argument.
- Why the failure value is 22, and whether any caller distinguishes it from other failures.
- What the shared callee at `0x55275b0` computes, and why its eight arguments are all derived from one base pointer.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation behind the call, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
