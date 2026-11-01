# foundation-byte-gate-counter-94: what does the byte-gate counter window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-byte-gate-counter-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the helper low-byte equality packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 76-byte FDE window, its four int3 padding bytes, four incoming direct call edges verified as instruction starts (one caller FDE), the shared-callee call edge, and the exact byte-gate flag rule with its unconditional counter increment.
- Excluded: the shared callee body at `0x5660550`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose byte-gate counter rule reads directly from its own bytes: select a helper flag through a three-branch gate, call a helper with it, bump a counter, and return the fourth input. It is the eleventh packet from the calls category's gate-singleton slice: like the helper low-byte equality window, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x4fd6030`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.184 against the divide-by-million window, 0.184 against the scaled-count window, 0.039 against the TLS-table-index window, 0.050 against the error-band range-check window, 0.244 against the cached-pointer-refresh window, 0.145 against the min-cap gap-check window, 0.053 against the offset-equality window, 0.237 against the two-mode limit-check window, 0.079 against the global-bounds-gated equality window, 0.125 against the struct-init flag-pack window, 0.013 against the all-records flag-scan window, 0.245 against the helper low-byte equality window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, push, mov, push, mov, mov, lea, sub, test, je, mov, call, add, add, mov, pop, pop, ret, nop, cmp, je, xor, movzx, cmp, setb, jmp`) is a singleton among small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The queue note flagged this candidate as thin with a 0.31 resemblance to weak-trio member `0x5559a10`. Both were re-checked before building: the explicit byte comparison against `0x5559a10` is 0.308 (8/26 by the prefix-byte method), well below the 0.60 threshold, and it is a prologue artifact — `0x5559a10` is a 26-byte window with no call at all (a magic-constant store: endbr64, movabs, mov, mov, add, ret), so the shared bytes are the standard endbr64 prologue plus coincidence, not a shared rule. The other weak-trio members score 0.233 (`0x5544560`) and 0.128 (`0x541bc60`). The rule below was also deepened past the queue one-liner in two places: the return value is the fourth input (entry rcx), not the input struct pointer, and the flag gate has three branches (nonzero second, pointer equality, unsigned byte comparison), not just the byte comparison.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_gate_counter.py --check research/work-items/foundation-byte-gate-counter-94/evidence.json
python3 -m unittest tests.test_foundation_byte_gate_counter -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4fd6030 --stop-address=0x4fd6080 artifacts/node/94/hl-node
objdump -d --start-address=0x4fe4e50 --stop-address=0x4fe72b2 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x0028e334` (this window) and `0x0062557c` (the caller) — the window uses CIE `0x00000000`, the caller uses CIE `0x006205d0`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x0028e334` describes `[0x4fd6030, 0x4fd607c)`, 76 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x4fd607a` falls through to the call path, and the FDE end follows the last gate instruction).
- The unwind index stride to the next entry is 80 bytes, ending at `0x4fd6080`, only because four `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those four padding bytes, and the checker locks the 76-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 4 direct `e8` calls to the window, at `0x4fe680e`, `0x4fe68c7`, `0x4fe69d0`, and `0x4fe6b54`, all verified as instruction starts by linear disassembly from their containing FDE start (`0x4fe4e50`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one three-branch flag gate, one helper call, one counter bump, one pass-through return

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4fd6030` | `endbr64` | Entry |
| `0x4fd6034` | `push rbp` | Save callee-saved register |
| `0x4fd6035` | `mov rbp, rcx` | Save fourth input |
| `0x4fd6038` | `push rbx` | Save callee-saved register |
| `0x4fd6039` | `mov rbx, rdi` | Save input struct pointer |
| `0x4fd603c` | `mov edi, 1` | Default first callee argument: flag 1 |
| `0x4fd6041` | `lea rcx, [rbx + 8]` | Fourth callee argument: input + 8 |
| `0x4fd6045` | `sub rsp, 8` | Stack alignment for the call |
| `0x4fd6049` | `test rsi, rsi` | Second-input zero test |
| `0x4fd604c` | `je 0x4fd6068` | Zero second takes the gate path |
| `0x4fd604e` | `mov rsi, rbp` | Second callee argument: fourth input |
| `0x4fd6051` | `call 0x5660550` | Shared callee; its body is excluded |
| `0x4fd6056` | `add qword ptr [rbx + 0x28], 1` | Counter at input + 0x28 increments |
| `0x4fd605b` | `add rsp, 8` | Epilogue |
| `0x4fd605f` | `mov rax, rbp` | Return the fourth input |
| `0x4fd6062` | `pop rbx` | Restore callee-saved register |
| `0x4fd6063` | `pop rbp` | Restore callee-saved register |
| `0x4fd6064` | `ret` | Return |
| `0x4fd6065` | `nop dword ptr [rax]` | 3-byte padding inside the window |
| `0x4fd6068` | `cmp rdx, rcx` | Gate: third input vs input + 8 |
| `0x4fd606b` | `je 0x4fd604e` | Equal pointers take the call with flag 1 |
| `0x4fd606d` | `xor edi, edi` | Flag reset to 0 for the byte comparison |
| `0x4fd606f` | `movzx eax, byte ptr [rdx + 0x20]` | Third input's byte at +0x20 |
| `0x4fd6073` | `cmp byte ptr [rbp + 0x20], al` | Fourth input's byte at +0x20 vs that byte |
| `0x4fd6076` | `setb dil` | Flag 1 iff fourth byte is below third byte (unsigned) |
| `0x4fd607a` | `jmp 0x4fd604e` | Take the call with the selected flag |

- The return rule, over the second input `second` (u64 in rsi), the third input `third` (pointer in rdx), the fourth input `fourth` (pointer in rcx), the counter `counter` (u64 at input + `0x28`), and the flag bytes at `fourth + 0x20` and `third + 0x20`, is: `flag = 1 if second != 0 else (1 if input + 8 == third else (1 if byte[fourth + 0x20] < byte[third + 0x20] (unsigned) else 0))`; `callee(flag, fourth, third, input + 8)` (result ignored); `counter = (counter + 1) mod 2**64`; return `fourth`.
- The callee is called with rdi = flag, rsi = fourth (entry rcx, saved in rbp), rdx = third (entry rdx, unchanged), rcx = input + 8. The rule depends only on the call happening, not on the callee's internals or its result.
- The flag gate's direction is unsigned and was verified against signed misreadings: `cmp byte ptr [rbp + 0x20], al` followed by `setb` sets the flag exactly when the fourth byte is strictly below the third byte unsigned — so 0xff vs 0x00 selects 0 (a signed reading would say 1) and 0x00 vs 0xff selects 1 (a signed reading would say 0). The checker verifies both.
- The counter increment is unconditional: every path reaches the call and then the `add qword ptr [rbx + 0x28], 1`, so the counter advances by exactly 1 on every invocation, wrapping mod 2**64 from the maximum value.
- The return value is the fourth input, not the input struct pointer: `mov rax, rbp` on the return path, where rbp holds entry rcx. This corrects the queue one-liner, which said "input passes through".
- The shared callee at `0x5660550` is not an FDE start, so no body size is claimed for it. The window's rule is stated over the call, not over the callee's internals.

## Inferences

- Inferred label: byte-gate counter helper. The rule is observed and proven above; only the label is inferred.
- The gate-then-call-then-count shape suggests a helper that records one observation per invocation, keyed by a flag that defaults to 1 and only falls back to a byte comparison when the second input is zero and the pointers differ — but what the input struct, the counter, the flag, and the helper mean are not closed here, so that reading is an inference only.
- The four incoming direct calls, all inside one caller FDE, suggest a repeatedly used helper, but the caller role is not established beyond those call sites.

## Unknowns

- The source-level name and types of this window, its input struct, its counter, and its shared callee.
- What the callee computes with the flag, the fourth input, the third input, and input + 8, and why its result is ignored.
- What the second input, the pointer-equality shortcut, and the +0x20 flag bytes represent.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5660550`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
