# foundation-cache-refresh-zero-94: what does the cache-refresh zero-test window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-cache-refresh-zero-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the u32 second-field equality packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 45-byte FDE window, its three int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact cache-refresh zero-test rule over the callee result.
- Excluded: the shared callee body at `0x54d5f30`, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose cache-refresh zero-test rule reads directly from its own bytes: call a helper with fixed arguments, store its result to a global slot, and report whether the result is zero. It is the fourteenth packet from the calls category's gate-singleton slice: like the u32 second-field equality window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x54d6360`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.289 against the divide-by-million window, 0.089 against the scaled-count window, 0.089 against the TLS-table-index window, 0.025 against the error-band range-check window, 0.122 against the cached-pointer-refresh window, 0.111 against the min-cap gap-check window, 0.178 against the offset-equality window, 0.111 against the two-mode limit-check window, 0.133 against the global-bounds-gated equality window, 0.133 against the struct-init flag-pack window, 0.089 against the all-records flag-scan window, 0.133 against the helper low-byte equality window, 0.156 against the byte-gate counter window, 0.089 against the triple-min inequality window, 0.089 against the u32 second-field equality window, none against the older claimed corpus). Its mnemonic skeleton (`endbr64, sub, lea, xor, mov, call, test, mov, sete, add, ret`) is a singleton among 31,898 small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The queue note flagged this candidate as weak ("rule is mostly the callee") and called it "lazy-init cache + boolean". Both were re-checked before building. The "lazy-init" label is corrected: the window performs no cache check before the call — it calls unconditionally and then overwrites the slot, so it is a cache refresh, not a lazy initialization. The rule still stands as its own packet: the window contributes the fixed call arguments, the unconditional global store, and the zero-test boolean, and both effects are consumed elsewhere — the slot is read by the neighboring getter window at `0x54d5f20`, and the boolean is consumed by the caller (`test al, al; jne`). The callee's internals are excluded, as in every calls packet.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_cache_refresh_zero.py --check research/work-items/foundation-cache-refresh-zero-94/evidence.json
python3 -m unittest tests.test_foundation_cache_refresh_zero -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54d6360 --stop-address=0x54d6390 artifacts/node/94/hl-node
objdump -d --start-address=0x54b9b60 --stop-address=0x54b9f1d artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002c1438` (this window), `0x002c12c4` (the shared callee), `0x002bfa24` (the first caller), and `0x002c1454` (the next FDE, bounding the padding) — all four use CIE `0x00000000`. The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002c1438` describes `[0x54d6360, 0x54d638d)`, 45 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x54d638c`).
- The unwind index stride to the next entry is 48 bytes, ending at `0x54d6390`, only because three `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those three padding bytes, and the checker locks the 45-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, at `0x54b9ce3`, verified as an instruction start by disassembly from its containing FDE start (`0x54b9b60`). Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one fixed-argument call, one unconditional global store, one zero test

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x54d6360` | `endbr64` | Entry |
| `0x54d6364` | `sub rsp, 8` | Stack alignment for the call |
| `0x54d6368` | `lea rdx, [rip + 0x2975b1]` | Fourth callee argument: table at `0x576d920` |
| `0x54d636f` | `xor esi, esi` | Second callee argument: 0 |
| `0x54d6371` | `mov ecx, 1` | Third callee argument: 1 |
| `0x54d6376` | `call 0x54d5f30` | Shared callee; its body is excluded |
| `0x54d637b` | `test rax, rax` | Callee result vs zero (full rax) |
| `0x54d637e` | `mov [rip + 0x4c3cf3], rax` | Store result to global slot `0x599a078` |
| `0x54d6385` | `sete al` | Verdict 1 iff the result is zero |
| `0x54d6388` | `add rsp, 8` | Epilogue |
| `0x54d638c` | `ret` | Return |

- The return rule, over the callee result `callee_result` (u64 rax from the call), is: `global_slot = callee_result` (the u64 at `0x599a078`, written on every invocation); return 1 in `al` iff `callee_result == 0`, else 0 in `al`.
- The callee is called with rdi = input (entry rdi, never reassigned before the call), rsi = 0, rdx = the table at `0x576d920`, rcx = 1. The rule depends only on the callee result, not its internals.
- The zero test is on the full rax (`test rax, rax`), not on the low byte: a result of `0x100` — zero low byte, nonzero upper bytes — returns 0. This distinguishes this window from the helper low-byte equality and u32 second-field equality windows, whose verdicts are low-byte-only. The verdict is still stated over `al` because `sete` sets just the low byte, so the upper bytes of rax after the call are the callee's return bits, not determined by this window's bytes alone.
- The store is unconditional: every path through the window writes the fresh result to the slot. There is no branch that skips the call or the store, so this is a refresh, not a lazy initialization guarded by a cache check.
- The shared callee at `0x54d5f30` IS an FDE start (592 bytes, `.eh_frame+0x002c12c4`, CIE `0x00000000`, the same CIE as the window) — but its body is excluded here all the same, so no claim about what it computes is made.
- The slot has a reader: the neighboring 12-byte window at `0x54d5f20` (`endbr64; mov rax, [0x599a078]; ret`) loads exactly this slot and returns it. That getter window is context for the cache reading only; it is not claimed here, and no claim is made about why the slot is cached.
- The caller consumes the boolean: the call site at `0x54b9ce3` is followed by `test al, al; jne`, so the window's zero-test verdict drives the caller's branch.

## Inferences

- Inferred label: cache-refresh zero-test helper. The rule is observed and proven above; only the label is inferred.
- The call-store-test shape suggests a helper that refreshes a cached value and reports whether the fresh value is zero, but what the input, the table, the callee, and the cached slot mean are not closed here, so that reading is an inference only.
- The single incoming direct call suggests a narrowly used helper, but the caller role is not established beyond the call site and its boolean branch.

## Unknowns

- The source-level name and types of this window, its input, its table, and its shared callee.
- What the callee computes with the input, 0, the table, and 1, and why its result is cached.
- What the cached slot at `0x599a078` represents, and why the zero case is reported.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x54d5f30`, the getter window at `0x54d5f20`, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
