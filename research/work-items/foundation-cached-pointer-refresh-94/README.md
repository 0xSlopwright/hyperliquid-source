# foundation-cached-pointer-refresh-94: what does the cached-pointer-refresh window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-cached-pointer-refresh-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the error-band range-check packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 41-byte FDE window, its seven int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact two-store rule over the callee result and the input struct's link field.
- Excluded: the shared callee body at `0x5172b00`, the other 6 raw call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose two-store rule reads directly from its own bytes: refresh a cached pointer from a shared callee, then flag whether a link field is self-referential. It is the third packet from the calls category's gate-singleton slice: like the error-band range-check window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x5172e20`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes. Its mnemonic skeleton (`endbr64, push, mov, mov, call, mov, mov, lea, cmp, setne, mov, pop, ret`) is a singleton among 31,443 small (20–150 byte) direct-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_cached_pointer_refresh.py --check research/work-items/foundation-cached-pointer-refresh-94/evidence.json
python3 -m unittest tests.test_foundation_cached_pointer_refresh -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5172e20 --stop-address=0x5172e50 artifacts/node/94/hl-node
objdump -d --start-address=0x5173a90 --stop-address=0x5173b49 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c4f0` (this window) and `0x29c678` (the first caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c4f0` describes `[0x5172e20, 0x5172e49)`, 41 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 48 bytes, ending at `0x5172e50`, only because seven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those seven padding bytes, and the checker locks the 41-byte body and the padding separately.
- A byte-pattern scan of `.text` finds 7 direct `e8` calls to the window. The first call site (`0x5173afd`) was verified as an instruction start by disassembly from its containing FDE start (`0x5173a90`). The other 6 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one callee call, one cache store, one self-reference flag

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5172e20` | `endbr64` | Entry |
| `0x5172e24` | `push rbx` | Save callee-saved register |
| `0x5172e25` | `mov rbx, rdi` | Save input struct pointer |
| `0x5172e28` | `mov rdi, qword ptr [rdi + 8]` | Callee argument: second field |
| `0x5172e2c` | `call 0x5172b00` | Shared callee; its body is excluded |
| `0x5172e31` | `mov qword ptr [rbx + 0x20], rax` | Cache store: callee result at +0x20 |
| `0x5172e35` | `mov rax, qword ptr [rbx + 8]` | Reload second field |
| `0x5172e39` | `lea rdx, [rax + 0x18]` | Link's own address |
| `0x5172e3d` | `cmp qword ptr [rax + 0x18], rdx` | Link vs its own address |
| `0x5172e41` | `setne al` | Flag: 1 iff link differs from its own address |
| `0x5172e44` | `mov byte ptr [rbx + 0x28], al` | Flag store at +0x28 |
| `0x5172e47` | `pop rbx` | Restore callee-saved register |
| `0x5172e48` | `ret` | Return (no meaningful return value claimed) |

- The two-store rule, over the callee result `rax` (u64), the second field `second` (u64 at input + 0x08), and the link field `link` (u64 at second + 0x18), is: store `callee_result` at input + 0x20, and store at input + 0x28 the byte 0 if `link == (second + 0x18) mod 2**64`, else 1. The flag is therefore 0 exactly when the link is self-referential.
- The window claims no meaningful return value: after `setne al`, rax still carries the high bytes of the second-field pointer, so only the two stores are the window's outputs.
- The wraparound edge is verified: with second = 2**64 - 0x18, second + 0x18 wraps to 0, and a link of 0 matches, so the flag is 0 and the cache passes the callee result through.
- The checker verifies the rule on self-referential links (flag 0), off-by-one links above and below the link address (flag 1), a zero link against a nonzero second (flag 1), and the wraparound case, with cache passthrough checked on every edge.
- The shared callee at `0x5172b00` is a 257-byte FDE whose body is excluded here. The window's rule is stated over the callee result, not over the callee's internals.

## Inferences

- Inferred label: cached-pointer-refresh helper. The rule is observed and proven above; only the label is inferred.
- The cache store plus self-reference flag shape suggests a refresh step that records a callee-derived pointer and notes whether a link still points at itself, but what the struct, the callee, and the link mean are not closed here, so that reading is an inference only.
- The 7 incoming direct calls suggest a reused helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its input struct, its shared callee, and its link field.
- What the callee returns; what the cached pointer and the link represent.
- Why the flag tests self-reference rather than some other link property.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x5172b00`, the other 6 call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
