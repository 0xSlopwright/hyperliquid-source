# foundation-error-band-range-94: what does the error-band range-check window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-error-band-range-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was ranked from the calls category's gate-singleton slice after the TLS-table-index packet.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 40-byte FDE window, its eight int3 padding bytes, one incoming direct call edge verified as an instruction start (first caller FDE), the shared-callee call edge, and the exact return rule over the callee result and the post-call rdx.
- Excluded: the shared callee body at `0x555e670`, the other 25 raw call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose return rule reads directly from its own bytes: an unsigned error-band gate on the callee result, followed by a signed split-range check of one input against the two halves of a 64-bit value. It is the second packet from the calls category's gate-singleton slice: like the TLS-table-index window, its rule is stated over its inputs and the callee result, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x555e870`, and a full-corpus byte comparison against every FDE body finds no body sharing 60% or more of this window's bytes (0.000 against the divide-by-million and scaled-count windows, 0.050 against the TLS-table-index window, none against the older claimed corpus). Its mnemonic skeleton (`sub, call, mov, xor, cmp, ja, cmp, jl, sar, xor, cmp, setle, add, ret`) is a singleton among 31,898 small (20–150 byte) single-call FDE windows, under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_error_band_range.py --check research/work-items/foundation-error-band-range-94/evidence.json
python3 -m unittest tests.test_foundation_error_band_range -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x555e870 --stop-address=0x555e8a0 artifacts/node/94/hl-node
objdump -d --start-address=0x555e8a0 --stop-address=0x555ee9c artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the first caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2cfdd8` (this window) and `0x2cfdf0` (the first caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2cfdd8` describes `[0x555e870, 0x555e898)`, 40 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- The unwind index stride to the next entry is 48 bytes, ending at `0x555e8a0`, only because eight `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those eight padding bytes, and the checker locks the 40-byte body and the padding separately.
- A byte-pattern scan of `.text` finds 26 direct `e8` calls to the window. The first call site (`0x555e938`) was verified as an instruction start by disassembly from its containing FDE start (`0x555e8a0`). The other 25 sites are retained as a raw scan list only, not individually verified. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one callee call, one band gate, one split-range check

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x555e870` | `sub rsp, 8` | Stack alignment for the call |
| `0x555e874` | `call 0x555e670` | Shared callee; its body is excluded |
| `0x555e879` | `mov rcx, rax` | Callee result |
| `0x555e87c` | `xor eax, eax` | Return 0 default |
| `0x555e87e` | `cmp rcx, -0x78` | Band comparison (imm8 -120, sign-extended) |
| `0x555e882` | `ja 0x555e893` | Unsigned-above routes to return 0 |
| `0x555e884` | `cmp esi, edx` | Low-bound comparison (signed i32) |
| `0x555e886` | `jl 0x555e893` | Below low bound routes to return 0 |
| `0x555e888` | `sar rdx, 0x20` | High half of rdx, sign-extended |
| `0x555e88c` | `xor eax, eax` | Return 0 default, again |
| `0x555e88e` | `cmp esi, edx` | High-bound comparison (signed i32) |
| `0x555e890` | `setle al` | Return 1 iff esi <= high bound |
| `0x555e893` | `add rsp, 8` | Restore stack |
| `0x555e897` | `ret` | Return 0 or 1 |

- The return rule, over the callee result `rcx` (u64), the input `esi` (i32), and `rdx` as observed after the call (u64), is: return 1 iff `rcx <= 2**64 - 120` (unsigned) and `low32(rdx) <= esi <= high32(rdx)` (both bounds signed i32); otherwise return 0.
- The band boundary is exact, and it corrects a loose queue description: the rejected band is signed `[-119, -1]`, not `[-120, -1]`. The comparison is `cmp rcx, -0x78` followed by unsigned-above (`ja`), which requires ZF = 0; the value -120 itself compares equal, so it does not take the branch and passes the gate. The checker verifies -120 -> pass, -119 -> reject, -1 -> reject, 0 -> pass, -121 -> pass.
- The range check is a split-range check: the low bound is the low 32 bits of rdx read as signed i32, the high bound is the high 32 bits of rdx read as signed i32, and `esi` must lie between them inclusively. The checker verifies this on rdx = (5 << 32) | 3 (esi 3 -> 1, 2 -> 0, 5 -> 1, 6 -> 0) and on rdx = (10 << 32) | 0xFFFFFFFB (low -5, high 10; esi -5 -> 1, -6 -> 0, 10 -> 1, 11 -> 0), plus a combined case where a band failure overrides an in-range input.
- `rdx` is read after the call, so the range bounds are the callee's post-call rdx. Whether the callee preserves its input rdx or produces the bounds itself is not closed here; the rule is stated over post-call rdx, and the callee's rdx behavior is part of what this packet excludes.
- The shared callee at `0x555e670` is a 505-byte FDE whose body is excluded here. The window's rule is stated over the callee result, not over the callee's internals.
- The checker verifies the band gate, both range bounds, and the combined case from the decoded rule, not from assumed values.

## Inferences

- Inferred label: error-band range-check helper. The rule is observed and proven above; only the label is inferred.
- The rejected band's shape (small-magnitude negative values) is consistent with rejecting error-coded callee results, but what the callee returns and what the range bounds mean are not closed here, so that reading is an inference only.
- The 26 incoming direct calls suggest a widely used helper, but caller roles are not established beyond the first caller's call site.

## Unknowns

- The source-level name and types of this window, its shared callee, and its range bounds.
- What the callee returns; whether it preserves rdx or produces the bounds.
- What the low/high bounds represent; why the band boundary sits at -120.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The shared callee body at `0x555e670`, the other 25 call sites beyond the scan list, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
