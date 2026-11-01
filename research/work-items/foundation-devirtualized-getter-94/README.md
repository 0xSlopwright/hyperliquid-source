# foundation-devirtualized-getter-94: what does the devirtualized-getter window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-devirtualized-getter-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was mined fresh from the big-band calls corpus (single-call FDE windows, 20–150 bytes) after the gate-singleton direct-call well ran dry, by resolving `-fno-plt` GOT-indirect calls through `.rela.dyn` RELATIVE relocations.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 101-byte FDE window, its eleven int3 padding bytes, the 9-byte known-getter callee, the global slot whose RELATIVE relocation resolves to that getter, and the exact devirtualized-getter rule over the element, the sentinel, and the out pointer.
- Excluded: the virtual-call target on the mismatch path (dynamic per element type), the getter implementation beyond its 9 retained bytes, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose devirtualized-getter rule reads directly from its own bytes: check a container slot against its sentinel, and either return nothing, read a field directly when the element's type is the known one, or fall back to the element's own virtual function. It is the eighth packet from the big-band calls category's single-call slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x514b620`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes under the max-length measure (0.165 against the all-empty-gate window, 0.089 against the offset-equality window, 0.089 against the TLS-table-index window, 0.088 against the destructor-loop window, 0.079 against the triple-min inequality window, the rest lower, none against the older claimed corpus); its mnemonic skeleton (`endbr64, mov, add, cmp, je, mov, mov, cmp, jne, mov, mov, mov, ret, nop, xor, mov, mov, ret, nop, sub, mov, call, mov, mov, mov, add, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The raw min-length comparison does report 314 hits at or above 0.60, and they are addressed head-on rather than hidden: 312 of them are bodies of 5–19 bytes (mostly 5-byte `endbr64; ret` stubs scoring 4/5 against this window's opening bytes), and exactly two are 20 bytes or more: `0x514ab90` (20 bytes, min-length 0.600, max-length 0.119) and `0x514abb0` (51 bytes, min-length 0.608, max-length 0.307). A 5-byte stub is not a twin of a 101-byte window, and the two larger hits are the shared-prologue neighbors discussed below, not twins: under the max-length measure used for the claimed-corpus comparison, both sit far below the 0.60 threshold.

The neighbor question is also addressed head-on, not hidden. The `0x514axxx` region holds a small family of accessor helpers over the same container protocol (element qword at `[rdx + 0x1200]`, sentinel at `rdx + 0x11e0`, return value always 1, value stored to `[rsi]`): `0x514ab90` (20 bytes, plain copy of `[rdx + 0x1228]` to `[rsi]`), `0x514abb0` (51 bytes, sentinel-checked read of `[elem + 0x30]` to `[rsi]`, no type check, no call), and `0x514abf0` (virtual call at vtable offset `0x478`). This window `0x514b620` is genuinely distinguishable from each of them: it is the only one that performs the type check against the known getter and falls back to the element's own first virtual function, its byte similarity to the nearest neighbor `0x514abb0` is 0.307 (max-length), and its mnemonic skeleton is a singleton. Only this one window is built; no neighbor is claimed anywhere in this packet.

The indirect-call question is addressed head-on as well. The window's only call is `call *%rax` (register-indirect), so its target is dynamic by construction: on the mismatch path the callee is the element's own first virtual function, which depends on the element's dynamic type and is not identified here. That is stated as an explicit unknown, not papered over: the rule claims the call's argument registers and the store of its result, never the callee's identity or behavior. The known getter on the match path, by contrast, is fully identified: the global slot `0x5778020` carries a `.rela.dyn` RELATIVE relocation with addend `0x4fa7e80`, and `0x4fa7e80` is an FDE start whose entire 9-byte body is exactly `endbr64; mov rax, [rdi + 8]; ret` — the same value the match path stores directly, which is why the match path is a devirtualization of that getter rather than a coincidence.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_devirtualized_getter.py --check research/work-items/foundation-devirtualized-getter-94/evidence.json
python3 -m unittest tests.test_foundation_devirtualized_getter -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b620 --stop-address=0x514b690 artifacts/node/94/hl-node
objdump -d --start-address=0x4fa7e80 --stop-address=0x4fa7e90 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding, plus the 9-byte getter. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x0029a5d4` (this window), `0x0029a5ec` (the next FDE, bounding the padding), `0x0028b658` (the known getter), and `0x0028b66c` (the FDE after the getter) — all four use CIE `0x00000000`. (Note the `objdump --dwarf=frames` line format: the third column is the FDE record's own field offset, not its CIE — the CIE is the value after `cie=`.) The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x0029a5d4` describes `[0x514b620, 0x514b685)`, 101 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x514b684`).
- The unwind index stride to the next entry is 112 bytes, ending at `0x514b690`, only because eleven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "112-byte FDE-bounded" would overstate the frame by those eleven padding bytes, and the checker locks the 101-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window, so no caller file is included and this packet has 7 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: sentinel check, then devirtualized getter or virtual fallback

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x514b620` | `endbr64` | Entry |
| `0x514b624` | `mov 0x1200(%rdx), %rdi` | Element pointer |
| `0x514b62b` | `add $0x11e0, %rdx` | Sentinel (rdx is clobbered) |
| `0x514b632` | `cmp %rdx, %rdi` | Empty test |
| `0x514b635` | `je 0x514b658` | Empty skips to the zero path |
| `0x514b637` | `mov (%rdi), %rax` | Element first qword |
| `0x514b63a` | `mov (%rax), %rax` | First virtual function |
| `0x514b63d` | `cmp 0x62c9dc(%rip), %rax` | Compare against the global slot |
| `0x514b644` | `jne 0x514b668` | Mismatch goes to the virtual path |
| `0x514b646` | `mov 0x8(%rdi), %rax` | Field at +0x8 |
| `0x514b64a` | `mov %rax, (%rsi)` | Store to out |
| `0x514b64d` | `mov $0x1, %eax` | Return 1 |
| `0x514b652` | `ret` | Return |
| `0x514b653` | `nopl 0x0(%rax,%rax,1)` | Alignment padding between paths |
| `0x514b658` | `xor %eax, %eax` | Zero |
| `0x514b65a` | `mov %rax, (%rsi)` | Store 0 to out |
| `0x514b65d` | `mov $0x1, %eax` | Return 1 |
| `0x514b662` | `ret` | Return |
| `0x514b663` | `nopl 0x0(%rax,%rax,1)` | Alignment padding between paths |
| `0x514b668` | `sub $0x18, %rsp` | Stack frame for the call |
| `0x514b66c` | `mov %rsi, 0x8(%rsp)` | Save out |
| `0x514b671` | `call *%rax` | Virtual call (register-indirect) |
| `0x514b673` | `mov 0x8(%rsp), %rsi` | Restore out |
| `0x514b678` | `mov %rax, (%rsi)` | Store call result to out |
| `0x514b67b` | `mov $0x1, %eax` | Return 1 |
| `0x514b680` | `add $0x18, %rsp` | Epilogue |
| `0x514b684` | `ret` | Return |

- The rule, over container pointer (`rdx`), element pointer (the qword at `[rdx + 0x1200]`), sentinel (`rdx + 0x11e0`), out pointer (`rsi`), and entry `rcx` (untouched by the window), is: if the element pointer equals the sentinel, store 0 to `[rsi]` and return 1; else let `vf` be the qword at `[[elem]]`: if `vf` equals the known getter `0x4fa7e80` (the runtime value of the global slot `0x5778020`), store `[elem + 8]` to `[rsi]` and return 1; else call `vf` with `rdi` = elem, `rsi` = out, `rdx` = sentinel, `rcx` = entry `rcx`, store its `rax` result to `[rsi]`, and return 1.
- The known getter at `0x4fa7e80` IS an FDE start (9 bytes, `.eh_frame+0x0028b658`, CIE `0x00000000`, the same CIE as the window), and its entire body is exactly `endbr64; mov rax, [rdi + 8]; ret` — it returns `[elem + 8]`, which is exactly what the match path stores without calling. So the match path is a devirtualization of that getter, and the getter's behavior beyond those 9 bytes is excluded.
- The global slot at `0x5778020` carries a `.rela.dyn` RELATIVE relocation (type 8, symbol 0) with addend `0x4fa7e80`; at load it resolves to the getter. The comparison in the window reads the slot's runtime value, not a hardcoded address.
- The window writes nothing else: the only stores are the single `[rsi]` store on each path (plus the saved `rsi` spill on the call path, which is restored), and the stack is balanced on every path.
- The return value is 1 on all three paths; the value itself is delivered through `[rsi]`, never as the return.
- Direct callers: none. A byte-pattern scan of `.text` finds exactly 0 direct `e8` calls to the window. The window is reached only indirectly, or not at all, by direct call.

## Inferences

- Inferred label: devirtualized-getter helper. The rule is observed and proven above; only the label is inferred. The element-first-qword-then-first-entry shape reads as a C++ object whose first qword is a vtable pointer and whose first virtual function is the getter, but whether the element is a C++ object, a callback descriptor, or something else is not established, so that reading is an inference only.
- The sentinel comparison reads as a small-buffer/empty-container check (the stored pointer equals an inline address), but what the container is and why the sentinel lives at offset `0x11e0` is not established, so that reading is an inference only.
- The neighbors suggest a family of accessors over one container, but what calls them and why is not established.

## Unknowns

- The source-level name and types of this window, its container, and its elements.
- The identity and behavior of the virtual function on the mismatch path; it depends on the element's dynamic type and is not identified here.
- What the `0x1200`/`0x11e0` container fields mean, and what the virtual function does with the sentinel and entry `rcx` arguments.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The virtual-call target on the mismatch path, the getter implementation beyond its 9 retained bytes, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
