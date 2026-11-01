# foundation-count-scale-94: what does the scaled-count window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-count-scale-94`).
- Reference pin: none. No reference label was used as a lead for this window.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 49-byte FDE window, its fifteen int3 padding bytes, one incoming
  direct call edge per caller (three callers), the outgoing direct call to a
  359-byte shared callee, and the exact integer formula over the input domain.
- Excluded: the call target body at `0x51c4000`, the callers beyond their call
  sites and argument setup (the first caller's FDE record is locked; the other
  two callers' bodies are not retained), other scaled-count windows, all #115
  addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code
from private helpers. A reference label or a matching string cannot establish
that mapping. This packet binds one small, previously unclaimed window whose
arithmetic reads directly from its own bytes: a count field scaled by a fixed
record size, one shared-callee call, and a shift-plus-magic step that recovers
an exact record count. It is the second packet from the calls category: like
the divide-by-one-million window, its rule is stated over its callee's return
value, with the callee itself explicitly excluded. It establishes a concrete
small entrypoint for further reconstruction without declaring the component
mapped.

This window was checked for overlap before building: no work-item, tool, test,
or doc in the tree mentions `0x51c96d0`, and a full-corpus byte comparison
against every FDE body finds no body sharing 60% or more of this window's bytes.
Its mnemonic skeleton is a singleton among small multiply/gate single-call
windows. The `0xcccccccd` multiply idiom appears in exactly one other place in
`.text` (inside an 11,730-byte function, as a mid-body step, not a window),
so this window is not a member of a repeated-window population.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3,
GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's
standard library only. No llvm-objdump, Ghidra, or Java was used; GNU
`--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_count_scale.py --check research/work-items/foundation-count-scale-94/evidence.json
python3 -m unittest tests.test_foundation_count_scale -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service,
networked node, chain operation, or model-backed program was executed. All
analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51c96d0 --stop-address=0x51c9710 artifacts/node/94/hl-node
objdump -d --start-address=0x51c9710 --stop-address=0x51c9d04 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window
including its padding. The `caller.objdump.txt` file retains complete
disassembly of the first caller FDE window. The `frames.txt` file retains
excerpts selecting the FDEs at `.eh_frame` section offsets `0x2a0eac` (this
window) and `0x2a0ec8` (the first caller). The checker locks these raw FDE
records and their shared CIE, and reads their PC/range fields. It does not add
a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase.
The ELF section table maps `.text` with file offset = VA - `0x1000`; the
retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections
rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a0eac` describes `[0x51c96d0, 0x51c9701)`, 49 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start gives
  the instruction sequence below, ending exactly at the FDE endpoint (the `ret`
  at `0x51c9700` is inside the FDE).
- The unwind index stride to the next entry is 64 bytes, ending at `0x51c9710`,
  only because fifteen `int3` bytes (`0xcc`) pad the window after the FDE end.
  The stride is **not** the FDE extent; any description of this window as
  "64-byte FDE-bounded" would overstate the frame by those fifteen padding
  bytes, and the checker locks the 49-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly three direct `e8` calls to the
  window, at `0x51c976d`, `0x51c9d4d`, and `0x51ca374`, each verified as an
  instruction start by disassembly from its containing FDE start
  (`0x51c9710`, `0x51c9d10`, `0x51ca1f0`). The first caller's FDE record is
  locked by the checker; the other two callers' bodies are not retained.
  Register-indirect references, other pointer paths, prefixes, and data
  sections are not a complete xref census.

### Body behavior: one count, one scaled pointer, one call, one exact division

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x51c96d0` | `endbr64` | Landing-pad marker |
| `0x51c96d4` | `push rbx` | Save callee-saved register |
| `0x51c96d5` | `mov eax, dword ptr [rsi]` | Load u32 count |
| `0x51c96d7` | `mov rbx, rsi` | Save struct pointer |
| `0x51c96da` | `mov rcx, rdi` | Pass original `rdi` through |
| `0x51c96dd` | `mov rdi, qword ptr [rsi + 8]` | Load base pointer |
| `0x51c96e1` | `lea rsi, [rax + rax*4]` | `5 * count` |
| `0x51c96e5` | `shl rsi, 4` | `80 * count` |
| `0x51c96e9` | `add rsi, rdi` | Pointer `base + 80 * count` |
| `0x51c96ec` | `call 0x51c4000` | Shared callee; its return in `rax` feeds the scaling |
| `0x51c96f1` | `sub rax, qword ptr [rbx + 8]` | `callee_result - base` |
| `0x51c96f5` | `pop rbx` | Restore callee-saved register |
| `0x51c96f6` | `sar rax, 4` | Arithmetic shift: divide the difference by 16 |
| `0x51c96fa` | `imul eax, eax, 0xcccccccd` | Scale by the magic constant, low 32 bits |
| `0x51c9700` | `ret` | Return the scaled value |

- The call target `0x51c4000` is a 359-byte FDE whose body is excluded here.
  The window's rule is stated over whatever value that callee returns, not over
  the callee's internals.
- The scaling step is an exact division by 80 for aligned inputs, not an
  approximation. For a difference that is a multiple of 80, the shifted value
  is `5 * k` where `k` is the record count, and `5 * 0xcccccccd` equals
  `0x400000001` (`2**34 + 1`), so `(5k * 0xcccccccd) mod 2**32` equals `k mod
  2**32` exactly, for every `k`. The checker verifies the aligned identity on
  `k = 0, 1, 3, 7, 10, 255, 4096, 2**32 - 1` and the raw formula on unaligned
  differences (`1 -> 0`, `16 -> 0xcccccccd`, `79 -> 858993460`, `81 -> 1`,
  `-80 -> 0xFFFFFFFF`, `800 -> 10`).
- The callers use the return as a count: the first caller sign-extends it into
  an argument, the second bounds-checks it against a length, and the third
  bounds-checks it as an index. Those uses are consistent with the record-count
  reading but are not part of the window's rule.

## Inferences

- Inferred label: scaled-count helper. The formula and the aligned identity are
  observed and proven above; only the label is inferred.
- The 80-byte stride and the record-count identity suggest the callee returns a
  pointer into an array of 80-byte records spanning `[base, base + 80*count]`,
  but the callee's behavior is not closed here, so that reading is an inference
  only.

## Unknowns

- The source-level name and types of this window and its callee.
- What the callee at `0x51c4000` computes, and what its other callers are.
- Why the record size is 80 bytes, and what the records contain.

## Excluded

The call target body at `0x51c4000`, the second and third callers' bodies
beyond their call sites, other scaled-count windows, all #115 addresses, target
execution, Rust reconstruction, any family census, and any progress gate. This
packet requests no gate.
