# foundation-round-up-division-94: what does the round-up-division window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-round-up-division-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was mined fresh from the small-band (20–100 byte) non-gate single-call slice after the big-band gate-singleton direct-call well ran dry, and it passed every guard on its own merits.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 28-byte FDE window, its four int3 padding bytes, the single call edge to the 11-byte field-plus-one callee, the single incoming direct call edge, and the exact round-up-division rule over the object field and the second argument.
- Excluded: the callee implementation beyond its 11 retained bytes, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose round-up-division rule reads directly from its own bytes: take a count from a small helper, and divide the second argument by it, rounded up. It is the ninth packet from the calls category's single-call slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x4f9ee90`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes under either measure (max-length best 0.448 against `0x5417110`, a 29-byte call-and-store window with a wholly different rule; 0.171 against the cached-pointer-refresh window, the rest lower, none against the older claimed corpus); its mnemonic skeleton (`endbr64, push, mov, call, xor, mov, lea, add, pop, div, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The min-length comparison is reported head-on rather than hidden: across the same full corpus with the same >=20-byte substance floor, there are zero hits at or above 0.60 — no >=20-byte body shares 60% or more of this window's shorter length. The 5-byte `endbr64; ret` stubs that produced min-length hits for earlier packets are below the floor and are not twins of a 28-byte window.

The nearest-neighbor question is also addressed head-on. The closest max-length body, `0x5417110` (0.448), is a call-and-store window: it calls a 0x110-byte callee, loads a global address plus 0x10, and stores it through its first argument — no division, no field-plus-one, no second argument. The positional byte matches are the shared `endbr64; push; mov; call` prologue, not a shared rule. Only this one window is built; no neighbor is claimed anywhere in this packet.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_round_up_division.py --check research/work-items/foundation-round-up-division-94/evidence.json
python3 -m unittest tests.test_foundation_round_up_division -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4f9ee80 --stop-address=0x4f9eeb0 artifacts/node/94/hl-node
objdump -d --start-address=0x4f9aab0 --stop-address=0x4f9ac00 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the callee and the window including their padding. The `caller.objdump.txt` file retains disassembly of the caller's containing FDE, with the call instruction verified as an instruction start inside that FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x0028ac68` (the callee), `0x0028ac7c` (this window), `0x00621cb4` (the next FDE, bounding the padding), and `0x00621240` (the caller FDE) — the callee and window use CIE `0x00000000`, while the next and caller FDEs use CIE `0x006205d0`, which differs from the window's CIE; the checker locks each record's own CIE rather than assuming one shared CIE. (Note the `objdump --dwarf=frames` line format: the third column is the FDE record's CIE-pointer delta, not its CIE — the CIE is the value after `cie=`.) The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x0028ac7c` describes `[0x4f9ee90, 0x4f9eeac)`, 28 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x4f9eeab`).
- The unwind index stride to the next entry is 32 bytes, ending at `0x4f9eeb0`, only because four `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those four padding bytes, and the checker locks the 28-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, so a caller file is included and this packet has 8 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: field-plus-one divisor, then round-up division

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4f9ee90` | `endbr64` | Entry |
| `0x4f9ee94` | `push rbx` | Save callee-saved register |
| `0x4f9ee95` | `mov rsi, rbx` | Save the second argument |
| `0x4f9ee98` | `call 0x4f9ee80` | Field-plus-one callee |
| `0x4f9ee9d` | `xor edx, edx` | Zero the high dividend half |
| `0x4f9ee9f` | `mov eax, ecx` | Divisor into rcx (zero-extended) |
| `0x4f9eea1` | `lea -0x1(%rcx), %eax` | Divisor minus one (32-bit) |
| `0x4f9eea4` | `add rbx, rax` | Dividend: x + (t - 1) |
| `0x4f9eea7` | `pop rbx` | Epilogue |
| `0x4f9eea8` | `div rcx` | Unsigned divide rdx:rax by t |
| `0x4f9eeab` | `ret` | Return the quotient |

- The callee at `0x4f9ee80` IS an FDE start (11 bytes, `.eh_frame+0x0028ac68`, CIE `0x00000000`, the same CIE as the window), and its entire body is exactly `endbr64; mov 0x40(%rdi), %eax; add $0x1, %eax; ret` — it returns the dword at `[rdi + 0x40]` plus one, with 32-bit wrap. Five `int3` bytes pad it to the window start. The callee's behavior beyond those 11 bytes is excluded.
- The rule, over object pointer (`rdi`) and second argument (`rsi`, called x), is: let t = (the dword at `[rdi + 0x40]` + 1) mod 2^32; return (x + (t - 1) mod 2^32) / t, as an unsigned 64-bit division, with the quotient in `rax` and the remainder in `rdx` (discarded by the caller-facing rule, since the window returns only `rax`).
- When t > 0 and the sum x + (t - 1) does not overflow 64 bits, that quotient is exactly ceil(x / t): x = 0 gives 0, t = 1 gives x, x = 25 with t = 10 gives 3, x = 20 with t = 10 gives 2. All four are recorded as edges.
- The 32-bit wrap edge is recorded: a field of `0xfffffffe` gives t = `0xffffffff`, and x = 5 gives (5 + `0xfffffffe`) / `0xffffffff` = 1 remainder 4.
- The two fault edges are recorded, not executed: a field of `0xffffffff` gives t = 0, so the `div` faults (#DE, no quotient); x = `0xffffffffffffffff` with t = 2 makes the dividend x + (t - 1) overflow 64 bits, so the `div` faults (#DE) as well. These are architectural consequences of the `div` encoding, stated as limits, not as observed executions.
- The window writes nothing: it stores nothing, and the single pushed register is popped on the only path, so the stack is balanced.
- The single direct caller is `0x4f9aaed` (FDE `0x4f9aab0..0x4f9ac00`, CIE `0x006205d0`), verified as an `e8` instruction start inside its containing FDE; it calls the window with `rdi` = its own entry `rdi` and `rsi` = its own entry `rsi`, and it also calls the callee directly elsewhere in the same FDE. What the caller does with the quotient is not established.

## Inferences

- Inferred label: round-up-division helper. The rule is observed and proven above; only the label is inferred. The (x + t - 1) / t shape reads as rounding a count up to a multiple of the divisor, but what the object, the field, and the second argument are is not established, so that reading is an inference only.
- The single caller suggests a narrowly used helper, but what calls it and why is not established.

## Unknowns

- The source-level name and types of this window, its object, and its field at offset `0x40`.
- What the second argument counts, and what the caller does with the quotient.
- Whether the fault edges are reachable in practice; the field value that would make t = 0 is not known to occur.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation beyond its 11 retained bytes, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
