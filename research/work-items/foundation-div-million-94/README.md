# foundation-div-million-94: what does the divide-by-one-million window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-div-million-94`).
- Reference pin: none. No reference label was used as a lead for this window.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 38-byte FDE window, its ten int3 padding bytes, one incoming
  `R_X86_64_RELATIVE` slot, the outgoing direct call to a 110-byte shared callee,
  and the exact integer formula over the input domain.
- Excluded: the call target body at `0x552ab00`, the slot user beyond its slot
  record, other divide-by-constant windows, all #115 addresses, target execution,
  Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code
from private helpers. A reference label or a matching string cannot establish
that mapping. This packet binds one small, previously unclaimed window whose
arithmetic reads directly from its own bytes: one call whose return value is
divided by exactly one million through a 128-bit magic multiply. It is the first
packet from the calls category: every earlier packet window was call-free, while
this window's rule is stated over its callee's return value, with the callee
itself explicitly excluded. It establishes a concrete small entrypoint for
further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test,
or doc in the tree mentions `0x55243d0`, and a full-corpus byte comparison
against every FDE body finds no body sharing 60% or more of this window's bytes.
Its mnemonic skeleton is a singleton among small multiply/gate single-call
windows. The divide-by-constant idiom recurs across the binary (the same magic
constant appears inside larger functions), but no other standalone window
implements this exact rule: the other small multiply windows divide by
different constants.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3,
GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's
standard library only. No llvm-objdump, Ghidra, or Java was used; GNU
`--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_div_million.py --check research/work-items/foundation-div-million-94/evidence.json
python3 -m unittest tests.test_foundation_div_million -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service,
networked node, chain operation, or model-backed program was executed. All
analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x55243d0 --stop-address=0x5524400 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window
including its padding. The `frames.txt` file retains the excerpt selecting the
FDE at `.eh_frame` section offset `0x2c9938` (this window). The checker locks
this raw FDE record and its shared CIE, and reads their PC/range fields. It
does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase.
The ELF section table maps `.text` with file offset = VA - `0x1000`; the
retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections
rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c9938` describes `[0x55243d0, 0x55243f6)`, 38 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start gives
  the instruction sequence below, ending exactly at the FDE endpoint (the `ret`
  at `0x55243f5` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x5524400`,
  only because ten `int3` bytes (`0xcc`) pad the window after the FDE end. The
  stride is **not** the FDE extent; any description of this window as "48-byte
  FDE-bounded" would overstate the frame by those ten padding bytes, and the
  checker locks the 38-byte body and the padding separately.
- Exactly one `R_X86_64_RELATIVE` relocation maps a slot to this window: slot
  `0x5788170` carries addend `0x55243d0`. That slot is the window's incoming
  edge: a byte-pattern scan of `.text` finds no direct `e8` call to the window
  and no `ff15`/`ff25` site targeting the slot. Register-indirect references,
  other pointer paths, prefixes, and data sections are not a complete xref
  census.

### Body behavior: one call, one exact division by one million

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x55243d0` | `endbr64` | Landing-pad marker |
| `0x55243d4` | `sub rsp, 8` | Stack alignment for the call |
| `0x55243d8` | `call 0x552ab00` | Shared callee; its return in `rax` is the dividend |
| `0x55243dd` | `add rsp, 8` | Stack restore |
| `0x55243e1` | `movabs rdx, 0x431bde82d7b634db` | Division magic constant |
| `0x55243eb` | `mul rdx` | 128-bit product `rdx:rax = rax * magic` |
| `0x55243ee` | `mov rax, rdx` | High half of the product |
| `0x55243f1` | `shr rax, 0x12` | Shift 18; total shift 64 + 18 = 82 |
| `0x55243f5` | `ret` | Return the quotient |

- The call target `0x552ab00` is a 110-byte FDE whose body is excluded here. Its
  observable arithmetic (not claimed as this packet's rule) reads an input
  structure, multiplies one field by `0x3b9aca00` (10^9), clamps the sum against
  a second field, and subtracts a base field; it calls two PLT entries whose
  identities are unknown. The window's rule is stated over whatever value that
  callee returns, not over the callee's internals.
- The division is exact, not approximate. The magic constant equals
  `ceil(2**82 / 1000000)`, so the computed value `(x * magic) >> 82` is at least
  `x / 1000000` and exceeds it by less than `2**-18`, which cannot cross an
  integer boundary for any `x` below `2**64`. The checker verifies the rule
  against `x // 1000000` on boundary values (`0`, `1`, `999999`, `1000000`,
  `1000001`, `1999999`, `2000000`, `123456789`, `2**63 - 1`, `2**64 - 1`) and
  on 5000 deterministically seeded inputs across the full `u64` range.

## Inferences

- Inferred label: divide-by-one-million helper. The rule itself is observed
  (exact division, proven above); only the label is inferred.
- The callee's multiply by 10^9 followed by this window's division by 10^6 is
  consistent with a nanoseconds-to-milliseconds conversion, but that unit
  reading is an inference only: neither window names its units, and the callee's
  external calls are unidentified.

## Unknowns

- The source-level name and types of this window and its callee.
- The identity of the callee's two PLT call targets (`0x56601a0`, `0x5660430`).
- What calls through slot `0x5788170`, and why the caller needs the quotient.
- Whether the slot user and this window belong to the same component.

## Excluded

The call target body at `0x552ab00`, the slot user beyond its slot record,
other divide-by-constant windows (different constants, different divisors),
all #115 addresses, target execution, Rust reconstruction, any family census,
and any progress gate. This packet requests no gate.
