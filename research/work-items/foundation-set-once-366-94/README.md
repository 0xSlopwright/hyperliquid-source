# foundation-set-once-366-94: what does the set-once cell window at 0x1515a30 compute?

- Component: `foundation`, a bounded part of its setter run (the run the
  `foundation-set-once-94` packet notes continues past `0x15159c0` to
  `0x1515ce0`).
- Task: RE-001 (#94 function map).
- Target: node **#94**, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim: observations about ONE target instruction window; its source-level
  name, its type, and the meaning of the 0/1/8 returns remain inferences or
  unknowns.
- Included: the single FDE window at `0x1515a30` (51 bytes, ending at
  `0x1515a63`), its thirteen int3 padding bytes up to the next FDE at
  `0x1515a70`, its FDE record at `0xcf59f8` (section offset `0x144e0`) and
  its CIE record at `0xce1518`, and the exact set-once protocol it
  implements.
- Excluded: the caller of this window (a full `.text` scan for `e8`/`e9`
  rel32 targeting `0x1515a30` and a whole-file scan for the 8-byte
  little-endian address found none; no caller claim is made), the rest of
  the setter run, all #115 addresses, target execution, Rust
  reconstruction, and any progress-gate change (none is requested).

## Why this packet

The `foundation-set-once-94` packet binds five adjacent windows that all
implement one directly readable protocol with different fields and ranges.
This packet binds the next window of the same shape in the same setter run,
with its own fields and range: flag at `0x60(rdi)`, value at `0x64(rdi)`,
valid inputs `1..366`. It establishes one more concrete small entrypoint
for further reconstruction without declaring the component mapped.

This packet was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1515a30`, and no open pull request title
mentions that address or set-once/set_once for this window.

## Distinction from the once-flag packet (PR #174)

As with the five sibling windows, this window is mechanically distinct from
the twin once-flag windows bound in PR #174: no lock prefix, no atomic
exchange, no call of any kind, no thread-local test, and no tail jump
through an imported slot. Every path ends in a plain `ret`, and the cell it
touches is reached by fixed displacements from the incoming `rdi` pointer.
The shared shape is the set-once protocol itself, not the once-flag
mechanism.

## The protocol, as the bytes show

- `lea rax, [rsi-1]`; `cmp $0x16d, rax`; `ja` out-of-range: inputs outside
  `1..366` return 0 and touch nothing. (Input 0 wraps under the window's
  own `(rsi - 1)` unsigned compare and is out of range too.)
- `cmpl $1, 0x60(rdi)`; `jne` store arm: when the flag is not 1, the
  window stores flag 1 and the input value, and returns `al` 8.
- Otherwise `cmp %esi, 0x64(rdi)` with `cmove`: a set cell returns 8 when
  the stored value matches and 1 when it differs.
- One precision note, locked in by the checker: on the store arm the window
  sets only the low byte of eax (`mov $8, %al`), so the full eax on that
  path is `((input - 1) & 0xFFFFFF00) | 8`, not a clean 8. The compare and
  out-of-range arms set eax fully, so they return clean 1/8 and 0. Callers
  that consume only `al` see 8 on the store arm.

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
python3 tools/foundation_set_once_366.py --check research/work-items/foundation-set-once-366-94/evidence.json
python3 -m unittest tests.test_foundation_set_once_366 -v
```

## Validation, stated honestly

- The retained 51 window bytes decode to a coherent set-once protocol with
  exact branch targets: the `ja` lands on the out-of-range arm at
  `0x1515a53` and the `jne` lands on the store arm at `0x1515a56`; the
  range immediate `0x16d` (365) gives valid inputs `1..366`; the flag and
  value displacements are `0x60` and `0x64`. The window SHA-256 in
  `evidence.json` matches the retained bytes.
- The four pure-simulation tests pass, including the boundary and
  eax-residue cases (`1 -> 8`, `366 -> 0x108`, `255 -> 8`, `256 -> 8`,
  `257 -> 0x108`).
- NOT run to completion on this machine, and why: the local
  `artifacts/node/94/hl-node` is a 133-byte LFS pointer (no git-lfs on this
  VM), so the checker itself and the five binary-dependent tests
  (reproduction plus body/padding/FDE corruption controls) error here at
  the target-digest / ELF-parse step. That is the repo's pre-existing
  LFS-baseline failure class, not a failure of this packet's logic: the
  same checks are written to pass against the materialized artifact, and
  the three evidence-tamper tests that fail before the ELF step pass.
- No raw `objdump`/`--dwarf=frames` output files are included in this
  packet, because the target binary is not materialized on this machine;
  fabricating them would be dishonest. The checker instead locks the exact
  window, padding, FDE, and CIE bytes, so a reviewer with the materialized
  artifact can verify them with the commands above.
- No gate change is requested. What remains unknown: the caller, the
  source-level name and type of the cell, and what the 0/1/8 returns mean
  to the caller. Concrete next question: which window in the setter run
  follows `0x1515a70`, and does it share this protocol?
