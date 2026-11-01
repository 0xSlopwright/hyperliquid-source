# RE-013: Visor readiness clock and strict deadline comparison

- Component: visor, separate from both node releases.
- Base: `cec50f68e01c967d21538d48c49683ddeea52767`.
- Capture: 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Question: which clock and comparison implement the one-minute override left
  open by `RE-013-visor-lifecycle/unresolved-edges.md`, item 6?
- Status: static observations and a conditional comparison argument. No gate
  requested. Rust reconstruction and runtime equivalence are not established.

This extends #45's bounded lifecycle record. Its string references already show
the deferral/override diagnostics. This packet follows the reaching clock call,
duration constant, relocation-bound arithmetic helpers and actual comparison.
It does not replace the parent's download, quorum or child-process claims.

## Reproduce

From the repository root on Linux, with GNU binutils 2.42 and Python 3.12:

```sh
packet=research/work-items/RE-013-visor-readiness-clock
python3 -B "$packet/survey.py" \
  --binary artifacts/visor/captured/hl-visor --output work/visor-readiness-new
python3 -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -B "$packet/crosscheck_llvm.py" \
  --binary artifacts/visor/captured/hl-visor --output work/visor-readiness-llvm-new
```

The producer authenticates the full input before interpreting offsets or
starting native tools. It makes a private non-executable snapshot, runs GNU
readelf/objdump on that copy and checks every exported instruction byte against
the snapshot. Output must be new. No captured process, emulator or instruction
evaluator runs; native tools only parse bytes. The retained raw outputs use the
relative filename `visor.elf`; no address, instruction or annotation is masked.
Other binutils renderings may differ and are not an exact retained-recipe pass.

`record.json` binds seven unique readelf FDE extents, 3,488 bytes and 818 native
instruction rows. These include previously observed code and library helpers;
they are not seven newly recovered source functions or coverage credit.
The primary FDE `[0x5b41b0,0x5b470d)` contains 1,373 bytes and 276 rows.
All coordinates are ELF virtual addresses; file offsets are recorded separately.

## Clock evidence

The readiness function calls relocation slot `0x7e5388`, whose RELATIVE addend
is `0x444600`. At `0x44460d` this helper clears EDI, then calls `0x66eb20` at
`0x44460f`. That callee preserves this argument until the indirect call at
`0x66eb2d`; its GLOB_DAT slot `0x7e7c78` names `clock_gettime`.
Thus the observed clock request uses numeric clock ID **0**. Linux's
`CLOCK_REALTIME = 0` identifies this as a wall-clock request under the ordinary
Linux ABI, not a monotonic timer. This is a static call argument, not a measured
clock value or proof that a deployment's imported function was not interposed.

On the primitive's normal success path, `0x66eb33` rejects return -1 and
`0x66eb3c` checks the unsigned nanosecond value below 1,000,000,000. The normal
return carries the seconds/nanoseconds loaded from the clock output. Error,
panic and unwind branches are retained but not claimed to return normally.
`0x444600` subtracts a zero epoch through `0x66ea50`, checks the result tag,
then constructs the twelve-byte calendar-shaped value. The complete calendar
encoding and extreme/pre-epoch behavior remain outside this packet's proof.

## Duration and arithmetic boundary

At `0x5b437f` the caller loads the exact binary64 bytes
`00 00 00 00 00 00 4e 40` (60.0) from `0x6e748`. Slot `0x7e53c8` binds the
conversion call to `[0x330360,0x330581)`. For this fixed positive integer input,
the path starts at `0x330439`, takes the exponent interval below `0x433` and
returns at `0x33056d`: RAX=60, EDX=0. In particular, the fractional mantissa
remaining after the integer extraction is zero, so no nanosecond carry occurs.
This specializes one constant; no general floating-duration theorem is claimed.

`0x5b438f..0x5b43d5` forms 60,000,000,000 nanoseconds, applies an i64-maximum
clamp and divides back into seconds/remainder before calling slot `0x7e5390`
(`0x445830`). This particular value does not saturate. The subsequent day/date
adjustment reaches slot `0x7e5398` (`0x444040`). Both complete helper FDE byte
exports are retained. Leap-second/calendar bounds, all overflow calls and a
complete proof of those helpers' calendar meanings are **not** closed here.
The timestamp argument's creation and mutation at the caller are also open.

## Conditional final comparison

Assume execution reaches the final compare with readable, unchanged clock and
deadline storage, and the called helpers return normally with their established
ABI preservation. Do not infer these premises merely from a call returning.
Let `now = (d, s, n)` be the words at stack offsets 0, 4 and 8; let
`deadline = (D, S, N)` be the three words selected by R15, RCX and RAX.

1. `0x5b4475..0x5b4480` (or fallback `0x5b44a2..0x5b44ab`) compares `d,D`
   as **signed 32-bit** values and sets DL for `d > D`. Unequal values go to
   `0x5b45a8` with that result.
2. On equality, `0x5b44b1..0x5b44ba` compares `s,S` as **unsigned 32-bit**
   values. Unequal values go to `0x5b45a8` with DL set for `s > S`.
3. On equality again, `0x5b44c0..0x5b44c6` branches to the override diagnostic
   only for **unsigned `n > N`**. Exact equality falls through to deferral.

Consequently this admitted compare is lexicographic **strict greater-than**,
with the stated mixed signedness. An equal final triple does not select the
override. The lesser/equal route reaches the deferral at `0x5b44cc` and clears
EBX at `0x5b45a4`; the common return at `0x5b45e6` returns EBX through EAX.
The override route retains the entry BL=1 across the normally returning calls.
This is not a complete C/Rust source type or a whole-function equivalence proof.

If the date conversion returns zero (`0x5b445a..0x5b445c`), the compare selects
the immutable fallback at `0x7c7e4`: raw words
`(2147473118, 86399, 999999999)`. It does not compare against an all-zero
deadline. Its ordering is established by the same instructions; labeling it as
a particular maximum calendar date would need the missing encoding proof.

## Validation and limits

On Ubuntu, Python 3.12.3, GNU binutils 2.42 and LLVM 18.1.3:

- Two complete regenerations agree byte-for-byte. Normal and `-O` verification
  pass with all eight corruption controls refused: truncated input, an LFS
  pointer, changed clock call/strict compare/duration/clock-slot data, a changed
  retained FDE end and a changed retained native export.
- Independent LLVM decoding agrees with GNU on the readiness and OS-clock
  extents: 324 instruction byte partitions, 1,574 bytes. Both raw exports and
  the crosscheck command/digests are retained under `crosscheck/`. This is an
  independent decoder check, not an independent semantic-equivalence proof.
- `make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
  pass on the base plus this packet. The eight artifact files, 38 immutable
  imports and seven source pins verify; no generated gate/table is changed.
- Full `make test` is **not run**. Its discovery includes captured-instruction
  evaluators (for example `tests/test_adl_shortfall_budget.py` and
  `tests/test_evm_amount_scale.py`), outside this task's execution permission.
  The packet checks above perform no such evaluation. Hosted CI, Ghidra and
  Rust builds are not claimed.

Initial environment preparation lacked the previously installed user-local
git-lfs PATH and an imported LFS disassembly. After checksum-bound materialization,
Git's stale LFS status in the private reference worktree was refreshed by staging
the identical blob (cached diff empty); the verifier's own fresh-index check
then passed. No reference bytes or source pins changed. An initial LLVM command
used an unsupported `--show-raw-insn`; the final command uses LLVM's default
raw-byte output. These are preparation failures, not captured-program defects.
`VALIDATION.json` records commands, log digests and exact source hashes.

The producer is independently authored project research; it reads no inferred
unlicensed reference source. The unchanged root reproduction command parses that
reference as its documented input; no inferred code is copied into this packet.
Neither existing evidence nor component gates are
edited. Native decoding/FDE/relocation binding and capture-corruption controls
validate the observations; they do not automatically prove the argument above.

The predicate has earlier exits, file/configuration checks, logging, panic and
unwind paths. This packet does not assert complete caller-state semantics,
monotonic elapsed time, exact behavior under clock changes, absence of side
effects, child supervision correctness or update security. No target execution,
network, child process or live filesystem update was performed.

Next question: qualify the timestamp producer and the calendar addition domain,
including day rollover and out-of-range dates, before claiming a full
one-minute readiness policy or implementing it in Rust.
