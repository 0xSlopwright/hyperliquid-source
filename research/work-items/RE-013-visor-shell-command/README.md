# RE-013: Visor shell program, argv layout and wait-status gate

The lifecycle packet [#45](https://github.com/lalalune/hyperliquid-source/pull/45)
maps child termination but leaves its command helper opaque. The separate retry
packet [#1258](https://github.com/lalalune/hyperliquid-source/pull/1258) binds that
callee without interpreting it. This independently scoped packet follows the
actual `0x3d8d70` callee: on the described normal path it constructs a process
object using **`/bin/sh`**, appends **`-c`** and a formatted command string,
passes the object to the known spawn boundary, and waits for its result. A raw
successful-wait status word of zero takes its explicit zero-return path.

This narrows the command-construction question. It does not establish the exact
formatted command, filesystem effects, environment inheritance or actual child
behavior. In particular, the argument is not proved equal to the unmodified
`pkill run-client` literal. The formatter data contains redirection/cleanup
fragments; its complete decoding and helper semantics remain open.

- Task/component: RE-013 / visor; conditional static research, no gate requested.
- Analysis base: `391fe838467760eefc04072c0ea762a7a1155c78`; final submission base:
  `15f79350f790a04aed73b5fc9319f85b535f8282`.
- Separate captured Visor: 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Coordinates: ELF virtual addresses; no inferred source implementation copied.

## Address-bound findings

| Boundary | Observation |
| --- | --- |
| Caller `0x5e2e82..0x5e2ec7` | Copies sixteen literal bytes `pkill run-client`, constructs words `(16, pointer, 16)` plus byte 0, and calls the unique `0x7e5f88 -> 0x3d8d70` relocation. |
| Helper prelude | Calls three opaque preparation helpers. A nonzero preparation result can return before constructing any process. Their filesystem and environment behavior is not inferred from names. |
| Fixed caller branch | The 16-byte input lacks the four-byte `2>&1` pattern and has neither a leading `(` nor a trailing `)`. With the caller's byte 0 it selects the formatter data window at `0x7a9a8`. The resulting string is called `S` here. |
| Process construction | `0x3d9117..0x3d912b` passes the seven bytes `/bin/sh` to slot `0x7e6138 -> 0x67f390`. |
| Argument construction | A two-element `(pointer,length)` array contains `-c` and `S`. The loop at `0x3d9150..0x3d916c` calls slot `0x7e6140 -> 0x67f290` exactly twice in that order. |
| Native representation | The constructor creates an argv pointer array containing a copied program and null. The append helper replaces its previous null with the argument pointer, appends a new null and increments its length. Under successful conversion and storage-preserving growth, the array becomes `["/bin/sh", "-c", S, NULL]`. The argv length field is 4, including that null. |
| Spawn/wait boundaries | Direct `0x3d9192 -> 0x66f280` passes that same process object with numeric arguments 0 and 1. On its non-error result branch the helper closes the selected descriptor and calls `0x67f160` at `0x3d91fa`. #45 supplies the prior spawn-boundary mapping; this packet does not re-prove every spawn fallback. |
| Status check | On the wrapper's tag-0 branch, DWORD status is tested at `0x3d9308`. Zero reaches explicit `xor r15d,r15d`; nonzero selects an opaque error-construction call. Spawn and wait error branches have distinct opaque error calls. No complete error-result discriminant theorem is claimed. |

The [conditional argument](PROOF.md) includes the exact branch and storage
reasoning, fixed short-string conversions, the argv-growth dependency and
unresolved paths. `observed/summary.json` retains fourteen unique relocations,
seven recomputed direct-call destinations and six byte-bound data windows.
Format windows are bounded raw records, not a recovered format-language ABI.

The `/bin/sh` and `-c` pair supports the inference that `S` is intended as a
shell command operand. This is not evidence of the deployed `/bin/sh` identity,
its options, or successful execution. No host shell, `pkill` or other command
was invoked as a test.

## Evidence and reproduction

The selected eight complete FDE extents total **6,320 bytes / 1,471 instruction
rows**. They include prior caller/wait context and shared library helpers, not
eight new recovered functions or matching-code credit. Full GNU records, two
CIE records, raw LLVM exports and comparison receipts are retained. No operand,
address or instruction bytes are masked. Native tools parse a private chmod-0400
copy named `visor.elf`, after full identity admission.

From the repository root, with GNU binutils 2.42 and LLVM 18.1.3:

```sh
packet=research/work-items/RE-013-visor-shell-command
python3 -B "$packet/survey.py" --binary artifacts/visor/captured/hl-visor --output work/visor-shell-new
diff -ru "$packet/observed" work/visor-shell-new
python3 -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -B "$packet/crosscheck_llvm.py" --binary artifacts/visor/captured/hl-visor --output work/visor-shell-llvm-new
diff -ru "$packet/llvm" work/visor-shell-llvm-new
```

Use new output paths. The verifier regenerates all twenty GNU/summary files
twice, rejects three wrong captures and six corrupted retained records, and
preserves existing output in the tenth control. GNU/LLVM agree on all 1,471
instruction byte partitions. This checks decoder boundaries and evidence
integrity; it does not independently prove the semantic argument. The scripts
adapt this author's existing native-export pattern from #1258; reusable tooling
novelty is not claimed and that packet is not a runtime dependency.

`VALIDATION.json` and `validation/` contain exact commands, outcomes, source/log
hashes and raw logs. `make doctor`, `make verify`, `make catalogue-check` and
`make reproduce` passed at both bases. Normal and optimized packet verification
passed at both bases; native scripts and records remained byte-identical.
Unrestricted `make test` was not run because its flat discovery includes
captured-instruction evaluators requiring separate authorization. Publication
is a draft with `[skip ci]`; no hosted CI success is claimed.

## Remaining scope

The argument is conditional on valid non-aliasing storage, ordinary imported
memory-copy behavior, successful allocation/conversion and preservation of live
argv entries by the lower growth helper. Opaque calls must complete normally
without invalidating the relevant storage. Full formatter/C-string domains,
allocator/growth closure, preparation/filesystem behavior, descriptor-wait
internals, command error formatting, signals, unwinding and process spawn
fallbacks are not closed by exporting these FDEs.

No captured execution, emulation, instruction evaluator, target networking,
Rust reconstruction or component-gate change occurred. Original evidence,
imports, pins and progress remain unchanged. New authored scripts/prose use
the root MIT terms; captured exports retain upstream rights. The concrete next
question is the formatter's exact `S` value and temporary-path construction,
before drawing any conclusion about redirection, cleanup or inherited state.
