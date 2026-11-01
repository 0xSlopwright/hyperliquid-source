# RE-013: local child termination retries

The lifecycle packet [#45](https://github.com/lalalune/hyperliquid-source/pull/45)
leaves child retry limits and delay units open (unresolved edge 7). This packet
qualifies the **local** termination path at `0x5e2d70`: signal-send failures
and a wait-error result take three fixed-delay retry loops. Each fresh delay
request is one second, using relative `CLOCK_MONOTONIC` sleep. The backedges
have no local attempt counter or growing delay. Continued failures can keep
these local loops repeating, conditional on the intervening calls returning
normally. This does not establish the enclosing async parent's retry policy.

Task/component: RE-013 / visor. Analysis began at `7194e50b54c6cea3380f2e78d6edfe6fd73cc7bb`;
final submission base is `391fe838467760eefc04072c0ea762a7a1155c78`. Target: the separate captured Visor,
8,305,392 bytes, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Coordinates below are ELF virtual addresses. No inferred unlicensed
implementation was read or copied into these independently authored tools.
New authored scripts and prose use the root MIT terms. Captured instruction
exports and header excerpts are evidence retaining their upstream terms.

## Observed paths

| Path | Bound observation |
| --- | --- |
| Entry | A signed-overflow branch on `0 - [B+0x18]` reaches the common finish. Otherwise a nonzero byte at `B+0x30` bypasses the signal-send branch. These are raw storage predicates; the enclosing type is not recovered. |
| Signal via descriptor | When DWORD `B+0x3c != 0xffffffff`, the call through imported `syscall` uses number 424, that descriptor, signal 9, null info and flags zero. A return other than `-1` advances to wait. Failure sleeps, drops its packed error, and repeats the same syscall. |
| Signal via PID | The descriptor sentinel selects imported `kill(DWORD[B+0x38], 9)`. A return other than `-1` advances to wait. Failure sleeps, drops its packed error, and repeats `kill`. |
| Wait | The caller stores `-1` to DWORD `B+0x40` before closing its former value, when present. The close result is ignored. It then calls `0x67f160` on storage at `B+0x30`. Result tag 1 sleeps and retries wait; this backedge does not resend the signal. |
| Wait wrapper | Cached tag 1 returns a stored status with result tag 0. The PID lane calls `waitpid(pid, &status, 0)` and retries errno 4 internally. Other errors return tag 1. The descriptor lane delegates to `0x671e30`; that callee's full behavior remains open. |
| Sleep | All three paths load the same binary64 `1.0` at `0x6e5f8` and call `0x330360`. Its fixed-input path returns `(RAX=1, EDX=0)`. Each initial `clock_nanosleep` call has clock 1, flags 0 and a `(1,0)` timespec. Code 4 resumes the remaining interval. Other nonzero codes take the helper/`ud2` error path. |
| Cleanup | `0x5d8610` is tagged-error cleanup. Low tags 0, 2 and 3 return immediately. Packed syscall errors have low tag 2. It is not the sleep operation. Heap-tag cleanup and unwind paths remain distinct. |
| Command context | After a non-error wait result, sixteen bytes `pkill run-client` are copied into owned storage and passed to the callee bound by slot `0x7e5f88`, namely `0x3d8d70`. Its argv, shell, environment and exit-status contract is not interpreted here. |
| Finish | The word at `B+0x58` is incremented with unsigned saturation on the common normal finish. It is outside all three retry backedges and supplies no attempt bound within them. No source-level field name is assigned. |

The [conditional argument](PROOF.md) gives branch addresses, the exact
fixed-input arithmetic and the boundary of each conclusion. Imported function
names and the converter/command target come from unique ELF relocations, with
independently decoded GNU records retained. The numeric ABI qualification is
in [ABI-EVIDENCE.json](ABI-EVIDENCE.json). Linux syscall 424 is identified by
the [kernel x86-64 syscall table](https://github.com/torvalds/linux/blob/v6.8/arch/x86/entry/syscalls/syscall_64.tbl).
The [clock_nanosleep interface](https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html)
defines flags zero as a relative interval and provides a remaining interval
on interruption. Installed header excerpts bind clock 1, errno 4 and signal 9.
These identify an ordinary Linux x86-64 ABI, not the deployed host's version,
availability, timing, interposition or observed behavior.

## Retained scope and reproduction

| Complete FDE extent | Bytes | GNU/LLVM instruction rows |
| --- | ---: | ---: |
| `0x5e2d70..0x5e334e` termination | 1,502 | 349 |
| `0x5d8610..0x5d86e1` cleanup context | 209 | 67 |
| `0x330360..0x330581` converter | 545 | 140 |
| `0x67f160..0x67f290` wait wrapper | 304 | 84 |
| Total | 2,560 | 640 |

These include prior lifecycle observations and a converter used by the earlier
readiness-clock packet. They are not four newly recovered source functions,
new matching coverage or completed component gates. Full bodies are exported;
opaque callees, heap cleanup and exceptional paths are not given invented
semantics. All original packets, captures, imports and seven source pins remain
unchanged.

`survey.py` admits the complete input before ELF parsing or native tools. GNU
readelf/objdump then parse a private, non-executable copy named `visor.elf`.
Every exported row must tile its exact FDE and equal the admitted bytes. Two
CIE records and eight relocation bindings are retained. No instruction bytes,
addresses or operands are masked; using the same fixed private basename needs
no pathname normalization. GNU 2.42 is the retained recipe.

From the repository root, choose new output paths:

```sh
packet=research/work-items/RE-013-visor-child-termination-retry
python3 -B "$packet/survey.py" --binary artifacts/visor/captured/hl-visor --output work/visor-retry-new
diff -ru "$packet/observed" work/visor-retry-new
python3 -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -B "$packet/crosscheck_llvm.py" --binary artifacts/visor/captured/hl-visor --output work/visor-retry-llvm-new
diff -ru "$packet/llvm" work/visor-retry-llvm-new
```

The verifier regenerates all twelve GNU/summary files twice. It refuses three
bad captures and six corrupted retained records, and preserves existing
output in the tenth control. LLVM 18.1.3 independently agrees on all 640
instruction byte partitions / 2,560 bytes. This checks decoder boundaries;
it does not independently prove the semantic argument. Exact executed
commands, source identities, outcomes, preparation corrections and raw logs
are recorded in `VALIDATION.json` and `validation/`.

## Limits

No captured binary, emulator, instruction evaluator, process signal, child
launch, target service or chain action was executed. Native analysis programs
and the owned Python controls do run. No Rust implementation, measured delay,
global retry bound, recovered nominal type/ABI, complete command/wait helper,
filesystem/environment inheritance, graceful-termination policy or update
security claim is made. The sleep request is not an elapsed-time guarantee.

Unrestricted `make test` is not run: its flat discovery includes captured-
instruction evaluators. Publication uses `[skip ci]` to keep this submission
from starting that unapproved automatic execution. Static root checks and
their exact scope are reported separately; no hosted pass is claimed. All
component gates stay false. A next step is to qualify the opaque descriptor-
wait and command callees, then relate these local loops to the parent's full
state transitions under separately authorized execution where needed.
