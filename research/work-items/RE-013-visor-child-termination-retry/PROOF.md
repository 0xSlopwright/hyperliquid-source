# Conditional static argument

This is a manual argument from the retained admitted bytes, FDEs and native
exports. It is not an interpreter, emulator, execution transcript or proof of
every opaque callee. It assumes valid storage and the ordinary x86-64 calling
convention, unmodified relocation bindings and normal completion of the calls
on each described trace. A panic, signal, invalid pointer, hostile import or
non-returning callee can end that trace. Numeric source-level type names are
not recovered from a register or tagged representation alone.

## Signal selection and three backedges

At `0x5e2d84..0x5e2d8a`, zero is compared with the qword at `B+0x18` and signed
overflow branches to `0x5e2ff0`. The subtraction `0 - INT64_MIN` is the sole
overflowing signed operand here. No retry count is tested by this branch.
At `0x5e2d90..0x5e2d9e`, a nonzero byte at `B+0x30` reaches wait directly;
zero reaches `0x5e3018`.

| Lane | Initial operation | Failure selects delay | Delay-complete backedge | Exit from this local loop |
| --- | --- | --- | --- | --- |
| Descriptor signal | `0x5e3026..0x5e303a`: syscall number `0x1a8`, descriptor in ESI, EDX 9, ECX/R8D 0 | RAX equals `-1`, `0x5e3040..0x5e3050` | `0x5e313d -> 0x5e3070`, cleanup then repeated syscall at `0x5e308e` | RAX not `-1` reaches `0x5e2da4` |
| PID signal | `0x5e3142..0x5e314e`: PID in EDI, ESI 9, imported kill | EAX equals `-1`, `0x5e3154..0x5e3163` | `0x5e3239 -> 0x5e3180`, cleanup then repeated kill at `0x5e3192` | EAX not `-1` reaches `0x5e2da4` |
| Wait error | `0x5e2de4`: wrapper `0x67f160` with input at `B+0x30` | DWORD result tag at `rsp+0x28` equals 1 | `0x5e2e7d -> 0x5e2dc0`, cleanup then close/sentinel check and wait again | Tag not 1 reaches `0x5e2e82` |

The signal mechanism is chosen once from DWORD `B+0x3c`: only `0xffffffff`
selects PID kill. A descriptor-send failure repeats that same operation, not
the PID branch. Neither signal retry tests its errno before sleeping.
Under normal Linux behavior the successful signal return is zero, but the
actual machine predicate is the broader `!= -1` shown above.

Before each wait call, `0x5e2dc8..0x5e2dd7` reads DWORD `B+0x40`, replaces it
with `-1`, and calls imported close when the old value differed. Its return
value is unused. Thus a wait-error backedge ordinarily sees the sentinel and
does not repeatedly close the former descriptor. No signal send lies on this
wait backedge.

There is no attempt-count update or budget test on these three cycles.
`B+0x58` is read and written only at common finish `0x5e2ff0..0x5e3002`.
The `inc` plus `cmovne` leaves `UINT64_MAX` saturated and otherwise adds one.
Those instructions do not lie on a retry backedge. This establishes no local
attempt bound, not a claim about every parent call or every possible runtime
interruption.

## Exact fixed-input duration

All fresh delays load eight bytes `00 00 00 00 00 00 f0 3f` from VA `0x6e5f8`
at `0x5e2dfe`, `0x5e30b2`, or `0x5e31b5`. Slot `0x7e53c8` has one
symbol-free RELATIVE relocation to `0x330360`. The argument is exactly 1.0.
For this input alone:

1. The ordered comparison with zero at `0x330364` selects `0x330439`.
   The raw exponent becomes `0x3ff`; the underflow branch is not selected.
2. The fraction is zero. Masking it, adding `2^52-1` and incrementing at
   `0x330458..0x33046b` yields `2^52`.
3. `0x3ff <= exponent < 0x433` selects `0x3304ef`. The shift count is
   `(0x33 - 0xff) mod 256 = 52`, whose x86 masked shift is also 52.
   The integer word saved in RDI is `(2^52) >> 52 = 1`.
4. The exponent difference is zero. Shifting the original bits by zero and
   masking their low 52 bits produces zero. Multiplication by `1,000,000,000`
   therefore produces zero fractional words. Bit 51 is zero, so the rounding
   increment is zero. EDX remains zero and the `1,000,000,000` carry test is
   false.
5. `0x330567..0x33056d` returns RAX 1 plus carry zero, and EDX zero.

This is a fixed-input branch argument, not a general float-duration theorem.
It does not rely on executing an extracted instruction, reproducing the
original object, or testing a Python model against itself.

Each caller stores the seconds and nanoseconds in adjacent qwords. The
seconds clamp is `min_unsigned(seconds, INT64_MAX)`, hence one for this input;
the extra-seconds accumulator becomes zero. At `0x5e2e37`, `0x5e30f7`, and
`0x5e31f7`, EDI is 1 and ESI is zero. RDX and RCX both address that timespec.
R14 comes from the unique imported `clock_nanosleep` slot `0x7e6628`.
The initial request is therefore `(clock=1, flags=0, seconds=1, nanoseconds=0)`.

The successful-return path finishes the current interval. Return code 4 adds
the remaining seconds back and uses the returned nanoseconds before another
sleep call. Any other nonzero return goes to the opaque error helper and
then `ud2` if it returns. New signal/wait failures load 1.0 again: no increasing
or exponential backoff is computed. Kernel scheduling, interruption and import
behavior prevent an exact elapsed-time or termination guarantee.

## Wait result and cleanup context

`0x67f160..0x67f290` has the following normal result construction:

- Input DWORD 1 returns the cached status at `+4`, with output tag 0.
- Descriptor DWORD `+0xc == -1` selects imported `waitpid` at slot `0x7e7df8`,
  using PID `+8`, a status pointer and flags zero. Return `-1` reads errno.
  Code 4 cleans the packed error via opaque helper `0x65f260` and retries
  `waitpid` immediately. Other errors write result tag 1 and a packed word.
  A non-`-1` return caches the status, writes input tag 1 and output tag 0.
- The descriptor lane calls `0x671e30` with the descriptor and numeric 4.
  The wrapper maps its error branch to output tag 1. Its success branch checks
  a presence byte before caching status/tag 1 and returning output tag 0;
  the absent branch calls an error helper. The callee's complete syscall,
  status translation and error contract are not closed here.

Consequently the interpreted ordinary PID wait errors have two levels:
EINTR is handled inside the wrapper without the outer delay; returned errors
take the caller's fixed-delay wait cycle. Do not apply that statement to the
opaque descriptor callee's internal behavior.

At `0x5d8618..0x5d862b`, cleanup examines the low two bits of its input word.
Tags 2 and 3 satisfy the unsigned `(tag-2) < 2` branch; tag 0 falls through
to return. Only tag 1 enters pointer/vtable cleanup. Syscall errno packing
shifts a DWORD by 32 and ORs 2, so those errors take the immediate return.
The full 209-byte cleanup export includes heap and unwind code for context;
their callbacks and allocator ABI are not proved by this observation.

## Post-wait context and remaining closure

The non-error wait branch copies exactly sixteen bytes from `0x6df30`:
`pkill run-client`. The caller constructs words `(16, pointer, 16)` and a zero
byte in stack storage, passes its address through slot `0x7e5f88`, and later
frees the copied allocation. The unique RELATIVE addend is **`0x3d8d70`**.
The returned word is tested for zero, with a logging/cleanup path for nonzero.
This does not identify a shell, argument vector, inherited environment,
signal delivered by that command, or its success/error API. In particular,
the GPG helper discussed in the parent packet is not substituted for this
observed callee.

The 1,502-byte termination FDE also retains logging, allocation and unwind
edges. The argument above is conditional on the described normal traces;
exporting the entire FDE does not close those opaque effects. Enclosing async
states, graceful termination, inherited file descriptors and all parent-level
retry limits remain open. No completed source component or gate follows.
