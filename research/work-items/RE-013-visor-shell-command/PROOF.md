# Conditional construction argument

This is a manual static argument from admitted bytes, FDEs, data and relocation
records. It is not instruction execution or a general source/ABI recovery.
Assume ordinary x86-64 calling conventions, valid non-overlapping input/output
storage, successful ordinary allocations and memory copying, and normal return
of opaque calls without invalidating live storage. Where a lower helper's
semantics are not closed, the additional assumption is stated explicitly.

## The fixed caller and formatter selection

At `0x5e2e99..0x5e2ea0`, sixteen bytes at `0x6df30` are copied to owned storage.
`0x5e2ea3..0x5e2ebf` constructs `(16, pointer, 16)` and byte 0 at offset `+24`.
The call at `0x5e2ec7` uses the unique RELATIVE slot `0x7e5f88 -> 0x3d8d70`.
The caller later checks the returned word for zero; this alone does not recover
the callee's result type or establish its error domain.

The callee reads the byte at `+24` into EBP and preserves the input object.
Its prelude calls slots bound to `0x3a0440`, `0x3a1780` and `0x3a0d10`, with a
formatter call at `0x2bebb0` in between. A nonzero return from `0x3a0d10` selects
the early return through `0x3d8e60`. No process construction is on that edge.
The complete preparation/formatting semantics remain opaque here.

On the preparation-success edge, `0x3d8e75..0x3d8eb6` reads pointer and length.
For length 16 the scalar scan compares each four-byte window at offsets 0..12
with `0x31263e32` (little-endian `2>&1`). The constant input has no byte `2`, so
none can match. The first byte is `p`, not `(`, and the last is `t`, not `)`.
The parenthesized-input branch at `0x3d9611` is therefore not selected.

The caller's option byte is zero. `0x3d8eed..0x3d8f78` selects the data at
`0x7a9a8`, supplying callbacks/data at `0x3d8230` and `0x3d7320`. Its output
words are captured in stack slots `+0x10`, `+0x18`, `+0x20`. Let `S` be the bytes
at that output pointer with that output length. This packet does not interpret
the format opcodes, callbacks, temporary-path value or exact contents of `S`.
Raw windows containing `2>&1`, `&& rm` and `/dev/null` are insufficient to prove
the complete shell syntax or filesystem effects.

## Fixed program and two ordered argument calls

At `0x3d90cc..0x3d9105`, a 32-byte allocation is populated with two 16-byte
records. The first points to two bytes `-c` at `0x7a9c2`; the second takes
pointer/length from `S`. Preparation of this array does not tokenize `S`.

`0x3d9117..0x3d912b` passes output object `W = rsp+0xf8`, pointer `0x7a9c4`
and length 7 to slot `0x7e6138`. Its unique RELATIVE binding is `0x67f390`.
Those seven admitted bytes are `/bin/sh`.

The loop starts RAX at zero. At `0x3d9150` it exits when RAX equals `0x20`.
Each iteration sets R13 to RAX+16, loads one pointer/length record, passes `W`
to slot `0x7e6140 -> 0x67f290`, then copies R13 back to RAX. Under normal call
return and callee-saved-register preservation, iterations use offsets 0 and
16, then exit at 32. Thus the two argument calls receive `-c` followed by `S`.
No additional argument call is on this local normal path.

## Short strings, argv words and growth dependency

Both construction routines call `0x7e4c48 -> 0x2bf100`. For the fixed short
inputs `/bin/sh` (7) and `-c` (2), this helper allocates length+1 bytes and calls
the unique imported `memcpy`. The scalar loop `0x2bf160..0x2bf172` visits each
original byte and finds no NUL. It reaches `0x2bf210`, then calls
`0x7e4bd0 -> 0x2bea00` with capacity length+1 and initialized length.

The finalizer's `0x2bea1f` stores NUL at the old length. After increment, length
equals capacity, selecting `0x2bea44` without shrink/grow. It returns the pointer
and length+1. The converter writes `INT64_MIN` as its successful tag. For these
inputs, this argument closes the short scan and finalizer under the stated
allocation/memcpy assumptions. It does not prove every vectorized search,
interior-NUL error, overflow, allocation-failure or unwind path.

The constructor reads that success tag and takes the signed-overflow edge of
negation, creates a 16-byte pointer array, copies the terminated program string
to another allocation and places its pointer at index 0. It stores null at
index 1. The object has capacity 2 at `W+0`, array pointer at `W+8`, and length
2 at `W+0x10`. Its other program pointer/length words are at `W+0x80/+0x88`;
the argv[0] pointer and this program pointer differ but contain copied bytes.
This is an observed representation, not a recovered nominal Rust type.

On successful conversion of an argument, `0x67f2fe..0x67f323` reads the old
length `n`, writes its pointer at argv[n-1], writes null at argv[n] and stores
length n+1. When length equals capacity it calls `0x7e7c90 -> 0x675c90` first.
For initial capacity 2, `0x675c9e..0x675ccf` selects new capacity 4 and calls
the still-opaque lower helper `0x6760d0` with old storage and 8-byte element
size/alignment. Normal result replaces pointer/capacity; error selects a fatal
helper. **Preservation of the live old entries by `0x6760d0` is an explicit
condition of the following array conclusion, not independently proved here.**

With that preservation condition and successful conversion of `S`, the first
append replaces index 1 with `-c`, grows capacity to 4, places null at index 2
and stores length 3. The second append uses spare capacity, writes `S` at index
2, null at index 3 and length 4. Hence the constructed pointer array is
`["/bin/sh", "-c", S, NULL]`. This is three non-null entries, not four arguments.
If `S` conversion reports its other tag, the helper sets a flag and substitutes
different bytes; the asserted array conclusion does not cover that branch.

## Spawn boundary and raw status gate

At `0x3d917e..0x3d9192`, RDI selects a result area, RSI is the same object `W`,
EDX is zero and ECX is one. The E8 displacement recomputes to `0x66f280`.
The accepted lifecycle packet #45 mapped that callee's Rust process-spawn
fallbacks. This packet does not export/re-prove its entire 9,849-byte body,
actual argument consumption, host executable lookup or runtime effects.

A result DWORD 1 at `rsp+0x30` selects `0x3d9870`. On the other branch, the
helper copies the result's child-state words, replaces one descriptor with
`-1`, conditionally closes the old descriptor through imported `close`, and
calls the complete retained wait wrapper at `0x67f160` (`0x3d91fa`).

The wrapper's cached/PID/opaque-descriptor lanes are retained for the result
layout context. Under its ordinary successful path, output DWORD tag is 0 and
DWORD `+4` is its cached or returned status. The caller tests its byte-0 tag
at `0x3d91ff`: a nonzero tag goes through `0x3d97f0`. On tag 0, it reads status
into EBX at `0x3d92bb`, performs descriptor/object cleanup and tests EBX at
`0x3d9308`. Status zero avoids `0x3d96b2`, executes `xor r15d,r15d` at
`0x3d9350`, and returns RAX from R15 through the common epilogue. Nonzero status
selects opaque error construction at `0x3d96dd -> 0x3df120`.

This proves that raw zero status takes an explicit zero-return normal path,
conditional on intervening cleanup returning normally and preserving the
callee-saved status. It is not a global iff theorem: opaque error/preparation
helpers and result formatting have not been proved unable to return zero.
No wait-status-to-POSIX-exit-code decoding or actual command success is claimed.

## Remaining closure

Program/argv fields here are construction observations. The shell-language
inference comes from those bytes; no claim identifies the host's `/bin/sh`
implementation. Closing the intended command still needs the format callbacks,
their encoded format language, temporary-path/preparation helpers, lower argv
growth semantics and the spawn consumer. Environment/FD inheritance, readback,
cleanup success, global termination policy and exceptional traces remain open.
