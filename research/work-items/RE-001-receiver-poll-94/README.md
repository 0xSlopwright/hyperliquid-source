# RE-001: receiver poll resumption and the terminal call path in node #94

- Component: `foundation`; one bounded RE-001 boundary/xref question, with no
  task prerequisites. No component gate changes.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115 or visor claim.
- Base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  The unlicensed `base/recver.rs` is a research lead, not copied code or trusted
  behavior. This collector and its interpretation were authored from ELF bytes.
- Question: which numeric states resume this receiver-like poll body, and does
  the branch that enters its wait-like helper retry reception after completion?

The retained receiver body has three checked relative jump tables and an actual
call to a wait-like poll helper with binary64 literal **20.0**. Completion of
that branch reaches a statically bound `exit(1)` call chain, not a branch back
to the channel poll. A suspended wait resumes through the stored state. This
distinction matters when reconstructing failure and resumption behavior: treating
this path as an unlimited receive/reconnect loop would change its control flow.
The channel-result meanings, live reachability and actual elapsed wait remain
unresolved; this is not execution or a full Rust async implementation.

## Reproduce

Use authenticated project LFS inputs, unchanged pinned references, Linux,
Python 3.10+ and GNU binutils. Recorded environment: Ubuntu 24.04/WSL2,
Python 3.12.3, GNU readelf/objdump 2.42. The producer uses `objdump -d` with
default AT&T syntax and linked ELF virtual addresses, not rebased addresses.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/receiver_poll_static.py --output work/receiver-poll-94
diff -ru research/work-items/RE-001-receiver-poll-94/observed work/receiver-poll-94
python3 -m unittest discover -s tests -p test_receiver_poll_static.py -v
```

The producer authenticates the entire target before collecting observations.
It checks actual instruction bytes, relative-table displacements, source and
GOT RELA bindings, and the dynamic symbol named `exit`. Exact FDE extents come
from `readelf -wf`; retained raw relocation rows come independently from
`readelf -rW`. Only the local binary pathname in objdump's header is replaced.
No instruction operands or body bytes are normalized. Text rendering can differ
between binutils versions; raw bytes, addresses and body hashes are retained.
No target, emulator, chain service or captured supervisor is executed.

## Exact scope and source binding

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Receiver-like poll | `0x145d5e0..0x145d97c` | `0x145c5e0` | 924 |
| Wait-like poll | `0x145d250..0x145d5da` | `0x145c250` | 906 |
| Channel-like poll | `0x1499120..0x14993c4` | `0x1498120` | 676 |
| Terminal wrapper | `0x14c4de0..0x14c4e17` | `0x14c3de0` | 55 |
| Exit wrapper | `0x4eee1b0..0x4eee1c4` | `0x4eed1b0` | 20 |
| Exit import caller | `0x4ee3710..0x4ee3725` | `0x4ee2710` | 21 |

These six FDE regions total 2,602 bytes. They are not six fully recovered
functions, a whole-node function denominator or equivalent Rust bodies. The
target's observed 121,299 FDE records remain an index-level count.

RELA slot `0x566b328` points to the embedded source path
`/home/ubuntu/hl/code_Mainnet/base/src/recver.rs` at VA/file offset `0x1de97c`.
The primary body references this location from two state-dispatch failure arms.
It associates that body with the source-path lead without establishing an
original Rust symbol. The adjacent wait helper's location slot `0x566b298`
and its exact addend are also retained, without claiming a whole source type.

## Stored state and resumption

The primary dispatch loads byte `input+0x48`, then sign-extends a four-byte
displacement from table `0x21a0f8` and adds the table base:

| Numeric input state | Decoded target |
| ---: | --- |
| 0 | `0x145d60a` |
| 1 | `0x145d8c9` |
| 2 | `0x145d882` |
| 3 | `0x145d61c` |
| 4 | `0x145d7f0` |

This describes those five encoded entries, not an assertion that arbitrary
input bytes are valid. The table load has no general index bound in this body;
safe construction/caller invariants are outside this packet. Two nested state
tables at `0x21a10c` and `0x21a11c` each have four retained entries. Their
actual signed displacements and targets are in `records.json`.

At `0x145d650` the primary calls `0x1499120`. The returned first word is
compared with `0x8000000000000001`; equality sets nested state bytes to 3 and
reaches the primary state-3 store/return path. Other encodings reach the
following retained processing/formatting code. The lower helper separately
uses `0x8000000000000000` and `0x8000000000000001` representations. These
numeric observations are not a recovered `Poll<Option<T>>` ABI or a proof of
which channel condition is reachable; lower queue/waker/TLS contracts remain
unclosed.

## Wait branch and terminal call closure

At `0x145d7db`, the primary stores bits `0x4034000000000000` (binary64 20.0)
at `input+0x50` and initializes the adjacent wait state. It calls the wait-like
helper at `0x145d7f7`. A nonzero helper return stores primary state 4 and returns;
state 4 dispatches back to `0x145d7f0`, the wait polling site. A zero helper
return takes `0x145d85f`, conditionally cleans up the nested object, and reaches
`0x145d87a`. It does not branch back to `0x145d650`.

The wait helper has two retained four-entry dispatch tables at `0x21a0d8`
and `0x21a0e8`. Its initial zero/unordered comparison distinguishes an ordered
zero input from other encodings. The caller's literal is positive finite 20.0.
The helper contains nonnegative checks and floating-to-integer conversion, then
calls constructor slot `0x576f728` and poll slot `0x576f088`. The full conversion,
timer implementation, time units, scheduler/environment and actual elapsed
delay are not proved here. In particular, this packet does not claim that a
live process necessarily waits exactly twenty seconds.

The terminal chain is independently bound through actual code and relocations:

1. `0x145d87a` calls GOT slot `0x576f530`, RELA addend `0x14c4de0`.
2. That wrapper makes two preparatory calls, puts **1** in `edi`, and calls
   slot `0x576fe08`, RELA addend `0x4eee1b0`.
3. The next body preserves that integer across another preparatory call and
   directly calls `0x4ee3710`.
4. That body preserves the integer across its preparatory call and invokes
   slot `0x5777378`. Its actual dynamic symbol table entry names `exit`, with
   relocation type `R_X86_64_GLOB_DAT`; readelf also renders
   `exit@GLIBC_2.2.5 + 0`.

Thus reaching this chain without an earlier helper diverging or unwinding
passes integer 1 to the imported `exit` function. Preparatory/logging/cleanup
helpers may have effects and are not fully closed. No live failure, production
reachability, network reconnect policy or observed process exit is claimed.

## Validation, comparison and limits

The collector's six tests authenticate the real input and exercise local
obligations below the whole-file digest gate: eighteen instruction mutations,
all five table displacements, six RELA retargets, the resolved dynamic import
name and source-path bytes. The original target bytes are the expectations;
these are collector corruption controls, not target execution or an invented
behavioral simulation. See `validation.txt` for exact runs and setup failures.

Rust implementation/build, raw-equal and normalized-equal comparisons, runtime
differential results, full async ABI/ownership and component gates are **not
implemented or measured**. There are no normalization masks, generated progress
changes, imported-file edits, pin advances or hosted CI claims. Next close the
queue/waker return encodings, timer/helper contracts and relevant callers before
implementing a replacement; numeric dispatch evidence alone is insufficient.
