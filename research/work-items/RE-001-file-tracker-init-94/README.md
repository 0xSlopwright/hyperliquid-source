# RE-001: one file-tracker initialization and fallback path in node #94

- Component: `foundation`; bounded RE-001 function-boundary/xref question,
  with no prerequisites. All component gates remain false.
- Target: node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115/visor or complete tracker claim.
- Main base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Unlicensed `base/file_mod_time_tracker.rs` is a lead, not copied source or
  trusted behavior. Tools and tests here were authored from authenticated bytes.
- Question: how does this initializer separate the regular-file predicate,
  metadata/load failure fallback and the alternative initialization helper?

This body is not simply a getter or an unconditional panic on read failure.
It prepares a diagnostic containing `could not load file, using default value.
Error: ` on a common fallback path and stores a fixed three-word default value.
The alternative predicate-false path calls another initialization helper and
checks its nonzero result separately. That helper has an exact `/dev/null`
short circuit. This evidence constrains initialization/error behavior before a
replacement is written; it does not recover every generic tracker instance,
the polling/update protocol or a full serialization/ownership ABI.

## Reproduce

Linux, Python3.10+, authenticated project inputs/pinned references and GNU
binutils are required. Recorded: Ubuntu24.04/WSL2, Python3.12.3, GNU
readelf/objdump2.42, default AT&T syntax, linked ELF virtual addresses.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/file_tracker_init_static.py --output work/file-tracker-init-94
diff -ru research/work-items/RE-001-file-tracker-init-94/observed work/file-tracker-init-94
python3 -m unittest discover -s tests -p test_file_tracker_init_static.py -v
```

The producer authenticates the entire input before interpreting sections,
instructions, literals or RELA bindings. Exact FDE extents come independently
from `readelf -wf`. Raw bounded objdump/readelf records and body hashes are
retained. Only the local input pathname in objdump's header is replaced;
instruction operands and bytes are not normalized. Different binutils text
rendering is possible. No captured binary, emulator or filesystem operation
from that binary was executed; only static parsing/disassembly was performed.

## Exact regions and attribution

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Initializer | `0x13cc980..0x13cce7f` | `0x13cb980` | 1,279 |
| Regular-mode predicate | `0x144a710..0x144a884` | `0x1449710` | 372 |
| Metadata path | `0x144c930..0x144ca41` | `0x144b930` | 273 |
| Load path | `0x144d470..0x144db5b` | `0x144c470` | 1,771 |
| Alternative initialization path | `0x144f030..0x144f43d` | `0x144e030` | 1,037 |

These five exact FDE regions total 4,732 bytes. They are not five reconstructed
Rust functions or a whole-node matching denominator. Helper names are inferred
roles, not original Rust symbols. The embedded target path
`/home/ubuntu/hl/code_Mainnet/base/src/file_mod_time_tracker.rs` is at VA/file
offset `0x1f9bb7`; actual RELA slot `0x5666c88` points to it, and the initializer
references that location record at `0x13ccc11` on its fallback diagnostic route.

## Predicate, fallback and stored fields

The initializer calls slot `0x576e9e8`, whose RELA addend is predicate entry
`0x144a710`. In the predicate's non-error mode-inspection route, instructions
at `0x144a769` mask a 32-bit word with `0xf000`, compare with `0x8000`, and
return the equality bit. Thus that local route recognizes modes with low16
bits in `[0x8000,0x9000)`. All65,536 low16 encodings are checked against an
independent interval predicate in the tests; higher bits are discarded by the
observed mask. This is not a test of real stat/syscall behavior or all helper
error/unwind paths.

When the initializer's predicate result is nonzero, it calls metadata slot
`0x576e9f0`, addend `0x144c930`. A returned DWORD tag1 goes to the common
fallback path. Other tags preserve the returned timestamp-shaped words and
call the load body `0x144d470`. That body's returned first word is negated;
the overflow case, corresponding to `0x8000000000000000`, also reaches the
fallback route. Numeric representations are observed; a complete Result/T ABI,
JSON schema, parser behavior and calendar/timestamp contract are not proved.

The common path prepares the compact descriptor at `0x1ecb5d` containing the
printable fallback/error message, references the tracker source-location record
and calls a diagnostic helper. Actual emission and logging side effects remain
unknown. It then stores:

- output `+0x18/+0x20/+0x28`: words **0,8,0**;
- output `+0x30`: bits `0x4014000000000000`, binary64 **5.0**;
- output `+0x38`: zero DWORD; output `+0x48`: the preserved error-related word;
- output `+0x50`: word `0x00f6401a`; output `+0x58`: zero DWORD.

The successful-load route instead stores the returned value's three words at
`+0x18/+0x20/+0x28`, preserves its metadata-derived words at `+0x50/+0x54`,
sets `+0x48` to zero and uses the same 5.0 interval-shaped value. We do not infer
a complete Vec/Option/Chrono layout or time unit solely from these offsets.
Defaults versus loaded values and the two failure representations are the
bounded observations, not a full recoverable-error guarantee.

## Alternative initialization and the exact null-device route

On predicate zero, the body calls `0x144f030` at `0x13cca94`. Nonzero returned
`rax` branches to the separate failure/formatting call near `0x13ccd74`;
zero proceeds to default field initialization. Consequently, not every failure
in this body follows the same diagnostic/default route. The lower helper's
I/O/serialization and failure helper contracts remain unclosed.

At `0x144f05d`, the alternative helper first compares the path length with9.
Only that length reaches an eight-byte comparison against little-endian
immediate bytes `/dev/nul` plus the ninth byte `l`. Exact `/dev/null` returns
zero through the early epilogue path without entering the remaining path
processing. Other paths continue into the retained helper body. This proves
the exact comparison and branch, not a general filesystem safety property or
that any real file was created or written during this research.

## Validation and remaining gaps

Six focused tests cover real target instructions/literals, five RELA retargets,
the mode-mask interval over all low16 values and null-device instruction
immediates. Corruption controls bypass only the global digest gate so the
local obligations are actually exercised. Required checks and exact repeated
producer results are in `validation.txt`.

No Rust implementation/build, raw/normalized-equivalence denominator, runtime
differential, whole file-tracker update protocol, caller ownership, complete
parser/metadata/initialization-helper closure or hosted CI claim exists. No
imports, pins, generated progress or component gates change. Next close the
metadata/load return representations and relevant update callers before
implementing a compatible tracker; these five retained bodies alone do not
establish a drop-in replacement.
