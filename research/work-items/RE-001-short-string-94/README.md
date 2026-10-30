# RE-001: node #94 compact-string construction and representation

- Component: `foundation`. Bounded RE-001 static boundary/xref question;
  RE-001 has no prerequisites. No component gate changes.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115 or visor claim.
- Repository base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  `base/short_string.rs` is an unlicensed research lead, not copied code or
  trusted semantics. This packet's tooling was independently authored from
  authenticated ELF bytes and native disassembly.
- Question: what compact carrier is produced from short inputs, and does the
  long-input path truncate those inputs or route them through another producer?

The observed constructor sends inputs of at most **16 bytes** through a checked
recursive little-endian 128-bit packer. Longer inputs use a lookup/cache path;
a miss generates a ten-step alias, checks its resulting byte length, and uses
the same packer. This matters when reconstructing identifiers: interpreting the
carrier as a pointer, packing in big-endian order, or truncating long inputs is
inconsistent with these instructions. It does not establish a whole Rust struct,
a wire encoding, accepted input identity, or a complete hash/alias algorithm.

## Reproduce

Requirements: Linux, Python 3.10+, GNU binutils (`readelf`, `objdump`), and the
project's authenticated LFS artifacts and unchanged pinned references. Follow
the reviewed `scripts/setup.sh` instructions for inputs. Rust toolchain installs
in that script are unnecessary for this Python-only static packet. No npm,
REA, Ghidra, node traffic, captured executable launch, or chain action is needed.

```sh
make doctor
make verify test catalogue-check reproduce
python3 tools/short_string_static.py --output work/short-string-static-94
diff -ru research/work-items/RE-001-short-string-94/observed work/short-string-static-94
python3 -m unittest discover -s tests -p test_short_string_static.py -v
```

Recorded tools: Python 3.12.3 and GNU binutils 2.42 on Ubuntu 24.04/WSL2.
The disassembly command is `objdump -d` with its default AT&T syntax; start/stop
addresses are ELF virtual addresses, with no rebasing or syntax overrides.
The producer checks the entire input's size and digest before reading the ELF.
It decodes section mappings and relevant RELA records, independently obtains
FDE ranges from readelf, and streams the complete `.text` objdump output to
collect the bounded direct/GOT references. Raw bounded disassembly, FDE and
relocation rows are retained. Only the local input pathname in objdump's
header is replaced; instruction bytes and operands are unchanged. Different
binutils versions can render text differently; the byte/hash records are also
retained. No body normalization or equivalence comparison is performed.

## Exact ranges and attribution

| Observed role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Constructor | `0x1449a80..0x144a009` | `0x1448a80` | 1,417 |
| Recursive packer | `0x144a010..0x144a069` | `0x1449010` | 89 |
| Long-form producer | `0x13c6060..0x13c629e` | `0x13c5060` | 574 |

These are exact readelf FDE extents, not next-index size guesses. The target
has 121,299 decoded FDE records; **three** bodies are studied here. Four caller
FDEs supply call-site context, not four additional recovered implementations.
No whole-target function denominator or component ownership is established.

Three `R_X86_64_RELATIVE` records at `0x566a990`, `0x566a9a8`, and `0x566a9c0`
point to the exact embedded path
`/home/ubuntu/hl/code_Mainnet/base/src/short_string.rs` at VA/file offset
`0x1ea56a`. Instructions in the constructor and packer reference those
location records on length/bounds/overflow failure paths. This associates the
observed bodies with the compact-string source path independently of inferred
reference names; it does not recover their original Rust function signatures.

## Carrier recurrence and admission

At `0x1449a9b`, the constructor compares its length argument against 16 with an
unsigned `jbe`. The inline route clears index register `edx` and tail-jumps
through GOT slot `0x576f5f0`, whose RELA addend is the packer `0x144a010`.

The packer receives a byte pointer, length and index. Its inspected body gives:

1. `index == length`: return zero in both halves. `index > length` takes a
   bounds failure path; it is not silently treated as the base case.
2. Load `byte[index]`, increment the index, and recursively call the same
   authenticated GOT target.
3. Check that the recursive result's high 64-bit half shifted right by 56 is
   zero. A discarded nonzero high byte takes an overflow failure path.
4. `shld $8` carries the low half into the high half; `shl $8` shifts the low
   half; OR the saved current byte into its low bits. Return low in `rax` and
   high in `rdx`.

Thus the observed recurrence is
`P(i) = byte[i] OR (P(i+1) << 8)`, with `P(length)=0`, checked against 128-bit
overflow. For constructor-admitted inputs, `P(0)` places the first byte in the
least significant eight bits. This proves the endian order from recursion and
unwinding, rather than guessing it from x86 memory order.

There is no separate encoded length in this returned two-register carrier.
For example, the recurrence alone assigns the same integer carrier to a byte
`0x41` and to bytes `0x41,0x00`. This is only a carrier-level observation:
caller acceptance/sanitization, string identity, display behavior, serialization
and any broader collision impact are not established by this packet.

## Long-input route and cache boundary

The `length > 16` route inspects a global table, uses a hash/probe path, checks
stored key length, and calls the external `bcmp` comparison path on candidate
keys. A hit returns the stored pair of 64-bit halves. On a miss:

- The constructor initializes an output buffer and passes a counter pair
  `[0,10]` to the body at `0x13c6060`.
- That producer resets four hash-like state constants for each iteration,
  feeds input bytes, one `0xff` byte and a four-byte counter through an
  unresolved feed helper, mixes the state, and emits one byte. Its output-byte
  arithmetic uses a multiply/shift/subtract sequence for reduction by 26 and
  adds `0x41`; this is consistent with uppercase aliases. The full hash-feed
  and allocation contracts remain unclosed, so no complete algorithm or
  particular input/output alias is claimed.
- The constructor checks the resulting **byte** length against 16, starts the
  same packer at index zero, and preserves both returned halves.
- The table-length observation is compared with `99,999` at `0x1449d8f`.
  An unsigned greater value skips the insertion route. Otherwise, the body
  acquires a separate lock and passes an owned input copy plus the packed pair
  to a table insertion helper. The packed result is returned on either route.

The table-length observation and later insertion do not occur under one
continuous lock in this body. **99,999 is an observed insertion-eligibility
comparison, not a proven concurrent cache-size cap or resource-safety bound.**
Lock fairness, races, allocation behavior, key equality and hash-feed semantics
require their own helper closure. This packet makes no runtime claim about them.

## Call and data closure

The complete `.text` decode observes four RIP-relative call sites through
constructor slot `0x576e798` (RELA addend `0x1449a80`):

| Call site | Containing decoded FDE |
| --- | --- |
| `0x13b604b` | `0x13b5df0..0x13b6530` |
| `0x13c64cb` | `0x13c6430..0x13c65e7` |
| `0x14bcf6a` | `0x14bcdb0..0x14bd3ed` |
| `0x358ead1` | `0x358ea60..0x358ed18` |

The retained caller bodies show pointer/length arguments and consumption of
the two result halves. For example, `0x13c64cb` loads a pointer/length pair,
calls the constructor slot, then saves `rax` and `rdx`. Their domain identities
are not assigned here. This census covers decoded direct/RIP-relative calls
and jumps to the selected addresses/slots; register-indirect, vtable and data
reference closure is not claimed.

The recorded packer references are the constructor's inline tail-jump
`0x1449af2`, its generated-form call `0x1449cd9`, and recursive call
`0x144a026`. The direct alias-producer call is `0x1449cb2`. Helpers for hash
feeding, hash-table operations, lock acquisition/release, allocation, formatting,
panic and unwind remain opaque. No captured machine code was executed or
transplanted into an implementation.

The separately retained `bcmp-relocation.txt` comes from this exact static
command (it is additional linkage evidence, outside the producer's ten exports):

```sh
readelf -rW artifacts/node/94/hl-node | grep '^000000000576e378 '
```

It resolves slot `0x576e378` as `R_X86_64_GLOB_DAT`, symbol index 11,
`bcmp@GLIBC_2.2.5`. The constructor loads that slot into `r8` at `0x1449b79`
and calls through `r8` at `0x1449be2`. This establishes the symbol binding;
the external library implementation itself is not closed or executed here.

## Validation and remaining work

Five focused tests include four real-target tests and a parser negative control.
Sixteen real instruction/data corruption subcases and three real RELA retargets
are rejected **below** the global input-hash check. They cover admission, index,
recursion, endian-shift/overflow controls, long-route counter/length/selection,
source attribution, and constructor/packer binding. Four actual caller-byte
sequences independently resolve to the constructor slot. These checks validate
the evidence collector; they are not execution tests of newly invented behavior.

See `validation.txt` for actual repository checks and repeated producer results.
All component gates remain false. No Rust component/workspace, native build,
runtime comparison, whole-alias equivalence, wire format, hosted CI or completion
credit is claimed. The next step before implementation is independently closing
the hash-feed/table and relevant consumer contracts; this packet alone cannot
establish a drop-in compact-string replacement.
