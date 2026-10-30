# foundation-millis-94: saturated product to millisecond calendar fields

- Component: `foundation`, bounded time-conversion mapping from its first task.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its time-related labels were search leads; no reference implementation was copied.
- Status: observed instructions/edges and exact integer identities; source-level
  names, units of the input fields, types and calendar semantics remain inferred.
- Included: one 323-byte conversion window and its 76-byte error formatter,
  unsigned reciprocal-division certificates, and static overflow/error routing.
- Excluded: execution, reconstructed Rust, full calendar helper, other callers,
  all #115 addresses, source equivalence and any component completion gate.

## Problem and result

The component map calls for target-grounded mapping of time conversions. A
reference method name or error string does not establish the actual arithmetic,
widths, overflow policy or failure path. This packet connects the string to its
formatter and one actual caller, decodes both complete FDE windows, and proves
the caller's three reciprocal divisions over their entire integer domains.

This is separate from PR #12's hour extraction window at `0x14509f0`. No window
here overlaps that packet. The FDEs are narrow retained records checked against
LLVM, not another general decoder competing with RE-001 (#2/#5). No functions
or code from those PRs are needed. The five raw direct-call candidates found
while locating the formatter are **not** counted as validated functions; only
one conversion caller is included here.

## Reproduce

From the repository root, with pinned LFS inputs and submodules materialized:

```sh
make doctor
make verify test catalogue-check
make reproduce
python3 tools/foundation_millis.py --check research/work-items/foundation-millis-94/evidence.json
python3 tools/foundation_millis.py --objdump /path/to/llvm-objdump > work/millis-fresh.json
cmp work/millis-fresh.json research/work-items/foundation-millis-94/evidence.json
```

This run used macOS 26.2 arm64, Python 3.12.14, Apple LLVM 21.0.0 and GnuPG
2.5.24. Tools were isolated under `/private/tmp`; PATH began with
`/private/tmp/hype-analysis-tools/bin:/private/tmp/slop-python-verify/bin`,
`TMPDIR=/private/tmp`, and LLVM was at
`/Library/Developer/CommandLineTools/usr/bin/llvm-objdump`.
The submitted checker/tests need Python's standard library only. Exploratory
FDE lookup used pyelftools 0.32; it is not a runtime dependency of this change.

Raw exports, with no execution of the target:

```sh
llvm-objdump -d --start-address=0x13c8e10 --stop-address=0x13c8f53 artifacts/node/94/hl-node
llvm-objdump -d --start-address=0x14509a0 --stop-address=0x14509ec artifacts/node/94/hl-node
llvm-objdump --dwarf=frames artifacts/node/94/hl-node > work/node94-frames.txt
```

`conversion.objdump.txt` and `error_formatter.objdump.txt` retain the complete
first two outputs. `frames.txt` retains the full two FDE blocks selected from
the third output. `records.json` retains the raw FDE/CIE records, body hashes
and relative slots. `MANIFEST.sha256` covers the exact packet file hashes.
The checker authenticates the complete target before reading any evidence.
`--objdump` reruns the decoder and compares all bytes and contiguous addresses
rather than relying on the saved text.

The baseline's 20 tests, doctor, input/import verification and catalogue checks
pass. The change has 29 passing tests. Required verification, reproduction,
packet regeneration and fresh LLVM checks pass. GPG uses an isolated temporary
home; in this environment its sandbox restriction required the verification
command outside that sandbox. No personal keys were read. Doctor reports
static analysis ready, exact rebuild not ready. No Rust/Java/Ghidra build or
hosted CI success is claimed by these local results.

## Observed windows, coordinates and edges

All addresses are ELF VAs, without runtime rebasing. The checker maps through
the section table; `.text` here has file offset = VA minus `0x1000`.

| Window | FDE section offset | ELF VA interval, end excluded | Bytes / instructions |
| --- | --- | --- | --- |
| conversion candidate | `0x2e46bc` | `0x13c8e10..0x13c8f53` | 323 / 78 |
| error formatter | `0xace0` | `0x14509a0..0x14509ec` | 76 / 20 |

LLVM frame exports independently agree with the ranges. Continuous full-range
linear disassembly validates the listed instruction boundaries and byte
coverage, not a complete CFG or a global function census. There is an actual
call at `0x13c8ef3` to the formatter's FDE start `0x14509a0`.
At `0x14509ba`, RIP-relative LEA resolves to `0x1e1152`; the next byte begins
`from_unix_millis: out-of-range input `. This is a formatting-data reference,
not a claim that a C string begins at the referenced byte.

### Product and decomposition

At `0x13c8e1e`, the code loads the u64 at input-pointer offset 8 and multiplies
it by the u64 at offset 0 using unsigned `mulq`. Its overflow branch at
`0x13c8e25` goes to `0x13c8f2d`, sets `r14` to `0xffffffffffffffff` and returns
to the common path at `0x13c8e2e`. Otherwise `r14` receives the low product.
Thus the common arithmetic input is `m = min(a*b, 2**64-1)`, rather than a
wrapping product. The fields' source-level names and units are unknown.

The code computes these unsigned quantities:

| Quantity | Observed operation | Integer identity |
| --- | --- | --- |
| seconds | high64(`(m >> 3) * 0x20c49ba5e353f7cf`) >> 4 | `m // 1000` |
| days | high64(`(m >> 10) * 0x31b5d43afe99ef`) >> 6 | `m // 86400000` |
| days from seconds | high64(`seconds * 0x308b91419ca253`) >> 6 | `seconds // 86400` |
| nanoseconds | low32(`m - low32(seconds*1000)`) * 1000000 | `(m % 1000) * 1000000` |
| seconds within day | seconds minus `(days from seconds)*86400` | `seconds % 86400` |

For the nanosecond calculation, low-32-bit subtraction preserves the true
remainder modulo `2**32`, and the true remainder is below 1000. Scaling it
by 1,000,000 also fits u32. The two day quotients agree by nested integer
division. These are identities of the observed arithmetic, not executed
behavior or a recovered implementation.

### Preliminary gate and unresolved calendar call

The first range test computes `(days - 2146764485) mod 2**64` and compares
it unsigned against `2**64 - 2**32`. For nonnegative `days` in the actual u64
millisecond-derived domain, the continuation is exactly
`0 <= days <= 2146764484`. It then adds 719163 in a 32-bit register, so the
largest continued value becomes `2147483647`.

The next call uses slot `0x576e890`, whose `R_X86_64_RELATIVE` addend is
`0x151f6f0`. A zero `eax` also goes to the error arm. This helper's calendar
semantics and additional rejection range are **unresolved**; passing the first
gate does not establish conversion success. Source names such as Chrono,
NaiveDate or `from_num_days_from_ce` are not assigned to it by this packet.
The successful-path register dataflow assumes ordinary preservation of the
callee-saved registers across this call; its transitive closure is not proven.

On the continuation after a nonzero helper result, stores at `0x13c8ec0` onward
assemble the helper's 32-bit result, seconds-within-day and nanoseconds, then
copy those 12 bytes to the output pointer. Calling this an exact datetime ABI
would need independent layout and helper evidence.

Both preliminary rejection and zero-helper-result paths reach `0x13c8eeb`,
which passes a pointer to the original saturated millisecond value to the
formatter. The caller checks a 32-bit value against 1 after the call and has
an unwrap-style error arm. Its result/option enum meaning, formatter allocation,
unwinding and generic error callees are not recovered here. The output checker
also records formatter slot `0x576e040 -> 0x1344760`, without assigning ownership.

## Finite division proof and controls

For each reciprocal, let `n=q*d+r`, `C*d=2**k+e`, with `e>=0`. Then

`floor(n*C / 2**k) = q + floor((q*e+r*C) / 2**k)`.

For a fixed remainder `r`, the fractional numerator increases with `q`.
Checking it at `q=floor((N-r)/d)` proves the identity for every allowed `q`.
The checker enumerates **all** remainder classes: 125, 84,375 and 86,400,
respectively, with N derived from the actual input bounds/preshifts. Each
maximum is strictly below `2**k`; `e` values are 19, 62,201 and 27,776.
The certificates and exact numerators are in `evidence.json`. No random
sampling or assumption that a familiar magic number is correct is used.

Tests independently compare ordinary division at every remainder class's
largest input, reject a smaller reciprocal and either adjacent shift, and
check millisecond/day transitions plus `u64::MAX`. Real-target controls reject
#115, truncation, mutated instruction constants/saturation bytes, an altered
error string, FDE/CIE changes, a retargeted relative slot and off-by-one,
byte-corrupted or truncated disassembly. Structural controls bypass only the
digest gate in tests so downstream checks are actually exercised. The CLI
always checks size and full SHA-256 first.

## Results and limitations

The explicit denominator is **two retained FDE windows**, 399 bytes and 98
instructions. It is not all time helpers or all references to the formatter.
Their complete retained bytes match fresh LLVM decoding. No raw/normalized
Rust-body comparison, reconstructed Cargo component, runtime differential
result or whole-ELF identity was implemented or measured. No normalization
mask or byte transplantation is used. Raw target evidence retains original
rights; new checker/tests/docs are independently authored.

**No gate requested:** all Foundation gates and generated progress stay false
and unchanged. Next question: establish the input fields' units and the exact
accepted domain/return encoding of `0x151f6f0`, including its own helpers and
private-versus-library ownership, before reconstructing a Rust conversion.
