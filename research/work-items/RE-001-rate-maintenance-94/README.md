# RE-001: guarded rate-limiter-associated maintenance and reset blocks, node #94

- Component `transport`; a bounded RE-001 boundary/xref question, not an
  implementation of a later transport task. No gate/prerequisite-completion claim.
- Node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115/visor claim.
- Independent main `6fb86319763b30860f92b9da746cbe4f9b637573`;
  reference `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Unlicensed `net_utils/rate_limiter.rs` is a lead, not copied implementation.
- Question: which byte guard reaches maintenance, what do the three visible
  reset blocks write, and is a complete TTL/admission decision established?

The actual caller only enters its maintained path when input byte+`0x20`
equals1. The other byte encodings branch directly to a return of that byte.
The enabled path calls a source-bound maintenance body before a shared-storage
lookup path. Three retained reset blocks fill control bytes with`0xff`, zero
count-shaped fields and recompute another metadata value using identical
integer instructions. These are concrete constraints on the reconstruction,
not evidence for an invented three-way admission enum or a recovered TTL rule.

## Reproduce

Linux, Python3.10+, authenticated project artifacts, unchanged reference pins,
GNU binutils. Recorded Ubuntu24.04/WSL2,Python3.12.3,GNU binutils2.42.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/rate_maintenance_static.py --output work/rate-maintenance-init-94
diff -ru research/work-items/RE-001-rate-maintenance-94/observed work/rate-maintenance-init-94
python3 -m unittest discover -s tests -p test_rate_maintenance_static.py -v
```

The collector authenticates the entire target, checks actual instruction/data
and RELA obligations and exact independently decoded readelf FDE extents.
Raw `objdump -d` output uses default AT&T syntax and linked ELF VAs. Only its
local input pathname is replaced. No operand normalization or equivalence mask;
binutils text rendering can vary, so bytes/body hashes are also retained.
No target/emulator/node service, network protocol or filesystem action is run.

## Exact scope and attribution

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Guarded caller | `0x4714c10..0x4714ffb` | `0x4713c10` | 1,003 |
| Maintenance | `0x4c8b860..0x4c8ba1c` | `0x4c8a860` | 444 |
| Iterator/helper | `0x4878c20..0x4879180` | `0x4877c20` | 1,376 |

Three exact FDE regions,2,823 bytes; not a whole-node denominator or three
reconstructed Rust functions. At`0x4c8b9ac`, the maintenance body references
source-location slot`0x5743150`, whose RELA addend is the embedded
`/home/ubuntu/hl/code_Mainnet/net_utils/src/rate_limiter.rs` at VA/file offset
`0x20252a`. This source association does not prove a particular Rust method
name. The iterator, lower table operations and generic types remain unclosed.

## Caller guard and shared lookup ordering

At`0x4714c21`, the caller loads byte`input+0x20`, compares with1, and jumps
to`0x4714f63` for any other encoding. That target moves the preserved byte to
`eax` and returns. The six tests check the encoded comparison/branch/return and
the partition of all256 byte encodings. No external construction invariants or
valid enum domain are inferred from arbitrary input bytes.

For byte1, the call at`0x4714c48` invokes the exact maintenance entry with the
second input pointer. The following retained code obtains timing-shaped
values, acquires a shared byte lock through slot`0x576eb60` (RELA addend
`0x577a838`), copies input bytes and traverses a string-comparison structure.
The search uses imported `memcmp` at slot`0x576e488`; raw readelf rows retain
the import identity. Its resulting state is passed to`0x4956d50`, followed by
callback slot`0x576efb0` (addend`0x14027b0`) and a release attempt.

This establishes ordering and call targets, not a complete admission result,
duplicate policy, time-unit conversion, latency-sampler contract or concurrency
guarantee. No TTL/expires-at comparison is claimed from a reference name.

## Three reset blocks and local integer formula

The maintenance body first calls iterator/helper`0x4878c20` when a selected
count is nonzero and conditionally releases returned temporary storage. It
then contains the following three visible reset blocks:

| Input-relative control pointer | Mask-shaped word | Zeroed count | Updated metadata |
| --- | --- | --- | --- |
| `0x118` | `0x120` | `0x130` | `0x128` |
| `0x160` | `0x168` | `0x178` | `0x170` |
| `0x190` | `0x198` | `0x1a8` | `0x1a0` |

When its count is nonzero and its mask-shaped word is nonzero, each block
passes the control pointer, byte value`0xff`, and mask+17 to imported `memset`
slot`0x576e1f8`. Raw readelf names `memset@GLIBC_2.2.5`. Each visible block
zeros its count and writes the formula result to the fourth column.

The instruction bytes at`0x4c8b914`,`0x4c8b970`,`0x4c8b9e4` are identical.
Within that integer fragment, with64-bit machine arithmetic:

- `word = mask+1`;
- `result = (word & ~7) - (word >> 3)`;
- if unsigned mask<8, select mask instead.

The zero-mask route selects zero directly. For selected power-of-two-minus-one
masks0,1,3,7,15,31,63,1023 the local results are0,1,3,7,14,28,56,896.
These are not allocation tests, proof of every valid mask, or recovery of the
complete table ABI. Overflow, capacity invariants and actual object validity
remain caller/helper obligations. The visible reset instructions do not
themselves rewrite the control-pointer/mask fields; **this is not a function-wide
allocation-lifetime guarantee**, because called helpers can have effects.

Between the second and third blocks, the body conditionally calls`0x471f8f0`
using input+`0x18` and the source-location record above. That helper is opaque
in this packet: no further file/configuration reload or timing contract is
claimed. Retaining the iterator body likewise does not close its lower hash,
lookup, allocation or element-processing contracts.

## Validation and limits

Six focused tests include20 real instruction/control mutations,3 actual RELA
retargets and source corruption below the whole-input digest gate, all256
guard-byte encodings and identical-formula checks across the three sites with
eight local integer cases. The models cover only the stated fragments.
See`validation.txt` for required checks and exact author-repeat results.

No Rust implementation/build, full rate-limit/TTL/ownership/layout recovery,
matching denominator, lower-helper/scheduler/concurrency closure, target
execution, runtime differential, chain/node traffic or hosted CI claim. No
imports/pins/generated progress/gates change. Next close the actual table and
caller/result contracts before implementing an admission policy; a source name
and these three retained bodies are insufficient to invent one.
