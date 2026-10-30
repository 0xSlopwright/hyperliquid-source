# RE-001: C-guard value comparison and the conditional counter route, node #94

- Component `foundation`; one bounded RE-001 boundary/xref question, no
  prerequisites; no component gates change.
- Node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes; no #115/visor claim.
- Independent main base `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  unlicensed `base/c_guard.rs` is a lead, not copied implementation or trusted
  semantics. All tool/test code here was authored from target bytes.
- Question: what does the configuration comparator inspect, and is the local
  count limit an unconditional call count or a pre-store saturation bound?

The observed comparator checks four scalar fields and three nullable,
length/content-based regions. It does not compare the complete raw structure
blob. A caller comparison-success branch bypasses the counter update. On the
route that does update it, the incremented value is stored **before** comparing
the old value against100. Those distinctions matter before implementing value
equality, reassertion or count-limit behavior. They do not establish a complete
C-guard API, log system, concurrency contract or reachable production failure.

## Reproduce

Linux, Python3.10+, authenticated project inputs/unchanged references, GNU
binutils. Recorded Ubuntu24.04/WSL2, Python3.12.3, GNU binutils2.42.

```sh
make doctor verify test catalogue-check reproduce
python3 tools/cguard_consistency_static.py --output work/cguard-init-94
diff -ru research/work-items/RE-001-cguard-consistency-94/observed work/cguard-init-94
python3 -m unittest discover -s tests -p test_cguard_consistency_static.py -v
```

Full input identity is checked first. Exact FDE extents come from `readelf -wf`;
RELA bindings are parsed and raw `readelf -rW` rows retained. `objdump -d` uses
default AT&T syntax and linked ELF VAs. Only its local input pathname is
replaced; no instruction/body normalization is performed. Different binutils
rendering is possible; exact bytes/body hashes are retained. No captured node,
emulator or supervisor was executed; no model, chain or networked-node calls.

## Exact scope and attribution

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Configuration path | `0x143a570..0x143ae6c` | `0x1439570` | 2,300 |
| Value comparator | `0x1445830..0x144594e` | `0x1444830` | 286 |
| Handle construction | `0x13e4ce0..0x13e4e3b` | `0x13e3ce0` | 347 |

Three exact unwind regions,2,933 bytes; not three reconstructed Rust functions
or a matching denominator. Four source-location RELA records at `0x566a1c8`,
`0x566a1e0`, `0x566a1f8`, `0x566a210` point to
`/home/ubuntu/hl/code_Mainnet/base/src/c_guard.rs` at VA/file offset `0x2019e9`.
Their references are within the configuration body's failure paths. Slot
`0x576f4f0` resolves to shared storage `0x577aba0`. The body uses its leading
byte in atomic compare/exchange operations. Names/layouts above are inferred
roles, not recovered original symbols, Rust types or complete mutex semantics.

## Defaults and comparison are value-shaped, not raw-blob equality

The input's first64-bit word is compared with `0x8000000000000001`. That
encoded route constructs local defaults: three words at relative offsets
0,`0x18`,`0x30` are `0x8000000000000000`; relative DWORD`0x48` is10;
byte`0x4c` is derived from whether byte`0x577ab70` equals2; bytes`0x4d/0x4e`
are0/1. Other input encodings copy the existing80-byte region to local storage.
This does not establish an Option/CGuard ABI or a particular build-mode enum.

The comparator first checks fields in this order:

| Relative field | Width | Mismatch target |
| --- | ---: | --- |
| `0x4c` | 1 | `0x14458ab` |
| `0x4d` | 1 | `0x14458ab` |
| `0x48` | 4 | `0x14458ab` |
| `0x4e` | 1 | `0x14458ab` |

That target returns zero. The remaining body handles three regions beginning
at offsets0,`0x18`,`0x30`. Their sentinel is `0x8000000000000000`; present
routes compare lengths at`0x10/0x28/0x40` and call the actual `bcmp` import on
pointers from`0x08/0x20/0x38`. Raw readelf slot`0x576e378` names
`bcmp@GLIBC_2.2.5`. Calls are at`0x14458d9`,`0x144590e`,`0x1445935`.

For valid present objects, pointer addresses and storage-capacity words are
not themselves compared for identity; they feed the observed length/content
operations or sentinel decision. This is incompatible with replacing this
body by bytewise comparison of the whole copied blob. Buffer validity,
allocator/ownership, external bcmp implementation and all invalid encodings
remain outside this packet; no complete Rust equality implementation is claimed.

## Conditional update and the old-value threshold

The caller at`0x143a9cf` invokes this comparator with local data and shared
storage+8. Its nonzero result branches to`0x143ab57`, bypassing the counter
update at`0x143ab2b`. Therefore the retained body does not support interpreting
that field as an unconditional count of every entry to this function.

On the update route, the old value is in`rcx` and storage offset is`+0x58`:

1. Compare old value with`u64::MAX`; equality takes a separate failure arm
   before the new store.
2. Compute old+1 and store it at shared storage+`0x58`.
3. Compare the **old** value with100; unsigned greater-or-equal takes another
   failure arm. Old99 stores100 before continuing; old100 stores101 before
   that failure branch. This is not a saturating counter or a proof that101
   can never exist in memory.

These are local instruction-order facts, not observed panic recovery or live
reachability. Earlier configuration/state checks, helper unwinding and global
invariants may prevent a concrete call from reaching this route. The body also
contains the actual atomic release operation; complete poison/fairness,
initialization, exceptional-path and thread-safety guarantees remain unclosed.

## Validation and limits

Six tests authenticate the real input and exercise14 instruction mutations,
seven RELA retargets, source bytes and four independently decoded scalar
field/branch sequences. The counter test checks actual store/comparison order
and five boundary cases in an explicitly local architectural model; it neither
executes the target nor simulates the complete function. Local corruption checks
run below the whole-input digest gate. Exact results are in`validation.txt`.

No Rust build/implementation, raw/normalized matching denominator, caller-wide
counter guarantee, full logging/handle/nullable-field ABI, runtime comparison or
hosted CI result. No imports/pins/generated progress/gates change. Next close
the shared-state invariants and construction/destruction helpers before a
replacement is implemented; the three retained extents are not a complete
configuration system.
