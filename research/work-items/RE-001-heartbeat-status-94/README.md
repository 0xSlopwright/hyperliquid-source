# RE-001: one node #94 heartbeat status query

- Component: `node-runtime`; bounded static function validation under RE-001,
  which has no prerequisites. This is not completion of RE-001 or RE-008.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Neither #115 nor visor is covered.
- Repository base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its leading EMA/heartbeat comments supplied a question, not implementation.
- Question: what does the shared unresolved `0x4726a50` seed actually decide,
  and how does its observed caller use its four result tags?

The reference associates this address with an unresolved heartbeat/base EMA
helper. The actual function is a key lookup and classification path,
with a ratio, flag, and floating helper-result threshold. No direct EMA update
is present in the inspected body; opaque callees remain unresolved. This narrows
the seed attribution; it does not prove
that EMA updates are absent elsewhere. No imported source was copied into
implementation, and no reconstructed Rust or component gate is claimed.

## Reproduce

Use Linux, Python 3.10+, GNU binutils (`readelf`, `objdump`), and the normal
verified pinned submodules/LFS inputs from `scripts/setup.sh`. That script
also installs Rust toolchains, which this Python-only packet does not need.
No npm/REA/Ghidra installation is needed. The captured executable is only read
as data; no command below launches it or contacts a node or chain.

```sh
make doctor
make verify test catalogue-check reproduce
python3 tools/heartbeat_status.py --output work/heartbeat-status-94
diff -ru research/work-items/RE-001-heartbeat-status-94/observed work/heartbeat-status-94
python3 -m unittest discover -s tests -p test_heartbeat_status.py -v
```

The tool authenticates the complete input before analysis, checks the decoded
FDE ranges, streams the complete `.text` disassembly for direct callers, and
checks critical instruction bytes, data, and relocation targets. It preserves
raw bounded disassembly and relevant readelf rows, replacing only the local
binary pathname in objdump's header. It does not normalize operands or claim
body equivalence. The observations are reproducible with GNU binutils 2.42
and Python 3.12.3 on Ubuntu 24.04/WSL2. Other binutils versions may change the
text rendering; compare machine records and bytes as well as text.

## Observations

`observed/records.json` retains hashes, coordinates, instruction controls,
and relocations. `observed/frames.txt` records independently decoded readelf
FDEs, not next-index upper bounds:

| Role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Status query | `0x4726a50..0x4726d2c` | `0x4725a50` | 732 |
| Observed consumer | `0x4876f90..0x48774b0` | `0x4875f90` | 1,312 |
| Floating elapsed helper | `0x1447130..0x14472a0` | `0x1446130` | 368 |

The target has 121,299 decoded FDE records. This packet studies **one** status
function, one consumer, and one immediate helper; it does not validate a
121,299-function denominator. FDE extents are unwind regions, not a claim of
complete function ownership or CFG recovery.

The status body traverses a tree using `memcmp(..., 20)` at `0x4726ad1`.
The linked dynamic symbol for slot `0x576e488` is `memcmp@GLIBC_2.2.5`.
On a found record, it loads two doubles at record-relative offsets 0 and 8:

The floating descriptions below interpret the decoded branches as IEEE binary64
with DAZ disabled and SIMD exceptions masked. MXCSR configuration and live input
reachability are not established here. In particular, `UCOMISD` on a signaling
NaN can trap with invalid exceptions unmasked; these are static branch semantics,
not a claim that every listed floating value reaches a runtime result.

1. Denominator `+8` equal to either signed zero yields ratio 0 without division.
   A nonzero denominator must compare strictly above zero; negative values and
   unordered comparisons take the assertion path. The bytes at VA/file offset
   `0x21a843` say `assertion failed: self.denom > 0.`.
2. A positive denominator is used in `numerator / denominator` at `0x4726b59`.
3. The ratio is compared with a double at config `+0x18`. An ordered greater
   ratio and a zero config flag byte at `+0x20` return tag 2. A less/equal or
   unordered ratio, or a nonzero flag, proceeds to the helper call.
4. The helper result in `xmm0` is compared against the double **180.0** at
   VA/file offset `0x20acd8`. Ordered greater returns tag 1 plus that double;
   less/equal or unordered returns tag 3. No-key returns tag 0.

| Condition | Observed result tag at output `+0x18` |
| --- | ---: |
| Key absent | 0 |
| Ordered ratio above config threshold and flag byte zero | 2 |
| Other found-key path, helper result ordered above 180.0 | 1 |
| Other found-key path, helper result at/below 180.0 or unordered | 3 |

Both decoded direct calls (`0x4876fd9`, `0x487734c`) belong to the same
consumer FDE. At `0x4876fe3` and `0x4877359` that consumer skips tag 3 and
continues iteration. The complete `.text` decoder produced exactly these
two direct calls to this address. Indirect references/callers are not ruled
out by that census.

The status query contains a RIP-relative reference to the exact embedded
`/home/ubuntu/hl/code_Mainnet/node/src/consensus/heartbeat_tracker.rs` at
VA/file offset `0x6fb82a`. That supports a heartbeat association independently
of the imported EMA label. It does not recover the source function name.

## Calls, data, and limits

Relevant relocations are retained in `observed/relocations.txt`:

- Comparator slot `0x576e488`: external `memcmp` (GLOB_DAT).
- Slot `0x576e8c0`: internal helper `0x1447130`, called at `0x4726c81`.
- Slot `0x576e978`: `0x143d010`, used by two diagnostic paths.
- Slot `0x576e108`: `0x157b7f0`, used by the denominator assertion.
- The elapsed helper's slot `0x576eaa0`: `0x151d1b0`.

The helper compares two timestamp-shaped triples, forms an integer using
`1,000,000` scaling, and divides its floating conversion by `1,000,000.0`.
Its negative/order/error paths can return zero and invoke diagnostics. The
leaf at `0x151d1b0` and diagnostic/panic callees are **not** closed here.
Consequently the packet keeps **180.0 as a numeric observation**: calling it
180 seconds, or naming tags healthy/stale/jailed, remains an inference until
timestamp units and producer state are independently established. Likewise,
the ratio is not established as an EMA update, nor is its concrete layout a
recovered Rust struct. No runtime behavior, chain safety, native build,
cross-release equivalence, full call closure, or progress gate is claimed.

## Controls and result

Four tests cover the packet: three use the authenticated target and one checks
decoded caller-line parsing. Twelve real-target subcases corrupt
the lookup length, ordered/unordered denominator control, division, threshold
branch, flag branch, output tag, 180.0 data, source path, helper scale, or
consumer filter. These call the local evidence checks **below** the global
SHA gate, demonstrating that relevant evidence changes are rejected, rather
than merely demonstrating a checksum mismatch. Another test retargets the
actual elapsed-helper RELA record and requires rejection. Caller parsing
also rejects address mentions and indirect-call comments as direct callers.
These are static evidence controls, not execution tests of the classifier.

All component gates remain false. The next bounded question is the producer
and units of the two doubles and timestamp triple, including closure of
`0x151d1b0`, before assigning human status names or implementing behavior.
