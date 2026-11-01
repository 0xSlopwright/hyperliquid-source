# RE-004: tagged perp price scaling and its rejection paths

Node #94 can reconstruct the two tagged perp price conversion helpers as exact division by `10^(2 + size_decimals)`, with a nonzero/divisibility gate and a distinct tag-2 bypass before metadata validation.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `15f79350f790a04aed73b5fc9319f85b535f8282`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: byte sequences, FDEs, branch destinations and constants are observations; price/size-decimal names are inferences; the bypass variant's meaning is unresolved.
- Scope included and excluded: the complete two unwind-described code ranges and their local branches; the calculation and output representation. The callers, allocation validity, panic-helper implementation, parsing, downstream order checks, other copies, execution and #115 are excluded.

## Reproduce

From the repository root, Linux x86-64, Python 3.12.3; standard library plus the repository's `tools/elf_index.py` and `tools/fde_extents.py`. No target execution, network, or binutils is needed for generation. The generator checks the complete input digest before analysis and uses file-backed sections only. The local text `.text` scan searches the exact 40-byte prefix, which is a byte-pattern census, not a census of all equivalent implementations.

```sh
python3 tools/artifacts.py verify
python3 tools/perp_order_price_scale.py --out research/work-items/RE-004-perp-order-price-scale-94
python3 -m unittest tests.test_perp_order_price_scale
(cd research/work-items/RE-004-perp-order-price-scale-94 && sha256sum -c MANIFEST.sha256)
```

Generated files are `copies.tsv`, `branches.tsv`, `decimal-bytes.tsv`, `locations.tsv`, `function-bytes.txt`, `vectors.tsv` and `evidence.json`. The full function hashes, file offsets, FDE record VAs and input digest are recorded there. `MANIFEST.sha256` covers this README and every generated file.

## Evidence

All addresses below are node #94 ELF virtual addresses. The FDE-described extents are `0x232e2e0..0x232e41e` and `0x49e4ca0..0x49e4dde` (318 bytes each); FDEs describe unwind ranges and are not, alone, proof of every callable entry. Both start at the same fixed 40-byte instruction prefix; these are the only two prefix occurrences in `.text`. Their raw body hashes differ. Masking precisely four 4-byte RIP displacements at offsets `0x127`, `0x12d`, `0x134`, `0x13a` makes the bodies equal. Resolving all four displacements shows that each copy names the same two location records and two indirect call slots. This equality does not establish relocation, helper, caller or whole-ELF identity.

Observed entry registers are `rdi` = result pointer, `rsi` = pointer to a tagged input, `rdx` = u64 identifier, and `rcx` = metadata pointer. For tag other than 2 the input contains a u64 at `+0`, a byte at `+8`, and a tag byte at `+9`. The result writes status as a u16 at `+0`; on successful conversion the quotient is at `+8`, input `+8` is copied to output `+0x10`, and the tag to output `+0x11`. The remainder of each result is outside the claim.

| Order | Observed condition | Result |
| --- | --- | --- |
| 1 | input tag equals 2 | status `0x186`; input byte `+0` and tag copied; metadata and numeric conversion are bypassed |
| 2 | `asset / 10000 != [metadata+0x30]`, or `asset % 10000 >= [metadata+0x10]` | indirect non-returning error at location `perp_meta.rs:194:38` |
| 3 | byte at `[[metadata+8] + 48*(asset % 10000) + 0x2a] >= 7` | indirect non-returning error at location `perp_meta.rs:319:28` |
| 4 | otherwise let `scale = 10^(2 + byte)`, `x = input.u64` | reject as status `0x65` if `x < scale` or `x % scale != 0`; else status `0x186` and `x / scale` |

The tag-2 path also writes the current `rcx` into bytes beginning at result `+9`. Its semantic payload and whether those bytes are live are unknown; no claim is made that this branch copies an entire input value. In the other branch the quotient is nonzero, at most `u64::MAX`, and computed with either 32-bit or 64-bit unsigned `div` based on `(x | scale) >> 32`. The selected width does not change quotient or remainder. This is exact division, not floor rounding of nonmultiples; the error path writes status only and does not promise initialized payload bytes.

The asset quotient uses the multiplier `0x346dc5d63886594b`, takes the high half of the 64-by-64 product and shifts it by 11. For any u64 `asset`, writing `asset = q*10000+r` with `0 <= r < 10000`, let `M` be the extracted multiplier and `delta = 10000*M - 2^75`. The generator checks `0 <= delta < 10000` and `floor((2^64-1)/10000)*delta + 9999*M < 2^75`. Therefore the computed quotient equals `floor(asset/10000)` for the whole u64 domain. The seven valid decimal values and all 249 rejected byte values appear in `decimal-bytes.tsv`; their ladder factors are extracted from actual immediate bytes. This proves the stated integer identities assuming the listed instruction interpretation; it does not execute the binary or validate pointer safety.

A human-readable excerpt for the first copy (not an input to generation):

```text
232e33d  cmp    eax,0x7
232e340  jae    232e411
232e3a4  mov    rax,rcx
232e3a7  or     rax,rsi
232e3aa  shr    rax,0x20
232e3ae  je     232e3c4
232e3b5  div    rsi
232e3bd  cmp    rsi,rcx
232e3c0  jbe    232e3d4
232e3d4  test   rdx,rdx
232e3d7  jne    232e382
```

The status `0x65` is identified as invalid price by the existing spot wire scaling evidence, and the metadata field at `+0x2a` as size decimals by the existing tick-ladder evidence. These interpretations and the proposed "perp price" name are inferences from those independently documented observations, not symbols recovered from this function. The inferred reference's `wire_decimals` suggests `6 - size_decimals` for perps; the observed divisor converts an 8-decimal raw integer into that precision. No reference code was copied.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, lockfile, build flags, two-build comparison, raw/normalized compiled-code comparison, and helper/data/relocation closure: not yet measured. The four masked bytes are used solely to compare the two target bodies, not to claim source equivalence.

The generator uses a small arithmetic model tied to hashed function bytes and extracted constants, plus a separate division-based oracle. It does not interpret all machine instructions and does not run machine code. The vector table is a check on the model and boundary cases, not an independent target execution. Tests include wrong digest, altered instruction even when the digest check is bypassed, out-of-range and NOBITS address, invalid branch, guard precedence, zero, exact and inexact division, decimal boundaries, and a damaged reciprocal.

## Results and limitations

- Two FDE ranges, two exact-prefix occurrences, 318 bytes per range; four 4-byte RIP operands differ but resolve pairwise to the same targets.
- All 256 decimal bytes are classified (7 valid and 249 panic); the asset reciprocal identity holds for all u64 values under the arithmetic proof above.
- `vectors.tsv` contains 586 model cases and zero model/oracle mismatches, covering all 256 tags and decimal bytes plus quotient and rejection boundaries. The model and oracle are not independent execution evidence.
- Tag semantics, initialization of other result bytes, malformed pointers, indirect call behavior, callers and all other candidate copies are not established. There is no execution or Rust comparison and no full-component gate is requested.

Next question: recover the producer of the tagged ten-byte input and establish which tag-2 fields are semantically live, using a non-overlapping caller or a separately authorized offline harness.
