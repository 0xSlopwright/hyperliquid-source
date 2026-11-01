# RE-004: perp asset price option scaling and display

This packet identifies how a perp asset's decimal byte selects an exact integer price divisor and a complementary floating display divisor, including the option bypass and failure order, so a reconstruction can preserve the two distinct conversion rules.

- Component ID: RE-004 (assets and fixed-point quantities).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `15f79350f790a04aed73b5fc9319f85b535f8282`; can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead.
- Claim status: observations and manual instruction lifts below; type names and the common price-unit interpretation are inferences; no runtime equivalence claim.
- Scope included and excluded: two FDE-bounded copies of the option conversion and one two-word display converter, their internal branches, constants and failure locations. Their callers and the contents of external failure handlers are excluded. These functions share metadata and scaling constants; a call between them or common provenance of their input values is not established. Node #115 and visor are excluded.

## Reproduce

From the repository root, using Python 3.12.3 and the standard library, with the authenticated node #94 present:

```sh
python3 tools/artifacts.py verify
python3 tools/perp_price_option_scale.py --out research/work-items/RE-004-perp-price-option-scale-94
python3 -m unittest tests.test_perp_price_option_scale
(cd research/work-items/RE-004-perp-price-option-scale-94 && sha256sum -c MANIFEST.sha256)
```

The generator imports the repository's `elf_index` and `fde_extents` parsers, validates the complete input digest and reads file-backed sections only. It does not invoke a disassembler, run the target, read the clock, or use the network. The byte records are `evidence.json`, `branches.tsv`, `decimal-cases.tsv`, `boundary-cases.tsv`, `control-cases.tsv`, `control-traces.tsv`, and `display-cases.tsv`. The byte-pattern census is a search, not a complete function census. For optional human inspection only, GNU objdump 2.42 was used:

```sh
objdump -d -M intel --start-address=0x232e2e0 --stop-address=0x232e41e artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2396c00 --stop-address=0x2396d49 artifacts/node/94/hl-node
```

## Evidence

All addresses are ELF virtual addresses; file offsets and FDE record addresses are in `evidence.json`. The option functions are `0x232e2e0..0x232e41e` and `0x49e4ca0..0x49e4dde`, each 318 bytes. The display function is `0x2396c00..0x2396d49`, 329 bytes. The `.eh_frame` FDEs bound these ranges; an FDE alone does not establish all possible entries. The copies differ at 16 bytes, all in four RIP-relative displacement fields; the two location addresses and two indirect-call slots resolve identically. The full raw bytes and hashes are retained. The five-byte error-tag pattern has six raw `.text` hits, three in each option copy; this is not a completeness claim for equivalent code.

The option function takes an input record at `rsi`, an asset key at `rdx`, and a metadata pointer at `rcx`. It writes a result through `rdi`. In the table below, `tag` is input byte `+9`, `x` is input word `+0`, and `d` is the byte at `+0x2a` of a 48-byte metadata row.

| Ordered decision | Observed result |
| --- | --- |
| `tag == 2` | Return word `0x0186`; write input byte `+0` to output `+8`, incoming `rcx` to output `+9`, and tag to output `+17`. No metadata read occurs in this arm. The meaning of the forwarded word remains unresolved. |
| Otherwise, `key / 10000 != [rcx+0x30]` | Call slot `0x576e470` with Location `l1/src/perp_meta.rs:194:38`. |
| Otherwise, `key % 10000 >= [rcx+0x10]` | Same failure slot and Location. |
| Otherwise, `d >= 7` | Call slot `0x576e150` with Location `l1/src/perp_meta.rs:319:28`. |
| Otherwise | Build `s = 10^(d+2)`; if `x < s` or `x % s != 0`, write error word `0x0065`; otherwise write word `0x0186` and `x/s` into the output payload, retaining input byte `+8` and the tag. |

The quotient/remainder operation uses a 32-bit `div` only if `(x | s) < 2^32`; otherwise it uses a 64-bit `div`. Since every admitted `s` is positive, neither form divides by zero. Both reject zero and nonmultiples rather than round them. On success the quotient occupies output bytes `+8..+15`, input byte `+8` becomes output byte `+16`, and tag becomes byte `+17`. The result word alone is written on the ordinary error path; the remaining output bytes are not characterized there.

The index split uses `m = 0x346dc5d63886594b` and the high half of `key*m` shifted right 11. The generator verifies `10000*m - 2^75 = 432` and `(2^64-1)*432 < 2^75`. Writing `key = 10000*q+r`, `0 <= r < 10000`, these bounds show that this quotient equals `floor(key/10000)` for every u64 key. The subtraction then gives the exact remainder. The seven admitted byte values select the following divisors; all other byte values take the failure above.

| `d` | Integer divisor | Display divisor |
| ---: | ---: | ---: |
| 0 | 100 | 1,000,000 |
| 1 | 1,000 | 100,000 |
| 2 | 10,000 | 10,000 |
| 3 | 100,000 | 1,000 |
| 4 | 1,000,000 | 100 |
| 5 | 10,000,000 | 10 |
| 6 | 100,000,000 | 1 |

The display function loads two u64 words at input `rsi+0` and `rsi+8`, and an asset key at `rdx+0xb0`. Each zero word independently yields positive zero without a metadata lookup. A nonzero word triggers the same group, row and decimal tests and the same two failure Locations. It uses packed integer-to-double conversion followed by `divsd` with the binary64 table at `0x3e0e90`, indexed by `6-d`. `evidence.json` retains the seven table bit patterns and both 16-byte packed conversion constants. The computation is binary floating point; integer inputs above 2^53 can lose precision, and division can round. The display cases assume the usual IEEE-754 round-to-nearest mode, not a verified runtime floating-point environment.

The generator checks 256 decimal byte values against a manually lifted ladder and runs a separate concrete block walker along encoded branch displacements: 682 walks across the two copies, including 77 boundary inputs per copy, all decimal bytes and eight controls. Its per-control paths are retained. The walker uses manually lifted block operations and the original opcode hash, not a general x86 decoder or execution of the capture. The 32/64-bit selection and quotient/remainder identities cover all u64 values mathematically **conditional on that lift**; the 682 walks are not an exhaustive differential test against the target. `display-cases.tsv` has 70 sample binary64 results from a separate hand lift, not target execution.

### Inferences and reference comparison

The two location paths and the metadata row make a perp asset decimal interpretation plausible. The integer and display divisors multiply to 10^8 for every admitted `d`; this supports a common 10^8 price envelope if the two independently supplied words represent the same quantity. The shared factor alone does not prove that correspondence. The inferred reference's `wire_decimals` describes a six-decimal perp envelope, consistent with the display divisor, but does not establish this option layout, its bypass, its exact-divisibility error, or the binary's failure order.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No build, byte comparison, relocation normalization, helper-closure result, or behavioral execution is claimed. The two copy comparisons above are original-to-original with only the four specified RIP displacement fields identified; no bytes are counted as a rebuilt match. The tests include a damaged input digest, a changed target instruction, a changed branch destination, a changed ladder factor, a damaged floating table, out-of-range inputs and file-backed VA checks.

## Results and limitations

18 targeted unit tests pass without skips, including with a PATH containing only Python; the generator records 38 branch instructions over three FDE ranges, 256 decimal bytes, 682 concrete block walks and 70 floating samples. All 682 block-walker outcomes agree with the separate closed-form lift; neither is a target run. The two regeneration outputs match byte for byte under different hash seeds and time zones. Artifact verification passes. Catalogue checking fails in the linked-binary workspace because its byte-evidence reader rejects external symlink targets; it passes in an isolated copy with the same authenticated #94 and #115 files materialized inside that copy.

No progress gate is requested. Calling contexts, the bypass word's type, display rounding mode, exceptional handler effects, independently built Rust and end-to-end reconstruction remain unresolved. The open asset-row scaling contribution is described only by its title and file list in the supplied context, so its function-address overlap still requires verification before submission. Next question: identify a non-overlapping caller that proves which option variant supplies `tag == 2` and whether the integer and floating words describe the same unit.
