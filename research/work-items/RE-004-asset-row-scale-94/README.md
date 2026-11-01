# RE-004: asset-row quantity conversion and its serialization-shaped record in node #94

This packet establishes that a node #94 asset-row converter forms two displayed quantities by rounding each u64 to binary64 before division by the asset's decimal scale, so a reconstruction can preserve that loss of precision and the zero/invalid-asset behavior instead of assuming exact integer decimal arithmetic.

- Component ID: assets / RE-004, quantities and rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `391fe838467760eefc04072c0ea762a7a1155c78`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was used only to identify possible quantity and TWAP terms, not copied.
- Claim status: observation for the pinned bytes, operands, control flow, power table, field-key accesses and exact integer lemmas; inference for field names on the produced record and for the quantity units; unresolved items below.
- Scope included and excluded: one allocation-to-row conversion path, its zero and invalid-id branches, the conversion of three words, and a separate serializer with a matching record layout. The serializer's ownership connection to the allocated vector, formatting helper bodies, the external rounding helper, and #115 are excluded.

## Reproduce

From the repository root, on Linux x86-64 with Python 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/asset_row_scale.py --out research/work-items/RE-004-asset-row-scale-94
python3 -m unittest tests.test_asset_row_scale
(cd research/work-items/RE-004-asset-row-scale-94 && sha256sum -c MANIFEST.sha256)
```

The generator checks the full binary SHA-256 before parsing, imports `tools/elf_index.py` and `tools/fde_extents.py`, reads only file-backed sections, and never executes the artifact or invokes a disassembler. Output is `evidence.json` and `vectors.json`. The manifest records hashes of those files and this README. This analysis completed; it is restricted to the stated path and selected scale entries. For a human-readable instruction check, GNU objdump 2.42 was used as follows; its text is not a generator input or output:

```sh
objdump -d -M intel --start-address=0x23118b0 --stop-address=0x2311bdc artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2a3deb0 --stop-address=0x2a3e0f6 artifacts/node/94/hl-node
```

## Evidence

Addresses below are node #94 ELF virtual addresses; file offsets and complete function bytes are in `evidence.json`. The four unique FDE extents are `0x25670c0..0x2567241` (allocator), `0x26b2530..0x26b2724` (collector), `0x23118b0..0x2311bdc` (converter), and `0x2a3deb0..0x2a3e0f6` (serializer). FDEs describe unwind ranges and do not alone prove complete source-level boundaries.

### Allocation and collector

The allocator multiplies a source count by 96 and compares the count with `floor((2^63-1)/96)` before allocating. A larger count reaches an allocation failure call; zero bytes use an aligned non-null placeholder. It passes an output vector to the collector at `0x256718a`, then returns its three vector words. Allocation and growth helpers are edges, not reconstructed here.

The collector repeatedly calls an iterator. A null row or a row byte at offset `+0x22` equal to 2 ends the conversion loop; these are two termination conditions, not an assertion about the iterator's meaning. For each other row it copies the row fields, calls the converter at `0x26b2637`, copies the resulting 0x58-byte record after an eight-byte prefix into an output slot, and advances by 0x60 bytes. The cleanup loop is present for termination and unwinding. Iterator and cleanup semantics are not resolved.

### Asset selection and two scaled u64 words

At converter entry, `rsi` points to the input, `rdx` to metadata and `rdi` to the output. Let `id = input[+0]`, `x = input[+8]`, and `y = input[+0x28]` be u64 words. The code computes the quotient and remainder of `id / 10000`. The quotient must equal metadata `+0x30`, and the remainder must be less than the row count at `+0x10`. The reciprocal multiply immediate and shift are in `evidence.json`; the tool proves that the quotient expression equals integer division for every u64 input by bounding the reciprocal excess.

| Asset lookup | `x` | `y` | Observed path |
| --- | --- | --- | --- |
| invalid | 0 | 0 | skip row and name lookup, set both scaled results to positive zero, continue |
| invalid | any | any | if either word is nonzero, branch to the unwrap panic call |
| valid | 0 | 0 | clone the row name, set both scaled results to positive zero, do not read the exponent table |
| valid | nonzero | 0 | compute the first scaled result; set the second to positive zero |
| valid | 0 | nonzero | set the first to positive zero; compute the second scaled result |
| valid | nonzero | nonzero | compute both scaled results independently |

The valid row is at `metadata[+8] + 48 * remainder`. Its name pointer and length are cloned. Its byte `+0x2a` selects a divisor from a table at `0x3c1a80`; both conversion sites refer to that same table. There is no local range check on that byte before the indexed read. For the seven inspected table entries, `e = 0..6`, the stored binary64 words are exactly `10^e`; `power_table` records each byte sequence. This packet does not claim the input byte is limited to that range, or that out-of-range table access is safe.

The unpack/subtract/add instruction sequence first constructs the high and low 32-bit parts of each u64 as exact binary64 values, adds them, then performs a scalar division by the selected binary64 word. Assuming the usual round-to-nearest-even SSE environment, for `e = 0..6` the results are

```text
out[+0x18] = RN64(RN64(x) / 10^e)
out[+0x20] = RN64(RN64(y) / 10^e)
```

The same u64 conversion followed by division by the binary64 constant 1,000,000 produces `out[+0x28]` from `input[+0x30]`. This word is converted even on the invalid-id, zero-quantity path. This is a reading of the pinned instructions, not an execution of the binary. The two 32-bit components are each exactly representable, so their correctly rounded sum is the correctly rounded u64 conversion for all u64 values; the following divide has its own rounding. The caller's MXCSR state is not established here.

`vectors.json` independently calculates 77 sample results using exact rational arithmetic with binary64 ties-to-even, including the input conversion and division separately. It is a model of the observed instruction sequence, not a target execution. For example, at exponent 0, `2^53` and `2^53 + 1` both produce binary64 bits `4340000000000000`; they collide before division. The same input pair also gives identical modeled results at exponents 3 and 6. The largest u64 rounds to `2^64` in the first stage. Exact decimal fixed-point output would therefore be observably different for these modeled inputs.

### Additional output and error edge

The converter multiplies input `+0x10` by the binary64 value 1000 and calls the relocated slot `0x576f6d8`. The callee is an external edge: its rounding rule is not re-established here. The returned value is filtered for non-finite values, clamped to the u64 range, converted to u64 and divided by 60000 before being stored at output `+0x30`. `evidence.json` proves the final reciprocal quotient for the full u64 domain: `(n >> 5) / 1875` is `n / 60000`. This conversion is described only from the helper return onward; input units and the helper's full behavior remain open.

Allocation failure can occur while cloning a nonempty name. The invalid-id panic depends on the two quantity words as shown above; it is not a general refusal of every invalid id. Other calls and failure behavior are not modeled.

### Serializer with matching offsets

The independently located serializer reads the following record offsets, key bytes and helper calls in order (`serializer_fields` in `evidence.json`); each of the ten calls tests its result and reaches the same error block on failure:

| Offset | Key |
| --- | --- |
| 0 | `coin` |
| 0x40 | `user` |
| 0x54 | `side` |
| 0x18 | `sz` |
| 0x20 | `executedSz` |
| 0x28 | `executedNtl` |
| 0x30 | `minutes` |
| 0x55 | `reduceOnly` |
| 0x56 | `randomize` |
| 0x38 | `timestamp` |

The three scaled output offsets and the other copied fields match this serializer's layout. It is therefore plausible that the first two u64s are size and executed size and the third is executed notional. This is an inference: the object handoff between the collector's vector and this serializer has not been traced. The serializer's value formatting helpers and its final output are not evaluated.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo.lock, compiler and linker flags, two-build comparison, normalized masks, helper closure and target byte identity: not yet measured. The rational model does not execute x86 and is not evidence of reconstructed Rust equivalence. No captured binary or service was run.

The test suite includes changed-hash, changed-instruction, changed-power-table and changed-key controls; missing file-backed and NOBITS address controls; a damaged reciprocal multiplier; and input-range failures. It compares the rational model against host binary64 on boundary values and 700 deterministic sampled u64/scale pairs. The reciprocal lemmas are integer inequalities over their whole stated domains, not sample tests.

## Results and limitations

Four FDE extents and two direct call edges are pinned; ten serializer key/offset pairs and their error destinations are byte-read; seven scale words and 77 model vectors are generated. Nine unit tests pass with zero skips. The serializer and conversion only have a matching layout, not a traced ownership edge; the input domains, name and time semantics, helper behavior, and actual SSE control state remain unproved. The sample vectors do not prove reachability of large quantities in live state. No component progress gate is requested.

Next question: trace the collector's vector into the serializer and identify the validation that bounds the exponent byte and the two quantity words.
