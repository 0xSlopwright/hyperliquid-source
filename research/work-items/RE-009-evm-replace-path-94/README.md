# RE-009: EVM account and code replacement into lattice accumulators

This packet shows how the account/code update path removes a prior value's contribution before adding the replacement, and how the code-value dispatcher decides whether to write a code entry and normalize its hash for the account entry.

- **Component ID:** storage / RE-009 (`l1/src/evm/evm_db.rs` consumers).
- **Target release and full SHA-256:** Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** repository `15f79350f790a04aed73b5fc9319f85b535f8282`; inferred can1357 tree `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- **Claim status:** observation for the pinned code, branches, table, calls and constants; inference for account/code roles, option meanings, and hash algorithm labels; unresolved for transactionality, durable writes, and caller-level error handling.
- **Scope included and excluded:** dispatcher `0x326aa40`, replacement routines `0x326a6f0` and `0x326abd0`, common accumulator addition `0x37ebb90`, and two contextual call sites in `0x3271680`. Referenced getters, serializers, and database write helpers are not reanalysed. No runtime execution or release other than #94.

## Reproduce

From repository root, with Python 3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/evm_replace_path.py --out research/work-items/RE-009-evm-replace-path-94
python3 -m unittest tests.test_evm_replace_path
(cd research/work-items/RE-009-evm-replace-path-94 && sha256sum -c MANIFEST.sha256)
```

The generator imports the repository's ELF and FDE parsers. It verifies the full input digest before analysis and emits `evidence.json` without invoking a disassembler or executing the binary. Fixed byte windows fail closed. Calls and branch displacements, relative relocations, table entries, constants and FDE extents are read from file-backed ELF sections. FDEs are unwind-described extents, not a complete function census. For human inspection GNU objdump 2.42 was used on bounded ranges; its text is not generator input. No masks or normalized byte comparisons are used.

## Evidence

All addresses below are ELF virtual addresses, endpoints exclusive. The evidence JSON retains the exact 22 instruction windows, 24 instruction-aligned calls, seven conditional branches, five relocation slots and all five FDE hashes. These are selected sites, not a whole-program call census.

| Role inferred from existing key-schema evidence | FDE | Observed body size |
| --- | --- | ---: |
| code replacement | `0x326a6f0..0x326aa38` | 840 |
| dispatcher | `0x326aa40..0x326abc1` | 385 |
| account replacement | `0x326abd0..0x326aebc` | 748 |
| contextual caller, not fully analysed | `0x3271680..0x3272188` | 2824 |
| common addition helper | `0x37ebb90..0x37ebda1` | 529 |

**Dispatcher.** At `0x326aa54`, an input qword indexes a signed relative jump table based at `0x581f44`. The five inspected entries for tags 0 through 4 target `0x326aa67`, `0x326aa7a`, `0x326aa6d`, `0x326aa67`, and `0x326ab08` respectively. Tags 0 and 3 load length from input `+0x18`; tag 2 obtains it through the pointer at `+0x08`, offset `+0xd8`; tag 1 loads the two values at `+0x30` and `+0x18`, branching to a non-returning failure path at `0x326ab92` if the former is unsigned-greater. The five-entry domain is a working interpretation; the dispatch itself contains no bounds check in this window, so behaviour for other tags is not claimed.

When the selected length is zero, control goes directly to `0x326ab08`, bypassing the code replacement call. A nonzero length compares the 32 bytes at input `+0x68` to `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`; if equal it calls the slot at `0x5773278` and stores its 32-byte result back to that field before calling through slot `0x5775550`. Separately, if those 32 bytes are all zero, `0x326ab24` copies that same constant to the field. The constant is consistent with Keccak-256 of the empty string; the meaning of the preceding callee is inferred, not established here. Finally `0x326ab73` calls slot `0x5775560` with the 20-byte key and the constructed account value. `.rela.dyn` resolves the slots to `0x326a6f0` and `0x326abd0`, respectively. The tag-4 branch skips the code-length and code-replacement block; the normal account call remains. The unwind cleanup path is present; this does not prove rollback of earlier changes.

**Replacement.** The first routine calls the previously mapped code getter with `self+0x928` and a 32-byte key. Its result discriminant equal to 4 bypasses old-value removal. The second calls the account getter with `self+0x20` and a 20-byte key; its result discriminant unequal to 1 bypasses old-value removal. On the removal arms, both encode the old entry through their respective existing entry builders, subtract one from the count and the encoded length from the byte counter, with unsigned underflow clamped to zero. Counter offsets are `self+0x1200/+0x1208` for code and `self+0x8f8/+0x900` for account. Both call the previously identified BLAKE3-related slots and request `0x800` output bytes. Their loops subtract 1024 big-endian 16-bit words modulo 65536 from accumulators at `self+0xa00` and `self+0xf8`, respectively. The `rol`/subtract/`rol` and word stores are retained in the exact windows.

On both paths, the routine then calls the same entry builder for the supplied new value, passes the resulting buffer and its accumulator to `0x37ebb90`, and calls its mapped database writer: `0x37d2000` for code, `0x37d15e0` for account. The common helper increments the count at accumulator `+0x800` and adds the entry length to `+0x808`, each saturating at `u64::MAX`; its `0x37ebd10` loop adds 1024 big-endian u16 words modulo 65536. The direct call and relocation edges and fixed instruction windows are recorded in JSON. `0x3271680` also calls the two routines in code-then-account order at `0x327199b` and `0x32719ac`; its entry conditions and remaining body are outside this packet.

**Relationship to prior work.** `RE-009-evm-kv-schema-94` maps the getters and writers and their keys; `RE-009-C-lthash-mechanism-94` maps a different set of addition leaves. This packet focuses on the previously unrecorded update functions and the old-value removal/addition ordering. Names, persistence and the complete hash preimage depend on those prior analyses and remain qualified here.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, build, byte comparison, masks and helper/data closure: not yet measured. No captured node, network, keys or chain fixture was used. Tests check the ELF digest, FDEs, dispatch and branch targets, relocation resolution, and reject corrupted instructions, a corrupted table, a wrong digest, invalid instruction shapes and out-of-range/NOBITS mappings. These are static parser controls, not differential execution or proof of storage success.

## Results and limitations

The generator records four analysed routines and two call sites in one additional FDE; it does not enumerate all callers. It resolves the observed replacement path through old-value branch, counter/lattice removal, new-value addition and writer calls, without determining the writers' failure semantics, database batch atomicity, encoded preimage or full state root. No completion gate is requested. Next question: trace the enclosing commit path's writer result and failure propagation to establish whether these accumulator changes are rolled back on a failed batch.
