# RE-009 — Storage and ABCI-state ownership (node #94)

Target: `artifacts/node/94/hl-node`, sha256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Produced by `tools/state_roots.py` (stdlib only, deterministic). Every address
is a virtual address. Function bounds come from `.eh_frame_hdr` FDEs (end
exclusive). The decoder ties a function to a source file only when a
RIP-relative `lea` inside the function points at a first-party panic `Location`
record. A record is an `R_X86_64_RELATIVE` slot in `.data.rel.ro` holding a
`/home/ubuntu/hl/code_Mainnet/<file>.rs` pointer, followed by len, line and
col. Literal ownership works the same way: a `lea` points at the literal or at
the start of its Rust format template, which is the byte after the preceding
NUL.

Depends on RE-005 (PR #10, `re-005-bincode-varint`) only in prose. The
branch is not based on it and imports nothing from it.

## Files

| File | What |
|---|---|
| `state-roots.json` | Full decoder output: Locations, functions, literals, `/dev/null` compares, reconstruction address statuses |
| `fixture-schema.json` | Small snapshot fixture schema (`re009-snapshot-fixture/v1`), every entry citing referencing functions |
| `objdump-excerpts.txt` | Narrow `objdump -d -M intel` windows for the `/dev/null` compares and every literal `lea` site |
| `verify.py` | Re-checks the manifest, regenerates both JSON files, and checks 11 pinned facts |
| `MANIFEST.sha256` | sha256 of the packet files |

## Findings (measured)

1. **Scoped Locations: 57.** Out of 1186 first-party Location records in the
   binary, 57 come from `db/src/*` or `l1/src/abci/state.rs`:
   - `l1/src/abci/state.rs`: 28;
   - `db/src/db_home.rs`: 13;
   - `db/src/db_hub.rs`: 7;
   - `db/src/owned_db_home.rs`: 3;
   - `db/src/block_reader.rs`: 2;
   - `db/src/dh.rs`: 2;
   - `db/src/rocks_db.rs`: 2.

   46 functions reference them. The FDE count is 121299.
2. **Reconstruction addresses.** The reconstruction gives 20 `.text`
   addresses:
   - All 17 in `l1/abci/state.rs` are FDE starts whose function references
     its own `state.rs` Location.
   - The 3 in `db/block_reader.rs` (0x27b6540, 0x27bbe50, 0x27c1710) are FDE
     starts, but none references a `block_reader.rs` Location. The functions
     that do are 0x27abee0 (line 45) and 0x27ae600 (line 27).
3. **Unseeded `state.rs` functions.** Three `state.rs` functions are not in
   the reconstruction. They carry the same line sets as seeded ones:
   - 0x28127a0 (line 145), like 0x46cea60 and 0x46cfe90;
   - 0x2811e40 (line 154), like 0x46cf030;
   - 0x28122a0 (lines 188/190), like 0x46cf490 and 0x46cf990.
4. **Snapshot artifact names and their owners.**
   - `/CHECKPOINT_COMPLETE`: db_home.rs line 23 functions 0x28d1650, 0x332e0a0
     and 0x459a7f0. A second template (`/CHECKPOINT_COMPLETE_…`, anchor
     0x1f2f3e) is used by 0x15867a0, which has no first-party Location.
   - `/lt_hashes.json`: three functions:
     - 0x332d440 (db_home.rs lines 301–332);
     - 0x32699c0 (`l1/src/evm/hash.rs` line 69);
     - 0x3269ae0 (`l1/src/evm/evm_db.rs` line 154).

     Reading and writing the LtHash file therefore spans db_home and the EVM
     hash/db modules.
   - `@@ linked abci state @@` log template: `state.rs` lines 196/203
     functions 0x2208e60, 0x446da60 and 0x446e050.
   - Debug dumps ending `.rmp`. None of them sits in a `db/*` or `state.rs`
     function:
     - `/tmp/abci_state_bad_app_hash.rmp`: `l1/src/abci/engine.rs` +
       `exchange.rs` functions 0x2209d40, 0x42e4600 and 0x42e5d40;
     - `/tmp/abci_state_with_l1_hash_mismatch.rmp`: node gossip/evm_kvs
       functions 0x22615b0, 0x4356c90 and 0x4b29760, plus 0x473c930, which
       has no first-party Location;
     - `/tmp/abci_checkpoint.rmp` and `/tmp/abci_checkpoint_evm_db`: 0x4b2fda0,
       which has no first-party Location.
   - `periodic_abci_states`: referenced only by a RELATIVE relocation slot. No
     code `lea` points at it.
5. **`/dev/null` guard.** Two `state.rs` line-145 functions compare a 9-byte
   path to `/dev/null` inline: 0x46cea60 at 0x46ceaef and 0x46cfe90 at
   0x46cff1f. The sequence is `cmp r12,9` → `movabs rax,"/dev/nul"` → xor
   with `[r15]` → 9th byte `xor rcx,0x6c` → `je`. This is the "/dev/null
   skip" that the reconstruction describes for the exchange dump wrappers
   (0x46CEA60/0x46CFE90). The unseeded line-145 twin 0x28127a0 contains no
   such `movabs` immediate.
6. **Hashing ownership: negative result.**
   - blake3-1.7.0, tiny-keccak-2.0.2 and sha2 Locations sit only in
     functions with no first-party Location.
   - A rel32 `call` scan found no edge at depth 1 or 2 from the 47
     first-party storage/state/EVM-hash functions to those hash-crate
     functions. The 47 were found during exploration and are not part of the
     tool output.
   - The binary has no `state_root` string.

## Fixture schema (summary)

`fixture-schema.json` lists 8 named artifacts. For each it gives the role, the
functions that reference it, and the first-party files those functions own:

- `CHECKPOINT_COMPLETE` marker → db_home.rs;
- `lt_hashes.json` → db_home.rs + evm/hash.rs + evm/evm_db.rs;
- linked ABCI state log → state.rs;
- four `/tmp/abci_*` dump paths;
- `periodic_abci_states`.

It also lists the two `/dev/null` guard functions. It is a fixture *shape*:
names, owners and evidence. It contains no file contents or encodings.

## Rerun

```
sudo -u pumpdev -H bash -lc 'source ~/.pumpenv; cd ~/hl-re009-wt && \
  P=research/work-items/RE-009-storage-state-roots && \
  python3 -B tools/state_roots.py --out $P/state-roots.json --schema-out $P/fixture-schema.json && \
  python3 -I -B $P/verify.py && python3 -O -B $P/verify.py && \
  python3 -B -m unittest tests.test_state_roots'
```

## What this does not claim

- Which hash algorithm computes the LtHash, the app hash or any state root.
  No hash-crate function is reachable from the scoped functions within two
  direct calls. Dispatch through vtables or closures was not traced.
- The byte format of any snapshot file. That covers whether `lt_hashes.json`
  is JSON or a MessagePack state file, field order, versioning, and the
  reconstruction's `.rmp`-vs-JSON branch. No `rmp`/`json` immediates exist in
  the scoped functions, and the `.rmp` template `\xc0\x01/\xc0\x01/\xc0\x04.rmp`
  is used only by 0x37eac50, which has no first-party Location.
- What happens after the `/dev/null` compare succeeds. Only the compare and
  its `je` target are shown.
- That the `/tmp/*.rmp` paths are written in production. They are referenced
  addresses only.
- What the reconstruction's seed functions do semantically, or its
  constants (0x810, 0x3ae8, 0x1fb8 and the db_hub masks). Only FDE starts and
  Location ownership are checked.
- Any snapshot compatibility *between versions*. Only node #94 was examined.
