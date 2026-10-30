# RE-009-B: `/lt_hashes.json` writer byte format (node #94)

Target: `artifacts/node/94/hl-node`, sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This is static evidence only. The packet stands alone: it imports only `tools/bincode_varint.py` from main, and `independent_verify.py` imports nothing from `tools/`.

Related work, cited but not depended on:
- RE-009 (#262) covers the blake3 input of the neighbouring EVM DB hasher.
- #154 and #158 cover the earlier storage/state-root packets and the 0x32fc267 caller.

## What the bytes show

**Writer `0x32699c0..0x3269ad1`** (Location `l1/src/evm/hash.rs:69`, record `0x56dfb28`)
- Three `.text` rel32 callers: `0x326a2e0`, `0x326aff3` and `0x32fc267`. A full scan found no others.
- It builds the path with a fmt call at `0x3269a0f`. The template at `0x201e63` is `c0 0f` followed by the literal `/lt_hashes.json`.
- It copies three blocks of `0x810` bytes each, `0x1830` in total, using memcpy through r15:

  | Source | Destination |
  |---|---|
  | `rec+0xf8` | `rsp+0x30` |
  | `rec+0xa00` | `rsp+0x840` |
  | `rec+0x1308` | `rsp+0x1050` |

- At `0x3269a7b` it calls the save helper `0x3c16810` (its only caller) with that value, the path, and the Location.

**Save helper `0x3c16810`**
- If the path has length 9 and equals `/dev/null`, it returns 0 without encoding (`0x3c16834..0x3c16853`).
- Otherwise a path predicate decides the encoding. The predicate is called through slot `0x576f620`, which relocates to `0x144a3e0`. The two outcomes:

  | Predicate | Encoder | Config | Path |
  |---|---|---|---|
  | nonzero | MessagePack, `0x37e2510` | dword `0x1000400` at `0x3c1688e`; byte `+0xb` = `0x01` | struct-as-map: the map-header helper `0x35981d0` is chosen with `edx=3` |
  | zero | serde_json pretty, `0x37e21c0` | writer struct with indent `"  "` (`0x5b876a`, len 2) | — |

- The map-header helper `0x35981d0` emits `0x80|n`, `0xde` or `0xdf`. The other branch would use the array-header helper `0x3598e20`, which emits `0x90|n`, `0xdc` or `0xdd`.
- The serde_json encoder `0x37e21c0` carries the Locations `serde_json-1.0.120/src/ser.rs:660`, `:2004` and `:2014`. It stores `{` at `0x37e21fe` and `": "` at `0x37e2256`.
- After encoding, the helper calls two more path helpers, through slots `0x576ea68` → `0x144c180` and `0x576f670` → `0x144c560`.

**Both encoders write the same 3-field struct, in this order:**

| # | key (literal VA, len) | value offset in the 0x1830 value |
|---|---|---|
| 1 | `accounts_hash` (`0x59b249`, 13) | `+0x0` (from `rec+0xf8`) |
| 2 | `contracts_hash` (`0x59b256`, 14) | `+0x810` (from `rec+0xa00`) |
| 3 | `storage_hash` (`0x59b264`, 12) | `+0x1020` (from `rec+0x1308`) |

The key pool at `0x59b249` continues with `struct LtHash`.

In JSON form, the shape is therefore `{"accounts_hash": V, "contracts_hash": V, "storage_hash": V}`, with 2-space pretty indentation. The encoding of each `V` is not decoded here.

## What this does not claim
- **The branch for `/lt_hashes.json`.** It does not claim which branch actually runs for that path. The `0x144a3e0` predicate inspects `/`, `..` and `.` in the path, but its exact test is not decoded.
- **The path helpers.** It does not claim what `0x144c180` or `0x144c560` do. That they create or write the file is an inference.
- **Value encoding.** It does not claim how a single `0x810`-byte value is encoded, whether as an array, bytes or numbers. The internals of `0x37eb840` and `0x3815120` are not decoded.
- **Meaning of the buffers.** It does not claim what the buffers mean. Calling them an "LtHash" lattice-hash accumulator is an inference from the `struct LtHash` literal.
- **The error path.** It does not claim anything about the vtable call at `0x3269a8b`.
- **Runtime behaviour.** It does not claim anything about runtime behaviour, files on disk, or parity with other releases.

## Reproduce
```
python3 -I -B research/work-items/RE-009B-lt-hashes-format/verify.py
python3 -I -B research/work-items/RE-009B-lt-hashes-format/independent_verify.py
python3 -m unittest tests.test_lt_hashes_format -v
```
`lt-hashes-format.json` sha256 is `1d1a70e88fbfe5a08a9636e277394cc89e36bc189fcc1a532c628c894501e61e`. It is byte-identical under PYTHONHASHSEED 0, 7 and 99.
