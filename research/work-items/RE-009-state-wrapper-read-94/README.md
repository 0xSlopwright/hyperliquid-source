# RE-009: state wrapper read path

Node #94's state wrapper reader accepts a one-element sequence as well as an `exchange`-keyed map, and distinguishes missing and duplicate map fields, enabling a reconstruction to preserve these outer-container decisions before implementing the inner state value.

- Component ID: RE-009, storage/state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `15f79350f790a04aed73b5fc9319f85b535f8282`; unlicensed can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was used as a lead only.
- Claim status: static observations and bounded control-flow inferences; not a complete decoder or compatibility claim.
- Scope included and excluded: two outer decoder copies and their distinct file/buffer entry paths; inner value, unknown-value helper, JSON decoding, complete MessagePack grammar, writes, other releases, runtime reachability and execution excluded.

## Reproduce

From the repository root, Python 3 standard library and the shared `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/state_wrapper_read.py --out work/state-wrapper-read-94
python3 -m unittest tests.test_state_wrapper_read
cmp work/state-wrapper-read-94/records.json research/work-items/RE-009-state-wrapper-read-94/records.json
```

No external programs are invoked by the generator or tests, and the capture is never executed. The input SHA-256 is checked before parsing. `records.json` is deterministic across `PYTHONHASHSEED=7,99`, `TZ=UTC,Pacific/Honolulu`, with no binutils on PATH. All addresses below and in the record are ELF virtual addresses; FDE endpoints are exclusive. No operand masks are used.

## Evidence

The FDE-described extents are `0x1799b10..0x179afb3` and `0x405b970..0x405ce13`, each 5,283 bytes. Their entry functions are `0x28e96b0..0x28e9d72` and `0x432fe50..0x432ff6f`: the first reaches the first decoder at `0x28e9bac`, the second reaches the other at `0x432fea7`. The former has case-folded comparisons against `r`, `m`, `p` before its byte-buffer route; its selected path copies 0x1fc8 bytes on the non-2 result. The latter also copies 0x1fc8 bytes on the non-2 result and writes tag 2 on its error route. The two entry contexts are distinct: this does not prove that the buffer wrapper is called by the file loader.

The decoder copies contain five corresponding signed relative dispatch-table spans: 225, 18, 225, 18 and 32 entries. The generator checks that every selected table entry lands in its own FDE extent and that all 518 corresponding offsets agree. The 225-entry spans are bounded by adjacent table starts; the 18-entry spans correspond to the explicit compare with 17, and the last span is the selected 0xc0..0xdf range. These are table spans, not a census of reachable tags or proof that every entry is a valid instruction boundary.

For the map path, the first copy initializes a local slot to tag 2 at `0x1799f35`, then checks its field count. The key checks at `0x179a1d0..0x179a213` compare length eight and the eight literal bytes `exchange`; an alternate eight-byte compare uses the same bytes at `0x20a468`. When the key is unequal, control reaches the helper call at `0x179a2c6`; its full behavior is not established. For a matching key, the slot test at `0x179a65f` chooses the child call at `0x179a67a` when the slot has tag 2 and the duplicate diagnostic route at `0x179ad4c` otherwise. At end of the map, tag 2 routes to the missing-field diagnostic at `0x179a703`. The format templates include `missing field` and `duplicate field`, with the same eight-byte key supplied as an argument. A short two-byte length branches to the input-exhaustion path, which sets remaining length to zero; other truncation states are not fully characterized.

For the sequence path, `0x179a8f8` tests the count: zero goes to an error-construction helper, nonzero calls the same child decoder at `0x179a90d`. After a non-2 child result, `0x179aa22` compares the count with one: equality selects the 0x1fc8-byte copy, while inequality constructs tag 2 and cleans up. This establishes the outer decision conditional on the child result, not that an arbitrary payload succeeds. The second copy has the same relative branch sites and dispatch-table offsets, independently checked from ELF bytes; all per-copy sites and target addresses are in `records.json`.

Inference: the matching key and diagnostic templates describe a required `exchange` field, and the calls are the reader's map/sequence alternatives for the same nested value. This follows the observed data flow and MessagePack marker paths; no Rust type identity is proven. The test's changed keys are synthetic classifier controls, not executions of the target or complete encoded fixtures.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No compiled comparison, fixture execution, normalization, call-target identity, vtable closure, or native behavior measurement is claimed. Seven focused unittest methods check both copy extents and table populations, branches, actual key compares, changed key bytes, malformed identity, corrupted compare opcode and conditional branch, damaged table bytes, wrong call opcode and out-of-range VAs. The corruption tests are static controls and do not establish full decoder behavior.

## Results and limitations

Two independently located 5,283-byte FDE ranges and two entry ranges were recorded. Five paired table spans agree at 518/518 selected target offsets; this is not a whole-function identity measurement. The selected map and sequence decisions are bounded observations, not a snapshot format or cross-version compatibility guarantee. The child decoder, ignored-key helper, malformed nested values, trailing bytes, all other serialization modes, and real fixture behavior remain unresolved. No milestone gate is requested. Next question: recover the child value schema and its error propagation using a non-overlapping decoder function, then validate complete synthetic fixtures in an authorized offline harness.
