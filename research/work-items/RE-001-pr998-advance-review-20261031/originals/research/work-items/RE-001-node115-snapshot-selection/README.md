# RE-001: node #115 snapshot-associated selector and dispatch gates

- Component: info-server snapshot preparation; bounded control-flow mapping for RE-012, not a completed request/serialization path.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: which raw selectors and length/mode tests distinguish the explicit-selection, all-collection and outer-wrapper dispatch routes in the source-associated family?
- Observation: four measured worker bodies share an unsigned count threshold 101 on their explicit-selection route; their different all-collection route does not visit that comparison. Two measured wrappers normalize one input word to 0/1 and select the workers using a separate byte.
- Unknown: original request enum/field names, concrete asset set, whole API acceptance, serialization/output formats and file/network effects. This is not a protocol defect/security finding or implementation claim.

## Full measured family

Original ELF virtual addresses, half-open actual FDE ranges:

| Role | Start..end | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| worker 0 | `0x22b6490..0x22b6cc3` | 2,099 | 412 |
| worker 1 | `0x22b6cd0..0x22b7503` | 2,099 | 412 |
| worker 2 | `0x22b7510..0x22b7d43` | 2,099 | 412 |
| worker 3 | `0x22b7d50..0x22b8583` | 2,099 | 412 |
| wrapper 0 | `0x273bb10..0x273bd19` | 521 | 137 |
| wrapper 1 | `0x273bd20..0x273bf29` | 521 | 137 |
| selected exit helper | `0x2308120..0x23082ff` | 479 | 135 |

Denominator: **seven full FDE bodies, 9,917 bytes / 2,057 native instructions**. No clone is submitted separately. Retained full native exports, file offsets/body hashes, raw FDE/CIE records and independent readelf confirmations cover each actual entry through end. No byte normalization, Rust compilation or reconstructed-binary comparison is performed.

The actual relocated Locations `0x642cd18` and `0x642cd30` reference `info_server/src/save_l4_snapshots.rs:51:45` and `:51:80`. Native LEAs in the six source-associated wrapper/worker bodies bind this source association. This does not establish original function names. `spec.json` retains 124 direct calls, 84 RIP-relative bindings and six distinct relevant RELATIVE slots; its SHA-256 is pinned in the producer. Direct targets and source/import slots are checked individually, not hidden by a normalization mask. Indirect register/vtable calls and helper bodies remain unclosed.

## Inner raw selector and length gate

In each worker, incoming RSI points at the raw selector-shaped input. Its first qword is loaded, copied, and subjected to 64-bit NEG; **JNO** transfers to worker-relative `+0x474`. The sole input word with NEG signed overflow is `0x8000000000000000`, so:

- That word follows the observed all-collection preparation prefix.
- Every other raw u64 word follows the explicit-selection prefix.

These are raw bit-pattern facts, not recovered Option/Result/enum discriminants.

The explicit prefix loads a qword at input `+0x10`, compares it against sign-extended immediate **101**, then uses unsigned JAE to worker `+0x5da`. For valid input memory this is exactly count >=101. Counts 0..100 pass the local guard. They are **not** thereby proved to complete: the selected-collection helper and subsequent processing can fail or have additional constraints.

The >=101 arm skips the selected-collection helper, handles the observed input ownership, prepares raw raw exit word **0x158**, calls `0x2308120`, and exits the worker's measured normal route. Its whole error/public status representation and helper side effects are unknown. This packet calls it a limit-exit route, not an established returned HTTP error.

The all-collection prefix instead obtains its buffer/count from the context:

| Workers | Buffer field | Count field | End-pointer step |
| --- | --- | --- | --- |
| 0 / 2 | `+0x7c8` | `+0x7d0` | count * `0x510` |
| 1 / 3 | `+0x1338` | `+0x1340` | count * `0x510` |

It initializes a collection adapter and calls `0x23446c0` before the common processing loop. That prefix does not pass through the explicit input count comparison. This does **not** prove an unbounded valid collection, integer/pointer safety for arbitrary context contents, a total response cap, or a way to bypass an API policy. The stated relation assumes valid memory and normal helper returns; no real API request is issued.

For the other prefix the collection helper is `0x2c6fa00` in workers 0/2 and `0x2c6fdb0` in 1/3. Neither is interpreted as a complete asset lookup. The common loop and transformation/cleanup bodies are retained, but underlying 200-byte records, transformed records, ownership, and input booleans are not assigned book/price/order semantics here.

## Outer selectors and mode binding

Each wrapper first tests incoming **R8d** and normalizes it to a retained word 1 for nonzero, 0 for zero. This is a 32-bit input test, not a test of the full 64-bit R8. It separately compares the selector's first qword to a constructed **0x8000000000000001**, using MOVABS 0x8000000000000000 then INC. That special route builds a different collection adapter and calls one of two output helpers. It is distinct from the workers' 0x8000000000000000 all-collection marker; no concrete enum interpretation is inferred from the adjacent values.

For a nonspecial outer word, a separate input byte **`+0x1a`** selects the worker:

| Wrapper | Byte nonzero | Byte zero |
| --- | --- | --- |
| 0 | worker 0 | worker 2 |
| 1 | worker 3 | worker 1 |

The caller copies the input state into a temporary, passes the normalized mode in R8 and a callback address on the stack. Both wrapper records and the full native call sites retain the exact distinct callback LEAs; original callback/output format semantics are unproved. The wrappers' special route also branches on the normalized word to `0x26a4290` versus `0x26a4970`. Collection fields differ (`+0x970` versus `+0x14e0`) in the two wrappers; a concrete context layout is not recovered.

At each worker's later output-call boundary the received mode qword is compared to **exactly 1**, not simply nonzero. Normalized wrapper modes therefore line up with this gate. A separate direct caller passing another word would take the unequal route; whole-caller enumeration is not established.

| Workers | Mode ==1 call | Other mode call |
| --- | --- | --- |
| 0 / 3 | `0x26a5f70` | `0x26a5100` |
| 1 / 2 | `0x26a5890` | `0x26a6650` |

The relevant Locations select columns 80 and 45 respectively. Names such as JSON/binary/save/write are deliberately not assigned to these opaque calls. Allocation/drop/unwind branches and register-indirect returned-object calls are preserved in the full exports but do not constitute ownership or exceptional-effect closure.

## Reproduce and corruption controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From the repository root with materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/snapshot_selection_static.py --output work/snapshot-selection-check
# Compare generated output with this packet except README/spec/manifest.
python3 -B -m unittest discover -s tests -p test_snapshot_selection_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-snapshot-selection && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the full capture and retained spec before interpretation, output or native analysis. Native tools receive private byte-identical snapshots; full-body byte coverage and every recorded direct call/RIP binding instruction start are independently checked. Output is unnormalized UTF-8/LF. Wrong-release, same-size modified and truncated inputs are rejected before output creation.

Seven focused tests include the raw selector/NEG overflow relation, all count values 0..101 and u64 extremes, and three **actual operand** counterfactuals on all four workers:

- Comparison 101 ->102 changes count 101 from limit exit to explicit preparation.
- JNO ->JO flips which raw word takes the explicit route; the real 0x8000000000000000 case with count101 changes from all-collection to limit exit.
- Mode comparison 1 ->2 changes the normalized mode1 output selection.

Tests additionally corrupt actual branch displacements, context offsets/stride, raw exit tag, wrapper TEST/normalization/sentinel/byte selectors, every direct call displacement, selected actual RIP bindings, six relocation addends, both source metadata records, and all seven FDE extents. Counterfactuals are extracted branch equations, not target execution or an instruction emulator.

Before: main has no digest-bound #115 packet tying these two wrapper and four worker selection routes together. After: their raw gate/dispatch relations and actual call targets are reproducible as one bounded family. All original artifacts/source pins, unlicensed inferred reference code and progress gates are untouched. New tools/docs are independently authored under root MIT. No captured node/emulator, API endpoint, snapshot write, wallet, signing, chain action, hosted CI or runtime equivalence is claimed.

Next question: close one selected-collection helper and its output callback before assigning concrete request fields, asset membership or output/file effects.

## Correction: raw exit word 0x158 does not establish a diagnostic

The earlier packet named the >=101 branch a diagnostic route. That label went
beyond the measured caller. This revision uses **limit-exit route** / **raw exit
tag** and includes the full 479-byte helper FDE to resolve the selected path.
The value is not assigned a public error enum, response status or message.

For raw entry word 0x158, `0x2308124` zero-extends the input u16. The actual
selected path is:

1. CMP EAX,239 / JG at `0x230812c`: taken to `0x230815c`.
2. CMP EAX,351 / JG at `0x2308161`: not taken.
3. ADD EAX,-240 at `0x2308163`: the resulting u32 index is **104**.
4. CMP EAX,25 / unsigned JA at `0x230816b`: taken to `0x2308274`.
5. ADD RSP,8 / POP RBX / POP R14 / RET: normal epilogue.

All comparisons and transfers are operand/destination-checked. The zero-extended
u16 is below 2^31, so the first two signed JG comparisons have the stated
positive integer meaning. **This selected helper path executes no internal
call and no jump-table dispatch.** Therefore it supplies no evidence that the
call emits a diagnostic. The surrounding worker's preceding ownership helper
calls are not erased by this observation, and whole API behavior is still
unproved. Other helper tags, its jump-table entries, nested cleanup helpers and
exceptional behavior remain unclosed despite the retained full native body.

The seventh focused test checks the actual selected branch equation and
corrupts its real table-limit immediate from25 to104: the raw 0x158 case then
leaves the proved epilogue route for unclosed table dispatch. It also attacks
actual branch destinations and epilogue bytes. This is a static counterfactual;
no modified capture is executed and no alternate-tag behavior is invented.

Final validation for the selected-helper correction: **seven focused tests
passed in 19.268s**. `make doctor verify test catalogue-check` passed **438 tests
in 169.645s**; `make reproduce` passed. Packet manifest and staged whitespace
checks passed. This replaces the earlier six-body validation denominator.
