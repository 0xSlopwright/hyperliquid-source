# RE-004: UsdClassTransfer in node #94: amount text, gates, the shared perp and spot move, its notional word and the event

This packet shows that a class transfer amount is a real decimal parse rounded half even to six places (extra digits are never refused), that the shared move `0x270f6f0` has three modes in which one raw unit is 100 spot wei, and that it also writes `total_net_deposit` and a per-user row word, so a reconstruction can drop the reference's digit parser and its user-path amount cap and write the move as one function used by all 39 callers.

- Component ID: RE-004 (quantities and rounding), perp and spot USDC conversion
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / reference `references/can1357-hl`, `l1/exchange/handlers/51_usd_class_transfer.rs` and `59_system_usd_class_transfer.rs`, used as a lead only
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the signed handler `0x1e60850` with copies `0x46bb840`, `0x46bb610`, the system handler `0x1e64530` with copies `0x4c03850`, `0x4c03760`, the apply wrapper `0x2717cf0` with copies `0x4d0fac0`, `0x4d0fca0`, the move `0x270f6f0` with copies `0x46e89a0` and `0x46e8290` (the last splits its first half into `0x46e93e0`), the amount field parser `0x3980a60` and the split collector `0x3bafa30`. Earlier packets stub the move or list it in caller and recorder tables (`RE-004-qty-recorder-lines-94`, `RE-004-spot-balance-ledger-94`, `system-buy` and `withdraw-fee` packets); none evaluates its body, and the handlers carry at most inventory rows. Run real as edges and not claimed: the text searcher `0x1579c90`, the split step `0x3bc9510`, the trim `0x337e6c0`, the address reader `0x1444a00`, the decimal parser `0x3799510`, the scaler `0x3750350` (`RE-004-decimal-scaled-u64-94`) and rust_decimal helpers. Stubs that check their arguments: margin rows `0x36f57f0`, margin sum `0x37d79e0`, withdrawable `0x36f7560`, row debit `0x370a3d0`, row credit `0x36ff4f0`, spot rows `0x371b3a0`, hold `0x371b140`, ledger `0x371d120`, one-whole price `0x375fb50`, recorder `0x358dcd0`, sub-account check `0x2714f80` and copies, user row `0x2755400` and copies, `0x1f849b0` and copy, stamp `0x3987cb0`, event sinks, status drops, address error builders. Excluded: what those callees do

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/usd_class_transfer.py --out research/work-items/RE-004-usd-class-transfer-94
python3 -m unittest tests.test_usd_class_transfer
cd research/work-items/RE-004-usd-class-transfer-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took about 3 minutes with one other run beside it on this server.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 951 named cases and 400 random cases run real rows; a separately written rule list predicts results, every callee event with its arguments, the two written words, the user word, the error block and every other fixture byte, and that no block is left unfreed. Subject code is 2916 instructions in 12909 bytes.

### The move, `0x270f6f0(out, S, dex, user, mode, amount)`

`callers.tsv` lists 39 direct call sites. `mode` is 0, 1 or 2 at 36 of them and comes from a register at the three apply wrappers, where it is `to_perp ^ 1`.

| Mode | Direction | Amount | Gate |
| --- | --- | --- | --- |
| 0 | spot to perp | argument, top bit panics | `wei + held <= total` in the spot row of token `dex+0x50`, else 0xf7 |
| 1 | perp to spot | argument, top bit panics | withdrawable `0x36f7560 >= amount`, else 0x33 |
| 2 | perp to spot | `value - used` from `0x37d79e0` (mode 2), saturating; argument ignored | none |

Order of the body:

1. `dex >= S+0x5c8` panics. Row is `S+0x5c0 + dex*0x2f0`; token is `dex+0x50`.
2. User found in the tree at `S+0x8d0` (20-byte key, value 0xb0): refused with 0x15 unless token is 0 and value byte `+0xaf` is not 0.
3. Amount as above, `base = max(amount, 0)`, `wei = base * 100` in `u64`; overflow is 0xf7.
4. Gate of the mode. A missing spot row or token counts as total 0, held 0. `wei + held` overflow is 0xf7.
5. `amount <= 0` returns OK with no effect.
6. Notional `n`: `f64(base) * dex+0x2a0` (`usdc_ntl_scale`), non-finite to 0, clamped to `+-0x147ae147ae147ae`, floor 0. The compare with `0x28f5c28f5c28f5c` before it cannot pick the other path: that constant is `floor(u64::MAX / 100)`, the same bound as step 3.
7. Price word: 0 for token 0; else the tree at `S+0x250`, else `0x375fb50(S+0x90, token)`.
8. Spot to perp: hold `0x371b140(wei)`; refused means **OK with no effect**; ledger direction 1 with `wei` and price; row credit `amount`; `dex+0x238 += amount`; row word `+= n / 10000`.
9. Perp to spot: mode 1 reads withdrawable again, signed; lower means **OK with no effect**. Row debit `amount`; `dex+0x238 -= amount`; ledger direction 0; row word `-= n / 10000`.

`dex+0x238` is `total_net_deposit` (serializer `0x370c340`, named by an earlier packet). The row word is value `+0x18` of the map at `S+0x740`, the same row `fees-request-budget-94` reads for its budget words. Both saturate with the recorder; `locations.tsv` gives the four Location records.

### Apply, `0x2717cf0(out, S, user, amount, to_perp)`

Byte `S+0x3ac8` not 0: 0xf9. Dex is always 0. On OK from the move, even with no effect, it allocates a one-user Vec and sends an event with word `0x800000000000000d`, `amount / 1e6` as f64 and the `to_perp` byte. The time is the 12 bytes at `S+0x60`. With word `S` equal to 1 the 32 stamp bytes come from `0x3987cb0`, else zero. Sink: slot `0x5774738` on `S+0x8f3`, copy c slot `0x5776ad0` on `S+0x5b8`.

### Signed handler

1. Text longer than 100 bytes: 0x143.
2. Empty text: 0x131. Split once at the first `subaccount:`; a later separator stays in the right part.
3. With a separator: the address is read first, 0xb6 on failure, then the left part is trimmed at its end for Unicode white space (table of 14 cases in `outcomes.tsv`). Without one there is no trim, so `7 ` is refused.
4. Decimal parser (`0x3799510`, tag 0xac on refusal), then `0x3750350` with mode 2 and exponent 6: half even, 0xa8 when negative and nonzero or above `2^63-2`.
5. With a separator: `0x2714f80`, 0xdc on refusal, and the sub-account replaces the user word.
6. Kind byte `+0x3c` of the user row: 3 needs `S+0x5b1`, above 3 needs `S+0x5b0`, else 0x16f.
7. Apply; outer code 0x0d on OK, 0x0e with the error object otherwise.

| Text | Result |
| --- | --- |
| `0.0000005`, `-0.0000005` | amount 0, OK, no move, event sent |
| `0.0000015`, `0.0000025` | 2 raw |
| `0.00000050000000000000000000001` | 0; read as the parser keeping 28 places, then a tie going to even |
| `1e3`, `1_000` | `1000000000` raw; `_1` and `1 ` are 0xac |
| `184467440737.095516` | `floor(u64::MAX / 100)` raw, the largest that can move; one unit more is 0xf7 |
| `9223372036854.775806` | `2^63-2` raw from the scaler, then 0xf7 from the move; one unit more is 0xa8 |

Address text: one optional lower case `0x`; below 40 bytes `string too short to be Address`; extra leading bytes must all be `0`, else `trailing characters of Address string must be '0'`; last 40 must be hex. So `0x00` plus 40 hex passes and `0X` does not.

### System handler

`amount >= 0x0ccc...`: 0x13f with the amount. Then the same kind gate on the user, then apply. No text, no sub-account.

### Copies

`copies.tsv` gives offsets. Copy c shifts fields from `+0x5c0` up by `0xa80` and keeps `S+0x80`, `S+0x90`, `S+0x250`, `S+0x5b0`. For the unused mode 3, copies a and b take the spot branch after a margin read, copy c takes the debit branch.

## Implementation and comparison

not yet implemented

`reference-diff.tsv` lists 15 differences from the lead, each with a case in `outcomes.tsv`. The largest: no digit-only parser and no refusal of a seventh fraction digit, no `0x0ccc...` compare on the user path (the lower bound there is `floor(u64::MAX / 100)`), a split of two parts, the address before the amount, and status 21 and 249 are the vault gate and `Spot disabled`.

## Results and limitations

- 951 named and 400 random cases match the rule list on all three copies. Inference: reading `S+0x8d0` as vaults rests only on tag text 0x15 and the 20-byte key. Unresolved: the names of value byte `+0xaf`, of `S+0x5b0`, `S+0x5b1`, of the kind byte and of row word `+0x18`; the text of tag 0x16f is the only hint for the kind.
- Mutation: 770 byte edits of conditional rows, immediates and field offsets on rows the cases reach, 702 killed, 68 survived (per edit in `mutations.tsv`):

- 25: error payload bytes past the tag; no reader in the subject and the parser leaves stack bytes there
- 12: text length or status word set just before a panic call; the stub does not read them
- 6: a longer key walk meets the fill or the stale key with a nonzero flag byte, same result
- 6: low bit of the integer clamp; the row word is the value over 10000, so the quotient is the same, and a negative clamp ends at 0
- 6: the f64 test only selects the clamp; the plain path and the clamp agree on these values
- 3: low bit of the sign mask or of the saturation word; the clamp below gives the same value
- 3: second read of the dex count on the same value; the first read refuses, and the edited read gives a pointer that passes
- 3: the 100 times gate refuses every amount past this bound, so a small change of the bound is not visible
- 2: a third part cannot exist, because the split stops at two parts
- 1: low bit of the reciprocal of 10000; the quotient is the same at the values this row ran, and the same constant is killed on the other tails
- 1: rescale modes above 1 share one rule

- `evidence.json` lists 148 unreached rows: landing pads, panic rows behind an earlier equal test, the allocation failure rows, and the parser's other part counts, which the two-part split cannot make.
- Amount and notional arithmetic is checked at edges and random points, not proved for all 2^64 inputs; the float chain itself is proved in `RE-004-usdc-ntl-scale-94`. Texts outside plain digits are a literal list, not a grammar of the parser.
- Mode values in `callers.tsv` come from the nearest `mov $imm,%r8d` or `xor %r8d,%r8d` byte shape before each call; they were read by eye at a sample of sites, not decoded by the tool.
- Which caller reaches which mode in practice, and whether a hold refusal or a second lower read can happen after the first gate, was not traced.

Next question: what do the callers `0x272bd60`, `0x272d000` and `0x272de40` move across dexes in modes 0, 1 and 2, and what reads row word `+0x18`?
