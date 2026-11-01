# RE-004: token supply in node #94: the non-circulating set vote, the supply summary, read precompile 0x80d and the proposal reader

This packet shows how node #94 turns stored words into circulating supply: `max - token_fees_collected - sum(listed users, two burn addresses, one per-token address) - native_token_reserve`, saturating at each subtraction, with token id 1 reporting 4e13 more in its top word only, so a reconstruction can write this function, which the reference does not have, and read vote word 55 as two user lists rather than the reference's two `u64` fields.

- Component ID: RE-004 (quantities and rounding), spot token supply
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `6d727b9ea2ca4dc497c96a2de35cfba064e14dcc` / reference `references/can1357-hl`, `l1/action/vote_global.rs` line 323 only, used as a lead; the reference has no supply computation
- Claim status: observation for bytes, offsets and evaluated behaviour; inference where marked; unresolved where marked
- Scope included and excluded: included are the supply summary `0x375e4c0`, the set body `0x37603e0`, the vote arm of word 55 in all three dispatchers (`0x23567d8`, `0x4cab148`, `0x4cb3ad8`, only the rows the arm reaches), read precompile `0x80d` body `0x3248ea0`, its row mapper `0x3baf8b0`, and the proposal handlers `0x1f68be0`, `0x47ba820`, `0x47bac70`, which are the only other callers of the summary. Earlier work on these addresses is narrow: open #849 pins `0x375e4c0` as byte and record observations with no labels, `RE-004-wei-saturating-ops-94` lists its one recorder site, `RE-004-read-precompile-gas-94` has one family row for `0x3248ea0` and `RE-004-user-read-precompile-outputs-94` names `0x80d` as excluded and `0x375ecdd` as not read; the question here, what the words mean and how they combine, is not answered by any of them. `RE-010` and `RE-014` hold dispatch inventory rows for `0x37603e0` and `0x1f68be0`. Run real as edges and not claimed: B-tree insert `0x339b590` and remove `0x33acfe0`, `Vec` growth, `Bytes` construction. Stubs that check their arguments: spot row lookup `0x371b3a0`, staking summary `0x3992540`, seed hash `0x399c4a0`, ABI decoder `0x37e65f0`, error text `0x37f3190` and `0x3c02770`, status drops, stamp `0x3987cb0`, recorder `0x358dcd0`, proposal sink `0x398d540`. Excluded: what those callees do, who writes the maps, and how much of the proposal sink uses the word

## Reproduce

Run from the repository root on Linux with Python 3 and the connected `artifacts/node/94/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/token_supply_summary.py --out research/work-items/RE-004-token-supply-summary-94
python3 -m unittest tests.test_token_supply_summary
cd research/work-items/RE-004-token-supply-summary-94 && sha256sum -c MANIFEST.sha256
```

The tool refuses any other binary digest, reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no objdump or readelf output, calls no external program and took about 2 minutes at server load 5.

## Evidence

Coordinates are virtual addresses. Bounds are FDE extents. 252 named cases and 200 random cases run real rows; a separately written rule list predicts results, every callee event with its arguments, the ABI bytes, the gas, and every other fixture byte, and that no block is left unfreed. Subject code is 2218 instructions in 10435 bytes.

`S` is the state, `P = S+0x80` the spot struct and `L = S+0x90` its meta. `field-keys.tsv` gives the four serde keys from the serializers, each beside its offset, and `tag-texts.tsv` the Display texts.

### Summary, `0x375e4c0(out, L, token, P, staking)`

1. `token >= L+0x188` panics. The token row is `[L+0x180] + token*0xe8`.
2. `top` is the value of `token` in the tree at `P+0x388` (`token_to_max_supply`), 0 if absent. `total = max(top - fees, 0)`, with `fees` from the tree at `P+0x3a0` (`token_fees_collected`).
3. Users are visited in this fixed order:
   - the set at token row `+0x90` (`non_circulating_users`), sorted;
   - the zero address, then `0x00..dead` (`constants.tsv`);
   - `0x32`, 11 zero bytes, `token` as big endian `u64`, only when `token` is a key of the hash table at `P+0x80`.
4. Each user's balance is word 0 of the value for `token` in the row from `0x371b3a0`, tree at row `+0x10`, 0 if absent.
5. If `token` is the native token (`P` flag byte set and `P+8 == token`), the first three words of `0x3992540` are added; `RE-004-user-read-precompile-outputs-94` reads them as `delegated`, `undelegated`, `totalPendingWithdrawal`. The fourth word is ignored. Each add is checked; overflow is tag 0xbe.
6. A balance of 0 leaves no row. Otherwise it is added to `used` (checked, 0xbe) and pushed as a 32-byte row: user at +0, amount at +0x18.
7. `free = max(total - used, 0)`.
8. Token id 1 only: `top + 4e13`, checked with `cmp` against `0xffffdb9ec6357fff`, 0xbe. `total` and `free` do not move.
9. Native token only: if the flag at staking `+0x60` (`native_token_reserve`) is set, `reserve` is the word at `+0x68`; `free - reserve`, with underflow giving 0 and the recorder on Location `impl_wei.rs:6:1`. The reserve word is returned unchanged.
10. `out`: tag 0x186, `Vec` at +8, `top` +0x20, `total` +0x28, `free` +0x30, `reserve` +0x38. On 0xbe the `Vec` is freed and only the tag is written.

A user listed in the set who is also a burn address is visited twice: two rows and two subtractions (case `summary dead user in the set counts twice`).

### Vote word 55, arm and body

The action holds two lists of 20-byte users at `+8` and `+0x20` and the token at `+0x38`. The arm is the same in the three dispatchers apart from one stack slot (`copies.tsv`):

1. `token >= S+0x218`: tag 0xea with the token.
2. First list longer than 10000: tag 0x143. Second list longer than 10000: tag 0x143. The payload points at the list's stack copy.
3. Body `0x37603e0(L, token, first, second)` inserts all of the first list, then removes all of the second, so a user in both ends absent. Then both lists are freed.

The token test comes first, so a bad token hides a long list.

### Precompile `0x80d`, `0x3248ea0(out, context, input, gas limit)`

Order:

1. `0x00..080d` in the set at `[[context+0x38]]`: halt result. Inference: a disabled precompile set.
2. Input above 2000 bytes: halt.
3. `gas = 1000 + 33*n` above the limit: halt.
4. Decoder refuses: text `Invalid input`.
5. Token `>= [context+0x10]+0x198`: tag 0xea through the error text helper.
6. Summary; an error goes through `0x3c02770`.
7. Output: `0x20`, `top`, `total`, `free`, `reserve`, `0xa0`, row count, then each row as address word, amount word. All words are 32 bytes; row order is the summary order.
8. `gas + 33*len(output)` above the limit: halt, and the output is dropped.

### Proposal handler, three copies

`0x1f68be0` refuses chain byte 3 with 0x8d, stamps when word `S` is 1, refuses a missing native token with 0xfb, runs the summary for the native token, refuses a title above 100 bytes and a body above 1000 bytes with 0x143, then calls `0x398d540` with `free` (+0x30 of the summary) in the frame at +0x50. Copy b reads the chain byte at `+0x1372` and staking at `+0x1378`; copy c keeps `+0x8f2` and `+0x8f8`.

## Implementation and comparison

not yet implemented

`reference-diff.tsv` lists 6 differences from the lead, each with a case in `outcomes.tsv`.

## Results and limitations

- 252 named and 200 random cases match the rule list. Copies a, b and c of the arm and of the proposal handler each ran their own cases.
- Mutation: 821 byte edits of conditional rows, immediates and field offsets on rows the cases reach, 722 killed, 99 survived (per edit in `mutations.tsv`):

- 46: ABI writer bookkeeping: capacity, reserve and offset stack words, or the zero top bytes of an amount word; the output bytes are the same
- 24: status payload copy past the tag; the summary writes only the tag on error, so these bytes are stack bytes
- 20: iterator state word: the loop compares these with 2 or tests bit 0 and keeps its own copies, so the edited value takes the same path
- 3: gas add cannot carry with these lengths, so the saturation rows have no effect
- 2: payload word of tag 0xfb; only the tag is compared, and the word is stack bytes
- 1: dangling pointer of an empty vector, never read
- 1: last pointer of the unrolled descent, not read again on the visited path
- 1: low bytes of the first text word are written over by the second word
- 1: size bound far above any row count

  Survivors are grouped by address range; a sample of each group was read, not every edit.

- `evidence.json` lists 176 unreached rows: landing pads, panic rows, allocation failure rows and `Vec` growth calls the stub capacity does not need.
- Arithmetic is checked at edges and random points, not proved for all inputs.
- Unresolved: why token id 1 reports 4e13 more; what the hash table at `P+0x80` holds and what the `0x32` user is (byte shape only; a dev census, not in this tool, saw the same build at 14 sites in 11 functions); who writes `native_token_reserve`.
- Inference: reading word 55 as ModifyNonCirculatingSupply rests on the raw value in the reference comment and on the body writing the field named `non_circulating_users`. Word 64 sets the native token after a four byte compare with `HYPE` (read by eye, not in the tool).
- The row serializer `0x2a365c0` has keys `circulatingSupply` and `totalSupply`, but none of the four callers of the summary is an info path. How that row is filled was not traced.
- Real insert and remove ran on lists up to 30 users. Lists at the 10000 cap ran with a checked stub for the body.

Next question: what fills the `circulatingSupply` and `totalSupply` words of the row at `0x2a365c0`, and do they use the same rule?
