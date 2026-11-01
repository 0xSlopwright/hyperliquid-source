# RE-004: node #94 BOLE index reset and the SetBole words around it

New in this packet: `SetBole::ResetIndex`, the tail of `SetBole::Adl`, `BackstopLiquidatorTokenParams` and words 4 and 7 are settled from bytes, so a reconstruction can write how a reserve index folds into every user word (borrow rounds up, supply rounds down, each user alone, and the total becomes the sum of the rounded words) and what these votes store.

- Component ID: `l1`, task `RE-004`
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`
- Claim status: partial. Words 4, 5, 7, 17 and the reset are pinned. Word 16 is pinned around its body and commit, which are hooks here.
- Scope: the SetBole sub arms for words 4, 5, 7, 16, 17 in all three dispatcher copies, `reset_a 0x232b460` (copies `0x48ccfa0` for dispatcher b, `0x48ccf10` for dispatcher c), `reset_plan 0x373c280`, `reset_apply 0x373be40`, `row_gate 0x3c0d830`, `token_read 0x3733540`, `params_apply 0x37350c0`, `params_entry 0x35971a0`, `option_number 0x374ffa0`, `option_length 0x24cdfe0`. No execution of the binary.

## Reproduce

```
python3 tools/bole_reset_index.py --out research/work-items/RE-004-bole-reset-index-94
python3 -m unittest tests.test_bole_reset_index
```

The tool checks the binary's SHA-256 first, uses only the standard library plus `tools/fde_extents.py`, and writes every generated file here byte for byte. It takes about 3 minutes on this server, the byte edit sweep included.

## Evidence

Files: `function-rows.tsv` (bytes of the subject functions, 1105 rows, 4745 bytes), `arm-rows.tsv` (1333 reached rows of the three dispatcher copies), `word-table.tsv`, `rounding.tsv` (10 by 10 ladder of index and word, both directions), `serde.tsv`, `slots.tsv`, `outcomes.tsv`, `mutations.tsv`, `evidence.json`.

Offsets are from state `S`. The block at `S+0x498` is the BOLE state. Reserve rows are the `0xb0` byte tree at `S+0x568`, as in the earlier SetBole packet. Addresses are virtual.

### Observed: action words

The arm loads the inner words from action `+0x08` on. `word-table.tsv` gives the arm of each word per copy.

| word | serde text | action words used |
|---|---|---|
| 17 | `SetBole::ResetIndex`, 2 elements | `+0x08` token, `+0x10` flag |
| 16 | `SetBole::Adl`, 2 elements | `+0x08` token, `+0x10` amount |
| 5 | `SetBole::BackstopLiquidatorTokenParams`, 4 elements | `+0x08`, `+0x10` optional word; `+0x18` and `+0x30` two texts; `+0x48` token |
| 4 | no struct text | `+0x08` to `+0x18` optional text |
| 7 | no struct text | `+0x08` to `+0x18` text |

### Observed: reset

The arm for word 17 refuses a token at or past `S+0x218` (tag `0xea`, token in word 1). `row_gate` then looks the token up in the reserve tree; a miss gives tag `0xe1` inner 0. The side is `!flag & 1`, from the low bit of the low byte.

`reset_plan(out, S+0x498, token, side)` copies the row and walks the user tree at `S+0x598` in key order. Users are 20 byte keys and `0x30` byte values, with a token map at value `+0x18`. Token map values are four words.

| side | user word | index | rounding |
|---|---|---|---|
| 1 | `+0x08` | row `+0x58` | up |
| 0 | `+0x18` | row `+0x78` | down |

For each user with the token: `q = word * index / 1e14` on the full 128-bit product, through `__udivti3`. Side 1 adds one when the remainder is not zero.

- `q` past 64 bits gives status 3. `rounding.tsv` shows the edge: side 0 stores `q = 2^64 - 1`, a quotient of exactly `2^64` is refused.
- Adding `q` to the running total past 64 bits gives status 7.
- A user with a zero word stays in the list with 0. A nonzero word that rounds to 0 is stored as 0.
- A user without the token is skipped.
- Status 9 is a missing row, only visible from the wrapper; the arm's gate comes first.

On success the plan holds a new row: side 1 sets `+0x40` to the sum and `+0x58` to `1e14`; side 0 sets `+0x60` to the sum and `+0x78` to `1e14`. All other row words stay, the other side's index included. `reset_apply` writes the row, then writes each `q` into the user's word.

No user word or row word changes on a refusal, because the plan runs first and stores nothing. Any status but `0x11` gives tag `0xe1` inner `0xa` at the arm, so statuses 3 and 7 look the same to the caller. The total is replaced by the sum, so an old total that disagrees is dropped without a check.

### Observed: word 16 around its body

Order: token gate, row gate, amount below `0x0ccc...cc` (tag `0x13f`, amount in word 1). The arm then reads the system user, key 20 bytes of `0xbb`, through slot `0x5773e58`, and `token_read(value, token, 1)` from slot `0x5773e60`. `token_read` returns word `+0x08` for side 1, `+0x18` for side 0, or 0; its result is not read by the next rows. Then the body `0x373cc50(out, S+0x498, token, amount)`.

| first word of the body's result | what follows |
|---|---|
| 3 | tag `0xe1`, inner = second word's low byte |
| 2 | call through slot `0x576f488`, then Ok with no commit and no reset |
| other | commit `0x373ae10`, a second system user read, then the reset on side 0 |

So a successful Adl with the third outcome always folds the supply index, and a reset refusal after the commit still gives `0xe1` inner `0xa` with the commit already done.

### Observed: `BackstopLiquidatorTokenParams`

Order: token gate, row gate, first text, second text (both through slot `0x5773e80`), then the optional word against `0x0ccc...cc` (tag `0x13f`). `params_apply(S+0x498, token, low tag, low, high tag, high, word tag, word)` gets a row from `params_entry`, a SwissTable at `S+0x4a8` with `0x28` byte buckets keyed by token. A missing token inserts a zeroed row **before** any check.

Row: `+0x00` flag, `+0x08` word, `+0x10` low, `+0x18` high. Tag 0 keeps the stored word, tag 1 stores 0, tag 2 stores the value. The optional word is tag 0 when not given, tag 1 when given as 0, else tag 2. Tag 1 clears the flag and leaves the word.

`high != 0 && high < low` returns status 4 and stores nothing, which is `0xe1` inner `0xa` at the arm. The zeroed row of a new token stays. `high == 0` is no limit.

### Observed: words 4 and 7

Word 4: an optional text. Absent writes `S+0x498 = 0` and a stack word into `S+0x4a0`. Text over 100 bytes gives tag `0x143`. Otherwise the decimal parser's error, or a failed conversion through slot `0x5773968` gives tag `0xab`. Success stores flag 1 and the f64 at `S+0x4a0`.

Word 7: a text of at most 100 bytes, parsed, then scaled to `10^14` by the exact mode of `0x3750350`. Above `1e14` or a scale error gives `0xe1` inner `0xa`. `1e14` itself is stored at `S+0x560`. Run real through `0x373cbf0`, with the scale call as a hook.

### Inferred

- The two sides are borrow and supply. The row offsets match the earlier reserve packet, and the side 1 ceiling and side 0 floor match `reserve_side_gate`.
- The serde run `wpPu` after the Reserve keys fits the four fields of `BackstopLiquidatorTokenParams`: `w` the optional word, `p` and `P` the two texts, `u` the token. Keys are not tied to action offsets here.
- `low` and `high` look like a price band, because both go through the token price parser. No reader of the row was traced.

## Implementation and comparison

Not yet implemented in Rust. A rule list in the tool, written apart from the machine, predicts status, nested byte, every reserve row, every user word, the parameter table and its counters, and every state byte. 690 named cases and 300 generated vectors match on real rows, with the reset, adl, text and parameter cases on all three copies. Trees use real node layouts up to height 3 and are walked afterwards, with stale keys in unused slots.

Hooks replace the decimal parser, `0x4ead680`, the scale call, the price parser, the user lookup `0x373acd0`, the Adl body and its commit. Each hook checks what it receives. These are edges here, not claims.

| check | result |
|---|---|
| byte edits on reached rows | 830 |
| killed | 764 |
| survived | 66 |

Survivors, all classified in `mutations.tsv`:

- 15: rest of a length refusal: those words of the object are never written
- 8: register argument the reset wrapper does not read
- 7: apply search: the plan lists only users that hold the token, so it always hits
- 6: action field the arms here do not read
- 6: selector row for words 0 to 2, other arms of the vote
- 6: side of the token read, whose result the next rows do not read
- 3: drop flag of the arm: every case frees every string either way
- 3: second copy of the result: the bytes are the same either way
- 2: height 8 guard: trees here are at most height 3
- 2: insert probe: the first group here always has a free slot
- 2: map hit: the value pointer is never null, so these two loop words are rewritten
- 1: any status but 0x11 gives the same 0xe1 with inner 0xa at the dispatcher
- 1: byte pattern shuffle: all lanes hold the same value
- 1: descent ends on a nonempty leaf at slot 0: any nonzero word passes
- 1: empty list pointer: not read before the first push
- 1: hasher key base: any stable words give the same table view
- 1: tag of a temporary passed to its drop: the drop acts the same

## Results and limitations

- 153 rows of the subject functions are unreached: landing pads, tree height 8 and over, the insert paths of `reset_apply` (the plan only lists users that hold the token, so its lookups always hit), and table growth in `params_entry`.
- The Adl body `0x373cc50` and commit `0x373ae10` are not read here. Which outcome word means what is open.
- The results of `token_read` in word 16 are not used by the next rows. Why the call stays is open.
- Dispatchers b and c pass two more registers to the reset wrapper, which does not read them. Every offset named here ran on all three copies.
- No reader of `S+0x498`, `S+0x560` or the parameter table was traced, so their names are open.
- When a refused reset can be reached depends on real index values, which are not read here.

Next question: what does `0x373cc50` move between users, and which step reads the row at `S+0x4a8`?
