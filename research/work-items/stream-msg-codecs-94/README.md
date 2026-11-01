# node-runtime: node #94 `node/stream_msg.rs` codecs (`0x466e3f0` is a MessagePack encode into `Arc<Vec<u8>>`, not a bincode decode; `AbciStreamGreeting` 0..=5; `GreetingHash` tag 1 has one 80-byte arm, the 32-byte shape is an error)

Question: what do the `node/stream_msg.rs` seeds encode and decode? The
can1357 lead (`node/stream_msg.rs`, header) says:

- `0x466E3F0` does a "bincode decode + `Result::unwrap` for a 24-byte
  payload, then allocates a `0x28` byte `ArcInner<T>`";
- `0x4674820` is the `AbciStreamGreeting` bincode `Deserialize` (tags 0..=5);
- `0x466E750` is the `GreetingHash` `Deserialize` (tags 0..=2), whose tag 1
  is decoded by `0x49784E0`, which "has two output shapes: a compact 32-byte
  hash arm and a full 80-byte arm".

What do the bytes show?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`; path rule `node/*`). `research/catalogue/seed-candidates.json`
  lists the seeds `0x466e3f0`, `0x466e750`, `0x466eb70`, `0x4674820` and
  `0x4674b50`. Only `0x4674b50` has an earlier packet
  (`RE-001-three-field-map-94`); no packet or open PR covers the others.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `546081f3`. Reference lead: `references/can1357-hl`
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for claims to test;
  no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `node-runtime` research; no gate changes.
- Companions: `abci-latency-sampler-94` and `channel-locations-94` cover
  other parts of `0x474bfa0`, the only caller of the encoder here.
- Scope (11 windows):
  - `0x466e3f0` up to its `ud2`, and the indirect call at `0x474cc03`;
  - the whole serializer `0x459d4f0..0x459d7ff` and the `proposer` field
    writer `0x4670030`;
  - the marker-byte helper `0x4aed5a0`, and the marker selection at the head
    of the map, array and str header writers;
  - `0x4674820` and `0x466e750` (whole FDEs, minus a landing pad), and
    `0x49784e0` up to its `ret`.
  - Also: the path string, the one `stream_msg.rs` Location, field and type
    names, the jump table, the two allowed-variant records, the RELATIVE
    slots, and a whole-`.text` census of references and direct callers.
- Excluded:
  - the value writers (`0x43e3470`, `0x4407ea0`, `0x4aeca50`, `0x4c13760`,
    `0x44355d0`, `0x459daf0`) and the hex helper `0x29ed380`;
  - the vector, varint and inner decoders (`0x4589a30`, `0x466bbb0`,
    `0x466bc10`, `0x485baa0`, `0x496ec70`, `0x466c1b0`, `0x496f370`,
    `0x496f030`);
  - the seed `0x466eb70`, and the callers `0x471b880` and `0x474bfa0`
    beyond the one call.

## Reproduce

```sh
make verify
python3 tools/stream_msg_static.py --json > research/work-items/stream-msg-codecs-94/records.json
python3 -m unittest tests.test_stream_msg_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` entries. It never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; about 2 s). `records.json` is
its complete output, and the test suite regenerates it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
11 windows (946 instructions, 4089 bytes), one for each checked byte window.
All 248 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 166 decoded call, branch and
RIP-relative operands, and every instruction it checks, lies inside a checked
window.

## Evidence

### One Location, one caller (observation)

The file holds `/node/src/stream_msg.rs` once, inside
`/home/ubuntu/hl/code_Mainnet/node/src/stream_msg.rs` at `0x1ec0f1`. Exactly
one RELATIVE-backed Location points at it: `0x572d6f0`, line 43, column 48.
The census covers every disp32 in `.text` that follows a RIP-relative ModRM
byte. Its only reference is `lea r8` at `0x466e4e0`.

`0x466e3f0` has no direct `e8` caller. The RELATIVE slot `0x5776ac8` holds
it, and the only `call [rip+…]` through that slot is at `0x474cc03`, inside
`0x474bfa0`. Direct callers of the other entries:

| Function | Direct callers |
| --- | --- |
| `0x459d4f0` | `0x466e435` (in `0x466e3f0`) |
| `0x4674820` | `0x471b967`, `0x471baa9`, `0x471bcbe` (all in `0x471b880`) |
| `0x466e750` | `0x46748c3` (in `0x4674820`) |
| `0x49784e0` | `0x466e81a` (in `0x466e750`) |

### `0x466e3f0` encodes (observation)

- `rsi = rdi` (the value).
- `[rsp] = 0`, `[rsp+8] = 1`, `[rsp+0x10] = 0`: capacity 0, dangling
  pointer 1, length 0.
- A config block at `rsp+0x30`: `+0` points at that triple. The dword
  `0x01000400` at `+8` gives the bytes `00 04 00 01` at `+8..+0xb`, and
  `+0xc` is 0.
- `call 0x459d4f0(rsp+0x18, value, config)`.
- If the result is `0x8000000000000004`, it allocates 0x28 bytes through slot
  `0x576dfd8`, stores 1, 1 and then the triple, and returns the pointer. A
  failed allocation reports size 0x28, alignment 8.
- Otherwise it frees the triple's buffer when its capacity is non-zero, and
  calls slot `0x576e048` (`0x157aa10`). The arguments are the message
  `called \`Result::unwrap()\` on an \`Err\` value` (`0x6f7dd2`, 0x2b bytes)
  and the Location `stream_msg.rs:43:48`. Then `ud2`.

Inference: this is `Arc::new(to_bytes(value).unwrap())`: a `Vec<u8>` output
buffer (the "24-byte payload") written by a serializer, moved into an
`ArcInner<Vec<u8>>` (16-byte header + 24). Nothing is read from an input
slice.

### `0x459d4f0` writes MessagePack (observation)

`r14` is the config and `r15` the value. The byte at config `+0xb` selects
the header writer:

- set: `0x4ae9900` (map);
- clear: `0x4aea420` (array).

Names are written with `0x4aeb170` only when the byte is set. The sequence
is:

| Step | Name (VA, length) | Value |
| --- | --- | --- |
| header 2 | | |
| | `abci_block` (`0x6f73f2`, 10) | header 6 |
| | `time` (`0x209d88`, 4) | `0x43e3470` with `&(value+0x38)` |
| | `signed_action_bundles` (`0x6f73cc`, 21) | `0x4407ea0` with `value` |
| | `round` (`0x6f73e1`, 5) | `0x4aeca50` with `[value+0x18]` |
| | `parent_round` (`0x6f73e6`, 12) | `0x4aeca50` with `[value+0x20]` |
| | `hardfork` (`0x20a618`, 8) | `0x4c13760` with `value+0x28` |
| | (in `0x4670030`) | `0x4670030` with `value+0x44` |
| | `resps` (`0x6f73fc`, 5) | `byte [value+0x58] == 2`: `0x44355d0`; else `0x459daf0` |

`0x4670030` writes the name `proposer` (`0x20af88`, 8) when the same byte is
set. It then calls slot `0x5773120` (`0x29ed380`) with a 0x2a-byte buffer and
0x14 input bytes, and writes the result with `0x4aeb170`.

The marker logic:

- `0x4ae9900`: `n < 16` gives `0x80`, else `0xde` if `n < 0x10000`, else
  `0xdf`.
- `0x4aea420`: `0x90`, `0xdc`, `0xdd` with the same bounds.
- `0x4aeb170`: `n < 32` gives `0xa0`, `n < 0x100` gives `0xd9`, else `0xda`
  if `n < 0x10000`, else `0xdb`.
- `0x4aed5a0` turns `0x80` / `0x90` / `0xa0` into `0x80 | n & 0xf`,
  `0x90 | n & 0xf` and `0xa0 | n & 0x1f`. Values already in `0xc0..0xdf` are
  returned unchanged.

These are the MessagePack fixmap / map16 / map32, fixarray / array16 /
array32 and fixstr / str8 / str16 / str32 markers.

Inference: with the struct-map byte 1 (as in `0x466e3f0`), the bytes are a
named MessagePack map `{abci_block: {time, signed_action_bundles, round,
parent_round, hardfork, proposer}, resps}`. The config layout and
`0x8000000000000004` Ok value match rmp-serde's `Serializer` with
`StructMapConfig`, but no crate source is checked here. `proposer` is a
20-byte value written as a 42-byte string, by inference `0x` + 40 hex
digits. `resps` is an `Option` with 2 as `None`.

### `0x4674820` `AbciStreamGreeting` (observation)

- It calls `0x466bc10`. A status byte other than 0x12 copies the error out
  with discriminant 8.
- A tag above 5 stores error kind 5 and the tag, the str `AbciStreamGreeting`
  (`0x6f878b`, 0x12) and `0x203580`, with discriminant 8. The record at
  `0x203580` is `(0u64, 0u32, 5u32)`.
- Otherwise it jumps through the table at `0x6f700c`:

| Tag | Target | Reads | Discriminant |
| --- | --- | --- | --- |
| 0 | `0x467486c` | `0x4589a30` (element decoder `0x466bbb0`), `0x466bd10`, `0x466e750` | the `GreetingHash` result's own (0..=2); its 3 is an error -> 8 |
| 1 | `0x4674966` | `0x466bd10` three times | 3 |
| 2 | `0x4674954` | nothing | 4 |
| 3 | `0x467495d` | nothing | 5 |
| 4 | `0x467494b` | nothing | 6 |
| 5 | `0x46749db` | nothing | 7 |

This agrees with the lead's six tags and their contents.

Inference: tag 0 shares its discriminant with the nested `GreetingHash`
(niche layout). The error is a bincode-2-style
`UnexpectedVariant { type_name, allowed: Range { min: 0, max: 5 }, found }`.

### `0x466e750` `GreetingHash` (observation)

`0x466bc10` reads the tag. Every error path stores discriminant 3.

- **Tag 0:**
  - It reads 32 raw bytes from the reader at `r14`. If `[r14] == 1`, it
    first adds 32 to the counter `[r14+0x20]`: overflow, or a value above
    `[r14+8]`, is error kind 2.
  - Then, if fewer than 32 bytes remain (`[r14+0x18] <= 31`), it is error
    kind 0 with `32 - remaining`.
  - Otherwise it advances the cursor `[r14+0x10]` and the remaining length.
  - It then calls `0x496ec70` and stores its 24 bytes at `+0x28`, with
    discriminant 0.
- **Tag 1:** `0x49784e0`. If its first byte is 0, it copies 80 bytes to
  `+0x8` with discriminant 1. Otherwise it copies 32 bytes and stores
  discriminant 3.
- **Tag 2:** `0x485baa0`. On status 0x12 it stores the u64 at `+0x8`, with
  discriminant 2.
- **Tag above 2:** error kind 5, the tag, `GreetingHash` (`0x6f877f`, 0xc)
  and `0x209410` = `(0u64, 0u32, 2u32)`.

`0x49784e0` calls three decoders in turn:

- `0x466c1b0` (its tag 1 is an error), giving 32 bytes;
- `0x496f370`, giving 24 bytes;
- `0x496f030`, giving 24 bytes.

When all three succeed it stores 80 bytes at `+0x8..+0x58` with tag 0. Each
failure stores tag 1 with 32 bytes at `+0x8`.

So tag 1 has a single 80-byte arm. The 32-byte shape is `0x49784e0`'s error,
and `0x466e750` turns it into its own error value 3. The lead's
`Compact([u8; 32])` arm is that error.

## Lead check

| Lead claim | Binary |
| --- | --- |
| `0x466E3F0`: bincode decode + `unwrap` of a 24-byte payload, then a 0x28 `ArcInner` | A serializer writes into a new `Vec<u8>` (the 24 bytes); the Vec goes into the 0x28 `ArcInner`; `unwrap` at `stream_msg.rs:43:48` |
| Stream payloads are bincode inside a `[u32 be length][u8 flag]` frame (`StreamFrame`) | The one encoder in this file, `0x459d4f0`, writes MessagePack markers (named maps with the config used here); the two decoders do read varint tags |
| `AbciStreamGreeting` tags 0..=5 with vector, u64, `GreetingHash` / three u64 / units | Yes |
| `GreetingHash` tags 0..=2 | Yes |
| Tag 1: `Compact([u8; 32])` or `Full([u8; 80])` | One 80-byte arm; the 32-byte shape is the inner error, mapped to the error value 3 |
| `read_exact` error `UnexpectedEof { needed: 32, remaining }` | Kind 0 carries `32 - remaining`; a configured limit is checked first, as kind 2 |

## Models

The tests check the following:

- header bytes: `0x82`, `0xde 00 10`, `0x96`, `0xdd 00 01 00 00`, `0xb5`,
  `0xd9 20`;
- the named skeleton `82 aa "abci_block" 86 a4 "time" …`, and the array
  skeleton `92 96 …` with no names;
- `AbciStreamGreeting` discriminants 3..=7 for tags 1..=5, and an error for
  tag 6;
- `GreetingHash` tag 1 with an inner error;
- the 32-byte read's two errors;
- the lead's `Compact` reading of tag 1.

## Unresolved

- The value writers (in particular how `time`, `hardfork` and the
  `resps` payload are encoded) and the hex helper `0x29ed380`.
- What `0x474bfa0` sends the encoded bytes to.
- The callers in `0x471b880` and how they frame the greeting bytes.
- The inner decoders under `GreetingHash` and the seed `0x466eb70`.
- Whether the reader and error kinds are bincode 2 or a fork; no crate
  source is checked.

## Controls

`tests/test_stream_msg_static.py`: 34 tests. The 23 corruption tests reject:

- changed window bytes, and an operand outside every window;
- re-pinned rewrites:
  - in the encoder: the Vec pointer, the struct-map byte, the Ok value and
    the Arc size;
  - in the serializer: the outer and inner entry counts, a name length, the
    field order, and the `resps` tag;
  - in the marker logic: a map marker and the fixstr marker;
  - in the greeting decoder: the tag bound;
  - in the `GreetingHash` decoder: the Ok test and the Err branch;
- a jump-table entry, a type name, an allowed-variant bound, the Location
  line, a stray `lea` to the Location planted in int3 padding, the encoder
  slot, and a field name.
