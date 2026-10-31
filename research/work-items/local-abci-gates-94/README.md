# node-runtime: node #94 local abci_state startup gates (height tolerance, logged tolerance, 600 s freshness panic)

Question: when node #94 starts from a local abci_state, which constants decide
that the local height is "too far behind" or "from stale hardfork", which
`tolerance` value is logged, and what does the
`use an abci state within … seconds` check compare? Where does the can1357
lead (`node/local_abci_state.rs`, `node/startup.rs`) differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for seed addresses and claims to test; no code, comments or names
  copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: eight fixed windows in `0x22689f0` (the lead's
  `local_abci_state.rs` seed), `0x2271d00` and the panic shim `0x157b810`.
  Excluded: how the compared heights and the timestamp are produced, what the
  logged tolerance is used for, the callers of `0x2271d00`, and release #115.

## Reproduce

```sh
make verify
python3 tools/local_abci_gates_static.py --json > research/work-items/local-abci-gates-94/records.json
python3 -m unittest tests.test_local_abci_gates_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 8
windows (163 instructions), one per checked byte window. All 13 code VAs in
`records.json` are instruction starts in those windows.

Format templates are decoded as rustc 1.94 packs them: a byte below 0x80 is a
literal length, and `0xc0` is a placeholder followed by the length of the next
literal; `0x00` ends the template. Every literal length decodes to printable
text that ends exactly at the next marker. Reading placeholder *k* as format
argument *k* is an inference.

## Evidence

### Height gate in `0x22689f0` (observation)

Window `0x226ab0a..0x226ab88`, with `x = [rsp+0xd8]`:

1. If `x >= 0xffffffffffffb1e0`, then `y = u64::MAX`; otherwise
   `y = x + 0x4e20` (20000). Both arms use the same constant: `add` at
   `0x226ab1d`, `lea` at `0x226ab52`.
2. If `y <= [rsp+0xd0]`, the message is `local height is too far behind` (30
   bytes, `0x3d79b2`, selected at `0x226ab49`).
3. Otherwise, if `x < [rsp+0xc8]`, the message is
   `local height is from stale hardfork` (35 bytes, `0x3d798f`, selected at
   `0x226ab81`).
4. Otherwise control goes to `0x226adb1`.

Inference: the messages suggest `x` is the local height, `[rsp+0xd0]` the
target height and `[rsp+0xc8]` the peers' initial height. The rule is then:
too far behind iff `local.saturating_add(20000) <= target`.

### Logged tolerance in `0x22689f0` (observation)

- **540.0:** `0x226900c` loads 540.0 (`.rodata` `0x20a3d8`). It then branches
  to the join `0x2269164` if `[rbx+0xc18] != 1` (`0x226901b`) or
  `[rbx+0xc20] != rax` (`0x226902e`). `[rbx+0xc20] < rax` goes to
  `0x2269760`, which LEAs `assertion failed: freeze_height >= self.…`.
- **840.0:** `0x226915c` loads 840.0 (`0x20a230`) and falls into the join,
  which stores `xmm0` to `[rsp+0xe0]` at `0x2269168`. The
  `applying hardfork to frozen local abci_state` log call (`0x226911b`,
  template `0x1ed136`) precedes it.
- **Only two branches into the join:** a scan of every `jcc`/`jmp` rel8 and
  rel32 in the FDE finds exactly these two branches into `0x2269164`.
- **Only two `[rsp+0xe0]` operands:** the store at `0x2269168` and a LEA at
  `0x226928a`. That LEA's pointer goes to `[rsp+0x48]`, and `&[rsp+0x48]` is
  argument 2 of a five-argument log call (`0x2269333`, template `0x1f5428`).
- **Argument 2 is the tolerance:** in that template, placeholder 2 sits
  between `… @@ initializing with local abci_state @@ [tolerance: ` and
  `] @ [pre_fork_context: `.

Inference: the logged tolerance is 840 on the frozen-state hardfork path and
540 otherwise. Indirect branches are not resolved, so a jump-table entry into
`0x2269164` is not excluded. What the tolerance controls, and its unit, are
unresolved.

### Freshness check in `0x2271d00`: panic at `hl_node.rs:346:9` (observation)

Window `0x2271d52..0x2271e8c`, with `r15 = [rbx+0x740]`:

1. **Message arguments:** the f64 600.0 is stored at `[rsp+0x138]`. The
   12-byte value at `[r15+0x60]` is copied to `[rsp+0x140]`. Those two
   addresses are the arguments of the panic template.
2. **Add 600:** the call through RELATIVE slot `0x576e8a8` (to `0x15206e0`)
   gets `rsi = &[rsp+0xc4]` (bytes 4..12 of the 12-byte copy), `edx = 600`
   (`0x258`) and `ecx = 0`.
3. **Day carry:** the returned carry `[rsp+0x18]` is range-checked and
   divided by 86400, truncating toward zero. The sequence is `imul` by
   `0x1845c8a0ce512957`, then `(rdx >> 63) + (rdx >> 13)` in 32 bits; the
   model is checked on 2010 values.
4. **Add days:** the days and the 4-byte head of the copy go to slot
   `0x576e8b0` (`0x151f870`). A zero result branches away to `0x227236d`.
5. **Clock read:** slot `0x576e8a0` (`0x151cba0`) fills `[rsp+0x10..0x1c]`.
6. **Compare:** the tuple `(ebp, r12d, r14d)` is compared with
   `([rsp+0x10], [rsp+0x14], [rsp+0x18])` lexicographically: signed
   `setge` on the first field, unsigned `setae`/`jae` on the others. If the
   first tuple is less, control goes to `0x2271e38`.
7. **Panic:** `0x2271e38` calls slot `0x576e098` (`0x157b810`) with template
   `0x1ed194` and Location `0x569e948`. The template is
   `use an abci state within {} seconds to ensure node_ips are up to date. abci_state_time={}`,
   with two placeholders. The Location is
   `/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs`, line 346, column 9.
   The next instruction jumps to `ud2` at `0x227283d`.
8. **Panic shim:** `0x157b810`'s FDE ends exactly at its call through slot
   `0x57706e0` (to `0x4ecdcf0`), and the call is preceded by a
   `can_unwind`-style word store of 1. Its shape matches a `panic_fmt` shim.

Inference: the 12 bytes are a date-time {date, seconds of day, fraction}. The
check panics iff `abci_state_time + 600 s < now`, and the same 600 is printed
as the f64 `600.0` in the message.

## Comparison with the lead

- **0x4e20:** `NODE_IP_FRESHNESS_TOLERANCE = Duration::from_secs(0x4e20)`
  cites "`add 0x4e20` in the stale-time branch at `0x226ab1d`". That `add` is
  the height gate above: its saturating sum is compared with `[rsp+0xd0]` and
  selects `local height is too far behind`. No time value is involved in that
  window.
- **Freshness check:** the lead's `StateFileTooOld` (age > 0x4e20 s,
  returned as a stale reason) does not match the binary. In the binary the
  `use an abci state within … seconds` message belongs to a 600 s check that
  panics at `hl_node.rs:346:9`. The lead places it in `local_abci_state.rs`.
- **Height lag:** `MAX_LOCAL_HEIGHT_LAG` is 200 in `local_abci_state.rs` and
  1_000 in `startup.rs`; the binary uses 20000. `startup.rs:500` tests
  `target - local > LAG`. The binary rejects at
  `local.saturating_add(20000) <= target`, which includes equality: for
  example, local 0 and target 20000 is "too far behind".
- **Stale hardfork:** the lead's stale-hardfork reason compares the local
  height with a peer initial height. That matches the operand order here
  (`x < [rsp+0xc8]`, tested only when not too far behind), under the
  naming inference above.

## Controls

`tests/test_local_abci_gates_static.py` (18 tests) regenerates
`records.json` and checks three models: the height gate including
saturation, the day division against exact truncating division, and the
lexicographic compare. It refuses each of these corruptions:

- The gate constant changed to 200.
- Either message's first byte changed.
- The 540.0 or 840.0 constant changed.
- An extra `je` into the join planted.
- An extra `[rsp+0xe0]` operand planted.
- The log template literal changed.
- The added seconds changed to 0x4e20.
- The Location file changed.
- The panic slot's RELATIVE addend redirected.
- The freshness template text changed.

The module passes with GNU binutils or with LLVM tools only on `PATH`; the
producer does not use either.

## Unresolved

- How `[rsp+0xd8]`, `[rsp+0xd0]` and `[rsp+0xc8]` are produced, and whether
  the selected message is later extended with values.
- The exact path from `0x2269034` to `0x226915c`, and any jump-table edge into
  the join.
- What the logged 540/840 tolerance controls.
- Who calls `0x2271d00` and what `[rbx+0x740]+0x60` holds.
- The identities of `0x15206e0`, `0x151f870`, `0x151cba0` and `0x4ecdcf0`
  (inferred above, not proven).
