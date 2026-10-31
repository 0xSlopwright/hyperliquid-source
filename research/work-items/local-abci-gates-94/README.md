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
- Scope: twenty-three fixed windows in `0x22689f0` (the lead's
  `local_abci_state.rs` seed), `0x2271d00`, its caller `0x22ae8a0` and the
  panic shim `0x157b810`.
  Excluded: what `0x226bb20` sends and decodes, how the timestamp is produced, what the
  logged tolerance is used for, the rest of the `0x22ae8a0` state machine, and
  release #115.

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

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 23
windows (950 instructions), one per checked byte window. All 47 `records.json`
VAs that fall inside a window are instruction starts there, except `slot_refs`
entries, which are ModRM-byte addresses inside instructions. The other code VAs
are FDE starts, call targets and branch targets outside the windows.

Format templates are decoded as rustc 1.94 packs them: a byte below 0x80 is a
literal length, and `0xc0` is a placeholder followed by the length of the next
literal; `0x00` ends the template. Every literal length decodes to printable
text that ends exactly at the next marker. Reading placeholder *k* as format
argument *k* is an inference.

## Evidence

### How `ip_to_heights` is filled (observation)

The peer loop `0x2269cd8..0x226a41a` runs before the selection below.

1. **Peer list:** `0x2269c63` stores `[[rbx+0x3c30]]` to `[rbx+0x49c8]` and
   clears the map root and length (`[rbx+0x49b0]`, `[rbx+0x49c0]`). The list's
   data pointer is `[+0x8]` and its length `[+0x10]`; entries are 5 bytes
   (`lea rcx,[rcx+rcx*4]`, stride `lea rcx,[rax+0x5]`). An empty list goes
   straight to the `got heights` log (`0x2269cd2 → 0x226a41a`). Each entry's
   first 4 bytes and fifth byte are copied to `[rbx+0x49d0]` and
   `[rbx+0x49d4]`.
2. **Query:** the code logs `… @@ querying height @@ [rpc_ip: {}]` (template
   `0x1dd96c`, argument `&[rbx+0x49d0]`). It then stores 2 to `[rbx+0x3c88]`
   and calls `0x226bb20` (`0x2269e87`). That FDE, `0x226bb20..0x226c2c8`,
   contains the `gossip_rpc_request` 10.0 s timeout window `0x226bb82` checked
   by [#211](https://github.com/lalalune/hyperliquid-source/pull/211). A
   result word equal to `r12 + 0x41` goes to `0x226a8bc` (pending). All
   three paths back to the next peer set `r12 = 0x8000000000000000`
   (`0x2269fe2`, `0x226a079`, `0x226a2dc`). Its value on the first entry is
   not checked.
3. **Reply:** a result word other than `0x8000000000000040` goes to the error
   log (`0x2269f4e → 0x226a1fa`). Otherwise `[rsp+0x128]` must be 2, else the
   30-byte `incorrect rpc response variant` (rebuilt from `0x3d79ef` and
   `0x3d79fd`) goes to the same log. If bit 0 of `[rsp+0x130]` is set,
   `0x28523b0` is called with `&[rbx+0x49b0]`, the current peer and the
   values `[rsp+0x138]`, `[rsp+0x140]` (`0x2269fdd`), then the next peer
   (`0x226a403`). If clear, the code logs
   `… ERROR >>> … @@ no heights from node @@ [rpc_ip: {}]` (template `0x1ebdb6`)
   and moves on to the next peer.
4. **Errors:** both error cases log
   `… ERROR >>> … @@ unable to query height: {} @@ [rpc_ip: {}]` (template
   `0x1ee557`) and continue with the next peer (`0x226a414 → 0x2269cd8`).
5. **No local-height filter:** no `[rbx+0xb0]` (local height) operand appears
   anywhere in `0x2269cd8..0x226a41a`.

So `[[[rbx+0x49c8]]+0x10]`, used by the single-entry exception below, is the
number of peers queried. Inference: `0x28523b0` is a `BTreeMap` insert keyed
by peer IP, the reply is `Option<(initial_height, latest_height)>`, and
request tag 2 asks for heights. Model `collect_heights` checks the
skip/insert rules.

### Where `initial_height` and `latest_height` come from (observation)

Window `0x226a53f..0x226a6d2` follows the `got heights` log (template
`0x1e7641`, `… @@ got heights @@ [ip_to_heights: {}]`, whose argument is
`&[rbx+0x49b0]`). It reads `[rbx+0x49c0]`, the length word of the map whose
root and height are `[rbx+0x49b0]` and `[rbx+0x49b8]`:

1. **Guard:** length > 1 goes to the loop (`ja` at `0x226a54f`). Length 0 goes
   to `0x226a6d2` (`0x226a551`). Length 1 goes to the loop only if
   `[[[rbx+0x49c8]]+0x10] == 1`; otherwise also to `0x226a6d2` (`0x226a566`).
2. **Selection:** an iterator over the map is built on the stack and advanced
   by calls to `0x27df4f0` (`0x226a5df`, `0x226a659`, `0x226a68a`), each
   returning `rdx` as a value pointer. `r15 = [rdx]`, `r14 = [rdx+8]` from the
   first entry. For each later entry `(rbp, r13) = ([rdx], [rdx+8])`, the
   current pair is kept only if `r15 > rbp`, or `r15 == rbp` and `r14 > r13`
   (`seta`/`seta`/`cmove` at `0x226a691..0x226a6a0`). Otherwise both are
   replaced (`cmove` at `0x226a6a6`, `0x226a6aa`). The loop back-edge is
   `0x226a6b6 → 0x226a680`.
3. **Error:** `0x226a6d2` allocates 43 bytes and copies three 16-byte pieces
   from `0x3d7964`, `0x3d7974` and `0x3d797f` to offsets 0, 0x10 and 0x1b.
   Together they read `unable to find at least 2 valid rpc heights`. The tool
   rebuilds the string from the three `movups` operands.
4. **Result:** `0x226a719` stores `r13`, `r15`, `r14` and 0x2b to
   `[rbx+0x3bd8..0x3bf0]`. On the loop path `r13 = 0x8000000000000040` and
   `r12b = 1`. On the error path `r15 = 0x2b` and `r14` is the string
   pointer, and `r12b = 0`. A set `r12b` jumps to `0x226a912` (`0x226a74d`).
   The only call in between is `0x28b37f0`, and `r14` and `r15` are
   callee-saved. That window reaches the status-log window at `0x226a974`
   without writing `r14` or `r15`, which are then logged as `initial_height`
   and `latest_height`.
5. **Retry:** the error path (`0x226a753..0x226a8bc`) formats
   `AsyncSleepRetry::retry desc=[…] n_tries=…` (template `0x1f2256`, LEA at
   `0x226a7eb`) and jumps back to `0x2269bcc` (`0x226a8b7`).

Model (`select_heights`): with `values` in iteration order, the pair used is
the lexicographic maximum of `(initial_height, latest_height)`. It is
checked against Python `max` on 500 random lists. Inference: the map is a
`BTreeMap` keyed by peer, from the `{root, height, length}` layout and the
`ip_to_heights` label. `[[[rbx+0x49c8]]+0x10]` is the queried peer count (see above).

### The three heights are named by the status log (observation)

Window `0x226a974..0x226ab0a` runs straight up to the gate. It:

- stores `r15` to `[rsp+0xc8]`, `r14` to `[rsp+0xd0]`, and `[rbx+0xb0]` to
  `[rsp+0xd8]`;
- passes pointers to those three slots as arguments 2, 3 and 4 of a log call
  (`0x226aad8`, template `0x1ef6dd`);
- then frees a buffer and reaches `0x226ab0a`.

The template decodes to
`{} WARN >>> {} @@ queried gossip status @@ [local_height: {}] @ [initial_height: {}] @ [latest_height: {}]`.
Its placeholders 2, 3 and 4 are labelled `local_height`, `initial_height`
and `latest_height`.

A scan of the whole FDE for `[rsp+disp32]` operands with these three
displacements finds only the three stores, the three LEAs and the gate's four
reads. No other instruction names these slots. Aliasing through a different
base register is not excluded.

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

With the status-log labels above (placeholder *k* read as argument *k*), the
rule is: too far behind iff
`local_height.saturating_add(20000) <= latest_height`; otherwise stale
hardfork iff `local_height < initial_height`.

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

### Where the freshness check runs (observation)

- **Dispatch:** `0x2271d00` dispatches on the byte `[rdi+0x756]` through the
  table at `0x3d5f10`. Entry 0 is `0x2271d38`, which runs straight-line into
  the freshness window.
- **Strings:** the same FDE LEAs `check_reachability_firewall_ips`
  (`0x2271f1e`) and `failed to load firewall ips` (`0x22722c1`).
- **Callers:** a scan of every `e8`/`e9` in `.text` finds exactly two direct
  calls to `0x2271d00`, both in `0x22ae8a0`, at `0x22aef61` and `0x22affe7`.
  The lead calls `0x22ae8a0` the hl-node startup orchestrator. After each
  call, a set `al` leads to `mov cl,0xa` or `mov cl,0xb` and a jump to
  `0x22b02dd`.
- **Second call site:** the second call follows a log call whose template
  (LEA at `0x22aff7c`, outside the checked windows and not checked by the tool)
  reads `@@ checking reachability first before changing validator ip from {} to {}`.

Inference: following rustc's async layout, state 0 is the first poll. So the
600 s freshness panic is the first step of the future the lead names
`poll_check_reachability_firewall_ips`. The orchestrator polls it from two
states, 0xa and 0xb, and treats a set `al` as pending.

## Comparison with the lead

- **Height quorum:** `startup.rs` `select_height_quorum` keeps fresh
  statuses, errors if fewer than `MIN_VALID_RPC_HEIGHTS = 2`, sorts by
  `latest_height` and takes the median `fresh[len / 2]`. The binary takes the
  lexicographic maximum of `(initial_height, latest_height)` over all map
  entries. It accepts a single entry when exactly one peer was queried. Its
  error path retries through `AsyncSleepRetry` instead of returning. For
  example, entries `(1, 100), (2, 3), (1, 200)` give the median `(1, 100)` in
  the lead's model but `(2, 3)` in the binary. - **Height collection:** the lead's `query_root_heights` returns an error from
  the whole startup on any RPC error. It records a `None` reply as Missing and
  classifies a status as Stale when `latest_height + MAX_LOCAL_HEIGHT_LAG <
  local_height`. The binary logs `unable to query height` and skips the peer
  on an error or a wrong reply variant. It logs `no heights from node` and
  skips the peer on an empty reply. It does not read the local height in the
  loop, so it has no stale filter there.
- **0x4e20:** `NODE_IP_FRESHNESS_TOLERANCE = Duration::from_secs(0x4e20)`
  cites "`add 0x4e20` in the stale-time branch at `0x226ab1d`". That `add` is
  the height gate above: its saturating sum is compared with `[rsp+0xd0]` and
  selects `local height is too far behind`. No time value is involved in that
  window.
- **Freshness check:** the lead's `StateFileTooOld` (age > 0x4e20 s,
  returned as a stale reason) does not match the binary. In the binary the
  `use an abci state within … seconds` message belongs to a 600 s check that
  panics at `hl_node.rs:346:9`, at the start of the future the lead itself
  names `poll_check_reachability_firewall_ips` (in `hl_node.rs`). The lead
  places the message in `local_abci_state.rs`.
- **Height lag:** `MAX_LOCAL_HEIGHT_LAG` is 200 in `local_abci_state.rs` and
  1_000 in `startup.rs`; the binary uses 20000. `startup.rs:500` tests
  `target - local > LAG`. The binary rejects at
  `local_height.saturating_add(20000) <= latest_height`, which includes
  equality: for example, local 0 and latest 20000 is "too far behind".
  The binary logs the compared value as `latest_height`; the lead calls it
  `target_height`.
- **Stale hardfork:** the lead's stale-hardfork reason compares the local
  height with a peer initial height. That matches the operand order here
  (`local_height < initial_height`, tested only when not too far behind).

## Controls

`tests/test_local_abci_gates_static.py` (37 tests) regenerates
`records.json` and checks five models: the peer-reply collection, the height selection, the height gate
including saturation, the day division against exact truncating division,
and the lexicographic compare. It refuses each of these corruptions:

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
- An extra direct call to `0x2271d00` planted.
- A status-log argument pointer swapped.
- A status-log field label broken.
- An extra height-slot operand planted.
- Dispatch-table entry 0 moved.
- The selection loop's `seta` changed to `setb`.
- A byte of the 43-byte heights error changed.
- The `AsyncSleepRetry::retry` or `got heights` template changed.
- A byte of `incorrect rpc response variant` changed.
- The `no heights from node` template changed.
- A `[rbx+0xb0]` operand planted in the peer loop.
- The request tag changed to 3.

The module passes with GNU binutils or with LLVM tools only on `PATH`; the
producer does not use either.

## Unresolved

- What `0x226bb20` sends for request tag 2 and how it decodes the reply,
  where `[rbx+0x3c30]`'s peer list comes from, and whether the selected
  message is later extended with values.
- The exact path from `0x2269034` to `0x226915c`, and any jump-table edge into
  the join.
- What the logged 540/840 tolerance controls.
- What `[rbx+0x740]+0x60` holds, and which orchestrator paths reach states
  0xa and 0xb.
- The identities of `0x15206e0`, `0x151f870`, `0x151cba0` and `0x4ecdcf0`
  (inferred above, not proven).
