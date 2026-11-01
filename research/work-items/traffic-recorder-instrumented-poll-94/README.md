# transport: node #94 traffic-recorder seed `0x3d13cd0` is tokio-metrics 0.3.1 `Instrumented<F>::poll` (the `xchg(0)` word is `woke_at` in nanoseconds, not a byte count; `0x3d21670` is the same `traffic_recorder.rs:62:47` future out of line)

Question: what does the `net_utils/tcp/traffic_recorder.rs` seed `0x3d13cd0`
account? The can1357 lead (`net_utils/tcp/traffic_recorder.rs`, header) says
it is a "per-recorder async poll/update path" that "initializes a one-shot
first-sample flag, atomically drains the pending byte counter with
`xchg(0)`, updates multiple `Arc<AtomicU64>` counters" and polls a 30 s
sleep. It also says `0x3d21670` is a separate "report task".

[PR 585](https://github.com/lalalune/hyperliquid-source/pull/585) kept that
reading: it treated the drained value as bytes and the `+0x80`/`+0x88`
totals as byte totals. It was closed as invalid. The review showed that the
amount added is an elapsed time computed from both seconds and nanoseconds,
and gave a counterexample: drained 1000, sample (0 s, 100 ns), helper result
(0 s, 250 ns), threshold (0 s, 500 ns) adds 250, not 1000. This packet
explains that arithmetic.

- Component ID: `transport` (`docs/COMPONENTS.md`; path rule `net_utils/*`).
  `research/catalogue/seed-candidates.json` lists `0x3d13cd0`, `0x3d21670`,
  `0x3d0eee0`, `0x3d1da50`, `0x3d1dde0` and `0x3d1e500` for this file. No
  merged packet or open PR covers them.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `cec50f68`. Reference lead: `references/can1357-hl`
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for claims to test.
- Public comparison source: the crates.io archive `tokio-metrics-0.3.1.crate`
  (SHA-256 `eace09241d62c98b7eeb1107d4c5c64ca3bd7da92e8c218c153ab3a78f9be112`,
  MIT). It was read to name the steps. No code from it is copied here, and it
  is not vendored.
- Companions:
  - `connections-accept-metrics-94` (PR 604) decoded the same `RawMetrics`
    updates in the accept-loop copies `0x203f3e0`/`0x2041c60`. Its offsets
    agree with the table below.
  - `lz4-stats-report-94` (PR 665) found `0x3d12780` to be the instrumented
    twin of the LZ4 report loop `0x3d21990`.
  - This packet adds `State`, `on_wake`, the meaning of the swapped word,
    the waker-vtable census, and the traffic-recorder and `lu.rs` copies.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `transport` research; no gate changes.
- Scope (9 windows):
  - the whole FDEs `0x3d13cd0..0x3d1438d` and `0x3d14390..0x3d14819`;
  - the waker functions `0x3d0a2e0` (`wake_by_ref`), `0x3d0a2d0` (`wake`) and
    `0x3d0a2b0` (`drop`);
  - `0x4ee3800` up to its `ret` and `0x4ee3730` (whole FDE);
  - the resume panics in `0x3d21520` and `0x3d21670`.
  - Also checked: the three path strings, every `task.rs` and
    `traffic_recorder.rs` Location, the `lu.rs:199:21` Location, the std
    instant-add Location and message, the waker vtable, the `clock_gettime`
    GOT slot, and a whole-`.text` census of references and direct callers.
- Excluded:
  - the sleep poller `0x3d0eee0`, the bucket drain `0x3d2b7b0` and the
    formatters `0x3d1da50`, `0x3d1dde0` and `0x3d1e500`;
  - the bodies of `0x3d21520` and `0x3d21670` past their panic sites;
  - the other four copies (`0x3d12780`, `0x3d12f20`, `0x3d133b0`,
    `0x3d13840`) beyond the census and their one inner call, and the task
    harness callers.

## Reproduce

```sh
make verify
python3 tools/tokio_metrics_poll_static.py --json > research/work-items/traffic-recorder-instrumented-poll-94/records.json
python3 -m unittest tests.test_tokio_metrics_poll_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` and `GLOB_DAT` entries. It never executes the target. It
needs only Python 3 (run here with 3.14.7 on macOS arm64; about 2 s).
`records.json` is its complete output, and the test suite regenerates it and
compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
9 windows (815 instructions, 3389 bytes), one for each checked byte window.
All 230 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 169 decoded call, branch and
RIP-relative operands, and every instruction it checks, lies inside a checked
window.

## Evidence

### Strings and Locations (observation)

| VA | Text |
| --- | --- |
| `0x1ea69a` | `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-metrics-0.3.1/src/task.rs` |
| `0x1e0680` | `/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/traffic_recorder.rs` |
| `0x1e4dcc` | `/home/ubuntu/hl/code_Mainnet/base/src/lu.rs` |
| `0x7ce45a` | `overflow when adding duration to instant` (0x28 bytes) |

Every RELATIVE-backed Location whose file is `task.rs`: `0x566d448`,
`0x5691708`, `0x5718a60` and `0x571c688` (all line 2483, column 23), and
`0x5756030` (1888:32). Every Location whose file is `traffic_recorder.rs`:
`0x5718be8` and `0x57193f8`, both 62:47. `0x57192b0` is `lu.rs:199:21`.
`0x5753120` is std `time.rs:429:33`.

Inference: in tokio-metrics 0.3.1, `src/task.rs` line 2483 is
`let idle_ns = woke_at - *idled_at;`, and column 23 is `woke_at`. Overflow
checks are on, so every monomorphized `instrument_poll` carries this
Location.

### Census (observation)

The census covers every disp32 in `.text` that follows a RIP-relative ModRM
byte after `48/4c 8d` (`lea`), and every `e8` call.

- **Copies.** 66 FDEs reference one of the four `task.rs:2483:23`
  Locations. Six of them reference `0x5718a60`, once each: `0x3d12780`,
  `0x3d12f20`, `0x3d133b0`, `0x3d13840`, `0x3d13cd0` and `0x3d14390`.
- **Waker vtable.** Those six FDEs, plus `0x3d0dff0`, are the only users of
  the vtable `0x5718a40`. Its RELATIVE slots hold `0x3d0dff0`, `0x3d0a2d0`,
  `0x3d0a2e0` and `0x3d0a2b0`, in `RawWakerVTable` order: clone, wake,
  wake_by_ref, drop. Apart from `0x5718a50` (`0x3d0a2e0`), no RELATIVE slot
  holds any function in the table below.
- **`traffic_recorder.rs:62:47`.** `0x5718be8` is referenced only at
  `0x3d13fdd` (in `0x3d13cd0`), and `0x57193f8` only at `0x3d216ca` (in
  `0x3d21670`).

| Function | Direct callers |
| --- | --- |
| `0x3d13cd0` | `0x3cfd416` (in `0x3cfd380`) |
| `0x3d14390` | `0x3cfddf4` (in `0x3cfdd60`) |
| `0x3d21520` | `0x3d136cc` (in `0x3d133b0`), `0x3d146ac` (in `0x3d14390`) |
| `0x3d21670` | `0x3d13b5c` (in `0x3d13840`) |
| `0x3d21990` | `0x3d1323c` (in `0x3d12f20`) |
| `0x3d0a2e0` | none (reached through the vtable) |

### Helpers (observation)

- `0x4ee3800` calls `clock_gettime` (GOT `0x576ea88`) with the caller's
  `edi`. Every call here passes 1 (`CLOCK_MONOTONIC`), so this is
  `Instant::now`.
- `0x4ee3730(out, a, b)` compares `(secs, nanos)`. When `a >= b` it writes
  tag 0 and `a - b`, borrowing a second when needed. Otherwise it calls
  itself with the arguments swapped and writes tag 1. This is std
  `Timespec::sub_timespec`.
- **Saturation.** After every `sub_timespec` below, a non-zero tag selects 0
  (`cmovne`), so `a - b` saturates at zero. Converting to `u64` nanoseconds
  multiplies by 10^9 and adds the nanos. A carry into the high word gives
  `u64::MAX` (`neg`/`sbb`/`or`).
- **Seconds and remainder.** `(x >> 9) * 0x44b82fa09b5a53 >> 75` is
  `x / 10^9`, and the remainder is `x - q * 10^9`.

### `0x3d13cd0` accounting (observation)

Register roles at entry:

- `rbx` is the instrumented future (`self`) and `r15` is the context;
  `r13 = [rbx]` is the `ArcInner` of `State`.
- `instrumented_at` is read from `r13+0x38` (secs) and `r13+0x40` (nanos),
  and the metrics `ArcInner` from `r13+0x30`. "Metrics" below means offsets
  into that `ArcInner`.

The steps, in order:

1. `poll_start = Instant::now()`.
2. **First poll.** If `[rbx+0x168]` is 0, it sets it to 1. It adds the
   saturating `poll_start - instrumented_at` nanoseconds to metrics `+0x58`,
   then increments `+0x18`.
3. **Swap.** `rcx = xchg([r13+0x10], 0)`.
4. **Idle.** If `[rbx+0x160] < rcx` (branch `jae` past), it increments
   `+0x20` and adds `rcx - [rbx+0x160]` to `+0x60`. The subtraction is
   checked: the borrow branch goes to the panic with Location `0x5718a60`
   (`task.rs:2483:23`).
5. **Not woken.** If `rcx == 0` it skips to step 7.
6. **Scheduled.**
   - It increments `+0x28` and builds `instrumented_at + (rcx / 10^9 s,
     rcx % 10^9 ns)`, with a carry when the nanos reach 10^9. Both additions
     overflow-check into `overflow when adding duration to instant`
     (`time.rs:429:33`).
   - `d` is the saturating `poll_start - that instant`, in u64 nanoseconds,
     split back into seconds and nanos.
   - `d` is compared with metrics `+0xa0` (secs) and `+0xa8` (nanos). At or
     above it, `+0x40` is incremented and `d` added to `+0x88`; below it,
     `+0x48` and `+0x80`. `d` is always added to `+0x68`.
7. **Register.** `AtomicWaker::register`: `cmpxchg(0 -> 1)` on `r13+0x28`,
   with the stored waker at `r13+0x18`/`+0x20` and `will_wake` by
   vtable and data.
8. **Instrumented waker.** It builds a context from the vtable `0x5718a40`
   with data `r13+0x10`.
9. `inner_poll_start = Instant::now()` (`r15`/`ebp`).
10. **Inlined future.** The state byte `[rbx+0x158]`:
    - 0 arms a `30.0` f64 sleep at `+0xb8`;
    - 3 polls it through `0x3d0eee0`;
    - any other value panics with `traffic_recorder.rs:62:47`.

    When the sleep poll returns 0 (inference: `Ready`), it takes the one-byte lock `0x5786480`, drains
    through `0x3d2b7b0`, unlocks, formats through `0x3d1da50`, re-arms
    30.0 s and polls again (`jmp 0x3d1402d`).
11. **Pending.** It sets the state byte to 3 and takes
    `inner_poll_end = Instant::now()`.
    - It stores the saturating `inner_poll_end - instrumented_at`
      nanoseconds in `[rbx+0x160]`.
    - `p = inner_poll_end - inner_poll_start` is compared with metrics
      `+0x90`/`+0x98`. At or above it, `+0x38` is incremented and the `p`
      nanoseconds added to `+0x78`; below it, `+0x30` and `+0x70`.
    - It returns `al = 1`. This is the only `ret` in the FDE; every other
      exit panics or unwinds.

### `0x3d14390` (observation)

`0x3d14390` performs the same steps 1–9 and 11. The differences:

- It keeps `State` at `[rbx+0xd8]`, `idled_at` at `+0xe0` and
  `did_poll_once` at `+0xe8`.
- Its future is at `rbx+0` and is not inlined: it calls `0x3d21520`, saves
  the returned byte, does step 11 unconditionally, and returns that byte.
- `0x3d21520`'s bad-state panic uses `lu.rs:199:21`.

### `0x3d0a2e0`, the `wake_by_ref` entry (observation)

- `rbx` is the data pointer (`State` `ArcInner + 0x10`).
- It takes `Instant::now()` and computes the saturating difference from
  `[rbx+0x28]`/`[rbx+0x30]` (`instrumented_at`).
- If the nanoseconds fit in a u64, it does `cmpxchg([rbx], 0 -> ns)`.
- It then ORs 2 into `[rbx+0x18]` with a `cmpxchg` loop. If the old state
  was 0, it takes the waker at `[rbx+8]`/`[rbx+0x10]`, clears the 2 and
  tail-calls the waker's `wake`. Inference: this is futures-core
  `AtomicWaker::wake` (WAITING 0, REGISTERING 1, WAKING 2); the binary holds
  the path `futures-core-0.3.31/src/task/__internal/atomic_waker.rs`.
- `0x3d0a2d0` subtracts 0x10 from the data pointer and jumps through slot
  `0x576f2a0`. `0x3d0a2b0` decrements the strong count at `data - 0x10`.

### Reading (inference)

Each step matches tokio-metrics 0.3.1 `instrument_poll` and
`State::on_wake`, in source order. With the 16-byte `ArcInner` header, the
offsets are:

| `State` `ArcInner` | Field |
| --- | --- |
| `+0x10` | `woke_at: AtomicU64` (ns since `instrumented_at`) |
| `+0x18`, `+0x20`, `+0x28` | `waker: AtomicWaker` (waker vtable, data, state) |
| `+0x30` | `metrics: Arc<RawMetrics>` |
| `+0x38`, `+0x40` | `instrumented_at: Instant` |

| `RawMetrics` `ArcInner` | Field |
| --- | --- |
| `+0x18` | `first_poll_count` |
| `+0x20`, `+0x28` | `total_idled_count`, `total_scheduled_count` |
| `+0x30`, `+0x38` | `total_fast_poll_count`, `total_slow_poll_count` |
| `+0x40`, `+0x48` | `total_long_delay_count`, `total_short_delay_count` |
| `+0x58` | `total_first_poll_delay_ns` |
| `+0x60`, `+0x68` | `total_idle_duration_ns`, `total_scheduled_duration_ns` |
| `+0x70`, `+0x78` | `total_fast_poll_duration_ns`, `total_slow_poll_duration` |
| `+0x80`, `+0x88` | `total_short_delay_duration_ns`, `total_long_delay_duration_ns` |
| `+0x90`, `+0xa0` | `slow_poll_threshold`, `long_delay_threshold` (`Duration`) |

`instrumented_count` and `dropped_count` are not touched by these functions,
so their offsets are not claimed.

- `[rbx+0x160]` is `idled_at` and `[rbx+0x168]` is `did_poll_once`.
- The inlined future in `0x3d13cd0` is an `async` block at
  `traffic_recorder.rs:62:47` that loops on a 30 s sleep and a report, so it
  never completes. The `Ready` arm of `instrument_poll` is unreachable and was
  removed.
- `0x3d21670` is the same block compiled out of line. Its only direct caller
  is the copy `0x3d13840`, so it is also wrapped by a `TaskMonitor`.
- So the six `0x5718a60` copies pair up by future:
  - the LZ4 report loop: inlined in `0x3d12780` (PR 665), and out of line
    as `0x3d21990` under `0x3d12f20`;
  - the traffic logger: inlined in `0x3d13cd0`, and out of line as
    `0x3d21670` under `0x3d13840`;
  - the `lu.rs:199:21` future `0x3d21520`, under both `0x3d133b0` and
    `0x3d14390`.
- Neither seed reads or writes per-connection byte counts; whatever records
  the traffic is outside this packet. The `+0x58..+0x88` totals are
  durations in nanoseconds.

## Lead and PR 585 check

| Claim | Binary |
| --- | --- |
| `0x3d13cd0` is a per-recorder poll/update path | It is `Instrumented<F>::poll`, with the traffic-logger loop inlined as `F` |
| One-shot first-sample flag | `did_poll_once` at `+0x168`; it adds the first-poll delay to `+0x58` and increments `+0x18` |
| `xchg(0)` drains a pending byte counter | It swaps `State.woke_at`, which only `on_wake` writes, as `instrumented_at.elapsed()` in ns |
| The waker under an atomic state word | `AtomicWaker::register` at `State+0x18` (`ArcInner+0x28`) |
| PR 585: `+0x80`/`+0x88` are byte totals, chosen by whole seconds | They are the short/long scheduling-delay totals; the seconds and nanos of the delay are both compared with `long_delay_threshold` |
| PR 585: the budget at `+0x160` | `idled_at`: `inner_poll_end - instrumented_at` in ns, written on every Pending |
| PR 585: the second copy at `0x3d14390` | Another `instrument_poll`, but over `0x3d21520` (`lu.rs:199:21`), not the traffic recorder |
| `0x3d21670` is a separate report task | The same `traffic_recorder.rs:62:47` future, out of line, under the copy `0x3d13840` |

## Models

`instrument_poll` in the tool follows the steps above, with `Instant`
values as `(secs, nanos)`. The tests check:

- the PR 585 review counterexample: 250 ns goes to the short bucket and the
  scheduled total, and the PR 585 reading adds 1000;
- the boundaries: a delay equal to `long_delay_threshold` is long, a poll
  equal to `slow_poll_threshold` is slow, and `idled_at == woke_at` is not
  an idle;
- `woke_at == 0` is not scheduled, and a wake instant after `poll_start`
  saturates to 0 (short bucket);
- the first poll's delay and the new `idled_at`;
- the seconds magic against `divmod` at the boundaries, and the instant-add
  overflow;
- `on_wake`: the first wake sets `woke_at`, later wakes keep it, and an
  earlier clock gives 0.

## Unresolved

- Which value each `TaskMonitor` is built with (`slow_poll_threshold`,
  `long_delay_threshold`) and where its metrics are read or reported.
- Why each future has two instrumented copies, and which spawn site uses
  which.
- The other three `task.rs:2483:23` Location groups (60 FDEs) and what they
  instrument.
- What the traffic-logger loop drains from `0x3d2b7b0` and how `0x3d1da50`
  formats it. Also: whether the `tcp_traffic` / `In` / `Out` strings belong
  to it, and where per-connection traffic is actually recorded.
- What `lu.rs:199:21` is, and the task harness callers `0x3cfd380` and
  `0x3cfdd60`.

## Controls

`tests/test_tokio_metrics_poll_static.py`: 41 tests: 10 model tests, 6
result tests and 25 corruption controls. The corruption tests reject:

- changed window bytes, and an operand outside every window;
- re-pinned rewrites:
  - swapped short/long buckets, and the idle branch;
  - the `did_poll_once`, `woke_at` and `instrumented_at` offsets;
  - the long- and slow-threshold fields, and the long-threshold nanos
    branch;
  - the scheduled saturation, the waker vtable `lea` (by the census and by
    the copy check), and the inner-future call (by the census and by the copy
    check);
  - the Pending return, the 30.0 s constant, `on_wake`'s overflow test, and
    `sub_timespec`'s Ok tag;
- the Location line, a Location's file, the `lu.rs` Location, a vtable
  slot, the instant-add message, a stray `lea` to `0x5718a60` and a stray
  `call` to `0x3d13cd0` planted in int3 padding, and a wrong identity hash.
