# RE-006: standalone node #94 order-book lifecycle component

- Component ID: `orderbook`.
- Target release and full SHA-256: node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit: upstream base `546081f30a3ebe6af1dadb6f90869f01bd08e1e4`;
  implementation commits are listed in the final PR. Reference lead pin:
  `can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: observations are inherited from the four merged digest-bound
  packets and the bounded caller window below; names and safe API boundaries
  are implementation choices; all listed gaps remain unresolved.
- Scope included: independently authored Rust for order slots, signed price
  levels, FIFO links, insert/remove/cancel, aggregate accounting, a single
  selected maker/taker step, fill records, partial/full fills, result statuses,
  relations, invariants, and deterministic snapshots.
- Scope excluded: full exchange or insertion loops, margin computation,
  reduce-only position lookup, unresolved predicates, trigger orders,
  concurrency, rollback, settlement, external side effects, and target ABI or
  binary identity.

No imported reference code was copied. The reference tree supplied search
terms only. No captured program, network service, trading path, key, or signing
operation is executed.

## Reproduce

Working directory: repository root. Recorded environment: macOS arm64; Rust
1.94.1 (`e408947bf 2026-03-25`); Cargo 1.94.1; GNU Binutils
2.47.20260726; Python 3.15.2. The Rust crate has no dependencies.

```sh
python3 tools/artifacts.py verify
python3 -I -B research/work-items/RE-006-node94-orderbook-94/verify.py
cargo test --manifest-path src/node94-orderbook/Cargo.toml
cargo clippy --manifest-path src/node94-orderbook/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-orderbook/Cargo.toml -- --check
python3 -m unittest \
  tests.test_order_book_lifecycle_94 \
  tests.test_match_resting_order \
  tests.test_user_book_cancel \
  tests.test_order_relation_transitions
PATH=/opt/homebrew/opt/binutils/bin:$PATH make verify test catalogue-check
```

The component test runs are deterministic and offline. A clean second build is
recorded in the PR qualification log. `make test` may use static disassemblers
but never executes the captured target.

## Evidence

All target addresses are linked ELF virtual addresses. For the `.text` windows
used here, file offset is virtual address minus `0x1000`. FDEs are unwind ranges,
not recovered source boundaries.

The implementation consumes these already reviewed evidence packets without
modifying them:

| Packet | Established subsystem |
| --- | --- |
| `RE-006-price-level-lifecycle-94` | `0xf8` slots; append/reuse; bid `-price`, ask `+price`; FIFO links; empty-level removal; `+0xc8` saturating aggregate |
| `RE-006-match-resting-order-94` | three copies of one match body; zero/self exits; cap ordering; fill/status record; mask bits; inclusive `0x7ffffffffffffffe` notional ceiling |
| `RE-006-user-book-cancel-94` | collect first, unsigned sort/deduplicate, then cancel in ascending order; user and slab layouts |
| `RE-006-order-relation-transitions-94` | parent/peer/children fields; reciprocal peers; child-first depth-first cascade |

### Bounded partial-fill follow-up

The match packet proves the returned fill quantity. The implementation also
needs the resting slot's quantity transition. A bounded static read of caller
FDE `0x4311140..0x4314da0` retained in `partial-fill-caller.tsv` covers
`0x4312289..0x43122ff` (118 bytes, SHA-256
`cc7957f79f8ced525c50ca8077cec35abbbc2afb38ad38e54faed2cbc25283c7`).

Within that range:

- `0x4312289` loads the returned fill quantity carried at stack `+0x530`;
- `0x4312291` loads the selected slab-slot pointer;
- `0x4312296` loads its qword at verified quantity offset `+0xc8`;
- `0x431229d` subtracts the fill quantity, with `0x43122a0` selecting the
  no-borrow path and `0x43122b6` producing zero on underflow;
- `0x43122bf` reloads the slot pointer and `0x43122d7` calls the following
  update helper with the remaining value in `rdx`.

This closes the bounded quantity-decrement observation used for partial-fill
accounting. The called helper's full behavior, event construction after this
window, and the surrounding loop remain unresolved. The Rust component rejects
arithmetic states outside its checked invariants instead of reproducing target
panic/diagnostic side effects.

## Implementation and comparison

- Independent Rust path: `src/node94-orderbook/`.
- Manifest and lock: component-local `Cargo.toml` and dependency-free
  `Cargo.lock`; edition 2024; `rust-version = 1.94.1`.
- Safe representation: not `repr(C)` and not ABI compatible. `layout.rs` keeps
  verified target offsets without conflating them with Rust layout.
- Signed price maps: both sides use ascending `BTreeMap<i64, _>` order, with
  bids negated and asks positive as observed.
- Slot removal validates both neighbors and the level endpoints before writes.
  Vacant slots are threaded through the observed LIFO free-list shape.
- Global quantity uses observed saturating add/subtract. Per-level quantity in
  snapshots is derived, not claimed as a target field.
- Match limits are explicit inputs representing external helper results. The
  crate does not infer margin or position logic. Reduce-only matching is
  rejected because its signed-position dependency is not present.
- Full fills unlink and free the resting slot; partial fills subtract the
  returned fill quantity from slot and global totals.
- Target comparison: no raw or normalized Rust-to-target body match is claimed
  or measured. The target ABI, compiler flags, helper closure, relocations,
  unwind data, and surrounding call graph are not reconstructed.

The test denominator is the number reported by `cargo test`. It covers every
supported transition family, exact target constants, head/middle/tail/singleton
unlink, LIFO reuse, both best-price orderings, partial/full fill accounting,
status-bearing fills, early exits, user cancellation, cascade order,
deterministic snapshots, a long deterministic lifecycle, and corruption of
queues, reachability, aggregates, free lists, and neighbor links.

## Results and limitations

- No component or repository progress gate is requested; all incomplete gates
  remain false.
- Duplicate target behavior is unknown. The library rejects duplicate IDs
  atomically and labels that outcome unsupported rather than assigning a target
  status.
- Equal-user self-cross is supported. The unresolved external predicate from
  the match body is not modeled.
- Margin, leverage, oracle, position, and fill-mask computations are external.
  Only the verified consumption of their supplied results is implemented.
- The selected match step does not assert price crossing; selection belongs to
  the unimplemented surrounding loop. It consumes at most one best FIFO head.
- Relation names are inferred. Stale references to absent relation targets are
  tolerated where target packets showed lookup-and-skip behavior; live
  reciprocal relations are checked.
- Target diagnostic/panic side effects are represented as typed Rust errors.
- No full source, binary equivalence, safety, consensus, or production-readiness
  claim is made.

Next question: close the price-crossing and repeated-level walk around the
already established single match body without overlapping pending perp/spot
insertion research, then bind its exact full-fill status/removal reason.

