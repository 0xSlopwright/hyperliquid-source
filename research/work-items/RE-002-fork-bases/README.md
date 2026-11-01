# RE-002: fork base versions and the overflow-check setting

- Component ID: build provenance (RE-002)
- Target release and full SHA-256:
  - node #94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  - node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  - visor `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` (overflow-check fact only)
- Source commit: repository `main` at `546081f`. Upstream revisions are listed per fork below and in `fork-bases.json`.
- Claim status: observation for every binary-side fact, inference for every base-version range. No implementation and no gate.
- Scope included: base versions of the patched forks named in the RE-002 fork matrix, and the RE-002 unresolved field `overflow_checks`.
- Scope excluded: the four #115 `reth-*` fork directories (1–4 Location points each, too few to separate revisions), fork patch contents, and every other unresolved RE-002 field.

The RE-002 packet (`research/work-items/RE-002-build-provenance/README.md`) records "Base version: unknown" for every fork, and it lists `overflow_checks` as unresolved. This packet binds both to captured bytes.

## Reproduce

Run from the repository root on Linux x86-64 with the pinned LFS artifacts present. Python 3.12.3, git 2.43.0, GNU objdump 2.42 (spot checks only).

```sh
python3 tools/fork_bases.py --check              # offline: binary facts + committed upstream point set
python3 -m unittest tests.test_fork_bases -v     # 7 tests, includes corruption controls
# optional upstream comparison (network: public GitHub clones and crates.io tarballs)
sh research/work-items/RE-002-fork-bases/fetch-upstream.sh /tmp/fork-upstream
python3 tools/fork_bases.py --upstream /tmp/fork-upstream
```

The offline mode reads only the three digest-checked ELF files. It regenerates every binary-side value and checks that the committed `upstream` section covers exactly the regenerated fork points. `--upstream` recomputes the `upstream` section. Output is byte-identical under `PYTHONHASHSEED=7` and `123`. `fork-bases.json` SHA-256: `40f840af787102ecbb8bb429f611d917ab5ea1e5e9b0d16299566ff57df9d5c3`.

Captured binaries were not executed.

## Evidence

### Method: panic Location records

A Rust `core::panic::Location` is 24 bytes in `.data.rel.ro`: a file `&str` (pointer, length), then `line: u32`, `col: u32`. In these PIE files the pointer word is filled by an `R_X86_64_RELATIVE` relocation, so the tool reads the file path from the relocation addend and the length/line/column from the record. It keeps records whose path is inside a fork directory: `/home/ubuntu/hl/<fork>/` in #94 and `z_forks/<fork>/` in #115. Records at line 1–2 with column 0 are excluded, because they are not source positions.

| Capture | Fork Location records | Distinct (file, line, col) points |
| --- | ---: | ---: |
| #94 | 462 | 152 (hyper-fork 134, hyper-alloy-core-fork 12, bincode-fork 4, hyper-tls-fork 2) |
| #115 | 872 | 340 (hyper-fork 292, revm-precompile 34, bincode-fork 4, reth-* 8, hyper-tls-fork 2) |

Each point is compared with upstream source text at that line and column:

- **token-start**: the column points at the first byte of a token (or at `[`, where rustc places index-panic columns).
- **strong**: the token is a panic or log call (`unwrap`, `expect`, `panic!`, `unreachable!`, `assert`, `trace!`…`error!`).
- **best shift**: only for base revisions with misses, the constant line offset that makes strictly more points match. It shows inserted or removed lines.

### Results per fork

| Fork | Capture | Inferred base | Base score | Nearest controls (token-start/points) | Local line changes seen |
| --- | --- | --- | --- | --- | --- |
| hyper-fork | #94 | hyper **0.14.16** (code at `bff977b7`…`e8cccce0`, includes tag `41dee4a7`) | 95/116, strong 50 | `84b78b6c` 92, `f44f7265` 86, v0.14.18 89, v0.14.17 77, v0.14.15 70 | `client/client.rs` +1 line (all 12 points match at +1); `client/connect/http.rs` patched |
| hyper-fork | #115 | hyper **0.14.16** | 231/274, strong 180 | `84b78b6c` 217, `f44f7265` 208, v0.14.18 195 | as #94, plus line removals in `body/body.rs`, `common/{buf,exec,lazy}.rs`, `error.rs`, `service/oneshot.rs`, `upgrade.rs` |
| hyper-tls-fork | #94 / #115 | hyper-tls **0.5.0** line layout (`client.rs` of `83747a7` = v0.5.0, same lines through `74044e3`; `9adf50b` hyper-1 port changes them) | 2/2 at shift +1 (#94), −8 (#115) | v0.6.0: the two `async` blocks are 18 lines apart, not 15 | 1 line added (#94), 8 removed (#115) above upstream L135 |
| bincode-fork | #94 | bincode **2.0.0 or 2.0.1** (the four files are byte-identical in both) | 4/4 | 2.0.0-rc.3 1/4, 3.0.0 0/4 | none at these points |
| bincode-fork | #115 | bincode 2.0.0 or 2.0.1 | 3/4, 4/4 at `lib.rs` +1 | same controls | `lib.rs` +1 line above L170 |
| hyper-alloy-core-fork | #94 | alloy-core **0.8.20–0.8.26** (commits from `3f28b07` = v0.8.19-4 up to the v1.0.0-rc.1 parents) | 12/12 | v0.8.19 and `7edc626` 11/12 (`sol-types/src/utils.rs:28:5`), v1.0.0 11/12 (`sol-types/src/types/function.rs:56:9`) | none at these points |
| revm-precompile | #115 | revm-precompile **35.0.0–41.0.1** (revm tags v108–v113, commit `a4219239`) | 34/34 | v107 (34.0.0) and `2e72f176` 33/34 (`src/lib.rs:80:5`), v114 (42.0.0) 15/34 | none at these points |

hyper-fork detail, upstream v0.14.16 coordinates. #94 and #115 give the same `http.rs` layout:

| Upstream region of `src/client/connect/http.rs` | Fork offset after it | Evidence |
| --- | --- | --- |
| before L270 (connector fields and setters) | +10 | L270 `async move` → fork 280:27, L277 `trace!(` → fork 287:5 |
| L325–L353 | +11 | L353 `warn!("tcp set_nodelay error…")` → fork 364:13 |
| L353–L534 (`ConnectingTcp` connect path) | +42 | fork points 494:21, 515:28, 546:55, 558:85 have no upstream counterpart (fork-only code) |
| L534 to end | +42 | L534 `debug!("connected to…")` → 576:21, L606/L639/L645/L651 `warn!` → 648/681/687/693, L656 `async move` → 698:8 |

#94 also links an unpatched `hyper 0.14.29` from crates.io, so the hyper-fork base is older than the registry copy linked beside it.

### overflow_checks: enabled for every crate with arithmetic sites

Each binary contains six `core::panicking::panic_const_*_overflow` helpers. Each helper has the shape `push rbp; mov rbp,rsp; mov rdx,rdi; lea rdi,[msg]; mov esi,(2·len+1); call [got]`, and the decoded message is `attempt to {add,subtract,multiply,negate,shift left,shift right} with overflow`. For example, #94 `0x157b480` → `attempt to add with overflow`, and `0x157b520` → `attempt to subtract with overflow`. The tool counts the sites `lea rdi,[Location]; call [GOT slot of a helper]` and groups them by the origin of the Location path:

| Capture | Sites | crates.io / vendored | first-party | forks | std (inherited) | git dependency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| #94 | 45102 | 44387 (84 crates) | 245 | 247 | 214 | 9 |
| #115 | 49193 | 48019 (91 crates) | 264 | 253 | 657 | 0 |
| visor | 1556 | 1472 (45 crates) | 1 | 40 | 43 | 0 |

Spot check, #94 bincode-fork `src/lib.rs:170:22` (`src.len() - decoder.reader().slice.len()`):

```
28bc0dc: sub    0x50(%rsp),%r12
28bc0e1: jae    28bc1e3
28bc0e7: lea    0x2e0a602(%rip),%rdi   # Location 0x56c66f0
28bc0ee: call   *0x2eb205c(%rip)       # GOT 0x576e150 -> 0x157b520 (subtract)
```

The std sites are the strongest signal. They include `core/src/iter/adapters/enumerate.rs:82:9` (#94 rustc `e408947`, visor rustc `59807616`) and `:120:17` (#115). At those revisions these lines are `self.count += 1` in `Enumerate::next` and `*count += 1` in its fold closure, and both have `#[rustc_inherit_overflow_checks]`. That attribute takes the overflow setting of the crate that instantiates the generic, so the checks were on in the user crates. Release builds disable overflow checks by default.

## Implementation and comparison

Not applicable: this packet has no Rust reconstruction. `tools/fork_bases.py` is analysis tooling.

## Results and limitations

- Observation: the fork Location points and the overflow-helper call sites listed above, bound to the three digests.
- Inference: `overflow-checks = true` in the release profile, or a `[profile.release.package."*"]` override that has the same effect. Bytes alone cannot tell the two apart. The precompiled libstd is not rebuilt, so only inherited std generics show the setting.
- Inference: the base ranges in the table. Each one rests on the listed points only. Files without panic sites are not compared, so "no local changes seen" means only "none at these points".
- The matching rule is textual (token start and strong token). It is not a compiler-span model, and a few exact matches can be coincidence. That is why each claim names its controls and its deciding points.
- Not attempted: the #115 `reth-*` forks, fork patch contents, and upstream revisions beyond those listed in `fork-bases.json`.
- The hyper-tls result rests on two points plus the line distance between them.
- No progress gate is requested. `research/progress.json` is unchanged.

Next question: which bytes does the 31-line fork-only hunk in hyper-fork `src/client/connect/http.rs` (fork lines 494–558) add to the `ConnectingTcp` connect path, and what is the role of the +10 fields/setters hunk before upstream L270?
