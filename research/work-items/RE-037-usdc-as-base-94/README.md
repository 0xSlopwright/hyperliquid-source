RE-037: USDC-as-base guard @ 0x274f860 (node #94)

- Component ID: RE-037 (`RE-037-usdc-as-base-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `cec50f68`; no radare2 revision (r2 not used)
- Claim: the refuse-USDC-as-base RULE only — reject when base token id is 0 (USDC) via `test rdi,rdi` / `je` to Err `0xdf` + string `cannot use USDC as base token`. HL own policy, not a vendored crate.
- Prior work: string VA `0x3eff61` / text appears only as inventory probes in merged PR #650 (spot-meta census / FDE) and #389 (length-bearing string census); no carve or rule claim at `0x274f860` there.

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 python3 tools/usdc_as_base_guard.py

# packet verify
python3 -I -B research/work-items/RE-037-usdc-as-base-94/verify.py
python3 -O -B research/work-items/RE-037-usdc-as-base-94/verify.py

# independent (stdlib only)
python3 -I -B research/work-items/RE-037-usdc-as-base-94/independent_verify.py

# unit tests (negatives + mutation/tamper; one negative for the claimed rule)
PYTHONHASHSEED=0 python3 -m unittest tests.test_usdc_as_base_guard -v
```

## Pins

- Carve: `0x274f860`..`0x274f994` (308 bytes), sha256 `28f03c90…a3cc`. Exclusive end is the first int3 after the body; 12-byte int3 pad then next function at `push r15` `0x274f9a0`.
- No GOT `R_X86_64_RELATIVE` for this entry; exactly 1 direct `e8` caller at `0x23e81f2` (`e869763600`); 0 `e9`; 0 inbound `ff15` via GOT.
- Error string (VA / len / verbatim bytes / sha256):
  - `0x3eff61` / 29 / `cannot use USDC as base token` / `e4f0351f…9d5b`. Exactly three packed occurrences (`0x3eff61`, `0x599641`, `0x715362`). LEA in carve at `0x274f960` (`488d0dfa05cafd`) targets the primary copy. Other LEAs of the duplicate copies (not claimed): `0x375ef8e` -> `0x599641`; `0x4d72180` / `0x4d722c0` -> `0x715362`.
- Rule: after `mov rax,rdi` (Result out) / `mov rdi,[rcx]` (base token id), `test rdi,rdi` at `0x274f876` (`4885ff`); `je` at `0x274f879` (`0f84dc000000`) -> `0x274f95b`. rdi==0 takes the refuse path (movw Err `0xdf` + LEA string + mov qword len `0x1d`); rdi!=0 continues past the branch.
- Tags (all movw STOREs reachable from this carve):
  - Err `0xdf` at `0x274f95b` (`66c700df00`) — USDC refuse path (CLAIMED rule).
  - Bounds Err `0xea` at `0x274f951` / `0x274f974` (`66c700ea00`) — jae OOB paths (pinned ABI; NOT claimed as a rule).
  - Success `0xac` at `0x274f8f5` (stack) / `0x274f981` (`[r15]`) — movw stores (pinned ABI; NOT a claimed rule).

## What this does not claim

- Does NOT claim a full spot-pair / market-create path end-to-end; claims the refuse-USDC-as-base RULE only.
- Does NOT claim the bounds Err `0xea` or success `0xac` paths as separate rules (observed + pinned as ABI tags only).
- Does NOT claim the near-clone LEA sites of the duplicate string copies (`0x375ef8e`, `0x4d72180`, `0x4d722c0`) as separate validators.
- Does NOT re-claim inventory probes from merged #650 / #389 (FDE/census only; no carve/rule there).
- Does NOT emulate (static pin only; no Unicorn vectors).
- No other node builds.

## Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).
