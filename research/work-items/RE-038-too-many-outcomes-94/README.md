RE-038: too-many-outcomes (0x31 arm) @ 0x372a470 (node #94)

- Component ID: RE-038 (`RE-038-too-many-outcomes-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `cec50f68`; no radare2 revision (r2 not used)
- Claim: the too-many-outcomes count-cap RULE only (0x31 arm) — reject when outcome count > 0x31 (49) via `cmpq imm 0x31` / `jbe` continue; fall-through Err `0x17b` + string `too many outcomes for question`. HL own policy, not a vendored crate.
- Prior work: open #997 (RE-004 OutcomeDeploy) is an adjacent SIBLING covering daily deploy caps / settle gates with a different string (`too many outcomes deployed today`); it does not claim entry `0x372a470`, string `0x599484`, or this 0x31 arm. No inventory-only refs for this exact string.

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 python3 tools/too_many_outcomes.py

# packet verify
python3 -I -B research/work-items/RE-038-too-many-outcomes-94/verify.py
python3 -O -B research/work-items/RE-038-too-many-outcomes-94/verify.py

# independent (stdlib only)
python3 -I -B research/work-items/RE-038-too-many-outcomes-94/independent_verify.py

# unit tests (negatives + mutation/tamper; one negative for the claimed 0x31 arm)
PYTHONHASHSEED=0 python3 -m unittest tests.test_too_many_outcomes -v
```

## Pins

- Carve: `0x372a470`..`0x372a905` (1173 bytes), sha256 `444bf531…e00d`. Exclusive end is the first int3 after the body; 11-byte int3 pad then next function at `push rbp` `0x372a910`.
- GOT slot `0x5774a68` with `R_X86_64_RELATIVE` addend `0x372a470`; exactly 3 inbound `ff15` at `0x2719c06` / `0x4d12096` / `0x4d127a6`; 0 direct `e8` / `e9`.
- Error string (VA / len / verbatim bytes / sha256):
  - `0x599484` / 30 / `too many outcomes for question` / `cffe7f24…4899`. Exactly one packed occurrence. LEA in carve at `0x372a55c` (`488d0521efe6fc`) targets it. No duplicate copies; no not-claimed LEAs of duplicates.
- Rule (0x31 arm ONLY): `cmpq [rcx+r9*1-0x20], 0x31` at `0x372a54f` (`4a837c09e031`); `jbe` at `0x372a555` (`761d`) -> `0x372a574`. count <= 0x31 continues; count > 0x31 falls through to movw Err `0x17b` at `0x372a557` (`66c7037b01`) + LEA string + mov qword len `0x1e` at `0x372a567` (`48c743101e000000`).
- Err tag `0x17b`: movw STORE (not a compare-gate) at `0x372a557` on this arm only. Neighbouring `0x17b` stores in the same carve (fallback / associated / compatible) are observed but NOT claimed.

## What this does not claim

- Does NOT claim neighbouring Err `0x17b` arms in the same carve:
  - `0x372a580` -> `0x59945b` `cannot register fallback as named outcome`
  - `0x372a6ad` -> `0x599441` `outcome already associated`
  - `0x372a8e1` -> `0x59941d` `outcome not compatible with question`
- Does NOT claim open #997 (RE-004 OutcomeDeploy) daily deploy / settle rules or its string `too many outcomes deployed today` (sibling, different arm).
- Does NOT claim a full outcome-register / question path end-to-end; claims the 0x31 count-cap RULE only.
- Does NOT emulate (static pin only; no Unicorn vectors).
- No other node builds.

## Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).
