# RE-033: sub-deployer set guards @ 0x37186d0 (node #94)

- Component ID: RE-033 (`RE-033-sub-deployer-guards-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `546081f3`; no radare2 revision (r2 not used)
- Claim: the sub-deployer set RULES only — reject duplicate sub-deployer, reject setting the deployer as a sub-deployer, and early-reject when the network/kind byte equals 3. Optional sibling pin for "too many sub-deployers". HL's own policy, not a vendored crate.
- Prior work: #969 (merged) covers deployer fee-share / fee-recipient admission — adjacent deployer-policy, different function.

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 python3 tools/sub_deployer_guards.py

# packet verify
python3 -I -B research/work-items/RE-033-sub-deployer-guards-94/verify.py
python3 -O -B research/work-items/RE-033-sub-deployer-guards-94/verify.py

# independent (stdlib only)
python3 -I -B research/work-items/RE-033-sub-deployer-guards-94/independent_verify.py

# unit tests (negatives + mutation/tamper; one negative per rule)
PYTHONHASHSEED=0 python3 -m unittest tests.test_sub_deployer_guards -v
```

## Pins

- Carve: `0x37186d0`..`0x3718e27` (1879 bytes), sha256 `62308cdc…b2d0`. Exclusive end is the first int3 after the body; pad then next function at `push r15` `0x3718e30`.
- GOT `0x5774bc8` ← RELATIVE addend `0x37186d0`; 3 `ff15` sites (`0x2740d6b`, `0x4d52ef5`, `0x4d58915`); 0 direct `e8`/`e9` (references-TO-the-entry).
- Early-reject: `cmpb $0x3, 0x230(rsi)` at `0x37186e7` → `movw $0xe3,(r14)` at `0x37186f0`.
- Error strings (VA / len / verbatim bytes):
  - `0x59900b` / 22 / `duplicate sub-deployer`
  - `0x599021` / 35 / `cannot set deployer as sub-deployer`
  - `0x5a80b4` / 22 / `too many sub-deployers` (sibling path)
- Err tag `0xe0` (duplicate / cannot-set); Ok tag `0x186`; early Err tag `0xe3`.
- Sibling carve `0x394ce40`..`0x394d5b6` (1910 bytes, sha256 `88176436…86d5`), called once from primary at `0x3718bf9`. Pinned as related, not a primary claim.

## What this does not claim

- Does NOT claim a full setSubDeployers path exists end-to-end; claims the set RULES only.
- Does NOT emulate the setter (static pin only; no Unicorn vectors).
- Sibling "too many" path is pinned as related, not claimed as a primary rule of this packet.
- No other node builds.
