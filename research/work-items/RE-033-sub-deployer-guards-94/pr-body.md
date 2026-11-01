RE-033: sub-deployer set guards @ 0x37186d0 (node #94) — duplicate / cannot-set-deployer / early-reject 0xe3

Static recovery of the Hyperliquid sub-deployer set guards in the pinned
node #94 binary: FDE `0x37186d0`..`0x3718e27` (1879 bytes, carve sha256
`62308cdc…b2d0`), GOT `0x5774bc8` ← RELATIVE addend `0x37186d0`, exactly
three `ff15` call sites and zero direct `e8`/`e9`, early-reject
`cmpb $0x3` → Err `0xe3`, and the two primary error strings for
duplicate / cannot-set-deployer (Err `0xe0`). Ok tag `0x186`. Optional
sibling carve `0x394ce40` for "too many sub-deployers".

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the set RULES only.

Prior work: #969 (merged) covers deployer fee-share / fee-recipient admission — adjacent deployer-policy, different function.

## Identification

- Carve extent: exclusive end at first int3; pad then next function
  (`push r15` at `0x3718e30`)
- Early-reject: `cmpb $0x3, 0x230(rsi)` → `movw $0xe3`
- Strings (VA/len/bytes): `0x59900b`/22 `duplicate sub-deployer`;
  `0x599021`/35 `cannot set deployer as sub-deployer`; sibling
  `0x5a80b4`/22 `too many sub-deployers`
- Err `0xe0` / Ok `0x186` / early Err `0xe3`

## Proof

- Deterministic Python ELF tool (`tools/sub_deployer_guards.py`) with its
  own VA→offset via `PT_LOAD`; exact pins (never `>=`); field name
  `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (one negative per rule)

## What this does not claim

- Does not claim a full setSubDeployers path; does not emulate
- Sibling "too many" is related, not a primary claim
- No other node builds

### make verify test catalogue-check output

PLACEHOLDER: `make verify test catalogue-check` has not been run for this
packet yet; its output will be recorded here. (make HELD)

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
