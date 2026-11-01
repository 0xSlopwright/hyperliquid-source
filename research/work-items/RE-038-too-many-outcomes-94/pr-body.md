RE-038: too-many-outcomes (0x31 arm) @ 0x372a470 (node #94)

Static recovery of the Hyperliquid too-many-outcomes count-cap (0x31 arm)
in the pinned node #94 binary: carve `0x372a470`..`0x372a905` (1173 bytes,
carve sha256 `444bf531…e00d`), GOT slot `0x5774a68` with
`R_X86_64_RELATIVE` addend `0x372a470`, 3 inbound `ff15`, 0 direct
`e8`/`e9`, string `0x599484` / 30 `too many outcomes for question`
(one packed occurrence; carve LEA only), `cmpq imm 0x31` / `jbe`
continue rule, Err `0x17b` movw store on the fall-through.

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the 0x31 count-cap RULE only (reject when
outcome count > 49). Neighbouring Err `0x17b` arms in the same carve
(fallback / associated / compatible) are not claimed.

Prior work: open #997 (RE-004 OutcomeDeploy) is an adjacent SIBLING
covering daily deploy caps / settle gates with a different string
(`too many outcomes deployed today`); it does not claim entry
`0x372a470`, string `0x599484`, or this 0x31 arm. No inventory-only
refs for this exact string.

## Identification

- Carve extent: exclusive end at first int3; 11-byte pad then next
  function (`push rbp` at `0x372a910`)
- Rule: `cmpq imm 0x31` / `jbe` continue; fall-through Err `0x17b` +
  string (reject count > 49)
- String (VA/len/bytes): `0x599484`/30 `too many outcomes for question`
- Err `0x17b` movw STORE at `0x372a557` (claimed arm only)

## Proof

- Deterministic Python ELF tool (`tools/too_many_outcomes.py`) with its
  own VA→offset via `PT_LOAD`; exact pins (never `>=`); field name
  `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (one negative for the claimed
  0x31 arm: flip cmp imm / jbe rel)

## What this does not claim

- Does not claim neighbouring Err `0x17b` arms (fallback / associated /
  compatible) in the same carve
- Does not claim #997 sibling daily-deploy / settle rules or its string
- Does not claim a full outcome-register path; does not emulate
- No other node builds

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
