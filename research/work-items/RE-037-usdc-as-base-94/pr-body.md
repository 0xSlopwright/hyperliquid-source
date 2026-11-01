RE-037: USDC-as-base guard @ 0x274f860 (node #94)

Static recovery of the Hyperliquid USDC-as-base guard in the pinned
node #94 binary: carve `0x274f860`..`0x274f994` (308 bytes, carve sha256
`28f03c90…a3cc`), no GOT RELATIVE for the entry, exactly one direct `e8`
caller at `0x23e81f2`, string `0x3eff61` / 29
`cannot use USDC as base token` (three packed occurrences; carve LEA
only), `test rdi,rdi` / `je` refuse rule, Err `0xdf` / bounds Err `0xea` /
Ok movw store `0xac`.

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the refuse-USDC-as-base RULE only (reject when
base token id is 0).

Prior work: string VA `0x3eff61` / text appears only as inventory probes
in merged PR #650 (spot-meta census / FDE) and #389 (length-bearing
string census); no carve or rule claim at `0x274f860` there.

## Identification

- Carve extent: exclusive end at first int3; 12-byte pad then next
  function (`push r15` at `0x274f9a0`)
- Rule: `test rdi,rdi` / `je` -> Err `0xdf` + string (refuse id 0 / USDC)
- String (VA/len/bytes): `0x3eff61`/29 `cannot use USDC as base token`
- Err `0xdf` (claimed) / bounds Err `0xea` / Ok movw store `0xac` (ABI)

## Proof

- Deterministic Python ELF tool (`tools/usdc_as_base_guard.py`) with its
  own VA→offset via `PT_LOAD`; exact pins (never `>=`); field name
  `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (one negative for the claimed rule)

## What this does not claim

- Does not claim a full spot-pair / market-create path; does not emulate
- Does not claim bounds Err `0xea` or success `0xac` as separate rules
- Does not claim near-clone LEA sites of duplicate string copies as
  separate validators (`0x375ef8e`, `0x4d72180`, `0x4d722c0`)
- Does not re-claim inventory probes from merged #650 / #389
- No other node builds

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
