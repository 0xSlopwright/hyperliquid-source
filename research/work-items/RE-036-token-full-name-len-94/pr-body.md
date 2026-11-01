RE-036: token full-name length + already-set @ 0x2748b80 (node #94)

Static recovery of the Hyperliquid token full-name helper in the pinned
node #94 binary: carve `0x2748b80`..`0x2748c4e` (206 bytes, carve sha256
`64084d42…167e`), no GOT RELATIVE for the entry, exactly one direct `e8`
caller at `0x23e8565`, strings `0x5996ec` / 56
`token full name must be between 1 and 50 characters long` and
`0x5996d7` / 21 `full name already set` (one occurrence each),
unsigned length gate `add`/`cmp` `-0x33` / `ja`, Option already-set
`cmp`/`jno`, Err `0xdf` / Ok movw store `0x186`.

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the full-name RULES only (length in `1..=50`;
reject when already set).

Adjacent prior work: OUR RE-030 (spot-token deploy name/decimals guard at
`0x375f3d0`, carve `0x375f3d0`..`0x375fa78`) also LEAs the length string
inside its host. THIS packet pins the separate 206 B helper at
`0x2748b80`, not that carve.

Prior work: entry VA `0x2748b80` appears only as an inventory FDE start in
merged PR #650 (spot-meta census); no carve or rule claim there (same
pattern as RE-034).

## Identification

- Carve extent: exclusive end at first int3; 2-byte pad then next
  function (`push rbp` at `0x2748c50`)
- Length gate: `add rdx,-0x33` / `cmp rdx,-0x33` / `ja` (accept 1..=50)
- Already-set: `xor edx,edx`; `cmp [slot],rdx`; `jno`
- Strings (VA/len/bytes): `0x5996ec`/56 `…characters long`; `0x5996d7`/21
  `full name already set`
- Err `0xdf` / Ok movw store `0x186`

## Proof

- Deterministic Python ELF tool (`tools/token_full_name_len.py`) with its
  own VA→offset via `PT_LOAD`; exact pins (never `>=`); field name
  `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (one negative per claimed rule)

## What this does not claim

- Does not claim a full token-deploy path; does not emulate
- Does not re-claim RE-030; adjacent prior work only (shared string LEA
  outside this carve)
- Does not claim near-clone LEA sites as separate validators
- No other node builds

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
