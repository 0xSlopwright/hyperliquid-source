RE-036: token full-name length + already-set @ 0x2748b80 (node #94)

- Component ID: RE-036 (`RE-036-token-full-name-len-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `cec50f68`; no radare2 revision (r2 not used)
- Claim: the full-name RULES only — reject when length is not in `1..=50` (unsigned `add`/`cmp` `-0x33` / `ja`), and reject when the name Option is already Some (`cmp`/`jno`). Err `0xdf` + pinned strings. HL own policy, not a vendored crate.
- Adjacent prior work: OUR RE-030 (spot-token deploy name/decimals guard at entry `0x375f3d0`, carve `0x375f3d0`..`0x375fa78`) also LEAs the length string at `0x375f424` inside its host carve. THIS packet pins the separate 206 B helper at `0x2748b80`, not that carve.
- Prior work: entry VA `0x2748b80` appears only as an inventory FDE start in merged PR #650 (spot-meta census); no carve or rule claim there (same pattern as RE-034).

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 python3 tools/token_full_name_len.py

# packet verify
python3 -I -B research/work-items/RE-036-token-full-name-len-94/verify.py
python3 -O -B research/work-items/RE-036-token-full-name-len-94/verify.py

# independent (stdlib only)
python3 -I -B research/work-items/RE-036-token-full-name-len-94/independent_verify.py

# unit tests (negatives + mutation/tamper; one negative per claimed rule)
PYTHONHASHSEED=0 python3 -m unittest tests.test_token_full_name_len -v
```

## Pins

- Carve: `0x2748b80`..`0x2748c4e` (206 bytes), sha256 `64084d42…167e`. Exclusive end is the first int3 after the body (including cold unwind tail); 2-byte int3 pad then next function at `push rbp` `0x2748c50`.
- No GOT `R_X86_64_RELATIVE` for this entry; exactly 1 direct `e8` caller at `0x23e8565`; 0 `e9`; 0 inbound `ff15` via GOT.
- Error strings (VA / len / verbatim bytes):
  - `0x5996ec` / 56 / `token full name must be between 1 and 50 characters long` (ends in ` long`; verified, no truncated form). Exactly one occurrence. LEA in carve at `0x2748bc1`. Other LEAs outside this carve (not claimed): `0x375f424` (RE-030), `0x4d64a41`, `0x4d64b11`.
  - `0x5996d7` / 21 / `full name already set`. Exactly one occurrence. LEA in carve at `0x2748bcf`.
- Rule A: `mov rdx,[rbx+0x10]`; `add rdx,-0x33`; `cmp rdx,-0x33`; `ja` Ok. Rejects len 0 and len >= 51; accepts 1..=50. Err path sets eax=`0x38` + LEA length string + movw Err `0xdf`.
- Rule B: `xor edx,edx`; `cmp [rax+rcx+0x68],rdx`; `jno` already-set Err (eax=`0x15` + LEA already-set string + movw Err `0xdf`).
- Ok tag `0x186` is a `movw` STORE at `0x2748c0f` on the success path (not a compare-gate).

## What this does not claim

- Does NOT claim a full token-deploy / name-validation path end-to-end; claims the two full-name RULES only.
- Does NOT re-claim RE-030 (`0x375f3d0`); that host also LEAs the length string, but is a separate carve (~16.8 MB away) with different entry/strings/rules.
- Does NOT claim the near-clone LEA sites at `0x4d64a41` / `0x4d64b11` as separate validators.
- Does NOT emulate (static pin only; no Unicorn vectors).
- No other node builds.

## Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

### Targeted checks (commands + output)

PENDING — to be filled with exact commands and output once the heavy slot is free (ASI run has it first).
