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

All checks below ran at head `e7ed47ba`. Output is verbatim; the full repository suite was not run (see above).

head `e7ed47ba`:

```text
$ .venv/bin/python -I -B research/work-items/RE-036-token-full-name-len-94/verify.py
verify: key_insns=15 strings=2 direct_calls=1 errors=0
[exit 0]
```

head `e7ed47ba`:

```text
$ .venv/bin/python -O -B research/work-items/RE-036-token-full-name-len-94/verify.py
verify: key_insns=15 strings=2 direct_calls=1 errors=0
[exit 0]
```

head `e7ed47ba`:

```text
$ .venv/bin/python -I -B research/work-items/RE-036-token-full-name-len-94/independent_verify.py
PASS carve=64084d429162ad92 e8=1 strings=2 key_insns=15
[exit 0]
```

head `e7ed47ba`:

```text
$ .venv/bin/python -O -B research/work-items/RE-036-token-full-name-len-94/independent_verify.py
PASS carve=64084d429162ad92 e8=1 strings=2 key_insns=15
[exit 0]
```

head `e7ed47ba`:

```text
$ .venv/bin/python -m unittest tests.test_token_full_name_len -v
test_committed_json_pins (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_carve (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_len_imm (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_mutation_tamper_len_imm) ... ok
test_mutation_tamper_option_jno (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_mutation_tamper_option_jno) ... ok
test_negative_controls_per_rule (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_negative_controls_per_rule) ... ok
test_range_gate_truth_table (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_range_gate_truth_table) ... ok
test_static_output_pin_and_expectations (tests.test_token_full_name_len.TokenFullNameLenStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 8 tests in 85.267s

OK
[exit 0]
```

head `e7ed47ba`:

```text
$ .venv/bin/python tools/catalogue.py --check
Stale catalogue: research/catalogue/components.json; run make catalogue
[exit 1]
```

head `e7ed47ba` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
README.md: OK
independent_verify.py: OK
pr-body.md: OK
token_full_name_len.json: OK
verify.py: OK
```

Note: `tools/catalogue.py --check` exits 1 here because of a pre-existing condition. The same command, run on an unmodified checkout of the base commit `cec50f68` (origin/main), prints the same "Stale catalogue: research/catalogue/components.json" message and also exits 1. This branch changes no catalogue file.

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
