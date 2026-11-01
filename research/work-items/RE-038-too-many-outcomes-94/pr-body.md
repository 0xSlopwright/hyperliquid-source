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

All checks below ran at head `6eac366b`. Output is verbatim; the full repository suite was not run (see above).

head `6eac366b`:

```text
$ .venv/bin/python -I -B research/work-items/RE-038-too-many-outcomes-94/verify.py
verify: key_insns=10 strings=1 direct_calls=0 errors=0
[exit 0]
```

head `6eac366b`:

```text
$ .venv/bin/python -O -B research/work-items/RE-038-too-many-outcomes-94/verify.py
verify: key_insns=10 strings=1 direct_calls=0 errors=0
[exit 0]
```

head `6eac366b`:

```text
$ .venv/bin/python -I -B research/work-items/RE-038-too-many-outcomes-94/independent_verify.py
PASS carve=444bf531ab17fbff ff15=3 strings=1 key_insns=10
[exit 0]
```

head `6eac366b`:

```text
$ .venv/bin/python -O -B research/work-items/RE-038-too-many-outcomes-94/independent_verify.py
PASS carve=444bf531ab17fbff ff15=3 strings=1 key_insns=10
[exit 0]
```

head `6eac366b`:

```text
$ .venv/bin/python -m unittest tests.test_too_many_outcomes -v
test_committed_json_pins (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_carve (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_cmp_imm (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_mutation_tamper_cmp_imm) ... ok
test_mutation_tamper_jbe_branch (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_mutation_tamper_jbe_branch) ... ok
test_negative_controls_per_rule (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_negative_controls_per_rule) ... ok
test_static_output_pin_and_expectations (tests.test_too_many_outcomes.TooManyOutcomesStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 7 tests in 82.154s

OK
[exit 0]
```

head `6eac366b`:

```text
$ .venv/bin/python tools/catalogue.py --check
Stale catalogue: research/catalogue/components.json; run make catalogue
[exit 1]
```

head `6eac366b` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
too_many_outcomes.json: OK
verify.py: OK
independent_verify.py: OK
README.md: OK
pr-body.md: OK
```

Note: `tools/catalogue.py --check` exits 1 here because of a pre-existing condition. The same command, run on an unmodified checkout of the base commit `cec50f68` (origin/main), prints the same "Stale catalogue: research/catalogue/components.json" message and also exits 1. This branch changes no catalogue file.

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
