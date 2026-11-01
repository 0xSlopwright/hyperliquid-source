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

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

All checks below ran at head `e55c8a03`. Output is verbatim; the full repository suite was not run (see above).

head `e55c8a03`:

```text
$ .venv/bin/python -I -B research/work-items/RE-033-sub-deployer-guards-94/verify.py
verify: key_insns=13 strings=3 got_slot_refs=3 errors=0
[exit 0]
```

head `e55c8a03`:

```text
$ .venv/bin/python -O -B research/work-items/RE-033-sub-deployer-guards-94/verify.py
verify: key_insns=13 strings=3 got_slot_refs=3 errors=0
[exit 0]
```

head `e55c8a03`:

```text
$ .venv/bin/python -I -B research/work-items/RE-033-sub-deployer-guards-94/independent_verify.py
PASS carve=62308cdc40af8382 refs=3 strings=3 key_insns=13
[exit 0]
```

head `e55c8a03`:

```text
$ .venv/bin/python -O -B research/work-items/RE-033-sub-deployer-guards-94/independent_verify.py
PASS carve=62308cdc40af8382 refs=3 strings=3 key_insns=13
[exit 0]
```

head `e55c8a03`:

```text
$ .venv/bin/python -m unittest tests.test_sub_deployer_guards -v
test_committed_json_pins (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_cannot_set_string (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_mutation_tamper_cannot_set_string) ... ok
test_mutation_tamper_carve (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_duplicate_string (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_mutation_tamper_duplicate_string) ... ok
test_mutation_tamper_early_reject_imm (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_mutation_tamper_early_reject_imm) ... ok
test_negative_controls_per_rule (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_negative_controls_per_rule) ... ok
test_static_output_pin_and_expectations (tests.test_sub_deployer_guards.SubDeployerGuardsStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 8 tests in 92.642s

OK
[exit 0]
```

head `e55c8a03`:

```text
$ .venv/bin/python tools/catalogue.py --check
Catalogue and progress tables match pinned inputs.
[exit 0]
```

head `e55c8a03` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
README.md: OK
sub_deployer_guards.json: OK
independent_verify.py: OK
pr-body.md: OK
verify.py: OK
```

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
