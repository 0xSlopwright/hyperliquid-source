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

All checks below ran at head `ee137d76`. Output is verbatim; the full repository suite was not run (see above).

head `ee137d76`:

```text
$ .venv/bin/python -I -B research/work-items/RE-037-usdc-as-base-94/verify.py
verify: key_insns=14 strings=1 direct_calls=1 errors=0
[exit 0]
```

head `ee137d76`:

```text
$ .venv/bin/python -O -B research/work-items/RE-037-usdc-as-base-94/verify.py
verify: key_insns=14 strings=1 direct_calls=1 errors=0
[exit 0]
```

head `ee137d76`:

```text
$ .venv/bin/python -I -B research/work-items/RE-037-usdc-as-base-94/independent_verify.py
PASS carve=28f03c901694e40e e8=1 strings=1 key_insns=14
[exit 0]
```

head `ee137d76`:

```text
$ .venv/bin/python -O -B research/work-items/RE-037-usdc-as-base-94/independent_verify.py
PASS carve=28f03c901694e40e e8=1 strings=1 key_insns=14
[exit 0]
```

head `ee137d76`:

```text
$ .venv/bin/python -m unittest tests.test_usdc_as_base_guard -v
test_committed_json_pins (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_carve (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_je_branch (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_mutation_tamper_je_branch) ... ok
test_negative_controls_per_rule (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_negative_controls_per_rule) ... ok
test_static_output_pin_and_expectations (tests.test_usdc_as_base_guard.UsdcAsBaseGuardStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 6 tests in 45.516s

OK
[exit 0]
```

head `ee137d76`:

```text
$ .venv/bin/python tools/catalogue.py --check
Stale catalogue: research/catalogue/components.json; run make catalogue
[exit 1]
```

head `ee137d76` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
README.md: OK
independent_verify.py: OK
pr-body.md: OK
usdc_as_base_guard.json: OK
verify.py: OK
```

Note: `tools/catalogue.py --check` exits 1 here because of a pre-existing condition. The same command, run on an unmodified checkout of the base commit `cec50f68` (origin/main), prints the same "Stale catalogue: research/catalogue/components.json" message and also exits 1. This branch changes no catalogue file.

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
