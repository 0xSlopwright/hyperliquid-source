# RE-002: source verification independent of Git's status display

- Component: build provenance and pinned analysis inputs. No progress gate requested.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Baseline node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- This is a tooling observation. The reproduction uses a synthetic temporary Git
  source repository; it neither modifies imported references nor executes a target.

## Problem and cause

`make verify` promises to reject modified pinned source repositories. With Git's
`status.showUntrackedFiles=no`, an extra source file does not appear in
`git status --porcelain`. The verifier used that output and printed that all
pinned source repositories were verified. The source walker in
`tools/catalogue.py` still reads `reference.rglob('*.rs')`, which includes the
extra file. A correct HEAD alone does not establish the analysis input tree.

This is an ordinary Git display setting, set only in the temporary fixture for
the reproduction. No malformed manifest or binary is needed.

## Reproduce

From the repository root, with Python and Git on PATH:

```sh
python3 research/work-items/RE-002-untracked-source-verification/reproduce.py --check
python3 -m unittest discover -s tests -p 'test_verify_imports.py' -v
```

The probe can check another checkout with `--repository-root /path/to/checkout`.
It commits one synthetic retained file, then adds one untracked `.rs` file. The
same tree is checked with normal and hidden-untracked status settings. Only the
temporary repository's Git configuration changes.

Before the fix, the probe reports clean=true, extra/normal=false and
extra/hidden=true; `--check` exits 1. After the fix the values are true, false,
false and the check exits 0. Ordinary status remains empty in the hidden case;
an explicit `--untracked-files=all` lists `?? unexpected.rs`. Both source files
remain visible to the glob. The regression also checks the clean tree under the
hidden setting, so the fix cannot simply reject that setting.

`before.json` and `after.json` preserve these probe outputs. They agree across
Windows Python 3.10.11 / Git 2.51.1.windows.1 and Ubuntu Python 3.12.3 / Git 2.43.0.
`MANIFEST.sha256` binds this packet's bytes. The Linux regression on the original
tool has five passes and the one expected new failure, with no test errors.

## Fix and limits

Request `--untracked-files=all` in the verifier. This overrides the display
preference for this read without changing local or global configuration. Keep
the existing commit, tracked-change, imported-file digest and failure checks.

This does not change source policy, ignored-file handling, any artifact or
inferred source, inventory interpretation, Rust reconstruction or acceptance
gates. Machine-code addresses and new runtime-equivalence measurements are not
applicable. Existing artifact, signature, pin, catalogue and reproduction checks
remain the validation of those separate inputs.

Windows Python 3.10 reproduces the new failure. The original test file also
encounters an unrelated Windows `WinError 5` while its existing test removes
read-only Git objects with `shutil.rmtree`. Preserve that failed run; use the
existing Ubuntu validation environment for the complete required checks.

Next step: maintainers review this verification change separately from open
manifest-key validation (#115) and retained-import coverage (#190).
