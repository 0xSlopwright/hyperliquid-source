# RE-000: cross-platform research tool discovery and Ghidra headless detection

- Component: preflight diagnostic tooling (`tools/doctor.py`).
- Baseline node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Target: `make doctor` read-only preflight diagnostic suite.
- Status: tooling verification complete. No component acceptance gate claimed.

## Problem and cause

`tools/doctor.py` performs essential read-only environment checks before static research tasks.
Three discovery gaps affected non-macOS/non-default workstation setups:

1. **Ghidra headless analyzer detection**:
   `locate_ghidra()` exclusively looked for `support/analyzeHeadless`. On Windows environments,
   Ghidra provides `support/analyzeHeadless.bat`. Consequently, `ghidra.available` remained
   `false` even when a valid `GHIDRA_HOME` was configured.

2. **Git LFS detection**:
   `probe('git-lfs', ...)` checked only for a standalone `git-lfs` executable on `PATH`. In many
   official Git distributions (such as Git for Windows and packaged Linux distros), Git LFS is
   provided as a Git subcommand (`git lfs`) without placing a standalone binary on `PATH`.
   This caused `doctor.py` to report `git-lfs: available: false` despite full Git LFS availability.

3. **Standard LLVM discovery**:
   `locate_llvm()` only inspected Homebrew and `/usr/local` fallback locations. Default LLVM
   installations under standard `ProgramFiles` directories were not discovered when `llvm-objdump`
   was not pre-added to `PATH`.

4. **Missing automated regression coverage**:
   `tools/doctor.py` lacked a dedicated test suite in `tests/`, allowing discovery regressions
   to go unnoticed in CI.

## Reproduce

```sh
python3 research/work-items/RE-000-doctor-cross-platform/reproduce.py --check
python3 -m unittest discover -s tests -p 'test_doctor.py' -v
python3 tools/doctor.py
```

`before.json` and `after.json` record the discovery behavior on synthetic environment structures.

## Scope of changes

- `tools/doctor.py`:
  - Check both `support/analyzeHeadless` and `support/analyzeHeadless.bat` in `locate_ghidra()`.
  - Add standard fallback discovery paths for LLVM installations.
  - Implement `probe_git_lfs()` with seamless fallback to `git lfs version`.
- `tests/test_doctor.py`:
  - Add unit test suite covering probe failure/success handling, Ghidra batch detection, LLVM override, and schema compliance.
- `research/work-items/RE-000-doctor-cross-platform/`:
  - Retain reproduction script, before/after evidence, and SHA-256 manifest.
