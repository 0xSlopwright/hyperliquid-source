# RE-000: Ghidra readiness and README milestone reporting

- Check date: 2026-10-31 (America/Los_Angeles).
- Component: research tooling; no reconstruction gate requested.
- Bounded question: does the installed Ghidra pipeline work, and can the README
  show every declared module's accepted gates and a reproducible total?
- Intended files: README.md, tools/catalogue.py, tests/test_research_tools.py,
  generated docs/PROGRESS.md, CONTRIBUTING.md and this packet.
- Source baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Inferred reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Native smoke target: captured visor,
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Node #94 progress scope:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115, checked as an input but excluded from the completion denominator:
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, on macOS arm64 with the installed Ghidra 12.1.4,
Java 21.0.10, Node 24.22.1 and pinned REA 6.8.0:

```sh
export PATH="$(brew --prefix binutils)/bin:$(brew --prefix llvm)/bin:$PATH"
make doctor verify
make rea-doctor
make rea-native-smoke
make catalogue
make verify test catalogue-check
```

The existing connected REA server was inspected directly with
`binary_session(expected_package_version="6.8.0")`: aligned, Ghidra available,
no open target or pending cleanup. No user registration was changed. The native
check uses the repository's separate owned stdio smoke server because its
explicit reduced profile disables `Decompiler Switch Analysis` and
`Decompiler Parameter ID`. It closes its temporary analysis project on exit.

The desktop launcher was also started using the same discovered Ghidra/JDK.
The operating-system app inventory and process list reported Ghidra running;
the Ghidra application log also recorded `Ghidra startup complete`.
The computer-use adapter could not bind the Java-hosted window, so no GUI
interaction or loaded desktop project is claimed. Logs and transient output
are under ignored `work/`; no captured node or visor was executed.

The first background desktop instance was no longer present during the final
check. It was relaunched in an owned foreground terminal session with a 2 GiB
GUI heap, using the installed launcher:

```sh
"$GHIDRA_INSTALL_DIR/support/launch.sh" fg jdk Ghidra 2G "" ghidra.GhidraRun
```

That session reported `Ghidra startup complete (5431 ms)` and remained running
at handoff. The cause of the earlier background process exit was not established.

## Progress metric and controls

The ledger has 24 components: 23 for node #94 and one for visor. Four reviewed
gates each give a denominator of 96. No gates are accepted, so the total is
**0/96 = 0.00%**, with **0/24 completed modules**. All individual rows are
**0/4 = 0%**. This is milestone completion; matched-function and byte-coverage
denominators remain unmeasured. No acceptance flags or imported evidence changed.

The PumpFun README's per-program counts and total row informed the presentation.
Its measured function windows cannot supply this project's denominator.
The component catalogue and the 689 unverified #94 comment seeds were inspected;
neither source-path counts nor seeds earn completion credit.

`make catalogue` generates the README block and detailed progress from the same
ledger. `make catalogue-check` detects stale generated content. Controls cover
a mixed nonzero ledger (5/96 = 5.21%, one fully complete module), preservation
of surrounding README prose, idempotent regeneration, and rejection of missing,
duplicate or reversed markers.

## Validation and limitations

`make doctor verify`, `make rea-doctor` and `make rea-native-smoke` passed.
The native smoke returned 280 characters of pseudocode for visor entrypoint
file offset `0x2bc180`, mapped by Ghidra to analysis address `0x3bd180`.
The fresh Evidence record is byte-for-byte identical to the retained
[visor native record](../../rea/setup-20261028/visor-native-evidence.json):

- Evidence ID: `ev_651ff239ebca14f06c61bb30b184f2168c45823f03488b7bdd3f57fe677731c1`.
- Record file SHA-256: `6c052519591ab7482fb5a8ac2808781a3043e77883ffb30176093b615cbaa3f1`.
- Reduced analysis-profile digest: `bffa12c2899826c7aa2a119d201d24e9dfbe7ef1a4ea7ab0880ec5c944bbfdcf`.

The original record retains provider limitations and complete options. This
reproduction verifies the reduced native pipeline, not the default analyzer
profile or full node analysis. The owned headless smoke server and its project
closed successfully; the desktop process was left running.

The initial full suite used the shell's Apple `objdump` and lacked `readelf` on
PATH. GNU binutils was already installed. The README now declares that dependency
and puts it first on PATH; the rerun uses the installed tools without changing
global shell settings. The original output remains in
`work/readme-progress-validation.log`; the corrected run is in
`work/readme-progress-validation-gnu.log`.

The first run reported 360 tests, four failures, 12 errors and 15 skips; these
include GNU-tool lookup and disassembly-format failures. The 16 focused research
tool tests, including the new progress controls, passed. With GNU binutils on
PATH, **all 434 tests passed in 148.849 seconds with no skips**, along with
`make verify` and `make catalogue-check`. `git diff --check` and local README
link checks also passed. The larger test count reflects setup classes and
tool-dependent controls that could run with the corrected environment.

No full-node analysis, build, behavioral equivalence, whole-ELF identity,
container run or hosted CI result is claimed. The next reconstruction step
remains a bounded, target-grounded work item from docs/TASKS.md, followed by
full-scope evidence review before any gate can advance.
