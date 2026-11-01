# Hyperliquid Source

Independent research and reconstruction workspace for Hyperliquid's node.
This repository consolidates original binary evidence, static-analysis tools,
research results, and pinned public source references. It is not an official
Hyperliquid source release. No buildable or equivalent node is claimed.

## Contribution focus

**All PRs, submissions and agent work must focus on completing the reverse
engineering of the node's code.** Contributions should hillclimb completion
through binary-backed findings, independently reconstructed Rust and validation
against the target. Show the concrete gap closed or evidence gained, even when
the result is partial and the component's acceptance gates remain unfinished.

Tooling, infrastructure, workflow and surrounding architecture changes are
accepted **only when an active reverse-engineering task is blocked**. Document
the blocker, make the smallest necessary fix, verify that the work can proceed,
and return to reverse engineering. **Window dressing, cosmetic cleanup and
inconsequential PRs or submissions will be closed**, as will supporting changes
without a demonstrated blocker. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
acceptance policy and evidence requirements.

## Reconstruction progress

Static inputs and research tooling are ready. A compilable, verified node is
not yet recovered.
The [component progress table](docs/PROGRESS.md) separates completion from
reference-file coverage and records node #94, node #115 and visor independently.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [scope](docs/SCOPE.md), the
[reverse-engineering guide](docs/REVERSE-ENGINEERING.md),
[ready work queue](docs/TASKS.md), and [REA setup](docs/REA.md).
[AGENTS.md](AGENTS.md) gives agent-specific rules.

## Get started

Prerequisites: Git, Git LFS, Python 3.10+, ripgrep, GnuPG and rustup.
LLVM's `llvm-objdump` is useful for further disassembly. On macOS:

```sh
brew install git-lfs ripgrep gnupg llvm rustup
export PATH="$(brew --prefix llvm)/bin:$PATH"
git clone --recurse-submodules https://github.com/lalalune/hyperliquid-source.git
cd hyperliquid-source
./scripts/setup.sh
make verify
make test
make catalogue-check
make doctor
make index
make reproduce
```

Setup installs Rust 1.94.1 and 1.95.0 via rustup, initializes pinned submodules,
and materializes Git LFS objects. It does not launch any captured executable.
For an existing clone, `make pull` materializes pinned source and binary inputs.
`make fetch` offers checksum-locked upstream recovery of missing artifact files;
mutable publisher URLs may no longer serve the pinned release, so LFS is preferred.

## Layout

- `artifacts/`: node #94, node #115, captured visor, signatures and public key; binaries use Git LFS.
- `references/can1357-hl/`: pinned third-party inferred source, with its upstream LFS binary.
- `upstream/`: pinned official node tooling, contracts, block importer, EVM sync, order-book server and historical-data repositories.
- `tools/legacy/`: preserved Python research scripts.
- `tools/artifacts.py`: integrity, download and isolated GPG verification.
- `research/imported/`: original inventories, classifications and visor disassembly.
- `research/upstream-docs/`: collected documentation and repository inventories.
- `provenance/`: imported file hashes, artifact identities and source commit pins.
- `src/`: home for future project-authored reconstruction code.
- `research/catalogue/`: generated component map and unverified address leads.
- `research/progress.json`: reviewed acceptance gates; `make catalogue` regenerates tables.
- `research/rea/`: retained static REA dependency-metadata evidence.
- `work/`: ignored output from local analysis, unwind indices and Ghidra projects.

See [research status](research/STATUS.md), [toolchains](docs/TOOLCHAINS.md),
[reproducibility](docs/REPRODUCIBILITY.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
REA is pinned locally: see [REA setup](docs/REA.md) for `make rea-install`,
`make rea-doctor`, `make rea-smoke` and the existing Codex connection.

New project work is MIT licensed; imported materials retain their original terms.
