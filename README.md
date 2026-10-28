# Hyperliquid Source

Independent research and reconstruction workspace for Hyperliquid's node.
This repository consolidates original binary evidence, static-analysis tools,
research results, and pinned public source references. It is not an official
Hyperliquid source release. No buildable or equivalent node is claimed.

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
- `work/`: ignored output from local analysis.

See [research status](research/STATUS.md), [toolchains](docs/TOOLCHAINS.md),
[reproducibility](docs/REPRODUCIBILITY.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
New project work is MIT licensed; imported materials retain their original terms.
