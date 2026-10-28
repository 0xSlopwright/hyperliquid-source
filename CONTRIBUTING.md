# Contributing

Start with [scope](docs/SCOPE.md), [current progress](docs/PROGRESS.md),
[component map](docs/COMPONENTS.md), and [ready tasks](docs/TASKS.md).
For REA CLI/MCP configuration and supported Node versions, see [REA.md](docs/REA.md).
The project reconstructs Linux x86-64 Hyperliquid binaries from evidence.
Node #94 is the initial baseline; #115 and visor remain separate targets.

## Set up and choose work

```sh
git clone --recurse-submodules https://github.com/lalalune/hyperliquid-source.git
cd hyperliquid-source
./scripts/setup.sh
make doctor
make verify test catalogue-check
make index
```

Choose a small question and component ID, note its task ID in an issue/PR,
and work on a descriptive branch. Keep shared reference submodules pinned
and untouched. Generated analysis and disassembler databases belong in work/.
Commit durable, compact evidence under research/work-items/<task-id>/.
The [packet template](research/templates/EVIDENCE.md) specifies required fields.

## Contribution types

- Static research: exact target, validated addresses/ranges, xrefs, instructions,
  source/data attribution, inferences and unresolved questions.
- Implementation: independently authored Rust, target ABI/layout, pinned
  component build and lockfile, helper closure and evidence-backed tests.
- Tooling: deterministic offline outputs, explicit input hashes, malformed-input
  checks where appropriate, and no implicit execution of captured binaries.
- Review: reproduce the claimed build/checks and attack the comparator with
  corruption controls. Missing evidence remains a gap even if code looks right.

There is intentionally no root Cargo workspace yet. Add a real component
manifest only when its dependencies and build behavior are established. Do not
turn the inferred reference tree into an apparently recovered workspace using
arbitrary dependency versions or placeholder implementations.

## Required evidence packet

Include the target SHA-256/release, component and bounded question; source and
reference revisions; original addresses plus their coordinate system; tool
versions and analysis options; exact commands; observations with supporting
files; clearly separated inferences; before/after build/comparison results;
negative controls; limitations and a next step. Cite the relevant binary bytes,
not only the can1357 narrative. An address in its comments is an unverified seed.
Never publish private keys, tokens, home-directory state or live user datasets.

Rust reconstruction is required for implementation claims. Hand-patched or
transplanted original machine code is not reconstruction. Preserve raw results
and state every normalized operand. Matching functions still need their calls,
data, relocations, vtables and layout checked; passing a test of your own newly
invented behavior does not validate the target.

## Validation and progress updates

Run the checks that cover your change:

```sh
make verify                 # authentic inputs and unchanged imports/pins
make test                   # offline tooling controls
make catalogue-check        # generated scope/progress consistency
make reproduce              # if literals, inventories or evidence interpretation change
```

Run `make catalogue` after an approved edit to research/components.json or
research/progress.json and commit generated tables/catalogues with it. Do not
edit generated tables directly. Completion is four reviewed component gates;
only mark a gate true with a packet covering its entire scope and an evidence
path in the progress record. The consistency check verifies paths and structure;
it is not a semantic proof or a substitute for review. Partial results keep
component gates false and are recorded in their work item.

Once measured function windows exist, report raw-equal, normalized-only and
unmatched counts over an explicit denominator. Do not substitute source-file,
line-count, unwind-index or string coverage for these counts.

## Licensing, execution and review

New code/docs use MIT. Imported sources and binaries retain upstream rights;
can1357's unlicensed source is a research reference, not a grant to copy code
into the MIT implementation. Attribute evidence and preserve upstream notices.

The default workflow is static. Running captured binaries, networked services,
chain actions or signing requires explicit authorization and an isolated
harness with declared effects. Static Ghidra imports are allowed; they can be
large, so reuse a digest-specific project. Scope/release changes belong in the
PR description. Include checks run, exact outcomes, known gaps and any progress
change. Never merge an implementation claim based only on green tooling CI.
