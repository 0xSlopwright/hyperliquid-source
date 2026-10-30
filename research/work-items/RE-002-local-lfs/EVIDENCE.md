# RE-002: initialize LFS in each repository that materializes pinned inputs

- Component: build-provenance/setup tooling; no completion gate requested.
- Question: do documented setup and `make pull` materialize the pinned inputs
  when Git LFS is installed without global Git filter configuration?
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
  Node #115 and visor are separate retained inputs checked by `make verify`.
- Changed entrypoints: `scripts/setup.sh` and the Makefile's `pull` target.
  Imported files, signatures, source pins and generated catalogues are unchanged.

## Observation and cause

A real fresh setup with Git LFS 3.8.1 and no global LFS filters downloaded the
retained artifacts, but the reference copy remained a 133-byte LFS pointer.
The parent repository's `git lfs install --local` does not configure a
submodule. Its subsequent `git lfs pull` exited zero while reporting:

```text
Skipping object checkout, Git LFS is not installed for this repository.
Consider installing it with 'git lfs install'.
```

Setup's final verification failed with `Pinned upstream mismatch` for the
node #94/reference pair. Installing LFS locally in the reference repository
before pulling restored the 91,774,280-byte file with the expected hash.
Standalone `make pull` also needs parent-local initialization when setup has
not previously run. The fix initializes exactly these two repositories; it
does not depend on or write global Git configuration.

## Reproduce

First materialize the source checkout using the corrected setup. The replay
requires Git, Git LFS, Python 3.10+, make and GnuPG. It clones the actual base
and all seven pinned references locally, copies their real cached LFS objects,
and uses an empty temporary global Git configuration with system configuration
disabled. No Git/LFS command or binary content is mocked. No captured program
is executed. Temporary clones and configuration are removed afterward.

```sh
mkdir -p work
python3 -B research/work-items/RE-002-local-lfs/reproduce.py > work/local-lfs-replay.json
```

The measured replay additionally used macOS `sandbox-exec` with
`(version 1)(allow default)(deny network-outbound (remote ip))(deny network-inbound (local ip))`.
IP networking was denied; Unix sockets remained available to isolated GPG
verification. An initial runner that denied Unix sockets as well could not
verify signatures; that runner failure is not a product result.

## Results

The adjacent `results.json` retains actual command output, target sizes/hashes,
tool versions and the reproducer's SHA-256.

| Authentic cached-clone condition | `make pull` | `make verify` | Node #94 parent/reference sizes |
| --- | --- | --- | --- |
| Base, neither repository configured | 0 | 2, artifact mismatch | 133 / 133 |
| Base, only parent configured as in setup | 0 | 2, pinned-pair mismatch | 91,774,280 / 133 |
| Candidate, both locally initialized | 0 | 0 | 91,774,280 / 91,774,280 |
| Candidate repeated | 0 | 0 | 91,774,280 / 91,774,280 |

Both candidate files match the full target SHA-256. All seven submodule
commits and clean contents, source input hashes, and the empty global config
are checked unchanged. Successful verification includes all retained artifact
hashes/signatures and the imported-file/source-pin checks.

On the working checkout, corrected `scripts/setup.sh` completed successfully.
`make doctor verify test catalogue-check` passed on base after manual local
configuration and on the candidate: analysis ready, 431 tests passing, and
catalogue consistency passing. The replay proves the differing fresh-config
behavior; the broader suite checks for regressions.

## Limits and next question

This is a local setup correction, not a reconstruction or equivalence result.
No Rust implementation, function-boundary or target-behavior claim is made;
address coordinates and normalization masks are inapplicable. No progress
gate changes. Static verification does not establish node safety. Hosted CI,
Windows and Linux runs were not observed. Existing custom LFS hooks can still
require operator resolution; initialization is not forced. The replay needs
already cached inputs and does not test a remote LFS service or missing-cache
recovery. Next: verify the corrected entrypoints in a clean Linux checkout.
