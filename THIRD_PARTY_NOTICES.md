# Licensing and provenance

The root MIT license covers new project-authored code and documentation only.
It does not relicense imported source, binaries, signatures, documentation, or
third-party dependencies.

| Path | Origin | License / status |
| --- | --- | --- |
| `references/can1357-hl` | https://github.com/can1357/hl | No license declared at imported commit. Reference material; no MIT grant is asserted. |
| `upstream/node` | https://github.com/hyperliquid-dex/node | Apache-2.0; retain its LICENSE and notices. |
| Other `upstream/*` submodules | hyperliquid-dex public repositories | Use each repository's terms. Several do not declare a license; no MIT grant is asserted. |
| `artifacts/` | Hyperliquid published binaries, signatures and public signing key | Original upstream material; no new license grant. |
| `research/upstream-docs/` | Existing collected Hyperliquid documentation and repository inventories | Upstream documentation; retain original attribution and terms. |
| `research/imported/`, `tools/legacy/` | User-supplied research copied from hlproject | Preserved research; external excerpts remain subject to their original rights. |
| `src/node94-tcp-frame` dependency `lz4_flex` 0.11.6 | https://github.com/PSeitz/lz4_flex | MIT; pinned by the component lockfile. |
| `src/node94-tcp-frame` transitive dependency `twox-hash` 2.1.5 | https://github.com/shepmaster/twox-hash | MIT; enabled by the pinned `lz4_flex` default feature set. |

Git submodules preserve the original repositories, history and terms without
copying their code into the project's MIT implementation. The absence of a
license is not a license grant. Consult the upstream owner before redistributing
or adapting unlicensed reference code. `provenance/sources.json` pins imports.

REA is pinned as an npm development dependency (`rea-agents` 6.8.0), from
[the MIT-licensed morluto/rea project](https://github.com/morluto/rea). Installed
packages under ignored node_modules/ retain their own upstream licenses.
