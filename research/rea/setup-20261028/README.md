# REA integration verification — 2026-10-28

Configuration and native-analysis integration passed. No reconstruction gate
is claimed. The captured executables were not run as host processes.

## Installed and connected

- Project package: rea-agents 6.8.0, pinned with npm integrity records.
- Runtime selected by the launcher: Node 24.22.1. The prior shell default
  24.15.0 is outside the package's supported engine range.
- Native provider: Ghidra 12.1.4 with Java 21.0.10 on macOS arm64.
- The existing Codex registration remains unchanged. A scoped registration,
  provider and skill check passed when run with its actual configured environment.
- Live server version and catalog identity matched the expected 6.8.0 catalog;
  the global server was confirmed closed with no cleanup pending.
- A separately owned server launched through tools/rea.py passed initialization,
  protocol negotiation and binary_session inspection. It was stopped after use.

## Native smoke result

`make rea-native-smoke` starts a fresh owned MCP server with the explicitly
reduced `native-smoke` profile. It opens the captured visor, resolves its ELF
entry to source offset `0x2bc180`, and asks Ghidra to decompile that entry.
The returned subject SHA-256 is
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.

The full [native Evidence](visor-native-evidence.json) is
`ev_651ff239ebca14f06c61bb30b184f2168c45823f03488b7bdd3f57fe677731c1`.
It reports Ghidra-generated entrypoint pseudocode and profile digest
`bffa12c2899826c7aa2a119d201d24e9dfbe7ef1a4ea7ab0880ec5c944bbfdcf`.
The [handshake record](mcp-handshake.json) retains provider and catalog identity.
The command completed successfully after close_binary and process cleanup.

The profile disables Decompiler Switch Analysis and Decompiler Parameter ID.
It verifies the integration on a real target, not full function recovery,
behavior, byte identity, or completeness of the default analyzer set.

## Preserved failures and corrective actions

The default analyzer set exceeded REA's 330-second startup deadline. Its original
error was too large for the MCP response buffer, so it was exported to the
[complete compressed bundle](visor-default-timeout.bundle.json.gz), then the
session was closed. Error evidence:
`ev_33af7deefb7116749e18d422ff914859dd0620fb88b25383136ef9cd839e4b5c`.
The response-buffer error was secondary; it was not the analysis failure.
No memory-exhaustion cause was established.

The first reduced-profile query completed import but used the ELF virtual
address directly. Ghidra had rebased the PIE image. The [retained coordinate
error](visor-coordinate-error.json) records the failure. The final check uses
an explicit source-file-offset selector, and a regression test checks that
ELF virtual addresses are translated through section mappings rather than
mistaken for loaded analysis addresses.

## Other checks

- `make rea-install`: clean lockfile install passed with lifecycle scripts disabled.
- `make rea-smoke`: CLI identity and static #94/#115 artifact bindings passed.
- `make verify test catalogue-check`: passed; 20 tests.
- Documentation links and pinned runtime/package version consistency passed.

For full native analysis, keep the default analyzer set and choose adequate
provider and host deadlines as documented in docs/REA.md. This configuration
check does not establish a full node or visor reconstruction.
