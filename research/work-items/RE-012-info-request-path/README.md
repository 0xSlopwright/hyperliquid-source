# RE-012 — InfoRequest API path

Pinned static evidence for Hyperliquid node `#94`
(`artifacts/node/94/hl-node`, sha256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`) covering
the TASKS.md paths `info_server/*` (with `node/hl_node.rs` Locations that share
an FDE with them). One request path as required: the InfoRequest JSON API
surface (not a TCP gossip frame and not a CLI flag path).

## What this proves

1. **Scoped Locations.** Exactly **26** first-party panic `Location` records
   under `info_server/src/**` (abci_state_info_handler.rs: 17, handle_request.rs: 3,
   request.rs: 2, and one each for handler/router/user_ip/f_types/position),
   attributed via RIP `lea` into **113** FDE-bounded functions. Five
   `node/src/hl_node.rs` Locations share FDEs with those info_server owners
   (startup linkage, not a separate path claim).
2. **Request hub.** FDE `0x24af210`..`0x24b22d8` owns the Locations in
   `handle_request.rs` (lines 30, 49, 120), `router.rs` (45), `handler.rs` (41),
   and `user_ip.rs` (28) — the InfoRequest HTTP/JSON request hub.
3. **Deserializer edge.** That hub contains the rel32 call at instruction
   start `0x24aff82` (`e8 f9 7c 41 00`) whose destination is FDE-start
   `0x28c7c80` (the main InfoRequest-tag deserializer). Instruction-start
   addresses include the REX prefix when present.
4. **Tag inventory.** All **56** `#[serde(rename = "...")]` tags from the
   can1357 `info_server/request.rs` reconstruction are lea-anchored (exact or
   length-prefixed). **52** of them have at least one lea site owned by the
   deserializer FDE `0x28c7c80`.
5. **Write / side-effect markers.** Tags `fileSnapshot`, `outPath`,
   `l4Snapshots`, and `referrerStates` are present and lea-anchored. The
   diagnostic template
   `not writing snapshot to file because request was not from localhost`
   is NUL-delimited-template-anchored and owned by FDE `0x27e91d0`
   (`abci_state_info_handler.rs`) — i.e. the snapshot write path is gated on
   a localhost request check.

## Exact rerun

```bash
python3 -I -B tools/info_request_path.py \
  --out research/work-items/RE-012-info-request-path/info-request-path.json
python3 -I -B research/work-items/RE-012-info-request-path/verify.py
python3 -O -B research/work-items/RE-012-info-request-path/verify.py
python3 -I -B -m unittest discover -s tests -p test_info_request_path.py -v
```

Byte-identical JSON under `PYTHONHASHSEED=0/7/99`
(sha256 `4edf26203f2a9f2ddd307b728d54aba77ac493a158462e40e331e4a494893baa`).

## Packet files

| file | role |
|---|---|
| `info-request-path.json` | tool output (sorted keys, hex addresses) |
| `objdump-excerpts.txt` | human-readable disassembly at pinned sites |
| `MANIFEST.sha256` | sha256 of every packet file except itself |
| `verify.py` | fail-closed regenerating verifier |
| `independent_verify.py` | second-method PASS/FAIL/INCONCLUSIVE check |
| `README.md` | this file |

## What this does **not** claim

- No live-network / runtime behaviour; evidence is static ELF only.
- No full serde layout / field offsets for InfoRequest variants — only the
  rename-tag inventory and owning FDEs.
- No claim that hub `0x24af210` is *named* `handle_request` in DWARF; only
  that it owns the listed Locations and contains the pinned deser call.
- Does not prove a call edge from the hub to the snapshot gate `0x27e91d0`
  (no FDE-start-landing rel32/slot edge within two hops); the gate is claimed
  only as the owner of the localhost write-gate template and of
  `abci_state_info_handler` Locations.
- Does not decode TCP gossip frames or CLI startup flags (those remain
  other RE-012 surfaces; this packet picks the InfoRequest API path).
- Does not claim node `#115` parity.
- Does not claim completeness of every info_server diagnostic string — only
  the inventoried tags plus the one snapshot template.
- Depends on RE-001 (binary pin) and on RE-005 (#10) for Location / FDE
  methodology; this packet does not re-litigate RE-005.

## Method

Stdlib-only ELF walk: `.eh_frame_hdr` FDE index, `.rela.dyn` RELATIVE slots
for first-party panic `Location` records, RIP `lea` attribution, rel32 call
edges that land on FDE starts, and exact / length-prefixed / NUL-template
string anchors. Cross-checked with `readelf -rW` (Location slots) and
`objdump -d` (hub→deser bytes; tag leas).
