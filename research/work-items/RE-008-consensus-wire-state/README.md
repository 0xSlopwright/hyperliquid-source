# RE-008 — Consensus wire/state

Pinned static evidence for Hyperliquid node `#94`
(`artifacts/node/94/hl-node`, sha256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`) covering
the TASKS.md paths `node/consensus/{types,signed,state}.rs`.

## What this proves

1. **Scoped Locations.** Exactly **13** first-party panic `Location` records
   under those three paths (state.rs: 11, types.rs: 1, signed.rs: 1),
   attributed via RIP `lea` into **8** FDE-bounded functions.
2. **Reconstruction seed status.** Of the can1357 seed addresses for these
   modules, the four verifier / state entrypoints
   (`0x47b01b0`, `0x454aa10`, `0x4758d70`, `0x47594f0`, `0x44a8420`,
   `0x44ab560`) are FDE starts; the types.rs serde seed VAs are **not** FDE
   starts (they sit inside other frames — claimed only as that negative).
3. **Message / tag inventory.** 24 literals (variant tags + diagnostic
   strings) with exact or length-prefixed-template `lea` anchors and their
   owning FDEs. Includes `VerifyQcSignature`, `QcNoQuorum`/`TcNoQuorum`,
   `Unexpected proposer for block`, and the packed
   `Qc does not have quorum` / `Tc does not have quorum` /
   `Failed to verify qc signature` strings (all lea-anchored at the first
   byte of the occurrence).
4. **Signature-verification call graph.** Among the four pinned verifier
   FDEs, the FDE-start-landing edges are:

   | from | to | kind | site |
   |---|---|---|---|
   | `verify_signed_block` `0x47b01b0` | `verify_qc` `0x4758d70` | rel32 | `0x47b0405` |
   | `verify_signed_block` `0x47b01b0` | `verify_tc` `0x47594f0` | rel32 | `0x47b0439` |
   | `verify_signed_timeout` `0x454aa10` | `verify_qc` `0x4758d70` | rel32 | `0x454ab03` |
   | `verify_tc` `0x47594f0` | `verify_signed_timeout` `0x454aa10` | rel32 | `0x475974f` |

   The proposer-mismatch template is owned by `0x47b01b0`. The three quorum /
   QC-signature diagnostic strings are owned by `0x4775de0`.
5. **Quorum-weight compare.** `verify_qc` reaches FDE `0x4ad90d0` through the
   RIP-slot call at `0x47590ca` → slot `0x5776ae8` (`R_X86_64_RELATIVE`
   addend `0x4ad90d0`). Inside that FDE the pinned sequence

   ```
   0x4ad9612  mov  edx, 3
   0x4ad9617  mov  rax, r10
   0x4ad961a  mul  rdx          ; rdx:rax = r10 * 3
   0x4ad961d  add  rcx, rcx     ; rcx = rcx * 2
   0x4ad9620  cmp  rcx, rax
   0x4ad9623  sbb  rsi, rdx
   0x4ad9626  setb al           ; al = 1 iff 2*rcx < 3*r10
   ```

   implements `2 * total < 3 * signed_weight` (with `rcx = total`,
   `r10 = signed_weight` as live at `0x4ad960b`), i.e. the integer form of
   `signed > (2/3) * total` / `floor(2*total/3)+1` threshold.

Instruction-start addresses include the REX prefix when present.

## Exact rerun

```bash
python3 -I -B tools/consensus_wire.py \
  --out research/work-items/RE-008-consensus-wire-state/consensus-wire.json
python3 -I -B research/work-items/RE-008-consensus-wire-state/verify.py
python3 -O -B research/work-items/RE-008-consensus-wire-state/verify.py
python3 -I -B -m unittest discover -s tests -p test_consensus_wire.py -v
```

Byte-identical JSON under `PYTHONHASHSEED=0/7/99`.

## Packet files

| file | role |
|---|---|
| `consensus-wire.json` | tool output (sorted keys, hex addresses) |
| `objdump-excerpts.txt` | human-readable disassembly at pinned sites |
| `MANIFEST.sha256` | sha256 of every packet file except itself |
| `verify.py` | fail-closed regenerating verifier |
| `README.md` | this file |

## What this does **not** claim

- No live-network / runtime behaviour; evidence is static ELF only.
- No full serde layout for `Timeout` / `Tc` / `Block` / `Signed` — the
  types.rs seed VAs are explicitly **not** FDE starts here.
- No claim that `0x4ad90d0` is *named* `has_quorum_weight` in DWARF; only
  that it is the slot-callee of `verify_qc` and contains the pinned
  `2*total < 3*signed` compare.
- No register provenance beyond the live state at `0x4ad960b` (the compare
  site). Calling-convention assignment of the two stake arguments is
  inferred from that live state + the inequality direction required for a
  quorum check, not from a recovered DWARF type.
- Does not cover `validator_set.rs` as a TASKS target (supporting only via
  the quorum callee and cross-check against the can1357 reconstruction
  comment).
- Does not claim node `#115` parity.
- Does not claim completeness of every consensus diagnostic string — only
  the 24 inventoried literals.
- Depends on RE-001 (binary pin) and on RE-005 (#10) for overlapping
  consensus-surface methodology; this packet does not re-litigate RE-005.

## Method

Stdlib-only deterministic decoder (`tools/consensus_wire.py`): ELF64 PT_LOAD
map, `.eh_frame_hdr` FDE index, `.rela.dyn` `R_X86_64_RELATIVE` scan, first-
party `Location` records under `/home/ubuntu/hl/code_Mainnet/`, RIP `lea`
attribution, exact/template literal anchors, verifier-local rel32/slot
edges that land on FDE starts, and pinned opcode checks for the quorum
compare. Cross-checked with `readelf -wf` / `readelf -rW` and `objdump -d`.
