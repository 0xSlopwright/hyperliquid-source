# RE-004: evm_extra_wei_decimals admission range - one 8-bit guard at every check site (node #94)

- Component ID: RE-004 (quantities/rounding; Wei decimal-scale admission)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  reference lead `references/can1357-hl/l1/spot_meta.rs` and
  `l1/exchange/impl_spot_deploy.rs` (used only to name the field `evm_extra_wei_decimals`
  and its i8 type; nothing copied)
- Claim status: observation for the byte-level facts listed under Evidence and for the
  256-value admission table; inference for the role names (insert vs. re-check path,
  pending-request map); unresolved items listed at the end
- Scope included and excluded: included - the one rodata message
  `EVM extra wei decimals must be between -2 and 18`, every RIP-relative LEA that loads it
  in `.text`, the FDE-bounded function holding each LEA, the 8-bit range guard that ends
  exactly at each LEA, the error payload written after it, and the
  `evm contract already set` check that jumps to the guard. Excluded - indirect
  references to the message, the scaling arithmetic that later consumes the decimals
  value (`pow10` multiply/divide of Wei amounts), the deserializer that produces the i8,
  and node #115.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3
(standard library only), GNU objdump 2.42 for the optional human cross-check.
The binary is only read; nothing is executed.

```
python3 tools/artifacts.py verify
python3 tools/evm_extra_wei_decimals.py --out research/work-items/RE-004-evm-extra-wei-decimals-94
python3 -m unittest tests.test_evm_extra_wei_decimals -v
(cd research/work-items/RE-004-evm-extra-wei-decimals-94 && sha256sum -c MANIFEST.sha256)
# optional cross-check of one site of each form
objdump -d -M intel --start-address=0x2748c50 --stop-address=0x2748d61 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x2748e2f --stop-address=0x2748f4a artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints the summary
`{"admitted_count": 21, "admitted_i8_max": 18, "admitted_i8_min": -2, "error_tags": [223],
"functions": 6, "guard_forms": 2, "lea_refs": 6, "sites_fully_verified": 6,
"sites_gated_by_already_set": 6, "sites_ok_path_stores_input_byte": 3,
"sites_with_exactly_one_guard": 6}` and writes `evidence.json`, `guards.tsv` and
`guard-bytes.txt` (MANIFEST hashes beside them). Run time is about 2-3 s.

## Evidence

Coordinates are ELF virtual addresses. For `.rodata` in this binary the VA equals the
file offset.

1. Message. `EVM extra wei decimals must be between -2 and 18` occurs exactly once in
   `.rodata`, at 0x599967. It is 48 bytes long and has no NUL; Rust `&str` pieces are
   passed as (pointer, length). The neighbouring message `evm contract already set`
   (0x59994f, 24 bytes) also occurs exactly once.
2. References. Six `lea r64,[rip+disp32]` instructions in `.text` resolve to 0x599967:
   0x2748cf8, 0x2748f1c, 0x4d64c48, 0x4d64d68, 0x4d64f8c and 0x4d65a9c. Each one lies
   in a different FDE (pc ranges in `guards.tsv`, which come from `.eh_frame_hdr` plus
   each FDE body).
3. Guard. Exactly one guard decodes so that it ends at the first byte of each LEA. There
   are two byte forms:
   - Form A, at 0x2748cf0, 0x4d64c40 and 0x4d64d60: `41 8d 40 ed 3c ea 77 23`, which is
     `lea eax,[r8-0x13]`, `cmp al,0xea`, `ja ok`.
   - Form B, at 0x2748f12, 0x4d64f82 and 0x4d65a92: `41 80 c1 ed 41 80 f9 eb 73 2e`,
     which is `add r9b,0xed`, `cmp r9b,0xeb`, `jae ok`.

   The fall-through of each guard is the message LEA, so the error is built when the
   branch is not taken. Every branch target lies inside the same FDE and after the
   error block.
4. Full-domain table. The tool evaluates `res = (x + k) & 0xff` and then `res > c`
   (ja) or `res >= c` (jae) for all 256 input bytes. It uses k = 0xed and c = 0xea/ja
   for form A, and k = 0xed and c = 0xeb/jae for form B. Both forms admit exactly 21
   values, which read as i8 are exactly -2..=18. That matches the bounds parsed from the
   message itself. Every other byte, including 19..127 and -128..-3, takes the error
   path. The per-byte table is in `guards.tsv`.
5. Error payload, the same at all six sites:
   - `mov e?x,0x30` (48 = message length),
   - `mov word [rdi],0xdf`,
   - `mov [rdi+8],<lea reg>`,
   - `mov [rdi+0x10],<length reg>`.

   The enum tag 0xdf (223) is also written on the "already set" path
   (`lea ...0x59994f; mov e?x,0x18`) and on the `Pending EVM contract missing` path
   (0x3efe7e, 0x1c) in form-B functions. In other words, these failures share a single
   (ptr, len) message-carrying error variant.
6. Gate. At every site a `cmp byte [base+idx+0xbc],0` (`41/43 80 bc .. bc 00 00 00 00`)
   is followed by `je <guard start>`, and its fall-through is the
   `evm contract already set` LEA. The je instructions are at 0x2748ce0, 0x2748ee8,
   0x4d64c30, 0x4d64d50, 0x4d64f58 and 0x4d65a68. So the range check runs only when that
   flag byte is zero. The index is scaled by `imul ..,0xe8`, which gives a 0xe8-byte
   record stride (see `guard-bytes.txt`).
7. Input source and ok path:
   - Form A tests r8. No movzx into r8 precedes the guard. The ok target
     (0x2748d1b and so on) copies 20 bytes from `[rcx]` to `[rsp..rsp+0x14)` and then
     stores `r8b` unchanged at `[rsp+0x14]` (`44 88 44 24 14`, at 0x2748d2b, 0x4d64c7b
     and 0x4d64d9b). It then does `add rsi,0x468` before a direct call.
   - Form B tests r9, which is loaded by `movzx r9d, byte [rax+0x14]` (`44 0f b6 48 14`)
     218 bytes before the guard. Those functions start with `mov r9,[rsi+0x468]`.

## Implementation and comparison

Not yet implemented. No Rust path exists in this packet. The predicate to implement is
`(-2..=18).contains(&v)` on an `i8`. Equivalently, on the raw byte,
`((b as u8).wrapping_add(0xed)) >= 0xeb`. The evidence table gives the expected verdict
for each of the 256 inputs.

Corruption controls in `tests/test_evm_extra_wei_decimals.py`:
- the analysis is rejected for a truncated buffer and for one flipped message byte
  (SHA-256 mismatch);
- `jbe` instead of `ja`, or a compare on a different register, does not decode as a
  guard;
- shifting c by one (0xeb with ja), swapping the jcc (0xea with jae) or shifting the
  bias (k = 0xec) each changes the admitted set;
- the boundary bytes 19 and -3 are rejected, and -2 and 18 are admitted;
- `Image.read(0x10)` and `Fdes.range_of(0x1000)` raise;
- a message without "between A and B" bounds raises;
- a fresh `--out` run is byte-identical to the packet files.

## Results and limitations

| metric | value |
|---|---|
| message LEA references | 6 / 6 sites analysed |
| sites with exactly one decoded guard | 6 / 6 |
| sites fully verified (guard + payload + range == message) | 6 / 6 |
| guard byte forms | 2 (A: lea/cmp/ja, B: add/cmp/jae) |
| admitted i8 values per guard | 21 / 256, exactly -2..=18 |
| sites gated by the `already set` flag | 6 / 6 |
| ok path stores the tested byte unchanged | 3 / 3 form-A sites; form B not measured |

Inferences (not proved by bytes):
- Form A is the request/insert path. The decimals byte is stored next to a 20-byte EVM
  address and then inserted through `self+0x468`.
- Form B is the later re-check of that stored pending record (the byte at +0x14).
- The three copies of each form are monomorphised or duplicated callers of the same
  source check.

Unresolved:
- Indirect references to the message are not searched.
- In form B the tool does not prove that no other path writes r9 between the movzx and
  the guard. A manual objdump scan of 0x2748e38..0x2748f12 shows no other r9 write.
- The caller ABI role of r8 in form A is inferred from SysV, not proved.
- Field offsets 0x468 and 0xbc are named only by inference.

No progress gate is requested. The packet is evidence only.

Next question: how does node #94 scale a Wei amount by `evm_extra_wei_decimals`? Which
pow10 source does it use, does it multiply or divide for the negative values -2 and -1,
and is the multiply checked, saturating or wrapping?
