# RE-004: spot token szDecimals/weiDecimals admission guards (node #94)

- Component ID: RE-004 (quantities/rounding; spot token size/wei decimal-scale admission)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  reference leads `references/can1357-hl/l1/spot_meta.rs` and
  `l1/exchange/handlers/26_spot_deploy.rs`. They were used only to name the message
  `must have szDecimals <= weiDecimals <= 10`. Nothing was copied. The reference has no
  code for the two other messages checked here.
- Claim status: the byte-level facts under Evidence and the 65536-pair admission counts
  are observations. The handler and role names are inferences. Unresolved items are
  listed at the end.
- Scope included and excluded:
  - Included: the three unique `.rodata` messages `szDecimals too large`,
    `weiDecimals must be at least szDecimals + 5` and
    `must have szDecimals <= weiDecimals <= 10`; every RIP-relative LEA in `.text` that
    loads one of them; the FDE-bounded function around each LEA; the byte guard that
    decides whether each error is built; the error payload; and the movzx loads that
    feed the guard registers.
  - Excluded: indirect references to the messages; the deserializer that produces the
    two u8 fields; any later use of the decimals (pow10 scaling of sizes or wei
    amounts); the other spot-deploy checks in the same functions (name, fee share,
    HYPE); and node #115.

## Reproduce

Run from the repository root. Platform used: Linux x86-64, Python 3.12.3 (standard
library only), and GNU objdump 2.42 for the optional cross-check. The binary is only
read; nothing is executed.

```
python3 tools/artifacts.py verify
python3 tools/spot_token_decimals.py --out research/work-items/RE-004-spot-token-decimals-94
python3 -m unittest discover -s tests -p 'test_spot_token_decimals.py' -v
(cd research/work-items/RE-004-spot-token-decimals-94 && sha256sum -c MANIFEST.sha256)
# optional cross-check: the deploy guard and one site of each range byte form
objdump -d -M intel --start-address=0x375f4c3 --stop-address=0x375f51a artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x274fb38 --stop-address=0x274fbae artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x28d2ca0 --stop-address=0x28d2cfa artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints this summary:

```
{"deploy_add_can_wrap": false, "deploy_admitted_pairs": 1491, "deploy_gated": 1,
 "deploy_lea_refs": 1, "deploy_sites_decoded": 1, "deploy_sites_fully_verified": 1,
 "deploy_sz_max": 5, "deploy_wei_offset": 5, "error_tags": [223],
 "joint_admitted_pairs": 21, "range_admitted_pairs": [66], "range_byte_forms": 2,
 "range_functions": 5, "range_lea_refs": 5, "range_load_disps": [[24, 25]],
 "range_sites_fully_verified": 5, "range_sites_with_exactly_one_guard": 5,
 "wei_min_lea_refs": 1}
```

It writes `evidence.json`, `admission.tsv` and `guard-bytes.txt`; `MANIFEST.sha256`
sits beside them. A run takes about 5 s.

## Evidence

Coordinates are ELF virtual addresses. For `.rodata` in this binary the VA equals the
file offset.

1. Messages. Each message occurs exactly once in `.rodata`:

   | message | address | bytes |
   |---|---|---|
   | `szDecimals too large` | 0x5997f9 | 20 |
   | `weiDecimals must be at least szDecimals + 5` | 0x5997ce | 43 |
   | `must have szDecimals <= weiDecimals <= 10` | 0x599ade | 41 |

   None is NUL-terminated. They are passed as (pointer, length).
2. Deploy guard. There is one site, in the FDE range 0x375f3d0..0x375fa78 (FDE
   0x11a6d88). Each of the first two messages has exactly one `lea r64,[rip+disp32]`:
   0x375f4dd for the first and 0x375f502 for the second. Both sit inside a single
   contiguous byte run, 0x375f4c3..0x375f51a:
   - `49 8b 8e 88 01 00 00` `48 85 c9` `74 4b` is `mov rcx,[r14+0x188]; test rcx,rcx;
     je 0x375f51a`.
   - `0f b6 44 24 18` `3c 05` `76 1d` is `movzx eax,byte [rsp+0x18]; cmp al,5;
     jbe 0x375f4f5`.
   - The fall-through writes tag 0xdf with `mov word [rbx],0xdf`, the message pointer
     into `[rbx+8]` and the length into `[rbx+0x10]` (20). It then jumps to 0x375f7ad.
   - At 0x375f4f5: `04 05` `38 44 24 19` `73 1d` is `add al,5; cmp [rsp+0x19],al;
     jae 0x375f51a`.
   - That fall-through writes tag 0xdf, the second message and length 43, then also
     jumps to 0x375f7ad.

   The `je` of the gate and the `jae` go to the same address, 0x375f51a, which is the
   first byte after the second error block. The `jbe` target is exactly the `add`.
3. Deploy admission over the full domain. The tool evaluates the decoded arithmetic for
   all 65536 byte pairs (sz = `[rsp+0x18]`, wei = `[rsp+0x19]`). The rule is
   `sz <= 5` (unsigned jbe), then `wei >= (sz + 5) & 0xff` (u8 add, unsigned jae).
   - 1491 pairs are admitted.
   - 0 pairs disagree with the predicate taken from the messages, `sz <= 5 && wei >= sz + 5`.
   - The admitted sz values are 0..=5. For those, `sz + 5` is at most 10, so the u8 add
     cannot wrap (`deploy_add_can_wrap: false`).
   - The minimum wei for sz 0..5 is 5..10.
   - There is no upper bound on wei in this guard.
4. Range guard. There are five LEAs of the third message, each in a different FDE:
   0x274fb97, 0x28d2cec, 0x49e1bcc, 0x4d725f7 and 0x4d728b7. Exactly one guard decodes
   so that it ends at each LEA. It comes in two byte forms that differ only in register
   choice:
   - Form A, at 0x274fb7e, 0x4d725de and 0x4d7289e:
     `45 38 ec 0f 97 c0 41 80 fd 0b 0f 93 c1 08 c1 0f 84 fe 00 00 00 66 bd df 00`.
     This is `cmp r12b,r13b; seta al; cmp r13b,0xb; setae cl; or cl,al; je ok;
     mov bp,0xdf`.
   - Form B, at 0x28d2cd3 and 0x49e1bb3: the same sequence on `r15b`/`bpl`, with
     `mov ax,0xdf`.

   The error (tag 0xdf) is built only when `a > b` or `b >= 11` (both unsigned). After
   each LEA comes `mov r32,0x29` (41 = message length). Every `je` target lies inside
   its own FDE and after the LEA.
5. Range admission over the full domain: the rule `!(a > b) && !(b >= 11)` admits 66 of
   65536 pairs at all five sites. It has 0 mismatches against the message predicate
   `sz <= wei <= 10`. Changing 11 to 10, or swapping the operands, both produce
   mismatches (unit test).
6. Operand sources. At every range site, the last byte load into the first compare
   register reads `[X+0x18]`, and the last load into the second reads `[X+0x19]`:
   - in form A, `movzx r12d,byte [r13+0x18]` and `movzx r13d,byte [r13+0x19]`;
   - in form B, `movzx r15d,byte [rsi+0x18]` and `movzx ebp,byte [rsi+0x19]`.

   This is the same pair of offsets that the deploy guard reads as sz (0x18) and wei
   (0x19) from `[rsp+..]`.
7. Joint table. The tool also intersects the two decoded predicates. 21 pairs satisfy
   both: sz 0..=5 and wei sz+5..=10. The 16x16 grid in `admission.tsv` lists the
   per-site verdicts.

## Implementation and comparison

Not yet implemented. No Rust path exists in this packet. The predicates to implement
on `u8` fields are:
- range check: `sz_decimals <= wei_decimals && wei_decimals <= 10`;
- deploy check: `sz_decimals <= 5`, then `wei_decimals >= sz_decimals + 5`. The first
  failing check selects the message. The second check is evaluated only after the first
  passes, so its `+ 5` cannot overflow.

`admission.tsv` gives the expected verdict for each (sz, wei) in 0..16, and
`evidence.json` gives the counts over the whole domain.

Corruption controls in `tests/test_spot_token_decimals.py`:
- the analysis is rejected for a truncated buffer and for one flipped message byte
  (SHA-256 mismatch);
- in the range form, `setb` instead of `seta`, a compare of a different register, or
  `jne` instead of `je` does not decode;
- in the deploy guard, `ja` instead of `jbe`, or a misaligned LEA offset, does not
  decode;
- bound 10 instead of 11, swapped operands, or a deploy offset of 4 instead of 5 each
  changes the admitted set;
- the deploy wrap case appears only under a widened sz bound;
- `Image.read(0x10)` and `Fdes.range_of(0x1000)` raise;
- malformed messages raise;
- a fresh `--out` run is byte-identical to the packet files.

## Results and limitations

| metric | value |
|---|---|
| deploy message LEAs (sz / wei) | 1 / 1, one decoded guard covering both |
| deploy admitted pairs | 1491 / 65536, 0 mismatches vs the message predicate |
| range message LEAs | 5, in 5 FDEs |
| range sites with exactly one decoded guard | 5 / 5 |
| range sites fully verified (guard + tag + length + predicate) | 5 / 5 |
| range admitted pairs | 66 / 65536 at every site, 0 mismatches |
| range operand loads at +0x18 / +0x19 | 5 / 5 |
| pairs admitted by both predicates | 21 |

Inferences (not proved by bytes):
- Function 0x375f3d0 is the spot-deploy token registration handler. The same function
  also loads `cannot use name of existing perp asset` (0x59980d),
  `deployer trading fee share cannot be more than 100%` (0x599833) and
  `unexpected deployer` (0x599724), and it compares a 4-byte name with `HYPE`
  (`cmp dword [rax],0x45505948`).
- Offset 0x18 is `szDecimals` and 0x19 is `weiDecimals` of one token spec layout. This
  is consistent with the messages and with the serde field order
  `szDecimals`/`weiDecimals` in `.rodata`.
- The five range sites are monomorphised or duplicated copies of one validation
  routine.
- At the form-A sites a `call` lies between the movzx loads and the guard. The values
  survive it only because r12, r13, r15 and rbp are callee-saved under SysV; this is
  ABI-based, not proved here.

Unresolved:
- The meaning of the gate `[r14+0x188] != 0`: the deploy checks are skipped entirely
  when it is zero.
- Whether one request passes through both the deploy guard and a range guard. The
  21-pair joint set is therefore only a derived table, not a claimed rule.
- Indirect references to the messages are not searched.
- The tool does not prove that nothing else writes the operand registers between the
  movzx loads and the guards; it reports the last load only.

No progress gate is requested. The packet is evidence only.

Next question: where does node #94 use `weiDecimals - szDecimals`? For example, does it
convert a size lot to wei with a pow10 table, and is that multiply checked, saturating
or wrapping?
