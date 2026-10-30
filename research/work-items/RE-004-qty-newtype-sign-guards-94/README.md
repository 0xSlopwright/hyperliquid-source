# RE-004: integer admission sign guards of NtlPriv, BigNtlPriv, SzPriv, SziPriv and NtliPriv (node #94)

- Component ID: RE-004 (quantities/rounding; Ntl, BigNtl, Sz, Szi and Ntli newtypes)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  reference lead `references/can1357-hl/l1/qtys/mod.rs` (`raw_newtype!` raw
  widths, used only as labels; nothing copied)
- Claim status: observation for the byte-level facts listed under Evidence;
  inference for the raw widths and the serde/JSON/binary-reader role names;
  unresolved items are listed at the end
- Scope included and excluded: included - the five rodata diagnostic pieces
  `invalid value {} for <T> when visiting <i64|u64>` for T in NtlPriv,
  BigNtlPriv, SzPriv (i64 input) and SziPriv, NtliPriv (u64 input); every
  RIP-relative LEA that loads them in `.text`; the FDE-bounded functions holding
  those LEAs; every direct `call rel32` to those functions; the 64-bit sign
  guard that routes each caller to that call; and every other branch into the
  same error block. Excluded - WeiPriv (separate packet,
  `RE-004-weipriv-sign-guard-94`), the three PxPriv pieces (they use a different
  multi-step decision, see Next question), indirect calls to the constructors,
  arithmetic on these types, and node #115.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3
(standard library only), GNU objdump 2.42 for the optional human cross-check.
The binary is only read; nothing is executed.

```
python3 tools/artifacts.py verify
python3 tools/qty_newtype_sign_guards.py --out research/work-items/RE-004-qty-newtype-sign-guards-94
python3 -m unittest tests.test_qty_newtype_sign_guards -v
sha256sum -c research/work-items/RE-004-qty-newtype-sign-guards-94/MANIFEST.sha256
# optional cross-check: one binary-reader caller (js form, i8/i16/i32 paths) and one jns-form caller
objdump -d -M intel --start-address=0x2e65a90 --stop-address=0x2e65d88 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x28dda90 --stop-address=0x28de065 artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints the summary
`{"all_sites_one_tied_guard": true, "call_sites": 34, "call_sites_with_exactly_one_sign_guard": 34,
"caller_functions": 34, "constructors": 16, "guard_value_is_formatted_value": 34, "jns_guards": 23,
"js_guards": 11, "lea_refs": 16, "mismatch_vs_message_predicate": 0, "narrow_guards": 21,
"narrow_mismatch_vs_message_predicate": 0, "ok_path_stores_unchanged": 11, "unexplained_error_entries": 0}`
and writes `evidence.json`, `call-sites.tsv` and `guard-bytes.txt` (MANIFEST
hashes beside them).

## Evidence

Coordinates are ELF virtual addresses. `.rodata` VA equals file offset;
`.text` starts at VA `0x1343c80` (70370352 bytes). Function extents come from
the `.eh_frame_hdr` search table (121299 entries) plus each FDE's own
`pc_begin`/`pc_range`, not from the start-only unwind index.

1. Diagnostic pieces. Each needle `" for <T> when visiting <t>\0"` occurs
   exactly once in `.rodata`, preceded by byte `0x0e` (= 14 = length of
   `"invalid value "`), the literal, and `c0 <n>` (format-argument marker):

   | newtype | visited | piece VA | LEAs | constructors (FDE start, size) |
   |---|---|---|---|---|
   | NtlPriv | i64 | 0x1ebe70 | 4 | 0x26bb340 (62), 0x3317ed0 (69), 0x3317f20 (62), 0x4592eb0 (62) |
   | BigNtlPriv | i64 | 0x1ee681 | 3 | 0x26bb5c0 (62), 0x3bf91d0 (62), 0x3bf9210 (69) |
   | SzPriv | i64 | 0x1f0bda | 3 | 0x1e64da0 (62), 0x324d0e0 (62), 0x324d120 (69) |
   | SziPriv | u64 | 0x1f0d7f | 3 | 0x22dcee0 (62), 0x3bf82e0 (69), 0x3bf8330 (62) |
   | NtliPriv | u64 | 0x1fd385 | 3 | 0x22dd1a0 (62), 0x3bf8370 (62), 0x3bf83b0 (69) |

   16 LEAs in total, each in its own FDE (`evidence.json: types[].lea_refs`,
   `constructors`). None of these 16 functions is shared with the WeiPriv packet.
2. Callers. 34 direct `call rel32` reach those 16 constructors, from 34
   distinct caller FDEs (`call-sites.tsv`). For each, the tool finds exactly one
   `test r64,r64` immediately followed by `js`/`jns` whose error side reaches the
   call within 5 bytes (`jns` form, 23 sites, register r14) or 13 bytes (`js`
   form, 11 sites, register rax or rcx). In all 34 the instruction just before
   the `test` spills the same register to `[rsp+disp8]` and the error block
   passes that slot (`lea r64,[rsp+disp8]`) to the constructor, so the tested
   value is the value printed in the message.
3. Admission predicate (64-bit path). `test r,r` sets SF = bit 63 and `js`/`jns`
   branch on SF only, so every site rejects exactly the register values with
   bit 63 set, for all 2^64 values. The tool compares this with the message
   predicate (i64 input to an unsigned-named type: admit `v >= 0`; u64 input to
   a signed-named type: admit `v <= i64::MAX`) on 190 boundary samples
   covering both SF classes (0, 1, 2^k, 2^k-1, 2^64-2^k, i64::MIN/MAX, u64::MAX):
   0 mismatches at 34/34 sites.
4. Narrow-width paths. The tool lists every `jmp`/`jcc` (rel8/rel32) in the
   caller FDE whose target is the guard's error entry. In the 7 `js`-form
   callers of NtlPriv, BigNtlPriv and SzPriv there are 3 more entries each
   (21 total), every one being `test r8|r16|r32,same; jns <ok entry>; jmp <error>`
   preceded within 16 bytes by a REX.W sign extension into the tested register
   (`movsx r64,r8`, `movsx r64,r16`, `movsxd r64,r32`). Example, caller
   `0x2e65a90`: `0x2e65b9d 84 c0 / 0f 89 ..` (i8), `0x2e65bdc 66 85 c0 / 0f 89 ..`
   (i16), `0x2e65b3d 85 c0 / 0f 89 ..` (i32), main `0x2e65cdc 48 85 c0 / 78 2c`.
   The narrow guards reject exactly the negative inputs of their width
   (exhaustive over 2^8 and 2^16; 65 boundary samples for 32-bit): 0 mismatches.
   The 4 `js`-form SziPriv/NtliPriv callers have no other entry (their narrow
   u8/u16/u32 inputs cannot exceed i64::MAX). The 23 `jns`-form error blocks
   have no incoming branch (fall-through only). `unexplained_error_entries: 0`.
5. Accepted value is not transformed (11 sites matched by pattern). On the 11
   `js` sites the fall-through starts with `mov [rdi+8], <tested reg>`
   (`ok_stores_tested_value_unchanged`; `ok_entry_hex` `48894708eb1a..` for the
   7 i64-input sites, `48894f08ebce..` for the 4 u64-input sites), then a short
   `jmp` to a join. For caller `0x2e65a90` objdump shows that join writing tag
   byte 9 (`0x2e65d01 c6 07 09`); the other joins were not decoded. The 23 `jns`
   sites jump to an ok block whose first instruction is not that store; the
   tool does not decode it.

Analysis was complete for the declared scope (whole `.text` scanned for LEAs
and `call rel32`; whole caller FDEs scanned for guards and branches). Indirect
calls into the constructors were not searched.

## Implementation and comparison

Not yet implemented. No Rust component is added. A future independent
deserializer for these five newtypes should: for NtlPriv, BigNtlPriv and SzPriv
accept an i64 only if `v >= 0` (narrow signed inputs are sign-extended first);
for SziPriv and NtliPriv accept a u64 only if `v <= i64::MAX`; on reject emit
the "invalid value .. when visiting <t>" diagnostic. No differential execution
was run (RE-003 is not available), so there is no comparison or normalization
mask.

## Results and limitations

- Metrics (denominators explicit): 5/5 diagnostic pieces found once each;
  16/16 LEAs in 16 distinct FDEs; 34 direct call sites in 34 caller FDEs;
  34/34 with exactly one 64-bit sign guard; 34/34 guard value tied to the
  formatted value; 0/34 predicate mismatches; 21/21 narrow entries decoded
  (0 mismatches); 0 unexplained error-block entries; 11/34 ok paths matched by
  the `[rdi+8]` store pattern (23/34 not decoded).
- Unit tests: 11 tests in `tests/test_qty_newtype_sign_guards.py`, including
  negative controls: wrong digest; `js`->`jl` in a real caller and in the whole
  binary (digest refusal); i32 `jns`->`jge` in a real caller (that narrow
  entry is no longer decoded); wrong spilled register; `test rax,rcx`;
  64-bit test given to the narrow decoder; memory-operand test; address in FDE
  padding; out-of-section VA; a diagnostic that does not exist (`SzPriv` u64).
- Inferences, not proven: the raw widths (u64, u128, i64) are labels from the
  reference tree; the binary only gives the type name and the visited type.
  The `js` form looks like a big-endian binary reader (bswap 8-byte reads,
  `movsx` 1/2/4-byte reads, tag 9 written on success); the `jns` form looks like
  a JSON integer path. Tag 9 as the `Ok` niche is inferred from callers.
- Unresolved: what the 23 `jns`-form ok blocks do with the value; which
  structs own each monomorphization; indirect-call users of the constructors;
  whether BigNtlPriv (u128) also has a visit_i128/u128 path with its own guard.
- No progress gate is requested.

Next question: the three PxPriv diagnostics (`when visiting u64`, `when
visiting i64`, `converting to intermediate u64 when visiting i64`) share
callers and use a multi-step decision instead of a single sign test; what
exact set of i64/u64 inputs does each PxPriv caller admit?
