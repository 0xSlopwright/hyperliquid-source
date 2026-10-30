# RE-004: WeiPriv integer admission - sign-bit guard at every "when visiting i64" site (node #94)

- Component ID: RE-004 (quantities/rounding; Wei family)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  reference lead `references/can1357-hl/l1/qtys/impl_wei.rs` (the visitor diagnostic
  string only; nothing copied)
- Claim status: observation for the byte-level facts listed under Evidence;
  inference for the serde/rmp/JSON role names; unresolved items listed at the end
- Scope included and excluded: included - the one rodata diagnostic piece
  `invalid value {} for WeiPriv when visiting i64`, every RIP-relative LEA that
  loads it in `.text`, the FDE-bounded functions holding those LEAs, every direct
  `call rel32` to those functions, and the sign guard that routes each caller to
  that call. Excluded - indirect calls/jumps to the constructors, Wei arithmetic
  (add/sub/mul overflow), Wei display/decimal scaling, BigNtlPriv, and node #115.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3
(standard library only), GNU objdump 2.42 for the optional human cross-check.
The binary is only read; nothing is executed.

```
python3 tools/artifacts.py verify
python3 tools/weipriv_sign_guard.py --out research/work-items/RE-004-weipriv-sign-guard-94
python3 -m unittest tests.test_weipriv_sign_guard -v
sha256sum -c research/work-items/RE-004-weipriv-sign-guard-94/MANIFEST.sha256
# optional cross-check of one caller and one constructor
objdump -d -M intel --start-address=0x16ca240 --stop-address=0x16ca353 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x26bb3c0 --stop-address=0x26bb405 artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints the summary
`{"call_sites": 6, "call_sites_with_exactly_one_sign_guard": 6, "constructors": 5,
"guard_value_is_formatted_value": true, "lea_refs": 5, "ok_path_stores_unchanged": 4}`
and writes `evidence.json`, `call-sites.tsv` and `caller-bytes.txt` (MANIFEST
hashes beside them).

## Evidence

Coordinates are ELF virtual addresses. `.rodata` VA equals file offset;
`.text` VA = file offset + 0x1000 (section table). Function extents come from
the `.eh_frame_hdr` search table (121299 entries) plus each FDE's own
`pc_begin`/`pc_range` (CIE `zR`, pointer encoding read from the CIE), not from
the start-only unwind index.

1. Diagnostic piece. Exactly one occurrence of
   `" for WeiPriv when visiting i64\0"` exists in `.rodata`. The piece starts at
   VA `0x1fa26e` with byte `0x0e` (= 14 = length of `"invalid value "`), then the
   literal, then `c0 1e`, then the tail; it ends at `0x1fa29e`
   (`evidence.json: piece.bytes_hex`).
2. Loads of the piece. 5 RIP-relative `lea r64,[rip+disp32]` in `.text` resolve
   into `[0x1fa26e,0x1fa29e)`, all to `0x1fa26e`: `0x26bb396`, `0x26bb3da`,
   `0x324d2aa`, `0x324d2f6`, `0x42c33ba`. Each lies in a distinct FDE
   (constructors `0x26bb380`, `0x26bb3c0`, `0x324d290`, `0x324d2e0`,
   `0x42c33a0`, 62..69 bytes each). objdump of `0x26bb3c0..0x26bb405` shows the
   only data flow: the caller's value pointer and a GOT-loaded formatter pointer
   are placed on the stack, an indirect call through the GOT builds the message
   from the piece, and the result goes to an error builder (`call 0x1704700`);
   no comparison is made on the value inside the constructor.
3. Callers. 6 direct `call rel32` reach those 5 constructors (`call-sites.tsv`):

   | call | constructor | caller FDE range | guard | jcc | value read width in caller |
   |---|---|---|---|---|---|
   | 0x16ca30a | 0x26bb3c0 | 0x16ca240..0x16ca353 | `test rax,rax` @0x16ca29b | js | `movsx rax, byte` @0x16ca283 |
   | 0x289833c | 0x26bb380 | 0x28980f0..0x289876d | `test r14,r14` @0x289832e | jns | result of callee 0x1b2eb80 |
   | 0x2aab9da | 0x324d290 | 0x2aab910..0x2aaba23 | `test rax,rax` @0x2aab96b | js | `movsx rax, byte` @0x2aab953 |
   | 0x2efcf5a | 0x324d290 | 0x2efccd0..0x2efcfc8 | `test rax,rax` @0x2efcf1c | js | `movsx` @0x2efcea5 / `bswap` @0x2efcf0c |
   | 0x330374d | 0x324d2e0 | 0x33034e0..0x3303ac2 | `test r14,r14` @0x330373f | jns | result of callee 0x2fe3cd0 |
   | 0x3d71e7a | 0x42c33a0 | 0x3d71db0..0x3d71ec3 | `test rax,rax` @0x3d71e0b | js | `movsx rax, byte` @0x3d71df3 |

   For all 6, the tool finds exactly one `test r64,r64` immediately followed by
   `js`/`jns` whose error side reaches the call within 5 or 13 bytes, the
   instruction immediately before the `test` spills the same register to
   `[rsp+disp8]`, and the error block passes that same slot (`lea r64,[rsp+disp8]`)
   to the constructor, so the value that is tested is the value printed in the
   message (`guard_value_is_formatted_value: true`).
4. Admission predicate. `test r,r` sets SF to bit 63 of the 64-bit register and
   clears OF/CF; `js`/`jns` branch on SF only. So at every site the value is
   rejected iff bit 63 is set, i.e. iff the signed 64-bit value is < 0, for all
   2^64 register values. `guard_model` lists boundaries: 0 and 2^63-1 admitted;
   2^63 (i64::MIN) and 2^64-1 (-1) rejected. Narrower inputs are sign-extended
   first (`movsx r64, byte`), so an 8-bit -1 also reaches the reject path.
5. Accepted value is not transformed. On the 4 `js` sites, the fall-through
   begins with `mov [rdi+8], <tested reg>` and the next instruction writes tag
   byte 9 to `[rdi]` (bytes in `caller-bytes.txt`; `ok_stores_tested_value_unchanged`).
   On the 2 `jns` sites the ok target is `xor eax,eax` then a join that does
   `mov rdx,r14; ... ret` (objdump `0x289828b`, `0x2898631`; `0x330367b`,
   `0x33039ac`) - the tool reports these as not matching its `[rdi+8]` store
   pattern; the pass-through there is an objdump observation only.
   No scaling, clamping, absolute value or wrap is applied on any accepted path.
6. Unsigned path has no guard. In `0x2efccd0`, a second big-endian 8-byte read
   (`bswap rdx` @0x2efcf32) is stored to `[rdi+8]` and tag 9 is written
   (`0x2efcf3d`, `0x2efcf41`) without any `test`/`js`.

Analysis was complete for the declared scope (whole `.text` scanned for the
two instruction forms). Indirect calls into the constructors were not searched.

## Implementation and comparison

Not yet implemented. No Rust component is added. A future independent
`WeiPriv` deserializer should: accept every u64 unchanged; accept i64 only if
`v >= 0` and store `v as u64` unchanged; reject `v < 0` with the
"invalid value .. when visiting i64" diagnostic. No differential execution was
run (RE-003 is not available), so no comparison or normalization mask exists.

## Results and limitations

- Metrics (denominators explicit): 1/1 diagnostic piece found; 5/5 LEAs to it
  lie in 5 distinct FDEs; 6 direct call sites; 6/6 with exactly one sign guard;
  6/6 guard value tied to the formatted value; 4/6 ok paths matched by the
  `[rdi+8]` store pattern (2/6 checked by objdump only).
- Unit tests: 10 tests in `tests/test_weipriv_sign_guard.py`, including
  negative controls (wrong digest, `js`->`jl` corruption in a real caller and
  in the full binary, wrong spilled register, `test rax,rcx`, 8/32-bit tests,
  out-of-section VA, address in FDE padding, error block beyond the limit).
- Inferences, not proven: 0x16ca240/0x2aab910/0x3d71db0 look like an rmp
  ext-type style reader (state byte at `[rsi+0xc]`, one signed byte);
  0x2efccd0 looks like an rmp integer reader (i8/i64/u64 markers);
  0x28980f0/0x33034e0 look like serde_json integer parsing (ASCII digit test
  `add dil,0xd0; cmp dil,0xa`; result tag 2 is the sign-checked arm). The tag
  value 9 as `Ok` niche is inferred from the caller's `cmp al,0x9` check.
- Unresolved: whether the constructor results can ever be tag 9 (callers check
  it; callees `0x1704700`, `0x1eba7f0` not analysed); indirect-call users of
  the constructors; which Wei-carrying structs own each monomorphization.
- No progress gate is requested.

Next question: do Wei add/sub helpers in #94 use checked arithmetic with a
panic/err path or saturating arithmetic over this u64 domain?
