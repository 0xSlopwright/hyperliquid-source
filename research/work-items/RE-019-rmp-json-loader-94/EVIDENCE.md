# RE-019: does 0x3c155a0 select MessagePack vs JSON by a case-folded `.rmp` extension?

- Component ID: RE-019-rmp-json-loader-94
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: base origin/main 1f8c67c63ca4794c9689235471c60297f8a5c985. No reference source is used.
- Claim status: observation for the FDE extent 0x3c155a0..0x3c15c70 (sha256-pinned), the whole-section e8 caller pass (exactly three sites), the absolute-`/` and `..` rejects, the case-folded `.rmp` extension gate, the two format arms (rmp_serde::from_slice via 0x2e0db40 vs serde_json::from_str via 0x2fe2fe0), the Ok payload length 0x1fc8 (memcpy) and Err tag movq $2, the five diagnostic label strings, and the two Location records at the callers. That the Result tag 2 is a Rust `Err` discriminant, and what the 0x1fc8-byte Ok payload means at the call sites, are inferences; see limitations.
- Scope included and excluded: included the FDE extent of 0x3c155a0, a whole-section e8 pass over .text/.init/.fini/.plt for callees equal to 0x3c155a0, 35 key instructions inside the function plus 6 at the three callers, five diagnostic label byte strings, and the Location records at 0x56dfc28 (state.rs:86) and 0x56dfbf8 (state.rs:107). Excluded: the body of 0x3273810 / call site 0x3273920 (RE-017), the GOT chain through 0x5773aa8 and the internals of 0x3751e80 (RE-016), the five contested [0x5773aa8] ABI windows (RE-018), and any claim that the shared diagnostic string at 0x1fd0ce is exclusive to this function (#365 cites the same string for a different restart-setting path).

## Reproduce

```
python3 -I -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -O -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -B research/work-items/RE-019-rmp-json-loader-94/independent_verify.py
python3 -B -m unittest tests.test_rmp_json_loader
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/rmp_json_loader.py | sha256sum; done
python3 -O -B tools/rmp_json_loader.py | sha256sum
```

Tool: Python 3.13 standard library only (no objdump, no pyelftools). Linux x86-64, working directory = repository root. No network, no execution of the target, no side effects; the tool reads the binary and writes only `--out` (or stdout).

Output: rmp-json-loader.json, sha256 d434acc77db5a0e8636833b1fab0d009416a9548b16d7ac49a4866d894fb472d. It is byte-identical for seeds 0, 7 and 99 and under -O. The tool emits nothing unless every exact expectation holds. File hashes are in MANIFEST.sha256.

## Evidence

All coordinates are virtual addresses (VAs) mapped through the PT_LOAD program headers. Analysis is complete for the listed ranges; nothing timed out.

1. **FDE extent.** Via .eh_frame_hdr datarel sdata4: function start 0x3c155a0, next start 0x3c15c70. Extent length **1744**. Extent sha256 **b9475c6190243bb4674d50321121a69fe42b87751dfcbea6acf3455738b08f8e**.

2. **Caller pass.** Every byte offset of .text, .init, .fini and .plt is tried as `e8` (target = site+5+disp32). Exact pinned result for target 0x3c155a0: **3** sites — 0x22aefea, 0x3273862, 0x4546bca. FDE starts: 0x22ae8a0, 0x3273810, 0x4546ba0. Each call is immediately preceded by an `lea rcx, Location` (0x56dfc28 at the two state.rs:86 sites; 0x56dfbf8 at the state.rs:107 site).

3. **Path rejects (bytes).** Early in the function: `cmpb $0x2f,(r15)` / `sete` at 0x3c155fc rejects an absolute `/` path; `cmpw $0x2e2e,(rsi)` at 0x3c156b5 rejects a `..` component. On those rejects (and other early failures) the function writes `movq $2,(rbx)` (Err tag) — five such sites at 0x3c1564a, 0x3c15819, 0x3c1590f, 0x3c15a49, 0x3c15b47 — and returns rbx.

4. **Case-folded `.rmp` gate (bytes).** After constructing a Path, the code scans for a trailing `.` (`cmpb $0x2e,-1(rsi,rdi)` at 0x3c156e1), then loads the next three bytes and folds each through the classic ASCII lowercase idiom (`lea reg,[char-0x41]`; `cmp $0x1a`; `setb`; `shl $5`; `or`) before comparing against `'r'` (0x72), `'m'` (0x6d), `'p'` (0x70) at 0x3c15718 / 0x3c15739 / 0x3c15756. Match takes the MessagePack arm; miss takes the JSON arm.

5. **Two format arms (bytes).**
   - **`.rmp` arm:** `call [0x576f640]` (open/read), then `call 0x2e0db40` at 0x3c15a9c, then `lea rax, rmp_serde::from_slice:` at 0x3c15add (label bytes at 0x1f3c9c pinned).
   - **non-`.rmp` arm:** `call [0x576f648]` (open/read_to_string), then `call 0x2fe2fe0` at 0x3c159ae, then `lea rax, serde_json::from_str:` at 0x3c159de (label bytes at 0x1fd0ce pinned).
   - Shared Ok path: `mov edx,0x1fc8` at 0x3c15b62 then `call [0x576dfe0]` (memcpy) copies a **0x1fc8**-byte payload into the out buffer.

6. **Diagnostic labels** (length-prefixed, trailing `c0`): missing file: (0x1f751c), read: (0x1f644e), read_to_string: (0x1de93b), serde_json::from_str: (0x1fd0ce), rmp_serde::from_slice: (0x1f3c9c). Byte strings pinned.

7. **Locations.** 0x56dfc28 → state.rs:86:40; 0x56dfbf8 → state.rs:107:37. Both point at the same path string at 0x1dd8eb (length 49). Read via .rela.dyn RELATIVE addends.

8. **41 key instructions** pinned byte-for-byte (35 inside the function + 6 at the three callers); see `key_bytes` in the JSON.

Resulting byte-proven fact: 0x3c155a0 is a path-selected loader that rejects absolute `/` and `..`, gates on a case-folded `.rmp` extension, decodes via rmp_serde::from_slice (0x2e0db40) or serde_json::from_str (0x2fe2fe0), returns Ok with a 0x1fc8-byte memcpy or Err with tag 2, and is called from exactly three sites that pass a state.rs Location.

## Implementation and comparison

Not yet implemented. No Rust re-implementation and no differential run; this is a static, bytes-only packet.

## Results and limitations

- Pinned counts: 3/3 e8 callers; 1744-byte extent; 41/41 key instructions; 5/5 labels; 2/2 Locations; Ok length 0x1fc8; Err tag 2; 19 decoded targets. independent_verify.py re-derives all of them without tools/.
- Inferred, not proven: that tag 2 is a Rust `Err` discriminant; what the 0x1fc8-byte Ok payload means at each caller; which source function name 0x3c155a0 implements beyond the Location-bearing call sites.
- Not claimed: the body of 0x3273810 / 0x3273920 (RE-017); the GOT chain 0x5773aa8 → 0x3751e80 (RE-016); the five contested ABI windows (RE-018); exclusive ownership of the shared `serde_json::from_str:` diagnostic at 0x1fd0ce (#365).
- Not covered by the caller pass: `ff15` / `jmp` indirect forms, and code outside the four scanned sections.

Next question: which on-disk filenames (beyond the `.rmp` gate) do the three callers pass, and does the 0x1fc8 Ok payload match the materializer block size RE-017 / RE-018 already pin at the [0x5773aa8] sites?
