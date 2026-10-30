# RE-001 / foundation: node94 truncated-debug cutpoint family

Question: does the source-location-linked debug formatter round a long string's
10,000-byte cutpoint down to a UTF-8 boundary, or check that exact byte position?
This packet covers one family across its monomorphized bodies, not separate
contributions per copy. It is partial RE-001 research, not a completed component.

## Identity and ownership

- Independent base: main `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Input: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Producer: `tools/truncated_debug_static.py`; six tests in
  `tests/test_truncated_debug_static.py`. Original independently authored code;
  no can1357 implementation, comments or inferred source copied.
- Embedded source path: `/home/ubuntu/hl/code_Mainnet/base/src/truncated_debug.rs`
  at linked VA `0x201a1a`. This is target evidence, not a local fixture path.
- Five R_X86_64_RELATIVE Location-pointer slots bind that path:
  `0x566a630`, `0x56bcf10`, `0x56f1710`, `0x57189a8`, `0x572aa50`.

The producer authenticates the entire input before parsing. It scans every byte
of `.text` for 64-bit RIP-relative LEA encodings targeting those five slots,
maps candidates to actual `readelf -wf` FDE extents, then verifies each source
LEA is a decoded instruction in bounded GNU objdump output. The census is
**66 distinct, 272-byte FDE bodies, 17,952 selected bytes**. This denominator
is only this source-linked encoding family, not all debug routines, all source
references, function coverage, code recovery or whole-node equivalence.

`observed/records.json` includes every linked VA interval, file offset, body
hash, complete body hex, source site/slot, callback and call slot. Raw exports
retain all 66 disassemblies, exact FDE rows and relevant relocation rows.
The quoted tool-generated symbol nearest these stripped addresses is not a
recovered function name. #115 and visor are not inputs to this result.

## Observations

Representative interval: `0x1445c70..0x1445d80` (exclusive end).
Offsets below are relative to each FDE start; all 66 pass these controls.

1. A generic formatter callback is prepared at `+0x0e`, followed by a call via
   GOT slot `0x576e040` at `+0x2c`. The resulting stack length is compared with
   `0x2710` (10,000) at `+0x37`.
2. `jbe` at `+0x3e` branches to `+0x8e` for unsigned length <=10,000. That route
   bypasses the cutpoint byte read and uses a different formatting callback.
3. For length >10,000, a single byte at pointer+10,000 is compared as signed:
   27 bodies use `cmpb $0xbf` / `jle`; 39 use `cmpb $0xc0` / `jl`.
   Both select failure for exactly bytes `0x80..0xbf` (all continuation-byte
   encodings), not for every byte with the high bit set.
4. That conditional branch goes to `+0xd8`, which loads the source Location,
   supplies ECX=10,000 and EDX=0, calls slot `0x576e070`, then has `ud2`.
   We call this the failure route; the complete helper/panic ABI is unclosed.
5. The other route stores prefix length exactly 10,000 at `+0x57`, prepares a
   callback and writes via slot `0x576e008` at `+0x86`. There is no backward
   scan or adjustment of this prefix length in these bodies.
6. The truncating route references bytes `c0 05 5b 2e 2e 2e 5d 00` at
   `0x201a53`. They contain printable `[...]` within a compact format
   descriptor. We do not treat it as a plain format string or recover the
   complete resulting text. Both writing routes use the same writer slot.

## Interpretation and limits

Given an already valid UTF-8 byte string, the local continuation-byte predicate
tests whether index 10,000 lies inside a multibyte character. For example,
9,999 ASCII bytes followed by `é` crosses that boundary; 10,000 ASCII bytes
followed by `é` ends a valid prefix before that character. Tests also cover
three- and four-byte characters. These are synthetic architectural examples,
not captured target invocations or proven reachable formatted inputs.

The two compiler encodings implement the same local predicate. They do not
validate arbitrary UTF-8: invalid leading bytes such as `0xc0` and `0xff` pass
this one check. Body bytes/callbacks are not identical across all 66 copies.
Formatting/type recovery, complete call graph, allocator and unwind behavior,
reachability, exact output quoting and full string/formatter ABI remain open.
This packet reports no live defect, crash reproduction or security finding.

The extent of the fixed prefix and branch target follows actual bytes, not
the unlicensed reference tree's names. Source-location attribution is evidence
for grouping, not proof of full ownership or semantic equivalence.

## Reproduction and validation

Ubuntu24.04/WSL2; Python3.12.3; GNU readelf/objdump2.42, default AT&T syntax.
Existing local Git LFS/ripgrep runtimes provide analysis prerequisites; no
captured executable or emulator is run. Existing authenticated LFS objects and
all seven reference commits are reused without changes to their content/pins.

```text
make doctor verify test catalogue-check reproduce
python3 tools/truncated_debug_static.py
python3 tools/truncated_debug_static.py --output work/truncated-repeat
diff -ru work/truncated-debug-94 work/truncated-repeat
```

See `validation.txt`, `required-checks.log` and `manifest.sha256` for actual
results and hashes. Negative controls run on copies below the whole-input
identity gate so a digest mismatch alone cannot satisfy a local obligation.
No progress/catalogue, input, imported reference or component gate changes.
No Rust reconstruction/build, target execution, runtime equivalence, hosted CI
or independent peer-review claim. Next work should close the formatter/helper
and input-type boundaries before implementation or output-equivalence claims.
