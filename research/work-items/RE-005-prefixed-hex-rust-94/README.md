# RE-005: independently reconstruct the prefixed-hex wire primitive

Accepted stream-message research #1162 leaves the proposer writer's hex helper
unimplemented; #955 records shared interpreted code in arm 87's signed-byte
path but supplies no Rust. This contribution implements that concrete codec
dependency in `src/node94-prefixed-hex`. It does not implement either caller,
a digest, signing, transport or the other value writers. No unlicensed inferred
implementation was read or copied.

## Target and bounded result

Target node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact FDE is `[0x29ed380,0x29ed51e)`: **414 bytes / 97 instructions**,
body SHA-256 `4467f0fb09786fc39b97b1925a7dda43d82bee4ffd4fa6c66920d6a471e3672e`.
Its admitted table at `0x208620` has 16 bytes `0123456789abcdef`.
All coordinates are original ELF VAs. Section/PT_LOAD coordinates, raw
FDE/CIE and unique type8/symbol0 RELATIVE slot `0x5773120` are retained.

The normal result is `0x` plus lowercase hexadecimal. Only the first high
nibble is omitted when entry R8 bit0 is one and the first byte is below 16.
This omits one nibble, not a whole zero byte or later zero nibbles. No NUL
is appended, and the output suffix is preserved. Return RAX points to the
original output, with length `2*n+2-delta` in RDX. The chosen safe Rust API
returns that length through ordinary Rust types; it is not an original ABI.

`PROOF.md` proves the complete normal-domain transfer, both short exits and
the loop, including its transient cursor bound and finite progress. Require
nonempty input, nonwrapping `2*n+2`, capacity at least that **untrimmed**
amount even when omitting a nibble, and valid disjoint input/output and
protected active stack/return/code/table regions. Caller-local stack output
is allowed; the whole caller frame is not incorrectly excluded.

All six bounds/empty/panic calls are retained and excluded by these proved
conditions; their helper semantics, malformed result, unwind and hypothetical
return behavior remain unqualified. In particular native empty input can
write the prefix before its helper call. The safe API instead returns
`UnsupportedDomain` before any output change on empty input, length overflow
or short output. Its refusal behavior is a separate API policy, not captured
error parity.

## Concrete uses and distinct denominators

The separately authenticated 69-byte bridge cut at `0x32479e1..0x3247a26`
sets input 32/capacity 66/mode 0 and passes the returned span to a string writer.
The separate 169-byte proposer context/FDE at `0x4670030..0x46700d9` contains
input 20/capacity 42/mode 0 and its following string-writer call. These **238
context bytes**, table 16 and unwind/relocation data are outside the 414-byte
semantic denominator. The cuts do not establish whole callers, input ownership,
legal state populations, full MessagePack payloads or signature/digest behavior.
The shared pair writer under open #1221 is also outside this component.

The pre-Rust oracle has **2,634 normal records + 30 separate safe-API policy
records**, not 2,664 executed target calls. Its 512 exhaustive byte/mode checks
support the static proof, not a whole-string execution census. A second author
froze 64 independent cases before production source: 42 normal/22 policy with
poisoned input/output neighbors, initial suffixes and repeated non-sorted IDs.
Those 64 cases are a separate control population; no additive coverage or
unseen-value claim is made.

## Actual build and controls

The real dependency-free `no_std`/unsafe-forbidden Rust library and input-only
driver build directly with the admitted research Rust 1.94.1 toolchain,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. It is not
claimed as the original compiler or a recovered Cargo/node workspace.

`build/RESULT.json` records the actual fixed pipeline:

* debug and optimized each pass one unit covering all 2,664 fixtures and a
  separately linked input-only client's complete 2,664 output records;
* three compiling normal-valued changes produce 2,372 / 68 / 560 normal-result
  mismatches, zero policy changes, and actual unit value-assertion failures;
* two fresh optimized rlibs are raw-equal, 15,684 bytes, SHA-256
  `817c861af53dd7e5da9b20fac4ad2be32070f33011c3382fe0431d86cdb6d175`;
* the ledger contains 29 Rust/linker/program invocations and 58 raw streams.
  Its 15 read-only Git probes/30 streams are separately recorded and excluded
  from that scientific count. Their inherited host environment is explicitly
  unrecorded; measured scientific children have the five recorded keys.

The before/after input audits match exactly: source, fixtures, all 103 pinned
research compiler payloads, host linker, seven imports and streamed capture
identity. These are observed hashes, not an atomic hostile-host guarantee or
a process-tree trace. The optimized own library has a real 1,034-byte public
encode entry. It is **not** a byte match to the 414-byte captured helper.
Raw own-archive reproducibility does not establish original machine bytes.

`independent-peer/actual-client-run/INDEPENDENT-CLIENT-RESULT.json` records
one separately authored client compile against the retained matching optimized
rlib, with no library rebuild. Its sole runtime argument is the independent
stimulus file. All 64 complete responses and input/output-neighbor/suffix,
identity/order checks pass. Expected data is never a production runtime input.
Compiled payloads are retained privately and are not vendored here.

## Reproduction and chronology

The original native admission and both oracles precede Rust. Candidate metadata
and small byte views are admitted only when each complete region hashes to its
corresponding bytes in the **same full expected-SHA stream**. No full capture
is allocated or copied as a fixture; GNU receives only tiny owned nonexecutable
views. The later portable CLI wrapper repeats that admission after source
qualification, without restamping it as pre-Rust evidence:

```sh
python3 -B research/work-items/RE-005-prefixed-hex-rust-94/recipe/reproduce_native.py \
  --binary artifacts/node/94/hl-node --out /tmp/hex-native-new
python3 -B research/work-items/RE-005-prefixed-hex-rust-94/recipe/qualify_component.py \
  --repo . --oracle research/work-items/RE-005-prefixed-hex-rust-94/oracle \
  --rustc /path/to/admitted/rust-1.94.1/bin/rustc --output /tmp/hex-rust-new
```

The native wrapper preserves raw streams. The original and later GNU headers
contain different owned file paths; only the comparison substitutes that
presentation path. All instruction rows and encoded bytes remain exact and
the two original streams remain unchanged. See
`NATIVE-PORTABLE-REPRODUCTION.json` and the independent source-peer receipt.
The original freezer scripts/paths are retained as historical chronology;
the CLI above and committed byte-identical fixtures support later reproduction.
The compiler recipe requires the exact admitted 103-payload prefix, records
the selected host linker, and checks both before and after. It installs nothing.

The evidence is source-hash-bound component qualification. Final exact-commit
repository checks, publication head/tree and hosted state are reported separately
in the PR; no full `make test`, hosted CI or captured execution is claimed by
this packet. The publication remains a source-ready `[skip ci]` draft.

New code, mathematical fixtures and documentation are independently authored
MIT work. Captured code/data/unwind excerpts retain their original ownership.
No upstream implementation, compiler payload or whole capture is redistributed.
No original name/type/ABI, physical read/fault trace, panic/unwind closure,
whole-caller/node equivalence, target-byte identity or full-scope gate is claimed.
